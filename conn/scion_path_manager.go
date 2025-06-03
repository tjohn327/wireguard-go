/*
 *
 * Path manager for SCION-aware WireGuard backend.
 *
 * This file is intended to live in the same Go package (conn) as bind_scion.go
 * and can be dropped next to it.  No changes outside of the conn package are
 * necessary – once the file is built into the module the SCION bind will
 * automatically pick it up.
 *
 * The manager keeps a per‑destination cache of SCION paths that is refreshed
 * in the background.  Retrieval and scoring of paths is delegated to the SCION
 * daemon (sciond) via the daemon.Connector interface that bind_scion.go
 * already initialises.
 */

package conn

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

// refreshInterval is the default cadence at which the manager re‑resolves
// paths.  Callers may override this by passing WithRefreshInterval when
// building the PathManager.
const refreshInterval = 5 * time.Minute

// PathCacheEntry represents a cache entry for paths to a specific IA
type PathCacheEntry struct {
	Paths          []snet.Path // All available paths
	SelectedIndex  int         // Index of currently selected path
	IsManualSelect bool        // Whether path was manually selected
	LastRefresh    time.Time   // When paths were last refreshed
	PathRanks      []PathRank  // Ranking information for each path
	LastError      error       // Last error encountered during refresh
}

// PathRank contains ranking information for a single path
type PathRank struct {
	LatencyScore   time.Duration // Calculated latency score
	BandwidthScore uint64        // Calculated bandwidth score
	HopCount       int           // Number of hops
	LastVerified   time.Time     // When the path was last verified
	IsAlive        bool          // Whether the path is currently alive
}

// PathManager maintains fresh SCION paths for all remote IAs that the program
// has seen so far.  All public methods are concurrency‑safe.
//
// A single instance is shared by all ScionNetBind objects, but nothing stops
// you from running several independent managers if you prefer tighter
// isolation.
//
// On creation PathManager immediately fetches paths for any destinations that
// were registered prior to Start() – this gives callers deterministic latency
// for their first packet.
//
// A background goroutine does periodic refreshes until Close() is called.  The
// manager is therefore long‑lived and should be closed during program
// shutdown.

type PathManager struct {
	ctx    context.Context
	cancel context.CancelFunc

	d       daemon.Connector
	localIA addr.IA
	policy  PathPolicy

	mu    sync.RWMutex // protects everything below
	cache map[addr.IA]*PathCacheEntry
	log   Logger

	refresh time.Duration
}

// NewPathManager wires up a new path manager.  The background refresh only
// starts after Start() is called.
func NewPathManager(d daemon.Connector, localIA addr.IA, pol PathPolicy, log Logger, opts ...PathManagerOption) *PathManager {
	pm := &PathManager{
		d:       d,
		localIA: localIA,
		policy:  pol,
		cache:   make(map[addr.IA]*PathCacheEntry),
		log:     log,
		refresh: refreshInterval,
	}
	for _, opt := range opts {
		opt(pm)
	}
	pm.ctx, pm.cancel = context.WithCancel(context.Background())
	return pm
}

// PathManagerOption configures a PathManager.
// Currently only WithRefreshInterval exists but more can be added as needed.
type PathManagerOption func(*PathManager)

func WithRefreshInterval(d time.Duration) PathManagerOption {
	return func(pm *PathManager) { pm.refresh = d }
}

// Start kicks off the periodic refresh goroutine.  Calling Start multiple
// times is a no‑op.
func (pm *PathManager) Start() {
	go pm.loop()
}

func (pm *PathManager) loop() {
	ticker := time.NewTicker(pm.refresh)
	defer ticker.Stop()
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.refreshAll()
		}
	}
}

// Close stops the background refresh.  It is safe to call Close more than
// once.
func (pm *PathManager) Close() {
	pm.cancel()
}

// RegisterEndpoint ensures that the given destination IA is tracked.  The
// method is cheap if the IA is already known.
func (pm *PathManager) RegisterEndpoint(ia addr.IA) {
	pm.mu.RLock()
	_, exists := pm.cache[ia]
	pm.mu.RUnlock()
	if exists {
		return
	}
	// Create empty entry and trigger immediate fetch so callers get paths
	// right away.
	pm.mu.Lock()
	pm.cache[ia] = nil
	pm.mu.Unlock()
	if err := pm.refreshOne(ia); err != nil {
		pm.log.Errorf("SCION path fetch failed for %s: %v", ia, err)
	}
}

// getPaths returns a snapshot of the current paths for a destination IA.  The
// slice is safe for the caller to modify.
func (pm *PathManager) getPaths(ia addr.IA) []snet.Path {
	pm.mu.RLock()
	entry := pm.cache[ia]
	pm.mu.RUnlock()
	if entry == nil {
		return nil
	}
	out := make([]snet.Path, len(entry.Paths))
	copy(out, entry.Paths)
	return out
}

func (pm *PathManager) GetPath(ia addr.IA) (snet.Path, error) {
	pm.mu.RLock()
	entry := pm.cache[ia]
	pm.mu.RUnlock()
	if entry == nil || len(entry.Paths) == 0 {
		return nil, fmt.Errorf("no path found for IA %s", ia)
	}
	return entry.Paths[entry.SelectedIndex], nil
}

func (pm *PathManager) refreshAll() {
	pm.mu.RLock()
	dests := make([]addr.IA, 0, len(pm.cache))
	for ia := range pm.cache {
		dests = append(dests, ia)
	}
	pm.mu.RUnlock()
	for _, ia := range dests {
		if err := pm.refreshOne(ia); err != nil {
			pm.log.Errorf("SCION path refresh failed for %s: %v", ia, err)
		}
	}
}

func (pm *PathManager) refreshOne(dest addr.IA) error {
	ctx, cancel := context.WithTimeout(pm.ctx, 3*time.Second)
	defer cancel()

	paths, err := pm.d.Paths(ctx, dest, pm.localIA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		pm.mu.Lock()
		if entry := pm.cache[dest]; entry != nil {
			entry.LastError = err
		}
		pm.mu.Unlock()
		return fmt.Errorf("daemon Paths(): %w", err)
	}

	if len(paths) == 0 {
		pm.log.Verbosef("No paths found from %s to %s", pm.localIA, dest)
	}

	// Create path ranks
	ranks := make([]PathRank, len(paths))
	for i, path := range paths {
		meta := path.Metadata()
		ranks[i] = PathRank{
			LatencyScore:   latencyScore(path),
			BandwidthScore: bandwidthScore(path),
			HopCount:       len(meta.Interfaces),
			LastVerified:   time.Now(),
			IsAlive:        true,
		}
	}

	// Update cache
	pm.mu.Lock()
	entry := pm.cache[dest]
	if entry == nil {
		entry = &PathCacheEntry{}
		pm.cache[dest] = entry
	}

	// If there was a manual selection, try to find the same path in the new set
	if entry.IsManualSelect && len(entry.Paths) > 0 && entry.SelectedIndex < len(entry.Paths) {
		oldPath := entry.Paths[entry.SelectedIndex]
		oldFingerprint := snet.Fingerprint(oldPath).String()

		// Find the same path in the new set
		for i, newPath := range paths {
			if snet.Fingerprint(newPath).String() == oldFingerprint {
				// Found the same path, keep it at the same index
				if i != entry.SelectedIndex {
					// Move the path to the selected index
					paths[i], paths[entry.SelectedIndex] = paths[entry.SelectedIndex], paths[i]
					ranks[i], ranks[entry.SelectedIndex] = ranks[entry.SelectedIndex], ranks[i]
				}
				break
			}
		}
	} else {
		// No manual selection or couldn't find the path, sort by policy
		if len(paths) > 0 {
			sort.SliceStable(paths, func(i, j int) bool {
				return lessByPolicy(paths[i], paths[j], pm.policy)
			})
			// Sort ranks in the same order
			sort.SliceStable(ranks, func(i, j int) bool {
				return lessByPolicy(paths[i], paths[j], pm.policy)
			})
		}
		entry.SelectedIndex = 0
		entry.IsManualSelect = false
	}

	entry.Paths = paths
	entry.PathRanks = ranks
	entry.LastRefresh = time.Now()
	entry.LastError = nil
	pm.mu.Unlock()

	return nil
}

// normalizePaths converts daemon API paths into snet.Path.  The connector
// already returns []snet.Path since SCION v0.6, but abstract it away so we can
// handle future API tweaks.
func normalizePaths(in []snet.Path) []snet.Path { return in }

// lessByPolicy implements the four simple scoring policies that bind_scion.go
// exposes via the PathPolicy enum.
func lessByPolicy(a, b snet.Path, pol PathPolicy) bool {
	switch pol {
	case PathPolicyShortest:
		la := len(a.Metadata().Interfaces)
		lb := len(b.Metadata().Interfaces)
		return la < lb
	case PathPolicyBandwidth:
		return bandwidthScore(a) > bandwidthScore(b)
	case PathPolicyLatency:
		return latencyScore(a) < latencyScore(b)
	case PathPolicyFirst:
		fallthrough
	default:
		return true // keep original order
	}
}

func bandwidthScore(p snet.Path) uint64 {
	meta := p.Metadata()
	if meta == nil || len(meta.Bandwidth) == 0 {
		return 0
	}
	min := meta.Bandwidth[0]
	for _, bw := range meta.Bandwidth[1:] {
		if bw < min {
			min = bw
		}
	}
	return min
}

func latencyScore(p snet.Path) time.Duration {
	meta := p.Metadata()
	if meta == nil || len(meta.Latency) == 0 {
		return time.Duration(1<<63 - 1) // effectively +∞
	}
	var total time.Duration
	for _, l := range meta.Latency {
		if l < 0 {
			// Missing measurement – treat as very slow.
			return time.Duration(1<<63 - 1)
		}
		total += l
	}
	return total
}

// PathInfo represents the JSON structure for path information
type PathInfo struct {
	LocalISDAS  string        `json:"local_isd_as"`
	Destination string        `json:"destination"`
	Paths       []PathDetails `json:"paths"`
	Error       string        `json:"error,omitempty"`
}

// PathDetails represents the JSON structure for individual path details
type PathDetails struct {
	Index       int       `json:"index"`
	Fingerprint string    `json:"fingerprint"`
	Hops        []HopInfo `json:"hops"`
	Sequence    string    `json:"sequence"`
	NextHop     string    `json:"next_hop"`
	Expiry      string    `json:"expiry"`
	MTU         uint16    `json:"mtu"`
	Latency     []int64   `json:"latency"`
	Bandwidth   []uint64  `json:"bandwidth"`
	Status      string    `json:"status"`
	LocalIP     string    `json:"local_ip"`
}

// HopInfo represents the JSON structure for hop information
type HopInfo struct {
	IFID  uint16 `json:"ifid"`
	ISDAS string `json:"isd_as"`
}

// GetPathsJSON returns a JSON string containing available paths for the given IA
func (pm *PathManager) GetPathsJSON(iaStr string) (string, error) {
	// Parse the IA string
	ia, err := addr.ParseIA(iaStr)
	if err != nil {
		return "", fmt.Errorf("invalid IA format: %w", err)
	}

	// Get paths for the IA
	pm.mu.RLock()
	entry := pm.cache[ia]
	pm.mu.RUnlock()

	if entry == nil || len(entry.Paths) == 0 {
		// Try to register and refresh paths if none found
		pm.RegisterEndpoint(ia)
		pm.mu.RLock()
		entry = pm.cache[ia]
		pm.mu.RUnlock()
	}

	// Create path info structure
	pathInfo := PathInfo{
		LocalISDAS:  pm.localIA.String(),
		Destination: iaStr,
	}

	if entry == nil || len(entry.Paths) == 0 {
		pathInfo.Error = "No paths available"
	} else {
		pathInfo.Paths = make([]PathDetails, len(entry.Paths))
		for i, path := range entry.Paths {
			meta := path.Metadata()
			if meta == nil {
				continue
			}

			// Convert latencies to int64 (milliseconds)
			latencies := make([]int64, len(meta.Latency))
			for j, l := range meta.Latency {
				if l < 0 {
					latencies[j] = -1
				} else {
					latencies[j] = l.Milliseconds()
				}
			}

			// Create sequence string
			var sequence strings.Builder
			for j, iface := range meta.Interfaces {
				if j > 0 {
					sequence.WriteString(" ")
				}
				sequence.WriteString(iface.String())
			}

			// Get next hop
			nextHop := path.UnderlayNextHop()
			nextHopStr := ""
			if nextHop != nil {
				nextHopStr = nextHop.String()
			}

			// Get path status
			status := "alive"
			if i < len(entry.PathRanks) && !entry.PathRanks[i].IsAlive {
				status = "dead"
			}

			details := PathDetails{
				Index:       i,
				Fingerprint: snet.Fingerprint(path).String(),
				MTU:         meta.MTU,
				Latency:     latencies,
				Bandwidth:   meta.Bandwidth,
				Sequence:    sequence.String(),
				NextHop:     nextHopStr,
				Expiry:      meta.Expiry.Format(time.RFC3339),
				Status:      status,
				LocalIP:     pm.localIA.String(),
			}

			// Add hop information
			details.Hops = make([]HopInfo, len(meta.Interfaces))
			for j, iface := range meta.Interfaces {
				details.Hops[j] = HopInfo{
					IFID:  uint16(iface.ID),
					ISDAS: iface.IA.String(),
				}
			}

			pathInfo.Paths[i] = details
		}
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(pathInfo, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal path info: %w", err)
	}

	return string(jsonData), nil
}

// SetPath sets the path for a given IA based on the path index.
// If the index is invalid or no paths are available, it returns an error.
func (pm *PathManager) SetPath(iaStr string, pathIndex int) error {
	// Parse the IA string
	ia, err := addr.ParseIA(iaStr)
	if err != nil {
		return fmt.Errorf("invalid IA format: %w", err)
	}

	// Get current paths
	pm.mu.RLock()
	entry := pm.cache[ia]
	pm.mu.RUnlock()

	// Check if we have any paths
	if entry == nil || len(entry.Paths) == 0 {
		return fmt.Errorf("no paths available for IA %s", iaStr)
	}

	// Check if the index is valid
	if pathIndex < 0 || pathIndex >= len(entry.Paths) {
		return fmt.Errorf("invalid path index %d for IA %s (available paths: %d)",
			pathIndex, iaStr, len(entry.Paths))
	}

	// Update the cache entry
	pm.mu.Lock()
	entry.SelectedIndex = pathIndex
	entry.IsManualSelect = true
	pm.mu.Unlock()

	return nil
}
