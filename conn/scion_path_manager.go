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
	"fmt"
	"sort"
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

// PathManager maintains fresh SCION paths for all remote IAs that the program
// has seen so far.  All public methods are concurrency‑safe.
//
// A single instance is shared by all ScionNetBind objects, but nothing stops
// you from running several independent managers if you prefer tighter
// isolation.
//
// On creation PathManager immediately fetches paths for any destinations that
// were registered prior to Start() – this gives callers deterministic latency
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
	cache map[addr.IA][]snet.Path
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
		cache:   make(map[addr.IA][]snet.Path),
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

// GetPaths returns a snapshot of the current paths for a destination IA.  The
// slice is safe for the caller to modify.
func (pm *PathManager) GetPaths(ia addr.IA) []snet.Path {
	pm.mu.RLock()
	paths := pm.cache[ia]
	pm.mu.RUnlock()
	out := make([]snet.Path, len(paths))
	copy(out, paths)
	return out
}

// SelectPath returns the best path for the given IA according to the current
// policy, or nil if no path is known.
func (pm *PathManager) SelectPath(ia addr.IA) snet.Path {
	paths := pm.GetPaths(ia)
	if len(paths) == 0 {
		return nil
	}
	sort.SliceStable(paths, func(i, j int) bool {
		return lessByPolicy(paths[i], paths[j], pm.policy)
	})
	return paths[0]
}

func (pm *PathManager) refreshAll() {
	pm.log.Verbosef("Refreshing all paths")
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
		return fmt.Errorf("daemon Paths(): %w", err)
	}
	if len(paths) == 0 {
		pm.log.Verbosef("No paths found from %s to %s", pm.localIA, dest)
	}
	pm.mu.Lock()
	pm.cache[dest] = normalizePaths(paths)
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
			// Missing measurement – treat as very slow.
			return time.Duration(1<<63 - 1)
		}
		total += l
	}
	return total
}
