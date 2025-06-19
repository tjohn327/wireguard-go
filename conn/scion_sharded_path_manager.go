// SCION Sharded Path Manager for reduced lock contention
// This file implements optimization 6 from the performance improvements

package conn

import (
	"context"
	"fmt"
	"hash/fnv"
	"sort"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

// OPTIMIZATION 6: Sharded Path Manager for reduced lock contention
const numShards = 256

type pathCacheShard struct {
	mu    sync.RWMutex
	cache map[addr.IA]*PathCacheEntry
}

type ShardedPathManager struct {
	*PathManager                            // Embed the original PathManager
	shards       [numShards]*pathCacheShard // Sharded cache
}

// NewShardedPathManager creates a new path manager with sharded cache
func NewShardedPathManager(d daemon.Connector, localIA addr.IA, pol PathPolicy, log Logger, opts ...PathManagerOption) *ShardedPathManager {
	// Create base PathManager
	basePM := &PathManager{
		d:       d,
		localIA: localIA,
		policy:  pol,
		cache:   make(map[addr.IA]*PathCacheEntry),
		log:     log,
		refresh: refreshInterval,
	}
	
	for _, opt := range opts {
		opt(basePM)
	}
	
	basePM.ctx, basePM.cancel = context.WithCancel(context.Background())
	
	// Create sharded manager
	spm := &ShardedPathManager{
		PathManager: basePM,
	}
	
	// Initialize shards
	for i := range spm.shards {
		spm.shards[i] = &pathCacheShard{
			cache: make(map[addr.IA]*PathCacheEntry),
		}
	}
	
	// Start refresh loop
	spm.Start()
	
	// Start API server
	go func() {
		if err := spm.StartAPIServer(defaultAPIPort, fallbackAPIPort1, fallbackAPIPort2); err != nil {
			spm.log.Errorf("Failed to start PathManager API server: %v", err)
		}
	}()
	
	return spm
}

func (spm *ShardedPathManager) getShard(ia addr.IA) *pathCacheShard {
	// Use FNV hash for better distribution
	h := fnv.New32a()
	h.Write([]byte(ia.String()))
	hash := h.Sum32()
	return spm.shards[hash&(numShards-1)]
}

// Override methods to use sharded cache
func (spm *ShardedPathManager) RegisterEndpoint(ia addr.IA) {
	shard := spm.getShard(ia)
	
	shard.mu.RLock()
	_, exists := shard.cache[ia]
	shard.mu.RUnlock()
	
	if exists {
		return
	}
	
	// Double-checked locking
	shard.mu.Lock()
	if _, exists := shard.cache[ia]; exists {
		shard.mu.Unlock()
		return
	}
	shard.cache[ia] = nil
	shard.mu.Unlock()
	
	// Trigger immediate fetch
	if err := spm.refreshOne(ia); err != nil {
		spm.log.Errorf("SCION path fetch failed for %s: %v", ia, err)
	}
}

func (spm *ShardedPathManager) GetPath(ia addr.IA) (snet.Path, error) {
	shard := spm.getShard(ia)
	
	shard.mu.RLock()
	entry := shard.cache[ia]
	shard.mu.RUnlock()
	
	if entry == nil || len(entry.Paths) == 0 {
		return nil, fmt.Errorf("no path found for IA %s", ia)
	}
	return entry.Paths[entry.SelectedIndex], nil
}

func (spm *ShardedPathManager) refreshOne(dest addr.IA) error {
	ctx, cancel := context.WithTimeout(spm.ctx, 3*time.Second)
	defer cancel()
	
	paths, err := spm.d.Paths(ctx, dest, spm.localIA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		shard := spm.getShard(dest)
		shard.mu.Lock()
		if entry := shard.cache[dest]; entry != nil {
			entry.LastError = err
		}
		shard.mu.Unlock()
		return fmt.Errorf("daemon Paths(): %w", err)
	}
	
	if len(paths) == 0 {
		spm.log.Verbosef("No paths found from %s to %s", spm.localIA, dest)
	}
	
	// Create path ranks
	ranks := make([]PathRank, len(paths))
	for i, path := range paths {
		meta := path.Metadata()
		hopCount := 0
		if meta != nil {
			hopCount = len(meta.Interfaces)
		}
		ranks[i] = PathRank{
			LatencyScore:   latencyScore(path),
			BandwidthScore: bandwidthScore(path),
			HopCount:       hopCount,
			LastVerified:   time.Now(),
			IsAlive:        true,
		}
	}
	
	// Update cache
	shard := spm.getShard(dest)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	
	entry := shard.cache[dest]
	if entry == nil {
		entry = &PathCacheEntry{}
		shard.cache[dest] = entry
	}
	
	// Handle manual path selection
	manualPathFound := false
	if entry.IsManualSelect && len(entry.Paths) > 0 &&
		entry.SelectedIndex >= 0 && entry.SelectedIndex < len(entry.Paths) {
		
		oldPath := entry.Paths[entry.SelectedIndex]
		oldFingerprint := snet.Fingerprint(oldPath).String()
		
		// Find the same path in the new set
		for i, newPath := range paths {
			if snet.Fingerprint(newPath).String() == oldFingerprint {
				// Found the same path, move it to the front and preserve selection
				if i != 0 {
					// Move the path and its corresponding rank to position 0
					paths[0], paths[i] = paths[i], paths[0]
					ranks[0], ranks[i] = ranks[i], ranks[0]
				}
				entry.SelectedIndex = 0
				manualPathFound = true
				break
			}
		}
	}
	
	// If no manual selection or manual path not found, use policy-based sorting
	if !manualPathFound {
		if len(paths) > 0 {
			// Create indices for sorting to maintain path-rank correspondence
			indices := make([]int, len(paths))
			for i := range indices {
				indices[i] = i
			}
			
			// Sort indices based on path policy
			sort.SliceStable(indices, func(i, j int) bool {
				return lessByPolicy(paths[indices[i]], paths[indices[j]], spm.policy)
			})
			
			// Reorder both paths and ranks based on sorted indices
			sortedPaths := make([]snet.Path, len(paths))
			sortedRanks := make([]PathRank, len(ranks))
			for i, idx := range indices {
				sortedPaths[i] = paths[idx]
				sortedRanks[i] = ranks[idx]
			}
			paths = sortedPaths
			ranks = sortedRanks
		}
		entry.SelectedIndex = 0
		entry.IsManualSelect = false
	}
	
	entry.Paths = paths
	entry.PathRanks = ranks
	entry.LastRefresh = time.Now()
	entry.LastError = nil
	
	return nil
}

func (spm *ShardedPathManager) refreshAll() {
	// Collect all destinations from all shards
	var dests []addr.IA
	
	for _, shard := range spm.shards {
		shard.mu.RLock()
		for ia := range shard.cache {
			dests = append(dests, ia)
		}
		shard.mu.RUnlock()
	}
	
	// Refresh paths
	for _, ia := range dests {
		if err := spm.refreshOne(ia); err != nil {
			spm.log.Errorf("SCION path refresh failed for %s: %v", ia, err)
		}
	}
}

// Override GetPathsJSON to use sharded cache
func (spm *ShardedPathManager) GetPathsJSON(iaStr string) (string, error) {
	// Simply delegate to the embedded PathManager's implementation
	// The sharded manager overrides GetPath and refreshOne which are used internally
	return spm.PathManager.GetPathsJSON(iaStr)
}

// Override SetPath to use sharded cache
func (spm *ShardedPathManager) SetPath(iaStr string, pathIndex int) error {
	// Parse the IA string
	ia, err := addr.ParseIA(iaStr)
	if err != nil {
		return fmt.Errorf("invalid IA format: %w", err)
	}

	// Get current paths and update selection atomically
	shard := spm.getShard(ia)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	entry := shard.cache[ia]

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
	entry.SelectedIndex = pathIndex
	entry.IsManualSelect = true

	return nil
}

// GetPathPolicy returns the current path selection policy
func (spm *ShardedPathManager) GetPathPolicy() string {
	return spm.policy.String()
}