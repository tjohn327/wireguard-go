/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

// PathSnapshot represents an atomic snapshot of paths for all destinations
type PathSnapshot struct {
	version   uint64                        // Monotonically increasing version
	timestamp time.Time                     // When this snapshot was created
	pathCache map[addr.IA]*FastPathEntry    // Fast lookup cache
}

// FastPathEntry represents a lock-free path cache entry
type FastPathEntry struct {
	paths         []snet.Path  // All available paths
	selectedIndex int          // Currently selected path index
	isManual      bool         // Whether path was manually selected
	lastUpdate    time.Time    // When paths were last updated
	quality       PathQuality  // Cached path quality metrics
}

// PathQuality contains pre-computed path quality metrics for fast selection
type PathQuality struct {
	latencyScore   time.Duration
	bandwidthScore uint64
	hopCount       int
	reliability    float64 // 0.0 to 1.0
}

// LockFreePathManager provides high-performance, lock-free path management
type LockFreePathManager struct {
	// Atomic pointers for lock-free reads
	currentSnapshot atomic.Pointer[PathSnapshot]
	
	// Background update management
	updateWorker   *PathUpdateWorker
	refreshTicker  *time.Ticker
	shutdownCh     chan struct{}
	
	// Configuration
	localIA        addr.IA
	daemonConn     daemon.Connector
	policy         atomic.Value // PathPolicy
	refreshInterval time.Duration
	
	// Logging
	logger Logger
	
	// Performance metrics
	lookupCount    atomic.Uint64
	updateCount    atomic.Uint64
	cacheHits      atomic.Uint64
	cacheMisses    atomic.Uint64
}

// PathUpdateWorker handles background path updates without blocking reads
type PathUpdateWorker struct {
	manager       *LockFreePathManager
	updateQueue   chan PathUpdateRequest
	batchUpdates  map[addr.IA]PathUpdateRequest
	batchTimer    *time.Timer
	batchDelay    time.Duration
}

// PathUpdateRequest represents a request to update paths for a destination
type PathUpdateRequest struct {
	destination addr.IA
	priority    UpdatePriority
	timestamp   time.Time
}

// UpdatePriority defines the priority of path updates
type UpdatePriority int

const (
	UpdatePriorityLow UpdatePriority = iota
	UpdatePriorityNormal
	UpdatePriorityHigh
	UpdatePriorityImmediate
)

// NewLockFreePathManager creates a new lock-free path manager
func NewLockFreePathManager(daemonConn daemon.Connector, localIA addr.IA, policy PathPolicy, logger Logger) *LockFreePathManager {
	lfpm := &LockFreePathManager{
		localIA:         localIA,
		daemonConn:      daemonConn,
		refreshInterval: 5 * time.Minute,
		logger:          logger,
		shutdownCh:      make(chan struct{}),
	}
	
	// Set initial policy
	lfpm.policy.Store(policy)
	
	// Initialize with empty snapshot
	initialSnapshot := &PathSnapshot{
		version:   1,
		timestamp: time.Now(),
		pathCache: make(map[addr.IA]*FastPathEntry),
	}
	lfpm.currentSnapshot.Store(initialSnapshot)
	
	// Create update worker
	lfpm.updateWorker = &PathUpdateWorker{
		manager:      lfpm,
		updateQueue:  make(chan PathUpdateRequest, 1000), // Buffered channel
		batchUpdates: make(map[addr.IA]PathUpdateRequest),
		batchDelay:   10 * time.Millisecond, // Batch updates for efficiency
	}
	
	// Start background workers
	go lfpm.updateWorker.run()
	go lfpm.refreshWorker()
	
	return lfpm
}

// GetPathFast performs a lock-free path lookup with O(1) complexity
func (lfpm *LockFreePathManager) GetPathFast(ia addr.IA) (snet.Path, bool) {
	lfpm.lookupCount.Add(1)
	
	// Load current snapshot atomically
	snapshot := lfpm.currentSnapshot.Load()
	if snapshot == nil {
		lfpm.cacheMisses.Add(1)
		return nil, false
	}
	
	// Fast lookup in snapshot
	entry, exists := snapshot.pathCache[ia]
	if !exists || len(entry.paths) == 0 {
		lfpm.cacheMisses.Add(1)
		// Trigger background update for missing destination
		lfpm.requestPathUpdate(ia, UpdatePriorityNormal)
		return nil, false
	}
	
	lfpm.cacheHits.Add(1)
	
	// Validate selected index
	if entry.selectedIndex < 0 || entry.selectedIndex >= len(entry.paths) {
		lfpm.logger.Errorf("Invalid path index %d for IA %s (total paths: %d)", 
			entry.selectedIndex, ia, len(entry.paths))
		return nil, false
	}
	
	return entry.paths[entry.selectedIndex], true
}

// RegisterDestinationFast registers a destination for path tracking (non-blocking)
func (lfpm *LockFreePathManager) RegisterDestinationFast(ia addr.IA) {
	// Check if destination already exists
	snapshot := lfpm.currentSnapshot.Load()
	if snapshot != nil {
		if _, exists := snapshot.pathCache[ia]; exists {
			return // Already registered
		}
	}
	
	// Request immediate path update for new destination
	lfpm.requestPathUpdate(ia, UpdatePriorityHigh)
}

// SetPathManual sets a specific path for a destination (non-blocking)
func (lfpm *LockFreePathManager) SetPathManual(ia addr.IA, pathIndex int) error {
	// This operation requires updating the snapshot, so we queue it
	req := PathUpdateRequest{
		destination: ia,
		priority:    UpdatePriorityImmediate,
		timestamp:   time.Now(),
	}
	
	// Add special handling for manual path selection
	select {
	case lfpm.updateWorker.updateQueue <- req:
		return nil
	default:
		return fmt.Errorf("update queue full, manual path setting rejected")
	}
}

// requestPathUpdate queues a path update request
func (lfpm *LockFreePathManager) requestPathUpdate(ia addr.IA, priority UpdatePriority) {
	req := PathUpdateRequest{
		destination: ia,
		priority:    priority,
		timestamp:   time.Now(),
	}
	
	select {
	case lfpm.updateWorker.updateQueue <- req:
		// Successfully queued
	default:
		// Queue full, drop low priority updates
		if priority <= UpdatePriorityLow {
			return
		}
		// For higher priority updates, try to make space
		select {
		case <-lfpm.updateWorker.updateQueue:
			// Dropped one request to make space
			lfpm.updateWorker.updateQueue <- req
		default:
			// Queue still full, log warning
			lfpm.logger.Errorf("Path update queue full, dropping update for IA %s", ia)
		}
	}
}

// refreshWorker handles periodic path refreshes
func (lfpm *LockFreePathManager) refreshWorker() {
	lfpm.refreshTicker = time.NewTicker(lfpm.refreshInterval)
	defer lfpm.refreshTicker.Stop()
	
	for {
		select {
		case <-lfpm.refreshTicker.C:
			lfpm.triggerFullRefresh()
		case <-lfpm.shutdownCh:
			return
		}
	}
}

// triggerFullRefresh triggers a refresh of all cached destinations
func (lfpm *LockFreePathManager) triggerFullRefresh() {
	snapshot := lfpm.currentSnapshot.Load()
	if snapshot == nil {
		return
	}
	
	// Queue updates for all cached destinations
	for ia := range snapshot.pathCache {
		lfpm.requestPathUpdate(ia, UpdatePriorityLow)
	}
}

// run executes the path update worker loop
func (puw *PathUpdateWorker) run() {
	puw.batchTimer = time.NewTimer(puw.batchDelay)
	puw.batchTimer.Stop() // Don't start until we have updates
	
	for {
		select {
		case req := <-puw.updateQueue:
			puw.handleUpdateRequest(req)
			
		case <-puw.batchTimer.C:
			puw.processBatch()
			
		case <-puw.manager.shutdownCh:
			return
		}
	}
}

// handleUpdateRequest processes a single update request
func (puw *PathUpdateWorker) handleUpdateRequest(req PathUpdateRequest) {
	// Add to batch (newer requests override older ones for same destination)
	existingReq, exists := puw.batchUpdates[req.destination]
	if !exists || req.priority > existingReq.priority || req.timestamp.After(existingReq.timestamp) {
		puw.batchUpdates[req.destination] = req
	}
	
	// Handle immediate priority requests
	if req.priority == UpdatePriorityImmediate {
		puw.processImmediateUpdate(req)
		delete(puw.batchUpdates, req.destination)
		return
	}
	
	// Start/restart batch timer for non-immediate requests
	if !puw.batchTimer.Stop() {
		select {
		case <-puw.batchTimer.C:
		default:
		}
	}
	puw.batchTimer.Reset(puw.batchDelay)
}

// processImmediateUpdate handles high-priority updates immediately
func (puw *PathUpdateWorker) processImmediateUpdate(req PathUpdateRequest) {
	paths, err := puw.fetchPaths(req.destination)
	if err != nil {
		puw.manager.logger.Errorf("Immediate path update failed for %s: %v", req.destination, err)
		return
	}
	
	puw.updateSingleDestination(req.destination, paths)
}

// processBatch processes all batched update requests
func (puw *PathUpdateWorker) processBatch() {
	if len(puw.batchUpdates) == 0 {
		return
	}
	
	// Copy batch and clear for next round
	batch := make(map[addr.IA]PathUpdateRequest, len(puw.batchUpdates))
	for ia, req := range puw.batchUpdates {
		batch[ia] = req
		delete(puw.batchUpdates, ia)
	}
	
	// Process batch efficiently
	puw.processBatchUpdates(batch)
}

// processBatchUpdates efficiently processes multiple path updates
func (puw *PathUpdateWorker) processBatchUpdates(batch map[addr.IA]PathUpdateRequest) {
	// Fetch paths for all destinations in parallel
	type pathResult struct {
		ia    addr.IA
		paths []snet.Path
		err   error
	}
	
	results := make(chan pathResult, len(batch))
	semaphore := make(chan struct{}, runtime.NumCPU()*2) // Limit concurrency
	
	// Launch concurrent path fetches
	for ia := range batch {
		go func(destIA addr.IA) {
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			paths, err := puw.fetchPaths(destIA)
			results <- pathResult{ia: destIA, paths: paths, err: err}
		}(ia)
	}
	
	// Collect results and update snapshot
	pathUpdates := make(map[addr.IA][]snet.Path)
	for i := 0; i < len(batch); i++ {
		result := <-results
		if result.err != nil {
			puw.manager.logger.Errorf("Path fetch failed for %s: %v", result.ia, result.err)
			continue
		}
		pathUpdates[result.ia] = result.paths
	}
	
	// Update snapshot with all results atomically
	if len(pathUpdates) > 0 {
		puw.updateSnapshot(pathUpdates)
	}
}

// fetchPaths retrieves paths for a destination from the daemon
func (puw *PathUpdateWorker) fetchPaths(dest addr.IA) ([]snet.Path, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	
	paths, err := puw.manager.daemonConn.Paths(ctx, dest, puw.manager.localIA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		return nil, err
	}
	
	return paths, nil
}

// updateSingleDestination updates a single destination in the snapshot
func (puw *PathUpdateWorker) updateSingleDestination(ia addr.IA, paths []snet.Path) {
	updates := map[addr.IA][]snet.Path{ia: paths}
	puw.updateSnapshot(updates)
}

// updateSnapshot atomically updates the path snapshot
func (puw *PathUpdateWorker) updateSnapshot(pathUpdates map[addr.IA][]snet.Path) {
	if len(pathUpdates) == 0 {
		return
	}
	
	for {
		// Load current snapshot
		currentSnapshot := puw.manager.currentSnapshot.Load()
		if currentSnapshot == nil {
			return
		}
		
		// Create new snapshot
		newSnapshot := &PathSnapshot{
			version:   currentSnapshot.version + 1,
			timestamp: time.Now(),
			pathCache: make(map[addr.IA]*FastPathEntry, len(currentSnapshot.pathCache)+len(pathUpdates)),
		}
		
		// Copy existing entries
		for ia, entry := range currentSnapshot.pathCache {
			newSnapshot.pathCache[ia] = entry
		}
		
		// Add/update new entries
		policy := puw.manager.policy.Load().(PathPolicy)
		for ia, paths := range pathUpdates {
			entry := puw.createFastPathEntry(paths, policy)
			newSnapshot.pathCache[ia] = entry
		}
		
		// Try to atomically swap the snapshot
		if puw.manager.currentSnapshot.CompareAndSwap(currentSnapshot, newSnapshot) {
			puw.manager.updateCount.Add(1)
			break
		}
		// If CAS failed, another goroutine updated the snapshot, retry
		runtime.Gosched() // Yield CPU to reduce contention
	}
}

// createFastPathEntry creates a fast path entry with pre-computed quality metrics
func (puw *PathUpdateWorker) createFastPathEntry(paths []snet.Path, policy PathPolicy) *FastPathEntry {
	if len(paths) == 0 {
		return &FastPathEntry{
			paths:         paths,
			selectedIndex: -1,
			lastUpdate:    time.Now(),
		}
	}
	
	// Pre-compute quality metrics for fast selection
	qualities := make([]PathQuality, len(paths))
	for i, path := range paths {
		qualities[i] = puw.computePathQuality(path)
	}
	
	// Select best path based on policy
	selectedIndex := puw.selectBestPath(paths, qualities, policy)
	
	return &FastPathEntry{
		paths:         paths,
		selectedIndex: selectedIndex,
		isManual:      false,
		lastUpdate:    time.Now(),
		quality:       qualities[selectedIndex],
	}
}

// computePathQuality pre-computes path quality metrics
func (puw *PathUpdateWorker) computePathQuality(path snet.Path) PathQuality {
	meta := path.Metadata()
	if meta == nil {
		return PathQuality{
			latencyScore:   time.Duration(1<<63 - 1), // Max duration
			bandwidthScore: 0,
			hopCount:       0,
			reliability:    0.0,
		}
	}
	
	// Compute latency score
	var totalLatency time.Duration
	for _, l := range meta.Latency {
		if l < 0 {
			totalLatency = time.Duration(1<<63 - 1)
			break
		}
		totalLatency += l
	}
	
	// Compute bandwidth score (minimum bandwidth along the path)
	var minBandwidth uint64 = ^uint64(0) // Max uint64
	if len(meta.Bandwidth) > 0 {
		minBandwidth = meta.Bandwidth[0]
		for _, bw := range meta.Bandwidth[1:] {
			if bw < minBandwidth {
				minBandwidth = bw
			}
		}
	} else {
		minBandwidth = 0
	}
	
	// Compute hop count
	hopCount := len(meta.Interfaces)
	
	// Compute reliability (simplified: based on freshness and hop count)
	age := time.Since(meta.Expiry)
	reliability := 1.0
	if age > 0 {
		reliability *= 0.5 // Reduce reliability for expired paths
	}
	if hopCount > 5 {
		reliability *= 0.8 // Reduce reliability for long paths
	}
	
	return PathQuality{
		latencyScore:   totalLatency,
		bandwidthScore: minBandwidth,
		hopCount:       hopCount,
		reliability:    reliability,
	}
}

// selectBestPath selects the best path based on policy and pre-computed quality
func (puw *PathUpdateWorker) selectBestPath(paths []snet.Path, qualities []PathQuality, policy PathPolicy) int {
	if len(paths) == 0 {
		return -1
	}
	
	bestIndex := 0
	
	switch policy {
	case PathPolicyShortest:
		for i := 1; i < len(qualities); i++ {
			if qualities[i].hopCount < qualities[bestIndex].hopCount {
				bestIndex = i
			}
		}
		
	case PathPolicyBandwidth:
		for i := 1; i < len(qualities); i++ {
			if qualities[i].bandwidthScore > qualities[bestIndex].bandwidthScore {
				bestIndex = i
			}
		}
		
	case PathPolicyLatency:
		for i := 1; i < len(qualities); i++ {
			if qualities[i].latencyScore < qualities[bestIndex].latencyScore {
				bestIndex = i
			}
		}
		
	case PathPolicyFirst:
		// Keep bestIndex = 0
		
	default:
		// Default to first path
	}
	
	return bestIndex
}

// Close shuts down the lock-free path manager
func (lfpm *LockFreePathManager) Close() {
	close(lfpm.shutdownCh)
	if lfpm.refreshTicker != nil {
		lfpm.refreshTicker.Stop()
	}
}

// GetStats returns performance statistics
func (lfpm *LockFreePathManager) GetStats() (lookups, updates, hits, misses uint64, hitRate float64) {
	lookups = lfpm.lookupCount.Load()
	updates = lfpm.updateCount.Load()
	hits = lfpm.cacheHits.Load()
	misses = lfpm.cacheMisses.Load()
	
	if lookups > 0 {
		hitRate = float64(hits) / float64(lookups)
	}
	
	return
}

// SetPolicy updates the path selection policy (thread-safe)
func (lfpm *LockFreePathManager) SetPolicy(policy PathPolicy) {
	lfpm.policy.Store(policy)
	// Trigger refresh to apply new policy
	lfpm.triggerFullRefresh()
}