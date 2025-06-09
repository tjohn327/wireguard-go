/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ScionPerformanceMonitor provides comprehensive performance monitoring for SCION connections
type ScionPerformanceMonitor struct {
	mu sync.RWMutex

	// Basic performance counters
	packetsTransmitted atomic.Uint64
	packetsReceived    atomic.Uint64
	bytesTransmitted   atomic.Uint64
	bytesReceived      atomic.Uint64

	// Error counters
	transmitErrors      atomic.Uint64
	receiveErrors       atomic.Uint64
	pathErrors          atomic.Uint64
	serializationErrors atomic.Uint64

	// Latency tracking
	txLatencySum   atomic.Uint64 // nanoseconds
	rxLatencySum   atomic.Uint64 // nanoseconds
	txLatencyCount atomic.Uint64
	rxLatencyCount atomic.Uint64
	maxTxLatency   atomic.Uint64 // nanoseconds
	maxRxLatency   atomic.Uint64 // nanoseconds

	// Throughput tracking
	lastThroughputCheck time.Time
	prevTxPackets       uint64
	prevRxPackets       uint64
	currentTxThroughput atomic.Uint64 // packets per second
	currentRxThroughput atomic.Uint64 // packets per second

	// Performance buckets for detailed analysis
	latencyBuckets [10]atomic.Uint64 // Latency distribution
	sizeBuckets    [8]atomic.Uint64  // Packet size distribution

	// Component-specific metrics
	offloadMetrics       OffloadMetrics
	pathMetrics          PathMetrics
	poolMetrics          PoolMetrics
	serializationMetrics SerializationMetrics

	// Configuration
	enabledMetrics uint32  // Bitfield for enabled metric categories
	samplingRate   float64 // 0.0 to 1.0, controls sampling frequency

	// Monitoring state
	startTime         time.Time
	lastResetTime     time.Time
	monitoringEnabled atomic.Bool
}

// OffloadMetrics tracks hardware offload performance
type OffloadMetrics struct {
	GSO_Attempts      atomic.Uint64
	GSO_Successes     atomic.Uint64
	GSO_Failures      atomic.Uint64
	GRO_Attempts      atomic.Uint64
	GRO_Successes     atomic.Uint64
	GRO_Failures      atomic.Uint64
	OffloadDisabled   atomic.Uint64 // Times offload was disabled due to errors
	FallbackActivated atomic.Uint64 // Times fallback mode was activated
}

// PathMetrics tracks SCION path management performance
type PathMetrics struct {
	PathLookups       atomic.Uint64
	PathCacheHits     atomic.Uint64
	PathCacheMisses   atomic.Uint64
	PathUpdates       atomic.Uint64
	PathFailures      atomic.Uint64
	PathSelectionTime atomic.Uint64 // Total time in nanoseconds
	ActivePaths       atomic.Uint64 // Current number of active paths
}

// PoolMetrics tracks memory pool efficiency
type PoolMetrics struct {
	PoolAllocations   atomic.Uint64
	PoolDeallocations atomic.Uint64
	PoolHits          atomic.Uint64
	PoolMisses        atomic.Uint64
	MemoryPressure    atomic.Uint32 // 0-100
	GCTriggered       atomic.Uint64
}

// SerializationMetrics tracks packet serialization performance
type SerializationMetrics struct {
	TemplateHits       atomic.Uint64
	TemplateMisses     atomic.Uint64
	TemplateCreations  atomic.Uint64
	FastSerializations atomic.Uint64
	SlowSerializations atomic.Uint64
	SerializationTime  atomic.Uint64 // Total time in nanoseconds
}

// MetricCategory defines different categories of metrics that can be enabled/disabled
type MetricCategory uint32

const (
	MetricCategoryBasic MetricCategory = 1 << iota
	MetricCategoryLatency
	MetricCategoryThroughput
	MetricCategoryErrors
	MetricCategoryOffload
	MetricCategoryPaths
	MetricCategoryPools
	MetricCategorySerialization
	MetricCategoryAll = MetricCategoryBasic | MetricCategoryLatency | MetricCategoryThroughput |
		MetricCategoryErrors | MetricCategoryOffload | MetricCategoryPaths |
		MetricCategoryPools | MetricCategorySerialization
)

// NewScionPerformanceMonitor creates a new performance monitor
func NewScionPerformanceMonitor() *ScionPerformanceMonitor {
	monitor := &ScionPerformanceMonitor{
		startTime:           time.Now(),
		lastResetTime:       time.Now(),
		lastThroughputCheck: time.Now(),
		samplingRate:        1.0, // Sample all events by default
		enabledMetrics:      uint32(MetricCategoryAll),
	}

	monitor.monitoringEnabled.Store(true)

	// Start background throughput calculator
	go monitor.throughputCalculator()

	return monitor
}

// RecordTransmit records a packet transmission event
func (spm *ScionPerformanceMonitor) RecordTransmit(packetSize int, latency time.Duration) {
	if !spm.isEnabled(MetricCategoryBasic) {
		return
	}

	if !spm.shouldSample() {
		return
	}

	spm.packetsTransmitted.Add(1)
	spm.bytesTransmitted.Add(uint64(packetSize))

	if spm.isEnabled(MetricCategoryLatency) && latency > 0 {
		latencyNs := uint64(latency.Nanoseconds())
		spm.txLatencySum.Add(latencyNs)
		spm.txLatencyCount.Add(1)

		// Update max latency
		for {
			currentMax := spm.maxTxLatency.Load()
			if latencyNs <= currentMax || spm.maxTxLatency.CompareAndSwap(currentMax, latencyNs) {
				break
			}
		}

		// Update latency bucket
		spm.updateLatencyBucket(latency)
	}

	if spm.isEnabled(MetricCategoryThroughput) {
		spm.updateSizeBucket(packetSize)
	}
}

// RecordReceive records a packet reception event
func (spm *ScionPerformanceMonitor) RecordReceive(packetSize int, latency time.Duration) {
	if !spm.isEnabled(MetricCategoryBasic) {
		return
	}

	if !spm.shouldSample() {
		return
	}

	spm.packetsReceived.Add(1)
	spm.bytesReceived.Add(uint64(packetSize))

	if spm.isEnabled(MetricCategoryLatency) && latency > 0 {
		latencyNs := uint64(latency.Nanoseconds())
		spm.rxLatencySum.Add(latencyNs)
		spm.rxLatencyCount.Add(1)

		// Update max latency
		for {
			currentMax := spm.maxRxLatency.Load()
			if latencyNs <= currentMax || spm.maxRxLatency.CompareAndSwap(currentMax, latencyNs) {
				break
			}
		}
	}
}

// RecordError records various types of errors
func (spm *ScionPerformanceMonitor) RecordError(errorType ErrorType) {
	if !spm.isEnabled(MetricCategoryErrors) {
		return
	}

	switch errorType {
	case ErrorTypeTransmit:
		spm.transmitErrors.Add(1)
	case ErrorTypeReceive:
		spm.receiveErrors.Add(1)
	case ErrorTypePath:
		spm.pathErrors.Add(1)
	case ErrorTypeSerialization:
		spm.serializationErrors.Add(1)
	}
}

// ErrorType defines different types of errors
type ErrorType int

const (
	ErrorTypeTransmit ErrorType = iota
	ErrorTypeReceive
	ErrorTypePath
	ErrorTypeSerialization
)

// RecordOffloadEvent records hardware offload events
func (spm *ScionPerformanceMonitor) RecordOffloadEvent(eventType OffloadEventType) {
	if !spm.isEnabled(MetricCategoryOffload) {
		return
	}

	switch eventType {
	case OffloadEventGSOAttempt:
		spm.offloadMetrics.GSO_Attempts.Add(1)
	case OffloadEventGSOSuccess:
		spm.offloadMetrics.GSO_Successes.Add(1)
	case OffloadEventGSOFailure:
		spm.offloadMetrics.GSO_Failures.Add(1)
	case OffloadEventGROAttempt:
		spm.offloadMetrics.GRO_Attempts.Add(1)
	case OffloadEventGROSuccess:
		spm.offloadMetrics.GRO_Successes.Add(1)
	case OffloadEventGROFailure:
		spm.offloadMetrics.GRO_Failures.Add(1)
	case OffloadEventDisabled:
		spm.offloadMetrics.OffloadDisabled.Add(1)
	case OffloadEventFallback:
		spm.offloadMetrics.FallbackActivated.Add(1)
	}
}

// OffloadEventType defines different hardware offload events
type OffloadEventType int

const (
	OffloadEventGSOAttempt OffloadEventType = iota
	OffloadEventGSOSuccess
	OffloadEventGSOFailure
	OffloadEventGROAttempt
	OffloadEventGROSuccess
	OffloadEventGROFailure
	OffloadEventDisabled
	OffloadEventFallback
)

// RecordPathEvent records path management events
func (spm *ScionPerformanceMonitor) RecordPathEvent(eventType PathEventType, duration time.Duration) {
	if !spm.isEnabled(MetricCategoryPaths) {
		return
	}

	switch eventType {
	case PathEventLookup:
		spm.pathMetrics.PathLookups.Add(1)
		if duration > 0 {
			spm.pathMetrics.PathSelectionTime.Add(uint64(duration.Nanoseconds()))
		}
	case PathEventCacheHit:
		spm.pathMetrics.PathCacheHits.Add(1)
	case PathEventCacheMiss:
		spm.pathMetrics.PathCacheMisses.Add(1)
	case PathEventUpdate:
		spm.pathMetrics.PathUpdates.Add(1)
	case PathEventFailure:
		spm.pathMetrics.PathFailures.Add(1)
	}
}

// PathEventType defines different path management events
type PathEventType int

const (
	PathEventLookup PathEventType = iota
	PathEventCacheHit
	PathEventCacheMiss
	PathEventUpdate
	PathEventFailure
)

// UpdatePoolMetrics updates pool performance metrics
func (spm *ScionPerformanceMonitor) UpdatePoolMetrics(poolManager *OptimizedPoolManager) {
	if !spm.isEnabled(MetricCategoryPools) || poolManager == nil {
		return
	}

	allocs, deallocs, hits, misses, _, memPressure := poolManager.GetStats()

	spm.poolMetrics.PoolAllocations.Store(allocs)
	spm.poolMetrics.PoolDeallocations.Store(deallocs)
	spm.poolMetrics.PoolHits.Store(hits)
	spm.poolMetrics.PoolMisses.Store(misses)
	spm.poolMetrics.MemoryPressure.Store(memPressure)
}

// UpdateSerializationMetrics updates serialization performance metrics
func (spm *ScionPerformanceMonitor) UpdateSerializationMetrics(serializer *OptimizedBatchSerializer) {
	if !spm.isEnabled(MetricCategorySerialization) || serializer == nil {
		return
	}

	_, hits, misses, _ := serializer.GetStats()

	spm.serializationMetrics.TemplateHits.Store(hits)
	spm.serializationMetrics.TemplateMisses.Store(misses)
}

// isEnabled checks if a metric category is enabled
func (spm *ScionPerformanceMonitor) isEnabled(category MetricCategory) bool {
	return spm.monitoringEnabled.Load() && (spm.enabledMetrics&uint32(category)) != 0
}

// shouldSample determines if an event should be sampled based on sampling rate
func (spm *ScionPerformanceMonitor) shouldSample() bool {
	if spm.samplingRate >= 1.0 {
		return true
	}
	// Simple sampling - could be enhanced with more sophisticated algorithms
	return (spm.packetsTransmitted.Load() % uint64(1.0/spm.samplingRate)) == 0
}

// updateLatencyBucket updates latency distribution buckets
func (spm *ScionPerformanceMonitor) updateLatencyBucket(latency time.Duration) {
	// Latency buckets: <1ms, 1-5ms, 5-10ms, 10-20ms, 20-50ms, 50-100ms, 100-200ms, 200-500ms, 500ms-1s, >1s
	ms := latency.Milliseconds()

	var bucket int
	switch {
	case ms < 1:
		bucket = 0
	case ms < 5:
		bucket = 1
	case ms < 10:
		bucket = 2
	case ms < 20:
		bucket = 3
	case ms < 50:
		bucket = 4
	case ms < 100:
		bucket = 5
	case ms < 200:
		bucket = 6
	case ms < 500:
		bucket = 7
	case ms < 1000:
		bucket = 8
	default:
		bucket = 9
	}

	spm.latencyBuckets[bucket].Add(1)
}

// updateSizeBucket updates packet size distribution buckets
func (spm *ScionPerformanceMonitor) updateSizeBucket(size int) {
	// Size buckets: <64, 64-128, 128-256, 256-512, 512-1024, 1024-1500, 1500-4096, >4096
	var bucket int
	switch {
	case size < 64:
		bucket = 0
	case size < 128:
		bucket = 1
	case size < 256:
		bucket = 2
	case size < 512:
		bucket = 3
	case size < 1024:
		bucket = 4
	case size < 1500:
		bucket = 5
	case size < 4096:
		bucket = 6
	default:
		bucket = 7
	}

	spm.sizeBuckets[bucket].Add(1)
}

// throughputCalculator runs in background to calculate throughput metrics
func (spm *ScionPerformanceMonitor) throughputCalculator() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !spm.isEnabled(MetricCategoryThroughput) {
			continue
		}

		now := time.Now()
		elapsed := now.Sub(spm.lastThroughputCheck).Seconds()

		if elapsed >= 1.0 {
			currentTx := spm.packetsTransmitted.Load()
			currentRx := spm.packetsReceived.Load()

			txThroughput := uint64(float64(currentTx-spm.prevTxPackets) / elapsed)
			rxThroughput := uint64(float64(currentRx-spm.prevRxPackets) / elapsed)

			spm.currentTxThroughput.Store(txThroughput)
			spm.currentRxThroughput.Store(rxThroughput)

			spm.prevTxPackets = currentTx
			spm.prevRxPackets = currentRx
			spm.lastThroughputCheck = now
		}
	}
}

// PerformanceSnapshot represents a snapshot of performance metrics
type PerformanceSnapshot struct {
	Timestamp     time.Time `json:"timestamp"`
	UptimeSeconds float64   `json:"uptime_seconds"`

	// Basic metrics
	PacketsTransmitted uint64 `json:"packets_transmitted"`
	PacketsReceived    uint64 `json:"packets_received"`
	BytesTransmitted   uint64 `json:"bytes_transmitted"`
	BytesReceived      uint64 `json:"bytes_received"`

	// Throughput
	TxThroughputPPS uint64 `json:"tx_throughput_pps"`
	RxThroughputPPS uint64 `json:"rx_throughput_pps"`

	// Latency
	AvgTxLatencyMs float64 `json:"avg_tx_latency_ms"`
	AvgRxLatencyMs float64 `json:"avg_rx_latency_ms"`
	MaxTxLatencyMs float64 `json:"max_tx_latency_ms"`
	MaxRxLatencyMs float64 `json:"max_rx_latency_ms"`

	// Errors
	TransmitErrors      uint64 `json:"transmit_errors"`
	ReceiveErrors       uint64 `json:"receive_errors"`
	PathErrors          uint64 `json:"path_errors"`
	SerializationErrors uint64 `json:"serialization_errors"`

	// Component metrics
	Offload       OffloadSnapshot         `json:"offload"`
	Paths         PathPerformanceSnapshot `json:"paths"`
	Pools         PoolSnapshot            `json:"pools"`
	Serialization SerializationSnapshot   `json:"serialization"`

	// Distribution data
	LatencyDistribution [10]uint64 `json:"latency_distribution"`
	SizeDistribution    [8]uint64  `json:"size_distribution"`
}

// Component-specific snapshot types
type OffloadSnapshot struct {
	GSOSuccessRate  float64 `json:"gso_success_rate"`
	GROSuccessRate  float64 `json:"gro_success_rate"`
	OffloadDisabled uint64  `json:"offload_disabled"`
	FallbackActive  uint64  `json:"fallback_active"`
}

type PathPerformanceSnapshot struct {
	CacheHitRate       float64 `json:"cache_hit_rate"`
	ActivePaths        uint64  `json:"active_paths"`
	AvgSelectionTimeMs float64 `json:"avg_selection_time_ms"`
	PathFailures       uint64  `json:"path_failures"`
}

type PoolSnapshot struct {
	HitRate        float64 `json:"hit_rate"`
	MemoryPressure uint32  `json:"memory_pressure"`
	GCTriggered    uint64  `json:"gc_triggered"`
}

type SerializationSnapshot struct {
	TemplateHitRate    float64 `json:"template_hit_rate"`
	FastSerializations uint64  `json:"fast_serializations"`
	SlowSerializations uint64  `json:"slow_serializations"`
}

// GetSnapshot returns a snapshot of current performance metrics
func (spm *ScionPerformanceMonitor) GetSnapshot() PerformanceSnapshot {
	now := time.Now()

	// Calculate averages
	var avgTxLatency, avgRxLatency float64
	if txCount := spm.txLatencyCount.Load(); txCount > 0 {
		avgTxLatency = float64(spm.txLatencySum.Load()) / float64(txCount) / 1e6 // Convert to ms
	}
	if rxCount := spm.rxLatencyCount.Load(); rxCount > 0 {
		avgRxLatency = float64(spm.rxLatencySum.Load()) / float64(rxCount) / 1e6 // Convert to ms
	}

	// Calculate rates
	var gsoSuccessRate, groSuccessRate float64
	if attempts := spm.offloadMetrics.GSO_Attempts.Load(); attempts > 0 {
		gsoSuccessRate = float64(spm.offloadMetrics.GSO_Successes.Load()) / float64(attempts)
	}
	if attempts := spm.offloadMetrics.GRO_Attempts.Load(); attempts > 0 {
		groSuccessRate = float64(spm.offloadMetrics.GRO_Successes.Load()) / float64(attempts)
	}

	var pathHitRate float64
	if lookups := spm.pathMetrics.PathLookups.Load(); lookups > 0 {
		pathHitRate = float64(spm.pathMetrics.PathCacheHits.Load()) / float64(lookups)
	}

	var poolHitRate float64
	if total := spm.poolMetrics.PoolHits.Load() + spm.poolMetrics.PoolMisses.Load(); total > 0 {
		poolHitRate = float64(spm.poolMetrics.PoolHits.Load()) / float64(total)
	}

	var templateHitRate float64
	if total := spm.serializationMetrics.TemplateHits.Load() + spm.serializationMetrics.TemplateMisses.Load(); total > 0 {
		templateHitRate = float64(spm.serializationMetrics.TemplateHits.Load()) / float64(total)
	}

	var avgPathSelectionTime float64
	if lookups := spm.pathMetrics.PathLookups.Load(); lookups > 0 {
		avgPathSelectionTime = float64(spm.pathMetrics.PathSelectionTime.Load()) / float64(lookups) / 1e6 // Convert to ms
	}

	// Copy distribution arrays
	var latencyDist [10]uint64
	var sizeDist [8]uint64
	for i := 0; i < 10; i++ {
		latencyDist[i] = spm.latencyBuckets[i].Load()
	}
	for i := 0; i < 8; i++ {
		sizeDist[i] = spm.sizeBuckets[i].Load()
	}

	return PerformanceSnapshot{
		Timestamp:           now,
		UptimeSeconds:       now.Sub(spm.startTime).Seconds(),
		PacketsTransmitted:  spm.packetsTransmitted.Load(),
		PacketsReceived:     spm.packetsReceived.Load(),
		BytesTransmitted:    spm.bytesTransmitted.Load(),
		BytesReceived:       spm.bytesReceived.Load(),
		TxThroughputPPS:     spm.currentTxThroughput.Load(),
		RxThroughputPPS:     spm.currentRxThroughput.Load(),
		AvgTxLatencyMs:      avgTxLatency,
		AvgRxLatencyMs:      avgRxLatency,
		MaxTxLatencyMs:      float64(spm.maxTxLatency.Load()) / 1e6,
		MaxRxLatencyMs:      float64(spm.maxRxLatency.Load()) / 1e6,
		TransmitErrors:      spm.transmitErrors.Load(),
		ReceiveErrors:       spm.receiveErrors.Load(),
		PathErrors:          spm.pathErrors.Load(),
		SerializationErrors: spm.serializationErrors.Load(),

		Offload: OffloadSnapshot{
			GSOSuccessRate:  gsoSuccessRate,
			GROSuccessRate:  groSuccessRate,
			OffloadDisabled: spm.offloadMetrics.OffloadDisabled.Load(),
			FallbackActive:  spm.offloadMetrics.FallbackActivated.Load(),
		},

		Paths: PathPerformanceSnapshot{
			CacheHitRate:       pathHitRate,
			ActivePaths:        spm.pathMetrics.ActivePaths.Load(),
			AvgSelectionTimeMs: avgPathSelectionTime,
			PathFailures:       spm.pathMetrics.PathFailures.Load(),
		},

		Pools: PoolSnapshot{
			HitRate:        poolHitRate,
			MemoryPressure: spm.poolMetrics.MemoryPressure.Load(),
			GCTriggered:    spm.poolMetrics.GCTriggered.Load(),
		},

		Serialization: SerializationSnapshot{
			TemplateHitRate:    templateHitRate,
			FastSerializations: spm.serializationMetrics.FastSerializations.Load(),
			SlowSerializations: spm.serializationMetrics.SlowSerializations.Load(),
		},

		LatencyDistribution: latencyDist,
		SizeDistribution:    sizeDist,
	}
}

// GetSnapshotJSON returns a JSON representation of performance metrics
func (spm *ScionPerformanceMonitor) GetSnapshotJSON() (string, error) {
	snapshot := spm.GetSnapshot()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal performance snapshot: %w", err)
	}
	return string(data), nil
}

// Reset resets all performance counters
func (spm *ScionPerformanceMonitor) Reset() {
	spm.mu.Lock()
	defer spm.mu.Unlock()

	// Reset all atomic counters
	spm.packetsTransmitted.Store(0)
	spm.packetsReceived.Store(0)
	spm.bytesTransmitted.Store(0)
	spm.bytesReceived.Store(0)

	spm.transmitErrors.Store(0)
	spm.receiveErrors.Store(0)
	spm.pathErrors.Store(0)
	spm.serializationErrors.Store(0)

	spm.txLatencySum.Store(0)
	spm.rxLatencySum.Store(0)
	spm.txLatencyCount.Store(0)
	spm.rxLatencyCount.Store(0)
	spm.maxTxLatency.Store(0)
	spm.maxRxLatency.Store(0)

	// Reset component metrics
	spm.resetOffloadMetrics()
	spm.resetPathMetrics()
	spm.resetPoolMetrics()
	spm.resetSerializationMetrics()

	// Reset distribution buckets
	for i := range spm.latencyBuckets {
		spm.latencyBuckets[i].Store(0)
	}
	for i := range spm.sizeBuckets {
		spm.sizeBuckets[i].Store(0)
	}

	spm.lastResetTime = time.Now()
	spm.prevTxPackets = 0
	spm.prevRxPackets = 0
}

// Helper methods to reset component metrics
func (spm *ScionPerformanceMonitor) resetOffloadMetrics() {
	spm.offloadMetrics.GSO_Attempts.Store(0)
	spm.offloadMetrics.GSO_Successes.Store(0)
	spm.offloadMetrics.GSO_Failures.Store(0)
	spm.offloadMetrics.GRO_Attempts.Store(0)
	spm.offloadMetrics.GRO_Successes.Store(0)
	spm.offloadMetrics.GRO_Failures.Store(0)
	spm.offloadMetrics.OffloadDisabled.Store(0)
	spm.offloadMetrics.FallbackActivated.Store(0)
}

func (spm *ScionPerformanceMonitor) resetPathMetrics() {
	spm.pathMetrics.PathLookups.Store(0)
	spm.pathMetrics.PathCacheHits.Store(0)
	spm.pathMetrics.PathCacheMisses.Store(0)
	spm.pathMetrics.PathUpdates.Store(0)
	spm.pathMetrics.PathFailures.Store(0)
	spm.pathMetrics.PathSelectionTime.Store(0)
}

func (spm *ScionPerformanceMonitor) resetPoolMetrics() {
	spm.poolMetrics.PoolAllocations.Store(0)
	spm.poolMetrics.PoolDeallocations.Store(0)
	spm.poolMetrics.PoolHits.Store(0)
	spm.poolMetrics.PoolMisses.Store(0)
	spm.poolMetrics.GCTriggered.Store(0)
}

func (spm *ScionPerformanceMonitor) resetSerializationMetrics() {
	spm.serializationMetrics.TemplateHits.Store(0)
	spm.serializationMetrics.TemplateMisses.Store(0)
	spm.serializationMetrics.TemplateCreations.Store(0)
	spm.serializationMetrics.FastSerializations.Store(0)
	spm.serializationMetrics.SlowSerializations.Store(0)
	spm.serializationMetrics.SerializationTime.Store(0)
}

// SetEnabled enables or disables the performance monitor
func (spm *ScionPerformanceMonitor) SetEnabled(enabled bool) {
	spm.monitoringEnabled.Store(enabled)
}

// SetEnabledMetrics sets which metric categories are enabled
func (spm *ScionPerformanceMonitor) SetEnabledMetrics(categories MetricCategory) {
	spm.mu.Lock()
	defer spm.mu.Unlock()
	spm.enabledMetrics = uint32(categories)
}

// SetSamplingRate sets the sampling rate for metrics collection
func (spm *ScionPerformanceMonitor) SetSamplingRate(rate float64) {
	spm.mu.Lock()
	defer spm.mu.Unlock()
	if rate >= 0.0 && rate <= 1.0 {
		spm.samplingRate = rate
	}
}
