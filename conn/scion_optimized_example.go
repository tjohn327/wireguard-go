/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

// OptimizedScionConnector demonstrates how to use all performance optimizations together
type OptimizedScionConnector struct {
	// Core components
	batchConn      *ScionBatchConn
	offloadManager *AdaptiveOffloadManager
	pathManager    *LockFreePathManager
	poolManager    *OptimizedPoolManager
	perfMonitor    *ScionPerformanceMonitor
	serializer     *OptimizedBatchSerializer

	// Configuration
	localIA addr.IA
	logger  Logger

	// Performance settings
	enabledOptimizations uint32
}

// OptimizationFeature defines different optimization features that can be enabled
type OptimizationFeature uint32

const (
	OptimizationAdaptiveOffload OptimizationFeature = 1 << iota
	OptimizationLockFreePaths
	OptimizationOptimizedPools
	OptimizationTemplateSerializer
	OptimizationPerformanceMonitoring
	OptimizationAll = OptimizationAdaptiveOffload | OptimizationLockFreePaths |
		OptimizationOptimizedPools | OptimizationTemplateSerializer |
		OptimizationPerformanceMonitoring
)

// ExampleLogger implements the Logger interface for demonstration
type ExampleLogger struct{}

func (el *ExampleLogger) Verbosef(format string, args ...interface{}) {
	log.Printf("[VERBOSE] "+format, args...)
}

func (el *ExampleLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

// NewOptimizedScionConnector creates a new optimized SCION connector with all performance features
func NewOptimizedScionConnector(localIA addr.IA, localIP net.IP, port uint16, daemonAddr string) (*OptimizedScionConnector, error) {
	logger := &ExampleLogger{}

	// Create UDP connection
	udpAddr := &net.UDPAddr{IP: localIP, Port: int(port)}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}

	// Load SCION configuration
	scionConfig := &ScionConfig{
		LocalIA:    localIA,
		LocalIP:    localIP,
		LocalPort:  port,
		DaemonAddr: daemonAddr,
		PathPolicy: PathPolicyBandwidth, // Use bandwidth-optimized paths
	}

	// Create SCION network bind with all optimizations
	scionBind := NewScionNetBind(scionConfig, logger)

	// Initialize the bind to create internal components
	_, actualPort, err := scionBind.Open(port)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to open SCION bind: %w", err)
	}

	// Extract optimized components from the bind
	var batchConn *ScionBatchConn
	var offloadManager *AdaptiveOffloadManager
	var pathManager *LockFreePathManager
	var poolManager *OptimizedPoolManager
	var perfMonitor *ScionPerformanceMonitor

	// Access internal components (this would normally be done differently in production)
	// For this example, we'll create them directly
	offloadManager = NewAdaptiveOffloadManager(udpConn)
	pathManager = NewLockFreePathManager(scionBind.daemonConn, localIA, PathPolicyBandwidth, logger)
	poolManager = NewOptimizedPoolManager()
	perfMonitor = NewScionPerformanceMonitor()
	serializer := NewOptimizedBatchSerializer()

	// Create batch connection with all optimizations
	batchConnConfig := ScionBatchConnConfig{
		EnableIPv4TxOffload: true, // Will be managed by adaptive system
		EnableIPv6TxOffload: true,
		EnableIPv4RxOffload: false, // Conservative default
		EnableIPv6RxOffload: false,
	}

	batchConn = NewScionBatchConnWithConfig(
		udpConn, localIA, scionBind.scionNetwork.Topology,
		scionBind.pathManager, logger, batchConnConfig)

	connector := &OptimizedScionConnector{
		batchConn:            batchConn,
		offloadManager:       offloadManager,
		pathManager:          pathManager,
		poolManager:          poolManager,
		perfMonitor:          perfMonitor,
		serializer:           serializer,
		localIA:              localIA,
		logger:               logger,
		enabledOptimizations: uint32(OptimizationAll),
	}

	logger.Verbosef("Created optimized SCION connector on port %d with all performance features enabled", actualPort)

	return connector, nil
}

// SendOptimized demonstrates optimized packet sending with all features
func (osc *OptimizedScionConnector) SendOptimized(destIA addr.IA, destHost net.IP, destPort uint16, payloads [][]byte) error {
	if len(payloads) == 0 {
		return nil
	}

	startTime := time.Now()

	// Get optimal path using lock-free manager
	path, pathFound := osc.pathManager.GetPathFast(destIA)
	if !pathFound {
		// Register destination for future fast lookups
		osc.pathManager.RegisterDestinationFast(destIA)
		osc.perfMonitor.RecordError(ErrorTypePath)
		return fmt.Errorf("no path found for destination %s", destIA)
	}

	// Record path lookup success
	osc.perfMonitor.RecordPathEvent(PathEventCacheHit, time.Since(startTime))

	// Create SCION endpoint
	scionAddr := &snet.UDPAddr{
		IA: destIA,
		Host: &net.UDPAddr{
			IP:   destHost,
			Port: int(destPort),
		},
		Path:    path.Dataplane(),
		NextHop: path.UnderlayNextHop(),
	}

	endpoint := &ScionNetEndpoint{
		scionAddr: scionAddr,
	}
	endpoint.StdNetEndpoint.AddrPort = netip.AddrPortFrom(
		netip.MustParseAddr(scionAddr.NextHop.IP.String()),
		uint16(scionAddr.NextHop.Port),
	)

	// Use optimized batch sending
	err := osc.batchConn.WriteBatch(payloads, endpoint)
	if err != nil {
		osc.perfMonitor.RecordError(ErrorTypeTransmit)
		return fmt.Errorf("optimized send failed: %w", err)
	}

	// Record successful transmission
	totalBytes := 0
	for _, payload := range payloads {
		totalBytes += len(payload)
	}

	sendLatency := time.Since(startTime)
	for range payloads {
		osc.perfMonitor.RecordTransmit(totalBytes/len(payloads), sendLatency/time.Duration(len(payloads)))
	}

	return nil
}

// ReceiveOptimized demonstrates optimized packet receiving
func (osc *OptimizedScionConnector) ReceiveOptimized(maxPackets int) ([][]byte, []Endpoint, error) {
	bufs := make([][]byte, maxPackets)
	sizes := make([]int, maxPackets)
	endpoints := make([]Endpoint, maxPackets)

	// Get buffers from optimized pool
	for i := range bufs {
		bufs[i] = osc.poolManager.GetBuffer(1500) // Standard MTU
	}

	startTime := time.Now()

	// Use batch receiving
	numReceived, err := osc.batchConn.ReadBatch(bufs, sizes, endpoints)
	if err != nil {
		osc.perfMonitor.RecordError(ErrorTypeReceive)
		// Return buffers to pool
		for i := range bufs {
			if bufs[i] != nil {
				osc.poolManager.PutBuffer(bufs[i])
			}
		}
		return nil, nil, fmt.Errorf("optimized receive failed: %w", err)
	}

	receiveLatency := time.Since(startTime)

	// Process received packets
	receivedBufs := make([][]byte, numReceived)
	receivedEndpoints := make([]Endpoint, numReceived)

	for i := 0; i < numReceived; i++ {
		if sizes[i] > 0 {
			// Create properly sized buffer with received data
			receivedBufs[i] = make([]byte, sizes[i])
			copy(receivedBufs[i], bufs[i][:sizes[i]])
			receivedEndpoints[i] = endpoints[i]

			// Record successful reception
			osc.perfMonitor.RecordReceive(sizes[i], receiveLatency/time.Duration(numReceived))
		}

		// Return original buffer to pool
		osc.poolManager.PutBuffer(bufs[i])
	}

	// Return unused buffers to pool
	for i := numReceived; i < len(bufs); i++ {
		if bufs[i] != nil {
			osc.poolManager.PutBuffer(bufs[i])
		}
	}

	return receivedBufs[:numReceived], receivedEndpoints[:numReceived], nil
}

// GetPerformanceStats returns comprehensive performance statistics
func (osc *OptimizedScionConnector) GetPerformanceStats() (string, error) {
	// Update component metrics in performance monitor
	osc.perfMonitor.UpdatePoolMetrics(osc.poolManager)
	osc.perfMonitor.UpdateSerializationMetrics(osc.serializer)

	// Get path manager stats
	lookups, updates, hits, misses, hitRate := osc.pathManager.GetStats()
	osc.perfMonitor.pathMetrics.PathLookups.Store(lookups)
	osc.perfMonitor.pathMetrics.PathUpdates.Store(updates)
	osc.perfMonitor.pathMetrics.PathCacheHits.Store(hits)
	osc.perfMonitor.pathMetrics.PathCacheMisses.Store(misses)

	// Get offload manager stats
	txEnabled, rxEnabled, inFallback, fallbackReason := osc.offloadManager.GetStatus()

	// Create comprehensive stats
	perfSnapshot := osc.perfMonitor.GetSnapshot()

	statsJSON, err := osc.perfMonitor.GetSnapshotJSON()
	if err != nil {
		return "", fmt.Errorf("failed to get performance stats: %w", err)
	}

	// Add additional optimization-specific information
	optimizationInfo := fmt.Sprintf(`
Optimization Status:
- Adaptive Offload: TX=%v, RX=%v, Fallback=%v (%s)
- Lock-Free Paths: Hit Rate=%.2f%%, Active Paths=%d
- Memory Pools: Hit Rate=%.2f%%, Memory Pressure=%d%%
- Template Serialization: Hit Rate=%.2f%%
- Performance Monitoring: Enabled, Uptime=%.1fs

Hardware Profile: %s
`,
		txEnabled, rxEnabled, inFallback, fallbackReason,
		hitRate*100, osc.pathManager.updateCount.Load(),
		perfSnapshot.Pools.HitRate*100, perfSnapshot.Pools.MemoryPressure,
		perfSnapshot.Serialization.TemplateHitRate*100,
		perfSnapshot.UptimeSeconds,
		osc.offloadManager.GetProfile().Name)

	return optimizationInfo + "\n" + statsJSON, nil
}

// OptimizeForWorkload adjusts optimization settings based on expected workload
func (osc *OptimizedScionConnector) OptimizeForWorkload(workloadType WorkloadType) {
	switch workloadType {
	case WorkloadHighThroughput:
		// Optimize for maximum throughput
		osc.perfMonitor.SetSamplingRate(0.1) // Sample 10% to reduce overhead
		osc.perfMonitor.SetEnabledMetrics(MetricCategoryBasic | MetricCategoryThroughput)

	case WorkloadLowLatency:
		// Optimize for minimum latency
		osc.perfMonitor.SetSamplingRate(1.0) // Sample everything for detailed latency tracking
		osc.perfMonitor.SetEnabledMetrics(MetricCategoryAll)

	case WorkloadMixed:
		// Balanced optimization
		osc.perfMonitor.SetSamplingRate(0.5) // Sample 50%
		osc.perfMonitor.SetEnabledMetrics(MetricCategoryAll)

	case WorkloadResourceConstrained:
		// Minimize resource usage
		osc.perfMonitor.SetSamplingRate(0.01) // Sample 1%
		osc.perfMonitor.SetEnabledMetrics(MetricCategoryBasic | MetricCategoryErrors)
	}

	osc.logger.Verbosef("Optimized for workload type: %v", workloadType)
}

// WorkloadType defines different types of expected workloads
type WorkloadType int

const (
	WorkloadHighThroughput WorkloadType = iota
	WorkloadLowLatency
	WorkloadMixed
	WorkloadResourceConstrained
)

// Close properly shuts down all optimization components
func (osc *OptimizedScionConnector) Close() error {
	var errors []error

	if osc.batchConn != nil {
		if err := osc.batchConn.Close(); err != nil {
			errors = append(errors, fmt.Errorf("batch conn close: %w", err))
		}
	}

	if osc.pathManager != nil {
		osc.pathManager.Close()
	}

	// Performance monitor doesn't need explicit cleanup as it uses atomic operations

	osc.logger.Verbosef("Optimized SCION connector closed")

	if len(errors) > 0 {
		return errors[0]
	}
	return nil
}

// ExampleUsage demonstrates how to use the optimized SCION connector
func ExampleUsage() {
	// Parse local IA
	localIA, err := addr.ParseIA("1-ff00:0:110")
	if err != nil {
		log.Fatalf("Failed to parse IA: %v", err)
	}

	// Create optimized connector
	connector, err := NewOptimizedScionConnector(
		localIA,
		net.ParseIP("127.0.0.1"),
		31000,             // SCION port range
		"127.0.0.1:30255", // SCION daemon
	)
	if err != nil {
		log.Fatalf("Failed to create optimized connector: %v", err)
	}
	defer connector.Close()

	// Optimize for high throughput workload
	connector.OptimizeForWorkload(WorkloadHighThroughput)

	// Example: Send multiple packets efficiently
	destIA, _ := addr.ParseIA("1-ff00:0:111")
	payloads := [][]byte{
		[]byte("Hello SCION 1"),
		[]byte("Hello SCION 2"),
		[]byte("Hello SCION 3"),
	}

	err = connector.SendOptimized(destIA, net.ParseIP("192.168.1.100"), 31001, payloads)
	if err != nil {
		log.Printf("Send failed: %v", err)
	}

	// Example: Receive packets efficiently
	receivedBufs, endpoints, err := connector.ReceiveOptimized(10)
	if err != nil {
		log.Printf("Receive failed: %v", err)
	} else {
		log.Printf("Received %d packets from %d endpoints", len(receivedBufs), len(endpoints))
	}

	// Get comprehensive performance statistics
	stats, err := connector.GetPerformanceStats()
	if err != nil {
		log.Printf("Failed to get stats: %v", err)
	} else {
		log.Printf("Performance Stats:\n%s", stats)
	}
}
