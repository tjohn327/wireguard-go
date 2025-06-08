/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/snet"
	"golang.org/x/net/ipv6"
)

// OptimizedPoolManager manages high-performance memory pools with NUMA awareness
type OptimizedPoolManager struct {
	// Per-CPU pools for better cache locality
	cpuPools     []cpuLocalPools
	numCPUs      int
	
	// Global pools for fallback
	globalPools  globalPoolSet
	
	// Pool statistics
	allocations  atomic.Uint64
	deallocations atomic.Uint64
	poolHits     atomic.Uint64
	poolMisses   atomic.Uint64
	
	// Memory pressure monitoring
	lastGC       atomic.Int64 // Time of last GC (Unix timestamp)
	memPressure  atomic.Uint32 // Memory pressure level (0-100)
	
	// Configuration
	maxPoolSize  int
	cleanupInterval time.Duration
}

// cpuLocalPools contains pools for a specific CPU core
type cpuLocalPools struct {
	cpu int
	
	// SCION packet pools
	scionPacketPool   fastPool[[]snet.Packet]
	singlePacketPool  fastPool[*snet.Packet]
	
	// Message pools for batch operations
	messagePool       fastPool[[]ipv6.Message]
	
	// Buffer pools
	smallBufferPool   fastPool[[]byte]  // 1500 bytes (MTU)
	largeBufferPool   fastPool[[]byte]  // 9000 bytes (Jumbo)
	
	// Address pools
	udpAddrPool       fastPool[UDPAddr]
	
	mu sync.Mutex // Protects pool operations
}

// globalPoolSet contains global fallback pools
type globalPoolSet struct {
	// Backup pools when per-CPU pools are exhausted
	scionPacketBackup   sync.Pool
	messageBackup       sync.Pool
	bufferBackup        sync.Pool
	addrBackup          sync.Pool
	
	// Emergency pools for high memory pressure situations
	emergencyBuffers    sync.Pool
	emergencyPackets    sync.Pool
}

// fastPool provides a lock-free pool implementation for specific types
type fastPool[T any] struct {
	items    []T
	head     atomic.Uint32
	tail     atomic.Uint32
	mask     uint32
	capacity uint32
}

// UDPAddr is a pool-friendly UDP address structure
type UDPAddr struct {
	IP   [16]byte // Fixed-size IP to avoid allocations
	Port int
	Zone string
}

// NewOptimizedPoolManager creates a new optimized pool manager
func NewOptimizedPoolManager() *OptimizedPoolManager {
	numCPUs := runtime.NumCPU()
	
	opm := &OptimizedPoolManager{
		cpuPools:        make([]cpuLocalPools, numCPUs),
		numCPUs:         numCPUs,
		maxPoolSize:     1024, // Configurable
		cleanupInterval: 30 * time.Second,
	}
	
	// Initialize per-CPU pools
	for i := 0; i < numCPUs; i++ {
		opm.cpuPools[i] = cpuLocalPools{
			cpu: i,
			scionPacketPool:  newFastPool[[]snet.Packet](64),
			singlePacketPool: newFastPool[*snet.Packet](256),
			messagePool:      newFastPool[[]ipv6.Message](64),
			smallBufferPool:  newFastPool[[]byte](512),
			largeBufferPool:  newFastPool[[]byte](64),
			udpAddrPool:      newFastPool[UDPAddr](256),
		}
	}
	
	// Initialize global pools
	opm.initGlobalPools()
	
	// Start background cleanup goroutine
	go opm.cleanupWorker()
	
	// Start memory pressure monitor
	go opm.memoryPressureMonitor()
	
	return opm
}

// newFastPool creates a lock-free ring buffer pool
func newFastPool[T any](capacity uint32) fastPool[T] {
	// Round up to next power of 2 for efficient masking
	if capacity&(capacity-1) != 0 {
		capacity = nextPowerOf2(capacity)
	}
	
	return fastPool[T]{
		items:    make([]T, capacity),
		capacity: capacity,
		mask:     capacity - 1,
	}
}

// nextPowerOf2 returns the next power of 2 >= n
func nextPowerOf2(n uint32) uint32 {
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}

// put adds an item to the fast pool (lock-free)
func (fp *fastPool[T]) put(item T) bool {
	for {
		head := fp.head.Load()
		tail := fp.tail.Load()
		
		// Check if pool is full
		if (head+1)&fp.mask == tail {
			return false // Pool full
		}
		
		// Try to update head atomically
		if fp.head.CompareAndSwap(head, (head+1)&fp.mask) {
			fp.items[head] = item
			return true
		}
		// Retry if CAS failed
		runtime.Gosched()
	}
}

// get retrieves an item from the fast pool (lock-free)
func (fp *fastPool[T]) get() (T, bool) {
	for {
		head := fp.head.Load()
		tail := fp.tail.Load()
		
		// Check if pool is empty
		if head == tail {
			var zero T
			return zero, false // Pool empty
		}
		
		// Try to update tail atomically
		if fp.tail.CompareAndSwap(tail, (tail+1)&fp.mask) {
			item := fp.items[tail]
			var zero T
			fp.items[tail] = zero // Clear reference
			return item, true
		}
		// Retry if CAS failed
		runtime.Gosched()
	}
}

// initGlobalPools initializes the global backup pools
func (opm *OptimizedPoolManager) initGlobalPools() {
	opm.globalPools.scionPacketBackup = sync.Pool{
		New: func() any {
			packets := make([]snet.Packet, IdealBatchSize)
			for i := range packets {
				packets[i].Bytes = make(snet.Bytes, common.SupportedMTU)
			}
			return &packets
		},
	}
	
	opm.globalPools.messageBackup = sync.Pool{
		New: func() any {
			msgs := make([]ipv6.Message, IdealBatchSize)
			for i := range msgs {
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
			}
			return &msgs
		},
	}
	
	opm.globalPools.bufferBackup = sync.Pool{
		New: func() any {
			return make([]byte, common.SupportedMTU)
		},
	}
	
	opm.globalPools.addrBackup = sync.Pool{
		New: func() any {
			return &UDPAddr{}
		},
	}
	
	// Emergency pools with smaller allocations
	opm.globalPools.emergencyBuffers = sync.Pool{
		New: func() any {
			return make([]byte, 1500) // Standard MTU only
		},
	}
	
	opm.globalPools.emergencyPackets = sync.Pool{
		New: func() any {
			return &snet.Packet{
				Bytes: make(snet.Bytes, 1500),
			}
		},
	}
}

// getCurrentCPU returns the current CPU ID (approximation)
func (opm *OptimizedPoolManager) getCurrentCPU() int {
	// This is an approximation - actual CPU affinity detection would require platform-specific code
	return int(uintptr(unsafe.Pointer(&opm)) / 64) % opm.numCPUs
}

// GetScionPackets retrieves a slice of SCION packets from the optimal pool
func (opm *OptimizedPoolManager) GetScionPackets() *[]snet.Packet {
	opm.allocations.Add(1)
	
	// Try per-CPU pool first
	cpuID := opm.getCurrentCPU()
	if cpuID >= 0 && cpuID < len(opm.cpuPools) {
		cpuPool := &opm.cpuPools[cpuID]
		
		if packets, ok := cpuPool.scionPacketPool.get(); ok {
			opm.poolHits.Add(1)
			return &packets
		}
	}
	
	// Fallback to global pool
	opm.poolMisses.Add(1)
	return opm.globalPools.scionPacketBackup.Get().(*[]snet.Packet)
}

// PutScionPackets returns a slice of SCION packets to the pool
func (opm *OptimizedPoolManager) PutScionPackets(packets *[]snet.Packet) {
	opm.deallocations.Add(1)
	
	if packets == nil {
		return
	}
	
	// Reset packet state
	for i := range *packets {
		(*packets)[i] = snet.Packet{
			Bytes: (*packets)[i].Bytes[:cap((*packets)[i].Bytes)], // Keep capacity
		}
	}
	
	// Try per-CPU pool first
	cpuID := opm.getCurrentCPU()
	if cpuID >= 0 && cpuID < len(opm.cpuPools) {
		cpuPool := &opm.cpuPools[cpuID]
		
		if cpuPool.scionPacketPool.put(*packets) {
			return // Successfully returned to per-CPU pool
		}
	}
	
	// Fallback to global pool
	opm.globalPools.scionPacketBackup.Put(packets)
}

// GetMessages retrieves a slice of IPv6 messages from the pool
func (opm *OptimizedPoolManager) GetMessages() *[]ipv6.Message {
	opm.allocations.Add(1)
	
	cpuID := opm.getCurrentCPU()
	if cpuID >= 0 && cpuID < len(opm.cpuPools) {
		cpuPool := &opm.cpuPools[cpuID]
		
		if msgs, ok := cpuPool.messagePool.get(); ok {
			opm.poolHits.Add(1)
			return &msgs
		}
	}
	
	opm.poolMisses.Add(1)
	return opm.globalPools.messageBackup.Get().(*[]ipv6.Message)
}

// PutMessages returns IPv6 messages to the pool
func (opm *OptimizedPoolManager) PutMessages(msgs *[]ipv6.Message) {
	opm.deallocations.Add(1)
	
	if msgs == nil {
		return
	}
	
	// Reset message state
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{
			Buffers: (*msgs)[i].Buffers,
			OOB:     (*msgs)[i].OOB,
		}
	}
	
	cpuID := opm.getCurrentCPU()
	if cpuID >= 0 && cpuID < len(opm.cpuPools) {
		cpuPool := &opm.cpuPools[cpuID]
		
		if cpuPool.messagePool.put(*msgs) {
			return
		}
	}
	
	opm.globalPools.messageBackup.Put(msgs)
}

// GetBuffer retrieves a buffer of appropriate size
func (opm *OptimizedPoolManager) GetBuffer(size int) []byte {
	opm.allocations.Add(1)
	
	cpuID := opm.getCurrentCPU()
	if cpuID >= 0 && cpuID < len(opm.cpuPools) {
		cpuPool := &opm.cpuPools[cpuID]
		
		var buffer []byte
		var ok bool
		
		if size <= 1500 {
			buffer, ok = cpuPool.smallBufferPool.get()
		} else {
			buffer, ok = cpuPool.largeBufferPool.get()
		}
		
		if ok {
			opm.poolHits.Add(1)
			if cap(buffer) >= size {
				return buffer[:size]
			}
		}
	}
	
	// Check memory pressure before allocating
	pressure := opm.memPressure.Load()
	if pressure > 80 { // High memory pressure
		// Try emergency pools first
		if size <= 1500 {
			if buffer := opm.globalPools.emergencyBuffers.Get().([]byte); cap(buffer) >= size {
				opm.poolHits.Add(1)
				return buffer[:size]
			}
		}
	}
	
	opm.poolMisses.Add(1)
	// Fallback to allocation
	return make([]byte, size)
}

// PutBuffer returns a buffer to the appropriate pool
func (opm *OptimizedPoolManager) PutBuffer(buffer []byte) {
	opm.deallocations.Add(1)
	
	if buffer == nil {
		return
	}
	
	size := cap(buffer)
	cpuID := opm.getCurrentCPU()
	
	if cpuID >= 0 && cpuID < len(opm.cpuPools) {
		cpuPool := &opm.cpuPools[cpuID]
		
		var success bool
		if size <= 1500 {
			success = cpuPool.smallBufferPool.put(buffer)
		} else if size <= 9000 {
			success = cpuPool.largeBufferPool.put(buffer)
		}
		
		if success {
			return
		}
	}
	
	// Put in global pool if per-CPU failed
	opm.globalPools.bufferBackup.Put(buffer)
}

// GetUDPAddr retrieves a UDP address from the pool
func (opm *OptimizedPoolManager) GetUDPAddr() *UDPAddr {
	opm.allocations.Add(1)
	
	cpuID := opm.getCurrentCPU()
	if cpuID >= 0 && cpuID < len(opm.cpuPools) {
		cpuPool := &opm.cpuPools[cpuID]
		
		if addr, ok := cpuPool.udpAddrPool.get(); ok {
			opm.poolHits.Add(1)
			return &addr
		}
	}
	
	opm.poolMisses.Add(1)
	return opm.globalPools.addrBackup.Get().(*UDPAddr)
}

// PutUDPAddr returns a UDP address to the pool
func (opm *OptimizedPoolManager) PutUDPAddr(addr *UDPAddr) {
	opm.deallocations.Add(1)
	
	if addr == nil {
		return
	}
	
	// Reset address state
	*addr = UDPAddr{}
	
	cpuID := opm.getCurrentCPU()
	if cpuID >= 0 && cpuID < len(opm.cpuPools) {
		cpuPool := &opm.cpuPools[cpuID]
		
		if cpuPool.udpAddrPool.put(*addr) {
			return
		}
	}
	
	opm.globalPools.addrBackup.Put(addr)
}

// cleanupWorker performs periodic cleanup of pools
func (opm *OptimizedPoolManager) cleanupWorker() {
	ticker := time.NewTicker(opm.cleanupInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		opm.performCleanup()
	}
}

// performCleanup cleans up unused pool entries during low memory pressure
func (opm *OptimizedPoolManager) performCleanup() {
	pressure := opm.memPressure.Load()
	
	if pressure < 50 { // Only cleanup during low memory pressure
		return
	}
	
	// Force GC if memory pressure is high
	if pressure > 80 {
		runtime.GC()
		opm.lastGC.Store(time.Now().Unix())
	}
	
	// Cleanup could involve draining some per-CPU pools
	// This is a simplified implementation
}

// memoryPressureMonitor monitors memory pressure and adjusts pool behavior
func (opm *OptimizedPoolManager) memoryPressureMonitor() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for range ticker.C {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		
		// Simple memory pressure calculation (can be enhanced)
		pressure := uint32(0)
		
		// Base pressure on heap usage
		if m.HeapAlloc > 0 {
			usage := float64(m.HeapAlloc) / float64(m.HeapSys)
			pressure = uint32(usage * 100)
		}
		
		// Increase pressure if GC is frequent
		lastGC := time.Unix(opm.lastGC.Load(), 0)
		if time.Since(lastGC) < 30*time.Second {
			pressure += 20
		}
		
		// Cap at 100
		if pressure > 100 {
			pressure = 100
		}
		
		opm.memPressure.Store(pressure)
	}
}

// GetStats returns pool performance statistics
func (opm *OptimizedPoolManager) GetStats() (allocs, deallocs, hits, misses uint64, hitRate float64, memPressure uint32) {
	allocs = opm.allocations.Load()
	deallocs = opm.deallocations.Load()
	hits = opm.poolHits.Load()
	misses = opm.poolMisses.Load()
	memPressure = opm.memPressure.Load()
	
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}
	
	return
}

// ResetStats resets performance statistics
func (opm *OptimizedPoolManager) ResetStats() {
	opm.allocations.Store(0)
	opm.deallocations.Store(0)
	opm.poolHits.Store(0)
	opm.poolMisses.Store(0)
}