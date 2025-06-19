// Comprehensive tests for bind_scion.go optimizations
// This file tests that optimizations don't break functionality or introduce corruption

package conn

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/scionproto/scion/pkg/snet"
)

// Test 1: Buffer clearing optimization
func TestBufferClearing(t *testing.T) {
	// Test various buffer sizes
	sizes := []int{64, 256, 1024, 1500, 4096}
	
	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			buf := make([]byte, size)
			
			// Fill buffer with test pattern
			for i := range buf {
				buf[i] = byte(i & 0xFF)
			}
			
			// Test clearing from various positions
			positions := []int{0, size/4, size/2, size*3/4, size-1}
			
			for _, pos := range positions {
				if pos >= size {
					continue
				}
				
				// Make a copy for comparison
				original := make([]byte, size)
				copy(original, buf)
				
				// Clear from position
				clearBuffer(buf, pos)
				
				// Verify data before position is unchanged
				if pos > 0 && !bytes.Equal(buf[:pos], original[:pos]) {
					t.Errorf("Data before position %d was modified", pos)
				}
				
				// Verify data from position is cleared
				for i := pos; i < size; i++ {
					if buf[i] != 0 {
						t.Errorf("Buffer not cleared at position %d, got %d", i, buf[i])
					}
				}
			}
		})
	}
}

// Test 2: IP address cache functionality
func TestIPAddrCache(t *testing.T) {
	cache := newIPAddrCache()
	
	// Test IPs
	testIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"2001:db8::1",
		"fe80::1",
	}
	
	// First pass: add to cache
	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Fatalf("Failed to parse IP: %s", ipStr)
		}
		
		// Should not be cached initially
		if _, found := cache.get(ip); found {
			t.Errorf("IP %s found in cache before adding", ipStr)
		}
		
		// Convert and cache
		addr, err := convertIPToAddr(ip)
		if err != nil {
			t.Fatalf("Failed to convert IP %s: %v", ipStr, err)
		}
		
		cache.put(ip, addr)
	}
	
	// Second pass: verify cache hits
	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		
		addr, found := cache.get(ip)
		if !found {
			t.Errorf("IP %s not found in cache", ipStr)
			continue
		}
		
		// Verify the cached address is correct
		expected, _ := convertIPToAddr(ip)
		if addr != expected {
			t.Errorf("Cached address for %s doesn't match: got %v, want %v", ipStr, addr, expected)
		}
	}
	
	// Test concurrent access
	t.Run("Concurrent", func(t *testing.T) {
		var wg sync.WaitGroup
		errors := make(chan error, 100)
		
		// Multiple goroutines accessing cache
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				
				for j := 0; j < 100; j++ {
					// Create a unique IP
					ip := net.IPv4(192, 168, byte(id), byte(j))
					addr, _ := convertIPToAddr(ip)
					
					// Store in cache
					cache.put(ip, addr)
					
					// Retrieve from cache
					if cached, found := cache.get(ip); found {
						if cached != addr {
							errors <- fmt.Errorf("goroutine %d: cache mismatch for %v", id, ip)
						}
					}
				}
			}(i)
		}
		
		wg.Wait()
		close(errors)
		
		// Check for errors
		for err := range errors {
			t.Error(err)
		}
	})
}

// Test 3: Endpoint pool functionality
func TestEndpointPool(t *testing.T) {
	pool := newEndpointPool()
	
	// Test basic get/put
	t.Run("Basic", func(t *testing.T) {
		ep1 := pool.get()
		if ep1 == nil {
			t.Fatal("Got nil endpoint from pool")
		}
		
		// Set some values
		testAddr := netip.MustParseAddrPort("192.168.1.1:31000")
		ep1.StdNetEndpoint.AddrPort = testAddr
		ep1.scionAddr = &snet.UDPAddr{}
		
		// Return to pool
		pool.put(ep1)
		
		// Get again - should be reset
		ep2 := pool.get()
		if ep2.StdNetEndpoint.AddrPort.IsValid() {
			t.Error("Endpoint not reset: AddrPort still valid")
		}
		if ep2.scionAddr != nil {
			t.Error("Endpoint not reset: scionAddr not nil")
		}
	})
	
	// Test concurrent access
	t.Run("Concurrent", func(t *testing.T) {
		const numGoroutines = 50
		const numOps = 1000
		
		var wg sync.WaitGroup
		wg.Add(numGoroutines)
		
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				
				for j := 0; j < numOps; j++ {
					ep := pool.get()
					if ep == nil {
						t.Errorf("Goroutine %d: got nil endpoint", id)
						return
					}
					
					// Use the endpoint
					ep.StdNetEndpoint.AddrPort = netip.MustParseAddrPort(
						fmt.Sprintf("10.0.%d.%d:31000", id%256, j%256))
					
					// Small delay to simulate work
					time.Sleep(time.Microsecond)
					
					// Return to pool
					pool.put(ep)
				}
			}(i)
		}
		
		wg.Wait()
	})
}

// Test 4: Batch validation without array compaction
func TestBatchValidationOptimization(t *testing.T) {
	// Create test data
	const batchSize = 32
	bufs := make([][]byte, batchSize)
	readSizes := make([]int, batchSize)
	
	// Initialize buffers
	for i := range bufs {
		bufs[i] = make([]byte, 1500)
		// Fill with test pattern
		for j := range bufs[i] {
			bufs[i][j] = byte((i + j) & 0xFF)
		}
	}
	
	// Test scenarios
	scenarios := []struct {
		name         string
		validIndices []int
		readSizes    []int
	}{
		{
			name:         "AllValid",
			validIndices: []int{0, 1, 2, 3, 4, 5, 6, 7},
			readSizes:    []int{100, 200, 300, 400, 500, 600, 700, 800},
		},
		{
			name:         "SomeInvalid",
			validIndices: []int{0, 2, 4, 6},
			readSizes:    []int{100, 20, 300, 20, 500, 20, 700, 20}, // 20 is below MinMessageSize
		},
		{
			name:         "Sparse",
			validIndices: []int{5, 10, 15, 20, 25},
			readSizes:    []int{0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 200, 0, 0, 0, 0, 300, 0, 0, 0, 0, 400, 0, 0, 0, 0, 500},
		},
	}
	
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			// Copy test data
			testBufs := make([][]byte, len(scenario.readSizes))
			for i := range testBufs {
				testBufs[i] = make([]byte, 1500)
				if i < len(bufs) {
					copy(testBufs[i], bufs[i])
				}
			}
			
			// Apply read sizes
			copy(readSizes, scenario.readSizes)
			
			// Simulate the optimization: identify valid packets without compaction
			validIndices := make([]int, 0, len(readSizes))
			for i, size := range readSizes {
				if size >= 32 { // MinMessageSize
					validIndices = append(validIndices, i)
				}
			}
			
			// Verify we identified the correct valid packets
			if len(validIndices) != len(scenario.validIndices) {
				t.Errorf("Valid packet count mismatch: got %d, want %d", 
					len(validIndices), len(scenario.validIndices))
			}
			
			// Verify no data corruption
			for i, validIdx := range validIndices {
				if i < len(scenario.validIndices) && validIdx != scenario.validIndices[i] {
					t.Errorf("Valid index mismatch at position %d: got %d, want %d",
						i, validIdx, scenario.validIndices[i])
				}
				
				// Verify buffer data is intact
				expectedPattern := byte((validIdx) & 0xFF)
				if testBufs[validIdx][0] != expectedPattern {
					t.Errorf("Buffer data corrupted at index %d", validIdx)
				}
			}
		})
	}
}

// Test 5: Sharded path manager
func TestShardedPathManager(t *testing.T) {
	// This would require mocking the daemon connection
	// For now, we'll test the sharding logic
	
	t.Run("ShardDistribution", func(t *testing.T) {
		// Test that different IAs map to different shards
		testCases := []string{
			"1-ffaa:0:1",
			"1-ffaa:0:2",
			"2-ffaa:0:1",
			"1-ffaa:1:1",
			"3-ffaa:0:1",
		}
		
		shardMap := make(map[uint32][]string)
		
		for _, iaStr := range testCases {
			// Simulate the sharding calculation
			h := fnv.New32a()
			h.Write([]byte(iaStr))
			shard := h.Sum32() & (numShards - 1)
			
			shardMap[shard] = append(shardMap[shard], iaStr)
		}
		
		// Verify we got some distribution
		if len(shardMap) == 1 {
			t.Error("All IAs mapped to the same shard - poor distribution")
		}
		
		t.Logf("Shard distribution: %d unique shards for %d IAs", len(shardMap), len(testCases))
	})
}

// Benchmark the optimizations
func BenchmarkOptimizations(b *testing.B) {
	b.Run("BufferClearing", func(b *testing.B) {
		buf := make([]byte, 1500)
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			clearBuffer(buf, 750)
		}
	})
	
	b.Run("IPCache", func(b *testing.B) {
		cache := newIPAddrCache()
		ips := make([]net.IP, 100)
		for i := range ips {
			ips[i] = net.IPv4(192, 168, 1, byte(i))
			addr, _ := convertIPToAddr(ips[i])
			cache.put(ips[i], addr)
		}
		
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			ip := ips[i%len(ips)]
			cache.get(ip)
		}
	})
	
	b.Run("EndpointPool", func(b *testing.B) {
		pool := newEndpointPool()
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			ep := pool.get()
			ep.StdNetEndpoint.AddrPort = netip.MustParseAddrPort("192.168.1.1:31000")
			pool.put(ep)
		}
	})
}

// Test that all optimizations work together without corruption
func TestIntegratedOptimizations(t *testing.T) {
	// This test simulates the full receive path with all optimizations
	
	logger := &testLogger{t: t}
	config := &ScionConfig{
		LocalIP:   net.IPv4(127, 0, 0, 1),
		LocalPort: 31000,
	}
	
	bind := NewScionNetBind(config, logger)
	
	// Test that all optimization components are initialized
	if bind.endpointPool == nil {
		t.Fatal("Endpoint pool not initialized")
	}
	if bind.ipCache == nil {
		t.Fatal("IP cache not initialized")
	}
	
	// Simulate packet processing
	const numPackets = 100
	
	// Track endpoints to ensure no corruption
	endpoints := make(map[string]bool)
	
	for i := 0; i < numPackets; i++ {
		// Get endpoint from pool
		ep := bind.endpointPool.get()
		
		// Use it
		ip := net.IPv4(10, 0, 0, byte(i%256))
		addr, _ := convertIPToAddr(ip)
		bind.ipCache.put(ip, addr)
		
		ep.StdNetEndpoint.AddrPort = netip.AddrPortFrom(addr, 31000+uint16(i%1000))
		
		// Track it
		endpoints[ep.StdNetEndpoint.AddrPort.String()] = true
		
		// Return to pool
		bind.endpointPool.put(ep)
	}
	
	// Verify we processed all unique endpoints
	if len(endpoints) != numPackets {
		t.Errorf("Expected %d unique endpoints, got %d", numPackets, len(endpoints))
	}
}

// Helper test logger
type testLogger struct {
	t *testing.T
}

func (l *testLogger) Verbosef(format string, args ...interface{}) {
	l.t.Logf("[VERBOSE] "+format, args...)
}

func (l *testLogger) Errorf(format string, args ...interface{}) {
	l.t.Logf("[ERROR] "+format, args...)
}