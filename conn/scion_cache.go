package conn

import (
	"net/netip"
	"sync"
	"sync/atomic"
)

// EndpointPool provides lock-free pooling of ScionNetEndpoint objects
type EndpointPool struct {
	pool sync.Pool
}

func NewEndpointPool() *EndpointPool {
	return &EndpointPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &ScionNetEndpoint{}
			},
		},
	}
}

func (p *EndpointPool) Get() *ScionNetEndpoint {
	return p.pool.Get().(*ScionNetEndpoint)
}

func (p *EndpointPool) Put(ep *ScionNetEndpoint) {
	// Clear the endpoint before returning to pool
	ep.StdNetEndpoint.AddrPort = netip.AddrPort{}
	ep.scionAddr = nil
	p.pool.Put(ep)
}

// IPAddrCache provides a lock-free cache for netip.Addr lookups
type IPAddrCache struct {
	entries atomic.Pointer[ipCacheEntry]
	pool    sync.Pool
}

type ipCacheEntry struct {
	// Use fixed-size array for better cache locality
	keys   [16][16]byte // IPv6 addresses are 16 bytes
	values [16]netip.Addr
	count  int32
	next   *ipCacheEntry
}

func NewIPAddrCache() *IPAddrCache {
	return &IPAddrCache{
		pool: sync.Pool{
			New: func() interface{} {
				return &ipCacheEntry{}
			},
		},
	}
}

func (c *IPAddrCache) Get(ip []byte) (netip.Addr, bool) {
	if len(ip) != 4 && len(ip) != 16 {
		return netip.Addr{}, false
	}

	// Create key with zero padding for IPv4
	var key [16]byte
	copy(key[:], ip)

	entry := c.entries.Load()
	for entry != nil {
		count := atomic.LoadInt32(&entry.count)
		for i := int32(0); i < count && i < 16; i++ {
			if key == entry.keys[i] {
				return entry.values[i], true
			}
		}
		entry = entry.next
	}
	return netip.Addr{}, false
}

func (c *IPAddrCache) Put(ip []byte, addr netip.Addr) {
	if len(ip) != 4 && len(ip) != 16 {
		return
	}

	var key [16]byte
	copy(key[:], ip)

	// Try to add to existing entry
	entry := c.entries.Load()
	if entry != nil {
		count := atomic.LoadInt32(&entry.count)
		if count < 16 {
			// Try to add to this entry
			if atomic.CompareAndSwapInt32(&entry.count, count, count+1) {
				entry.keys[count] = key
				entry.values[count] = addr
				return
			}
		}
	}

	// Need new entry
	newEntry := c.pool.Get().(*ipCacheEntry)
	newEntry.keys[0] = key
	newEntry.values[0] = addr
	atomic.StoreInt32(&newEntry.count, 1)

	// Prepend to list
	for {
		oldHead := c.entries.Load()
		newEntry.next = oldHead
		if c.entries.CompareAndSwap(oldHead, newEntry) {
			// Limit cache size by dropping old entries
			if oldHead != nil {
				var depth int
				for e := oldHead; e != nil; e = e.next {
					depth++
					if depth > 4 { // Keep max 5 entries (80 addresses)
						e.next = nil
						// Return remaining entries to pool
						for e2 := e.next; e2 != nil; {
							next := e2.next
							e2.next = nil
							atomic.StoreInt32(&e2.count, 0)
							c.pool.Put(e2)
							e2 = next
						}
						break
					}
				}
			}
			return
		}
	}
}

// BufferPool provides lock-free pooling of byte buffers
type BufferPool struct {
	pools [32]sync.Pool // Support different buffer sizes
}

func NewBufferPool() *BufferPool {
	bp := &BufferPool{}
	for i := range bp.pools {
		size := 1 << (i + 10) // 1KB to 2TB in powers of 2
		bp.pools[i] = sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		}
	}
	return bp
}

func (bp *BufferPool) Get(size int) []byte {
	// Find the appropriate pool
	poolIndex := 0
	adjustedSize := size
	if adjustedSize < 1024 {
		adjustedSize = 1024
	}
	for adjustedSize > 1024 {
		adjustedSize >>= 1
		poolIndex++
	}
	if poolIndex >= len(bp.pools) {
		return make([]byte, size)
	}

	buf := bp.pools[poolIndex].Get().([]byte)
	if len(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

func (bp *BufferPool) Put(buf []byte) {
	size := cap(buf)
	if size < 1024 {
		return
	}

	// Find the appropriate pool
	poolIndex := 0
	adjustedSize := size
	for adjustedSize > 1024 {
		adjustedSize >>= 1
		poolIndex++
	}
	if poolIndex >= len(bp.pools) {
		return
	}

	// Clear sensitive data before returning to pool
	clear(buf)
	bp.pools[poolIndex].Put(buf[:cap(buf)])
}


// convertIPToAddrCached converts IP bytes to netip.Addr with caching
func convertIPToAddrCached(cache *IPAddrCache, ip []byte) (netip.Addr, error) {
	// Check cache first
	if addr, found := cache.Get(ip); found {
		return addr, nil
	}

	// Convert and cache
	addr, err := convertIPToAddr(ip)
	if err == nil {
		cache.Put(ip, addr)
	}
	return addr, err
}

// BatchEndpointCache caches endpoint creation for batch operations
type BatchEndpointCache struct {
	endpointPool *EndpointPool
	ipCache      *IPAddrCache
	bufferPool   *BufferPool
}

func NewBatchEndpointCache() *BatchEndpointCache {
	return &BatchEndpointCache{
		endpointPool: NewEndpointPool(),
		ipCache:      NewIPAddrCache(),
		bufferPool:   NewBufferPool(),
	}
}

// GetEndpoint retrieves or creates a cached endpoint
func (c *BatchEndpointCache) GetEndpoint(ip []byte, port uint16, scionAddr interface{}) (*ScionNetEndpoint, error) {
	// Convert IP with caching
	netipAddr, err := convertIPToAddrCached(c.ipCache, ip)
	if err != nil {
		return nil, err
	}

	// Get endpoint from pool
	ep := c.endpointPool.Get()
	ep.StdNetEndpoint.AddrPort = netip.AddrPortFrom(netipAddr, port)
	// scionAddr should be cast to the appropriate type by caller
	ep.scionAddr = nil

	return ep, nil
}

// PutEndpoint returns an endpoint to the cache
func (c *BatchEndpointCache) PutEndpoint(ep *ScionNetEndpoint) {
	c.endpointPool.Put(ep)
}

// GetBuffer gets a buffer from the pool
func (c *BatchEndpointCache) GetBuffer(size int) []byte {
	return c.bufferPool.Get(size)
}

// PutBuffer returns a buffer to the pool
func (c *BatchEndpointCache) PutBuffer(buf []byte) {
	c.bufferPool.Put(buf)
}