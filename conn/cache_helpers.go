package conn

import (
	"net"
	"net/netip"
)

// clearBuffer clears a buffer starting from the given position
func clearBuffer(buf []byte, from int) {
	if from < len(buf) {
		clear(buf[from:])
	}
}

// Helper functions for the old cache API to maintain compatibility
type ipAddrCache struct {
	*IPAddrCache
}

func (c *ipAddrCache) get(ip net.IP) (netip.Addr, bool) {
	return c.Get(ip)
}

func (c *ipAddrCache) put(ip net.IP, addr netip.Addr) {
	c.Put(ip, addr)
}

// newIPAddrCache creates a new IP address cache with compatible API
func newIPAddrCache() *ipAddrCache {
	return &ipAddrCache{
		IPAddrCache: NewIPAddrCache(),
	}
}

// endpointPool wraps EndpointPool for compatibility
type endpointPool struct {
	*EndpointPool
}

func (p *endpointPool) get() *ScionNetEndpoint {
	return p.Get()
}

func (p *endpointPool) put(ep *ScionNetEndpoint) {
	p.Put(ep)
}

func newEndpointPool() *endpointPool {
	return &endpointPool{
		EndpointPool: NewEndpointPool(),
	}
}