// SCION Batch Connection for WireGuard backend.
// Provides batch send/receive capabilities for SCION packets.
// Uses UDP batching for performance.

package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/snet"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// Maximum number of retry attempts for GSO operations
	maxGSORetries = 1
)

var (
	ErrInvalidEndpointType = errors.New("invalid endpoint type, expected *ScionNetEndpoint")
	ErrInvalidAddressType  = errors.New("invalid address type, expected *net.UDPAddr")
	ErrConnectionClosed    = errors.New("connection is closed")
	ErrPacketDecode        = errors.New("failed to decode SCION packet")
	ErrNoUDPPayload        = errors.New("packet does not contain UDP payload")
	ErrNoRawPath           = errors.New("packet does not contain raw path")
)

// ScionBatchConn provides batch send/receive capabilities for SCION packets
// All methods are thread-safe unless otherwise documented
type ScionBatchConn struct {
	mu          sync.RWMutex
	conn        *net.UDPConn
	ipv4PC      *ipv4.PacketConn
	ipv6PC      *ipv6.PacketConn
	localIA     addr.IA
	localAddr   *net.UDPAddr
	topology    snet.Topology
	pathManager *PathManager
	scmpHandler snet.SCMPHandler
	replyPather snet.ReplyPather
	logger      Logger
	closed      bool

	// Performance optimization components
	offloadManager  *AdaptiveOffloadManager
	lockFreePathMgr *LockFreePathManager
	poolManager     *OptimizedPoolManager

	// Current offload state - protected by mu
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	// Legacy pools (kept for compatibility)
	msgsPool           sync.Pool
	scionPktPool       sync.Pool
	scionEmptyPktPool  sync.Pool
	scionSinglePktPool sync.Pool
	udpAddrPool        sync.Pool
	endpointPool       sync.Pool

	// Optimized pools flag
	useOptimizedPools bool

	// Performance optimization
	batchSize       int
	fastSerialize   bool
	batchSerializer *OptimizedBatchSerializer
	perfMonitor     *ScionPerformanceMonitor

	// Performance monitoring
	lastTxTime time.Time
	lastRxTime time.Time
	txRetries  uint64
	rxRetries  uint64
}

// ScionBatchConnConfig holds configuration options for ScionBatchConn
type ScionBatchConnConfig struct {
	// EnableIPv4RxOffload enables IPv4 receive offloading (default: false)
	EnableIPv4RxOffload bool
	// EnableIPv6RxOffload enables IPv6 receive offloading (default: false)
	EnableIPv6RxOffload bool
	// EnableIPv4TxOffload enables IPv4 transmit offloading (default: true)
	EnableIPv4TxOffload bool
	// EnableIPv6TxOffload enables IPv6 transmit offloading (default: true)
	EnableIPv6TxOffload bool
}

func NewScionBatchConn(
	conn *net.UDPConn,
	localIA addr.IA,
	topology snet.Topology,
	pathManager *PathManager,
	logger Logger,
) *ScionBatchConn {
	return NewScionBatchConnWithConfig(conn, localIA, topology, pathManager, logger, ScionBatchConnConfig{
		EnableIPv4TxOffload: false,
		EnableIPv6TxOffload: false,
		EnableIPv4RxOffload: false, // Now optimized for performance
		EnableIPv6RxOffload: false, // Now optimized for performance
	})
}

func NewScionBatchConnWithConfig(
	conn *net.UDPConn,
	localIA addr.IA,
	topology snet.Topology,
	pathManager *PathManager,
	logger Logger,
	config ScionBatchConnConfig,
) *ScionBatchConn {
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		logger.Errorf("Invalid local address type: %T", conn.LocalAddr())
		return nil
	}

	// Minimal component creation to avoid overhead
	// Skip expensive "optimization" components that are causing performance regression

	sbc := &ScionBatchConn{
		conn:        conn,
		localIA:     localIA,
		localAddr:   localAddr,
		topology:    topology,
		pathManager: pathManager,
		logger:      logger,
		replyPather: snet.DefaultReplyPather{},
		batchSize:   IdealBatchSize, // Use simple static batch size

		scionPktPool: sync.Pool{
			New: func() any {
				scionPkts := make([]snet.Packet, IdealBatchSize)
				for i := range scionPkts {
					scionPkts[i].Bytes = make(snet.Bytes, common.SupportedMTU)
				}
				return &scionPkts
			},
		},
		scionEmptyPktPool: sync.Pool{
			New: func() any {
				scionPkts := make([]snet.Packet, IdealBatchSize)
				return &scionPkts
			},
		},
		scionSinglePktPool: sync.Pool{
			New: func() any {
				return &snet.Packet{}
			},
		},
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},

		// Add endpoint pool to reduce GC pressure
		endpointPool: sync.Pool{
			New: func() any {
				return &ScionNetEndpoint{}
			},
		},

		poolManager:       NewOptimizedPoolManager(),
		useOptimizedPools: true,
	}

	// Simple packet connection configuration - avoid adaptive overhead
	if localAddr.IP.To4() != nil {
		sbc.ipv4PC = ipv4.NewPacketConn(conn)
		// Use simple static configuration instead of complex adaptive logic
		if config.EnableIPv4TxOffload {
			txOffload, _ := supportsUDPOffload(conn)
			sbc.ipv4TxOffload = txOffload
		}
		if config.EnableIPv4RxOffload {
			_, rxOffload := supportsUDPOffload(conn)
			sbc.ipv4RxOffload = rxOffload
		}
	} else {
		sbc.ipv6PC = ipv6.NewPacketConn(conn)
		// Use simple static configuration
		if config.EnableIPv6TxOffload {
			txOffload, _ := supportsUDPOffload(conn)
			sbc.ipv6TxOffload = txOffload
		}
		if config.EnableIPv6RxOffload {
			_, rxOffload := supportsUDPOffload(conn)
			sbc.ipv6RxOffload = rxOffload
		}
	}

	if sbc.ipv4TxOffload || sbc.ipv6TxOffload {
		sbc.fastSerialize = true
	}

	sbc.msgsPool = sync.Pool{
		New: func() any {
			msgs := make([]ipv6.Message, IdealBatchSize)
			for i := range msgs {
				msgs[i].Buffers = make(net.Buffers, 1)
				msgs[i].OOB = make([]byte, 0, stickyControlSize+gsoControlSize)
			}
			return &msgs
		},
	}

	logger.Verbosef("Created ScionBatchConn - Batch size: %d, IPv4 TX/RX: %v/%v, IPv6 TX/RX: %v/%v",
		sbc.batchSize, sbc.ipv4TxOffload, sbc.ipv4RxOffload, sbc.ipv6TxOffload, sbc.ipv6RxOffload)

	return sbc
}

func (s *ScionBatchConn) getMessages() *[]ipv6.Message {
	if s.useOptimizedPools && s.poolManager != nil {
		return s.poolManager.GetMessages()
	}
	return s.msgsPool.Get().(*[]ipv6.Message)
}

func (s *ScionBatchConn) putMessages(msgs *[]ipv6.Message) {
	if s.useOptimizedPools && s.poolManager != nil {
		s.poolManager.PutMessages(msgs)
		return
	}

	// Legacy pool path
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	s.msgsPool.Put(msgs)
}

func (s *ScionBatchConn) getScionPkts() *[]snet.Packet {
	if s.useOptimizedPools && s.poolManager != nil {
		return s.poolManager.GetScionPackets()
	}
	return s.scionPktPool.Get().(*[]snet.Packet)
}

func (s *ScionBatchConn) putScionPkts(pkts *[]snet.Packet) {
	if s.useOptimizedPools && s.poolManager != nil {
		s.poolManager.PutScionPackets(pkts)
		return
	}

	// Legacy pool path
	for i := range *pkts {
		// Reset packet state but keep allocated buffers
		(*pkts)[i] = snet.Packet{
			Bytes: (*pkts)[i].Bytes,
		}
	}
	s.scionPktPool.Put(pkts)
}

func (s *ScionBatchConn) SetSCMPHandler(handler snet.SCMPHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scmpHandler = handler
}

func (s *ScionBatchConn) LocalAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localAddr
}

func (s *ScionBatchConn) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	var err error
	if s.conn != nil {
		err = s.conn.Close()
		s.conn = nil
		s.ipv4PC = nil
		s.ipv6PC = nil
	}

	s.closed = true
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false

	return err
}

func (s *ScionBatchConn) BatchSize() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.batchSize
}

// ReadBatch reads multiple SCION packets in a single syscall
func (s *ScionBatchConn) ReadBatch(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return 0, ErrConnectionClosed
	}

	ipv4PC := s.ipv4PC
	ipv6PC := s.ipv6PC
	ipv4RxOffload := s.ipv4RxOffload
	ipv6RxOffload := s.ipv6RxOffload
	s.mu.RUnlock()

	if ipv4PC == nil && ipv6PC == nil {
		// Fallback to single packet read
		return s.readSingle(bufs[0], sizes, eps)
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)

	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}

	// Read batch
	var numMsgs int
	var err error

	if ipv4PC != nil {
		if ipv4RxOffload {
			readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
			if readAt < 0 {
				readAt = 0
			}
			_, err = ipv4PC.ReadBatch((*msgs)[readAt:], 0)
			if err != nil {
				return 0, fmt.Errorf("IPv4 batch read failed: %w", err)
			}
			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				return 0, fmt.Errorf("failed to split coalesced messages: %w", err)
			}
		} else {
			numMsgs, err = ipv4PC.ReadBatch(*msgs, 0)
			if err != nil {
				return 0, fmt.Errorf("IPv4 batch read failed: %w", err)
			}
		}
	} else {
		if ipv6RxOffload {
			readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
			if readAt < 0 {
				readAt = 0
			}
			_, err = ipv6PC.ReadBatch((*msgs)[readAt:], 0)
			if err != nil {
				return 0, fmt.Errorf("IPv6 batch read failed: %w", err)
			}
			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				return 0, fmt.Errorf("failed to split coalesced messages: %w", err)
			}
		} else {
			numMsgs, err = ipv6PC.ReadBatch(*msgs, 0)
			if err != nil {
				return 0, fmt.Errorf("IPv6 batch read failed: %w", err)
			}
		}
	}

	scionPkts := s.scionEmptyPktPool.Get().(*[]snet.Packet)
	defer s.scionEmptyPktPool.Put(scionPkts)

	// Efficient bounds check - single min calculation like StdNetBind
	maxMsgs := numMsgs
	if len(bufs) < maxMsgs {
		maxMsgs = len(bufs)
	}

	// Optimized packet processing loop - reduce overhead for RX offload performance
	for i := 0; i < maxMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = 0 // Default to 0, only set on successful processing
		
		if msg.N == 0 {
			continue
		}

		// SCION packet processing - minimize decode overhead
		scionPkt := &(*scionPkts)[i]
		scionPkt.Bytes = msg.Buffers[0][:msg.N]

		// Fast decode with minimal error handling
		if err := scionPkt.Decode(); err != nil {
			continue // Skip invalid SCION packets silently
		}

		// Combined payload type checking - reduce type assertions
		switch payload := scionPkt.Payload.(type) {
		case snet.UDPPayload:
			// Fast path for UDP packets
			udp := payload
			
			// Streamlined reply path creation
			rpath, ok := scionPkt.Path.(snet.RawPath)
			if !ok {
				continue
			}

			replyPath, err := s.replyPather.ReplyPath(rpath)
			if err != nil {
				continue
			}

			// Direct address handling - skip intermediate allocations
			nextHop := msg.Addr.(*net.UDPAddr)
			
			// Optimized endpoint creation using pool
			ep := s.endpointPool.Get().(*ScionNetEndpoint)
			
			// Direct SCION address assignment
			ep.scionAddr = &snet.UDPAddr{
				IA: scionPkt.Source.IA,
				Host: &net.UDPAddr{
					IP:   scionPkt.Source.Host.IP().AsSlice(),
					Port: int(udp.SrcPort),
				},
				Path:    replyPath,
				NextHop: nextHop,
			}

			// Efficient address conversion - avoid complex logic
			ep.StdNetEndpoint.AddrPort = nextHop.AddrPort()
			eps[i] = ep

			// Set source control - matches StdNetBind pattern
			getSrcFromControl(msg.OOB[:msg.NN], &ep.StdNetEndpoint)

			// Fast payload copy with single bounds check
			payloadLen := len(udp.Payload)
			if payloadLen <= len(bufs[i]) {
				sizes[i] = payloadLen
				copy(bufs[i], udp.Payload)
			}
			
		case snet.SCMPPayload:
			// Handle SCMP packets silently - no processing needed
			continue
			
		default:
			// Skip unknown payload types
			continue
		}
	}

	return maxMsgs, nil
}

// WriteBatch sends multiple SCION packets in a single syscall
func (s *ScionBatchConn) WriteBatch(bufs [][]byte, endpoint Endpoint) error {
	if len(bufs) == 0 {
		return nil
	}

	// Minimal performance tracking - avoid heavy monitoring in critical path

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return ErrConnectionClosed
	}

	ipv4PC := s.ipv4PC
	ipv6PC := s.ipv6PC
	s.mu.RUnlock()

	if ipv4PC == nil && ipv6PC == nil {
		// Fallback to single packet writes
		for _, buf := range bufs {
			if err := s.writeSingle(buf, endpoint); err != nil {
				return err
			}
		}
		return nil
	}

	scionEp, ok := endpoint.(*ScionNetEndpoint)
	if !ok {
		return ErrInvalidEndpointType
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)

	scionPkts := s.getScionPkts()
	defer s.putScionPkts(scionPkts)

	// Optimize by avoiding expensive string parsing - use efficient IP conversion
	var destAddr, srcAddr netip.Addr

	// Convert destination IP efficiently
	if ip4 := scionEp.scionAddr.Host.IP.To4(); ip4 != nil {
		destAddr = netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
	} else {
		var ip16 [16]byte
		copy(ip16[:], scionEp.scionAddr.Host.IP.To16())
		destAddr = netip.AddrFrom16(ip16)
	}

	// Use cached source address to avoid repeated conversions (source IP doesn't change)
	destination := snet.SCIONAddress{
		IA:   scionEp.scionAddr.IA,
		Host: addr.HostIP(destAddr),
	}

	// Convert source IP efficiently
	if ip4 := s.localAddr.IP.To4(); ip4 != nil {
		srcAddr = netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
	} else {
		var ip16 [16]byte
		copy(ip16[:], s.localAddr.IP.To16())
		srcAddr = netip.AddrFrom16(ip16)
	}

	source := snet.SCIONAddress{
		IA:   s.localIA,
		Host: addr.HostIP(srcAddr),
	}

	path := scionEp.scionAddr.Path
	srcPort := uint16(s.localAddr.Port)
	dstPort := uint16(scionEp.scionAddr.Host.Port)

	// Get UDP address from pool
	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)

	if ipv4PC != nil {
		as4 := scionEp.StdNetEndpoint.DstIP().As4()
		copy(ua.IP, as4[:])
		ua.IP = ua.IP[:4]
	} else {
		as16 := scionEp.StdNetEndpoint.DstIP().As16()
		copy(ua.IP, as16[:])
		ua.IP = ua.IP[:16]
	}
	ua.Port = int(scionEp.StdNetEndpoint.Port())

	// Get serialization buffer slice from pool to reduce allocations
	sbufs := make([][]byte, len(bufs)) // TODO: Pool this allocation
	// Optimize packet preparation - minimize field assignments
	for i, buf := range bufs {
		pkt := &(*scionPkts)[i]
		pkt.PacketInfo = snet.PacketInfo{
			Destination: destination,
			Source:      source,
			Path:        path,
			Payload: snet.UDPPayload{
				SrcPort: srcPort,
				DstPort: dstPort,
				Payload: buf,
			},
		}
	}

	// Fast serialization path - prepare all packets without per-packet validation
	for i := range bufs {
		(*scionPkts)[i].Prepare() // Only prepare, defer serialization
	}

	// Use batch serialization for better performance
	if err := SerializeBatch((*scionPkts)[:len(bufs)], sbufs); err != nil {
		// Fallback to individual serialization if batch fails
		for i := range bufs {
			if err := (*scionPkts)[i].Serialize(); err != nil {
				return fmt.Errorf("failed to serialize SCION packet %d: %w", i, err)
			}
			sbufs[i] = (*scionPkts)[i].Bytes
		}
	}

	// Send batch with retry logic
	retryCount := 0
	for retryCount <= maxGSORetries {
		var err error

		if ipv4PC != nil {
			if s.ipv4TxOffload {
				n := coalesceMessages(ua, &scionEp.StdNetEndpoint, sbufs, *msgs, setGSOSize)
				err = s.sendv4(ipv4PC, (*msgs)[:n])
				if err != nil && errShouldDisableUDPGSO(err) {
					s.logger.Verbosef("Disabling IPv4 GSO due to error: %v", err)
					s.mu.Lock()
					s.ipv4TxOffload = false
					// ipv4TxOffload disabled via struct field above
					s.mu.Unlock()
					retryCount++
					continue
				}
			} else {
				for i := range bufs {
					(*msgs)[i].Buffers[0] = sbufs[i]
					(*msgs)[i].Addr = ua
					setSrcControl(&(*msgs)[i].OOB, &scionEp.StdNetEndpoint)
				}
				err = s.sendv4(ipv4PC, (*msgs)[:len(bufs)])
			}
		} else {
			if s.ipv6TxOffload {
				n := coalesceMessages(ua, &scionEp.StdNetEndpoint, sbufs, *msgs, setGSOSize)
				err = s.sendv6(ipv6PC, (*msgs)[:n])
				if err != nil && errShouldDisableUDPGSO(err) {
					s.logger.Verbosef("Disabling IPv6 GSO due to error: %v", err)
					s.mu.Lock()
					s.ipv6TxOffload = false
					// ipv6TxOffload disabled via struct field above
					s.mu.Unlock()
					retryCount++
					continue
				}
			} else {
				for i := range bufs {
					(*msgs)[i].Buffers[0] = sbufs[i]
					(*msgs)[i].Addr = ua
					setSrcControl(&(*msgs)[i].OOB, &scionEp.StdNetEndpoint)
				}
				err = s.sendv6(ipv6PC, (*msgs)[:len(bufs)])
			}
		}

		if err != nil {
			// Remove expensive performance monitoring in hot path
			return fmt.Errorf("batch write failed: %w", err)
		}
		return nil
	}
	return fmt.Errorf("batch write failed: retry limit exceeded")
}

// send implements the efficient batch writing logic matching StdNetBind.send
func (s *ScionBatchConn) send(conn *net.UDPConn, pc batchWriter, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		for {
			n, err = pc.WriteBatch(msgs[start:], 0)
			if err != nil || n == len(msgs[start:]) {
				break
			}
			start += n
		}
	} else {
		for _, msg := range msgs {
			_, _, err = conn.WriteMsgUDP(msg.Buffers[0], msg.OOB, msg.Addr.(*net.UDPAddr))
			if err != nil {
				break
			}
		}
	}
	return err
}

func (s *ScionBatchConn) sendv4(pc *ipv4.PacketConn, msgs []ipv6.Message) error {
	return s.send(s.conn, batchWriter(pc), msgs)
}

func (s *ScionBatchConn) sendv6(pc *ipv6.PacketConn, msgs []ipv6.Message) error {
	return s.send(s.conn, batchWriter(pc), msgs)
}

// readSingle reads a single SCION packet (fallback for non-batch systems)
func (s *ScionBatchConn) readSingle(buf []byte, sizes []int, eps []Endpoint) (int, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return 0, ErrConnectionClosed
	}
	conn := s.conn
	s.mu.RUnlock()

	pkt := s.scionSinglePktPool.Get().(*snet.Packet)
	defer s.scionSinglePktPool.Put(pkt)

	pkt.Bytes = snet.Bytes(buf)
	n, remoteAddr, err := conn.ReadFrom(buf)
	if err != nil {
		return 0, fmt.Errorf("failed to read from connection: %w", err)
	}

	pkt.Bytes = pkt.Bytes[:n]
	if err := pkt.Decode(); err != nil {
		s.logger.Verbosef("Failed to decode SCION packet: %v", err)
		return 0, ErrPacketDecode
	}

	// Handle SCMP packets
	if _, ok := pkt.Payload.(snet.SCMPPayload); ok {
		s.mu.RLock()
		handler := s.scmpHandler
		s.mu.RUnlock()

		if handler != nil {
			if err := handler.Handle(pkt); err != nil {
				s.logger.Verbosef("SCMP handler error: %v", err)
			}
		}
		return 0, nil // SCMP handled, no data to return
	}

	// Extract UDP payload
	udp, ok := pkt.Payload.(snet.UDPPayload)
	if !ok {
		return 0, ErrNoUDPPayload
	}

	// Create reply path
	rpath, ok := pkt.Path.(snet.RawPath)
	if !ok {
		return 0, ErrNoRawPath
	}
	replyPath, err := s.replyPather.ReplyPath(rpath)
	if err != nil {
		return 0, fmt.Errorf("failed to create reply path: %w", err)
	}

	// Safely extract remote address
	nextHop, ok := remoteAddr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("%w: got %T", ErrInvalidAddressType, remoteAddr)
	}

	// Create endpoint
	scionAddr := &snet.UDPAddr{
		IA: pkt.Source.IA,
		Host: &net.UDPAddr{
			IP:   pkt.Source.Host.IP().AsSlice(),
			Port: int(udp.SrcPort),
		},
		Path:    replyPath,
		NextHop: nextHop,
	}

	eps[0] = &ScionNetEndpoint{
		StdNetEndpoint: StdNetEndpoint{
			AddrPort: netip.AddrPortFrom(
				netip.MustParseAddr(scionAddr.NextHop.IP.String()),
				uint16(scionAddr.NextHop.Port)),
		},
		scionAddr: scionAddr,
	}

	payloadLen := len(udp.Payload)
	if payloadLen > len(buf) {
		return 0, fmt.Errorf("UDP payload too large (%d bytes) for buffer (%d bytes)", payloadLen, len(buf))
	}

	sizes[0] = payloadLen
	copy(buf, udp.Payload)

	return 1, nil
}

// writeSingle writes a single SCION packet (fallback for non-batch systems)
func (s *ScionBatchConn) writeSingle(buf []byte, ep Endpoint) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return ErrConnectionClosed
	}
	conn := s.conn
	s.mu.RUnlock()

	scionEp, ok := ep.(*ScionNetEndpoint)
	if !ok {
		return ErrInvalidEndpointType
	}

	scionPkt := s.scionSinglePktPool.Get().(*snet.Packet)
	defer s.scionSinglePktPool.Put(scionPkt)

	scionPkt.PacketInfo = snet.PacketInfo{
		Destination: snet.SCIONAddress{
			IA:   scionEp.scionAddr.IA,
			Host: addr.HostIP(netip.MustParseAddr(scionEp.scionAddr.Host.IP.String())),
		},
		Source: snet.SCIONAddress{
			IA:   s.localIA,
			Host: addr.HostIP(netip.MustParseAddr(s.localAddr.IP.String())),
		},
		Path: scionEp.scionAddr.Path,
		Payload: snet.UDPPayload{
			SrcPort: uint16(s.localAddr.Port),
			DstPort: uint16(scionEp.scionAddr.Host.Port),
			Payload: buf,
		},
	}

	if err := scionPkt.Serialize(); err != nil {
		return fmt.Errorf("failed to serialize SCION packet: %w", err)
	}

	_, err := conn.WriteTo(scionPkt.Bytes, scionEp.scionAddr.NextHop)
	if err != nil {
		return fmt.Errorf("failed to write packet: %w", err)
	}

	return nil
}
