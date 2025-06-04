package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

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

	// Offloads - protected by mu
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	// Object pools
	msgsPool      sync.Pool
	scionPktPool  sync.Pool
	singlePktPool sync.Pool
	udpAddrPool   sync.Pool

	// Capabilities
	batchSize     int
	fastSerialize bool
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
		EnableIPv4TxOffload: true,
		EnableIPv6TxOffload: true,
		EnableIPv4RxOffload: false, // Disabled by default due to stability concerns
		EnableIPv6RxOffload: false, // Disabled by default due to stability concerns
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

	sbc := &ScionBatchConn{
		conn:        conn,
		localIA:     localIA,
		localAddr:   localAddr,
		topology:    topology,
		pathManager: pathManager,
		logger:      logger,
		replyPather: snet.DefaultReplyPather{},
		batchSize:   1, // Default to single packet mode

		scionPktPool: sync.Pool{
			New: func() any {
				scionPkts := make([]snet.Packet, IdealBatchSize)
				for i := range scionPkts {
					scionPkts[i].Bytes = make(snet.Bytes, common.SupportedMTU)
				}
				return &scionPkts
			},
		},
		singlePktPool: sync.Pool{
			New: func() any {
				return &snet.Packet{
					Bytes: make(snet.Bytes, common.SupportedMTU),
				}
			},
		},
		udpAddrPool: sync.Pool{
			New: func() any {
				return &net.UDPAddr{
					IP: make([]byte, 16),
				}
			},
		},
	}

	// Configure packet connections and offloading based on IP version
	if localAddr.IP.To4() != nil {
		sbc.ipv4PC = ipv4.NewPacketConn(conn)
		if config.EnableIPv4TxOffload || config.EnableIPv4RxOffload {
			txOffload, rxOffload := supportsUDPOffload(conn)
			sbc.ipv4TxOffload = config.EnableIPv4TxOffload && txOffload
			sbc.ipv4RxOffload = config.EnableIPv4RxOffload && rxOffload
		}
		sbc.batchSize = IdealBatchSize
	} else {
		sbc.ipv6PC = ipv6.NewPacketConn(conn)
		if config.EnableIPv6TxOffload || config.EnableIPv6RxOffload {
			txOffload, rxOffload := supportsUDPOffload(conn)
			sbc.ipv6TxOffload = config.EnableIPv6TxOffload && txOffload
			sbc.ipv6RxOffload = config.EnableIPv6RxOffload && rxOffload
		}
		sbc.batchSize = IdealBatchSize
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

	logger.Verbosef("Created ScionBatchConn with batch size %d, IPv4 TX/RX offload: %v/%v, IPv6 TX/RX offload: %v/%v",
		sbc.batchSize, sbc.ipv4TxOffload, sbc.ipv4RxOffload, sbc.ipv6TxOffload, sbc.ipv6RxOffload)

	return sbc
}

func (s *ScionBatchConn) getMessages() *[]ipv6.Message {
	return s.msgsPool.Get().(*[]ipv6.Message)
}

func (s *ScionBatchConn) putMessages(msgs *[]ipv6.Message) {
	for i := range *msgs {
		(*msgs)[i].OOB = (*msgs)[i].OOB[:0]
		(*msgs)[i] = ipv6.Message{Buffers: (*msgs)[i].Buffers, OOB: (*msgs)[i].OOB}
	}
	s.msgsPool.Put(msgs)
}

func (s *ScionBatchConn) getScionPkts() *[]snet.Packet {
	return s.scionPktPool.Get().(*[]snet.Packet)
}

func (s *ScionBatchConn) putScionPkts(pkts *[]snet.Packet) {
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

	// Prepare message buffers
	numBufs := len(bufs)
	if numBufs > len(*msgs) {
		numBufs = len(*msgs)
	}

	for i := 0; i < numBufs; i++ {
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
			numMsgs, err = ipv4PC.ReadBatch((*msgs)[:numBufs], 0)
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
			numMsgs, err = ipv6PC.ReadBatch((*msgs)[:numBufs], 0)
			if err != nil {
				return 0, fmt.Errorf("IPv6 batch read failed: %w", err)
			}
		}
	}

	// Get a single SCION packet object to reuse for parsing
	scionPkt := s.singlePktPool.Get().(*snet.Packet)
	defer s.singlePktPool.Put(scionPkt)

	validPackets := 0

	// Process each message
	for i := 0; i < numMsgs && validPackets < len(bufs); i++ {
		msg := &(*msgs)[i]
		if msg.N == 0 {
			continue
		}

		// Parse SCION packet
		scionPkt.Bytes = msg.Buffers[0][:msg.N]
		if err := scionPkt.Decode(); err != nil {
			s.logger.Verbosef("Failed to decode SCION packet: %v", err)
			continue
		}

		// Handle SCMP packets
		if _, ok := scionPkt.Payload.(snet.SCMPPayload); ok {
			s.mu.RLock()
			handler := s.scmpHandler
			s.mu.RUnlock()

			if handler != nil {
				if err := handler.Handle(scionPkt); err != nil {
					s.logger.Verbosef("SCMP handler error: %v", err)
				}
			}
			continue
		}

		// Extract UDP payload
		udp, ok := scionPkt.Payload.(snet.UDPPayload)
		if !ok {
			s.logger.Verbosef("Packet does not contain UDP payload")
			continue
		}

		// Create reply path
		rpath, ok := scionPkt.Path.(snet.RawPath)
		if !ok {
			s.logger.Verbosef("Packet does not contain raw path")
			continue
		}

		replyPath, err := s.replyPather.ReplyPath(rpath)
		if err != nil {
			s.logger.Verbosef("Failed to create reply path: %v", err)
			continue
		}

		// Safely extract address
		nextHop, ok := msg.Addr.(*net.UDPAddr)
		if !ok {
			s.logger.Verbosef("Invalid address type in message: %T", msg.Addr)
			continue
		}

		// Create endpoint
		scionAddr := &snet.UDPAddr{
			IA: scionPkt.Source.IA,
			Host: &net.UDPAddr{
				IP:   scionPkt.Source.Host.IP().AsSlice(),
				Port: int(udp.SrcPort),
			},
			Path:    replyPath,
			NextHop: nextHop,
		}

		eps[validPackets] = &ScionNetEndpoint{
			StdNetEndpoint: StdNetEndpoint{
				AddrPort: netip.AddrPortFrom(
					netip.MustParseAddr(scionAddr.NextHop.IP.String()),
					uint16(scionAddr.NextHop.Port)),
			},
			scionAddr: scionAddr,
		}

		if scionEp, ok := eps[validPackets].(*ScionNetEndpoint); ok {
			getSrcFromControl(msg.OOB[:msg.NN], &scionEp.StdNetEndpoint)
		}

		payloadLen := len(udp.Payload)
		if payloadLen > len(bufs[validPackets]) {
			s.logger.Verbosef("UDP payload too large (%d bytes) for buffer (%d bytes)", payloadLen, len(bufs[validPackets]))
			continue
		}

		sizes[validPackets] = payloadLen
		copy(bufs[validPackets], udp.Payload)
		validPackets++
	}

	return validPackets, nil
}

// WriteBatch sends multiple SCION packets in a single syscall
func (s *ScionBatchConn) WriteBatch(bufs [][]byte, endpoint Endpoint) error {
	if len(bufs) == 0 {
		return nil
	}

	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return ErrConnectionClosed
	}

	ipv4PC := s.ipv4PC
	ipv6PC := s.ipv6PC
	ipv4TxOffload := s.ipv4TxOffload
	ipv6TxOffload := s.ipv6TxOffload
	fastSerialize := s.fastSerialize
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

	// Prepare addresses and path info
	destination := snet.SCIONAddress{
		IA:   scionEp.scionAddr.IA,
		Host: addr.HostIP(netip.MustParseAddr(scionEp.scionAddr.Host.IP.String())),
	}
	source := snet.SCIONAddress{
		IA:   s.localIA,
		Host: addr.HostIP(netip.MustParseAddr(s.localAddr.IP.String())),
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

	// Prepare SCION packets
	sbufs := make([][]byte, len(bufs))
	for i, buf := range bufs {
		(*scionPkts)[i].PacketInfo.Destination = destination
		(*scionPkts)[i].PacketInfo.Source = source
		(*scionPkts)[i].PacketInfo.Path = path
		(*scionPkts)[i].PacketInfo.Payload = snet.UDPPayload{
			SrcPort: srcPort,
			DstPort: dstPort,
			Payload: buf,
		}

		if !fastSerialize {
			if err := (*scionPkts)[i].Serialize(); err != nil {
				return fmt.Errorf("failed to serialize SCION packet %d: %w", i, err)
			}
			sbufs[i] = (*scionPkts)[i].Bytes
		}
	}

	if fastSerialize {
		if err := SerializeBatch((*scionPkts)[:len(bufs)], sbufs); err != nil {
			return fmt.Errorf("failed to serialize SCION packets: %w", err)
		}
	}

	// Send batch with retry logic
	retryCount := 0
	for retryCount <= maxGSORetries {
		var err error

		if ipv4PC != nil {
			if ipv4TxOffload {
				n := coalesceMessages(ua, &scionEp.StdNetEndpoint, sbufs, *msgs, setGSOSize)
				err = s.sendv4(ipv4PC, (*msgs)[:n])
				if err != nil && errShouldDisableUDPGSO(err) {
					s.logger.Verbosef("Disabling IPv4 GSO due to error: %v", err)
					s.mu.Lock()
					s.ipv4TxOffload = false
					ipv4TxOffload = false
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
			if ipv6TxOffload {
				n := coalesceMessages(ua, &scionEp.StdNetEndpoint, sbufs, *msgs, setGSOSize)
				err = s.sendv6(ipv6PC, (*msgs)[:n])
				if err != nil && errShouldDisableUDPGSO(err) {
					s.logger.Verbosef("Disabling IPv6 GSO due to error: %v", err)
					s.mu.Lock()
					s.ipv6TxOffload = false
					ipv6TxOffload = false
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
			return fmt.Errorf("batch write failed after %d retries: %w", retryCount, err)
		}
		return nil
	}

	return fmt.Errorf("batch write failed after %d retries: GSO retry limit exceeded", retryCount)
}

func (s *ScionBatchConn) sendv4(pc *ipv4.PacketConn, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	for start < len(msgs) {
		n, err = pc.WriteBatch(msgs[start:], 0)
		if err != nil {
			return err
		}
		start += n
	}
	return nil
}

func (s *ScionBatchConn) sendv6(pc *ipv6.PacketConn, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	for start < len(msgs) {
		n, err = pc.WriteBatch(msgs[start:], 0)
		if err != nil {
			return err
		}
		start += n
	}
	return nil
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

	pkt := s.singlePktPool.Get().(*snet.Packet)
	defer s.singlePktPool.Put(pkt)

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

	scionPkt := s.singlePktPool.Get().(*snet.Packet)
	defer s.singlePktPool.Put(scionPkt)

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
