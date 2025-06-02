package conn

import (
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

// ScionBatchConn provides batch send/receive capabilities for SCION packets
type ScionBatchConn struct {
	mu          sync.Mutex
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

	// Offloads
	ipv4TxOffload bool
	ipv4RxOffload bool
	ipv6TxOffload bool
	ipv6RxOffload bool

	msgsPool   sync.Pool

	// SCION packet pools
	scionPktPool  sync.Pool
	singlePktPool sync.Pool

	udpAddrPool sync.Pool

	// Capabilities
	batchSize int
}

func NewScionBatchConn(
	conn *net.UDPConn,
	localIA addr.IA,
	topology snet.Topology,
	pathManager *PathManager,
	logger Logger,
) *ScionBatchConn {
	sbc := &ScionBatchConn{
		conn:        conn,
		localIA:     localIA,
		localAddr:   conn.LocalAddr().(*net.UDPAddr),
		topology:    topology,
		pathManager: pathManager,
		logger:      logger,
		replyPather: snet.DefaultReplyPather{},
		batchSize:   1,
		
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

	// Enable batch operations on Linux/Android
	if conn.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
		sbc.ipv4PC = ipv4.NewPacketConn(conn)
		sbc.ipv4TxOffload, sbc.ipv4RxOffload = supportsUDPOffload(conn)
		sbc.batchSize = IdealBatchSize
	} else {
		sbc.ipv6PC = ipv6.NewPacketConn(conn)
		sbc.ipv6TxOffload, sbc.ipv6RxOffload = supportsUDPOffload(conn)
		sbc.batchSize = IdealBatchSize
	}

	// sbc.ipv6TxOffload = false
	sbc.ipv6RxOffload = false
	// sbc.ipv4TxOffload = false
	sbc.ipv4RxOffload = false

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
	s.scmpHandler = handler
}

func (s *ScionBatchConn) LocalAddr() net.Addr {
	return s.localAddr
}

func (s *ScionBatchConn) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error

	if s.conn != nil {
		err = s.conn.Close()
		s.conn = nil
		s.ipv4PC = nil
		s.ipv6PC = nil
	}
	s.ipv4TxOffload = false
	s.ipv4RxOffload = false
	s.ipv6TxOffload = false
	s.ipv6RxOffload = false
	return err
}

func (s *ScionBatchConn) BatchSize() int {
	return s.batchSize
}

// ReadBatch reads multiple SCION packets in a single syscall
func (s *ScionBatchConn) ReadBatch(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
	if s.ipv4PC == nil && s.ipv6PC == nil {
		// Fallback to single packet read
		return s.readSingle(bufs[0], sizes, eps)
	}

	msgs := s.getMessages()
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}
	defer s.putMessages(msgs)

	// sbufs := s.getBuffers()
	// defer s.putBuffers(sbufs)

	// Read batch
	var numMsgs int
	var err error
	if s.ipv4PC != nil {
		if s.ipv4RxOffload {
			readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
			numMsgs, err = s.ipv4PC.ReadBatch((*msgs)[readAt:], 0)
			if err != nil {
				return 0, err
			}
			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				return 0, err
			}
		} else {
			numMsgs, err = s.ipv4PC.ReadBatch((*msgs), 0)
		}
	} else {
		if s.ipv6RxOffload {
			readAt := len(*msgs) - (IdealBatchSize / udpSegmentMaxDatagrams)
			_, err = s.ipv6PC.ReadBatch((*msgs)[readAt:], 0)
			if err != nil {
				return 0, err
			}
			numMsgs, err = splitCoalescedMessages(*msgs, readAt, getGSOSize)
			if err != nil {
				return 0, err
			}
		} else {
			numMsgs, err = s.ipv6PC.ReadBatch((*msgs), 0)
		}
	}
	if err != nil {
		return 0, err
	}

	// Get a single SCION packet object to reuse
	scionPkt := s.singlePktPool.Get().(*snet.Packet)
	defer s.singlePktPool.Put(scionPkt)

	pkt := scionPkt

	// Process each message
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		sizes[i] = msg.N
		if msg.N == 0 {
			continue
		}

		// Parse SCION packet
		pkt.Bytes = msg.Buffers[0][:msg.N]
		if err := pkt.Decode(); err != nil {
			s.logger.Verbosef("Failed to decode SCION packet: %v", err)
			continue
		}

		// Handle SCMP
		if _, ok := pkt.Payload.(snet.SCMPPayload); ok {
			if s.scmpHandler != nil {
				if err := s.scmpHandler.Handle(pkt); err != nil {
					s.logger.Verbosef("SCMP handler error: %v", err)
				}
			}
			continue
		}

		// Extract UDP payload
		udp, ok := pkt.Payload.(snet.UDPPayload)
		if !ok {
			continue
		}

		// Create reply path
		rpath, ok := pkt.Path.(snet.RawPath)
		if !ok {
			continue
		}
		replyPath, err := s.replyPather.ReplyPath(rpath)
		if err != nil {
			s.logger.Verbosef("Failed to create reply path: %v", err)
			continue
		}

		// Create endpoint
		scionAddr := &snet.UDPAddr{
			IA: pkt.Source.IA,
			Host: &net.UDPAddr{
				IP:   pkt.Source.Host.IP().AsSlice(),
				Port: int(udp.SrcPort),
			},
			Path:    replyPath,
			NextHop: msg.Addr.(*net.UDPAddr),
		}

		eps[i] = &ScionNetEndpoint{
			StdNetEndpoint: StdNetEndpoint{
				AddrPort: netip.AddrPortFrom(
					netip.MustParseAddr(
						scionAddr.NextHop.IP.String()),
					uint16(scionAddr.NextHop.Port)),
			},
			scionAddr: scionAddr,
		}
		if scionEp, ok := eps[i].(*ScionNetEndpoint); ok {
			getSrcFromControl(msg.OOB[:msg.NN], &scionEp.StdNetEndpoint)
		}
		sizes[i] = len(udp.Payload)
		copy(bufs[i], udp.Payload)
	}

	return numMsgs, nil
}

// WriteBatch sends multiple SCION packets in a single syscall
func (s *ScionBatchConn) WriteBatch(bufs [][]byte, endpoint Endpoint) error {
	if s.ipv4PC == nil && s.ipv6PC == nil {
		// Fallback to single packet writes
		for _, buf := range bufs {
			if err := s.writeSingle(buf, endpoint); err != nil {
				return err
			}
		}
		return nil
	}

	msgs := s.getMessages()
	defer s.putMessages(msgs)

	scionPkts := s.getScionPkts()
	defer s.putScionPkts(scionPkts)

	scionEp, ok := endpoint.(*ScionNetEndpoint)
	if !ok {
		return fmt.Errorf("invalid endpoint type")
	}
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

	ua := s.udpAddrPool.Get().(*net.UDPAddr)
	defer s.udpAddrPool.Put(ua)
	if s.ipv4PC != nil {
		as4 := scionEp.StdNetEndpoint.DstIP().As4()
		copy(ua.IP, as4[:])
		ua.IP = ua.IP[:4]
	} else {
		as16 := scionEp.StdNetEndpoint.DstIP().As16()
		copy(ua.IP, as16[:])
		ua.IP = ua.IP[:16]
	}
	ua.Port = int(scionEp.StdNetEndpoint.Port())

	sbufs := make([][]byte, len(bufs))

	// Prepare SCION packets
	for i, buf := range bufs {
		(*scionPkts)[i].PacketInfo.Destination = destination
		(*scionPkts)[i].PacketInfo.Source = source
		(*scionPkts)[i].PacketInfo.Path = path
		(*scionPkts)[i].PacketInfo.Payload = snet.UDPPayload{
			SrcPort: srcPort,
			DstPort: dstPort,
			Payload: buf,
		}
		if err := (*scionPkts)[i].Serialize(); err != nil {
			return fmt.Errorf("failed to serialize SCION packet: %w", err)
		}
		sbufs[i] = (*scionPkts)[i].Bytes
	}

	// Send batch
	var err error
retry:
	if s.ipv4PC != nil {
		if s.ipv4TxOffload {
			n := coalesceMessages(ua, &scionEp.StdNetEndpoint, sbufs, *msgs, setGSOSize)
			err = s.sendv4(s.ipv4PC, (*msgs)[:n])
			if err != nil && errShouldDisableUDPGSO(err) {
				s.ipv4TxOffload = false
				goto retry
			}
		} else {
			for i := range bufs {
				(*msgs)[i].Buffers[0] = sbufs[i]
				(*msgs)[i].Addr = ua
				setSrcControl(&(*msgs)[i].OOB, &scionEp.StdNetEndpoint)
			}
			err = s.sendv4(s.ipv4PC, (*msgs)[:len(bufs)])
		}
	} else {
		if s.ipv6TxOffload {
			n := coalesceMessages(ua, &scionEp.StdNetEndpoint, sbufs, *msgs, setGSOSize)
			err = s.sendv6(s.ipv6PC, (*msgs)[:n])
			if err != nil && errShouldDisableUDPGSO(err) {
				s.ipv6TxOffload = false
				goto retry
			}
		} else {
			for i := range bufs {
				(*msgs)[i].Buffers[0] = sbufs[i]
				(*msgs)[i].Addr = ua
				setSrcControl(&(*msgs)[i].OOB, &scionEp.StdNetEndpoint)
			}
			err = s.sendv6(s.ipv6PC, (*msgs)[:len(bufs)])
		}
	}

	return err
}

func (s *ScionBatchConn) sendv4(pc *ipv4.PacketConn, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	for {
		n, err = pc.WriteBatch(msgs[start:], 0)
		if err != nil || n == len(msgs[start:]) {
			break
		}
		start += n
	}
	return err
}

func (s *ScionBatchConn) sendv6(pc *ipv6.PacketConn, msgs []ipv6.Message) error {
	var (
		n     int
		err   error
		start int
	)
	for {
		n, err = pc.WriteBatch(msgs[start:], 0)
		if err != nil || n == len(msgs[start:]) {
			break
		}
		start += n
	}
	return err
}

// readSingle reads a single SCION packet (fallback for non-batch systems)
func (s *ScionBatchConn) readSingle(buf []byte, sizes []int, eps []Endpoint) (int, error) {
	pkt := s.singlePktPool.Get().(*snet.Packet)
	defer s.singlePktPool.Put(pkt)

	pkt.Bytes = snet.Bytes(buf)
	n, remoteAddr, err := s.conn.ReadFrom(buf)
	if err != nil {
		return 0, err
	}

	pkt.Bytes = pkt.Bytes[:n]
	if err := pkt.Decode(); err != nil {
		return 0, nil // Skip invalid packets
	}

	// Handle SCMP
	if _, ok := pkt.Payload.(snet.SCMPPayload); ok {
		if s.scmpHandler != nil {
			s.scmpHandler.Handle(pkt)
		}
		return 0, nil // SCMP handled, no data to return
	}

	// Extract UDP payload
	udp, ok := pkt.Payload.(snet.UDPPayload)
	if !ok {
		return 0, nil
	}

	// Create reply path
	rpath, ok := pkt.Path.(snet.RawPath)
	if !ok {
		return 0, nil
	}
	replyPath, err := s.replyPather.ReplyPath(rpath)
	if err != nil {
		return 0, nil
	}

	// Create endpoint
	scionAddr := &snet.UDPAddr{
		IA: pkt.Source.IA,
		Host: &net.UDPAddr{
			IP:   pkt.Source.Host.IP().AsSlice(),
			Port: int(udp.SrcPort),
		},
		Path:    replyPath,
		NextHop: remoteAddr.(*net.UDPAddr),
	}

	eps[0] = &ScionNetEndpoint{
		StdNetEndpoint: StdNetEndpoint{
			AddrPort: netip.AddrPortFrom(
				netip.MustParseAddr(scionAddr.NextHop.IP.String()),
				uint16(scionAddr.NextHop.Port)),
		},
		scionAddr: scionAddr,
	}
	sizes[0] = len(udp.Payload)
	copy(buf, udp.Payload)

	return 1, nil
}

// writeSingle writes a single SCION packet (fallback for non-batch systems)
func (s *ScionBatchConn) writeSingle(buf []byte, ep Endpoint) error {
	scionEp, ok := ep.(*ScionNetEndpoint)
	if !ok {
		return fmt.Errorf("invalid endpoint type")
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

	_, err := s.conn.WriteTo(scionPkt.Bytes, scionEp.scionAddr.NextHop)
	return err
}
