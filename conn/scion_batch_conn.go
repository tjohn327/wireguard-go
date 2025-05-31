/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/snet"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ScionBatchConn provides batch send/receive capabilities for SCION packets
type ScionBatchConn struct {
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

	// Buffer pools
	bufferPool sync.Pool
	msgsPool   sync.Pool

	// SCION packet pools
	scionPktPool sync.Pool

	// Capabilities
	supportsBatch bool
	batchSize     int
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
		bufferPool: sync.Pool{
			New: func() any {
				buf := make([]byte, common.SupportedMTU)
				return &buf
			},
		},
		scionPktPool: sync.Pool{
			New: func() any {
				return &snet.Packet{
					Bytes: make(snet.Bytes, common.SupportedMTU),
				}
			},
		},
	}

	// Enable batch operations on Linux/Android
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		if conn.LocalAddr().(*net.UDPAddr).IP.To4() != nil {
			sbc.ipv4PC = ipv4.NewPacketConn(conn)
			sbc.supportsBatch = true
			sbc.batchSize = IdealBatchSize
		} else {
			sbc.ipv6PC = ipv6.NewPacketConn(conn)
			sbc.supportsBatch = true
			sbc.batchSize = IdealBatchSize
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
	}

	return sbc
}

func (s *ScionBatchConn) SetSCMPHandler(handler snet.SCMPHandler) {
	s.scmpHandler = handler
}

func (s *ScionBatchConn) LocalAddr() net.Addr {
	return s.localAddr
}

func (s *ScionBatchConn) Close() error {
	return s.conn.Close()
}

func (s *ScionBatchConn) BatchSize() int {
	return s.batchSize
}

// ReadBatch reads multiple SCION packets in a single syscall
func (s *ScionBatchConn) ReadBatch(bufs [][]byte, sizes []int, eps []Endpoint) (int, error) {
	if !s.supportsBatch || s.ipv4PC == nil && s.ipv6PC == nil {
		// Fallback to single packet read
		return s.readSingle(bufs[0], sizes, eps)
	}

	msgs := s.msgsPool.Get().(*[]ipv6.Message)
	defer s.msgsPool.Put(msgs)

	// Setup message buffers
	for i := range bufs {
		(*msgs)[i].Buffers[0] = bufs[i]
		(*msgs)[i].OOB = (*msgs)[i].OOB[:cap((*msgs)[i].OOB)]
	}

	// Read batch
	var numMsgs int
	var err error
	if s.ipv4PC != nil {
		numMsgs, err = s.ipv4PC.ReadBatch((*msgs)[:len(bufs)], 0)
	} else {
		numMsgs, err = s.ipv6PC.ReadBatch((*msgs)[:len(bufs)], 0)
	}
	if err != nil {
		return 0, err
	}

	// Process each message
	validMsgs := 0
	for i := 0; i < numMsgs; i++ {
		msg := &(*msgs)[i]
		if msg.N == 0 {
			continue
		}

		// Parse SCION packet
		pkt := s.scionPktPool.Get().(*snet.Packet)
		defer s.scionPktPool.Put(pkt)

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

		eps[validMsgs] = &ScionNetEndpoint{scionAddr: scionAddr}
		sizes[validMsgs] = len(udp.Payload)
		copy(bufs[validMsgs], udp.Payload)
		validMsgs++
	}

	return validMsgs, nil
}

// WriteBatch sends multiple SCION packets in a single syscall
func (s *ScionBatchConn) WriteBatch(bufs [][]byte, endpoint Endpoint) error {
	if !s.supportsBatch || s.ipv4PC == nil && s.ipv6PC == nil {
		// Fallback to single packet writes
		for _, buf := range bufs {
			if err := s.writeSingle(buf, endpoint); err != nil {
				return err
			}
		}
		return nil
	}

	msgs := s.msgsPool.Get().(*[]ipv6.Message)
	defer s.msgsPool.Put(msgs)

	scionEp, ok := endpoint.(*ScionNetEndpoint)
	if !ok {
		return fmt.Errorf("invalid endpoint type")
	}

	// Prepare SCION packets
	for i, buf := range bufs {

		// Get buffer for serialized packet
		pktBuf := *(s.bufferPool.Get().(*[]byte))
		defer s.bufferPool.Put(&pktBuf)

		// Create SCION packet
		pkt := &snet.Packet{
			Bytes: snet.Bytes(pktBuf),
			PacketInfo: snet.PacketInfo{
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
			},
		}

		// Serialize packet
		if err := pkt.Serialize(); err != nil {
			return fmt.Errorf("failed to serialize SCION packet: %w", err)
		}

		// Setup message
		(*msgs)[i].Buffers[0] = pkt.Bytes
		(*msgs)[i].Addr = scionEp.scionAddr.NextHop
		setSrcControl(&(*msgs)[i].OOB, &StdNetEndpoint{
			AddrPort: scionEp.scionAddr.NextHop.AddrPort(),
		})
	}

	// Send batch
	var err error
	if s.ipv4PC != nil {
		_, err = s.ipv4PC.WriteBatch((*msgs)[:len(bufs)], 0)
	} else {
		_, err = s.ipv6PC.WriteBatch((*msgs)[:len(bufs)], 0)
	}

	return err
}

// readSingle reads a single SCION packet (fallback for non-batch systems)
func (s *ScionBatchConn) readSingle(buf []byte, sizes []int, eps []Endpoint) (int, error) {
	pkt := s.scionPktPool.Get().(*snet.Packet)
	defer s.scionPktPool.Put(pkt)

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

	eps[0] = &ScionNetEndpoint{scionAddr: scionAddr}
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

	pktBuf := *(s.bufferPool.Get().(*[]byte))
	defer s.bufferPool.Put(&pktBuf)

	pkt := &snet.Packet{
		Bytes: snet.Bytes(pktBuf),
		PacketInfo: snet.PacketInfo{
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
		},
	}

	if err := pkt.Serialize(); err != nil {
		return fmt.Errorf("failed to serialize SCION packet: %w", err)
	}

	_, err := s.conn.WriteTo(pkt.Bytes, scionEp.scionAddr.NextHop)
	return err
}
