/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

var (
	_ Bind = (*ScionNetBind)(nil)
)

// ScionNetBind implements Bind for SCION networks with fallback to standard IP.
type ScionNetBind struct {
	mu     sync.Mutex
	logger Logger

	// SCION network and connections
	scionNetwork  *snet.SCIONNetwork
	scionConn     *snet.Conn
	localAddr     *net.UDPAddr
	daemonService daemon.Service
	daemonConn    daemon.Connector


	// Path management
	pathPolicy PathPolicy
	pathMu     sync.RWMutex

	// Configuration
	config *ScionConfig

	// State
	closed bool
}

// ScionConfig holds SCION-specific configuration
type ScionConfig struct {
	DaemonAddr   string
	LocalAS      addr.AS
	TopologyFile string
	PathPolicy   PathPolicy
	LocalIA      addr.IA
	LocalIP      net.IP
	LocalPort    uint16
}

type PathPolicy int

const (
	PathPolicyShortest PathPolicy = iota
	PathPolicyBandwidth
	PathPolicyLatency
	PathPolicyFirst
)

func (p PathPolicy) String() string {
	switch p {
	case PathPolicyShortest:
		return "shortest"
	case PathPolicyBandwidth:
		return "bandwidth"
	case PathPolicyLatency:
		return "latency"
	case PathPolicyFirst:
		return "first"
	default:
		return "unknown"
	}
}

func ParsePathPolicy(s string) PathPolicy {
	switch strings.ToLower(s) {
	case "shortest":
		return PathPolicyShortest
	case "bandwidth":
		return PathPolicyBandwidth
	case "latency":
		return PathPolicyLatency
	case "first":
		return PathPolicyFirst
	default:
		return PathPolicyFirst
	}
}

// Logger interface for SCION bind
type Logger interface {
	Verbosef(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// ScionNetEndpoint represents a SCION endpoint
type ScionNetEndpoint struct {
	scionAddr *snet.UDPAddr
}

var (
	_ Endpoint = &ScionNetEndpoint{}
)

func NewScionNetBind(config *ScionConfig, logger Logger) *ScionNetBind {
	return &ScionNetBind{
		config: config,
		logger: logger,
	}
}

func (s *ScionNetBind) initSCION() error {
	if s.config == nil {
		return fmt.Errorf("SCION config is nil")
	}

	// Set up daemon service
	daemonAddr := s.config.DaemonAddr
	if daemonAddr == "" {
		daemonAddr = s.config.DaemonAddr
	}

	s.daemonService = daemon.Service{
		Address: daemonAddr,
		Metrics: daemon.Metrics{},
	}

	// Connect to SCION daemon
	ctx := context.Background()
	conn, err := s.daemonService.Connect(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect to SCION daemon at %s: %w", daemonAddr, err)
	}
	s.daemonConn = conn

	// Get local IA from daemon
	localIA, err := s.daemonConn.LocalIA(ctx)
	if err != nil {
		s.daemonConn.Close()
		return fmt.Errorf("failed to get local IA from daemon: %w", err)
	}

	// Override with config if specified
	if s.config.LocalIA.IsZero() {
		s.config.LocalIA = localIA
	}

	// Initialize SCION network with proper topology
	s.scionNetwork = &snet.SCIONNetwork{
		Topology: &scionTopology{
			localIA: localIA,
			daemon:  s.daemonConn,
		},
		// ReplyPather: &defaultReplyPather{},
		Metrics: snet.SCIONNetworkMetrics{},
	}

	s.pathPolicy = s.config.PathPolicy
	s.logger.Verbosef("SCION network initialized with IA", s.config.LocalIA)

	return nil
}

func (s *ScionNetBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger.Verbosef("Open called with port", port)
	s.logger.Verbosef("scionConn:", s.scionConn)
	s.logger.Verbosef("closed:", s.closed)
	if s.scionConn != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	var fns []ReceiveFunc
	var actualPort uint16

	if s.config != nil {
		err := s.initSCION()
		if err != nil {
			s.logger.Errorf("Failed to initialize SCION: %v", err)
			return nil, 0, err
		} else {
			// Create SCION local address
			s.localAddr = &net.UDPAddr{IP: s.config.LocalIP, Port: int(port)}

			// Listen on SCION
			conn, err := s.scionNetwork.Listen(context.Background(), "udp", s.localAddr)
			if err != nil {
				s.logger.Errorf("Failed to listen on SCION: %v", err)
				return nil, 0, err
			} else {
				s.scionConn = conn
				actualPort = uint16(s.scionConn.LocalAddr().(*snet.UDPAddr).Host.Port)
				fns = append(fns, s.makeReceiveSCION())
				s.logger.Verbosef("SCION listener started on port %d", actualPort)
			}
		}
	}

	if len(fns) == 0 {
		return nil, 0, fmt.Errorf("no listeners could be started")
	}

	return fns, actualPort, nil
}

func (s *ScionNetBind) makeReceiveSCION() ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		if s.scionConn == nil {
			return 0, net.ErrClosed
		}

		// Read packet from SCION connection
		buffer := bufs[0]
		fmt.Println("buffer:", len(buffer))
		readBytes, remote, err := s.scionConn.ReadFrom(buffer)
		if err != nil {
			fmt.Println("Error reading from SCION connection:", err)
			return 0, err
		}

		sizes[0] = readBytes
		// Convert net.Addr to our endpoint type
		if scionAddr, ok := remote.(*snet.UDPAddr); ok {
			eps[0] = &ScionNetEndpoint{
				scionAddr: scionAddr,
			}
		} else {
			// Fallback if it's not a SCION address
			return 0, fmt.Errorf("unexpected address type: %T", remote)
		}

		return 1, nil
	}
}

func (s *ScionNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true

	var err1, err2, err3 error
	if s.scionConn != nil {
		err1 = s.scionConn.Close()
		s.scionConn = nil
	}

	if s.daemonConn != nil {
		err2 = s.daemonConn.Close()
		s.daemonConn = nil
	}

	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func (s *ScionNetBind) SetMark(mark uint32) error {
	// SCION doesn't support SO_MARK directly
	return nil
}

func (s *ScionNetBind) Send(bufs [][]byte, ep Endpoint) error {
	scionEp, ok := ep.(*ScionNetEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}

	// Send via SCION if available and endpoint is SCION
	if s.scionConn != nil {
		return s.sendSCION(bufs, scionEp)
	}

	return fmt.Errorf("no suitable transport for endpoint")
}

func (s *ScionNetBind) sendSCION(bufs [][]byte, ep *ScionNetEndpoint) error {
	for _, buf := range bufs {
		_, err := s.scionConn.WriteTo(buf, ep.scionAddr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ScionNetBind) ParseEndpoint(str string) (Endpoint, error) {
	// Try parsing as SCION address first
	if strings.Contains(str, ",") {
		scionAddr, err := snet.ParseUDPAddr(str)
		if err == nil {
			return &ScionNetEndpoint{
				scionAddr: scionAddr,
			}, nil
		}
	}

	return nil, fmt.Errorf("invalid endpoint: %s", str)
}

func (s *ScionNetBind) BatchSize() int {
	return 1 // SCION typically processes one packet at a time
}

// Path management methods (simplified for now)
func (s *ScionNetBind) SetPathPolicy(policy PathPolicy) {
	s.pathMu.Lock()
	defer s.pathMu.Unlock()
	s.pathPolicy = policy
}
// ScionNetEndpoint implementations
func (e *ScionNetEndpoint) ClearSrc() {

}

func (e *ScionNetEndpoint) SrcToString() string {
	if e.scionAddr != nil {
		return "" // SCION doesn't expose source the same way
	}
	return ""
}

func (e *ScionNetEndpoint) DstToString() string {
	if e.scionAddr != nil {
		return e.scionAddr.String()
	}
	return ""
}

func (e *ScionNetEndpoint) DstToBytes() []byte {
	if e.scionAddr != nil {
		return []byte(e.scionAddr.String())
	}
	return nil
}

func (e *ScionNetEndpoint) DstIP() netip.Addr {
	if e.scionAddr != nil {
		if e.scionAddr.Host != nil {
			addr, _ := netip.AddrFromSlice(e.scionAddr.Host.IP)
			return addr
		}
	}
	return netip.Addr{}
}

func (e *ScionNetEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

func (e *ScionNetEndpoint) Port() uint16 {
	if e.scionAddr != nil {
		if e.scionAddr.Host != nil {
			return uint16(e.scionAddr.Host.Port)
		}
	}
	return 0
}

func (e *ScionNetEndpoint) GetScionAddr() *snet.UDPAddr {
	return e.scionAddr
}

func (e *ScionNetEndpoint) SetScionAndIPAddresses(scionAddr *snet.UDPAddr) {
	e.scionAddr = scionAddr
}

// scionTopology implements the Topology interface for SCION
type scionTopology struct {
	localIA addr.IA
	daemon  daemon.Connector
}

func (t *scionTopology) LocalIA(ctx context.Context) (addr.IA, error) {
	return t.localIA, nil
}

func (t *scionTopology) PortRange(ctx context.Context) (uint16, uint16, error) {
	// Return default port range for SCION dispatcher
	return 30061, 30061, nil
}

func (t *scionTopology) Interfaces(ctx context.Context) (map[uint16]netip.AddrPort, error) {
	// For basic implementation, return empty map
	// In a full implementation, this would query the daemon for interface information
	return make(map[uint16]netip.AddrPort), nil
}

// // defaultReplyPather implements the ReplyPather interface
// type defaultReplyPather struct{}

// func (r *defaultReplyPather) ReplyPath(rawPath snet.RawPath) (snet.DataplanePath, error) {
// 	if len(rawPath.Raw) == 0 {
// 		return nil, fmt.Errorf("empty raw path provided")
// 	}
// 	// In a basic implementation, return the raw path as dataplane path
// 	// A full implementation would need to properly reverse the path
// 	return rawPath, nil
// }
