package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

var (
	_ Bind = (*ScionNetBind)(nil)
)

// ScionNetBind implements Bind for SCION networks
type ScionNetBind struct {
	mu     sync.Mutex
	logger Logger

	// SCION network and connections
	scionNetwork  *snet.SCIONNetwork
	scionConn     *snet.Conn
	batchConn     *ScionBatchConn // New batch connection
	localAddr     *net.UDPAddr
	daemonService daemon.Service
	daemonConn    daemon.Connector

	// Path management
	pathPolicy  PathPolicy
	pathManager *PathManager
	pathMu      sync.RWMutex

	// Configuration
	config *ScionConfig

	// State
	closed   bool
	useBatch bool // Whether to use batch operations
}

// ScionConfig holds SCION-specific configuration
type ScionConfig struct {
	DaemonAddr string
	LocalAS    addr.AS
	PathPolicy PathPolicy
	LocalIA    addr.IA
	LocalIP    net.IP
	LocalPort  uint16
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
	src       []byte
}

var (
	_ Endpoint = &ScionNetEndpoint{}
)

func NewScionNetBind(config *ScionConfig, logger Logger) *ScionNetBind {
	return &ScionNetBind{
		config:   config,
		logger:   logger,
		useBatch: runtime.GOOS == "linux" || runtime.GOOS == "android",
	}
}

func (s *ScionNetBind) initSCION() error {
	if s.config == nil {
		return fmt.Errorf("SCION config is nil")
	}

	// Set up daemon service
	daemonAddr := s.config.DaemonAddr
	if daemonAddr == "" {
		daemonAddr = DefaultSCIONDaemonAddr
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
		Topology:    s.daemonConn,
		ReplyPather: snet.DefaultReplyPather{},
		Metrics:     snet.SCIONNetworkMetrics{},
	}

	s.pathManager = NewPathManager(
		s.daemonConn,        // SCION daemon connection
		s.config.LocalIA,    // our IA
		s.config.PathPolicy, // selection policy
		s.logger,
		WithRefreshInterval(1*time.Minute),
	)
	s.pathManager.Start()

	s.pathPolicy = s.config.PathPolicy
	s.logger.Verbosef("SCION network initialized with IA %s", s.config.LocalIA)

	return nil
}

func (s *ScionNetBind) getUDPConn(localAddr *net.UDPAddr, port uint16) (*net.UDPConn, error) {
	start, end, err := s.scionNetwork.Topology.PortRange(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get port range: %w", err)
	}
	if port != 0 {
		conn, err := listenConfig().ListenPacket(context.Background(), "udp", localAddr.String())
		if err != nil {
			return nil, fmt.Errorf("failed to listen on SCION: %w", err)
		}
		return conn.(*net.UDPConn), nil
	}

	restrictedStart := start
	if start < 1024 {
		restrictedStart = 1024
	}
	for port := end; port >= restrictedStart; port-- {
		localAddr.Port = int(port)
		conn, err := listenConfig().ListenPacket(context.Background(), "udp", localAddr.String())
		if err == nil {
			return conn.(*net.UDPConn), nil
		}
		if strings.Contains(err.Error(), "address already in use") {
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("binding to port range: start=%d, end=%d",
		restrictedStart, end)
}

func (s *ScionNetBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.scionConn != nil || s.batchConn != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	var fns []ReceiveFunc
	var actualPort uint16

	if s.config != nil {
		err := s.initSCION()
		if err != nil {
			s.logger.Errorf("Failed to initialize SCION: %v", err)
			return nil, 0, err
		}

		// Create SCION local address
		s.localAddr = &net.UDPAddr{IP: s.config.LocalIP, Port: int(port)}

		if s.useBatch {
			// Try to use batch connection on Linux/Android
			var udpConn *net.UDPConn
			var err error
			udpConn, err = s.getUDPConn(s.localAddr, port)
			if err != nil {
				s.logger.Errorf("Failed to create UDP conn for batch: %v", err)
				s.logger.Verbosef("Falling back to regular SCION connection")
				s.useBatch = false
			} else {
				s.batchConn = NewScionBatchConn(
					udpConn,
					s.config.LocalIA,
					s.scionNetwork.Topology,
					s.pathManager,
					s.logger,
				)
				s.batchConn.SetSCMPHandler(s.scionNetwork.SCMPHandler)
				actualPort = uint16(s.batchConn.LocalAddr().(*net.UDPAddr).Port)
				fns = append(fns, s.makeReceiveBatch())
				s.logger.Verbosef("SCION batch listener started on port %d", actualPort)
			}
		}

		// Fallback to regular SCION connection if batch failed or not supported
		if !s.useBatch || s.batchConn == nil {
			conn, err := s.scionNetwork.Listen(context.Background(), "udp", s.localAddr)
			if err != nil {
				s.logger.Errorf("Failed to listen on SCION: %v", err)
				return nil, 0, err
			}
			s.scionConn = conn
			actualPort = uint16(s.scionConn.LocalAddr().(*snet.UDPAddr).Host.Port)
			fns = append(fns, s.makeReceiveSCION())
			s.logger.Verbosef("SCION listener started on port %d (non-batch)", actualPort)
		}
	}

	if len(fns) == 0 {
		return nil, 0, fmt.Errorf("no listeners could be started")
	}

	return fns, actualPort, nil
}

func (s *ScionNetBind) makeReceiveBatch() ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		if s.batchConn == nil {
			return 0, net.ErrClosed
		}
		return s.batchConn.ReadBatch(bufs, sizes, eps)
	}
}

func (s *ScionNetBind) makeReceiveSCION() ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		if s.scionConn == nil {
			return 0, net.ErrClosed
		}

		// Read packet from SCION connection
		buffer := bufs[0]
		readBytes, remote, err := s.scionConn.ReadFrom(buffer)
		if err != nil {
			s.logger.Errorf("Error reading from SCION connection: %v", err)
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

	var err1, err2, err3, err4 error

	if s.batchConn != nil {
		err1 = s.batchConn.Close()
		s.batchConn = nil
	}

	if s.scionConn != nil {
		err2 = s.scionConn.Close()
		s.scionConn = nil
	}

	if s.daemonConn != nil {
		err3 = s.daemonConn.Close()
		s.daemonConn = nil
	}

	if s.pathManager != nil {
		s.pathManager.Close()
		s.pathManager = nil
	}

	// Return first non-nil error
	for _, err := range []error{err1, err2, err3, err4} {
		if err != nil {
			return err
		}
	}
	return nil
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

	if p := s.pathManager.SelectPath(scionEp.scionAddr.IA); p != nil {
		scionEp.scionAddr.Path = p.Dataplane()
		scionEp.scionAddr.NextHop = p.UnderlayNextHop()
	}

	// Use batch connection if available
	if s.batchConn != nil && s.useBatch {
		return s.batchConn.WriteBatch(bufs, scionEp)
	}

	// Fallback to regular SCION connection
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
			scionEndpoint := &ScionNetEndpoint{
				scionAddr: scionAddr,
			}
			s.pathManager.RegisterEndpoint(scionAddr.IA)
			if p := s.pathManager.SelectPath(scionAddr.IA); p != nil {
				scionAddr.Path = p.Dataplane()
				scionAddr.NextHop = p.UnderlayNextHop()
			}
			return scionEndpoint, nil
		}
	}

	return nil, fmt.Errorf("invalid endpoint: %s", str)
}

func (s *ScionNetBind) BatchSize() int {
	if s.batchConn != nil {
		return s.batchConn.BatchSize()
	}
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
