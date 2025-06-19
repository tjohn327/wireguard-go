// SCION Network Bind for WireGuard backend.
// Provides SCION network support for WireGuard.

package conn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fastsnet/fastsnet/pkg/fastsnet"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

var (
	_ Bind = (*ScionNetBind)(nil)
)

// ScionNetBind implements Bind for SCION networks
type ScionNetBind struct {
	mu     sync.RWMutex
	logger Logger

	// SCION network and connections - protected by atomic operations for lock-free access
	scionNetwork  atomic.Pointer[fastsnet.FastSCIONNetwork]
	scionConn     atomic.Pointer[fastsnet.FastSCIONPacketConn]
	
	localAddr     *net.UDPAddr
	daemonService daemon.Service
	daemonConn    daemon.Connector

	// Path management - protected by atomic operations
	pathManager atomic.Pointer[PathManager]

	// Configuration
	config *ScionConfig

	// State - immutable after initialization
	useBatch bool
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
	StdNetEndpoint
	scionAddr *snet.UDPAddr
}

var (
	_ Endpoint = &ScionNetEndpoint{}
)

func NewScionNetBind(config *ScionConfig, logger Logger) *ScionNetBind {
	useBatch := os.Getenv("USE_BATCH") == "1"
	if useBatch {
		useBatch = runtime.GOOS == "linux" || runtime.GOOS == "android"
	}

	return &ScionNetBind{
		config:   config,
		logger:   logger,
		useBatch: useBatch,
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

	batchSize := 1
	if s.useBatch {
		batchSize = IdealBatchSize
	}

	// Initialize SCION network with proper topology
	scionNet := &fastsnet.FastSCIONNetwork{
		Topology:  s.daemonConn,
		BatchSize: batchSize,
	}
	s.scionNetwork.Store(scionNet)

	pathMgr := NewPathManager(
		s.daemonConn,        // SCION daemon connection
		s.config.LocalIA,    // our IA
		s.config.PathPolicy, // selection policy
		s.logger,
		WithRefreshInterval(5*time.Minute),
	)
	s.pathManager.Store(pathMgr)
	s.logger.Verbosef("SCION network initialized with IA %s", s.config.LocalIA)

	return nil
}

func (s *ScionNetBind) getUDPConn(localAddr *net.UDPAddr, port uint16) (*net.UDPConn, error) {
	scionNet := s.scionNetwork.Load()
	if scionNet == nil {
		return nil, fmt.Errorf("SCION network not initialized")
	}
	start, end, err := scionNet.Topology.PortRange(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get port range: %w", err)
	}

	network := "udp4"
	if localAddr.IP.To4() == nil {
		network = "udp6"
	}

	if port != 0 {
		conn, err := listenConfig().ListenPacket(context.Background(), network, localAddr.String())
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
		conn, err := listenConfig().ListenPacket(context.Background(), network, localAddr.String())
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

	if s.scionConn.Load() != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	// Initialize SCION if config is provided
	if s.config != nil {
		if err := s.initSCION(); err != nil {
			s.logger.Errorf("Failed to initialize SCION: %v", err)
			return nil, 0, fmt.Errorf("SCION initialization failed: %w", err)
		}
	} else {
		return nil, 0, fmt.Errorf("SCION config is required")
	}

	var fns []ReceiveFunc
	var actualPort uint16

	// Create SCION local address
	s.localAddr = &net.UDPAddr{IP: s.config.LocalIP, Port: int(port)}

	udpConn, err := s.getUDPConn(s.localAddr, port)
	if err != nil {
		s.logger.Errorf("Failed to create UDP conn: %v", err)
		return nil, 0, fmt.Errorf("failed to create UDP conn: %w", err)
	}

	scionNet := s.scionNetwork.Load()
	if scionNet == nil {
		return nil, 0, fmt.Errorf("SCION network not initialized")
	}
	
	conn := fastsnet.NewFastSCIONPacketConn(udpConn, scionNet.Topology,
		scionNet.BatchSize)
	s.scionConn.Store(conn)

	actualPort = uint16(conn.LocalAddr().(*snet.UDPAddr).Host.Port)

	fns = append(fns, s.makeReceiveSCION())
	s.logger.Verbosef("SCION listener started on port %d (non-batch)", actualPort)

	if len(fns) == 0 {
		return nil, 0, fmt.Errorf("no listeners could be started")
	}

	return fns, actualPort, nil
}

func (s *ScionNetBind) makeReceiveSCION() ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
		conn := s.scionConn.Load()
		if conn == nil {
			return 0, net.ErrClosed
		}

		if s.useBatch {
			return s.receiveBatchSCION(conn, bufs, sizes, eps)
		}

		return s.receiveSCION(conn, bufs, sizes, eps)
	}
}

func (s *ScionNetBind) receiveBatchSCION(conn *fastsnet.FastSCIONPacketConn,
	bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
	if conn == nil {
		return 0, net.ErrClosed
	}

	readSizes, addrs, err := conn.ReadBatchFrom(bufs)
	if err != nil {
		return 0, err
	}

	for i, size := range readSizes {
		sizes[i] = size
		addr, err := convertIPToAddr(addrs[i].NextHop.IP)
		if err != nil {
			return 0, fmt.Errorf("invalid IP address in SCION NextHop: %w", err)
		}
		addrPort := netip.AddrPortFrom(addr, uint16(addrs[i].NextHop.Port))
		eps[i] = &ScionNetEndpoint{
			StdNetEndpoint: StdNetEndpoint{
				AddrPort: addrPort,
			},
			scionAddr: addrs[i],
		}
	}
	return len(sizes), nil
}

func (s *ScionNetBind) receiveSCION(conn *fastsnet.FastSCIONPacketConn,
	bufs [][]byte, sizes []int, eps []Endpoint) (n int, err error) {
	if conn == nil {
		return 0, net.ErrClosed
	}
	// Read packet from SCION connection
	buffer := bufs[0]
	readBytes, remote, err := conn.ReadFrom(buffer)
	if err != nil {
		s.logger.Errorf("Error reading from SCION connection: %v", err)
		return 0, err
	}

	sizes[0] = readBytes
	// Convert net.Addr to our endpoint type
	if scionAddr, ok := remote.(*snet.UDPAddr); ok {
		// Use optimized IP address conversion
		addr, err := convertIPToAddr(scionAddr.NextHop.IP)
		if err != nil {
			return 0, fmt.Errorf("invalid IP address in SCION NextHop: %w", err)
		}

		addrPort := netip.AddrPortFrom(addr, uint16(scionAddr.NextHop.Port))
		eps[0] = &ScionNetEndpoint{
			StdNetEndpoint: StdNetEndpoint{
				AddrPort: addrPort,
			},
			scionAddr: scionAddr,
		}
	} else {
		// Fallback if it's not a SCION address
		return 0, fmt.Errorf("unexpected address type: %T", remote)
	}

	return 1, nil
}

func (s *ScionNetBind) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	
	// Close SCION connection
	if conn := s.scionConn.Swap(nil); conn != nil {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("scion conn close: %w", err)
		}
	}

	// Close path manager
	if pm := s.pathManager.Swap(nil); pm != nil {
		pm.Close()
	}

	// Clear SCION network
	s.scionNetwork.Store(nil)

	// Close daemon connection
	if s.daemonConn != nil {
		if err := s.daemonConn.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("daemon conn close: %w", err)
		}
		s.daemonConn = nil
	}

	return firstErr
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

	conn := s.scionConn.Load()
	if conn == nil {
		return net.ErrClosed
	}

	if s.useBatch {
		return s.sendBatchSCION(bufs, scionEp, conn)
	}

	return s.sendSCION(bufs, scionEp, conn)
}

func (s *ScionNetBind) sendSCION(bufs [][]byte, ep *ScionNetEndpoint, conn *fastsnet.FastSCIONPacketConn) error {
	for _, buf := range bufs {
		_, err := conn.WriteTo(buf, ep.scionAddr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *ScionNetBind) sendBatchSCION(bufs [][]byte, ep *ScionNetEndpoint, conn *fastsnet.FastSCIONPacketConn) error {
	dst := ep.scionAddr

	n, err := conn.WriteBatchTo(bufs, dst)
	if err != nil {
		return err
	}
	if n != len(bufs) {
		return fmt.Errorf("expected to write %d packets, wrote %d", len(bufs), n)
	}
	return nil
}

func (s *ScionNetBind) ParseEndpoint(str string) (Endpoint, error) {
	// Try parsing as SCION address first
	if strings.Contains(str, ",") {
		scionAddr, err := snet.ParseUDPAddr(str)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SCION address %s: %w", str, err)
		}

		scionEndpoint := &ScionNetEndpoint{
			scionAddr: scionAddr,
		}

		pathManager := s.pathManager.Load()

		if pathManager != nil {
			pathManager.RegisterEndpoint(scionAddr.IA)
			if p, err := pathManager.GetPath(scionAddr.IA); err == nil {
				scionAddr.Path = p.Dataplane()
				scionAddr.NextHop = p.UnderlayNextHop()

				// Use optimized IP address conversion
				addr, _ := convertIPToAddr(scionAddr.NextHop.IP)

				scionEndpoint.StdNetEndpoint.AddrPort = netip.AddrPortFrom(
					addr, uint16(scionAddr.NextHop.Port))
			}
		}
		return scionEndpoint, nil
	}

	return nil, fmt.Errorf("invalid endpoint: %s", str)
}

func (s *ScionNetBind) BatchSize() int {
	if scionNet := s.scionNetwork.Load(); scionNet != nil {
		return scionNet.BatchSize
	} else if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return IdealBatchSize
	}
	return 1
}

// Path management methods
func (s *ScionNetBind) SetPathPolicy(policy string) {
	if pm := s.pathManager.Load(); pm != nil {
		pm.SetPolicy(policy)
	}
}

func (e *ScionNetEndpoint) GetScionAddr() *snet.UDPAddr {
	return e.scionAddr
}

func (e *ScionNetEndpoint) SetScionAndIPAddresses(scionAddr *snet.UDPAddr) {
	e.scionAddr = scionAddr
	if scionAddr != nil && scionAddr.NextHop != nil {
		// Use optimized IP address conversion
		if addr, err := convertIPToAddr(scionAddr.NextHop.IP); err == nil {
			e.StdNetEndpoint.AddrPort = netip.AddrPortFrom(
				addr, uint16(scionAddr.NextHop.Port))
		}
	}
}

// convertIPToAddr efficiently converts net.IP to netip.Addr without string parsing
func convertIPToAddr(ip net.IP) (netip.Addr, error) {
	if ip4 := ip.To4(); ip4 != nil {
		return netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}), nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		return netip.AddrFrom16([16]byte(ip16)), nil
	}
	return netip.Addr{}, fmt.Errorf("invalid IP address")
}

// GetPathsJSON returns a JSON string containing available paths for the given IA
func (bind *ScionNetBind) GetPathsJSON(iaStr string) (string, error) {
	pathManager := bind.pathManager.Load()
	if pathManager == nil {
		return "", fmt.Errorf("path manager not initialized")
	}
	return pathManager.GetPathsJSON(iaStr)
}

// SetPath sets a specific path for a destination IA
func (bind *ScionNetBind) SetPath(iaStr string, pathIndex int) error {
	pathManager := bind.pathManager.Load()
	if pathManager == nil {
		return fmt.Errorf("path manager not initialized")
	}
	return pathManager.SetPath(iaStr, pathIndex)
}

// GetPathPolicy returns the current path selection policy
func (bind *ScionNetBind) GetPathPolicy() string {
	pathManager := bind.pathManager.Load()
	if pathManager == nil {
		return "unknown"
	}
	return pathManager.policy.String()
}
