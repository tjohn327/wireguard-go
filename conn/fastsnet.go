package conn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/snet"
)

var (
	ErrBufferTooSmall = errors.New("buffer too small")
)

// FastSnetSerializer provides optimized SCION packet serialization
type FastSnetSerializer struct {
	// Pre-allocated buffers for reuse
	scratchBuf []byte
}

// NewFastSnetSerializer creates a new fast serializer
func NewFastSnetSerializer() *FastSnetSerializer {
	return &FastSnetSerializer{
		scratchBuf: make([]byte, 1 << 16 - 1),
	}
}

// SerializeUDP serializes a UDP packet using direct byte manipulation
// This is optimized for the common case of UDP over SCION
func (fs *FastSnetSerializer) SerializeUDP(
	srcIA, dstIA addr.IA,
	srcHost, dstHost addr.Host,
	srcPort, dstPort uint16,
	pathType uint8,
	pathBytes []byte,
	payload []byte,
	outBuf []byte,
) (int, error) {
	// Calculate sizes
	srcAddrLen := 4 // IPv4 default
	dstAddrLen := 4 // IPv4 default
	
	// Get raw addresses
	srcIP := srcHost.IP()
	dstIP := dstHost.IP()
	
	if srcIP.Is6() {
		srcAddrLen = 16
	}
	if dstIP.Is6() {
		dstAddrLen = 16
	}
	
	addrHdrLen := 2*addr.IABytes + srcAddrLen + dstAddrLen
	pathLen := len(pathBytes)
	scionHdrLen := slayers.CmnHdrLen + addrHdrLen + pathLen
	udpLen := 8 + len(payload)
	totalLen := scionHdrLen + udpLen
	
	if len(outBuf) < totalLen {
		return 0, ErrBufferTooSmall
	}
	
	// Zero the header area for clean state
	for i := 0; i < slayers.CmnHdrLen; i++ {
		outBuf[i] = 0
	}
	
	// Common header (12 bytes)
	// Version=0, TrafficClass=0, FlowID based on ports
	flowID := uint32(srcPort)<<4 | uint32(dstPort&0xf)
	binary.BigEndian.PutUint32(outBuf[0:4], flowID)
	
	outBuf[4] = byte(slayers.L4UDP)                          // NextHdr
	outBuf[5] = uint8(scionHdrLen / 4)                       // HdrLen in 4-byte units
	binary.BigEndian.PutUint16(outBuf[6:8], uint16(udpLen))  // PayloadLen
	
	// Path type and address types
	srcAddrType := uint8(0) // T4Ip
	dstAddrType := uint8(0) // T4Ip
	if srcIP.Is6() {
		srcAddrType = 1 // T16Ip
	}
	if dstIP.Is6() {
		dstAddrType = 1 // T16Ip
	}
	
	outBuf[8] = byte(pathType)                              // PathType
	outBuf[9] = (dstAddrType << 4) | srcAddrType            // Addr types
	// outBuf[10:12] reserved (already zeroed)
	
	// Address header
	off := slayers.CmnHdrLen
	
	// Destination IA
	binary.BigEndian.PutUint64(outBuf[off:], uint64(dstIA))
	off += addr.IABytes
	
	// Source IA
	binary.BigEndian.PutUint64(outBuf[off:], uint64(srcIA))
	off += addr.IABytes
	
	// Destination host
	if dstIP.Is4() {
		copy(outBuf[off:off+4], dstIP.AsSlice())
		off += 4
	} else {
		copy(outBuf[off:off+16], dstIP.AsSlice())
		off += 16
	}
	
	// Source host
	if srcIP.Is4() {
		copy(outBuf[off:off+4], srcIP.AsSlice())
		off += 4
	} else {
		copy(outBuf[off:off+16], srcIP.AsSlice())
		off += 16
	}
	
	// Path
	if pathLen > 0 {
		copy(outBuf[off:off+pathLen], pathBytes)
		off += pathLen
	}
	
	// UDP header
	binary.BigEndian.PutUint16(outBuf[off:], srcPort)
	binary.BigEndian.PutUint16(outBuf[off+2:], dstPort)
	binary.BigEndian.PutUint16(outBuf[off+4:], uint16(udpLen))
	binary.BigEndian.PutUint16(outBuf[off+6:], 0) // checksum disabled
	off += 8
	
	// Payload
	copy(outBuf[off:], payload)
	
	return totalLen, nil
}

// DeserializeUDP deserializes a UDP packet using direct byte access
func (fs *FastSnetSerializer) DeserializeUDP(
	buf []byte,
) (
	srcIA, dstIA addr.IA,
	srcHost, dstHost addr.Host,
	srcPort, dstPort uint16,
	pathType uint8,
	pathBytes []byte,
	payload []byte,
	err error,
) {
	if len(buf) < slayers.CmnHdrLen {
		err = ErrBufferTooSmall
		return
	}
	
	// Parse common header
	version := buf[0] >> 4
	if version != 0 {
		err = fmt.Errorf("unsupported SCION version: %d", version)
		return
	}
	
	nextHdr := buf[4]
	if slayers.L4ProtocolType(nextHdr) != slayers.L4UDP {
		err = fmt.Errorf("not a UDP packet: L4=%d", nextHdr)
		return
	}
	
	hdrLen := int(buf[5]) * 4
	payloadLen := binary.BigEndian.Uint16(buf[6:8])
	
	if len(buf) < hdrLen+int(payloadLen) {
		err = ErrBufferTooSmall
		return
	}
	
	pathType = buf[8] & 0x3f
	dstAddrType := (buf[9] >> 4) & 0xf
	srcAddrType := buf[9] & 0xf
	
	// Parse addresses
	off := slayers.CmnHdrLen
	
	// IAs
	dstIA = addr.IA(binary.BigEndian.Uint64(buf[off:]))
	off += addr.IABytes
	srcIA = addr.IA(binary.BigEndian.Uint64(buf[off:]))
	off += addr.IABytes
	
	// Host addresses
	if dstAddrType == 0 { // T4Ip
		var ipBytes [4]byte
		copy(ipBytes[:], buf[off:off+4])
		dstHost = addr.HostIP(netip.AddrFrom4(ipBytes))
		off += 4
	} else { // T16Ip
		var ipBytes [16]byte
		copy(ipBytes[:], buf[off:off+16])
		dstHost = addr.HostIP(netip.AddrFrom16(ipBytes))
		off += 16
	}
	
	if srcAddrType == 0 { // T4Ip
		var ipBytes [4]byte
		copy(ipBytes[:], buf[off:off+4])
		srcHost = addr.HostIP(netip.AddrFrom4(ipBytes))
		off += 4
	} else { // T16Ip
		var ipBytes [16]byte
		copy(ipBytes[:], buf[off:off+16])
		srcHost = addr.HostIP(netip.AddrFrom16(ipBytes))
		off += 16
	}
	
	// Path
	pathLen := hdrLen - off
	if pathLen > 0 {
		pathBytes = buf[off : off+pathLen]
		off += pathLen
	}
	
	// UDP header
	srcPort = binary.BigEndian.Uint16(buf[off:])
	dstPort = binary.BigEndian.Uint16(buf[off+2:])
	udpLen := binary.BigEndian.Uint16(buf[off+4:])
	off += 8
	
	// Payload
	payloadSize := int(udpLen) - 8
	if payloadSize > 0 {
		payload = buf[off : off+payloadSize]
	}
	
	return
}

// SerializePacket serializes an snet.Packet efficiently
// This is a compatibility wrapper that extracts data from snet.Packet
func (fs *FastSnetSerializer) SerializePacket(pkt *snet.Packet, outBuf []byte) (int, error) {
	// Check if packet already has bytes
	if len(pkt.Bytes) > 0 {
		if len(outBuf) < len(pkt.Bytes) {
			return 0, ErrBufferTooSmall
		}
		copy(outBuf, pkt.Bytes)
		return len(pkt.Bytes), nil
	}
	
	// Extract UDP payload
	udpPayload, ok := pkt.Payload.(snet.UDPPayload)
	if !ok {
		return 0, fmt.Errorf("only UDP payloads supported in fast path")
	}
	
	// Extract path bytes
	var pathType uint8
	var pathBytes []byte
	
	switch p := pkt.Path.(type) {
	case snet.RawPath:
		pathType = uint8(p.PathType)
		pathBytes = p.Raw
	default:
		// For other path types, fall back to standard serialization
		pkt.Bytes = outBuf
		if err := pkt.Serialize(); err != nil {
			return 0, err
		}
		return len(pkt.Bytes), nil
	}
	
	return fs.SerializeUDP(
		pkt.Source.IA,
		pkt.Destination.IA,
		pkt.Source.Host,
		pkt.Destination.Host,
		udpPayload.SrcPort,
		udpPayload.DstPort,
		pathType,
		pathBytes,
		udpPayload.Payload,
		outBuf,
	)
}

// DeserializePacket deserializes into an snet.Packet
func (fs *FastSnetSerializer) DeserializePacket(buf []byte) (*snet.Packet, error) {
	srcIA, dstIA, srcHost, dstHost, srcPort, dstPort, pathType, pathBytes, payload, err := 
		fs.DeserializeUDP(buf)
	
	if err != nil {
		return nil, err
	}
	
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   srcIA,
				Host: srcHost,
			},
			Destination: snet.SCIONAddress{
				IA:   dstIA,
				Host: dstHost,
			},
			Path: snet.RawPath{
				PathType: path.Type(pathType),
				Raw:      pathBytes,
			},
			Payload: snet.UDPPayload{
				SrcPort: srcPort,
				DstPort: dstPort,
				Payload: payload,
			},
		},
		Bytes: buf,
	}
	
	return pkt, nil
}

// BatchSerialize serializes multiple packets efficiently
func (fs *FastSnetSerializer) BatchSerialize(packets []snet.Packet, outBufs [][]byte) ([]int, error) {
	if len(packets) != len(outBufs) {
		return nil, errors.New("packet and buffer count mismatch")
	}
	
	lengths := make([]int, len(packets))
	
	for i, pkt := range packets {
		n, err := fs.SerializePacket(&pkt, outBufs[i])
		if err != nil {
			return lengths[:i], err
		}
		lengths[i] = n
	}
	
	return lengths, nil
}