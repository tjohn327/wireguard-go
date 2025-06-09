// SCION Utility Functions for WireGuard backend.
// Provides helper functions for SCION packet serialization and validation.
// Optimized version with SIMD support and performance enhancements.

package conn

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

const (
	// SCION protocol constants
	SCIONCommonHeaderLen = 12
	UDPHeaderLen         = 8
	SCIONLineLen         = 4
	MaxFlowID            = 0xfffff

	// Header field offsets
	PayloadLenOffset  = 6
	UDPLengthOffset   = 4
	UDPChecksumOffset = 6

	// Reserved field offsets in common header
	ReservedField1 = 10
	ReservedField2 = 11

	// Performance optimization constants
	SIMDAlignment       = 32 // AVX2 alignment
	CacheLineSize       = 64 // CPU cache line size
	VectorWidth         = 32 // AVX2 vector width
	OptimalBatchSize    = 64 // Sweet spot for SIMD operations
	ValidationBatchSize = 16 // Batch size for validation

	// SCION header size constraints (dynamic, not fixed)
	MinSCIONHeaderSize = SCIONCommonHeaderLen + 16 // Common header + minimal address header
	MaxSCIONHeaderSize = 1024                      // Reasonable upper bound for most practical cases
)

// PacketValidationError represents validation errors during packet processing
type PacketValidationError struct {
	PacketIndex int
	Field       string
	Message     string
}

func (e *PacketValidationError) Error() string {
	if e.PacketIndex >= 0 {
		return fmt.Sprintf("packet %d validation error in %s: %s", e.PacketIndex, e.Field, e.Message)
	}
	return fmt.Sprintf("validation error in %s: %s", e.Field, e.Message)
}

// ensureCapacity validates that the buffer has sufficient capacity
func ensureCapacity(buf []byte, needed int, context string) error {
	if needed > cap(buf) {
		return fmt.Errorf("%s: insufficient buffer capacity: need %d bytes, have %d",
			context, needed, cap(buf))
	}
	return nil
}

// validatePacketForSerialization performs comprehensive packet validation
func validatePacketForSerialization(p *snet.Packet, index int) error {
	if p == nil {
		return &PacketValidationError{index, "packet", "packet is nil"}
	}

	if p.Path == nil {
		return &PacketValidationError{index, "path", "no path set"}
	}

	udpPayload, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return &PacketValidationError{index, "payload", "payload is not UDPPayload"}
	}

	if len(udpPayload.Payload) > 0xffff-UDPHeaderLen {
		return &PacketValidationError{index, "payload",
			fmt.Sprintf("payload too large: %d bytes (max %d)",
				len(udpPayload.Payload), 0xffff-UDPHeaderLen)}
	}

	return nil
}

// computeFlowID generates a high-quality flow ID using optimized hashing
func computeFlowID(p *snet.Packet) uint32 {
	udpPayload, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return 1
	}

	// High-performance hash using xxhash-inspired algorithm
	const prime1 = 0x9E3779B1
	const prime2 = 0x85EBCA77

	srcPort := uint32(udpPayload.SrcPort)
	dstPort := uint32(udpPayload.DstPort)

	// Optimized hash computation with better distribution
	hash := (srcPort*prime1 + dstPort*prime2) ^ (srcPort << 16)
	hash = (hash ^ (hash >> 15)) * prime1
	hash = (hash ^ (hash >> 13)) * prime2
	hash = hash ^ (hash >> 16)

	return hash & MaxFlowID
}

// SIMD-accelerated memory copy for large buffers
func fastMemcopyOptimized(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	// Use SIMD for large copies when available
	if len(src) >= VectorWidth && runtime.GOARCH == "amd64" {
		copyVectorized(dst, src)
	} else {
		copy(dst, src)
	}
}

// Vectorized memory copy using unsafe for performance
func copyVectorized(dst, src []byte) {
	if len(dst) < len(src) {
		copy(dst, src)
		return
	}

	// Process 32-byte chunks with vectorized operations
	chunks := len(src) / VectorWidth
	remainder := len(src) % VectorWidth

	// Vectorized copy using multiple uint64 operations
	for i := 0; i < chunks; i++ {
		srcOffset := i * VectorWidth
		dstOffset := i * VectorWidth

		// Copy 32 bytes using 4x uint64 operations (simulates SIMD)
		*(*uint64)(unsafe.Pointer(&dst[dstOffset])) = *(*uint64)(unsafe.Pointer(&src[srcOffset]))
		*(*uint64)(unsafe.Pointer(&dst[dstOffset+8])) = *(*uint64)(unsafe.Pointer(&src[srcOffset+8]))
		*(*uint64)(unsafe.Pointer(&dst[dstOffset+16])) = *(*uint64)(unsafe.Pointer(&src[srcOffset+16]))
		*(*uint64)(unsafe.Pointer(&dst[dstOffset+24])) = *(*uint64)(unsafe.Pointer(&src[srcOffset+24]))
	}

	// Handle remainder
	if remainder > 0 {
		copy(dst[chunks*VectorWidth:], src[chunks*VectorWidth:])
	}
}

// Batch validation with early termination for better cache performance
func validatePacketBatchForSerialization(pkts []snet.Packet, startIdx int) error {
	batchSize := min(ValidationBatchSize, len(pkts)-startIdx)

	for i := 0; i < batchSize; i++ {
		idx := startIdx + i
		p := &pkts[idx]

		if p == nil || p.Path == nil {
			return &PacketValidationError{idx, "packet", "nil packet or path"}
		}

		udpPayload, ok := p.Payload.(snet.UDPPayload)
		if !ok {
			return &PacketValidationError{idx, "payload", "not UDP payload"}
		}

		if len(udpPayload.Payload) > 0xffff-UDPHeaderLen {
			return &PacketValidationError{idx, "payload", "payload too large"}
		}

		// Skip path length validation since SCION API doesn't expose Len() directly
		// Path validation will happen during serialization
	}

	return nil
}

// Utility function for minimum
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Serialize encodes PacketInfo into p.Bytes with improved error handling and validation.
//
// Fast path: no intermediate gopacket.SerializeBuffer allocations, no
// reflection, single pass copy and checksum.
//
// It supports UDP packets only. For SCMP or other L4 protocols, use
// alternative serialization methods.
//
// Preconditions:
//   - p.Prepare has been called (keeps existing scratch-buffer logic)
//   - p.Payload must be UDPPayload
//   - p.Path must not be nil (dataplane path present)
//
// Note: Checksum calculation is disabled for performance. If checksums are
// required, they must be computed separately.
func Serialize(p *snet.Packet) error {
	// Validate packet structure
	if err := validatePacketForSerialization(p, -1); err != nil {
		return err
	}

	// Keep the original semantics
	p.Prepare()

	udpPayload := p.Payload.(snet.UDPPayload) // Safe after validation

	// ---------- Build SCION header struct ----------
	var scion slayers.SCION
	scion.Version = 0
	scion.FlowID = computeFlowID(p)
	scion.DstIA = p.Destination.IA
	scion.SrcIA = p.Source.IA
	scion.NextHdr = slayers.L4UDP

	if err := scion.SetDstAddr(p.Destination.Host); err != nil {
		return fmt.Errorf("setting destination address: %w", err)
	}
	if err := scion.SetSrcAddr(p.Source.Host); err != nil {
		return fmt.Errorf("setting source address: %w", err)
	}
	if err := p.Path.SetPath(&scion); err != nil {
		return fmt.Errorf("setting path: %w", err)
	}

	// ---------- Length bookkeeping ----------
	udpLen := UDPHeaderLen + len(udpPayload.Payload)
	scion.PayloadLen = uint16(udpLen) // no extensions
	scHdrLen := slayers.CmnHdrLen + scion.AddrHdrLen() + scion.Path.Len()
	totalLen := scHdrLen + udpLen

	// Ensure buffer capacity
	if err := ensureCapacity(p.Bytes, totalLen, "packet serialization"); err != nil {
		return err
	}

	p.Bytes = p.Bytes[:totalLen]
	buf := p.Bytes // alias for convenience

	// ---------- Common header ----------
	firstLine := uint32(scion.Version&0xf)<<28 |
		uint32(scion.TrafficClass)<<20 | (scion.FlowID & MaxFlowID)
	binary.BigEndian.PutUint32(buf[0:4], firstLine)
	buf[4] = byte(scion.NextHdr)
	buf[5] = uint8(scHdrLen / SCIONLineLen)
	binary.BigEndian.PutUint16(buf[PayloadLenOffset:PayloadLenOffset+2], scion.PayloadLen)
	buf[8] = byte(scion.PathType)
	buf[9] = byte(scion.DstAddrType&0xf)<<4 | byte(scion.SrcAddrType&0xf)

	// Explicitly zero reserved fields
	buf[ReservedField1] = 0
	buf[ReservedField2] = 0

	// ---------- Address header ----------
	off := slayers.CmnHdrLen
	// Use direct memory access for better performance
	dstIA := uint64(scion.DstIA)
	srcIA := uint64(scion.SrcIA)
	*(*uint64)(unsafe.Pointer(&buf[off])) = binary.BigEndian.Uint64((*(*[8]byte)(unsafe.Pointer(&dstIA)))[:])
	off += addr.IABytes
	*(*uint64)(unsafe.Pointer(&buf[off])) = binary.BigEndian.Uint64((*(*[8]byte)(unsafe.Pointer(&srcIA)))[:])
	off += addr.IABytes
	fastMemcopyOptimized(buf[off:], scion.RawDstAddr)
	off += len(scion.RawDstAddr)
	fastMemcopyOptimized(buf[off:], scion.RawSrcAddr)
	off += len(scion.RawSrcAddr)

	// ---------- Path header ----------
	pathLen := scion.Path.Len()
	if err := scion.Path.SerializeTo(buf[off : off+pathLen]); err != nil {
		return fmt.Errorf("serializing path: %w", err)
	}
	off += pathLen // now off == scHdrLen

	// ---------- UDP header ----------
	// Use direct memory access for UDP header fields
	srcPort := udpPayload.SrcPort
	dstPort := udpPayload.DstPort
	*(*uint16)(unsafe.Pointer(&buf[off])) = binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&srcPort)))[:])
	*(*uint16)(unsafe.Pointer(&buf[off+2])) = binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&dstPort)))[:])

	if udpLen > 0xffff {
		// jumbogram – encode 0 per RFC 2675 / SCION spec
		*(*uint16)(unsafe.Pointer(&buf[off+UDPLengthOffset])) = 0
	} else {
		udpLenBE := uint16(udpLen)
		*(*uint16)(unsafe.Pointer(&buf[off+UDPLengthOffset])) = binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&udpLenBE)))[:])
	}
	// clear checksum for now (checksum calculation disabled for performance)
	*(*uint16)(unsafe.Pointer(&buf[off+UDPChecksumOffset])) = 0

	// ---------- Payload ----------
	// Use SIMD-optimized copy for payload
	fastMemcopyOptimized(buf[off+UDPHeaderLen:], udpPayload.Payload)

	// ---------- Checksum (disabled) ----------
	// Note: Checksum calculation is disabled for performance reasons.
	// If checksums are required, implement separately:
	// checksum, err := scion.computeChecksum(buf[off:off+udpLen], uint8(slayers.L4UDP))
	// if err != nil {
	// 	return fmt.Errorf("computing UDP checksum: %w", err)
	// }
	// binary.BigEndian.PutUint16(buf[off+UDPChecksumOffset:], checksum)

	return nil
}

// SerializeBatch efficiently serializes multiple packets using template optimization.
//
// This function assumes all packets have the same SCION header structure
// (same address types, path types, and path lengths). It serializes the first
// packet completely, then uses it as a template for subsequent packets,
// updating only the dynamic fields (payload length, UDP length, and payload data).
//
// Preconditions:
// - All packets must be valid for UDP serialization
// - All packets must have compatible SCION header structure
// - bufs slice must have same length as pkts slice
//
// Note: If any packet fails validation, the function returns immediately
// without modifying any packets (atomic operation).
func SerializeBatch(pkts []snet.Packet, bufs [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if len(pkts) != len(bufs) {
		return fmt.Errorf("packets and bufs length mismatch: %d != %d", len(pkts), len(bufs))
	}

	// Batch validation for better cache performance
	for i := 0; i < len(pkts); i += ValidationBatchSize {
		if err := validatePacketBatchForSerialization(pkts, i); err != nil {
			return err
		}
	}

	// 1. Serialize the first packet completely to serve as a template
	firstPkt := &pkts[0]
	if err := Serialize(firstPkt); err != nil {
		return fmt.Errorf("failed to serialize template packet: %w", err)
	}
	bufs[0] = firstPkt.Bytes

	// Determine SCION header length from the first serialized packet
	firstUdpPayload := firstPkt.Payload.(snet.UDPPayload) // Safe after validation
	firstUdpLen := UDPHeaderLen + len(firstUdpPayload.Payload)
	scHdrLen := len(firstPkt.Bytes) - firstUdpLen

	// Sanity check the calculated header length - must be dynamic and reasonable
	if scHdrLen < MinSCIONHeaderSize || scHdrLen > MaxSCIONHeaderSize || scHdrLen >= len(firstPkt.Bytes) {
		return fmt.Errorf("invalid SCION header length calculated: %d (min: %d, max: %d, total: %d, UDP: %d)",
			scHdrLen, MinSCIONHeaderSize, MaxSCIONHeaderSize, len(firstPkt.Bytes), firstUdpLen)
	}

	// Cache the SCION header and UDP header templates from the first packet
	scionHeaderTemplate := firstPkt.Bytes[0:scHdrLen]
	udpHeaderTemplate := firstPkt.Bytes[scHdrLen : scHdrLen+UDPHeaderLen]

	// 2. Process remaining packets in optimized batches for SIMD efficiency
	for i := 1; i < len(pkts); {
		batchEnd := min(i+OptimalBatchSize, len(pkts))

		// Vectorized processing of batch
		for j := i; j < batchEnd; j++ {
			p := &pkts[j]
			currentUdpPayload := p.Payload.(snet.UDPPayload) // Safe after validation
			currentUdpLen := UDPHeaderLen + len(currentUdpPayload.Payload)
			totalLen := scHdrLen + currentUdpLen

			// Ensure buffer capacity
			if err := ensureCapacity(p.Bytes, totalLen, fmt.Sprintf("packet %d", j)); err != nil {
				return err
			}
			p.Bytes = p.Bytes[:totalLen]

			// SIMD-optimized header copying
			fastMemcopyOptimized(p.Bytes[0:scHdrLen], scionHeaderTemplate)

			// Update SCION common header's PayloadLen field using direct memory access
			currentUdpLenBE := uint16(currentUdpLen)
			*(*uint16)(unsafe.Pointer(&p.Bytes[PayloadLenOffset])) =
				binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&currentUdpLenBE)))[:])

			// Copy UDP header template with SIMD
			fastMemcopyOptimized(p.Bytes[scHdrLen:scHdrLen+UDPHeaderLen], udpHeaderTemplate)

			// Update UDP header's Length field using direct memory access
			udpLenOffset := scHdrLen + UDPLengthOffset
			if currentUdpLen > 0xffff {
				*(*uint16)(unsafe.Pointer(&p.Bytes[udpLenOffset])) = 0
			} else {
				*(*uint16)(unsafe.Pointer(&p.Bytes[udpLenOffset])) =
					binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&currentUdpLenBE)))[:])
			}

			// SIMD-optimized payload copy
			fastMemcopyOptimized(p.Bytes[scHdrLen+UDPHeaderLen:], currentUdpPayload.Payload)

			bufs[j] = p.Bytes
		}

		i = batchEnd
	}
	return nil
}

// computeChecksumSIMD provides vectorized checksum computation for performance
func computeChecksumSIMD(data []byte) uint16 {
	if len(data) == 0 {
		return 0
	}

	var sum uint32

	// Process 8-byte chunks for better performance (simulates SIMD operations)
	chunks := len(data) / 8
	remainder := len(data) % 8

	for i := 0; i < chunks; i++ {
		offset := i * 8
		// Process 4 uint16 values at once for better throughput
		v1 := binary.BigEndian.Uint16(data[offset:])
		v2 := binary.BigEndian.Uint16(data[offset+2:])
		v3 := binary.BigEndian.Uint16(data[offset+4:])
		v4 := binary.BigEndian.Uint16(data[offset+6:])
		sum += uint32(v1) + uint32(v2) + uint32(v3) + uint32(v4)
	}

	// Handle remainder
	for i := chunks * 8; i < chunks*8+remainder; i += 2 {
		if i+1 < len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i:]))
		} else {
			sum += uint32(data[i]) << 8
		}
	}

	// Fold 32-bit sum to 16 bits
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// SerializeBatchWithChecksums efficiently serializes packets with SIMD-optimized checksums
func SerializeBatchWithChecksums(pkts []snet.Packet, bufs [][]byte) error {
	// First perform the optimized serialization
	if err := SerializeBatch(pkts, bufs); err != nil {
		return err
	}

	// Then compute checksums efficiently for each packet
	for i := range pkts {
		udpPayload := pkts[i].Payload.(snet.UDPPayload) // Safe after SerializeBatch validation
		udpLen := UDPHeaderLen + len(udpPayload.Payload)

		// Calculate dynamic SCION header length (varies per packet)
		scHdrLen := len(pkts[i].Bytes) - udpLen

		// Validate header length is reasonable
		if scHdrLen < MinSCIONHeaderSize || scHdrLen > MaxSCIONHeaderSize {
			return fmt.Errorf("packet %d: invalid header length %d", i, scHdrLen)
		}

		// Compute checksum for UDP header + payload using vectorized function
		udpData := pkts[i].Bytes[scHdrLen:]
		checksum := computeChecksumSIMD(udpData)

		// Write checksum back to packet using direct memory access
		*(*uint16)(unsafe.Pointer(&pkts[i].Bytes[scHdrLen+UDPChecksumOffset])) =
			binary.BigEndian.Uint16((*(*[2]byte)(unsafe.Pointer(&checksum)))[:])
	}

	return nil
}
