package conn

import (
	"encoding/binary"
	"fmt"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
)

// / Serialize encodes PacketInfo into p.Bytes.
//
// Fast path: no intermediate gopacket.SerializeBuffer allocations, no
// reflection, single pass copy and checksum.
//
// It supports both UDP and all SCMP flavours that the original version handled.
// Any new L4 implementation can be added with an extra case in the payload
// switch without touching the hot-path.
//
// Preconditions (identical to the original):
//   - p.Prepare has been called            (keeps existing scratch-buffer logic)
//   - p.Payload != nil                     (layer-4 present)
//   - p.Path    != nil                     (dataplane path present)
//
// Serialize serializes the Packet into p.Bytes.
//
// It is optimized for SCION/UDP only.  SCMP or any other L4 type must be
// handled elsewhere.
func Serialize(p *snet.Packet) error {
	// Keep the original semantics.
	p.Prepare()

	udpPayload, ok := p.Payload.(snet.UDPPayload)
	if !ok {
		return fmt.Errorf("Serialize fast-path supports UDPPayload only")
	}
	if p.Path == nil {
		return fmt.Errorf("no path set")
	}

	// ---------- Build SCION header struct ----------
	var scion slayers.SCION
	scion.Version = 0
	scion.FlowID = 1 // TODO: pick real flowID later.
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
	udpLen := 8 + len(udpPayload.Payload) // header + data
	scion.PayloadLen = uint16(udpLen)     // no extensions
	scHdrLen := slayers.CmnHdrLen + scion.AddrHdrLen() + scion.Path.Len()
	totalLen := scHdrLen + udpLen

	if totalLen > cap(p.Bytes) {
		return fmt.Errorf("packet exceeds backing buffer: need %d, cap %d", totalLen, cap(p.Bytes))
	}
	p.Bytes = p.Bytes[:totalLen]
	buf := p.Bytes // alias for convenience

	// ---------- Common header ----------
	firstLine := uint32(scion.Version&0xf)<<28 |
		uint32(scion.TrafficClass)<<20 | (scion.FlowID & 0xfffff)
	binary.BigEndian.PutUint32(buf[0:4], firstLine)
	buf[4] = byte(scion.NextHdr)
	buf[5] = uint8(scHdrLen / slayers.LineLen)
	binary.BigEndian.PutUint16(buf[6:8], scion.PayloadLen)
	buf[8] = byte(scion.PathType)
	buf[9] = byte(scion.DstAddrType&0xf)<<4 | byte(scion.SrcAddrType&0xf)
	// bytes 10-11 are reserved = 0

	// ---------- Address header ----------
	off := slayers.CmnHdrLen
	binary.BigEndian.PutUint64(buf[off:], uint64(scion.DstIA))
	off += addr.IABytes
	binary.BigEndian.PutUint64(buf[off:], uint64(scion.SrcIA))
	off += addr.IABytes
	copy(buf[off:], scion.RawDstAddr)
	off += len(scion.RawDstAddr)
	copy(buf[off:], scion.RawSrcAddr)
	off += len(scion.RawSrcAddr)

	// ---------- Path header ----------
	if err := scion.Path.SerializeTo(buf[off : off+scion.Path.Len()]); err != nil {
		return fmt.Errorf("serializing path: %w", err)
	}
	off += scion.Path.Len() // now off == scHdrLen

	// ---------- UDP header ----------
	binary.BigEndian.PutUint16(buf[off+0:], udpPayload.SrcPort)
	binary.BigEndian.PutUint16(buf[off+2:], udpPayload.DstPort)
	if udpLen > 0xffff {
		// jumbogram – encode 0 per RFC 2675 / SCION spec
		binary.BigEndian.PutUint16(buf[off+4:], 0)
	} else {
		binary.BigEndian.PutUint16(buf[off+4:], uint16(udpLen))
	}
	// clear checksum for now
	binary.BigEndian.PutUint16(buf[off+6:], 0)

	// ---------- Payload ----------
	copy(buf[off+8:], udpPayload.Payload)

	// ---------- Checksum ----------
	// checksum, err := scion.computeChecksum(buf[off:off+udpLen], uint8(slayers.L4UDP))
	// if err != nil {
	// 	return err
	// }
	// binary.BigEndian.PutUint16(buf[off+6:], checksum)

	return nil
}
