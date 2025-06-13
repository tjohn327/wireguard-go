package conn

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"
)

func TestFastSnetSerializer(t *testing.T) {
	fs := NewFastSnetSerializer()
	
	// Test data
	srcIA := addr.MustIAFrom(1, 2)
	dstIA := addr.MustIAFrom(3, 4)
	srcHost := addr.HostIP(netip.MustParseAddr("10.0.0.1"))
	dstHost := addr.HostIP(netip.MustParseAddr("10.0.0.2"))
	srcPort := uint16(31000)
	dstPort := uint16(31001)
	pathType := uint8(0) // Empty path
	pathBytes := []byte{}
	payload := []byte("Hello, SCION!")
	
	// Serialize
	outBuf := make([]byte, 2048)
	n, err := fs.SerializeUDP(srcIA, dstIA, srcHost, dstHost, srcPort, dstPort, pathType, pathBytes, payload, outBuf)
	if err != nil {
		t.Fatalf("SerializeUDP failed: %v", err)
	}
	
	// Deserialize
	gotSrcIA, gotDstIA, gotSrcHost, gotDstHost, gotSrcPort, gotDstPort, gotPathType, gotPathBytes, gotPayload, err := 
		fs.DeserializeUDP(outBuf[:n])
	
	if err != nil {
		t.Fatalf("DeserializeUDP failed: %v", err)
	}
	
	// Verify
	if gotSrcIA != srcIA {
		t.Errorf("Source IA mismatch: got %v, want %v", gotSrcIA, srcIA)
	}
	if gotDstIA != dstIA {
		t.Errorf("Destination IA mismatch: got %v, want %v", gotDstIA, dstIA)
	}
	if gotSrcHost.IP() != srcHost.IP() {
		t.Errorf("Source host mismatch: got %v, want %v", gotSrcHost.IP(), srcHost.IP())
	}
	if gotDstHost.IP() != dstHost.IP() {
		t.Errorf("Destination host mismatch: got %v, want %v", gotDstHost.IP(), dstHost.IP())
	}
	if gotSrcPort != srcPort {
		t.Errorf("Source port mismatch: got %v, want %v", gotSrcPort, srcPort)
	}
	if gotDstPort != dstPort {
		t.Errorf("Destination port mismatch: got %v, want %v", gotDstPort, dstPort)
	}
	if gotPathType != pathType {
		t.Errorf("Path type mismatch: got %v, want %v", gotPathType, pathType)
	}
	if !bytes.Equal(gotPathBytes, pathBytes) {
		t.Errorf("Path bytes mismatch")
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("Payload mismatch: got %q, want %q", string(gotPayload), string(payload))
	}
}

func TestFastSnetSerializerWithPath(t *testing.T) {
	fs := NewFastSnetSerializer()
	
	// Test with a path
	srcIA := addr.MustIAFrom(1, 0xff00)
	dstIA := addr.MustIAFrom(2, 0xff00)
	srcHost := addr.HostIP(netip.MustParseAddr("192.168.1.10"))
	dstHost := addr.HostIP(netip.MustParseAddr("192.168.2.20"))
	srcPort := uint16(32000)
	dstPort := uint16(32001)
	pathType := uint8(2) // SCION path
	pathBytes := make([]byte, 32)   // Dummy path
	for i := range pathBytes {
		pathBytes[i] = byte(i)
	}
	payload := []byte("Test with path")
	
	// Serialize
	outBuf := make([]byte, 2048)
	n, err := fs.SerializeUDP(srcIA, dstIA, srcHost, dstHost, srcPort, dstPort, pathType, pathBytes, payload, outBuf)
	if err != nil {
		t.Fatalf("SerializeUDP failed: %v", err)
	}
	
	// Deserialize
	_, _, _, _, _, _, _, gotPathBytes, gotPayload, err := fs.DeserializeUDP(outBuf[:n])
	if err != nil {
		t.Fatalf("DeserializeUDP failed: %v", err)
	}
	
	// Verify path and payload
	if !bytes.Equal(gotPathBytes, pathBytes) {
		t.Errorf("Path bytes mismatch: got %d bytes, want %d bytes", len(gotPathBytes), len(pathBytes))
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestFastSnetSerializerPacket(t *testing.T) {
	fs := NewFastSnetSerializer()
	
	// Create a packet
	pkt := &snet.Packet{
		PacketInfo: snet.PacketInfo{
			Source: snet.SCIONAddress{
				IA:   addr.MustIAFrom(1, 2),
				Host: addr.HostIP(netip.MustParseAddr("10.0.0.1")),
			},
			Destination: snet.SCIONAddress{
				IA:   addr.MustIAFrom(3, 4),
				Host: addr.HostIP(netip.MustParseAddr("10.0.0.2")),
			},
			Path: snet.RawPath{
				PathType: 0,
				Raw:      []byte{},
			},
			Payload: snet.UDPPayload{
				SrcPort: 31000,
				DstPort: 31001,
				Payload: []byte("Packet test"),
			},
		},
	}
	
	// Serialize
	outBuf := make([]byte, 2048)
	n, err := fs.SerializePacket(pkt, outBuf)
	if err != nil {
		t.Fatalf("SerializePacket failed: %v", err)
	}
	
	// Deserialize
	gotPkt, err := fs.DeserializePacket(outBuf[:n])
	if err != nil {
		t.Fatalf("DeserializePacket failed: %v", err)
	}
	
	// Verify
	if gotPkt.Source.IA != pkt.Source.IA {
		t.Errorf("Source IA mismatch")
	}
	if gotPkt.Destination.IA != pkt.Destination.IA {
		t.Errorf("Destination IA mismatch")
	}
	
	gotUDP := gotPkt.Payload.(snet.UDPPayload)
	origUDP := pkt.Payload.(snet.UDPPayload)
	
	if gotUDP.SrcPort != origUDP.SrcPort || gotUDP.DstPort != origUDP.DstPort {
		t.Errorf("Port mismatch")
	}
	if !bytes.Equal(gotUDP.Payload, origUDP.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestFastSnetSerializerIPv6(t *testing.T) {
	fs := NewFastSnetSerializer()
	
	// Test with IPv6
	srcIA := addr.MustIAFrom(1, 2)
	dstIA := addr.MustIAFrom(3, 4)
	srcHost := addr.HostIP(netip.MustParseAddr("2001:db8::1"))
	dstHost := addr.HostIP(netip.MustParseAddr("2001:db8::2"))
	srcPort := uint16(31000)
	dstPort := uint16(31001)
	pathType := uint8(0)
	pathBytes := []byte{}
	payload := []byte("IPv6 test")
	
	// Serialize
	outBuf := make([]byte, 2048)
	n, err := fs.SerializeUDP(srcIA, dstIA, srcHost, dstHost, srcPort, dstPort, pathType, pathBytes, payload, outBuf)
	if err != nil {
		t.Fatalf("SerializeUDP failed: %v", err)
	}
	
	// Deserialize
	_, _, gotSrcHost, gotDstHost, _, _, _, _, gotPayload, err := fs.DeserializeUDP(outBuf[:n])
	if err != nil {
		t.Fatalf("DeserializeUDP failed: %v", err)
	}
	
	// Verify
	if gotSrcHost.IP() != srcHost.IP() {
		t.Errorf("IPv6 source host mismatch")
	}
	if gotDstHost.IP() != dstHost.IP() {
		t.Errorf("IPv6 destination host mismatch")
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("Payload mismatch")
	}
}

// Benchmarks

func BenchmarkFastSnetSerialize(b *testing.B) {
	fs := NewFastSnetSerializer()
	
	srcIA := addr.MustIAFrom(1, 2)
	dstIA := addr.MustIAFrom(3, 4)
	srcHost := addr.HostIP(netip.MustParseAddr("10.0.0.1"))
	dstHost := addr.HostIP(netip.MustParseAddr("10.0.0.2"))
	srcPort := uint16(31000)
	dstPort := uint16(31001)
	pathType := uint8(0)
	pathBytes := []byte{}
	payload := make([]byte, 100)
	
	outBuf := make([]byte, 2048)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fs.SerializeUDP(srcIA, dstIA, srcHost, dstHost, srcPort, dstPort, pathType, pathBytes, payload, outBuf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFastSnetDeserialize(b *testing.B) {
	fs := NewFastSnetSerializer()
	
	// Prepare a serialized packet
	srcIA := addr.MustIAFrom(1, 2)
	dstIA := addr.MustIAFrom(3, 4)
	srcHost := addr.HostIP(netip.MustParseAddr("10.0.0.1"))
	dstHost := addr.HostIP(netip.MustParseAddr("10.0.0.2"))
	srcPort := uint16(31000)
	dstPort := uint16(31001)
	pathType := uint8(0)
	pathBytes := []byte{}
	payload := make([]byte, 100)
	
	outBuf := make([]byte, 2048)
	n, _ := fs.SerializeUDP(srcIA, dstIA, srcHost, dstHost, srcPort, dstPort, pathType, pathBytes, payload, outBuf)
	serialized := outBuf[:n]
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _, _, _, _, _, err := fs.DeserializeUDP(serialized)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStandardSerialize(b *testing.B) {
	// Skip this benchmark as RawPath doesn't support SetPath required by Serialize
	b.Skip("RawPath doesn't support SetPath required by standard Serialize")
}

func BenchmarkSnetDecode(b *testing.B) {
	fs := NewFastSnetSerializer()
	
	// Prepare a serialized packet using our fast serializer
	srcIA := addr.MustIAFrom(1, 2)
	dstIA := addr.MustIAFrom(3, 4)
	srcHost := addr.HostIP(netip.MustParseAddr("10.0.0.1"))
	dstHost := addr.HostIP(netip.MustParseAddr("10.0.0.2"))
	srcPort := uint16(31000)
	dstPort := uint16(31001)
	pathType := uint8(0)
	pathBytes := []byte{}
	payload := make([]byte, 100)
	
	outBuf := make([]byte, 2048)
	n, _ := fs.SerializeUDP(srcIA, dstIA, srcHost, dstHost, srcPort, dstPort, pathType, pathBytes, payload, outBuf)
	serialized := make([]byte, n)
	copy(serialized, outBuf[:n])
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := &snet.Packet{
			Bytes: make([]byte, len(serialized)),
		}
		copy(pkt.Bytes, serialized)
		err := pkt.Decode()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFastDecodeVsSnetDecode(b *testing.B) {
	fs := NewFastSnetSerializer()
	
	// Prepare test data
	srcIA := addr.MustIAFrom(1, 2)
	dstIA := addr.MustIAFrom(3, 4)
	srcHost := addr.HostIP(netip.MustParseAddr("10.0.0.1"))
	dstHost := addr.HostIP(netip.MustParseAddr("10.0.0.2"))
	srcPort := uint16(31000)
	dstPort := uint16(31001)
	pathType := uint8(0)
	pathBytes := []byte{}
	payload := make([]byte, 100)
	
	outBuf := make([]byte, 2048)
	n, _ := fs.SerializeUDP(srcIA, dstIA, srcHost, dstHost, srcPort, dstPort, pathType, pathBytes, payload, outBuf)
	serialized := outBuf[:n]
	
	b.Run("FastDecode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := fs.DeserializePacket(serialized)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
	
	b.Run("SnetDecode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			pkt := &snet.Packet{
				Bytes: make([]byte, len(serialized)),
			}
			copy(pkt.Bytes, serialized)
			err := pkt.Decode()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}



func BenchmarkFastSnetBatch(b *testing.B) {
	fs := NewFastSnetSerializer()
	
	// Create 10 packets
	packets := make([]snet.Packet, 10)
	bufs := make([][]byte, 10)
	
	for i := 0; i < 10; i++ {
		packets[i] = snet.Packet{
			PacketInfo: snet.PacketInfo{
				Source: snet.SCIONAddress{
					IA:   addr.MustIAFrom(1, 2),
					Host: addr.HostIP(netip.MustParseAddr("10.0.0.1")),
				},
				Destination: snet.SCIONAddress{
					IA:   addr.MustIAFrom(3, 4),
					Host: addr.HostIP(netip.MustParseAddr("10.0.0.2")),
				},
				Path: snet.RawPath{
					PathType: 0,
					Raw:      []byte{},
				},
				Payload: snet.UDPPayload{
					SrcPort: uint16(31000 + i),
					DstPort: uint16(31001 + i),
					Payload: make([]byte, 100),
				},
			},
		}
		bufs[i] = make([]byte, 2048)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fs.BatchSerialize(packets, bufs)
		if err != nil {
			b.Fatal(err)
		}
	}
}