package flowhash_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx/flowhash"
)

func makeIPv4UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	ipHdr := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
	ip := header.IPv4(ipHdr)

	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(ipHdr)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(srcIP.To4()),
		DstAddr:     tcpip.AddrFromSlice(dstIP.To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udp := header.UDP(ipHdr[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  header.UDPMinimumSize,
	})

	return ipHdr
}

func makeIPv6UDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	ipHdr := make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize)
	ip := header.IPv6(ipHdr)

	ip.Encode(&header.IPv6Fields{
		PayloadLength:     8,
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFromSlice(srcIP.To16()),
		DstAddr:           tcpip.AddrFromSlice(dstIP.To16()),
	})

	udp := header.UDP(ipHdr[header.IPv6MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  header.UDPMinimumSize,
	})

	return ipHdr
}

func TestFlowHash_IPv4(t *testing.T) {
	pkt := makeIPv4UDPPacket(net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 1234, 5678)
	hash := flowhash.Hash(pkt)
	require.NotZero(t, hash)
}

func TestFlowHash_IPv6(t *testing.T) {
	pkt := makeIPv6UDPPacket(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 1234, 5678)
	hash := flowhash.Hash(pkt)
	require.NotZero(t, hash)
}

func TestFlowHash_Symmetric_IPv4(t *testing.T) {
	tests := []struct {
		name             string
		src, dst         net.IP
		srcPort, dstPort uint16
	}{
		{"10.0.0.1:1234<->10.0.0.2:5678", net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 1234, 5678},
		{"192.168.1.1:80<->192.168.1.2:443", net.IPv4(192, 168, 1, 1), net.IPv4(192, 168, 1, 2), 80, 443},
		{"172.16.0.10:1<->172.16.0.11:65535", net.IPv4(172, 16, 0, 10), net.IPv4(172, 16, 0, 11), 1, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd := makeIPv4UDPPacket(tt.src, tt.dst, tt.srcPort, tt.dstPort)
			rev := makeIPv4UDPPacket(tt.dst, tt.src, tt.dstPort, tt.srcPort)

			fwdHash := flowhash.Hash(fwd)
			revHash := flowhash.Hash(rev)

			require.NotZero(t, fwdHash, "forward hash should be non-zero")
			require.NotZero(t, revHash, "reverse hash should be non-zero")
			require.Equal(t, fwdHash, revHash, "hash must be symmetric for reversed IPv4 5-tuple")
		})
	}
}

func TestFlowHash_Symmetric_IPv6(t *testing.T) {
	tests := []struct {
		name             string
		src, dst         net.IP
		srcPort, dstPort uint16
	}{
		{"2001:db8::1:1234<->2001:db8::2:5678", net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 1234, 5678},
		{"2001:db8:1::a:80<->2001:db8:1::b:443", net.ParseIP("2001:db8:1::a"), net.ParseIP("2001:db8:1::b"), 80, 443},
		{"2001:db8:abcd::10:1<->2001:db8:abcd::11:65535", net.ParseIP("2001:db8:abcd::10"), net.ParseIP("2001:db8:abcd::11"), 1, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd := makeIPv6UDPPacket(tt.src, tt.dst, tt.srcPort, tt.dstPort)
			rev := makeIPv6UDPPacket(tt.dst, tt.src, tt.dstPort, tt.srcPort)

			fwdHash := flowhash.Hash(fwd)
			revHash := flowhash.Hash(rev)

			require.NotZero(t, fwdHash, "forward hash should be non-zero")
			require.NotZero(t, revHash, "reverse hash should be non-zero")
			require.Equal(t, fwdHash, revHash, "hash must be symmetric for reversed IPv6 5-tuple")
		})
	}
}

func BenchmarkFlowHash_IPv4(b *testing.B) {
	pkt := makeIPv4UDPPacket(net.IPv4(192, 168, 1, 1), net.IPv4(192, 168, 1, 2), 12345, 80)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = flowhash.Hash(pkt)
	}
}

func BenchmarkFlowHash_IPv6(b *testing.B) {
	pkt := makeIPv6UDPPacket(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 12345, 80)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = flowhash.Hash(pkt)
	}
}

func TestMapToEphemeralPort(t *testing.T) {
	port := flowhash.MapToEphemeralPort(12345)

	require.GreaterOrEqual(t, port, uint16(49152))
	require.LessOrEqual(t, port, uint16(65535))
}
