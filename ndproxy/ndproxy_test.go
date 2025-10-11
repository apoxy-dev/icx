package ndproxy_test

import (
	"encoding/binary"
	"math"
	"net"
	"net/netip"
	"testing"

	"github.com/apoxy-dev/icx/ndproxy"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestNDProxy_Reply_Success(t *testing.T) {
	proxyMAC := tcpip.GetRandMacAddr()
	srcMAC := tcpip.GetRandMacAddr()

	srcIP := tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::1").AsSlice())
	targetIP := tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::2").AsSlice())

	req := buildNSFrame(t, srcMAC, srcIP, targetIP, header.NDPHopLimit)

	totalLen := header.EthernetMinimumSize + header.IPv6MinimumSize + ndproxy.ICMPv6NeighborAdvertSize
	resp := make([]byte, totalLen)

	p := ndproxy.NewNDProxy(proxyMAC)
	n, err := p.Reply(req, resp)
	require.NoError(t, err)
	require.Equal(t, totalLen, n)

	// Verify Ethernet
	eth := header.Ethernet(resp)
	require.Equal(t, header.IPv6ProtocolNumber, eth.Type())
	require.Equal(t, proxyMAC, eth.SourceAddress())
	require.Equal(t, srcMAC, eth.DestinationAddress())

	// Verify IPv6
	ip6 := header.IPv6(resp[header.EthernetMinimumSize:])
	require.True(t, ip6.IsValid(len(resp[header.EthernetMinimumSize:])))
	require.Equal(t, uint16(ndproxy.ICMPv6NeighborAdvertSize), ip6.PayloadLength())
	require.Equal(t, header.ICMPv6ProtocolNumber, ip6.TransportProtocol())
	require.Equal(t, byte(header.NDPHopLimit), ip6.HopLimit())
	require.Equal(t, targetIP, ip6.SourceAddress())
	require.Equal(t, srcIP, ip6.DestinationAddress())

	// Verify ICMPv6 NA
	icmp := ip6.Payload()
	require.Len(t, icmp, ndproxy.ICMPv6NeighborAdvertSize)
	require.Equal(t, byte(136), icmp[0]) // NA
	require.Equal(t, byte(0), icmp[1])   // Code

	flags := binary.BigEndian.Uint32(icmp[4:8])
	require.Equal(t, uint32(ndproxy.NAFlagSolicited|ndproxy.NAFlagOverride), flags)

	require.Equal(t, targetIP.AsSlice(), icmp[8:8+16])

	opt := icmp[header.ICMPv6NeighborAdvertMinimumSize:ndproxy.ICMPv6NeighborAdvertSize]
	require.Equal(t, byte(2), opt[0])
	require.Equal(t, byte(1), opt[1])
	require.Equal(t, proxyMAC.String(), net.HardwareAddr([]byte(opt[2:8])).String())

	// Checksum verification
	cs := checksum.Combine(
		header.PseudoHeaderChecksum(
			header.ICMPv6ProtocolNumber,
			ip6.SourceAddress(),
			ip6.DestinationAddress(),
			uint16(len(icmp)),
		),
		checksum.Checksum(icmp, 0),
	)
	require.Equal(t, uint16(math.MaxUint16), cs, "Invalid ICMPv6 checksum")
}

func TestNDProxy_Reply_Errors(t *testing.T) {
	proxyMAC := tcpip.GetRandMacAddr()
	srcMAC := tcpip.GetRandMacAddr()

	srcIP := tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::1").AsSlice())
	targetIP := tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::2").AsSlice())

	p := ndproxy.NewNDProxy(proxyMAC)

	t.Run("TooShortRequest", func(t *testing.T) {
		req := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+header.ICMPv6NeighborSolicitMinimumSize-1)
		resp := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+ndproxy.ICMPv6NeighborAdvertSize)
		_, err := p.Reply(req, resp)
		require.Error(t, err)
	})

	t.Run("NotIPv6EtherType", func(t *testing.T) {
		req := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+header.ICMPv6NeighborSolicitMinimumSize)
		eth := header.Ethernet(req)
		eth.Encode(&header.EthernetFields{
			SrcAddr: srcMAC,
			DstAddr: proxyMAC,
			Type:    header.ARPProtocolNumber, // wrong
		})
		resp := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+ndproxy.ICMPv6NeighborAdvertSize)
		_, err := p.Reply(req, resp)
		require.Error(t, err)
	})

	t.Run("InvalidIPv6HopLimit", func(t *testing.T) {
		req := buildNSFrame(t, srcMAC, srcIP, targetIP, 64)
		resp := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+ndproxy.ICMPv6NeighborAdvertSize)
		_, err := p.Reply(req, resp)
		require.Error(t, err)
	})

	t.Run("NotICMPv6", func(t *testing.T) {
		req := buildNSFrame(t, srcMAC, srcIP, targetIP, header.NDPHopLimit)
		ip6 := header.IPv6(req[header.EthernetMinimumSize:])
		ip6.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(header.ICMPv6NeighborSolicitMinimumSize),
			TransportProtocol: header.TCPProtocolNumber,
			HopLimit:          header.NDPHopLimit,
			SrcAddr:           srcIP,
			DstAddr:           targetIP,
		})
		resp := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+ndproxy.ICMPv6NeighborAdvertSize)
		_, err := p.Reply(req, resp)
		require.Error(t, err)
	})

	t.Run("NotNeighborSolicitation", func(t *testing.T) {
		req := buildNSFrame(t, srcMAC, srcIP, targetIP, header.NDPHopLimit)
		ip6 := header.IPv6(req[header.EthernetMinimumSize:])
		icmp := ip6.Payload()
		icmp[0] = 133 // Router Solicitation
		resp := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+ndproxy.ICMPv6NeighborAdvertSize)
		_, err := p.Reply(req, resp)
		require.Error(t, err)
	})

	t.Run("ICMPv6PayloadTooShort", func(t *testing.T) {
		req := buildNSFrame(t, srcMAC, srcIP, targetIP, header.NDPHopLimit)
		req = req[:header.EthernetMinimumSize+header.IPv6MinimumSize+header.ICMPv6NeighborSolicitMinimumSize-1]
		resp := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+ndproxy.ICMPv6NeighborAdvertSize)
		_, err := p.Reply(req, resp)
		require.Error(t, err)
	})

	t.Run("ResponseBufferTooSmall", func(t *testing.T) {
		req := buildNSFrame(t, srcMAC, srcIP, targetIP, header.NDPHopLimit)
		resp := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+ndproxy.ICMPv6NeighborAdvertSize-1)
		_, err := p.Reply(req, resp)
		require.Error(t, err)
	})
}

// buildNSFrame constructs a minimal Ethernet+IPv6+ICMPv6 Neighbor Solicitation.
func buildNSFrame(t *testing.T, srcMAC tcpip.LinkAddress, srcIP, targetIP tcpip.Address, hopLimit byte) []byte {
	t.Helper()

	req := make([]byte, header.EthernetMinimumSize+header.IPv6MinimumSize+header.ICMPv6NeighborSolicitMinimumSize)

	eth := header.Ethernet(req)
	eth.Encode(&header.EthernetFields{
		SrcAddr: srcMAC,
		DstAddr: tcpip.GetRandMacAddr(),
		Type:    header.IPv6ProtocolNumber,
	})

	ip6 := header.IPv6(req[header.EthernetMinimumSize:])
	ip6.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6NeighborSolicitMinimumSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          hopLimit,
		SrcAddr:           srcIP,
		DstAddr:           targetIP,
	})

	icmp := ip6.Payload()
	icmp[0] = 135 // NS
	icmp[1] = 0
	icmp[2] = 0
	icmp[3] = 0
	copy(icmp[8:8+16], targetIP.AsSlice())

	return req
}
