package icx_test

import (
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx"
)

func TestHandler(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	localAddr := &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}

	peerAddr := &tcpip.FullAddress{
		NIC:  2,
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}

	virtMAC := tcpip.GetRandMacAddr()

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	h, err := icx.NewHandler(localAddr, virtMAC, true, false)
	require.NoError(t, err)

	err = h.AddVirtualNetwork(0x12345, peerAddr, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	require.NoError(t, err)

	err = h.UpdateVirtualNetworkKeys(0x12345, 1, key, key, time.Now().Add(time.Hour))
	require.NoError(t, err)

	virtFrame := makeIPv4UDPEthernetFrame(virtMAC)

	phyFrame := make([]byte, 1500)
	frameLen, loopback := h.VirtToPhy(virtFrame, phyFrame)
	require.NotZero(t, frameLen)
	require.False(t, loopback)

	receivedFrame := make([]byte, 1500)
	decodedLen := h.PhyToVirt(phyFrame[:frameLen], receivedFrame)
	require.NotZero(t, decodedLen)

	receivedFrame = receivedFrame[:decodedLen]

	require.Equal(t, virtFrame[header.EthernetMinimumSize:], receivedFrame[header.EthernetMinimumSize:])

	eth := header.Ethernet(receivedFrame)

	require.Equal(t, virtMAC, eth.DestinationAddress())

	require.NoError(t, h.RemoveVirtualNetwork(0x12345))

	frameLen, loopback = h.VirtToPhy(virtFrame, phyFrame)
	require.Zero(t, frameLen)
	require.False(t, loopback)
}

func TestHandler_Layer3(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	localAddr := &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}

	peerAddr := &tcpip.FullAddress{
		NIC:  2,
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	// Create handler with layer3 mode enabled
	h, err := icx.NewHandler(localAddr, tcpip.GetRandMacAddr(), false, true)
	require.NoError(t, err)

	err = h.AddVirtualNetwork(0x12345, peerAddr, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")})
	require.NoError(t, err)

	err = h.UpdateVirtualNetworkKeys(0x12345, 1, key, key, time.Now().Add(time.Hour))
	require.NoError(t, err)

	ipPacket := makeIPv4UDPPacket()

	phyFrame := make([]byte, 1500)
	frameLen, loopback := h.VirtToPhy(ipPacket, phyFrame)
	require.NotZero(t, frameLen)
	require.False(t, loopback)

	decoded := make([]byte, 1500)
	decodedLen := h.PhyToVirt(phyFrame[:frameLen], decoded)
	require.NotZero(t, decodedLen)

	require.Equal(t, ipPacket, decoded[:decodedLen])

	require.NoError(t, h.RemoveVirtualNetwork(0x12345))
}

func BenchmarkHandler(b *testing.B) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	localAddr := mustNewFullAddress("10.0.0.1:6081")
	remoteAddr := mustNewFullAddress("10.0.0.2:6081")

	h, err := icx.NewHandler(localAddr, tcpip.GetRandMacAddr(), false, false)
	require.NoError(b, err)

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	const vni = 0x12345

	err = h.AddVirtualNetwork(vni, remoteAddr, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")})
	require.NoError(b, err)

	err = h.UpdateVirtualNetworkKeys(0x12345, 1, key, key, time.Now().Add(time.Hour))
	require.NoError(b, err)

	virtMAC := tcpip.GetRandMacAddr()
	virtFrame := makeIPv4UDPEthernetFrame(virtMAC)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		phyFrame := make([]byte, 1500)
		decodedFrame := make([]byte, 1400)

		for pb.Next() {
			n, _ := h.VirtToPhy(virtFrame, phyFrame)
			require.NotZero(b, n, "Failed to encode frame")

			n = h.PhyToVirt(phyFrame, decodedFrame)
			require.NotZero(b, n, "Failed to decode frame")
		}
	})
}

func makeIPv4UDPEthernetFrame(virtMAC tcpip.LinkAddress) []byte {
	ipPacket := makeIPv4UDPPacket()

	frame := make([]byte, header.EthernetMinimumSize+len(ipPacket))
	copy(frame[header.EthernetMinimumSize:], ipPacket)

	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.GetRandMacAddr(),
		DstAddr: tcpip.GetRandMacAddr(),
		Type:    header.IPv4ProtocolNumber,
	})

	return frame
}

func makeIPv4UDPPacket() []byte {
	ipPacket := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)

	ip := header.IPv4(ipPacket)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(ipPacket)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 1).To4()),
		DstAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 2).To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udp := header.UDP(ipPacket[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: 1234,
		DstPort: 5678,
		Length:  header.UDPMinimumSize,
	})

	return ipPacket
}

func mustNewFullAddress(addrPortStr string) *tcpip.FullAddress {
	addrPort := netip.MustParseAddrPort(addrPortStr)

	switch addrPort.Addr().BitLen() {
	case 32:
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(addrPort.Addr().AsSlice()),
			Port: addrPort.Port(),
		}
	case 128:
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom16Slice(addrPort.Addr().AsSlice()),
			Port: addrPort.Port(),
		}
	default:
		panic("Unsupported IP address length")
	}
}
