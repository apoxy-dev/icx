package icx_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx"
)

func TestHandler(t *testing.T) {
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

	h, err := icx.NewHandler(localAddr, peerAddr, virtMAC, 0x12345, key, key, true)
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
}

func makeIPv4UDPEthernetFrame(virtMAC tcpip.LinkAddress) []byte {
	frame := make([]byte, header.EthernetMinimumSize+header.IPv4MinimumSize+header.UDPMinimumSize)
	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.GetRandMacAddr(),
		DstAddr: tcpip.GetRandMacAddr(),
		Type:    header.IPv4ProtocolNumber,
	})

	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(frame) - header.EthernetMinimumSize),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 1).To4()),
		DstAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 2).To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udp := header.UDP(frame[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: 1234,
		DstPort: 5678,
		Length:  header.UDPMinimumSize,
	})

	return frame
}
