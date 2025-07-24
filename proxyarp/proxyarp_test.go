package proxyarp_test

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx/proxyarp"
)

func TestProxyARP_Reply(t *testing.T) {
	proxyMAC := tcpip.GetRandMacAddr() // the “fake” MAC this proxy will use
	p := proxyarp.NewProxyARP(proxyMAC)

	reqMAC := tcpip.GetRandMacAddr()
	senderIP := tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 55).To4())
	targetIP := tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 1).To4())

	// Build a minimal ARP-request Ethernet frame.
	const frameLen = header.EthernetMinimumSize + header.ARPSize
	req := make([]byte, frameLen)

	ethReq := header.Ethernet(req)
	ethReq.Encode(&header.EthernetFields{
		SrcAddr: reqMAC,
		DstAddr: header.EthernetBroadcastAddress,
		Type:    header.ARPProtocolNumber,
	})

	arpReq := header.ARP(req[header.EthernetMinimumSize:])
	// Hardware-type = Ethernet, Proto-type = IPv4, sizes 6/4, opcode = request.
	binary.BigEndian.PutUint16(arpReq[proxyarp.ArpOffsetHardwareType:], 1)
	binary.BigEndian.PutUint16(arpReq[proxyarp.ArpOffsetProtocolType:], uint16(header.IPv4ProtocolNumber))
	arpReq[proxyarp.ArpOffsetHardwareSize] = uint8(header.EthernetAddressSize)
	arpReq[proxyarp.ArpOffsetProtocolSize] = uint8(header.IPv4AddressSize)
	binary.BigEndian.PutUint16(arpReq[proxyarp.ArpOffsetOpcode:], uint16(header.ARPRequest))
	// Sender MAC / IP.
	copy(arpReq[proxyarp.ArpOffsetSenderMAC:], reqMAC)
	copy(arpReq[proxyarp.ArpOffsetSenderIP:], senderIP.AsSlice())
	// Target MAC is all zeroes in an ARP request.
	copy(arpReq[proxyarp.ArpOffsetTargetIP:], targetIP.AsSlice())

	resp := make([]byte, frameLen)
	n, err := p.Reply(req, resp)
	require.NoError(t, err)
	require.Equal(t, frameLen, n)

	ethResp := header.Ethernet(resp)
	require.Equal(t, proxyMAC, ethResp.SourceAddress(), "Ethernet src should be the proxy’s MAC")
	require.Equal(t, reqMAC, ethResp.DestinationAddress(), "Ethernet dst should be the requester’s MAC")
	require.Equal(t, header.ARPProtocolNumber, ethResp.Type())

	arpResp := header.ARP(resp[header.EthernetMinimumSize:])
	require.True(t, arpResp.IsValid(), "ARP payload should be well-formed")
	require.Equal(t, header.ARPReply, arpResp.Op())
	require.Equal(t, proxyMAC, tcpip.LinkAddress(arpResp.HardwareAddressSender()))
	require.Equal(t, targetIP, tcpip.AddrFromSlice(arpResp.ProtocolAddressSender()))
	require.Equal(t, reqMAC, tcpip.LinkAddress(arpResp.HardwareAddressTarget()))
	require.Equal(t, senderIP, tcpip.AddrFromSlice(arpResp.ProtocolAddressTarget()))
}
