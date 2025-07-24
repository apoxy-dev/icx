package proxyarp

import (
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// ARP packet field offsets (in bytes)
const (
	ArpOffsetHardwareType = 0  // 2 bytes
	ArpOffsetProtocolType = 2  // 2 bytes
	ArpOffsetHardwareSize = 4  // 1 byte
	ArpOffsetProtocolSize = 5  // 1 byte
	ArpOffsetOpcode       = 6  // 2 bytes
	ArpOffsetSenderMAC    = 8  // 6 bytes
	ArpOffsetSenderIP     = 14 // 4 bytes
	ArpOffsetTargetMAC    = 18 // 6 bytes
	ArpOffsetTargetIP     = 24 // 4 bytes
)

// Really simple Proxy ARP implementation.
type ProxyARP struct {
	mac tcpip.LinkAddress // Fake source MAC address for ARP responses
}

func NewProxyARP(mac tcpip.LinkAddress) *ProxyARP {
	return &ProxyARP{mac: mac}
}

func (p *ProxyARP) Reply(reqFrame, respFrame []byte) (int, error) {
	if len(reqFrame) < header.EthernetMinimumSize+header.ARPSize {
		return 0, fmt.Errorf("invalid ARP request frame")
	}

	arpReq := header.ARP(reqFrame[header.EthernetMinimumSize:])
	if !arpReq.IsValid() || arpReq.Op() != header.ARPRequest {
		return 0, fmt.Errorf("invalid ARP request")
	}

	// Ethernet header.
	ethResp := header.Ethernet(respFrame)
	ethResp.Encode(&header.EthernetFields{
		SrcAddr: p.mac,
		DstAddr: tcpip.LinkAddress(arpReq.HardwareAddressSender()),
		Type:    header.ARPProtocolNumber,
	})

	// ARP payload.
	arpResp := header.ARP(respFrame[header.EthernetMinimumSize:])

	// Set hardware type: Ethernet (1)
	binary.BigEndian.PutUint16(arpResp[ArpOffsetHardwareType:], 1)

	// Set protocol type: IPv4 (0x0800)
	binary.BigEndian.PutUint16(arpResp[ArpOffsetProtocolType:], uint16(header.IPv4ProtocolNumber))

	// Set lengths
	arpResp[ArpOffsetHardwareSize] = uint8(header.EthernetAddressSize) // 6
	arpResp[ArpOffsetProtocolSize] = uint8(header.IPv4AddressSize)     // 4

	// Set opcode: reply (2)
	binary.BigEndian.PutUint16(arpResp[ArpOffsetOpcode:], uint16(header.ARPReply))

	// Sender MAC: our MAC
	copy(arpResp[ArpOffsetSenderMAC:], p.mac)

	// Sender IP: originally requested IP (i.e., target IP in request)
	copy(arpResp[ArpOffsetSenderIP:], arpReq.ProtocolAddressTarget())

	// Target MAC: requester’s MAC
	copy(arpResp[ArpOffsetTargetMAC:], arpReq.HardwareAddressSender())

	// Target IP: requester’s IP
	copy(arpResp[ArpOffsetTargetIP:], arpReq.ProtocolAddressSender())

	// Return the total length of the response frame.
	return header.EthernetMinimumSize + header.ARPSize, nil
}
