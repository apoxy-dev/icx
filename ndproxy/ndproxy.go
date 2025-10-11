package ndproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	// NA header (24) + TLLAO option (8) = 32 bytes ICMPv6 payload.
	tllaoOptLen              = 8 // Type(1)=2, Len(1)=1(=8 bytes), MAC(6)
	ICMPv6NeighborAdvertSize = header.ICMPv6NeighborAdvertMinimumSize + tllaoOptLen
)

// Flags for NA (RFC 4861 §4.4).
const (
	NAFlagRouter    = 0x80000000
	NAFlagSolicited = 0x40000000
	NAFlagOverride  = 0x20000000
)

// Really simple Neighbor Discovery Proxy implementation.
type NDProxy struct {
	mac tcpip.LinkAddress // Fake source MAC address for NA responses
}

func NewNDProxy(mac tcpip.LinkAddress) *NDProxy {
	return &NDProxy{mac: mac}
}

// Reply reads an Ethernet+IPv6+ICMPv6 Neighbor Solicitation in reqFrame and
// writes an Ethernet+IPv6+ICMPv6 Neighbor Advertisement into respFrame.
// Returns the total response length.
func (p *NDProxy) Reply(reqFrame, respFrame []byte) (int, error) {
	// Ethernet + IPv6 + minimal NS.
	if len(reqFrame) < header.EthernetMinimumSize+header.IPv6MinimumSize+header.ICMPv6NeighborSolicitMinimumSize {
		return 0, fmt.Errorf("invalid NS frame: too short")
	}

	// Parse request Ethernet
	ethReq := header.Ethernet(reqFrame)
	if ethReq.Type() != header.IPv6ProtocolNumber {
		return 0, errors.New("not IPv6")
	}
	srcMAC := ethReq.SourceAddress()

	// Parse IPv6
	ip6Req := header.IPv6(reqFrame[header.EthernetMinimumSize:])
	if !ip6Req.IsValid(len(reqFrame[header.EthernetMinimumSize:])) {
		return 0, errors.New("invalid IPv6 header")
	}
	if ip6Req.TransportProtocol() != header.ICMPv6ProtocolNumber {
		return 0, errors.New("not ICMPv6")
	}
	// RFC 4861 §7.1.1: NS MUST be received with HopLimit=255.
	if ip6Req.HopLimit() != header.NDPHopLimit {
		return 0, errors.New("NS invalid hop limit")
	}
	srcIP := ip6Req.SourceAddress()

	// Parse ICMPv6
	icmpReq := ip6Req.Payload()
	if len(icmpReq) < header.ICMPv6NeighborSolicitMinimumSize {
		return 0, errors.New("ICMPv6 payload too short")
	}
	if icmpReq[0] != 135 /* NS */ || icmpReq[1] != 0 {
		return 0, errors.New("not a Neighbor Solicitation")
	}

	// Extract target IP from NS (bytes 8..23 of ICMPv6).
	var targetIP16 [16]byte
	copy(targetIP16[:], icmpReq[8:8+16])
	targetIP := tcpip.AddrFrom16(targetIP16)

	// Prepare response lengths
	totalLen := header.EthernetMinimumSize + header.IPv6MinimumSize + ICMPv6NeighborAdvertSize
	if len(respFrame) < totalLen {
		return 0, fmt.Errorf("response buffer too small: need %d", totalLen)
	}

	// Ethernet (unicast back to requester)
	ethResp := header.Ethernet(respFrame[:header.EthernetMinimumSize])
	ethResp.Encode(&header.EthernetFields{
		SrcAddr: p.mac,
		DstAddr: tcpip.LinkAddress(srcMAC),
		Type:    header.IPv6ProtocolNumber,
	})

	// IPv6
	ip6Resp := header.IPv6(respFrame[header.EthernetMinimumSize : header.EthernetMinimumSize+header.IPv6MinimumSize])
	ip6Resp.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(ICMPv6NeighborAdvertSize),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          header.NDPHopLimit,
		SrcAddr:           targetIP, // we "own" the target
		DstAddr:           srcIP,    // reply to the NS sender
	})

	// ICMPv6 NA
	icmp := respFrame[header.EthernetMinimumSize+header.IPv6MinimumSize : totalLen]
	icmp[0] = 136 // NA
	icmp[1] = 0
	icmp[2] = 0 // checksum placeholder
	icmp[3] = 0

	// Flags: Solicited + Override (not a router).
	binary.BigEndian.PutUint32(icmp[4:8], NAFlagSolicited|NAFlagOverride)

	// Target Address (16 bytes).
	copy(icmp[8:8+16], targetIP.AsSlice())

	// Option: Target Link-Layer Address (Type=2, Len=1 (8bytes), MAC 6B).
	opt := icmp[header.ICMPv6NeighborAdvertMinimumSize:ICMPv6NeighborAdvertSize]
	opt[0] = 2 // TLLAO
	opt[1] = 1 // length in 8-byte units
	copy(opt[2:8], p.mac[:])

	// ICMPv6 checksum using gVisor helpers
	cs := checksum.Combine(
		header.PseudoHeaderChecksum(
			header.ICMPv6ProtocolNumber,
			targetIP,
			srcIP,
			uint16(len(icmp)),
		),
		checksum.Checksum(icmp, 0),
	)
	if cs != math.MaxUint16 {
		cs = ^cs
	}
	// ICMPv6 stores checksum big-endian in bytes 2..3.
	binary.BigEndian.PutUint16(icmp[2:4], cs)

	return totalLen, nil
}
