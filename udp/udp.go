package udp

import (
	"errors"
	"math"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	PayloadOffsetIPv4 = header.EthernetMinimumSize + header.IPv4MinimumSize + header.UDPMinimumSize
	PayloadOffsetIPv6 = header.EthernetMinimumSize + header.IPv6MinimumSize + header.UDPMinimumSize
)

// Decode extracts the source address and payload from a UDP ethernet frame.
func Decode(frame []byte, addr *tcpip.FullAddress, skipChecksumValidation bool) ([]byte, error) {
	var (
		udp     header.UDP
		srcAddr tcpip.Address
		dstAddr tcpip.Address
	)

	if len(frame) < header.EthernetMinimumSize {
		return nil, errors.New("frame too short")
	}

	eth := header.Ethernet(frame)
	ethType := eth.Type()

	switch ethType {
	case header.IPv4ProtocolNumber:
		ip := header.IPv4(frame[header.EthernetMinimumSize:])
		if !ip.IsValid(len(ip)) || ip.Protocol() != uint8(header.UDPProtocolNumber) {
			return nil, errors.New("not a valid IPv4 UDP packet")
		}
		srcAddr = ip.SourceAddress()
		dstAddr = ip.DestinationAddress()
		udp = header.UDP(ip.Payload())

	case header.IPv6ProtocolNumber:
		ip := header.IPv6(frame[header.EthernetMinimumSize:])
		if !ip.IsValid(len(ip)) || ip.TransportProtocol() != header.UDPProtocolNumber {
			return nil, errors.New("not a valid IPv6 UDP packet")
		}
		srcAddr = ip.SourceAddress()
		dstAddr = ip.DestinationAddress()
		udp = header.UDP(ip.Payload())

	default:
		return nil, errors.New("unsupported ethertype")
	}

	lengthValid, csumValid := header.UDPValid(
		udp,
		func() uint16 { return checksum.Checksum(udp.Payload(), 0) },
		uint16(len(udp.Payload())),
		tcpip.NetworkProtocolNumber(header.UDPProtocolNumber),
		srcAddr,
		dstAddr,
		skipChecksumValidation,
	)
	if !lengthValid || !csumValid {
		return nil, errors.New("invalid UDP checksum or length")
	}

	if addr != nil {
		addr.Addr = srcAddr
		addr.Port = udp.SourcePort()
		addr.LinkAddr = eth.SourceAddress()
	}

	return udp.Payload(), nil
}

// Encode constructs a UDP ethernet frame with the given parameters.
// It assumes that the payload is already in the frame buffer at the correct
// offset.
func Encode(frame []byte, src, dst *tcpip.FullAddress, payloadLength int, skipChecksumCalculation bool) (int, error) {
	var offset int

	isIPv6 := src.Addr.Len() == net.IPv6len

	eth := header.Ethernet(frame[offset:])
	eth.Encode(&header.EthernetFields{
		SrcAddr: src.LinkAddr,
		DstAddr: dst.LinkAddr,
		Type: func() tcpip.NetworkProtocolNumber {
			if isIPv6 {
				return header.IPv6ProtocolNumber
			}
			return header.IPv4ProtocolNumber
		}(),
	})
	offset += header.EthernetMinimumSize

	udpPayloadLength := header.UDPMinimumSize + payloadLength

	if isIPv6 {
		ip := header.IPv6(frame[offset:])
		ip.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(udpPayloadLength),
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          64,
			SrcAddr:           src.Addr,
			DstAddr:           dst.Addr,
		})
		offset += header.IPv6MinimumSize
	} else {
		ip := header.IPv4(frame[offset:])
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(header.IPv4MinimumSize + udpPayloadLength),
			TTL:         64,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     src.Addr,
			DstAddr:     dst.Addr,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		offset += header.IPv4MinimumSize
	}

	udp := header.UDP(frame[offset:])
	udp.Encode(&header.UDPFields{
		SrcPort: src.Port,
		DstPort: dst.Port,
		Length:  uint16(udpPayloadLength),
	})
	offset += header.UDPMinimumSize

	if !skipChecksumCalculation {
		csum := udp.CalculateChecksum(checksum.Combine(
			header.PseudoHeaderChecksum(
				header.UDPProtocolNumber,
				src.Addr,
				dst.Addr,
				uint16(udpPayloadLength),
			),
			checksum.Checksum(frame[offset:offset+payloadLength], 0),
		))
		if csum != math.MaxUint16 {
			csum = ^csum
		}
		udp.SetChecksum(csum)
	}

	return offset + payloadLength, nil
}
