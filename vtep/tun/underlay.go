package tun

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/apoxy-dev/icx/udp"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Peel/synthesize errors. The engine's phy frame is a full Ethernet+IP+UDP+Geneve
// frame, but the backplane pod has no CAP_NET_RAW for a packet socket, so the
// underlay is a plain UDP socket: WriteFrames peels the outer headers and sends
// only the Geneve UDP payload to the destination the engine selected, and
// ReadFrame synthesizes a matching outer frame around an inbound payload so the
// engine's PhyToVirt (which parses a full L2 frame) can decode it. This is the
// same bridge apoxy-cli's l2pc performs for the netstack driver.
var (
	errShortFrame           = errors.New("tun underlay: frame shorter than ethernet header")
	errInvalidFrame         = errors.New("tun underlay: invalid outer IPv4/IPv6+UDP frame")
	errUnsupportedEthertype = errors.New("tun underlay: unsupported ethertype")
	errFrameTooLarge        = errors.New("tun underlay: frame exceeds buffer")
)

// udpUnderlay adapts a *net.UDPConn into an Underlay that carries full
// Ethernet+IP+UDP+Geneve phy frames, peeling/synthesizing the outer headers.
type udpUnderlay struct {
	conn *net.UDPConn
}

var _ Underlay = (*udpUnderlay)(nil)

// newUDPUnderlay wraps a bound UDP socket. The driver owns the socket and closes
// it on Close.
func newUDPUnderlay(conn *net.UDPConn) (*udpUnderlay, error) {
	if conn == nil {
		return nil, fmt.Errorf("tun underlay: conn is required")
	}
	if _, ok := conn.LocalAddr().(*net.UDPAddr); !ok {
		return nil, fmt.Errorf("tun underlay: conn must be UDP")
	}
	return &udpUnderlay{conn: conn}, nil
}

func (u *udpUnderlay) Close() error { return u.conn.Close() }

// WriteFrames peels each full phy frame to (Geneve payload, outer destination)
// and sends the payload over the UDP socket. A frame that fails to peel (malformed
// engine output) is skipped rather than stalling the batch. On a socket write
// error it returns the number sent so far so the caller can drain the remainder.
func (u *udpUnderlay) WriteFrames(frames [][]byte) (int, error) {
	for i, f := range frames {
		payload, dst, err := peel(f)
		if err != nil {
			// peel only ever sees our own engine's VirtToPhy/ToPhy output, so a
			// failure here implies an engine bug, not untrusted input — surface it
			// rather than dropping silently. Keep the batch moving.
			slog.Warn("tun underlay: dropping unpeelable engine frame", slog.Any("error", err))
			continue
		}
		if _, err := u.conn.WriteToUDPAddrPort(payload, dst); err != nil {
			if isClosedErr(err) {
				return i, net.ErrClosed
			}
			return i, err
		}
	}
	return len(frames), nil
}

// ReadFrame reads one UDP datagram (a Geneve payload) and synthesizes a full
// Ethernet+IP+UDP frame around it into buf, returning the frame length.
func (u *udpUnderlay) ReadFrame(buf []byte) (int, error) {
	// Read the payload into the part of buf where it will live for an IPv6 outer
	// frame (the larger header room); synthesize then shifts it down for an IPv4
	// outer frame, avoiding a second buffer.
	const reserve = 62 // udp.PayloadOffsetIPv6
	if len(buf) <= reserve {
		return 0, errFrameTooLarge
	}
	n, peer, err := u.conn.ReadFromUDPAddrPort(buf[reserve:])
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	return synthesize(buf, reserve, n, peer)
}

// peel extracts the Geneve UDP payload and the outer destination AddrPort from a
// full Ethernet+IP+UDP frame produced by the engine's VirtToPhy/ToPhy. The
// returned payload aliases frame.
func peel(frame []byte) ([]byte, netip.AddrPort, error) {
	if len(frame) < header.EthernetMinimumSize {
		return nil, netip.AddrPort{}, errShortFrame
	}
	eth := header.Ethernet(frame)
	switch eth.Type() {
	case header.IPv4ProtocolNumber:
		ip := header.IPv4(frame[header.EthernetMinimumSize:])
		if !ip.IsValid(len(ip)) || ip.Protocol() != uint8(header.UDPProtocolNumber) {
			return nil, netip.AddrPort{}, errInvalidFrame
		}
		udpHdr := header.UDP(ip.Payload())
		if len(udpHdr) < header.UDPMinimumSize {
			return nil, netip.AddrPort{}, errInvalidFrame
		}
		dstIP, ok := netip.AddrFromSlice(ip.DestinationAddressSlice())
		if !ok {
			return nil, netip.AddrPort{}, errInvalidFrame
		}
		return udpHdr.Payload(), netip.AddrPortFrom(dstIP.Unmap(), udpHdr.DestinationPort()), nil

	case header.IPv6ProtocolNumber:
		ip := header.IPv6(frame[header.EthernetMinimumSize:])
		if !ip.IsValid(len(ip)) || ip.TransportProtocol() != header.UDPProtocolNumber {
			return nil, netip.AddrPort{}, errInvalidFrame
		}
		udpHdr := header.UDP(ip.Payload())
		if len(udpHdr) < header.UDPMinimumSize {
			return nil, netip.AddrPort{}, errInvalidFrame
		}
		dstIP, ok := netip.AddrFromSlice(ip.DestinationAddressSlice())
		if !ok {
			return nil, netip.AddrPort{}, errInvalidFrame
		}
		return udpHdr.Payload(), netip.AddrPortFrom(dstIP.Unmap(), udpHdr.DestinationPort()), nil

	default:
		return nil, netip.AddrPort{}, errUnsupportedEthertype
	}
}

// synthesize builds a full Ethernet+IP+UDP frame around the payload currently at
// buf[payloadAt:payloadAt+payloadLen] into buf, returning the frame length. The
// outer family is taken from peer so udp.Decode routes the correct path. The
// outer addresses are decorative to the engine: udp.Decode (called with
// skip-checksum) ignores the MACs and checksum, validating only the length
// fields, and PhyToVirt selects the SA by Geneve SPI and never learns the peer.
// Both outer src and dst are set to peer, which trivially keeps the address
// families equal as udp.Encode requires.
func synthesize(buf []byte, payloadAt, payloadLen int, peer netip.AddrPort) (int, error) {
	a := peer.Addr().Unmap()

	var payloadOff int
	var fa tcpip.FullAddress
	if a.Is4() {
		payloadOff = udp.PayloadOffsetIPv4
		fa = tcpip.FullAddress{Addr: tcpip.AddrFrom4(a.As4()), Port: peer.Port()}
	} else {
		payloadOff = udp.PayloadOffsetIPv6
		fa = tcpip.FullAddress{Addr: tcpip.AddrFrom16(a.As16()), Port: peer.Port()}
	}

	if payloadOff+payloadLen > len(buf) {
		return 0, errFrameTooLarge
	}
	if payloadOff != payloadAt {
		// IPv4 outer: shift the payload down from the IPv6 reserve to the IPv4
		// offset. copy handles the overlap (dst < src) correctly.
		copy(buf[payloadOff:payloadOff+payloadLen], buf[payloadAt:payloadAt+payloadLen])
	}
	// skip-checksum: the synthesized frame is consumed only by our own engine's
	// PhyToVirt in this process and never goes on a wire; udp.Decode is called
	// with skipChecksumValidation, so a real checksum would be wasted work.
	return udp.Encode(buf, &fa, &fa, payloadLen, true)
}
