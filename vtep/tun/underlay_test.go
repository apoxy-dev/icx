package tun

import (
	"net"
	"net/netip"
	"testing"

	"github.com/apoxy-dev/icx/udp"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func fullAddr(ap netip.AddrPort) *tcpip.FullAddress {
	a := ap.Addr().Unmap()
	if a.Is4() {
		return &tcpip.FullAddress{Addr: tcpip.AddrFrom4(a.As4()), Port: ap.Port()}
	}
	return &tcpip.FullAddress{Addr: tcpip.AddrFrom16(a.As16()), Port: ap.Port()}
}

// buildPhyFrame builds a full Ethernet+IP+UDP frame carrying payload, the shape
// the engine's VirtToPhy/ToPhy emit and the underlay peels.
func buildPhyFrame(t *testing.T, src, dst netip.AddrPort, payload []byte) []byte {
	t.Helper()
	off := udp.PayloadOffsetIPv4
	if !dst.Addr().Unmap().Is4() {
		off = udp.PayloadOffsetIPv6
	}
	buf := make([]byte, off+len(payload))
	copy(buf[off:], payload)
	n, err := udp.Encode(buf, fullAddr(src), fullAddr(dst), len(payload), false)
	require.NoError(t, err)
	return buf[:n]
}

func TestPeelIPv4(t *testing.T) {
	src := netip.MustParseAddrPort("1.2.3.4:1111")
	dst := netip.MustParseAddrPort("5.6.7.8:6081")
	payload := []byte("geneve-and-ciphertext")
	frame := buildPhyFrame(t, src, dst, payload)

	gotPayload, gotDst, err := peel(frame)
	require.NoError(t, err)
	require.Equal(t, payload, gotPayload)
	require.Equal(t, dst, gotDst)
}

func TestPeelIPv6(t *testing.T) {
	src := netip.MustParseAddrPort("[2001:db8::1]:1111")
	dst := netip.MustParseAddrPort("[2001:db8::2]:6081")
	payload := []byte("geneve-and-ciphertext-v6")
	frame := buildPhyFrame(t, src, dst, payload)

	gotPayload, gotDst, err := peel(frame)
	require.NoError(t, err)
	require.Equal(t, payload, gotPayload)
	require.Equal(t, dst, gotDst)
}

func TestPeelRejectsMalformed(t *testing.T) {
	_, _, err := peel([]byte{0x00, 0x01, 0x02})
	require.ErrorIs(t, err, errShortFrame)

	// A 14-byte ethernet header with an unsupported ethertype.
	bad := make([]byte, header.EthernetMinimumSize)
	header.Ethernet(bad).Encode(&header.EthernetFields{Type: 0x9999})
	_, _, err = peel(bad)
	require.ErrorIs(t, err, errUnsupportedEthertype)
}

// TestSynthesizeRoundTrip checks that a frame synthesized from a payload + peer
// address decodes back to that payload via the same udp.Decode the engine uses
// (skip-checksum), for both address families. The payload starts at the IPv6
// reserve offset, matching udpUnderlay.ReadFrame's in-place contract.
func TestSynthesizeRoundTrip(t *testing.T) {
	const reserve = 62 // udp.PayloadOffsetIPv6
	for _, tc := range []struct {
		name string
		peer netip.AddrPort
	}{
		{"ipv4", netip.MustParseAddrPort("10.0.0.9:6081")},
		{"ipv6", netip.MustParseAddrPort("[fd00::9]:6081")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("decryptable-geneve-payload")
			buf := make([]byte, 2048)
			copy(buf[reserve:], payload)

			n, err := synthesize(buf, reserve, len(payload), tc.peer)
			require.NoError(t, err)

			out, err := udp.Decode(buf[:n], nil, true)
			require.NoError(t, err)
			require.Equal(t, payload, out)
		})
	}
}

func TestSynthesizeRejectsOversized(t *testing.T) {
	buf := make([]byte, 100)
	_, err := synthesize(buf, 62, 200, netip.MustParseAddrPort("10.0.0.1:6081"))
	require.ErrorIs(t, err, errFrameTooLarge)
}

// TestUDPUnderlayLoopback drives the real udpUnderlay over a loopback UDP socket
// pair: a full phy frame written to A is peeled, sent, received by B, and
// synthesized back into a frame whose decoded payload matches the original.
func TestUDPUnderlayLoopback(t *testing.T) {
	connA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	connB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	uuA, err := newUDPUnderlay(connA)
	require.NoError(t, err)
	t.Cleanup(func() { _ = uuA.Close() })
	uuB, err := newUDPUnderlay(connB)
	require.NoError(t, err)
	t.Cleanup(func() { _ = uuB.Close() })

	src := connA.LocalAddr().(*net.UDPAddr).AddrPort()
	dst := connB.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := []byte("geneve-header-plus-aead-ciphertext")
	frame := buildPhyFrame(t, src, dst, payload)

	n, err := uuA.WriteFrames([][]byte{frame})
	require.NoError(t, err)
	require.Equal(t, 1, n)

	buf := make([]byte, maxFrameSize)
	fn, err := uuB.ReadFrame(buf)
	require.NoError(t, err)
	require.NotZero(t, fn)

	out, err := udp.Decode(buf[:fn], nil, true)
	require.NoError(t, err)
	require.Equal(t, payload, out, "payload must survive peel -> UDP wire -> synthesize")
}
