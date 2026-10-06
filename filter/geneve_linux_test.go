//go:build linux

package filter

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"
)

// xdpActions are the names of the XDP actions.
var xdpActions = map[uint32]string{xdpDROP: "XDP_DROP", xdpPASS: "XDP_PASS", xdpTX: "XDP_TX", xdpREDIRECT: "XDP_REDIRECT"}

// v1Frames returns the frames that a handler at src sends to dst: a keepalive
// (protocol type 0), an inner IPv4 packet and an inner IPv6 packet.
func v1Frames(t testing.TB, src, dst netip.AddrPort) (keepalive, inner4, inner6 []byte) {
	t.Helper()
	full := func(a netip.AddrPort) *tcpip.FullAddress {
		return &tcpip.FullAddress{Addr: tcpip.AddrFromSlice(a.Addr().AsSlice()), Port: a.Port()}
	}
	h, err := icx.NewHandler(icx.WithLocalAddr(full(src)), icx.WithLayer3VirtFrames(), icx.WithKeepAliveInterval(time.Second))
	require.NoError(t, err)
	const vni = 0x12345
	all4, all6 := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	require.NoError(t, h.AddVirtualNetwork(vni, full(dst), []icx.Route{{Src: all4, Dst: all4}, {Src: all6, Dst: all6}}))
	require.NoError(t, h.UpdateVirtualNetworkSecret(vni, [32]byte{1}, 1, 2, time.Now().Add(time.Hour)))

	phy := make([]byte, 1500)
	n := h.ToPhy(phy)
	require.NotZero(t, n, "keepalive")
	keepalive = append(keepalive, phy[:n]...)
	// The inner packets are the test frames with no Ethernet header.
	ip4 := packet(t, netip.AddrPortFrom(sender4, 1), netip.AddrPortFrom(other4, 2), 64, []byte("inner"))[14:]
	ip6 := packet(t, netip.AddrPortFrom(sender6, 1), netip.AddrPortFrom(other6, 2), 64, []byte("inner"))[14:]
	n, _ = h.VirtToPhy(ip4, phy)
	require.NotZero(t, n, "inner IPv4 packet")
	inner4 = append(inner4, phy[:n]...)
	n, _ = h.VirtToPhy(ip6, phy)
	require.NotZero(t, n, "inner IPv6 packet")
	inner6 = append(inner6, phy[:n]...)
	return keepalive, inner4, inner6
}

// v2Probe returns a VPC v2 path probe of size bytes: type 0x02, version 1,
// flags (1 is a reply), a zero byte, then the IDs, the padding and the tag.
func v2Probe(flags byte, size int) []byte {
	p := make([]byte, size)
	p[0], p[1], p[2] = 0x02, 1, flags
	for i := 4; i < 46; i++ {
		p[i] = byte(i)
	}
	for i := size - 16; i < size; i++ {
		p[i] = 0xa5
	}
	return p
}

// v2PSP returns a VPC v2 PSP packet for each next header and each flags byte
// that a receiver accepts: version 0 or 1, with and without the S bit.
func v2PSP() [][]byte {
	var out [][]byte
	for _, next := range []byte{4, 41} {
		for _, flags := range []byte{0x03, 0x07, 0x83, 0x87} {
			p := pspPayload(64, testSPI)
			p[0], p[3] = next, flags
			out = append(out, p)
		}
	}
	return out
}

// firstBytes returns a packet for each first byte from lo to hi. The other
// bytes are zero, as the version bytes of a QUIC v1 long header are.
func firstBytes(lo, hi int) [][]byte {
	var out [][]byte
	for b := lo; b <= hi; b++ {
		p := make([]byte, 64)
		p[0] = byte(b)
		out = append(out, p)
	}
	return out
}

// udpPayload returns the UDP payload of frame, with the link padding if there is one.
func udpPayload(frame []byte) []byte {
	if binary.BigEndian.Uint16(frame[12:14]) == unix.ETH_P_IP {
		return frame[14+20+8:]
	}
	return frame[14+40+8:]
}

// TestGeneveSharedPort checks which packets to a bound address the Geneve
// program takes. VPC v2 packets and QUIC use the same port, and must pass.
func TestGeneveSharedPort(t *testing.T) {
	needXSK(t)
	ns := newTestNS(t)
	dst4, dst6 := netip.AddrPortFrom(relay4, relayPort), netip.AddrPortFrom(relay6, relayPort)
	src4, src6 := netip.AddrPortFrom(sender4, 4000), netip.AddrPortFrom(sender6, 4000)
	g, err := Geneve(net.UDPAddrFromAddrPort(dst4), net.UDPAddrFromAddrPort(dst6))
	if errors.Is(err, unix.EPERM) {
		skipOrFail(t, "cannot load BPF programs: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = g.Close() })
	// With a socket on the queue, the program redirects the packets that it takes.
	xsk, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(xsk) })
	require.NoError(t, unix.SetsockoptInt(xsk, unix.SOL_XDP, unix.XDP_RX_RING, 64))
	require.NoError(t, g.Register(0, xsk))

	ka4, v4in4, v6in4 := v1Frames(t, src4, dst4)
	ka6, v4in6, v6in6 := v1Frames(t, src6, dst6)
	// v2 returns a frame to each relay address for each UDP payload. The frames
	// have no link padding, so the IPv4 frame loses the padding from packet.
	v2 := func(payloads ...[]byte) [][]byte {
		var out [][]byte
		for _, p := range payloads {
			out = append(out, packet(t, src4, dst4, 64, p)[:14+20+8+len(p)], packet(t, src6, dst6, 64, p))
		}
		return out
	}
	cases := []struct {
		name   string
		frames [][]byte
		padTo  int // Frame length with link padding. Zero means no padding.
		want   uint32
	}{
		{name: "v1 keepalive", frames: [][]byte{ka4, ka6}, want: xdpREDIRECT},
		{name: "v1 inner IPv4 packet", frames: [][]byte{v4in4, v4in6}, want: xdpREDIRECT},
		{name: "v1 inner IPv6 packet", frames: [][]byte{v6in4, v6in6}, want: xdpREDIRECT},
		{name: "v2 path probe", frames: v2(v2Probe(0, 62), v2Probe(0, 1440)), want: xdpPASS},
		{name: "v2 path probe reply", frames: v2(v2Probe(1, 62), v2Probe(1, 1440)), want: xdpPASS},
		{name: "v2 lane keepalive", frames: v2([]byte{0x03}), want: xdpPASS},
		// A link pads a short frame to 60 B. The padding is not a Geneve header.
		{name: "v2 lane keepalive with link padding", frames: v2([]byte{0x03}), padTo: 60, want: xdpPASS},
		{name: "v2 PSP packet", frames: v2(v2PSP()...), want: xdpPASS},
		{name: "QUIC short header", frames: v2(firstBytes(0x40, 0x7f)...), want: xdpPASS},
		{name: "QUIC long header", frames: v2(firstBytes(0x80, 0xff)...), want: xdpPASS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, f := range tc.frames {
				if len(f) < tc.padTo {
					f = append(f[:len(f):len(f)], make([]byte, tc.padTo-len(f))...)
				}
				ret, _ := ns.run(t, g.Program, f)
				p := udpPayload(f)
				assert.Equalf(t, xdpActions[tc.want], xdpActions[ret], "frame of %d B with UDP payload % x", len(f), p[:min(len(p), 4)])
			}
		})
	}
}
