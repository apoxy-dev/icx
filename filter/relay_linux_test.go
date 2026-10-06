//go:build linux

package filter

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/icx/permissions"
)

// XDP actions.
const (
	xdpDROP     uint32 = 1
	xdpPASS     uint32 = 2
	xdpTX       uint32 = 3
	xdpREDIRECT uint32 = 4
)

const (
	relayPort  = 6081
	nextPort   = 5000
	testSPI    = 0x01020304
	testMaxLen = 1500
	// timerTick is the longest timer tick of a kernel.
	timerTick = 10 * time.Millisecond
)

var (
	relayMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	peerMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	// relay4 and relay6 are on the test link. next4 and next6 are neighbors
	// on it. The senders are anywhere.
	relay4   = netip.MustParseAddr("10.9.0.1")
	next4    = netip.MustParseAddr("10.9.0.2")
	sender4  = netip.MustParseAddr("192.0.2.7")
	relay6   = netip.MustParseAddr("fd09::1")
	next6    = netip.MustParseAddr("fd09::2")
	sender6  = netip.MustParseAddr("2001:db8::7")
	noNeigh  = netip.MustParseAddr("10.9.0.77")
	noNeigh6 = netip.MustParseAddr("fd09::77")
	other4   = netip.MustParseAddr("198.51.100.9")
	other6   = netip.MustParseAddr("2001:db8:1::9")
	relayB4  = netip.MustParseAddr("10.9.0.4")
	mapped4  = netip.AddrFrom16(sender4.As16())
	ones4    = netip.MustParseAddr("255.255.255.255")
	ones6    = netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
)

// xdpMD is struct xdp_md, the context of an XDP test run.
type xdpMD struct {
	Data, DataEnd, DataMeta, IngressIfindex, RxQueueIndex, EgressIfindex uint32
}

// testNS is a netns with a veth link rl0 that has the relay addresses and
// the neighbors next4 and next6. A test run finds the ingress ifindex in the
// netns of the thread, so the programs run on the thread of testNS.
type testNS struct {
	ifindex int
	peer    int // The ifindex of rl1, which has no forwarding.
	work    chan func()
}

// requireBPFEnv is set where the tests have the rights to load and run BPF
// programs, as in the privileged CI lanes.
const requireBPFEnv = "ICX_REQUIRE_BPF"

// skipOrFail skips a test that the process has no rights for. It fails the
// test when requireBPFEnv is set, so a CI lane cannot pass with a skip.
func skipOrFail(t testing.TB, format string, args ...any) {
	t.Helper()
	if os.Getenv(requireBPFEnv) != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

// noXSK returns the error of a kernel with no AF_XDP sockets, as that of the
// arm64 CI runners. Such a kernel cannot load a program with a socket map.
func noXSK() error {
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	if errors.Is(err, unix.EAFNOSUPPORT) {
		return err
	}
	return nil
}

// needXSK skips a test of the All or Geneve program on a kernel with no
// AF_XDP sockets.
func needXSK(t testing.TB) {
	t.Helper()
	if err := noXSK(); err != nil {
		t.Skipf("the kernel has no AF_XDP sockets: %v", err)
	}
}

// newTestNS makes a testNS. It skips the test without NET_ADMIN.
func newTestNS(t testing.TB) *testNS {
	t.Helper()
	if ok, _ := permissions.IsNetAdmin(); !ok {
		skipOrFail(t, "needs NET_ADMIN")
	}
	ns := &testNS{work: make(chan func())}
	errc := make(chan error, 1)
	go func() {
		// The thread stays in the new netns, so it must exit with the goroutine.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		var err error
		ns.ifindex, ns.peer, err = setupLink()
		errc <- err
		if err != nil {
			return
		}
		for fn := range ns.work {
			fn()
		}
	}()
	if err := <-errc; err != nil {
		skipOrFail(t, "cannot set up the test netns: %v", err)
	}
	t.Cleanup(func() { close(ns.work) })
	return ns
}

func setForwarding(t testing.TB, ns *testNS, v string) {
	var err error
	ns.do(func() { err = os.WriteFile("/proc/sys/net/ipv4/conf/rl0/forwarding", []byte(v), 0o644) })
	require.NoError(t, err)
}

// netlink runs fn with the link rl0 on the thread of ns.
func (ns *testNS) netlink(t testing.TB, fn func(netlink.Link) error) {
	t.Helper()
	var err error
	ns.do(func() {
		var l netlink.Link
		if l, err = netlink.LinkByName("rl0"); err == nil {
			err = fn(l)
		}
	})
	require.NoError(t, err)
}

// do runs fn on the thread of ns.
func (ns *testNS) do(fn func()) {
	done := make(chan struct{})
	ns.work <- func() {
		defer close(done)
		fn()
	}
	<-done
}

func setupLink() (ifindex, peer int, err error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "rl0", HardwareAddr: relayMAC},
		PeerName:  "rl1",
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return 0, 0, err
	}
	for _, name := range []string{"lo", "rl0", "rl1"} {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return 0, 0, err
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return 0, 0, err
		}
	}
	l, err := netlink.LinkByName("rl0")
	if err != nil {
		return 0, 0, err
	}
	for _, p := range []string{"10.9.0.1/24", "fd09::1/64"} {
		a, _ := netlink.ParseAddr(p)
		a.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(l, a); err != nil {
			return 0, 0, err
		}
	}
	for _, ip := range []netip.Addr{next4, next6} {
		fam := netlink.FAMILY_V4
		if ip.Is6() {
			fam = netlink.FAMILY_V6
		}
		n := &netlink.Neigh{LinkIndex: l.Attrs().Index, Family: fam, State: netlink.NUD_PERMANENT, IP: ip.AsSlice(), HardwareAddr: peerMAC}
		if err := netlink.NeighAdd(n); err != nil {
			return 0, 0, err
		}
	}
	// The FIB lookup of XDP needs forwarding on the ingress link.
	for _, f := range []string{"/proc/sys/net/ipv4/conf/rl0/forwarding", "/proc/sys/net/ipv6/conf/rl0/forwarding"} {
		if err := os.WriteFile(f, []byte("1"), 0o644); err != nil {
			return 0, 0, err
		}
	}
	p, err := netlink.LinkByName("rl1")
	if err != nil {
		return 0, 0, err
	}
	return l.Attrs().Index, p.Attrs().Index, nil
}

// pspPayload returns a PSP packet of size bytes with spi.
func pspPayload(size int, spi uint32) []byte {
	p := make([]byte, size)
	p[0], p[1], p[2], p[3] = 4, 2, 2, 0x03
	binary.BigEndian.PutUint32(p[4:8], spi)
	for i := 8; i < size; i++ {
		p[i] = byte(i)
	}
	return p
}

// packet returns an Ethernet frame from src to dst with payload.
func packet(t testing.TB, src, dst netip.AddrPort, ttl uint8, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: peerMAC, DstMAC: relayMAC, EthernetType: layers.EthernetTypeIPv4}
	udp := &layers.UDP{SrcPort: layers.UDPPort(src.Port()), DstPort: layers.UDPPort(dst.Port())}
	var ip gopacket.NetworkLayer
	if src.Addr().Is4() {
		ip4 := &layers.IPv4{Version: 4, IHL: 5, TTL: ttl, Protocol: layers.IPProtocolUDP, SrcIP: src.Addr().AsSlice(), DstIP: dst.Addr().AsSlice()}
		ip = ip4
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip = &layers.IPv6{Version: 6, HopLimit: ttl, NextHeader: layers.IPProtocolUDP, SrcIP: src.Addr().AsSlice(), DstIP: dst.Addr().AsSlice()}
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip.(gopacket.SerializableLayer), udp, gopacket.Payload(payload)))
	return buf.Bytes()
}

// sum16 returns the one's complement sum of b, with initial sum s.
func sum16(s uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s > 0xffff {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}

// fixIPv4Sum sets the header checksum of the IPv4 header h.
func fixIPv4Sum(h []byte) {
	h[10], h[11] = 0, 0
	binary.BigEndian.PutUint16(h[10:12], ^fold(sum16(0, h)))
}

// checkSums checks the IPv4 header checksum and the UDP checksum of frame.
func checkSums(t *testing.T, frame []byte) {
	t.Helper()
	var src, dst []byte
	var udp []byte
	if binary.BigEndian.Uint16(frame[12:14]) == 0x0800 {
		ip := frame[14:34]
		assert.Equal(t, uint16(0xffff), fold(sum16(0, ip)), "IPv4 header checksum")
		src, dst, udp = ip[12:16], ip[16:20], frame[34:]
	} else {
		ip := frame[14:54]
		src, dst, udp = ip[8:24], ip[24:40], frame[54:]
	}
	udp = udp[:binary.BigEndian.Uint16(udp[4:6])]
	if binary.BigEndian.Uint16(udp[6:8]) == 0 {
		return
	}
	s := sum16(0, src)
	s = sum16(s, dst)
	s += uint32(unix.IPPROTO_UDP) + uint32(len(udp))
	assert.Equal(t, uint16(0xffff), fold(sum16(s, udp)), "UDP checksum")
}

// newTestRelay loads a relay program with the test port, length bound and addresses.
func newTestRelay(t testing.TB, cfg RelayConfig) *Relay {
	t.Helper()
	cfg.Port = relayPort
	cfg.MaxLen = testMaxLen
	r, err := NewRelay(cfg)
	if errors.Is(err, unix.EPERM) {
		skipOrFail(t, "cannot load BPF programs: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })
	require.NoError(t, r.SetAddrs([]netip.Addr{relay4, relay6}))
	return r
}

func (ns *testNS) run(t testing.TB, prog *ebpf.Program, frame []byte) (uint32, []byte) {
	t.Helper()
	return ns.runOn(t, prog, frame, ns.ifindex)
}

// runOn runs prog on frame as a packet of the link ifindex.
func (ns *testNS) runOn(t testing.TB, prog *ebpf.Program, frame []byte, ifindex int) (uint32, []byte) {
	t.Helper()
	out := make([]byte, len(frame)+256)
	opts := &ebpf.RunOptions{
		Data:    frame,
		DataOut: out,
		Context: xdpMD{DataEnd: uint32(len(frame)), IngressIfindex: uint32(ifindex)},
	}
	var ret uint32
	var err error
	ns.do(func() { ret, err = prog.Run(opts) })
	require.NoError(t, err)
	return ret, opts.DataOut
}

func TestRelayForward(t *testing.T) {
	far := Monotonic() + time.Hour
	src4, dst4 := netip.AddrPortFrom(sender4, 4000), netip.AddrPortFrom(relay4, relayPort)
	src6, dst6 := netip.AddrPortFrom(sender6, 4000), netip.AddrPortFrom(relay6, relayPort)
	row4 := map[netip.AddrPort]RelayRow{src4: {Next: netip.AddrPortFrom(next4, nextPort), Expires: far}}
	row6 := map[netip.AddrPort]RelayRow{src6: {Next: netip.AddrPortFrom(next6, nextPort), Expires: far}}
	cases := []struct {
		name    string
		cfg     RelayConfig
		rows    map[netip.AddrPort]RelayRow // Rows for testSPI.
		tunnels []uint32
		frames  int // Frames to send; the last one is checked. Default 1.
		src     netip.AddrPort
		dst     netip.AddrPort
		ttl     uint8
		payload []byte
		noCsum  bool                // Send with UDP checksum 0.
		noFwd   bool                // Turn off IPv4 forwarding on the link.
		mutate  func([]byte) []byte // Changes the frame. A forward keeps the change.
		want    uint32
		stats   RelayStats
	}{
		{
			name: "IPv4 forward",
			rows: row4, src: src4, dst: dst4, ttl: 3,
			want: xdpTX, stats: RelayStats{Packets: 1, Bytes: 100},
		},
		{
			name: "IPv6 forward",
			rows: row6, src: src6, dst: dst6, ttl: 1,
			want: xdpTX, stats: RelayStats{Packets: 1, Bytes: 100},
		},
		{
			name: "IPv4 forward with a redirect",
			cfg:  RelayConfig{Redirect: true},
			rows: row4, src: src4, dst: dst4, ttl: 3,
			want: xdpREDIRECT, stats: RelayStats{Packets: 1, Bytes: 100},
		},
		{
			name: "IPv6 forward with a redirect",
			cfg:  RelayConfig{Redirect: true},
			rows: row6, src: src6, dst: dst6, ttl: 1,
			want: xdpREDIRECT, stats: RelayStats{Packets: 1, Bytes: 100},
		},
		{
			name: "IPv4 forward with a kept next hop",
			cfg:  RelayConfig{NextHopCache: time.Hour},
			rows: row4, frames: 3, src: src4, dst: dst4, ttl: 3,
			want: xdpTX, stats: RelayStats{Packets: 3, Bytes: 300},
		},
		{
			name: "IPv6 forward with a kept next hop",
			cfg:  RelayConfig{NextHopCache: time.Hour},
			rows: row6, frames: 3, src: src6, dst: dst6, ttl: 1,
			want: xdpTX, stats: RelayStats{Packets: 3, Bytes: 300},
		},
		{
			// The words of the addresses and the ports carry in the sums.
			name: "IPv4 forward from an address and a port of all ones",
			rows: map[netip.AddrPort]RelayRow{netip.AddrPortFrom(ones4, 65535): {Next: netip.AddrPortFrom(next4, 65535), Expires: far}},
			src:  netip.AddrPortFrom(ones4, 65535), dst: dst4, ttl: 255,
			want: xdpTX, stats: RelayStats{Packets: 1, Bytes: 100},
		},
		{
			name: "IPv6 forward from an address and a port of all ones",
			rows: map[netip.AddrPort]RelayRow{netip.AddrPortFrom(ones6, 65535): {Next: netip.AddrPortFrom(next6, 65535), Expires: far}},
			src:  netip.AddrPortFrom(ones6, 65535), dst: dst6, ttl: 255,
			want: xdpTX, stats: RelayStats{Packets: 1, Bytes: 100},
		},
		{
			// The row of an IPv4 sender also takes its address in an IPv6 packet.
			name: "IPv6 forward from a mapped IPv4 address",
			rows: map[netip.AddrPort]RelayRow{netip.AddrPortFrom(mapped4, 4000): {Next: netip.AddrPortFrom(next6, nextPort), Expires: far}},
			src:  netip.AddrPortFrom(mapped4, 4000), dst: dst6, ttl: 64,
			want: xdpTX, stats: RelayStats{Packets: 1, Bytes: 100},
		},
		{
			name: "IPv4 forward with no UDP checksum",
			rows: row4, src: src4, dst: dst4, ttl: 64, noCsum: true,
			want: xdpTX, stats: RelayStats{Packets: 1, Bytes: 100},
		},
		{
			name: "IPv6 with no UDP checksum",
			rows: row6, src: src6, dst: dst6, ttl: 64, noCsum: true,
			want: xdpPASS, stats: RelayStats{Malformed: 1},
		},
		{
			name: "frame with Ethernet padding",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			mutate: func(f []byte) []byte { return append(f, make([]byte, 20)...) },
			want:   xdpTX, stats: RelayStats{Packets: 1, Bytes: 100},
		},
		{
			name: "unknown row",
			rows: map[netip.AddrPort]RelayRow{netip.AddrPortFrom(sender4, 4001): {Next: netip.AddrPortFrom(next4, nextPort), Expires: far}},
			src:  src4, dst: dst4, ttl: 64,
			want: xdpPASS, stats: RelayStats{NoRow: 1},
		},
		{
			name: "IPv6 unknown row",
			rows: map[netip.AddrPort]RelayRow{netip.AddrPortFrom(sender6, 4001): {Next: netip.AddrPortFrom(next6, nextPort), Expires: far}},
			src:  src6, dst: dst6, ttl: 64,
			want: xdpPASS, stats: RelayStats{NoRow: 1},
		},
		{
			name: "row of another SPI",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			payload: pspPayload(100, testSPI+1),
			want:    xdpPASS, stats: RelayStats{NoRow: 1},
		},
		{
			name: "destination is not a relay address",
			rows: row4, src: src4, dst: netip.AddrPortFrom(other4, relayPort), ttl: 64,
			want: xdpPASS,
		},
		{
			name: "IPv6 destination is not a relay address",
			rows: row6, src: src6, dst: netip.AddrPortFrom(other6, relayPort), ttl: 64,
			want: xdpPASS,
		},
		{
			name: "datagram above the length bound",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			payload: pspPayload(testMaxLen-28+1, testSPI),
			want:    xdpPASS, stats: RelayStats{TooLong: 1},
		},
		{
			name: "datagram at the length bound",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			payload: pspPayload(testMaxLen-28, testSPI),
			want:    xdpTX, stats: RelayStats{Packets: 1, Bytes: testMaxLen - 28},
		},
		{
			name: "IPv6 datagram above the length bound",
			rows: row6, src: src6, dst: dst6, ttl: 64,
			payload: pspPayload(testMaxLen-48+1, testSPI),
			want:    xdpPASS, stats: RelayStats{TooLong: 1},
		},
		{
			name: "IPv6 QUIC packet",
			rows: row6, src: src6, dst: dst6, ttl: 64,
			payload: append([]byte{0x40}, pspPayload(99, testSPI)[1:]...),
			want:    xdpPASS,
		},
		{
			name: "IPv6 reserved SPI",
			rows: row6, src: src6, dst: dst6, ttl: 64,
			payload: pspPayload(100, 0),
			want:    xdpPASS,
		},
		{
			name: "QUIC packet",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			payload: append([]byte{0x40}, pspPayload(99, testSPI)[1:]...),
			want:    xdpPASS,
		},
		{
			name: "reserved SPI",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			payload: pspPayload(100, 0x80000000),
			want:    xdpPASS,
		},
		{
			name: "short PSP packet",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			payload: pspPayload(39, testSPI),
			want:    xdpPASS,
		},
		{
			name: "PSP packet with the D bit",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			payload: func() []byte {
				p := pspPayload(100, testSPI)
				p[3] |= 0x40
				return p
			}(),
			want: xdpPASS,
		},
		{
			name: "other port",
			rows: row4, src: src4, dst: netip.AddrPortFrom(relay4, relayPort+1), ttl: 64,
			want: xdpPASS,
		},
		{
			name: "IPv4 options",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			mutate: func(f []byte) []byte {
				out := append(append(append([]byte{}, f[:34]...), 1, 1, 1, 0), f[34:]...)
				out[14] = 0x46
				binary.BigEndian.PutUint16(out[16:18], binary.BigEndian.Uint16(f[16:18])+4)
				fixIPv4Sum(out[14:38])
				return out
			},
			want: xdpPASS,
		},
		{
			name: "IPv4 fragment",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			mutate: func(f []byte) []byte {
				f[20] |= 0x20
				fixIPv4Sum(f[14:34])
				return f
			},
			want: xdpPASS,
		},
		{
			name: "truncated frame",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			mutate: func(f []byte) []byte { return f[:len(f)-10] },
			want:   xdpPASS,
		},
		{
			name: "UDP length below the IP length",
			rows: row4, src: src4, dst: dst4, ttl: 64,
			mutate: func(f []byte) []byte {
				binary.BigEndian.PutUint16(f[38:40], 100)
				return f
			},
			want: xdpPASS,
		},
		{
			name: "expired row",
			rows: map[netip.AddrPort]RelayRow{src4: {Next: netip.AddrPortFrom(next4, nextPort), Expires: Monotonic() - time.Second}},
			src:  src4, dst: dst4, ttl: 64,
			want: xdpPASS, stats: RelayStats{Expired: 1},
		},
		{
			name: "IPv6 expired row",
			rows: map[netip.AddrPort]RelayRow{src6: {Next: netip.AddrPortFrom(next6, nextPort), Expires: Monotonic() - time.Second}},
			src:  src6, dst: dst6, ttl: 64,
			want: xdpPASS, stats: RelayStats{Expired: 1},
		},
		{
			name: "IPv6 no neighbor",
			rows: map[netip.AddrPort]RelayRow{src6: {Next: netip.AddrPortFrom(noNeigh6, nextPort), Expires: far}},
			src:  src6, dst: dst6, ttl: 64,
			want: xdpPASS, stats: RelayStats{NoRoute: 1},
		},
		{
			name: "IPv6 next hop of the other family",
			rows: map[netip.AddrPort]RelayRow{src6: {Next: netip.AddrPortFrom(next4, nextPort), Expires: far}},
			src:  src6, dst: dst6, ttl: 64,
			want: xdpPASS, stats: RelayStats{NoRoute: 1},
		},
		{
			name: "next hop on no link",
			rows: map[netip.AddrPort]RelayRow{src4: {Next: netip.AddrPortFrom(other4, nextPort), Expires: far}},
			src:  src4, dst: dst4, ttl: 64,
			want: xdpPASS, stats: RelayStats{NoRoute: 1},
		},
		{
			name:   "no neighbor with a kept next hop",
			cfg:    RelayConfig{NextHopCache: time.Hour},
			rows:   map[netip.AddrPort]RelayRow{src4: {Next: netip.AddrPortFrom(noNeigh, nextPort), Expires: far}},
			frames: 2, src: src4, dst: dst4, ttl: 64,
			want: xdpPASS, stats: RelayStats{NoRoute: 2},
		},
		{
			name: "no neighbor",
			rows: map[netip.AddrPort]RelayRow{src4: {Next: netip.AddrPortFrom(noNeigh, nextPort), Expires: far}},
			src:  src4, dst: dst4, ttl: 64,
			want: xdpPASS, stats: RelayStats{NoRoute: 1},
		},
		{
			name: "next hop of the other family",
			rows: map[netip.AddrPort]RelayRow{src4: {Next: netip.AddrPortFrom(next6, nextPort), Expires: far}},
			src:  src4, dst: dst4, ttl: 64,
			want: xdpPASS, stats: RelayStats{NoRoute: 1},
		},
		{
			name: "forwarding off",
			rows: row4, noFwd: true, src: src4, dst: dst4, ttl: 64,
			want: xdpPASS, stats: RelayStats{NoRoute: 1},
		},
		{
			name: "lane meter drop",
			cfg:  RelayConfig{LaneRate: 1, LaneBurst: 250},
			rows: row4, frames: 3, src: src4, dst: dst4, ttl: 64,
			want: xdpDROP, stats: RelayStats{Packets: 2, Bytes: 200, LaneDrops: 1},
		},
		{
			name:    "tunnel limit drop",
			cfg:     RelayConfig{TunnelRate: 1, TunnelBurst: 150},
			rows:    map[netip.AddrPort]RelayRow{src4: {Next: netip.AddrPortFrom(next4, nextPort), Tunnel: 7, Expires: far}},
			tunnels: []uint32{7},
			frames:  2, src: src4, dst: dst4, ttl: 64,
			want: xdpDROP, stats: RelayStats{Packets: 1, Bytes: 100, TunnelDrops: 1},
		},
		{
			name: "row with no tunnel",
			cfg:  RelayConfig{TunnelRate: 1, TunnelBurst: 150},
			rows: row4, frames: 3, src: src4, dst: dst4, ttl: 64,
			want: xdpTX, stats: RelayStats{Packets: 3, Bytes: 300},
		},
	}
	ns := newTestNS(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRelay(t, tc.cfg)
			for src, row := range tc.rows {
				require.NoError(t, r.PutRow(src, testSPI, row))
			}
			for _, id := range tc.tunnels {
				require.NoError(t, r.PutTunnel(id))
			}
			payload := tc.payload
			if payload == nil {
				payload = pspPayload(100, testSPI)
			}
			frame := packet(t, tc.src, tc.dst, tc.ttl, payload)
			if tc.noCsum {
				off := 34
				if tc.src.Addr().Is6() {
					off = 54
				}
				frame[off+6], frame[off+7] = 0, 0
			}
			if tc.mutate != nil {
				frame = tc.mutate(frame)
			}
			if tc.noFwd {
				setForwarding(t, ns, "0")
				t.Cleanup(func() { setForwarding(t, ns, "1") })
			}
			start := Monotonic()
			var ret uint32
			var out []byte
			for range max(tc.frames, 1) {
				ret, out = ns.run(t, r.Program(), frame)
			}
			assert.Equal(t, tc.want, ret)
			st, err := r.Stats()
			require.NoError(t, err)
			assert.Equal(t, tc.stats, st)
			if ret != xdpTX && ret != xdpREDIRECT {
				if ret == xdpPASS {
					assert.Equal(t, frame, out, "a passed frame does not change")
				}
				return
			}
			row := tc.rows[tc.src]
			end := Monotonic()
			want := packet(t, netip.AddrPortFrom(tc.dst.Addr(), relayPort), row.Next, 64, payload)
			copy(want[0:6], peerMAC)
			copy(want[6:12], relayMAC)
			if tc.noCsum {
				want[34+6], want[34+7] = 0, 0
			}
			if tc.mutate != nil {
				want = tc.mutate(want)
			}
			if tc.src.Addr().Is4() {
				// The IP ID and the IP checksum come from the input frame.
				copy(want[18:20], out[18:20])
				copy(want[24:26], out[24:26])
			}
			assert.Equal(t, want, out)
			checkSums(t, out)
			c, err := r.Counters(tc.src, testSPI)
			require.NoError(t, err)
			assert.Equal(t, tc.stats.Packets, c.Packets)
			assert.Equal(t, tc.stats.Bytes, c.Bytes)
			// The program reads a clock that can be one timer tick behind.
			assert.Greater(t, c.Used, start-timerTick)
			assert.LessOrEqual(t, c.Used, end)
		})
	}
}

func TestRelayRows(t *testing.T) {
	ns := newTestNS(t)
	r := newTestRelay(t, RelayConfig{LaneRate: 1, LaneBurst: 250, TunnelRate: 1, TunnelBurst: 1000})
	src := netip.AddrPortFrom(sender4, 4000)
	frame := packet(t, src, netip.AddrPortFrom(relay4, relayPort), 64, pspPayload(100, testSPI))
	require.NoError(t, r.PutTunnel(3))
	require.NoError(t, r.PutRow(src, testSPI, RelayRow{Next: netip.AddrPortFrom(next4, nextPort), Tunnel: 3, Expires: Monotonic() + time.Hour}))
	for range 3 {
		ns.run(t, r.Program(), frame)
	}
	// A change keeps the meter and the counters.
	require.NoError(t, r.PutRow(src, testSPI, RelayRow{Next: netip.AddrPortFrom(next4, nextPort+1), Tunnel: 3, Expires: Monotonic() + time.Hour}))
	ret, out := ns.run(t, r.Program(), frame)
	assert.Equal(t, xdpDROP, ret)
	assert.NotEqual(t, uint16(nextPort+1), binary.BigEndian.Uint16(out[36:38]))
	c, err := r.Counters(src, testSPI)
	require.NoError(t, err)
	assert.Equal(t, RelayCounters{Packets: 2, Bytes: 200, Drops: 2, Used: c.Used}, c)

	c, err = r.DeleteRow(src, testSPI)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), c.Packets)
	_, err = r.Counters(src, testSPI)
	assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	ret, _ = ns.run(t, r.Program(), frame)
	assert.Equal(t, xdpPASS, ret)
	// A new row starts with a full meter and zero counters.
	require.NoError(t, r.PutRow(src, testSPI, RelayRow{Next: netip.AddrPortFrom(next4, nextPort), Tunnel: 3, Expires: Monotonic() + time.Hour}))
	ret, _ = ns.run(t, r.Program(), frame)
	assert.Equal(t, xdpTX, ret)
	c, err = r.Counters(src, testSPI)
	require.NoError(t, err)
	assert.Equal(t, RelayCounters{Packets: 1, Bytes: 100, Used: c.Used}, c)

	drops, err := r.DeleteTunnel(3)
	require.NoError(t, err)
	assert.Zero(t, drops)
	_, err = r.TunnelDrops(3)
	assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
}

// TestRelayNextHopCache checks when a row uses the next hop that it keeps and
// when it does a new route lookup. Each case sends one packet, takes the
// neighbor of the next hop away and sends a second packet. A lookup then
// finds no neighbor, so the second packet passes.
func TestRelayNextHopCache(t *testing.T) {
	type env struct {
		t        *testing.T
		r        *Relay
		src, dst netip.AddrPort
		row      RelayRow
		frame    []byte
	}
	tos := func(v byte) func(env) []byte {
		return func(e env) []byte {
			e.frame[15] = v
			fixIPv4Sum(e.frame[14:34])
			return e.frame
		}
	}
	cases := []struct {
		name  string
		v6    bool
		cache time.Duration
		mtu   int // MTU of the link, if not 0.
		// change runs after the first packet and returns the second frame.
		change func(env) []byte
		peer   bool // The second packet comes in on the other link.
		want   uint32
	}{
		{name: "no cache", want: xdpPASS},
		{name: "kept next hop", cache: time.Hour, want: xdpTX},
		{name: "IPv6 no cache", v6: true, want: xdpPASS},
		{name: "IPv6 kept next hop", v6: true, cache: time.Hour, want: xdpTX},
		{
			name: "cache time is over", cache: 2 * timerTick, want: xdpPASS,
			change: func(e env) []byte {
				time.Sleep(10 * timerTick)
				return e.frame
			},
		},
		{
			name: "new expiry of the row", cache: time.Hour, want: xdpTX,
			change: func(e env) []byte {
				e.row.Expires += time.Hour
				require.NoError(e.t, e.r.PutRow(e.src, testSPI, e.row))
				return e.frame
			},
		},
		{
			name: "new next hop of the row", cache: time.Hour, want: xdpPASS,
			change: func(e env) []byte {
				e.row.Next = netip.AddrPortFrom(e.row.Next.Addr(), nextPort+1)
				require.NoError(e.t, e.r.PutRow(e.src, testSPI, e.row))
				return e.frame
			},
		},
		{
			name: "new row with the lane of the old row", cache: time.Hour, want: xdpPASS,
			change: func(e env) []byte {
				_, err := e.r.DeleteRow(e.src, testSPI)
				require.NoError(e.t, err)
				require.NoError(e.t, e.r.PutRow(e.src, testSPI, e.row))
				return e.frame
			},
		},
		{
			name: "other relay address", cache: time.Hour, want: xdpPASS,
			change: func(e env) []byte {
				return packet(e.t, e.src, netip.AddrPortFrom(relayB4, relayPort), 64, pspPayload(100, testSPI))
			},
		},
		{name: "other TOS", cache: time.Hour, change: tos(0x20), want: xdpPASS},
		{name: "other ECN bits", cache: time.Hour, change: tos(0x02), want: xdpTX},
		{
			name: "IPv6 other flow label", v6: true, cache: time.Hour, want: xdpPASS,
			change: func(e env) []byte {
				e.frame[17] = 0x01
				return e.frame
			},
		},
		{name: "other link", cache: time.Hour, peer: true, want: xdpPASS},
		{
			name: "packet above the MTU of the route", cache: time.Hour, mtu: 1280, want: xdpPASS,
			change: func(e env) []byte {
				return packet(e.t, e.src, e.dst, 64, pspPayload(1300, testSPI))
			},
		},
		{
			name: "packet below the MTU of the route", cache: time.Hour, mtu: 1280, want: xdpTX,
			change: func(e env) []byte {
				return packet(e.t, e.src, e.dst, 64, pspPayload(60, testSPI))
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns := newTestNS(t)
			r := newTestRelay(t, RelayConfig{NextHopCache: tc.cache})
			require.NoError(t, r.SetAddrs([]netip.Addr{relay4, relay6, relayB4}))
			e := env{
				t: t, r: r,
				src: netip.AddrPortFrom(sender4, 4000), dst: netip.AddrPortFrom(relay4, relayPort),
				row: RelayRow{Next: netip.AddrPortFrom(next4, nextPort), Expires: Monotonic() + time.Hour},
			}
			if tc.v6 {
				e.src, e.dst = netip.AddrPortFrom(sender6, 4000), netip.AddrPortFrom(relay6, relayPort)
				e.row.Next = netip.AddrPortFrom(next6, nextPort)
			}
			if tc.mtu != 0 {
				ns.netlink(t, func(l netlink.Link) error { return netlink.LinkSetMTU(l, tc.mtu) })
			}
			require.NoError(t, r.PutRow(e.src, testSPI, e.row))
			e.frame = packet(t, e.src, e.dst, 64, pspPayload(100, testSPI))
			ret, _ := ns.run(t, r.Program(), e.frame)
			require.Equal(t, xdpTX, ret)

			ns.netlink(t, func(l netlink.Link) error {
				fam := netlink.FAMILY_V4
				if tc.v6 {
					fam = netlink.FAMILY_V6
				}
				return netlink.NeighDel(&netlink.Neigh{LinkIndex: l.Attrs().Index, Family: fam, IP: e.row.Next.Addr().AsSlice()})
			})
			frame := e.frame
			if tc.change != nil {
				frame = tc.change(e)
			}
			ifindex := ns.ifindex
			if tc.peer {
				ifindex = ns.peer
			}
			ret, out := ns.runOn(t, r.Program(), frame, ifindex)
			assert.Equal(t, tc.want, ret)
			st, err := r.Stats()
			require.NoError(t, err)
			if tc.want == xdpPASS {
				assert.Equal(t, RelayStats{Packets: 1, Bytes: 100, NoRoute: 1}, st)
				return
			}
			assert.Equal(t, uint64(2), st.Packets)
			assert.Equal(t, peerMAC, net.HardwareAddr(out[0:6]))
			assert.Equal(t, relayMAC, net.HardwareAddr(out[6:12]))
			checkSums(t, out)
		})
	}
}

// TestRelayMeterLargestBurst runs each meter with the largest burst at a low
// rate, on back-to-back packets. A refill must not overflow the tokens, which
// would empty the bucket.
func TestRelayMeterLargestBurst(t *testing.T) {
	cases := []struct {
		name string
		cfg  RelayConfig
	}{
		{"lane meter", RelayConfig{LaneRate: 2e8, LaneBurst: MaxRelayBurst}},
		{"tunnel limit", RelayConfig{TunnelRate: 2e8, TunnelBurst: MaxRelayBurst}},
	}
	ns := newTestNS(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRelay(t, tc.cfg)
			// The forwarded frame goes to next, so next is a relay address too.
			require.NoError(t, r.SetAddrs([]netip.Addr{relay4, next4}))
			require.NoError(t, r.PutTunnel(1))
			to := netip.AddrPortFrom(next4, relayPort)
			for _, src := range []netip.AddrPort{netip.AddrPortFrom(sender4, 4000), netip.AddrPortFrom(relay4, relayPort), to} {
				require.NoError(t, r.PutRow(src, testSPI, RelayRow{Next: to, Tunnel: 1, Expires: Monotonic() + time.Hour}))
			}
			frame := packet(t, netip.AddrPortFrom(sender4, 4000), netip.AddrPortFrom(relay4, relayPort), 64, pspPayload(100, testSPI))
			opts := &ebpf.RunOptions{
				Data:    frame,
				Repeat:  2000,
				Context: xdpMD{DataEnd: uint32(len(frame)), IngressIfindex: uint32(ns.ifindex)},
			}
			var ret uint32
			var err error
			ns.do(func() { ret, err = r.Program().Run(opts) })
			require.NoError(t, err)
			assert.Equal(t, xdpTX, ret)
			st, err := r.Stats()
			require.NoError(t, err)
			assert.Equal(t, RelayStats{Packets: 2000, Bytes: 200000}, st)
		})
	}
}

// TestRelayMeterManyThreads runs the program on many threads at the same time
// on one meter, with more packets than the meter passes. The bytes that pass
// must not be more than the rate gives in the time of the run, plus the burst
// and the share of each CPU.
func TestRelayMeterManyThreads(t *testing.T) {
	const (
		size    = 1000
		rate    = 100_000_000
		burst   = rate / 10
		threads = 8
		runTime = 500 * time.Millisecond
	)
	cases := []struct {
		name string
		cfg  RelayConfig
		// share is the most bytes that one CPU holds for its next packets.
		share uint64
	}{
		{"lane meter", RelayConfig{LaneRate: rate, LaneBurst: burst}, 0},
		{"tunnel limit", RelayConfig{TunnelRate: rate, TunnelBurst: burst}, burst/4096 + size},
	}
	ns := newTestNS(t)
	var nsfd int
	var err error
	ns.do(func() { nsfd, err = unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0) })
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(nsfd) })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.NextHopCache = time.Hour
			r := newTestRelay(t, tc.cfg)
			// A forward of a frame from next to next gives the same frame, so
			// all runs of all threads have one row.
			require.NoError(t, r.SetAddrs([]netip.Addr{next4}))
			require.NoError(t, r.PutTunnel(1))
			to := netip.AddrPortFrom(next4, relayPort)
			require.NoError(t, r.PutRow(to, testSPI, RelayRow{Next: to, Tunnel: 1, Expires: Monotonic() + time.Hour}))
			frame := packet(t, to, to, 64, pspPayload(size, testSPI))

			start := Monotonic()
			var g errgroup.Group
			for range threads {
				g.Go(func() error {
					// The thread moves to the test netns, so it must exit with the goroutine.
					runtime.LockOSThread()
					if err := unix.Setns(nsfd, unix.CLONE_NEWNET); err != nil {
						return err
					}
					opts := &ebpf.RunOptions{
						Data:    frame,
						Repeat:  50000,
						Context: xdpMD{DataEnd: uint32(len(frame)), IngressIfindex: uint32(ns.ifindex)},
					}
					for Monotonic() < start+runTime {
						if _, err := r.Program().Run(opts); err != nil {
							return err
						}
					}
					return nil
				})
			}
			require.NoError(t, g.Wait())
			elapsed := Monotonic() - start

			st, err := r.Stats()
			require.NoError(t, err)
			limit := rate*uint64(elapsed)/uint64(time.Second) + burst
			assert.LessOrEqual(t, st.Bytes, limit+tc.share*uint64(runtime.NumCPU()))
			// The threads start in a short time, and then they use all tokens.
			assert.GreaterOrEqual(t, st.Bytes, 9*rate*uint64(runTime)/uint64(time.Second)/10)
			assert.Equal(t, st.Packets*size, st.Bytes)
			// The meter counts each drop that the CPUs count.
			c, err := r.Counters(to, testSPI)
			require.NoError(t, err)
			assert.Equal(t, st.LaneDrops, c.Drops)
			drops, err := r.TunnelDrops(1)
			require.NoError(t, err)
			assert.Equal(t, st.TunnelDrops, drops)
			assert.NotZero(t, st.LaneDrops+st.TunnelDrops)
		})
	}
}

// TestRelayChain checks that the Geneve program sends the packets that it
// passes to the relay program.
func TestRelayChain(t *testing.T) {
	needXSK(t)
	ns := newTestNS(t)
	r := newTestRelay(t, RelayConfig{})
	g, err := Geneve(&net.UDPAddr{IP: relay4.AsSlice(), Port: relayPort})
	require.NoError(t, err)
	t.Cleanup(func() { _ = g.Close() })
	src := netip.AddrPortFrom(sender4, 4000)
	require.NoError(t, r.PutRow(src, testSPI, RelayRow{Next: netip.AddrPortFrom(next4, nextPort), Expires: Monotonic() + time.Hour}))
	frame := packet(t, src, netip.AddrPortFrom(relay4, relayPort), 64, pspPayload(100, testSPI))

	ret, _ := ns.run(t, g.Program, frame)
	assert.Equal(t, xdpPASS, ret)
	require.NoError(t, g.Chain(r.Program()))
	ret, _ = ns.run(t, g.Program, frame)
	assert.Equal(t, xdpTX, ret)
	require.NoError(t, g.Chain(nil))
	ret, _ = ns.run(t, g.Program, frame)
	assert.Equal(t, xdpPASS, ret)
}

// genericResult is what the next hops of a TestRelayGeneric case got.
type genericResult struct {
	spisA, spisB []uint32
	stats        RelayStats
	err          error
}

// TestRelayGeneric runs the program in generic mode on a veth and sends to it
// from the peer netns, as a wire does and as a sender with UDP GSO does. The
// kernel gives a GSO message to generic XDP as one datagram.
func TestRelayGeneric(t *testing.T) {
	if ok, _ := permissions.IsNetAdmin(); !ok {
		skipOrFail(t, "needs NET_ADMIN")
	}
	cases := []struct {
		name  string
		cfg   RelayConfig
		gso   bool // Send both packets in one UDP GSO message.
		size  int  // PSP packet size.
		spisA []uint32
		spisB []uint32
		stats RelayStats
	}{
		{name: "single datagrams", size: 100, spisA: []uint32{1}, spisB: []uint32{2}, stats: RelayStats{Packets: 2, Bytes: 200}},
		{name: "single datagrams with a redirect", cfg: RelayConfig{Redirect: true}, size: 100, spisA: []uint32{1}, spisB: []uint32{2}, stats: RelayStats{Packets: 2, Bytes: 200}},
		{name: "single datagrams with a kept next hop", cfg: RelayConfig{NextHopCache: time.Hour}, size: 100, spisA: []uint32{1}, spisB: []uint32{2}, stats: RelayStats{Packets: 2, Bytes: 200}},
		{name: "joined datagram above the length bound", gso: true, size: 800, stats: RelayStats{TooLong: 1}},
		// The program does not see this join, so the packet of SPI 2 goes to
		// the next hop of SPI 1. The loader must check the link.
		{name: "joined datagram below the length bound", gso: true, size: 600, spisA: []uint32{1, 2}, stats: RelayStats{Packets: 1, Bytes: 1200}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runGeneric(t, tc.cfg, tc.gso, tc.size)
			// Root in a container can be without the rights for a netns or BPF.
			if errors.Is(res.err, unix.EPERM) {
				skipOrFail(t, "cannot run the program in a test netns: %v", res.err)
			}
			require.NoError(t, res.err)
			assert.Equal(t, tc.spisA, res.spisA)
			assert.Equal(t, tc.spisB, res.spisB)
			assert.Equal(t, tc.stats, res.stats)
		})
	}
}

// runGeneric makes a relay netns with rl0 (10.9.0.1) and a peer netns with
// rl1, which has the sender 10.9.0.7 and the next hops 10.9.0.2 and 10.9.0.3.
// It sends a PSP packet with SPI 1 and one with SPI 2 to the relay and
// returns what each next hop got.
func runGeneric(t *testing.T, cfg RelayConfig, gso bool, size int) genericResult {
	t.Helper()
	resc := make(chan genericResult, 1)
	go func() {
		// The thread moves between the netns, so it must exit with the goroutine.
		runtime.LockOSThread()
		var res genericResult
		defer func() { resc <- res }()
		res.err = func() error {
			relayNS, peerNS, err := twoNetNS()
			if err != nil {
				return err
			}
			defer unix.Close(relayNS)
			defer unix.Close(peerNS)
			veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "rl0", HardwareAddr: relayMAC}, PeerName: "rl1", PeerHardwareAddr: peerMAC}
			if err := netlink.LinkAdd(veth); err != nil {
				return err
			}
			l0, err := netlink.LinkByName("rl0")
			if err != nil {
				return err
			}
			l1, err := netlink.LinkByName("rl1")
			if err != nil {
				return err
			}
			if err := netlink.LinkSetNsFd(l1, peerNS); err != nil {
				return err
			}
			if err := linkUp(l0, "10.9.0.1/24", map[string]net.HardwareAddr{"10.9.0.2": peerMAC, "10.9.0.3": peerMAC, "10.9.0.7": peerMAC}); err != nil {
				return err
			}
			if err := os.WriteFile("/proc/sys/net/ipv4/conf/rl0/forwarding", []byte("1"), 0o644); err != nil {
				return err
			}
			cfg.Port, cfg.MaxLen = relayPort, uint32(l0.Attrs().MTU)
			r, err := NewRelay(cfg)
			if err != nil {
				return err
			}
			defer r.Close()
			if err := r.SetAddrs([]netip.Addr{relay4}); err != nil {
				return err
			}
			if err := r.Attach(l0.Attrs().Index, link.XDPGenericMode); err != nil {
				return err
			}
			sender := netip.MustParseAddrPort("10.9.0.7:4000")
			for spi, next := range map[uint32]string{1: "10.9.0.2:5000", 2: "10.9.0.3:5000"} {
				if err := r.PutRow(sender, spi, RelayRow{Next: netip.MustParseAddrPort(next), Expires: Monotonic() + time.Hour}); err != nil {
					return err
				}
			}

			if err := unix.Setns(peerNS, unix.CLONE_NEWNET); err != nil {
				return err
			}
			l1, err = netlink.LinkByName("rl1")
			if err != nil {
				return err
			}
			if err := linkUp(l1, "10.9.0.7/24", map[string]net.HardwareAddr{"10.9.0.1": relayMAC}); err != nil {
				return err
			}
			for _, p := range []string{"10.9.0.2/24", "10.9.0.3/24"} {
				a, _ := netlink.ParseAddr(p)
				if err := netlink.AddrAdd(l1, a); err != nil {
					return err
				}
			}
			var conns [3]*net.UDPConn
			for i, a := range []string{"10.9.0.2:5000", "10.9.0.3:5000", "10.9.0.7:4000"} {
				if conns[i], err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(a))); err != nil {
					return err
				}
				defer conns[i].Close()
			}
			dst := &net.UDPAddr{IP: relay4.AsSlice(), Port: relayPort}
			p1, p2 := pspPayload(size, 1), pspPayload(size, 2)
			if gso {
				oob := make([]byte, unix.CmsgSpace(2))
				h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
				h.Level, h.Type = unix.SOL_UDP, unix.UDP_SEGMENT
				h.SetLen(unix.CmsgLen(2))
				binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], uint16(size))
				if _, _, err := conns[2].WriteMsgUDP(append(append([]byte{}, p1...), p2...), oob, dst); err != nil {
					return err
				}
			} else {
				for _, p := range [][]byte{p1, p2} {
					if _, err := conns[2].WriteToUDP(p, dst); err != nil {
						return err
					}
				}
			}
			res.spisA, res.spisB = readSPIs(conns[0]), readSPIs(conns[1])
			res.stats, err = r.Stats()
			return err
		}()
	}()
	return <-resc
}

// twoNetNS puts the thread in a new netns and returns it and a second new
// netns.
func twoNetNS() (relayNS, peerNS int, err error) {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return 0, 0, err
	}
	relayNS, err = unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, err
	}
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return 0, 0, err
	}
	peerNS, err = unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, err
	}
	return relayNS, peerNS, unix.Setns(relayNS, unix.CLONE_NEWNET)
}

// linkUp sets l and lo up, gives l the address a, and adds the neighbors.
func linkUp(l netlink.Link, a string, neighbors map[string]net.HardwareAddr) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return err
	}
	addr, _ := netlink.ParseAddr(a)
	if err := netlink.AddrAdd(l, addr); err != nil {
		return err
	}
	for ip, mac := range neighbors {
		n := &netlink.Neigh{LinkIndex: l.Attrs().Index, Family: netlink.FAMILY_V4, State: netlink.NUD_PERMANENT, IP: net.ParseIP(ip), HardwareAddr: mac}
		if err := netlink.NeighAdd(n); err != nil {
			return err
		}
	}
	return nil
}

// readSPIs returns the SPIs of the PSP packets that c gets in 500 ms.
func readSPIs(c *net.UDPConn) []uint32 {
	var spis []uint32
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(buf)
		if err != nil {
			return spis
		}
		if n >= 8 {
			spis = append(spis, binary.BigEndian.Uint32(buf[4:8]))
		}
	}
}

// BenchmarkRelayForward runs the program on one frame many times. The rows
// send the frame on to the same next hop each time, so each run forwards.
func BenchmarkRelayForward(b *testing.B) {
	configs := []struct {
		name string
		cfg  RelayConfig
	}{
		{"no meter", RelayConfig{}},
		{"tunnel limit", RelayConfig{TunnelRate: 1e12, TunnelBurst: 1e8}},
		{"next hop cache", RelayConfig{NextHopCache: time.Second}},
		{"next hop cache and tunnel limit", RelayConfig{NextHopCache: time.Second, TunnelRate: 1e12, TunnelBurst: 1e8}},
	}
	for _, c := range configs {
		for _, v6 := range []bool{false, true} {
			for _, size := range []int{64, 1400} {
				name := c.name + "/IPv4/" + strconv.Itoa(size)
				sender, relay, next := sender4, relay4, next4
				if v6 {
					name = c.name + "/IPv6/" + strconv.Itoa(size)
					sender, relay, next = sender6, relay6, next6
				}
				b.Run(name, func(b *testing.B) {
					ns := newTestNS(b)
					r := newTestRelay(b, c.cfg)
					// The forwarded frame goes to next, so next is a relay address too.
					require.NoError(b, r.SetAddrs([]netip.Addr{relay, next}))
					require.NoError(b, r.PutTunnel(1))
					to := netip.AddrPortFrom(next, relayPort)
					for _, src := range []netip.AddrPort{netip.AddrPortFrom(sender, 4000), netip.AddrPortFrom(relay, relayPort), to} {
						require.NoError(b, r.PutRow(src, testSPI, RelayRow{Next: to, Tunnel: 1, Expires: Monotonic() + time.Hour}))
					}
					frame := packet(b, netip.AddrPortFrom(sender, 4000), netip.AddrPortFrom(relay, relayPort), 64, pspPayload(size, testSPI))
					opts := &ebpf.RunOptions{
						Data:    frame,
						Repeat:  uint32(b.N),
						Context: xdpMD{DataEnd: uint32(len(frame)), IngressIfindex: uint32(ns.ifindex)},
					}
					var ret uint32
					var err error
					b.ResetTimer()
					ns.do(func() { ret, err = r.Program().Run(opts) })
					b.StopTimer()
					require.NoError(b, err)
					require.Equal(b, xdpTX, ret)
					st, err := r.Stats()
					require.NoError(b, err)
					require.GreaterOrEqual(b, st.Packets, uint64(b.N))
				})
			}
		}
	}
}

// BenchmarkRelayRows runs the program one time for each packet, on the packets
// of one row or of many rows in turn. With many rows the map entries of a
// packet are not in the CPU cache. It reports the program run time that the
// kernel counts, without the time of the test run call.
func BenchmarkRelayRows(b *testing.B) {
	stats, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		b.Skipf("cannot count the program run time: %v", err)
	}
	defer stats.Close()
	for _, rows := range []int{1, 60000} {
		for _, v6 := range []bool{false, true} {
			name := strconv.Itoa(rows) + " rows/IPv4"
			sender, relay, next := sender4, relay4, next4
			if v6 {
				name = strconv.Itoa(rows) + " rows/IPv6"
				sender, relay, next = sender6, relay6, next6
			}
			b.Run(name, func(b *testing.B) {
				ns := newTestNS(b)
				r := newTestRelay(b, RelayConfig{})
				to := netip.AddrPortFrom(next, nextPort)
				frame := packet(b, netip.AddrPortFrom(sender, 4000), netip.AddrPortFrom(relay, relayPort), 64, pspPayload(800, testSPI))
				frames := make([][]byte, rows)
				for i := range frames {
					// The rows differ in the last bytes of the sender address. The
					// program does not check the UDP checksum of the frame.
					f := append([]byte{}, frame...)
					a := sender.As16()
					binary.BigEndian.PutUint16(a[14:], uint16(i))
					src := netip.AddrFrom16(a).Unmap()
					if v6 {
						copy(f[14+8:], a[:])
					} else {
						copy(f[14+12:], a[12:])
						fixIPv4Sum(f[14:34])
					}
					frames[i] = f
					require.NoError(b, r.PutRow(netip.AddrPortFrom(src, 4000), testSPI, RelayRow{Next: to, Expires: Monotonic() + time.Hour}))
				}
				prog := r.Program()
				ctx := xdpMD{DataEnd: uint32(len(frame)), IngressIfindex: uint32(ns.ifindex)}
				var ret uint32
				var err error
				run := func(n int) {
					for i := 0; i < n && err == nil; i++ {
						// A large step, so that the next row is not near the last one.
						ret, err = prog.Run(&ebpf.RunOptions{Data: frames[i*40503%rows], Context: ctx})
					}
				}
				ns.do(func() { run(rows) })
				require.NoError(b, err)
				t0, n0 := runTime(b, prog)
				b.ResetTimer()
				ns.do(func() { run(b.N) })
				b.StopTimer()
				require.NoError(b, err)
				require.Equal(b, xdpTX, ret)
				t1, n1 := runTime(b, prog)
				require.Equal(b, uint64(b.N), n1-n0)
				b.ReportMetric(float64(t1-t0)/float64(b.N), "program-ns/op")
			})
		}
	}
}

// runTime returns the run time and the run count of prog.
func runTime(b *testing.B, prog *ebpf.Program) (time.Duration, uint64) {
	b.Helper()
	info, err := prog.Info()
	require.NoError(b, err)
	t, _ := info.Runtime()
	n, _ := info.RunCount()
	return t, n
}
