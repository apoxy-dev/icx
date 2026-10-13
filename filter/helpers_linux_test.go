//go:build linux

package filter

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
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
	relayPort = 6081
	testSPI   = 0x01020304
)

var (
	relayMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	peerMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	// relay4 and relay6 are on the test link. next4 and next6 are neighbors
	// on it. The senders are anywhere.
	relay4  = netip.MustParseAddr("10.9.0.1")
	next4   = netip.MustParseAddr("10.9.0.2")
	sender4 = netip.MustParseAddr("192.0.2.7")
	relay6  = netip.MustParseAddr("fd09::1")
	next6   = netip.MustParseAddr("fd09::2")
	sender6 = netip.MustParseAddr("2001:db8::7")
	other4  = netip.MustParseAddr("198.51.100.9")
	other6  = netip.MustParseAddr("2001:db8:1::9")
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
