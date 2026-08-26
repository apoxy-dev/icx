package icx_test

// Authenticated source learning (APO-740, WireGuard-roaming semantics): the RX
// path adopts the outer underlay source of a packet as the network's remote
// endpoint ONLY after both the AEAD Open and the anti-replay check succeed, so
// an off-path spoofer can never redirect the tunnel. These tests drive real
// sealed frames between two handlers sharing a raw test key (the loopback
// convention of handler_test.go) and, where a "roamed" source is needed,
// rewrite the outer IPv4 source in the sealed frame directly — legitimate,
// because the outer headers are NOT part of the AEAD's AAD (only the Geneve
// header is), which is exactly the property roaming relies on.

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx"
)

const learnVNI = 0x7777

var learnKey = func() [16]byte {
	var k [16]byte
	copy(k[:], []byte("0123456789abcdef"))
	return k
}()

// newLearningReceiver builds a layer3 handler with source learning enabled, a
// wildcard route, keys installed, and NO remote endpoint configured.
func newLearningReceiver(t *testing.T, clk icx.Clock) *icx.Handler {
	t.Helper()
	local := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 6081,
	}
	opts := []icx.HandlerOption{
		icx.WithLocalAddr(local),
		icx.WithLayer3VirtFrames(),
		icx.WithSourceLearning(),
	}
	if clk != nil {
		opts = append(opts, icx.WithClock(clk))
	}
	h, err := icx.NewHandler(opts...)
	require.NoError(t, err)

	wildcard := netip.MustParsePrefix("0.0.0.0/0")
	require.NoError(t, h.AddVirtualNetwork(learnVNI, nil, []icx.Route{{Src: wildcard, Dst: wildcard}}))
	require.NoError(t, h.InstallKeysForTest(learnVNI, 1, learnKey, learnKey, time.Now().Add(time.Hour)))
	return h
}

// newLearningSender builds a layer3 handler at the given underlay source that
// seals frames toward the receiver under the shared test key.
func newLearningSender(t *testing.T, srcIP net.IP, srcPort uint16, key [16]byte) *icx.Handler {
	t.Helper()
	local := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(srcIP.To4()),
		Port: srcPort,
	}
	receiver := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 6081,
	}
	h, err := icx.NewHandler(
		icx.WithLocalAddr(local),
		icx.WithLayer3VirtFrames(),
		icx.WithKeepAliveInterval(time.Millisecond),
	)
	require.NoError(t, err)

	wildcard := netip.MustParsePrefix("0.0.0.0/0")
	require.NoError(t, h.AddVirtualNetwork(learnVNI, receiver, []icx.Route{{Src: wildcard, Dst: wildcard}}))
	require.NoError(t, h.InstallKeysForTest(learnVNI, 1, key, key, time.Now().Add(time.Hour)))
	return h
}

// sealFrame produces one sealed physical frame from the sender.
func sealFrame(t *testing.T, sender *icx.Handler) []byte {
	t.Helper()
	phy := make([]byte, 2000)
	n, loop := sender.VirtToPhy(makeIPv4UDPPacket(), phy)
	require.NotZero(t, n)
	require.False(t, loop)
	return append([]byte(nil), phy[:n]...)
}

// rewriteOuterSrcIPv4 rewrites the outer IPv4 source address (and optionally
// the UDP source port) of a sealed frame in place, simulating the same
// authenticated payload arriving from a different underlay source. The RX path
// decodes with checksum validation skipped, so no checksum fixup is needed.
func rewriteOuterSrcIPv4(frame []byte, srcIP net.IP, srcPort uint16) {
	const ipSrcOff = header.EthernetMinimumSize + 12
	copy(frame[ipSrcOff:ipSrcOff+4], srcIP.To4())
	if srcPort != 0 {
		udpHdr := header.UDP(frame[header.EthernetMinimumSize+header.IPv4MinimumSize:])
		udpHdr.SetSourcePort(srcPort)
	}
}

// deliverFunc abstracts the two RX implementations so every case runs against
// both and they cannot drift.
type deliverFunc func(h *icx.Handler, frame []byte) int

var deliverModes = []struct {
	name    string
	deliver deliverFunc
}{
	{"cross-buffer", func(h *icx.Handler, frame []byte) int {
		out := make([]byte, 2000)
		return h.PhyToVirt(frame, out)
	}},
	{"in-place", func(h *icx.Handler, frame []byte) int {
		buf := append([]byte(nil), frame...)
		_, n := h.PhyToVirtInPlace(buf, 0, len(frame))
		return n
	}},
}

// requireRemote asserts the learned endpoint.
func requireRemote(t *testing.T, h *icx.Handler, ip net.IP, port uint16) {
	t.Helper()
	vnet, ok := h.GetVirtualNetwork(learnVNI)
	require.True(t, ok)
	remote := vnet.RemoteAddr()
	require.NotNil(t, remote)
	require.Equal(t, tcpip.AddrFrom4Slice(ip.To4()), remote.Addr)
	require.Equal(t, port, remote.Port)
}

func TestSourceLearning(t *testing.T) {
	for _, mode := range deliverModes {
		t.Run(mode.name, func(t *testing.T) {
			clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
			rx := newLearningReceiver(t, clk)
			vnet, ok := rx.GetVirtualNetwork(learnVNI)
			require.True(t, ok)
			require.Nil(t, vnet.RemoteAddr())

			// TX before any remote is learned fails closed with its own counter.
			phy := make([]byte, 2000)
			n, loop := rx.VirtToPhy(makeIPv4UDPPacket(), phy)
			require.Zero(t, n)
			require.False(t, loop)
			require.Equal(t, uint64(1), vnet.Stats.TXDropsNoRemote.Load())

			// First authenticated packet populates the endpoint.
			sender := newLearningSender(t, net.IPv4(10, 0, 0, 2), 4321, learnKey)
			n = mode.deliver(rx, sealFrame(t, sender))
			require.NotZero(t, n)
			requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)
			require.Equal(t, uint64(1), vnet.Stats.RXLearnedRemotes.Load())

			// TX now reaches the learned endpoint: outer IPv4 dst + UDP dst port.
			n, loop = rx.VirtToPhy(makeIPv4UDPPacket(), phy)
			require.NotZero(t, n)
			require.False(t, loop)
			const ipDstOff = header.EthernetMinimumSize + 16
			require.Equal(t, net.IPv4(10, 0, 0, 2).To4(), net.IP(phy[ipDstOff:ipDstOff+4]))
			udpHdr := header.UDP(phy[header.EthernetMinimumSize+header.IPv4MinimumSize:])
			require.Equal(t, uint16(4321), udpHdr.DestinationPort())

			// The peer roams (same keys, new source): past the damping interval
			// the endpoint follows it.
			clk.Advance(6 * time.Second)
			roamed := sealFrame(t, sender)
			rewriteOuterSrcIPv4(roamed, net.IPv4(10, 0, 0, 3), 9999)
			n = mode.deliver(rx, roamed)
			require.NotZero(t, n)
			requireRemote(t, rx, net.IPv4(10, 0, 0, 3), 9999)
			require.Equal(t, uint64(2), vnet.Stats.RXLearnedRemotes.Load())
		})
	}
}

func TestSourceLearningDamping(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	rx := newLearningReceiver(t, clk)
	vnet, ok := rx.GetVirtualNetwork(learnVNI)
	require.True(t, ok)
	sender := newLearningSender(t, net.IPv4(10, 0, 0, 2), 4321, learnKey)

	// First learn is immediate.
	require.NotZero(t, rx.PhyToVirt(sealFrame(t, sender), make([]byte, 2000)))
	requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)

	// A change inside the damping interval is suppressed; the packet itself is
	// still delivered.
	flap := sealFrame(t, sender)
	rewriteOuterSrcIPv4(flap, net.IPv4(10, 0, 0, 3), 0)
	require.NotZero(t, rx.PhyToVirt(flap, make([]byte, 2000)))
	requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)
	require.Equal(t, uint64(1), vnet.Stats.RXLearnsDamped.Load())

	// Same-endpoint packets never count as learns or damps.
	require.NotZero(t, rx.PhyToVirt(sealFrame(t, sender), make([]byte, 2000)))
	require.Equal(t, uint64(1), vnet.Stats.RXLearnedRemotes.Load())
	require.Equal(t, uint64(1), vnet.Stats.RXLearnsDamped.Load())

	// Past the interval the change is accepted.
	clk.Advance(6 * time.Second)
	moved := sealFrame(t, sender)
	rewriteOuterSrcIPv4(moved, net.IPv4(10, 0, 0, 3), 0)
	require.NotZero(t, rx.PhyToVirt(moved, make([]byte, 2000)))
	requireRemote(t, rx, net.IPv4(10, 0, 0, 3), 4321)
	require.Equal(t, uint64(2), vnet.Stats.RXLearnedRemotes.Load())
}

func TestSourceLearningRequiresAuthentication(t *testing.T) {
	for _, mode := range deliverModes {
		t.Run(mode.name, func(t *testing.T) {
			rx := newLearningReceiver(t, nil)
			vnet, ok := rx.GetVirtualNetwork(learnVNI)
			require.True(t, ok)

			// A frame sealed under the WRONG key fails Open and must not learn.
			var wrongKey [16]byte
			copy(wrongKey[:], []byte("ffffffffffffffff"))
			imposter := newLearningSender(t, net.IPv4(172, 16, 0, 1), 5555, wrongKey)
			require.Zero(t, mode.deliver(rx, sealFrame(t, imposter)))
			require.Nil(t, vnet.RemoteAddr())
			require.Equal(t, uint64(1), vnet.Stats.RXDecryptErrors.Load())

			// A REPLAYED authentic frame (fails the replay window) must not move
			// an established endpoint, even from a new source.
			sender := newLearningSender(t, net.IPv4(10, 0, 0, 2), 4321, learnKey)
			frame := sealFrame(t, sender)
			require.NotZero(t, mode.deliver(rx, frame))
			requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)

			replayed := append([]byte(nil), frame...)
			rewriteOuterSrcIPv4(replayed, net.IPv4(172, 16, 0, 2), 5555)
			require.Zero(t, mode.deliver(rx, replayed))
			requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)
			require.Equal(t, uint64(1), vnet.Stats.RXReplayDrops.Load())
			require.Equal(t, uint64(1), vnet.Stats.RXLearnedRemotes.Load())
		})
	}
}

// TestSourceLearningFromKeepAlive pins the learn hook's placement BEFORE the
// out-of-band early-return: an authenticated keep-alive (ProtocolType == 0,
// empty payload) yields no virtual frame but must still populate the endpoint —
// that is what lets a silent peer become reachable and keeps NAT roaming fresh.
func TestSourceLearningFromKeepAlive(t *testing.T) {
	for _, mode := range deliverModes {
		t.Run(mode.name, func(t *testing.T) {
			rx := newLearningReceiver(t, nil)
			vnet, ok := rx.GetVirtualNetwork(learnVNI)
			require.True(t, ok)

			sender := newLearningSender(t, net.IPv4(10, 0, 0, 2), 4321, learnKey)
			phy := make([]byte, 2000)
			n := sender.ToPhy(phy)
			require.NotZero(t, n)

			// A keep-alive decodes to nothing but still learns.
			require.Zero(t, mode.deliver(rx, append([]byte(nil), phy[:n]...)))
			requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)
			require.Equal(t, uint64(1), vnet.Stats.RXLearnedRemotes.Load())
		})
	}
}

// TestSourceLearningGraceEpoch verifies a packet authenticated under an
// old-but-in-grace epoch key still updates the endpoint: the learn hook is
// downstream of whichever receive SA authenticated the frame, so a peer that
// roams mid-rekey is not lost.
func TestSourceLearningGraceEpoch(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	rx := newLearningReceiver(t, clk)
	sender := newLearningSender(t, net.IPv4(10, 0, 0, 2), 4321, learnKey)

	// Establish the endpoint under epoch 1.
	require.NotZero(t, rx.PhyToVirt(sealFrame(t, sender), make([]byte, 2000)))
	requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)

	// Seal another epoch-1 frame BEFORE rotating, then rotate the receiver to
	// epoch 2 (epoch 1 enters its grace window).
	graceFrame := sealFrame(t, sender)
	var k2 [16]byte
	copy(k2[:], []byte("bbbbbbbbbbbbbbbb"))
	require.NoError(t, rx.InstallKeysForTest(learnVNI, 2, k2, k2, clk.Now().Add(time.Hour)))

	// The peer roams and its in-flight old-epoch frame arrives from the new
	// source: it authenticates under the graced key and must learn.
	clk.Advance(6 * time.Second)
	rewriteOuterSrcIPv4(graceFrame, net.IPv4(10, 0, 0, 3), 9999)
	require.NotZero(t, rx.PhyToVirt(graceFrame, make([]byte, 2000)))
	requireRemote(t, rx, net.IPv4(10, 0, 0, 3), 9999)
}

// TestSourceLearningKeepAliveSkipsUnlearned verifies ToPhy treats an unlearned
// network as serviced (no frame, no error) instead of leaving it perpetually
// "due" — which would starve every other network's keep-alives, since the
// selection Range stops at the first due network.
func TestSourceLearningKeepAliveSkipsUnlearned(t *testing.T) {
	local := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 6081,
	}
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	h, err := icx.NewHandler(
		icx.WithLocalAddr(local),
		icx.WithLayer3VirtFrames(),
		icx.WithSourceLearning(),
		icx.WithKeepAliveInterval(time.Second),
		icx.WithClock(clk),
	)
	require.NoError(t, err)

	// An unlearned network alongside a learned one.
	unlearnedPrefix := netip.MustParsePrefix("192.168.2.0/24")
	require.NoError(t, h.AddVirtualNetwork(learnVNI, nil, []icx.Route{{Src: unlearnedPrefix, Dst: unlearnedPrefix}}))
	require.NoError(t, h.InstallKeysForTest(learnVNI, 1, learnKey, learnKey, clk.Now().Add(time.Hour)))

	peer := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}
	learnedPrefix := netip.MustParsePrefix("192.168.1.0/24")
	require.NoError(t, h.AddVirtualNetwork(0x8888, peer, []icx.Route{{Src: learnedPrefix, Dst: learnedPrefix}}))
	require.NoError(t, h.InstallKeysForTest(0x8888, 1, learnKey, learnKey, clk.Now().Add(time.Hour)))

	// Within two polls every due network must be serviced: the unlearned one is
	// skipped (marked serviced, no frame) and the learned one emits a keep-alive.
	// If the unlearned network were NOT marked serviced it would win the Range
	// pick on every poll and the learned network would never emit.
	phy := make([]byte, 2000)
	var emitted int
	for range 4 {
		if h.ToPhy(phy) != 0 {
			emitted++
		}
	}
	require.Equal(t, 1, emitted)

	unlearned, ok := h.GetVirtualNetwork(learnVNI)
	require.True(t, ok)
	require.Zero(t, unlearned.Stats.TXErrors.Load())
	require.Zero(t, unlearned.Stats.TXDropsNoRemote.Load())
}

// TestSourceLearningSteadyStateAllocFree pins the RX hot path's allocation
// behavior with learning enabled: after the endpoint is learned, an unchanged
// outer source must decode with ZERO heap allocations per packet. This guards
// the udp.Decode contract (Addr+Port only; no LinkAddr string conversion) and
// maybeLearnRemote's compare-without-store steady state.
func TestSourceLearningSteadyStateAllocFree(t *testing.T) {
	rx := newLearningReceiver(t, nil)
	sender := newLearningSender(t, net.IPv4(10, 0, 0, 2), 4321, learnKey)

	// Learn once, then pre-seal fresh frames (the replay window rejects reuse).
	require.NotZero(t, rx.PhyToVirt(sealFrame(t, sender), make([]byte, 2000)))

	const runs = 200
	frames := make([][]byte, runs+10)
	for i := range frames {
		frames[i] = sealFrame(t, sender)
	}
	out := make([]byte, 2000)
	var i int
	allocs := testing.AllocsPerRun(runs, func() {
		if rx.PhyToVirt(frames[i], out) == 0 {
			t.Fatal("steady-state frame dropped")
		}
		i++
	})
	require.Zero(t, allocs)
}

// TestSourceLearningFamilyGuard verifies a cross-family outer source is never
// adopted: udp.Encode requires the local and remote underlay families to match,
// so learning an IPv6 endpoint on an IPv4-only handler would turn every TX into
// a hard error. The frame itself is still delivered; only the learn is skipped.
func TestSourceLearningFamilyGuard(t *testing.T) {
	rx := newLearningReceiver(t, nil) // IPv4-only local underlay address.
	vnet, ok := rx.GetVirtualNetwork(learnVNI)
	require.True(t, ok)

	// A sender on an IPv6 underlay with the same keys.
	v6local := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom16Slice(net.ParseIP("fd00::2").To16()),
		Port: 4321,
	}
	v6receiver := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom16Slice(net.ParseIP("fd00::1").To16()),
		Port: 6081,
	}
	v6sender, err := icx.NewHandler(icx.WithLocalAddr(v6local), icx.WithLayer3VirtFrames())
	require.NoError(t, err)
	wildcard := netip.MustParsePrefix("0.0.0.0/0")
	require.NoError(t, v6sender.AddVirtualNetwork(learnVNI, v6receiver, []icx.Route{{Src: wildcard, Dst: wildcard}}))
	require.NoError(t, v6sender.InstallKeysForTest(learnVNI, 1, learnKey, learnKey, time.Now().Add(time.Hour)))

	// The authenticated v6-outer frame is delivered but must NOT be learned.
	require.NotZero(t, rx.PhyToVirt(sealFrame(t, v6sender), make([]byte, 2000)))
	require.Nil(t, vnet.RemoteAddr())
	require.Zero(t, vnet.Stats.RXLearnedRemotes.Load())

	// A same-family source is learned, and a subsequent v6 frame does not
	// displace it (family guard, not damping: no RXLearnsDamped bump). Both
	// senders share one key/epoch, so burn the v4 sender's low TX counters,
	// which the v6 sender has already consumed in rx's shared replay window.
	sender := newLearningSender(t, net.IPv4(10, 0, 0, 2), 4321, learnKey)
	_ = sealFrame(t, sender)
	_ = sealFrame(t, sender)
	require.NotZero(t, rx.PhyToVirt(sealFrame(t, sender), make([]byte, 2000)))
	requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)

	require.NotZero(t, rx.PhyToVirt(sealFrame(t, v6sender), make([]byte, 2000)))
	requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)
	require.Equal(t, uint64(1), vnet.Stats.RXLearnedRemotes.Load())
	require.Zero(t, vnet.Stats.RXLearnsDamped.Load())
}

func TestSourceLearningOptionValidation(t *testing.T) {
	local := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 6081,
	}

	// Learning and outer-source validation are semantically opposite.
	_, err := icx.NewHandler(
		icx.WithLocalAddr(local),
		icx.WithLayer3VirtFrames(),
		icx.WithSourceLearning(),
		icx.WithOuterSrcValidation(),
	)
	require.ErrorContains(t, err, "mutually exclusive")

	// A nil remote requires source learning.
	h, err := icx.NewHandler(icx.WithLocalAddr(local), icx.WithLayer3VirtFrames())
	require.NoError(t, err)
	wildcard := netip.MustParsePrefix("0.0.0.0/0")
	err = h.AddVirtualNetwork(learnVNI, nil, []icx.Route{{Src: wildcard, Dst: wildcard}})
	require.ErrorContains(t, err, "source learning")
}

// TestKeepAliveRXStats pins the receive-side keep-alive accounting: an
// authenticated out-of-band frame counts only in RXKeepAlives, never in
// RXPackets or RXBytes, so an idle tunnel reports a zero packet rate. The frame
// must still refresh the last receive time and still teach the RX path where
// the peer is, because those are the two jobs a keep-alive exists to do.
func TestKeepAliveRXStats(t *testing.T) {
	for _, mode := range deliverModes {
		t.Run(mode.name, func(t *testing.T) {
			clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
			rx := newLearningReceiver(t, clk)
			vnet, ok := rx.GetVirtualNetwork(learnVNI)
			require.True(t, ok)

			sender := newLearningSender(t, net.IPv4(10, 0, 0, 2), 4321, learnKey)
			phy := make([]byte, 2000)
			n := sender.ToPhy(phy)
			require.NotZero(t, n)

			clk.Advance(time.Second)
			require.Zero(t, mode.deliver(rx, append([]byte(nil), phy[:n]...)), "a keep-alive yields no virtual frame")

			require.Equal(t, uint64(1), vnet.Stats.RXKeepAlives.Load(), "the keep-alive is counted as a keep-alive")
			require.Zero(t, vnet.Stats.RXPackets.Load(), "a keep-alive is not a packet")
			require.Zero(t, vnet.Stats.RXBytes.Load(), "a keep-alive carries no payload bytes")
			require.Equal(t, clk.Now().UnixNano(), vnet.Stats.LastRXUnixNano.Load(), "the last receive time moves")

			// Source learning still runs on the keep-alive path.
			require.Equal(t, uint64(1), vnet.Stats.RXLearnedRemotes.Load(), "the keep-alive still teaches the endpoint")
			requireRemote(t, rx, net.IPv4(10, 0, 0, 2), 4321)
		})
	}
}
