package icx_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx"
)

// These tests are the regression for the RX-hardening family:
//   APO-649 (S6)  RX never validated the inner DESTINATION address, so cryptokey
//                 routing was source-only — a peer could inject to any local dst.
//   APO-650 (S7)  RX never compared the outer underlay source to the configured
//                 peer (opt-in WithOuterSrcValidation).
//   APO-655 (S12) RX had no rate limit, so an off-path flood of forgeable frames
//                 burned unbounded AES-GCM CPU (opt-in WithRXRateLimit).
//
// Each drives a sender handler that mints genuinely-encrypted Geneve frames and a
// receiver handler (the unit under test) that decapsulates them, asserting the
// admit/drop decision and the corresponding drop counter.

const rxHardenVNI = 0x424344

func sharedKey() [16]byte {
	var k [16]byte
	copy(k[:], "0123456789abcdef")
	return k
}

// senderHandler mints L3 frames sourced from underlay `local`, addressed to peer
// `remote`, under a single shared epoch-1 key (so the receiver's RX cipher, keyed
// with the same bytes, opens them).
func senderHandler(t *testing.T, local, remote tcpip.Address, routes []icx.Route) *icx.Handler {
	t.Helper()
	h, err := icx.NewHandler(
		icx.WithLocalAddr(&tcpip.FullAddress{Addr: local, Port: 6081}),
		icx.WithLayer3VirtFrames(),
	)
	require.NoError(t, err)
	require.NoError(t, h.AddVirtualNetwork(rxHardenVNI, &tcpip.FullAddress{Addr: remote, Port: 6081}, routes))
	require.NoError(t, h.InstallKeysForTest(rxHardenVNI, 1, sharedKey(), sharedKey(), time.Now().Add(time.Hour)))
	return h
}

// receiverHandler decapsulates frames from peer `remote`, applying any extra
// options under test. Its RX cipher shares the sender's key.
func receiverHandler(t *testing.T, local, remote tcpip.Address, routes []icx.Route, extra ...icx.HandlerOption) *icx.Handler {
	t.Helper()
	opts := append([]icx.HandlerOption{
		icx.WithLocalAddr(&tcpip.FullAddress{Addr: local, Port: 6081}),
		icx.WithLayer3VirtFrames(),
	}, extra...)
	h, err := icx.NewHandler(opts...)
	require.NoError(t, err)
	require.NoError(t, h.AddVirtualNetwork(rxHardenVNI, &tcpip.FullAddress{Addr: remote, Port: 6081}, routes))
	require.NoError(t, h.InstallKeysForTest(rxHardenVNI, 1, sharedKey(), sharedKey(), time.Now().Add(time.Hour)))
	return h
}

// innerIPv4 builds a raw IPv4+UDP packet (L3 virtual frame) src->dst.
func innerIPv4(src, dst netip.Addr) []byte {
	frame := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
	ip := header.IPv4(frame)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(frame)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(src.AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(dst.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(frame[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: 1234, DstPort: 5678, Length: header.UDPMinimumSize})
	return frame
}

func addr(s string) tcpip.Address { return tcpip.AddrFromSlice(netip.MustParseAddr(s).AsSlice()) }

func wildcardRoutes() []icx.Route {
	return []icx.Route{{Src: netip.MustParsePrefix("0.0.0.0/0"), Dst: netip.MustParsePrefix("0.0.0.0/0")}}
}

// mint encaps one inner packet on the sender and returns the physical frame.
func mint(t *testing.T, sender *icx.Handler, inner []byte) []byte {
	t.Helper()
	phy := make([]byte, 2048)
	n, loop := sender.VirtToPhy(inner, phy)
	require.NotZero(t, n, "sender must route+encap the inner packet")
	require.False(t, loop)
	return phy[:n]
}

// APO-649 (S6): a frame whose inner SOURCE is allowed but whose inner DESTINATION
// falls outside every route.Src prefix is dropped (RXInvalidDst) — the
// destination-side cryptokey-routing check RX previously skipped.
func TestRXRejectsInnerDestinationOutsideRoutes(t *testing.T) {
	local, remote := addr("10.0.0.1"), addr("10.0.0.2")
	// Sender routes anything so it will mint our chosen src/dst.
	sender := senderHandler(t, remote, local, wildcardRoutes())
	// Receiver permits any inner source (Dst=/0) but confines delivery to
	// 10.0.1.0/24 (Src). Inner dst 9.9.9.9 is outside it.
	narrow := []icx.Route{{Src: netip.MustParsePrefix("10.0.1.0/24"), Dst: netip.MustParsePrefix("0.0.0.0/0")}}
	receiver := receiverHandler(t, local, remote, narrow)

	phy := mint(t, sender, innerIPv4(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")))

	out := make([]byte, 2048)
	require.Zero(t, receiver.PhyToVirt(phy, out), "inner dst outside route.Src must be dropped")

	vnet, ok := receiver.GetVirtualNetwork(rxHardenVNI)
	require.True(t, ok)
	require.Equal(t, uint64(1), vnet.Stats.RXInvalidDst.Load(), "drop is attributed to the destination check")
	require.Zero(t, vnet.Stats.RXInvalidSrc.Load(), "source check passed")
	require.Zero(t, vnet.Stats.RXPackets.Load())

	// Teeth: the SAME frame is accepted by a receiver whose routes permit the dst.
	wide := receiverHandler(t, local, remote, wildcardRoutes())
	require.NotZero(t, wide.PhyToVirt(phy, out), "wildcard receiver accepts the identical frame")
}

// APO-649 (S6): the pre-existing inner-SOURCE check still rejects a frame whose
// inner source is outside every route.Dst prefix (RXInvalidSrc) — the fix adds
// the dst check without weakening the src one.
func TestRXRejectsInnerSourceOutsideRoutes(t *testing.T) {
	local, remote := addr("10.0.0.1"), addr("10.0.0.2")
	sender := senderHandler(t, remote, local, wildcardRoutes())
	// Permit only sources/dsts in 10.0.1.0/24.
	narrow := []icx.Route{{Src: netip.MustParsePrefix("10.0.1.0/24"), Dst: netip.MustParsePrefix("10.0.1.0/24")}}
	receiver := receiverHandler(t, local, remote, narrow)

	// Inner src 8.8.8.8 is outside route.Dst; dst 10.0.1.9 is inside route.Src.
	phy := mint(t, sender, innerIPv4(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.1.9")))

	out := make([]byte, 2048)
	require.Zero(t, receiver.PhyToVirt(phy, out))

	vnet, ok := receiver.GetVirtualNetwork(rxHardenVNI)
	require.True(t, ok)
	require.Equal(t, uint64(1), vnet.Stats.RXInvalidSrc.Load())
	require.Zero(t, vnet.Stats.RXInvalidDst.Load(), "source check fails first; dst not reached")
}

// APO-650 (S7): with WithOuterSrcValidation, a frame whose outer underlay source
// IP is not the configured peer is dropped before decryption (RXDropsBadPeer);
// without the option the same frame is accepted (the check is opt-in).
func TestRXOuterSourceValidation(t *testing.T) {
	const peer = "10.0.0.2"
	local := addr("10.0.0.1")
	sender := senderHandler(t, addr(peer), local, wildcardRoutes())
	inner := innerIPv4(netip.MustParseAddr("10.0.1.5"), netip.MustParseAddr("10.0.1.6"))
	routes := []icx.Route{{Src: netip.MustParsePrefix("10.0.1.0/24"), Dst: netip.MustParsePrefix("10.0.1.0/24")}}
	out := make([]byte, 2048)

	t.Run("accept matching peer", func(t *testing.T) {
		receiver := receiverHandler(t, local, addr(peer), routes, icx.WithOuterSrcValidation())
		require.NotZero(t, receiver.PhyToVirt(mint(t, sender, inner), out))
		vnet, _ := receiver.GetVirtualNetwork(rxHardenVNI)
		require.Zero(t, vnet.Stats.RXDropsBadPeer.Load())
	})

	t.Run("reject wrong peer", func(t *testing.T) {
		// Receiver expects its peer at 10.0.0.99, but the frame is sourced from 10.0.0.2.
		receiver := receiverHandler(t, local, addr("10.0.0.99"), routes, icx.WithOuterSrcValidation())
		require.Zero(t, receiver.PhyToVirt(mint(t, sender, inner), out), "outer source != peer must drop")
		vnet, _ := receiver.GetVirtualNetwork(rxHardenVNI)
		require.Equal(t, uint64(1), vnet.Stats.RXDropsBadPeer.Load())
		require.Zero(t, vnet.Stats.RXPackets.Load())
	})

	t.Run("opt-in: wrong peer accepted without the option", func(t *testing.T) {
		receiver := receiverHandler(t, local, addr("10.0.0.99"), routes) // no option
		require.NotZero(t, receiver.PhyToVirt(mint(t, sender, inner), out), "without the option the source is not checked")
		vnet, _ := receiver.GetVirtualNetwork(rxHardenVNI)
		require.Zero(t, vnet.Stats.RXDropsBadPeer.Load())
	})
}

// APO-655 (S12): WithRXRateLimit caps the frames per window admitted to Open. At a
// frozen clock, only `limit` frames pass and the rest are dropped
// (RXRateLimitDrops); advancing past the window admits a fresh batch.
func TestRXRateLimit(t *testing.T) {
	local, remote := addr("10.0.0.1"), addr("10.0.0.2")
	sender := senderHandler(t, remote, local, wildcardRoutes())

	// 50 pps over 10 sub-windows => 5 admitted per 100ms window.
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	receiver := receiverHandler(t, local, remote, wildcardRoutes(),
		icx.WithRXRateLimit(50), icx.WithClock(clk))

	inner := innerIPv4(netip.MustParseAddr("10.0.1.5"), netip.MustParseAddr("10.0.1.6"))
	out := make([]byte, 2048)

	// Pre-mint distinct frames (each VirtToPhy advances the TX counter, so every
	// frame carries a unique nonce and clears the replay filter).
	const burst = 20
	frames := make([][]byte, burst)
	for i := range frames {
		frames[i] = mint(t, sender, inner)
	}

	var accepted int
	for _, phy := range frames {
		if receiver.PhyToVirt(phy, out) > 0 {
			accepted++
		}
	}
	require.Equal(t, 5, accepted, "only the per-window budget is admitted")

	vnet, ok := receiver.GetVirtualNetwork(rxHardenVNI)
	require.True(t, ok)
	require.Equal(t, uint64(5), vnet.Stats.RXPackets.Load())
	require.Equal(t, uint64(burst-5), vnet.Stats.RXRateLimitDrops.Load(), "the rest are shed before Open")

	// Advance past the window: a fresh batch is admitted.
	clk.Advance(100 * time.Millisecond)
	accepted = 0
	for i := 0; i < 5; i++ {
		if receiver.PhyToVirt(mint(t, sender, inner), out) > 0 {
			accepted++
		}
	}
	require.Equal(t, 5, accepted, "a new window refills the budget")
}
