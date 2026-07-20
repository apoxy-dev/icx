package icx_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/control"
	"github.com/apoxy-dev/icx/psp"
)

// This file proves the control-plane → data-plane bridge end to end under per-direction
// SPIs: each peer installs two simplex SAs (its own receive SPI, the peer's receive SPI),
// and two independently-keyed handlers exchange Geneve traffic in both directions, each
// decrypting under its own receive SPI. The handler is cross-platform, so this runs
// without the AF_XDP forwarder.

// negotiateLoopback brings up an initiator and a responder control session over
// loopback UDP and returns each peer's negotiated directional SAs.
func negotiateLoopback(t *testing.T) (iSAs, rSAs *control.DirectionalSAs) {
	t.Helper()
	idA, err := control.GenerateIdentity()
	require.NoError(t, err)
	idB, err := control.GenerateIdentity()
	require.NoError(t, err)

	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)
	cli, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close(); _ = cli.Close() })

	ln, err := control.Listen(srv, idB, idA.PublicKey())
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type sres struct {
		s   *control.Session
		err error
	}
	accCh := make(chan sres, 1)
	go func() {
		s, err := ln.Accept(ctx)
		accCh <- sres{s, err}
	}()
	iSess, err := control.Dial(ctx, cli, ln.Addr(), idA, idB.PublicKey())
	require.NoError(t, err)
	acc := <-accCh
	require.NoError(t, acc.err)
	rSess := acc.s
	t.Cleanup(func() { _ = iSess.Close(); _ = rSess.Close() })

	type nres struct {
		sas *control.DirectionalSAs
		err error
	}
	negCh := make(chan nres, 1)
	go func() {
		sas, err := rSess.NegotiateSAs(ctx, control.AESGCM128)
		negCh <- nres{sas, err}
	}()
	iSAs, err = iSess.NegotiateSAs(ctx, control.AESGCM128)
	require.NoError(t, err)
	neg := <-negCh
	require.NoError(t, neg.err)
	return iSAs, neg.sas
}

func newPeerHandler(t *testing.T, vni uint, local, remote tcpip.Address) *icx.Handler {
	t.Helper()
	h, err := icx.NewHandler(
		icx.WithLocalAddr(&tcpip.FullAddress{Addr: local, Port: 6081}),
		icx.WithLayer3VirtFrames(),
	)
	require.NoError(t, err)
	prefix := netip.MustParsePrefix("192.168.1.0/24")
	require.NoError(t, h.AddVirtualNetwork(vni, &tcpip.FullAddress{Addr: remote, Port: 6081},
		[]icx.Route{{Src: prefix, Dst: prefix}}))
	return h
}

// installDirectional installs a peer's negotiated directional SAs into its handler via
// the real guarded derivation seam the production installer calls: rxSPI is our own
// receive SPI, txSPI is the peer's receive SPI (what we transmit to). The handler
// derives both AEAD keys itself from the session master.
func installDirectional(t *testing.T, h *icx.Handler, vni uint, sas *control.DirectionalSAs) {
	t.Helper()
	require.Equal(t, control.AESGCM128, sas.Version)
	require.NoError(t, h.UpdateVirtualNetworkSecret(vni, sas.Master, sas.RxSPI, sas.TxSPI, time.Now().Add(time.Hour)))
}

func TestControlPlanePerDirectionGeneveRoundTrip(t *testing.T) {
	iSAs, rSAs := negotiateLoopback(t)

	// Per-direction SPIs: each peer's transmit SPI is the other's receive SPI, and the
	// two directions are distinct (role-partitioned), so each direction owns its own
	// nonce space — there is no shared epoch. Both peers hold the same session master.
	require.NotEqual(t, iSAs.RxSPI, iSAs.TxSPI, "the two directions must use distinct SPIs")
	require.Equal(t, iSAs.TxSPI, rSAs.RxSPI, "initiator tx SPI must equal responder rx SPI")
	require.Equal(t, iSAs.RxSPI, rSAs.TxSPI, "initiator rx SPI must equal responder tx SPI")
	require.Equal(t, iSAs.Master, rSAs.Master, "both peers derive from the same session master")

	const vni = 0x424344
	addrA := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4())
	addrB := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4())
	hI := newPeerHandler(t, vni, addrA, addrB)
	hR := newPeerHandler(t, vni, addrB, addrA)
	installDirectional(t, hI, vni, iSAs)
	installDirectional(t, hR, vni, rSAs)

	ip := makeIPv4UDPPacket()
	phy := make([]byte, 1500)
	out := make([]byte, 1500)

	// initiator -> responder: hR decrypts under its own receive SPI (== hI's tx SPI).
	n, loop := hI.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	m := hR.PhyToVirt(phy[:n], out)
	require.NotZero(t, m, "responder must decrypt initiator traffic")
	require.Equal(t, ip, out[:m])

	// responder -> initiator: hI decrypts under its own receive SPI (== hR's tx SPI).
	n, loop = hR.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	m = hI.PhyToVirt(phy[:n], out)
	require.NotZero(t, m, "initiator must decrypt responder traffic")
	require.Equal(t, ip, out[:m])

	// No key-miss or SPI-mismatch drops on either side: each direction's frame is bound
	// to its own receive SPI and decrypts cleanly.
	vnR, ok := hR.GetVirtualNetwork(vni)
	require.True(t, ok)
	require.Zero(t, vnR.Stats.RXDropsNoKey.Load())
	require.Zero(t, vnR.Stats.RXDropsSPIMismatch.Load())
	require.Equal(t, uint64(1), vnR.Stats.RXPackets.Load())
	vnI, ok := hI.GetVirtualNetwork(vni)
	require.True(t, ok)
	require.Zero(t, vnI.Stats.RXDropsNoKey.Load())
	require.Zero(t, vnI.Stats.RXDropsSPIMismatch.Load())
	require.Equal(t, uint64(1), vnI.Stats.RXPackets.Load())
}

// TestInstallResetsTxCounterPerEpoch pins the nonce-uniqueness invariant the control
// plane relies on: each new epoch install starts a FRESH transmit counter. Because every
// session derives a fresh master key (fresh ECDHE per reconnect), pairing a from-zero
// counter with each generation's key keeps the AES-GCM nonce (epoch‖counter) unique even
// when an SPI is reused or regresses after a restart. A refactor that carried the counter
// across installs would reuse a (key, nonce) pair and trip this test.
func TestInstallResetsTxCounterPerEpoch(t *testing.T) {
	const vni = 0x334455
	addrA := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4())
	addrB := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4())
	h := newPeerHandler(t, vni, addrA, addrB)

	var master [32]byte
	for i := range master {
		master[i] = byte(i)
	}
	rxSPI, txSPI, err := psp.EpochSPIs(psp.Initiator, 100)
	require.NoError(t, err)
	require.NoError(t, h.UpdateVirtualNetworkSecret(vni, master, rxSPI, txSPI, time.Now().Add(time.Hour)))
	c, ok := h.TxCounterForTest(vni)
	require.True(t, ok)
	require.Zero(t, c, "fresh install starts at counter 0")

	ip := makeIPv4UDPPacket()
	phy := make([]byte, 1500)
	n, loop := h.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	c, _ = h.TxCounterForTest(vni)
	require.Equal(t, uint64(1), c, "first frame uses counter 1")

	// Install a NEW, higher epoch under the SAME master (an in-connection rekey).
	// The advanced SPI is a fresh KDF context — a fresh key — and the counter MUST
	// reset to zero with no carryover.
	rxSPI2, txSPI2, err := psp.EpochSPIs(psp.Initiator, 200)
	require.NoError(t, err)
	require.NoError(t, h.UpdateVirtualNetworkSecret(vni, master, rxSPI2, txSPI2, time.Now().Add(time.Hour)))
	c, _ = h.TxCounterForTest(vni)
	require.Zero(t, c, "a new epoch must start a fresh zero counter (no carryover → no nonce reuse)")

	n, loop = h.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	c, _ = h.TxCounterForTest(vni)
	require.Equal(t, uint64(1), c, "first frame under the new epoch counts from 1 again")
}

// TestSameRoleMismatchDropsTraffic shows WHY the SPI role partition matters: a
// shared-epoch collapse onto one SPI for both directions is now structurally rejected
// (rxSPI == txSPI fails the install guard), and the remaining misuse — both peers
// deriving with the SAME role instead of mirrored ones — makes the sender transmit
// under an SPI the receiver never installed, so every frame misses the receiver's
// rxCiphers. The production paths avoid this by negotiating per-direction SPIs
// (TestControlPlanePerDirectionGeneveRoundTrip) or mirroring roles via psp.EpochSPIs.
func TestSameRoleMismatchDropsTraffic(t *testing.T) {
	iSAs, rSAs := negotiateLoopback(t)
	require.NotEqual(t, iSAs.RxSPI, rSAs.RxSPI, "the two receive SPIs are role-partitioned and distinct")

	const vni = 0x515253
	addrA := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4())
	addrB := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4())
	hI := newPeerHandler(t, vni, addrA, addrB)
	hR := newPeerHandler(t, vni, addrB, addrA)

	// The single-SPI collapse cannot even be installed: equal SPIs would derive equal
	// keys for both directions, so the guard rejects the shape outright.
	require.Error(t, hI.UpdateVirtualNetworkSecret(vni, iSAs.Master, iSAs.RxSPI, iSAs.RxSPI, time.Now().Add(time.Hour)),
		"rxSPI == txSPI must be rejected")

	// Both peers derive with the same role (a misconfigured symmetric bridge): each
	// installs its RX under the Initiator-role SPI while transmitting to the
	// Responder-role SPI, which neither ever installed for receive.
	rxI, txI, err := psp.EpochSPIs(psp.Initiator, 7)
	require.NoError(t, err)
	require.NoError(t, hI.UpdateVirtualNetworkSecret(vni, iSAs.Master, rxI, txI, time.Now().Add(time.Hour)))
	require.NoError(t, hR.UpdateVirtualNetworkSecret(vni, rSAs.Master, rxI, txI, time.Now().Add(time.Hour)))

	ip := makeIPv4UDPPacket()
	phy := make([]byte, 1500)
	out := make([]byte, 1500)
	n, loop := hI.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	m := hR.PhyToVirt(phy[:n], out)
	require.Zero(t, m, "same-role derivation transmits under an SPI the receiver never installed and drops")

	vnR, ok := hR.GetVirtualNetwork(vni)
	require.True(t, ok)
	require.Equal(t, uint64(1), vnR.Stats.RXDropsNoKey.Load())
}
