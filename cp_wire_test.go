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
)

// This file proves the Phase 4 control-plane → data-plane bridge end to end: the
// shared-epoch chosen by control.SharedEpoch lets two independently-keyed handlers
// exchange Geneve traffic, and the naive alternative (each peer using its own Tx SPI
// as the epoch) provably drops every frame. The handler is cross-platform, so this
// runs without the AF_XDP forwarder.

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
		sas, err := rSess.NegotiateSAs(ctx, control.PSPv0)
		negCh <- nres{sas, err}
	}()
	iSAs, err = iSess.NegotiateSAs(ctx, control.PSPv0)
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

func installSAs(t *testing.T, h *icx.Handler, vni uint, epoch uint32, sas *control.DirectionalSAs) {
	t.Helper()
	require.Len(t, sas.Rx.Key, 16)
	require.Len(t, sas.Tx.Key, 16)
	var rx, tx [16]byte
	copy(rx[:], sas.Rx.Key)
	copy(tx[:], sas.Tx.Key)
	// Use the real guarded seam the production installer calls.
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, epoch, rx, tx, time.Now().Add(time.Hour)))
}

func TestControlPlaneSharedEpochGeneveRoundTrip(t *testing.T) {
	iSAs, rSAs := negotiateLoopback(t)

	eI, err := control.SharedEpoch(iSAs)
	require.NoError(t, err)
	eR, err := control.SharedEpoch(rSAs)
	require.NoError(t, err)
	require.Equal(t, eI, eR, "both peers must derive the identical shared epoch")

	const vni = 0x424344
	addrA := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4())
	addrB := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4())
	hI := newPeerHandler(t, vni, addrA, addrB)
	hR := newPeerHandler(t, vni, addrB, addrA)
	installSAs(t, hI, vni, eI, iSAs)
	installSAs(t, hR, vni, eR, rSAs)

	ip := makeIPv4UDPPacket()
	phy := make([]byte, 1500)
	out := make([]byte, 1500)

	// initiator -> responder
	n, loop := hI.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	m := hR.PhyToVirt(phy[:n], out)
	require.NotZero(t, m, "responder must decrypt initiator traffic")
	require.Equal(t, ip, out[:m])

	// responder -> initiator
	n, loop = hR.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	m = hI.PhyToVirt(phy[:n], out)
	require.NotZero(t, m, "initiator must decrypt responder traffic")
	require.Equal(t, ip, out[:m])

	vnR, ok := hR.GetVirtualNetwork(vni)
	require.True(t, ok)
	require.Zero(t, vnR.Stats.RXDropsNoKey.Load())
	require.Zero(t, vnR.Stats.RXDropsSPIMismatch.Load())
	require.Equal(t, uint64(1), vnR.Stats.RXPackets.Load())
}

// TestInstallResetsTxCounterPerEpoch pins the nonce-uniqueness invariant the durable-
// epoch seeding (control/epochstate.go) depends on: each new epoch install starts a
// FRESH transmit counter, so the AES-GCM nonce (epoch‖counter) never repeats even as
// epochs climb monotonically across rekeys/restarts. A refactor that carried the
// counter across installs would reuse a (key, nonce) pair and trip this test.
func TestInstallResetsTxCounterPerEpoch(t *testing.T) {
	const vni = 0x334455
	addrA := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4())
	addrB := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4())
	h := newPeerHandler(t, vni, addrA, addrB)

	var rx, tx [16]byte
	for i := range rx {
		rx[i], tx[i] = byte(i), byte(255-i)
	}
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 100, rx, tx, time.Now().Add(time.Hour)))
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

	// Install a NEW, higher epoch (as a rekey or a seeded post-restart generation
	// would). The counter MUST reset to zero — no carryover.
	var rx2, tx2 [16]byte
	for i := range rx2 {
		rx2[i], tx2[i] = byte(i+1), byte(254-i)
	}
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 200, rx2, tx2, time.Now().Add(time.Hour)))
	c, _ = h.TxCounterForTest(vni)
	require.Zero(t, c, "a new epoch must start a fresh zero counter (no carryover → no nonce reuse)")

	n, loop = h.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	c, _ = h.TxCounterForTest(vni)
	require.Equal(t, uint64(1), c, "first frame under the new epoch counts from 1 again")
}

func TestControlPlaneNaiveTxSPIEpochDropsTraffic(t *testing.T) {
	iSAs, rSAs := negotiateLoopback(t)

	// The naive bridge — each peer installs under its OWN Tx SPI — gives the two
	// peers different epochs (the SPIs are role-partitioned), so the receiver's
	// rxCiphers lookup misses and every frame drops. This is exactly why SharedEpoch
	// is required; assert the failure mode explicitly.
	require.NotEqual(t, iSAs.Tx.SPI, rSAs.Tx.SPI)

	const vni = 0x515253
	addrA := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4())
	addrB := tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4())
	hI := newPeerHandler(t, vni, addrA, addrB)
	hR := newPeerHandler(t, vni, addrB, addrA)
	installSAs(t, hI, vni, iSAs.Tx.SPI, iSAs)
	installSAs(t, hR, vni, rSAs.Tx.SPI, rSAs)

	ip := makeIPv4UDPPacket()
	phy := make([]byte, 1500)
	out := make([]byte, 1500)
	n, loop := hI.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	m := hR.PhyToVirt(phy[:n], out)
	require.Zero(t, m, "naive per-direction Tx.SPI epoch must miss the receiver's rxCiphers and drop")

	vnR, ok := hR.GetVirtualNetwork(vni)
	require.True(t, ok)
	require.Equal(t, uint64(1), vnR.Stats.RXDropsNoKey.Load())
}
