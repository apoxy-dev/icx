package control

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCanonicalInitiator(t *testing.T) {
	a, err := GenerateIdentity()
	require.NoError(t, err)
	b, err := GenerateIdentity()
	require.NoError(t, err)

	aInit, err := CanonicalInitiator(a.PublicKey(), b.PublicKey())
	require.NoError(t, err)
	bInit, err := CanonicalInitiator(b.PublicKey(), a.PublicKey())
	require.NoError(t, err)
	// Exactly one side is the initiator, and both compute it consistently.
	require.NotEqual(t, aInit, bInit)

	// Pin the rule, not just its antisymmetry: the node whose SPKI DER sorts lower is
	// the initiator. (A flipped comparison would still pass the NotEqual check above.)
	aDER, err := x509.MarshalPKIXPublicKey(a.PublicKey())
	require.NoError(t, err)
	bDER, err := x509.MarshalPKIXPublicKey(b.PublicKey())
	require.NoError(t, err)
	require.Equal(t, bytes.Compare(aDER, bDER) < 0, aInit, "the lower SPKI must be the initiator")

	_, err = CanonicalInitiator(a.PublicKey(), a.PublicKey())
	require.Error(t, err, "identical keys must be rejected")
	_, err = CanonicalInitiator(nil, b.PublicKey())
	require.Error(t, err)
}

// validV0SAs returns a role-partitioned, PSPv0 DirectionalSAs with distinct
// 16-byte keys, as NegotiateSAs would produce.
func validV0SAs() *DirectionalSAs {
	iSPI, _ := MakeSPI(0, Initiator, 1)
	rSPI, _ := MakeSPI(0, Responder, 1)
	rx := make([]byte, 16)
	tx := make([]byte, 16)
	for i := range rx {
		rx[i] = byte(i)
		tx[i] = byte(i + 100)
	}
	return &DirectionalSAs{
		Tx: &SA{SPI: rSPI, Key: tx, Version: PSPv0},
		Rx: &SA{SPI: iSPI, Key: rx, Version: PSPv0},
	}
}

func TestInstallSAsRejectsNonV0(t *testing.T) {
	tn := &Tunnel{install: func(uint32, uint32, [16]byte, [16]byte) error {
		t.Fatal("installer must not be called for a non-PSPv0 SA")
		return nil
	}}
	sas := validV0SAs()
	sas.Tx.Version = PSPv1
	sas.Tx.Key = make([]byte, 32)
	require.Error(t, tn.installSAs(sas))
}

func TestInstallSAsSwallowsRotationRejection(t *testing.T) {
	called := false
	tn := &Tunnel{install: func(uint32, uint32, [16]byte, [16]byte) error {
		called = true
		// Mimic the handler's monotonicity guard rejecting a regressed per-direction SPI.
		return errors.New("rx SPI must be monotonically increasing")
	}}
	// A rejected rotation is logged and swallowed (the data plane keeps its current
	// keys and fails closed on their own expiry); it must not look like a transport
	// error to the run loop.
	require.NoError(t, tn.installSAs(validV0SAs()))
	require.True(t, called)
}

// twoTunnels wires an initiator and a responder Tunnel over loopback UDP, assigning
// the canonical roles correctly, with tight timings for tests.
// twoTunnels wires an initiator and a responder Tunnel over loopback UDP with the
// canonical roles assigned and tight test timings.
func twoTunnels(t *testing.T, instInit, instResp SAInstaller, rekey time.Duration) (initT, respT *Tunnel, cleanup func()) {
	t.Helper()
	idA, err := GenerateIdentity()
	require.NoError(t, err)
	idB, err := GenerateIdentity()
	require.NoError(t, err)

	aInit, err := CanonicalInitiator(idA.PublicKey(), idB.PublicKey())
	require.NoError(t, err)
	initID, respID := idA, idB
	if !aInit {
		initID, respID = idB, idA
	}

	respConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)
	initConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)

	initT, err = NewTunnel(TunnelConfig{
		Local: initID, PeerPub: respID.PublicKey(), Conn: initConn,
		PeerAddr: respConn.LocalAddr(), RekeyInterval: rekey,
	}, instInit)
	require.NoError(t, err)
	require.True(t, initT.Initiator())

	respT, err = NewTunnel(TunnelConfig{
		Local: respID, PeerPub: initID.PublicKey(), Conn: respConn,
		PeerAddr: initConn.LocalAddr(), RekeyInterval: rekey,
	}, instResp)
	require.NoError(t, err)
	require.False(t, respT.Initiator())

	for _, tn := range []*Tunnel{initT, respT} {
		tn.perExchangeTimeout = 2 * time.Second
		tn.reconnectBackoff = 50 * time.Millisecond
	}

	cleanup = func() {
		_ = initT.Close()
		_ = respT.Close()
		_ = initConn.Close()
		_ = respConn.Close()
	}
	return initT, respT, cleanup
}

// guardInstaller is an SAInstaller that mirrors the handler's relaxed TX anti-reset
// guard (handler.go: UpdateVirtualNetworkSAs) — it rejects only a re-install of the
// currently-live transmit SA, i.e. the same transmit SPI AND the same key — so tests can
// detect a spurious rejection rather than the no-op epochRecorder which accepts everything.
// The key comparison matters: across a reconnect the allocator resets and the transmit SPI
// can collide with the still-live one, but under a fresh key, which is safe and must be
// accepted. Because every control-plane generation carries a fresh key, the guard should
// never reject in normal operation, even across a reconnect that resets SPIs to a low value.
type guardInstaller struct {
	mu        sync.Mutex
	curTx     uint32   // currently-live transmit SPI (0 = none)
	curTxKey  [16]byte // currently-live transmit key
	installed []uint32 // accepted receive SPIs, in order
	rejects   int
}

func newGuardInstaller() *guardInstaller { return &guardInstaller{} }

func (g *guardInstaller) install(rxSPI, txSPI uint32, _, txKey [16]byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.curTx != 0 && txSPI == g.curTx && txKey == g.curTxKey {
		g.rejects++
		return errors.New("tx SA is already live")
	}
	g.curTx = txSPI
	g.curTxKey = txKey
	g.installed = append(g.installed, rxSPI)
	return nil
}

func (g *guardInstaller) snapshot() (installed []uint32, rejects int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]uint32(nil), g.installed...), g.rejects
}

// installRec captures one per-direction SA generation for assertions: the receive SPI
// (this peer's own data-plane epoch) and transmit SPI (the peer's receive SPI), plus
// both keys.
type installRec struct {
	rxSPI, txSPI uint32
	rxKey, txKey [16]byte
}

// epochRecorder is a thread-safe SAInstaller that records the per-direction generations
// it installs.
type epochRecorder struct {
	mu   sync.Mutex
	recs []installRec
}

func newEpochRecorder() *epochRecorder { return &epochRecorder{} }

func (r *epochRecorder) install(rxSPI, txSPI uint32, rxKey, txKey [16]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recs = append(r.recs, installRec{rxSPI: rxSPI, txSPI: txSPI, rxKey: rxKey, txKey: txKey})
	return nil
}

func (r *epochRecorder) snapshot() []installRec {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]installRec(nil), r.recs...)
}

func TestTunnelBringupAndRekey(t *testing.T) {
	initRec, respRec := newEpochRecorder(), newEpochRecorder()
	initT, respT, cleanup := twoTunnels(t, initRec.install, respRec.install, 100*time.Millisecond)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Bring both peers up; the responder must be accepting before the initiator dials.
	brCh := make(chan error, 1)
	go func() { brCh <- respT.Bringup(ctx) }()
	require.NoError(t, initT.Bringup(ctx))
	require.NoError(t, <-brCh)

	// Both installed exactly one (matching) generation in bring-up.
	ir := initRec.snapshot()
	rr := respRec.snapshot()
	require.Len(t, ir, 1)
	require.Len(t, rr, 1)
	// Per-direction SPIs: each peer installs its OWN receive SPI; they are distinct
	// (role-partitioned), and each peer's transmit SPI is the other peer's receive SPI.
	require.NotZero(t, ir[0].rxSPI)
	require.NotEqual(t, ir[0].rxSPI, rr[0].rxSPI, "peers must allocate distinct receive SPIs")
	require.Equal(t, ir[0].rxSPI, rr[0].txSPI, "initiator rx SPI must equal responder tx SPI")
	require.Equal(t, ir[0].txSPI, rr[0].rxSPI, "initiator tx SPI must equal responder rx SPI")
	// Cross-derivation: initiator TX key == responder RX key and vice versa.
	require.Equal(t, ir[0].txKey, rr[0].rxKey, "initiator tx key != responder rx key")
	require.Equal(t, ir[0].rxKey, rr[0].txKey, "initiator rx key != responder tx key")
	// Within a peer, the two directions use distinct keys.
	require.NotEqual(t, ir[0].rxKey, ir[0].txKey)

	// Run both peers and let the initiator drive a few rekeys.
	runCh := make(chan error, 2)
	go func() { runCh <- initT.Run(ctx) }()
	go func() { runCh <- respT.Run(ctx) }()

	require.Eventually(t, func() bool {
		return len(initRec.snapshot()) >= 3
	}, 10*time.Second, 20*time.Millisecond, "initiator should rekey several times")

	cancel()
	require.NoError(t, <-runCh)
	require.NoError(t, <-runCh)

	// Receive SPIs strictly increase per peer, and the two peers agree generation-by-
	// generation (the initiator's receive SPI for gen i is the responder's transmit SPI).
	ir = initRec.snapshot()
	rr = respRec.snapshot()
	for i := 1; i < len(ir); i++ {
		require.Greater(t, ir[i].rxSPI, ir[i-1].rxSPI, "initiator receive SPIs must strictly increase")
	}
	n := len(ir)
	if len(rr) < n {
		n = len(rr)
	}
	require.GreaterOrEqual(t, n, 2)
	for i := 0; i < n; i++ {
		require.Equal(t, ir[i].rxSPI, rr[i].txSPI, "peers disagree on SPI for generation %d", i)
	}
}

func TestTunnelBringupFailsClosedOnPinMismatch(t *testing.T) {
	idA, err := GenerateIdentity()
	require.NoError(t, err)
	idB, err := GenerateIdentity()
	require.NoError(t, err)
	imposter, err := GenerateIdentity()
	require.NoError(t, err)

	aInit, err := CanonicalInitiator(idA.PublicKey(), idB.PublicKey())
	require.NoError(t, err)
	initID, respID := idA, idB
	if !aInit {
		initID, respID = idB, idA
	}

	respConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)
	defer respConn.Close()
	initConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)
	defer initConn.Close()

	mustNotInstall := func(uint32, uint32, [16]byte, [16]byte) error {
		t.Fatal("keys must never be installed on a pin failure")
		return nil
	}

	// The initiator pins the real responder, but the responder pins an imposter, so
	// the SA-setup round-trip (the mutual key-confirmation) must fail closed.
	initT, err := NewTunnel(TunnelConfig{
		Local: initID, PeerPub: respID.PublicKey(), Conn: initConn,
		PeerAddr: respConn.LocalAddr(), RekeyInterval: time.Second,
	}, mustNotInstall)
	require.NoError(t, err)
	respT, err := NewTunnel(TunnelConfig{
		Local: respID, PeerPub: imposter.PublicKey(), Conn: respConn,
		PeerAddr: initConn.LocalAddr(), RekeyInterval: time.Second,
	}, mustNotInstall)
	require.NoError(t, err)
	defer initT.Close()
	defer respT.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	go func() { _ = respT.Bringup(ctx) }()
	require.Error(t, initT.Bringup(ctx), "bring-up must fail when the peer does not pin us")
}

// TestTunnelReconnects exercises the reestablish state machine: a session loss
// mid-run must tear the dead session down and re-establish a fresh one on both ends,
// resuming rotation, rather than wedging or hot-looping.
func TestTunnelReconnects(t *testing.T) {
	initRec, respRec := newEpochRecorder(), newEpochRecorder()
	initT, respT, cleanup := twoTunnels(t, initRec.install, respRec.install, 100*time.Millisecond)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	brCh := make(chan error, 1)
	go func() { brCh <- respT.Bringup(ctx) }()
	require.NoError(t, initT.Bringup(ctx))
	require.NoError(t, <-brCh)

	// Force a session loss before the run loops start: closing the initiator's session
	// tears down both ends' QUIC connections, so the initiator detects loss via the
	// connection context and the responder's next accept errors out.
	require.NoError(t, initT.sess.Close())

	runCh := make(chan error, 2)
	go func() { runCh <- initT.Run(ctx) }()
	go func() { runCh <- respT.Run(ctx) }()

	// Both peers must reconnect and resume installing generations (well past the single
	// bring-up generation), proving the reconnect path self-heals.
	require.Eventually(t, func() bool {
		return len(initRec.snapshot()) >= 3 && len(respRec.snapshot()) >= 3
	}, 18*time.Second, 25*time.Millisecond, "peers must self-heal and resume rekeying after a session loss")

	cancel()
	require.NoError(t, <-runCh)
	require.NoError(t, <-runCh)

	// Agreement invariant: the initiator installs a generation only after reading the
	// responder's offer, which the responder writes only after it has committed to
	// installing — so the responder must have transmitted under (i.e. installed as its
	// tx SPI) every receive SPI the initiator installed. (The reverse can differ by one:
	// a negotiation torn by the forced loss after the responder committed but before the
	// initiator finished leaves the responder with an extra generation.)
	ir := initRec.snapshot()
	respTxSPIs := map[uint32]bool{}
	for _, rec := range respRec.snapshot() {
		respTxSPIs[rec.txSPI] = true
	}
	for _, rec := range ir {
		require.True(t, respTxSPIs[rec.rxSPI], "responder never transmitted under initiator receive SPI %d", rec.rxSPI)
	}

	// The receive SPIs are NOT globally monotonic across the reconnect: the per-session
	// allocator resets, so the post-reconnect generations start over at a low value. That
	// is safe (and accepted by the handler) because the reconnect derives fresh keys —
	// recovery rests on fresh keys, not on a carried-forward high-water. Just assert every
	// installed receive SPI is a valid non-zero selector.
	for _, rec := range ir {
		require.NotZero(t, rec.rxSPI)
	}
}

// TestTunnelReconnectGuardNeverRejects is the recovery regression test: with installers
// that ENFORCE the handler's relaxed TX anti-reset guard (reject only a re-install of
// the currently-live transmit SPI), a forced session loss must self-heal, keep installing
// generation after generation, AND never make either guard reject. The per-session
// allocator resets the SPIs to a low value after the reconnect, but each generation
// carries a fresh key, so the new (lower) transmit SPI is never equal to the survivor's
// currently-live one and the guard accepts it — recovery with zero persisted state and
// zero rejections.
func TestTunnelReconnectGuardNeverRejects(t *testing.T) {
	initGuard, respGuard := newGuardInstaller(), newGuardInstaller()
	initT, respT, cleanup := twoTunnels(t, initGuard.install, respGuard.install, 100*time.Millisecond)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	brCh := make(chan error, 1)
	go func() { brCh <- respT.Bringup(ctx) }()
	require.NoError(t, initT.Bringup(ctx))
	require.NoError(t, <-brCh)

	require.NoError(t, initT.sess.Close()) // force a session loss

	runCh := make(chan error, 2)
	go func() { runCh <- initT.Run(ctx) }()
	go func() { runCh <- respT.Run(ctx) }()

	// Progress well past the single bring-up generation on BOTH peers proves the guard
	// keeps accepting because each fresh-keyed generation's transmit SPI differs from the
	// currently-live one, even after the reconnect resets the allocator.
	require.Eventually(t, func() bool {
		ig, _ := initGuard.snapshot()
		rg, _ := respGuard.snapshot()
		return len(ig) >= 5 && len(rg) >= 5
	}, 18*time.Second, 25*time.Millisecond, "peers must self-heal and keep installing under the guard")

	cancel()
	require.NoError(t, <-runCh)
	require.NoError(t, <-runCh)

	ig, iRej := initGuard.snapshot()
	_, rRej := respGuard.snapshot()
	require.Zero(t, iRej, "initiator guard must never reject")
	require.Zero(t, rRej, "responder guard must never reject")
	for _, rxSPI := range ig {
		require.NotZero(t, rxSPI)
	}
}
