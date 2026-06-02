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

func TestSelectMode(t *testing.T) {
	cases := []struct {
		name                    string
		keyFile, identity, peer bool
		want                    Mode
		wantErr                 bool
	}{
		{"static", true, false, false, ModeStatic, false},
		{"control-plane", false, true, true, ModeControlPlane, false},
		{"cp half (identity only)", false, true, false, ModeNone, true},
		{"cp half (peer only)", false, false, true, ModeNone, true},
		{"both modes", true, true, true, ModeNone, true},
		{"static + identity", true, true, false, ModeNone, true},
		{"nothing", false, false, false, ModeNone, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectMode(tc.keyFile, tc.identity, tc.peer)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

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

func TestSharedEpoch(t *testing.T) {
	iSPI, err := MakeSPI(0, Initiator, 7) // role bit clear
	require.NoError(t, err)
	rSPI, err := MakeSPI(0, Responder, 3) // role bit set
	require.NoError(t, err)

	// Initiator's view: Tx == peer (responder) Rx == rSPI; Rx == own == iSPI.
	eInit, err := SharedEpoch(&DirectionalSAs{Tx: &SA{SPI: rSPI}, Rx: &SA{SPI: iSPI}})
	require.NoError(t, err)
	require.Equal(t, iSPI, eInit)

	// Responder's view: Tx == peer (initiator) Rx == iSPI; Rx == own == rSPI.
	eResp, err := SharedEpoch(&DirectionalSAs{Tx: &SA{SPI: iSPI}, Rx: &SA{SPI: rSPI}})
	require.NoError(t, err)
	require.Equal(t, iSPI, eResp)

	// Both peers therefore install the identical epoch.
	require.Equal(t, eInit, eResp)

	// Not role-partitioned (both initiator) → error.
	_, err = SharedEpoch(&DirectionalSAs{Tx: &SA{SPI: iSPI}, Rx: &SA{SPI: iSPI}})
	require.Error(t, err)

	// Master-key index != 0 is unsupported by the shared-epoch bridge.
	hiSPI, err := MakeSPI(1, Initiator, 1)
	require.NoError(t, err)
	_, err = SharedEpoch(&DirectionalSAs{Tx: &SA{SPI: rSPI}, Rx: &SA{SPI: hiSPI}})
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
	tn := &Tunnel{install: func(uint32, [16]byte, [16]byte) error {
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
	tn := &Tunnel{install: func(uint32, [16]byte, [16]byte) error {
		called = true
		// Mimic the handler's monotonicity guard rejecting a regressed epoch.
		return errors.New("epoch must be monotonically increasing")
	}}
	// A rejected rotation is logged and swallowed (the data plane keeps its current
	// keys and fails closed on their own expiry); it must not look like a transport
	// error to the run loop.
	require.NoError(t, tn.installSAs(validV0SAs()))
	require.True(t, called)
}

// twoTunnels wires an initiator and a responder Tunnel over loopback UDP, assigning
// the canonical roles correctly, with tight timings for tests.
func twoTunnels(t *testing.T, instInit, instResp SAInstaller, rekey time.Duration) (initT, respT *Tunnel, cleanup func()) {
	return twoTunnelsWithStore(t, instInit, instResp, rekey, nil)
}

// twoTunnelsWithStore is twoTunnels with an optional durable EpochStore on the
// INITIATOR (the only role for which durable state is load-bearing).
func twoTunnelsWithStore(t *testing.T, instInit, instResp SAInstaller, rekey time.Duration, initStore EpochStore) (initT, respT *Tunnel, cleanup func()) {
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
		PeerAddr: respConn.LocalAddr(), RekeyInterval: rekey, EpochStore: initStore,
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

// guardInstaller is an SAInstaller that enforces the handler's strictly-increasing
// epoch guard (handler.go), so tests can detect a regressed/rejected epoch rather
// than the no-op epochRecorder which accepts everything.
type guardInstaller struct {
	mu        sync.Mutex
	max       uint32
	installed []uint32
	rejects   int
}

func newGuardInstaller() *guardInstaller { return &guardInstaller{} }

func (g *guardInstaller) install(epoch uint32, _, _ [16]byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if epoch <= g.max {
		g.rejects++
		return errors.New("epoch must be monotonically increasing")
	}
	g.max = epoch
	g.installed = append(g.installed, epoch)
	return nil
}

func (g *guardInstaller) snapshot() (installed []uint32, rejects int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]uint32(nil), g.installed...), g.rejects
}

// epochRecorder is a thread-safe SAInstaller that records the epochs it installs.
type epochRecorder struct {
	mu     sync.Mutex
	epochs []uint32
	keys   map[uint32][2][16]byte // epoch -> {rx, tx}
}

func newEpochRecorder() *epochRecorder { return &epochRecorder{keys: map[uint32][2][16]byte{}} }

func (r *epochRecorder) install(epoch uint32, rxKey, txKey [16]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.epochs = append(r.epochs, epoch)
	r.keys[epoch] = [2][16]byte{rxKey, txKey}
	return nil
}

func (r *epochRecorder) snapshot() ([]uint32, map[uint32][2][16]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]uint32(nil), r.epochs...)
	cp := make(map[uint32][2][16]byte, len(r.keys))
	for k, v := range r.keys {
		cp[k] = v
	}
	return out, cp
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
	ie, ik := initRec.snapshot()
	re, rk := respRec.snapshot()
	require.Len(t, ie, 1)
	require.Len(t, re, 1)
	require.Equal(t, ie[0], re[0], "peers must install the same shared epoch")
	require.NotZero(t, ie[0])
	// Cross-derivation: initiator TX == responder RX and vice versa.
	require.Equal(t, ik[ie[0]][1], rk[re[0]][0], "initiator tx key != responder rx key")
	require.Equal(t, ik[ie[0]][0], rk[re[0]][1], "initiator rx key != responder tx key")
	// Within a peer, the two directions use distinct keys.
	require.NotEqual(t, ik[ie[0]][0], ik[ie[0]][1])

	// Run both peers and let the initiator drive a few rekeys.
	runCh := make(chan error, 2)
	go func() { runCh <- initT.Run(ctx) }()
	go func() { runCh <- respT.Run(ctx) }()

	require.Eventually(t, func() bool {
		e, _ := initRec.snapshot()
		return len(e) >= 3
	}, 10*time.Second, 20*time.Millisecond, "initiator should rekey several times")

	cancel()
	require.NoError(t, <-runCh)
	require.NoError(t, <-runCh)

	// Epochs strictly increase per peer, and the two peers agree generation-by-generation.
	ie, _ = initRec.snapshot()
	re, _ = respRec.snapshot()
	for i := 1; i < len(ie); i++ {
		require.Greater(t, ie[i], ie[i-1], "initiator epochs must strictly increase")
	}
	n := len(ie)
	if len(re) < n {
		n = len(re)
	}
	require.GreaterOrEqual(t, n, 2)
	for i := 0; i < n; i++ {
		require.Equal(t, ie[i], re[i], "peers disagree on epoch for generation %d", i)
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

	mustNotInstall := func(uint32, [16]byte, [16]byte) error {
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

	// Both peers must reconnect and resume installing matching epochs (well past the
	// single bring-up generation), proving the reconnect path self-heals.
	require.Eventually(t, func() bool {
		ie, _ := initRec.snapshot()
		re, _ := respRec.snapshot()
		return len(ie) >= 3 && len(re) >= 3
	}, 18*time.Second, 25*time.Millisecond, "peers must self-heal and resume rekeying after a session loss")

	cancel()
	require.NoError(t, <-runCh)
	require.NoError(t, <-runCh)

	// Agreement invariant: the initiator installs a generation only after reading the
	// responder's offer, which the responder writes only after it has committed to
	// installing — so every epoch the initiator installed must also have been
	// installed by the responder. (The reverse can differ by one: a negotiation torn
	// by the forced loss after the responder committed but before the initiator
	// finished leaves the responder with an extra generation.)
	ie, _ := initRec.snapshot()
	_, rk := respRec.snapshot()
	for _, e := range ie {
		require.Contains(t, rk, e, "responder never installed initiator epoch %d", e)
	}

	// Monotonicity invariant (Phase 5): seeding the new session's allocator from the
	// in-memory epoch high-water means the shared epoch no longer resets to 1 across
	// the reconnect — the initiator's installed epochs are now globally strictly
	// increasing, which is what lets the survivor's monotonicity guard accept the
	// post-reconnect generation.
	for i := 1; i < len(ie); i++ {
		require.Greater(t, ie[i], ie[i-1], "initiator epochs must be globally monotonic across the reconnect")
	}
}

// TestTunnelReconnectGuardNeverRejects is the recovery regression test the design
// review demanded: with installers that ENFORCE the handler's strictly-increasing
// epoch guard, a forced session loss must self-heal, keep installing generation after
// generation, AND never make either guard reject a regressed epoch. Without the
// epoch-floor seeding the post-reconnect epoch would reset to 1 and the guard would
// reject every generation (installs would stall at the single bring-up generation);
// without the seed MARGIN, a torn-after-responder-install exchange would re-offer an
// already-installed epoch and the responder's guard would reject it. The seed margin
// (>= the worst-case one-generation responder lead) is what makes zero rejections
// hold; the deterministic proof of that margin is TestReconnectSeedCoversTornLead.
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
	// keeps accepting because seeding keeps the epoch climbing across the reconnect.
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
	require.Zero(t, iRej, "initiator guard must never reject (seeding keeps epochs monotonic)")
	require.Zero(t, rRej, "responder guard must never reject (the seed margin covers a torn-exchange lead)")
	for i := 1; i < len(ig); i++ {
		require.Greater(t, ig[i], ig[i-1], "accepted epochs are strictly increasing")
	}
}

// TestReconnectSeedCoversTornLead is the deterministic guard for the in-memory
// reconnect seed margin: it simulates the torn-exchange race — the responder committed
// epoch E but the initiator failed to record it, so the initiator's high-water lags by
// one — and proves the next session's seed still produces an epoch strictly greater
// than E, so the responder's monotonicity guard accepts it (no black-hole).
func TestReconnectSeedCoversTornLead(t *testing.T) {
	const responderMax = uint32(50)   // responder installed up to 50
	initHighWater := responderMax - 1 // initiator recorded only 49 (torn after 50)

	a := NewSPIAllocator(Initiator)
	a.SeedFloor(activeMasterKeyIndex, seedWithMargin(initHighWater))
	next, err := a.Allocate(activeMasterKeyIndex)
	require.NoError(t, err)
	require.Greater(t, next&spiCounterMask, responderMax,
		"the seeded epoch must exceed the responder's retained max despite the one-generation lag")
}

// TestTunnelSeedsFromDurableHighWater proves the initiator-restart recovery
// mechanism deterministically: a fresh initiator whose store already holds a high
// high-water (as a prior process would have left) seeds its FIRST epoch above it, so
// a survivor that retained that high-water still accepts the new SA. It also confirms
// the value is re-persisted.
func TestTunnelSeedsFromDurableHighWater(t *testing.T) {
	const prior = uint32(1000)
	store := &fakeEpochStore{}
	store.set(prior)

	initRec, respRec := newEpochRecorder(), newEpochRecorder()
	initT, respT, cleanup := twoTunnelsWithStore(t, initRec.install, respRec.install, 100*time.Millisecond, store)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	brCh := make(chan error, 1)
	go func() { brCh <- respT.Bringup(ctx) }()
	require.NoError(t, initT.Bringup(ctx))
	require.NoError(t, <-brCh)

	ie, _ := initRec.snapshot()
	re, _ := respRec.snapshot()
	require.Len(t, ie, 1)
	// First epoch is seeded strictly above the durable high-water (+margin), so it
	// exceeds anything a survivor retained from the pre-restart session.
	require.Equal(t, seedWithMargin(prior)+1, ie[0])
	require.Greater(t, ie[0], prior)
	require.Equal(t, ie[0], re[0], "both peers install the seeded epoch")

	// The new high-water is persisted durably for the next restart.
	require.Eventually(t, func() bool {
		hw, ok := store.loaded()
		return ok && hw == ie[0]
	}, 2*time.Second, 5*time.Millisecond)
}

// TestTunnelRequireStateFailsBringupOnCorruptState asserts the fail-closed Load
// policy: under RequireState a corrupt/unreadable store fails Bringup (on the
// initiator), while the default policy starts fresh.
func TestTunnelRequireStateFailsBringupOnCorruptState(t *testing.T) {
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

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)
	defer conn.Close()

	loadErr := errors.New("state corrupt")
	tn, err := NewTunnel(TunnelConfig{
		Local: initID, PeerPub: respID.PublicKey(), Conn: conn,
		PeerAddr: conn.LocalAddr(), RekeyInterval: time.Second,
		EpochStore: &fakeEpochStore{loadErr: loadErr}, RequireState: true,
	}, func(uint32, [16]byte, [16]byte) error { return nil })
	require.NoError(t, err)
	require.True(t, tn.Initiator())
	defer tn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Bringup must fail closed at loadEpochState, before any session is established.
	err = tn.Bringup(ctx)
	require.Error(t, err)
	require.ErrorIs(t, err, loadErr)
	require.Nil(t, tn.sess)
}

func TestNewTunnelRequireStateNeedsStore(t *testing.T) {
	idA, err := GenerateIdentity()
	require.NoError(t, err)
	idB, err := GenerateIdentity()
	require.NoError(t, err)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)
	defer conn.Close()
	_, err = NewTunnel(TunnelConfig{
		Local: idA, PeerPub: idB.PublicKey(), Conn: conn,
		PeerAddr: conn.LocalAddr(), RekeyInterval: time.Second, RequireState: true,
	}, func(uint32, [16]byte, [16]byte) error { return nil })
	require.Error(t, err, "RequireState without an EpochStore must be rejected")
}

// TestTunnelDurableRoundTripAcrossRestart is the true end-to-end durable-recovery
// proof: a real initiator persists its climbing high-water to a shared store, then a
// SECOND initiator instance on the SAME store (a simulated restart) reloads exactly
// what the first persisted and will seed strictly above it.
func TestTunnelDurableRoundTripAcrossRestart(t *testing.T) {
	store := &fakeEpochStore{}
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

	// Round 1: run a real pair until the initiator has persisted a couple generations.
	func() {
		respConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
		require.NoError(t, err)
		defer respConn.Close()
		initConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
		require.NoError(t, err)
		defer initConn.Close()

		t1, err := NewTunnel(TunnelConfig{
			Local: initID, PeerPub: respID.PublicKey(), Conn: initConn,
			PeerAddr: respConn.LocalAddr(), RekeyInterval: 100 * time.Millisecond, EpochStore: store,
		}, newEpochRecorder().install)
		require.NoError(t, err)
		require.True(t, t1.Initiator())
		r, err := NewTunnel(TunnelConfig{
			Local: respID, PeerPub: initID.PublicKey(), Conn: respConn,
			PeerAddr: initConn.LocalAddr(), RekeyInterval: 100 * time.Millisecond,
		}, newEpochRecorder().install)
		require.NoError(t, err)
		defer t1.Close()
		defer r.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		brCh := make(chan error, 1)
		go func() { brCh <- r.Bringup(ctx) }()
		require.NoError(t, t1.Bringup(ctx))
		require.NoError(t, <-brCh)

		runCh := make(chan error, 2)
		go func() { runCh <- t1.Run(ctx) }()
		go func() { runCh <- r.Run(ctx) }()
		require.Eventually(t, func() bool {
			hw, ok := store.loaded()
			return ok && hw >= 2
		}, 10*time.Second, 10*time.Millisecond, "initiator must persist a few generations")
		cancel()
		require.NoError(t, <-runCh)
		require.NoError(t, <-runCh)
	}()

	persisted, ok := store.loaded()
	require.True(t, ok)
	require.GreaterOrEqual(t, persisted, uint32(2))

	// Round 2: a fresh initiator (same identity + store) reloads what round 1 wrote.
	conn2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)
	defer conn2.Close()
	t2, err := NewTunnel(TunnelConfig{
		Local: initID, PeerPub: respID.PublicKey(), Conn: conn2,
		PeerAddr: conn2.LocalAddr(), RekeyInterval: time.Second, EpochStore: store,
	}, func(uint32, [16]byte, [16]byte) error { return nil })
	require.NoError(t, err)
	require.True(t, t2.Initiator())
	defer t2.Close()

	require.NoError(t, t2.loadEpochState())
	require.Equal(t, persisted, t2.installedHigh, "second instance loads exactly what the first persisted")
	require.Greater(t, seedWithMargin(t2.epochSeed), persisted, "and seeds strictly above it")
}

// TestResponderIgnoresStore pins the initiator-only invariant: a responder configured
// with a store (and even --require-state) must never consult or write it, must not be
// gated by a load error, and must not start a persister.
func TestResponderIgnoresStore(t *testing.T) {
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

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	require.NoError(t, err)
	defer conn.Close()

	store := &fakeEpochStore{loadErr: errors.New("responder must never read this")}
	respT, err := NewTunnel(TunnelConfig{
		Local: respID, PeerPub: initID.PublicKey(), Conn: conn,
		PeerAddr: conn.LocalAddr(), RekeyInterval: time.Second,
		EpochStore: store, RequireState: true,
	}, func(uint32, [16]byte, [16]byte) error { return nil })
	require.NoError(t, err)
	require.False(t, respT.Initiator())
	defer respT.Close()

	// On the responder, loadEpochState is a no-op: it must not Load (so the load error
	// and RequireState do not gate it) and must not start a persister.
	require.NoError(t, respT.loadEpochState())
	require.Nil(t, respT.persist)
	loads, stores := store.counts()
	require.Zero(t, loads, "responder must never Load its store")
	require.Zero(t, stores, "responder must never Store")
}
