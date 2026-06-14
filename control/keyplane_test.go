package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// recordingGranter is a KeyGranter over a real VNIAllocator that records
// every grant and release for assertions. reject, when set, vetoes grants.
type recordingGranter struct {
	mu          sync.Mutex
	alloc       *VNIAllocator
	grants      map[uint32]grantRecord
	released    []uint32
	reject      func(addr netip.Addr) error
	releaseErr  func(vni uint32) error // when set, Release records the call then returns this error
	vniOverride uint32                 // when non-zero, Grant returns this VNI instead of allocating
}

type grantRecord struct {
	peer *ecdsa.PublicKey
	addr netip.Addr
	sas  *DirectionalSAs
}

func newRecordingGranter() *recordingGranter {
	return &recordingGranter{
		alloc:  NewVNIAllocator(30 * time.Second),
		grants: make(map[uint32]grantRecord),
	}
}

func (g *recordingGranter) Grant(peer *ecdsa.PublicKey, addr netip.Addr, sas *DirectionalSAs) (uint32, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reject != nil {
		if err := g.reject(addr); err != nil {
			return 0, err
		}
	}
	vni := g.vniOverride
	if vni == 0 {
		var err error
		if vni, err = g.alloc.Allocate(); err != nil {
			return 0, err
		}
	}
	g.grants[vni] = grantRecord{peer: peer, addr: addr, sas: sas}
	return vni, nil
}

func (g *recordingGranter) Release(peer *ecdsa.PublicKey, vni uint32) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.released = append(g.released, vni) // record every call, even the ones that error
	if g.releaseErr != nil {
		if err := g.releaseErr(vni); err != nil {
			return err
		}
	}
	g.alloc.Release(vni)
	delete(g.grants, vni)
	return nil
}

func (g *recordingGranter) record(vni uint32) (grantRecord, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	r, ok := g.grants[vni]
	return r, ok
}

func (g *recordingGranter) releasedVNIs() []uint32 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]uint32(nil), g.released...)
}

// keyplaneResponder starts a multi-peer responder that serves the key plane
// on every accepted session and returns a dial helper for initiators.
func keyplaneResponder(t *testing.T, authorize PeerAuthorizer, granter KeyGranter) func(*Identity) *Session {
	t.Helper()
	srvID, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := ListenPeers(srvConn, srvID, authorize)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = srvConn.Close()
	})

	go func() {
		for {
			sess, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func() { _ = sess.ServeKeyPlane(ctx, granter) }()
		}
	}()

	srvPub := srvID.PublicKey()
	return func(id *Identity) *Session {
		t.Helper()
		cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cliConn.Close() })
		sess, err := Dial(ctx, cliConn, ln.Addr(), id, srvPub)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = sess.Close() })
		return sess
	}
}

// acceptAnyOf authorizes the given identities only.
func acceptAnyOf(ids ...*Identity) PeerAuthorizer {
	return func(peerPub *ecdsa.PublicKey) error {
		for _, id := range ids {
			if peerPub.Equal(id.PublicKey()) {
				return nil
			}
		}
		return errors.New("unknown peer")
	}
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestKeyPlaneGrantDerivesMatchingSAs(t *testing.T) {
	workerA, _ := GenerateIdentity()
	workerB, _ := GenerateIdentity()
	granter := newRecordingGranter()
	dial := keyplaneResponder(t, acceptAnyOf(workerA, workerB), granter)
	ctx := testCtx(t)

	sessA := dial(workerA)
	sessB := dial(workerB)

	addrA := netip.MustParseAddr("fd61:706f:7879:1:100::1")
	addrB := netip.MustParseAddr("fd61:706f:7879:1:100::2")
	grantA, err := sessA.RequestKeys(ctx, PSPv0, addrA)
	if err != nil {
		t.Fatalf("worker A RequestKeys: %v", err)
	}
	grantB, err := sessB.RequestKeys(ctx, PSPv0, addrB)
	if err != nil {
		t.Fatalf("worker B RequestKeys: %v", err)
	}
	if grantA.VNI == grantB.VNI {
		t.Fatalf("both workers granted VNI %d", grantA.VNI)
	}

	// The responder's installed SAs must mirror the initiator's: what the
	// initiator transmits with is what the responder receives with, and vice
	// versa. This is the whole point — both ends derived identical keys
	// without any key bytes on the wire.
	recA, ok := granter.record(grantA.VNI)
	if !ok {
		t.Fatalf("granter has no record for VNI %d", grantA.VNI)
	}
	if !bytes.Equal(grantA.SAs.Tx.Key, recA.sas.Rx.Key) {
		t.Fatal("initiator TX key != responder RX key")
	}
	if !bytes.Equal(grantA.SAs.Rx.Key, recA.sas.Tx.Key) {
		t.Fatal("initiator RX key != responder TX key")
	}
	if bytes.Equal(grantA.SAs.Tx.Key, grantA.SAs.Rx.Key) {
		t.Fatal("tx and rx keys collided")
	}
	if recA.addr != addrA {
		t.Fatalf("granter saw addr %v, want %v", recA.addr, addrA)
	}
	if !recA.peer.Equal(workerA.PublicKey()) {
		t.Fatal("granter did not see worker A's identity key")
	}

	// Cross-session: the two grants must not share keys (distinct sessions ⇒
	// distinct master keys; distinct SPIs regardless).
	recB, _ := granter.record(grantB.VNI)
	if bytes.Equal(recA.sas.Rx.Key, recB.sas.Rx.Key) {
		t.Fatal("two workers derived the same RX key")
	}
}

func TestKeyPlaneConcurrentGrants(t *testing.T) {
	worker, _ := GenerateIdentity()
	granter := newRecordingGranter()
	dial := keyplaneResponder(t, acceptAnyOf(worker), granter)
	ctx := testCtx(t)
	sess := dial(worker)

	const n = 12
	grants := make([]*KeyGrant, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := netip.MustParseAddr(fmt.Sprintf("fd61:706f:7879:1:100::%x", i+1))
			grants[i], errs[i] = sess.RequestKeys(ctx, PSPv0, addr)
		}()
	}
	wg.Wait()

	vnis := make(map[uint32]struct{})
	spis := make(map[uint32]struct{})
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("concurrent RequestKeys #%d: %v", i, errs[i])
		}
		if _, dup := vnis[grants[i].VNI]; dup {
			t.Fatalf("duplicate VNI %d", grants[i].VNI)
		}
		vnis[grants[i].VNI] = struct{}{}
		for _, spi := range []uint32{grants[i].SAs.Tx.SPI, grants[i].SAs.Rx.SPI} {
			if _, dup := spis[spi]; dup {
				t.Fatalf("duplicate SPI %d", spi)
			}
			spis[spi] = struct{}{}
		}
	}
}

func TestKeyPlaneRejectsUnauthorizedPeer(t *testing.T) {
	authorized, _ := GenerateIdentity()
	imposter, _ := GenerateIdentity()
	granter := newRecordingGranter()

	srvID, _ := GenerateIdentity()
	srvConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	defer srvConn.Close()
	ln, err := ListenPeers(srvConn, srvID, acceptAnyOf(authorized))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx := testCtx(t)
	go func() {
		for {
			sess, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func() { _ = sess.ServeKeyPlane(ctx, granter) }()
		}
	}()

	cliConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	defer cliConn.Close()
	// As with the pinned 1:1 tunnel, the client handshake may complete before
	// the server's authorizer rejects it; the fail-closed property is that no
	// EXCHANGE can succeed.
	sess, err := Dial(ctx, cliConn, ln.Addr(), imposter, srvID.PublicKey())
	if err != nil {
		return // rejected at dial — also acceptable
	}
	defer sess.Close()
	if _, err := sess.RequestKeys(ctx, PSPv0, netip.MustParseAddr("fd61::1")); err == nil {
		t.Fatal("unauthorized peer obtained a key grant")
	}
	if granter.alloc.Live() != 0 {
		t.Fatal("granter allocated a VNI for an unauthorized peer")
	}
}

func TestKeyPlaneGranterRejection(t *testing.T) {
	worker, _ := GenerateIdentity()
	granter := newRecordingGranter()
	badAddr := netip.MustParseAddr("fd61::bad")
	fullAddr := netip.MustParseAddr("fd61::f0:11")
	granter.reject = func(addr netip.Addr) error {
		switch addr {
		case badAddr:
			return errors.New("address not authorized for this peer")
		case fullAddr:
			return ErrVNIExhausted
		}
		return nil
	}
	dial := keyplaneResponder(t, acceptAnyOf(worker), granter)
	ctx := testCtx(t)
	sess := dial(worker)

	if _, err := sess.RequestKeys(ctx, PSPv0, badAddr); !errors.Is(err, ErrGrantRejected) {
		t.Fatalf("rejected addr: %v, want ErrGrantRejected", err)
	}
	if _, err := sess.RequestKeys(ctx, PSPv0, fullAddr); !errors.Is(err, ErrVNIExhausted) {
		t.Fatalf("exhausted space: %v, want ErrVNIExhausted", err)
	}
	// The session must remain usable after rejections.
	if _, err := sess.RequestKeys(ctx, PSPv0, netip.MustParseAddr("fd61::0:0c")); err != nil {
		t.Fatalf("grant after rejections: %v", err)
	}
}

func TestKeyPlaneReleaseAndSessionIsolation(t *testing.T) {
	workerA, _ := GenerateIdentity()
	workerB, _ := GenerateIdentity()
	granter := newRecordingGranter()
	dial := keyplaneResponder(t, acceptAnyOf(workerA, workerB), granter)
	ctx := testCtx(t)

	sessA := dial(workerA)
	sessB := dial(workerB)
	grantA, err := sessA.RequestKeys(ctx, PSPv0, netip.MustParseAddr("fd61::a"))
	if err != nil {
		t.Fatal(err)
	}

	// Worker B must not be able to release worker A's VNI.
	if err := sessB.ReleaseKeys(ctx, grantA.VNI); !errors.Is(err, ErrGrantRejected) {
		t.Fatalf("cross-session release: %v, want ErrGrantRejected", err)
	}
	if got := granter.releasedVNIs(); len(got) != 0 {
		t.Fatalf("cross-session release reached the granter: %v", got)
	}

	// The owner can release; the granter sees it and the VNI quarantines.
	if err := sessA.ReleaseKeys(ctx, grantA.VNI); err != nil {
		t.Fatalf("owner release: %v", err)
	}
	if got := granter.releasedVNIs(); len(got) != 1 || got[0] != grantA.VNI {
		t.Fatalf("released VNIs = %v, want [%d]", got, grantA.VNI)
	}
	// Double release of an already-released VNI is rejected (no longer granted).
	if err := sessA.ReleaseKeys(ctx, grantA.VNI); !errors.Is(err, ErrGrantRejected) {
		t.Fatalf("double release: %v, want ErrGrantRejected", err)
	}
}

func TestKeyPlaneSessionTeardownReleasesGrants(t *testing.T) {
	worker, _ := GenerateIdentity()
	granter := newRecordingGranter()
	dial := keyplaneResponder(t, acceptAnyOf(worker), granter)
	ctx := testCtx(t)

	sess := dial(worker)
	g1, err := sess.RequestKeys(ctx, PSPv0, netip.MustParseAddr("fd61::1"))
	if err != nil {
		t.Fatal(err)
	}
	g2, err := sess.RequestKeys(ctx, PSPv0, netip.MustParseAddr("fd61::2"))
	if err != nil {
		t.Fatal(err)
	}

	// A worker crash = session close without releases. Every outstanding VNI
	// must be released (quarantine starts) by the serve loop's teardown.
	_ = sess.Close()
	waitForReleases(t, granter, []uint32{g1.VNI, g2.VNI})
}

func waitForReleases(t *testing.T, granter *recordingGranter, want []uint32) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		got := granter.releasedVNIs()
		if len(got) == len(want) {
			set := make(map[uint32]struct{}, len(got))
			for _, v := range got {
				set[v] = struct{}{}
			}
			ok := true
			for _, w := range want {
				if _, in := set[w]; !in {
					ok = false
					break
				}
			}
			if ok {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("teardown releases = %v, want %v", granter.releasedVNIs(), want)
}

func TestKeyPlaneWireFormats(t *testing.T) {
	cases := []struct {
		name    string
		marshal func() []byte
		parse   func([]byte) error
	}{
		{
			name:    "key request",
			marshal: keyRequest{PSPVersion: PSPv0, RxSPI: 0x40000007, Addr: netip.MustParseAddr("fd61::9")}.marshal,
			parse: func(b []byte) error {
				got, err := parseKeyRequest(b)
				if err != nil {
					return err
				}
				want := keyRequest{PSPVersion: PSPv0, RxSPI: 0x40000007, Addr: netip.MustParseAddr("fd61::9")}
				if got != want {
					return fmt.Errorf("round-trip mismatch: %+v != %+v", got, want)
				}
				return nil
			},
		},
		{
			name:    "key request ipv4 unmaps",
			marshal: keyRequest{PSPVersion: PSPv0, RxSPI: 0x40000003, Addr: netip.MustParseAddr("10.0.0.7")}.marshal,
			parse: func(b []byte) error {
				got, err := parseKeyRequest(b)
				if err != nil {
					return err
				}
				// The 16-byte wire form must Unmap back to the native IPv4 addr,
				// not its ::ffff: 4-in-6 form (which compares unequal).
				want := netip.MustParseAddr("10.0.0.7")
				if got.Addr != want {
					return fmt.Errorf("addr round-trip: got %v (Is4=%v), want %v", got.Addr, got.Addr.Is4(), want)
				}
				return nil
			},
		},
		{
			name:    "key grant",
			marshal: keyGrant{Status: grantOK, PSPVersion: PSPv0, RxSPI: 0x1234, VNI: 0xabcdef}.marshal,
			parse: func(b []byte) error {
				got, err := parseKeyGrant(b)
				if err != nil {
					return err
				}
				want := keyGrant{Status: grantOK, PSPVersion: PSPv0, RxSPI: 0x1234, VNI: 0xabcdef}
				if got != want {
					return fmt.Errorf("round-trip mismatch: %+v != %+v", got, want)
				}
				return nil
			},
		},
		{
			name:    "vni release",
			marshal: vniRelease{VNI: 0xabcdef}.marshal,
			parse: func(b []byte) error {
				got, err := parseVNIRelease(b)
				if err != nil {
					return err
				}
				if got.VNI != 0xabcdef {
					return fmt.Errorf("VNI = %x", got.VNI)
				}
				return nil
			},
		},
		{
			name:    "release ack",
			marshal: releaseAck{Status: grantExhausted}.marshal,
			parse: func(b []byte) error {
				got, err := parseReleaseAck(b)
				if err != nil {
					return err
				}
				if got.Status != grantExhausted {
					return fmt.Errorf("status = %d", got.Status)
				}
				return nil
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.marshal()
			if err := tc.parse(b); err != nil {
				t.Fatal(err)
			}
			// Malformed variants must be rejected: truncated, bad version, bad type.
			if err := tc.parse(b[:len(b)-1]); err == nil {
				t.Fatal("accepted truncated frame")
			}
			badVer := append([]byte(nil), b...)
			badVer[0] = ProtocolVersion + 1
			if err := tc.parse(badVer); err == nil {
				t.Fatal("accepted wrong protocol version")
			}
			badType := append([]byte(nil), b...)
			badType[1] = 0xff
			if err := tc.parse(badType); err == nil {
				t.Fatal("accepted wrong message type")
			}
		})
	}
}

// TestDeriveDirectionalRejectsPeerRoleCollision pins the fix for the SPI
// role-partition bypass: a responder must refuse a peer-announced RX SPI that
// sits in its own role/master-key partition, or the responder's TX key for one
// exchange can byte-for-byte collide with an RX key its allocator later mints.
func TestDeriveDirectionalRejectsPeerRoleCollision(t *testing.T) {
	mk, err := DeriveMasterKeys(bytes.Repeat([]byte{0x42}, RootSecretLen))
	if err != nil {
		t.Fatal(err)
	}
	resp := &Session{role: Responder, masterKeys: mk}
	myRxSPI, err := MakeSPI(activeMasterKeyIndex, Responder, 7)
	if err != nil {
		t.Fatal(err)
	}

	// A spoofed peer SPI in the responder's own (Responder) role partition.
	spoofed, err := MakeSPI(activeMasterKeyIndex, Responder, 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.deriveDirectional(PSPv0, myRxSPI, saOffer{PSPVersion: PSPv0, RxSPI: spoofed}); err == nil {
		t.Fatal("accepted a peer SPI in the responder's own role partition")
	}

	// An inactive master-key index is likewise rejected.
	badIdx, err := MakeSPI(1, Initiator, 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.deriveDirectional(PSPv0, myRxSPI, saOffer{PSPVersion: PSPv0, RxSPI: badIdx}); err == nil {
		t.Fatal("accepted a peer SPI with an inactive master-key index")
	}

	// The legitimate case — a peer SPI allocated by the opposite (Initiator)
	// role under the active index — still succeeds.
	legit, err := MakeSPI(activeMasterKeyIndex, Initiator, 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.deriveDirectional(PSPv0, myRxSPI, saOffer{PSPVersion: PSPv0, RxSPI: legit}); err != nil {
		t.Fatalf("rejected a legitimate initiator SPI: %v", err)
	}
}

// TestKeyPlaneManySequentialGrants drives more lifetime exchanges than the
// responder's concurrent-stream window, proving each exchange retires its
// stream and replenishes credit. Before the drain-to-EOF fix this starved
// around keyPlaneMaxConcurrentStreams and every later RequestKeys timed out.
func TestKeyPlaneManySequentialGrants(t *testing.T) {
	worker, _ := GenerateIdentity()
	granter := newRecordingGranter()
	dial := keyplaneResponder(t, acceptAnyOf(worker), granter)
	ctx := testCtx(t)
	sess := dial(worker)

	const n = keyPlaneMaxConcurrentStreams + 64
	for i := 0; i < n; i++ {
		addr := netip.MustParseAddr(fmt.Sprintf("fd61:706f:7879:2:100::%x", i+1))
		g, err := sess.RequestKeys(ctx, PSPv0, addr)
		if err != nil {
			t.Fatalf("RequestKeys #%d of %d: %v (stream credit likely leaked)", i, n, err)
		}
		if err := sess.ReleaseKeys(ctx, g.VNI); err != nil {
			t.Fatalf("ReleaseKeys #%d: %v", i, err)
		}
	}
}

func TestStatusToError(t *testing.T) {
	cases := []struct {
		status grantStatus
		want   error
	}{
		{grantExhausted, ErrVNIExhausted},
		{grantSPIExhausted, ErrSPIExhausted},
		{grantRejected, ErrGrantRejected},
		{grantStatus(99), ErrGrantRejected},
	}
	for _, tc := range cases {
		if got := statusToError(tc.status); !errors.Is(got, tc.want) {
			t.Errorf("statusToError(%d) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

// TestKeyPlaneReleaseErrorNoDoubleRelease verifies that a granter Release error
// still untracks the VNI, so the session-teardown sweep cannot release it a
// second time (which a non-idempotent granter would observe as a double-uninstall).
func TestKeyPlaneReleaseErrorNoDoubleRelease(t *testing.T) {
	worker, _ := GenerateIdentity()
	granter := newRecordingGranter()
	dial := keyplaneResponder(t, acceptAnyOf(worker), granter)
	ctx := testCtx(t)
	sess := dial(worker)

	g, err := sess.RequestKeys(ctx, PSPv0, netip.MustParseAddr("fd61::1"))
	if err != nil {
		t.Fatal(err)
	}
	granter.mu.Lock()
	granter.releaseErr = func(uint32) error { return errors.New("transient uninstall failure") }
	granter.mu.Unlock()

	if err := sess.ReleaseKeys(ctx, g.VNI); !errors.Is(err, ErrGrantRejected) {
		t.Fatalf("ReleaseKeys with failing granter: %v, want ErrGrantRejected", err)
	}
	// Untracked despite the error: a second release is rejected as not-ours, so
	// teardown has nothing to double-release.
	if err := sess.ReleaseKeys(ctx, g.VNI); !errors.Is(err, ErrGrantRejected) {
		t.Fatalf("second release: %v, want ErrGrantRejected (VNI should be untracked)", err)
	}
	count := 0
	for _, v := range granter.releasedVNIs() {
		if v == g.VNI {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("granter.Release reached %d times for VNI %d, want exactly 1", count, g.VNI)
	}
}

// TestKeyPlaneRejectsOutOfRangeGranterVNI verifies the responder refuses to
// track or advertise an out-of-range VNI from a broken granter and releases
// whatever it installed.
func TestKeyPlaneRejectsOutOfRangeGranterVNI(t *testing.T) {
	worker, _ := GenerateIdentity()
	granter := newRecordingGranter()
	granter.vniOverride = MaxVNI + 1
	dial := keyplaneResponder(t, acceptAnyOf(worker), granter)
	ctx := testCtx(t)
	sess := dial(worker)

	if _, err := sess.RequestKeys(ctx, PSPv0, netip.MustParseAddr("fd61::1")); !errors.Is(err, ErrGrantRejected) {
		t.Fatalf("out-of-range granter VNI: %v, want ErrGrantRejected", err)
	}
	released := granter.releasedVNIs()
	if len(released) != 1 || released[0] != uint32(MaxVNI+1) {
		t.Fatalf("released = %v, want [%d] (responder cleans up the rejected VNI)", released, uint32(MaxVNI+1))
	}
}
