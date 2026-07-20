package control

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// loopbackPeers wires an initiator and responder over two loopback UDP sockets
// and returns their established sessions.
func loopbackPeers(t *testing.T) (initiator, responder *Session, cleanup func()) {
	t.Helper()
	idA, err := GenerateIdentity() // initiator
	if err != nil {
		t.Fatal(err)
	}
	idB, err := GenerateIdentity() // responder
	if err != nil {
		t.Fatal(err)
	}

	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}
	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := Listen(srvConn, idB, idA.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	type res struct {
		s   *Session
		err error
	}
	respCh := make(chan res, 1)
	go func() {
		s, err := ln.Accept(ctx)
		respCh <- res{s, err}
	}()

	initiator, err = Dial(ctx, cliConn, ln.ln.Addr(), idA, idB.PublicKey())
	if err != nil {
		cancel()
		t.Fatalf("dial: %v", err)
	}
	r := <-respCh
	if r.err != nil {
		cancel()
		t.Fatalf("accept: %v", r.err)
	}
	responder = r.s

	cleanup = func() {
		cancel()
		_ = initiator.Close()
		_ = responder.Close()
		_ = ln.Close()
		_ = cliConn.Close()
	}
	return initiator, responder, cleanup
}

func TestControlSessionHandshakeAndSANegotiation(t *testing.T) {
	initiator, responder, cleanup := loopbackPeers(t)
	defer cleanup()

	// The handshake must be TLS 1.3 with an AES-GCM suite (FIPS-approved).
	st := initiator.TLSState()
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version %#x, want 1.3", st.Version)
	}
	switch st.CipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384:
	default:
		t.Fatalf("negotiated non-AES-GCM suite %#x", st.CipherSuite)
	}

	// Both peers must derive identical master keys from the shared exporter.
	if initiator.MasterKeys().keys != responder.MasterKeys().keys {
		t.Fatal("peers derived different master keys")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type res struct {
		sas *DirectionalSAs
		err error
	}
	rCh := make(chan res, 1)
	go func() {
		sas, err := responder.NegotiateSAs(ctx, AESGCM128)
		rCh <- res{sas, err}
	}()
	iSAs, err := initiator.NegotiateSAs(ctx, AESGCM128)
	if err != nil {
		t.Fatalf("initiator NegotiateSAs: %v", err)
	}
	r := <-rCh
	if r.err != nil {
		t.Fatalf("responder NegotiateSAs: %v", r.err)
	}
	rSAs := r.sas

	// Cross-match: both peers must carry the same session master, and what the
	// initiator transmits to must be what the responder receives under, and vice
	// versa. With a shared master and matching SPIs, the (handler-side) derived
	// keys match by construction — deriveDirectional already asserted tx != rx on
	// the transient derived keys.
	if iSAs.Master != rSAs.Master {
		t.Fatal("peers derived different session masters")
	}
	if iSAs.TxSPI != rSAs.RxSPI || iSAs.RxSPI != rSAs.TxSPI {
		t.Fatal("SPIs did not cross-match between peers")
	}
	// Within each peer, tx and rx must differ (role partition).
	if iSAs.TxSPI == iSAs.RxSPI {
		t.Fatal("initiator tx and rx SPIs collided")
	}
	// And the derivation over the cross-matched inputs is byte-identical.
	iTx, err := DeriveSAKey(iSAs.Master[:], iSAs.TxSPI, iSAs.Version)
	if err != nil {
		t.Fatal(err)
	}
	rRx, err := DeriveSAKey(rSAs.Master[:], rSAs.RxSPI, rSAs.Version)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(iTx, rRx) {
		t.Fatal("initiator TX key != responder RX key")
	}
	if MasterKeyIndex(iSAs.TxSPI) != activeMasterKeyIndex {
		t.Fatalf("tx SPI selects master key %d, want %d", MasterKeyIndex(iSAs.TxSPI), activeMasterKeyIndex)
	}
}

func TestControlSessionRejectsUnpinnedPeer(t *testing.T) {
	idA, _ := GenerateIdentity()
	idB, _ := GenerateIdentity()
	imposter, _ := GenerateIdentity()

	srvConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	cliConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	defer srvConn.Close()
	defer cliConn.Close()

	// Responder pins `imposter`, but the initiator authenticates as idA.
	ln, err := Listen(srvConn, idB, imposter.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, _ = ln.Accept(ctx) }()

	// In TLS 1.3 mutual auth the client's handshake completes before the server
	// verifies the client certificate, so Dial may return a session even though
	// the responder will reject us. The security property is that we can never
	// NEGOTIATE with a peer that does not pin us: the SA-setup round-trip is the
	// mutual key-confirmation, and it must fail closed.
	sess, err := Dial(ctx, cliConn, ln.Addr(), idA, idB.PublicKey())
	if err != nil {
		return // rejected at dial — also acceptable
	}
	defer sess.Close()
	if _, err := sess.NegotiateSAs(ctx, AESGCM128); err == nil {
		t.Fatal("SA negotiation succeeded against a responder that pinned a different key")
	}
}
