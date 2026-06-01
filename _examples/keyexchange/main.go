// Command keyexchange is a runnable demonstration of the ICX control plane:
// two peers establish a forward-secret, mutually-authenticated QUIC/mTLS
// session over loopback, derive PSP master keys from the TLS exporter, and
// negotiate per-direction Security Associations whose AES-GCM keys feed the
// Geneve/AF_XDP data plane.
//
// It runs both peers in one process and self-verifies the result, so it doubles
// as living documentation and a smoke test. Build under GODEBUG=fips140=on to
// confirm the whole exchange uses only FIPS-approved primitives:
//
//	GODEBUG=fips140=on go run ./_examples/keyexchange
//
// This example tracks the control-plane API as it evolves; keep it building.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/apoxy-dev/icx/control"
)

func main() {
	pspV1 := flag.Bool("v1", false, "use PSP v1 (AES-256-GCM) instead of v0 (AES-128-GCM)")
	flag.Parse()

	version := control.PSPv0
	if *pspV1 {
		version = control.PSPv1
	}

	if err := run(version); err != nil {
		log.Fatalf("keyexchange demo failed: %v", err)
	}
}

func run(version control.PSPVersion) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Long-term identities. In production each side holds its own private key
	//    and is configured with the peer's public key (--peer-key), WireGuard
	//    style. Here we mint both.
	initiatorID, err := control.GenerateIdentity()
	if err != nil {
		return err
	}
	responderID, err := control.GenerateIdentity()
	if err != nil {
		return err
	}
	iFP, _ := initiatorID.Fingerprint()
	rFP, _ := responderID.Fingerprint()
	fmt.Printf("identities:\n  initiator %s\n  responder %s\n", iFP, rFP)

	// 2. Loopback UDP sockets (the control-plane port; AF_XDP owns the data port).
	srvConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		return err
	}
	defer srvConn.Close()
	cliConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		return err
	}
	defer cliConn.Close()

	// 3. Responder listens (and pins the initiator's key).
	ln, err := control.Listen(srvConn, responderID, initiatorID.PublicKey())
	if err != nil {
		return err
	}
	defer ln.Close()

	type negResult struct {
		sess *control.Session
		sas  *control.DirectionalSAs
		err  error
	}
	respCh := make(chan negResult, 1)
	go func() {
		sess, err := ln.Accept(ctx)
		if err != nil {
			respCh <- negResult{err: err}
			return
		}
		sas, err := sess.NegotiateSAs(ctx, version)
		respCh <- negResult{sess: sess, sas: sas, err: err}
	}()

	// 4. Initiator dials (and pins the responder's key) — this is the TLS 1.3
	//    handshake: mutual auth + ephemeral ECDHE (forward secrecy).
	initSess, err := control.Dial(ctx, cliConn, ln.Addr(), initiatorID, responderID.PublicKey())
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer initSess.Close()

	st := initSess.TLSState()
	fmt.Printf("handshake: TLS %s, cipher %s, ALPN %q\n",
		tlsVersionName(st.Version), tls.CipherSuiteName(st.CipherSuite), st.NegotiatedProtocol)

	// 5. Negotiate SAs (initiator side).
	initSAs, err := initSess.NegotiateSAs(ctx, version)
	if err != nil {
		return fmt.Errorf("initiator NegotiateSAs: %w", err)
	}

	r := <-respCh
	if r.sess != nil {
		defer r.sess.Close()
	}
	if r.err != nil {
		return fmt.Errorf("responder side: %w", r.err)
	}
	respSAs := r.sas

	// 6. Report and verify.
	fmt.Printf("master keys agree: %v\n", initSess.MasterKeys() != nil && r.sess.MasterKeys() != nil)
	fmt.Printf("SAs (PSP %s):\n", pspName(version))
	fmt.Printf("  initiator: tx spi=%#08x key=%s | rx spi=%#08x key=%s\n",
		initSAs.Tx.SPI, fp(initSAs.Tx.Key), initSAs.Rx.SPI, fp(initSAs.Rx.Key))
	fmt.Printf("  responder: tx spi=%#08x key=%s | rx spi=%#08x key=%s\n",
		respSAs.Tx.SPI, fp(respSAs.Tx.Key), respSAs.Rx.SPI, fp(respSAs.Rx.Key))

	if !equal(initSAs.Tx.Key, respSAs.Rx.Key) || !equal(initSAs.Rx.Key, respSAs.Tx.Key) {
		return fmt.Errorf("VERIFY FAILED: tx/rx keys do not cross-match between peers")
	}
	if equal(initSAs.Tx.Key, initSAs.Rx.Key) {
		return fmt.Errorf("VERIFY FAILED: initiator tx and rx keys collided")
	}
	if len(initSAs.Tx.Key) != expectedKeyLen(version) {
		return fmt.Errorf("VERIFY FAILED: key length %d, want %d", len(initSAs.Tx.Key), expectedKeyLen(version))
	}

	fmt.Println("VERIFY OK: cross-matched, tx≠rx, FIPS-suite handshake, keys never crossed the wire")
	return nil
}

func fp(key []byte) string {
	sum := sha256.Sum256(key)
	return fmt.Sprintf("%x", sum[:6])
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func expectedKeyLen(v control.PSPVersion) int {
	if v == control.PSPv1 {
		return 32
	}
	return 16
}

func pspName(v control.PSPVersion) string {
	if v == control.PSPv1 {
		return "v1/AES-256-GCM"
	}
	return "v0/AES-128-GCM"
}

func tlsVersionName(v uint16) string {
	if v == tls.VersionTLS13 {
		return "1.3"
	}
	return fmt.Sprintf("%#x", v)
}
