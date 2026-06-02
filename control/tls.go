package control

import (
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
)

// ALPN is the application-layer protocol name negotiated on the ICX control
// channel. A mismatch (e.g. a stray TLS client) fails the handshake.
const ALPN = "icx-ctrl/1"

// exporterLabel is the RFC 5705 / RFC 8446 §7.5 exporter label used to derive
// the data-plane master-key seed from the completed TLS 1.3 handshake. Changing
// it is a breaking protocol change.
const exporterLabel = "EXPORTER-icx-master-v1"

// exporterContext domain-separates the master-key seed from any other exporter
// use on the same connection.
var exporterContext = []byte("icx control plane master seed v1")

// RootSecretLen is the length of the exported master-key seed (256-bit).
const RootSecretLen = 32

// pinVerifier returns a tls.Config.VerifyConnection callback that authenticates
// the peer WireGuard-style: the leaf certificate's public key must equal the
// pinned peer identity key. Chain/CA/hostname validation is intentionally not
// used (the certificates are self-signed); pinning is the whole trust model.
func pinVerifier(peerPub *ecdsa.PublicKey) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("control: peer presented no certificate")
		}
		leafPub, ok := cs.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("control: peer certificate key is not ECDSA")
		}
		if !leafPub.Equal(peerPub) {
			return errors.New("control: peer key pin mismatch")
		}
		return nil
	}
}

// baseTLSConfig builds the shared TLS 1.3 configuration: our self-signed
// identity certificate, the pinned-peer verifier, TLS 1.3 only, the ICX ALPN,
// and FIPS-approved curves. In a fips140=on build the module further restricts
// the suite to AES-GCM + SHA-2 and disables X25519/ChaCha automatically, so the
// whole handshake stays inside the validated boundary.
func baseTLSConfig(local *Identity, peerPub *ecdsa.PublicKey) (*tls.Config, error) {
	if local == nil || peerPub == nil {
		return nil, errors.New("control: local identity and peer key are required")
	}
	cert, err := local.TLSCertificate()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		NextProtos:       []string{ALPN},
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384},
		VerifyConnection: pinVerifier(peerPub),
		// Disable TLS 1.3 session resumption (and therefore 0-RTT). Every (re)connect
		// MUST be a full ECDHE handshake so each session derives FRESH master keys: that
		// freshness is the data plane's nonce-uniqueness foundation (the per-direction
		// install guard accepts a reset/regressed SPI precisely because its key is fresh
		// — see handler.UpdateVirtualNetworkSAs). A resumed session could reuse keying
		// material and, paired with a reset SPI, repeat a (key, nonce) pair. The server
		// also never issues tickets; newSession additionally asserts !DidResume/!0-RTT.
		SessionTicketsDisabled: true,
	}, nil
}

// ServerTLSConfig builds the responder side of the control-plane mTLS: it
// requires (and pins) a client certificate.
func ServerTLSConfig(local *Identity, peerPub *ecdsa.PublicKey) (*tls.Config, error) {
	cfg, err := baseTLSConfig(local, peerPub)
	if err != nil {
		return nil, err
	}
	// Accept any presented client cert at the chain layer; pinVerifier (run via
	// VerifyConnection) is what actually authenticates it.
	cfg.ClientAuth = tls.RequireAnyClientCert
	return cfg, nil
}

// ClientTLSConfig builds the initiator side of the control-plane mTLS.
func ClientTLSConfig(local *Identity, peerPub *ecdsa.PublicKey) (*tls.Config, error) {
	cfg, err := baseTLSConfig(local, peerPub)
	if err != nil {
		return nil, err
	}
	// InsecureSkipVerify disables ONLY the default CA-chain/hostname checks, which
	// are meaningless for a self-signed, pinned peer. It does NOT disable peer
	// authentication: VerifyConnection (pinVerifier) still runs and fully
	// authenticates the peer by its pinned public key. Without this flag the
	// handshake would fail on the absent CA chain before pinning could run.
	cfg.InsecureSkipVerify = true
	cfg.ServerName = "icx"
	return cfg, nil
}

// ExportRootSecret derives the 32-byte data-plane master-key seed from a
// completed TLS 1.3 handshake via the RFC 8446 exporter. Both peers compute the
// identical value; it is the forward-secret root the PSP master keys are seeded
// from (see keys.go). It must only be called after the handshake completes.
func ExportRootSecret(cs tls.ConnectionState) ([]byte, error) {
	if cs.Version != tls.VersionTLS13 {
		return nil, fmt.Errorf("control: refusing to export from TLS version %#x (want 1.3)", cs.Version)
	}
	secret, err := cs.ExportKeyingMaterial(exporterLabel, exporterContext, RootSecretLen)
	if err != nil {
		return nil, fmt.Errorf("control: export keying material: %w", err)
	}
	return secret, nil
}
