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

// PeerAuthorizer authenticates a connecting peer by its identity public key.
// It runs inside the TLS handshake (VerifyConnection); a non-nil error fails
// the handshake before any session state exists. Implementations must be safe
// for concurrent use — a multi-peer listener runs one handshake per inbound
// peer.
type PeerAuthorizer func(peerPub *ecdsa.PublicKey) error

// PinnedPeer returns a PeerAuthorizer that accepts exactly one peer key — the
// WireGuard-style 1:1 trust model used by the symmetric tunnel.
func PinnedPeer(peerPub *ecdsa.PublicKey) PeerAuthorizer {
	return func(leafPub *ecdsa.PublicKey) error {
		if !leafPub.Equal(peerPub) {
			return errors.New("control: peer key pin mismatch")
		}
		return nil
	}
}

// authVerifier returns a tls.Config.VerifyConnection callback that extracts
// the leaf certificate's ECDSA key and hands it to authorize. Chain/CA/
// hostname validation is intentionally not used (the certificates are
// self-signed); identity-key authorization is the whole trust model.
func authVerifier(authorize PeerAuthorizer) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("control: peer presented no certificate")
		}
		leafPub, ok := cs.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("control: peer certificate key is not ECDSA")
		}
		return authorize(leafPub)
	}
}

// baseTLSConfig builds the shared TLS 1.3 configuration: our self-signed
// identity certificate, the peer authorizer, TLS 1.3 only, the ICX ALPN,
// and FIPS-approved curves. In a fips140=on build the module further restricts
// the suite to AES-GCM + SHA-2 and disables X25519/ChaCha automatically, so the
// whole handshake stays inside the validated boundary.
func baseTLSConfig(local *Identity, authorize PeerAuthorizer) (*tls.Config, error) {
	if local == nil || authorize == nil {
		return nil, errors.New("control: local identity and peer authorizer are required")
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
		VerifyConnection: authVerifier(authorize),
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
	if peerPub == nil {
		return nil, errors.New("control: peer key is required")
	}
	return ServerTLSConfigAuth(local, PinnedPeer(peerPub))
}

// ServerTLSConfigAuth builds a multi-peer responder mTLS config: any client
// whose identity key passes authorize may complete the handshake. This is the
// key-plane trust model (one responder, many authorized initiators), vs
// ServerTLSConfig's 1:1 pinned tunnel.
func ServerTLSConfigAuth(local *Identity, authorize PeerAuthorizer) (*tls.Config, error) {
	cfg, err := baseTLSConfig(local, authorize)
	if err != nil {
		return nil, err
	}
	// Accept any presented client cert at the chain layer; authVerifier (run via
	// VerifyConnection) is what actually authenticates it.
	cfg.ClientAuth = tls.RequireAnyClientCert
	return cfg, nil
}

// ClientTLSConfig builds the initiator side of the control-plane mTLS.
func ClientTLSConfig(local *Identity, peerPub *ecdsa.PublicKey) (*tls.Config, error) {
	if peerPub == nil {
		return nil, errors.New("control: peer key is required")
	}
	cfg, err := baseTLSConfig(local, PinnedPeer(peerPub))
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
