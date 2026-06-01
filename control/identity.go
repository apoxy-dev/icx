package control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// Identity is a node's long-term signing key used to mutually authenticate the
// QUIC/mTLS control channel. It is an ECDSA P-256 key: a FIPS 186-approved
// signature algorithm in the Go FIPS 140-3 module, and a curve TLS 1.3 will use
// in FIPS mode. Peers authenticate each other WireGuard-style — by pinning the
// expected public key — rather than via a CA, so identities are self-signed.
//
// Note this signing key is distinct from the ephemeral ECDHE that TLS performs
// for forward secrecy; the identity only proves "who", the handshake provides
// the fresh per-session secret.
type Identity struct {
	priv *ecdsa.PrivateKey
}

// identityCertValidity is how long the self-signed identity certificate is
// nominally valid. Pinning ignores CA chains and (with the custom verifier)
// time validity, but a sane window keeps stricter stacks happy.
const identityCertValidity = 100 * 365 * 24 * time.Hour

// GenerateIdentity creates a fresh ECDSA P-256 identity using crypto/rand.
func GenerateIdentity() (*Identity, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("control: generate identity: %w", err)
	}
	return &Identity{priv: priv}, nil
}

// MarshalPrivatePEM encodes the identity private key as a PKCS#8 PEM block,
// suitable for writing to a 0600 key file.
func (id *Identity) MarshalPrivatePEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(id.priv)
	if err != nil {
		return nil, fmt.Errorf("control: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadIdentityPEM parses a PKCS#8 PEM private key produced by MarshalPrivatePEM.
// It rejects anything that is not an ECDSA P-256 key.
func LoadIdentityPEM(pemBytes []byte) (*Identity, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("control: no PEM block in identity key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("control: parse identity key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("control: identity key must be ECDSA P-256")
	}
	return &Identity{priv: priv}, nil
}

// PublicKey returns the identity's public key.
func (id *Identity) PublicKey() *ecdsa.PublicKey {
	return &id.priv.PublicKey
}

// PublicKeyString returns the base64(SPKI DER) encoding of the public key. This
// is the value distributed to peers and supplied via --peer-key (analogous to a
// WireGuard public key).
func (id *Identity) PublicKeyString() (string, error) {
	return MarshalPublicKey(&id.priv.PublicKey)
}

// Fingerprint returns a short, stable identifier for the public key:
// base64(SHA-256(SPKI DER)). Used as the certificate subject and in logs.
func (id *Identity) Fingerprint() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&id.priv.PublicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// MarshalPublicKey encodes a public key as base64(SPKI DER).
func MarshalPublicKey(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("control: marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// ParsePublicKey decodes a base64(SPKI DER) public key (the --peer-key value)
// and verifies it is ECDSA P-256.
func ParsePublicKey(s string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("control: decode peer key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("control: parse peer key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("control: peer key must be ECDSA P-256")
	}
	return ec, nil
}

// TLSCertificate builds a self-signed leaf certificate for this identity, for
// use as the local end of the mTLS handshake. Authentication is by key pinning,
// not by chain validation, so the certificate is its own issuer.
func (id *Identity) TLSCertificate() (tls.Certificate, error) {
	fp, err := id.Fingerprint()
	if err != nil {
		return tls.Certificate{}, err
	}
	// A fixed serial is fine: the cert is never chained or revoked, only pinned.
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "icx:" + fp},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(identityCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &id.priv.PublicKey, id.priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("control: create self-signed cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("control: parse self-signed cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  id.priv,
		Leaf:        leaf,
	}, nil
}

// PublicKeyEqual reports whether two ECDSA public keys are identical.
func PublicKeyEqual(a, b *ecdsa.PublicKey) bool {
	return a != nil && b != nil && a.Equal(b)
}
