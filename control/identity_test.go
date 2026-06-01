package control

import (
	"testing"
)

func TestIdentityPrivatePEMRoundTrip(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := id.MarshalPrivatePEM()
	if err != nil {
		t.Fatal(err)
	}
	got, err := LoadIdentityPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !PublicKeyEqual(id.PublicKey(), got.PublicKey()) {
		t.Fatal("round-tripped identity public key differs")
	}
}

func TestPublicKeyStringRoundTrip(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	s, err := id.PublicKeyString()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(s)
	if err != nil {
		t.Fatal(err)
	}
	if !PublicKeyEqual(id.PublicKey(), pub) {
		t.Fatal("parsed peer key differs from original")
	}
}

func TestParsePublicKeyRejectsGarbage(t *testing.T) {
	if _, err := ParsePublicKey("not-base64!!"); err == nil {
		t.Fatal("expected error for non-base64 peer key")
	}
	if _, err := ParsePublicKey("aGVsbG8="); err == nil { // valid base64, not a key
		t.Fatal("expected error for non-SPKI peer key")
	}
}

func TestTLSCertificatePinsIdentityKey(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := id.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil {
		t.Fatal("expected parsed Leaf on tls.Certificate")
	}
	// The leaf's public key must equal the identity's, so a pin against the
	// identity key matches the certificate presented during the handshake.
	if !id.PublicKey().Equal(cert.Leaf.PublicKey) {
		t.Fatal("leaf certificate public key does not match identity")
	}
}

func TestDistinctIdentitiesDiffer(t *testing.T) {
	a, _ := GenerateIdentity()
	b, _ := GenerateIdentity()
	if PublicKeyEqual(a.PublicKey(), b.PublicKey()) {
		t.Fatal("two generated identities must not collide")
	}
	fa, _ := a.Fingerprint()
	fb, _ := b.Fingerprint()
	if fa == fb || fa == "" {
		t.Fatalf("fingerprints should be distinct and non-empty: %q %q", fa, fb)
	}
}
