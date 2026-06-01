package control

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestAESCMAC_RFC4493 validates the AES-CMAC PRF against the canonical RFC 4493
// (= NIST SP 800-38B) test vectors: empty, one full block, a partial final
// block, and a multi-block message.
func TestAESCMAC_RFC4493(t *testing.T) {
	key := unhex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	const (
		b1      = "6bc1bee22e409f96e93d7e117393172a"
		b2      = "ae2d8a571e03ac9c9eb76fac45af8e51"
		b3      = "30c81c46a35ce411e5fbc1191a0a52ef"
		b4      = "f69f2445df4f9b17ad2b417be66c3710"
		b3part8 = "30c81c46a35ce411" // first 8 bytes of b3 (40-byte message)
	)
	cases := []struct {
		name, msg, want string
	}{
		{"len0", "", "bb1d6929e95937287fa37d129b756746"},
		{"len16", b1, "070a16b46b4d4144f79bdd9dd04a287c"},
		{"len40", b1 + b2 + b3part8, "dfa66747de9ae63030ca32611497c827"},
		{"len64", b1 + b2 + b3 + b4, "51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := aesCMAC(key, unhex(t, c.msg))
			if err != nil {
				t.Fatal(err)
			}
			if want := unhex(t, c.want); !bytes.Equal(got, want) {
				t.Fatalf("CMAC mismatch\n got %x\nwant %x", got, want)
			}
		})
	}
}

// TestDeriveSAKey_PSPSpec validates the SP 800-108 KDF against the worked
// examples in the PSP Architecture Specification ("Examples of key
// derivation", p.7).
func TestDeriveSAKey_PSPSpec(t *testing.T) {
	k0 := unhex(t, "34448a064292601b11a0978f56a2d34cf3fc35ede1a6bc04f8db3e5243a2b0ca")
	k1 := unhex(t, "563952565d3a78ae773ec1b779f2f2d99f4a7f53a6fbb9b07d5b71f39364d739")

	cases := []struct {
		name    string
		master  []byte
		spi     uint32
		version PSPVersion
		want    string
	}{
		{
			name: "v0_spi_12345678_mk0", master: k0, spi: 0x12345678, version: PSPv0,
			want: "96c22dc799198090b74b70ae468e4e30",
		},
		{
			// MSB set -> master key 1 selected by the caller.
			name: "v0_spi_9A345678_mk1", master: k1, spi: 0x9A345678, version: PSPv0,
			want: "3946da2554eae46ad1ef77a64372edc4",
		},
		{
			name: "v1_spi_12345678_mk0", master: k0, spi: 0x12345678, version: PSPv1,
			want: "2b7d72074e42ca334487f2990e3f8c4037e436f38283449b76463e9b7fb2e3de",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DeriveSAKey(c.master, c.spi, c.version)
			if err != nil {
				t.Fatal(err)
			}
			if want := unhex(t, c.want); !bytes.Equal(got, want) {
				t.Fatalf("SA key mismatch\n got %x\nwant %x", got, want)
			}
			if len(got) != c.version.keyLen() {
				t.Fatalf("key length = %d, want %d", len(got), c.version.keyLen())
			}
		})
	}
}

func TestDeriveSAKey_BadMasterKeyLen(t *testing.T) {
	if _, err := DeriveSAKey(make([]byte, 16), 1, PSPv0); err == nil {
		t.Fatal("expected error for 16-byte master key, got nil")
	}
}

func TestDeriveSAKey_UnsupportedVersionFailsClosed(t *testing.T) {
	mk := make([]byte, MasterKeyLen)
	if _, err := DeriveSAKey(mk, 1, PSPVersion(7)); err == nil {
		t.Fatal("expected error for unsupported PSP version, got nil (must fail closed, not default to 16 bytes)")
	}
}
