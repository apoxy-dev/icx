// Package psp implements the PSP-model cryptographic primitives shared by the
// icx data plane (package icx) and the key-establishment control plane
// (package control): the NIST SP 800-108 / AES-CMAC key-derivation function
// from the PSP Architecture Specification, and the SPI bit layout that
// partitions the derivation space by master key and allocating role.
//
// The package is a stdlib-only leaf so the data-plane handler can derive its
// own security-association keys without importing the control plane (and its
// QUIC/x509 dependency tree).
package psp

import (
	"encoding/binary"
	"fmt"
)

// ICXVersion is an AEAD cipher-suite codepoint for an SA. It selects both the
// AEAD (AES-GCM-128 vs AES-GCM-256) and, via the KDF label, the size of the
// derived security-association key. It is a local cipher selector, not a
// wire-format version (that is ProtocolVersion in the control plane).
type ICXVersion uint8

const (
	// AESGCM128 selects AES-GCM-128: a 16-byte SA key. The ICX default (zero
	// churn to the [16]byte data plane).
	AESGCM128 ICXVersion = 0
	// AESGCM256 selects AES-GCM-256: a 32-byte SA key. The CNSA / 256-bit path.
	AESGCM256 ICXVersion = 1
)

// MasterKeyLen is the required length of a PSP master key (256 bits). PSP
// master keys are always AES-256 keys regardless of the SA key size.
const MasterKeyLen = 32

// NumMasterKeys is the PSP master-key count: one active, one retained for
// in-flight SAs during rotation (the MSB of the SPI selects between them).
const NumMasterKeys = 2

// label returns the 4-byte SP 800-108 label for the version: "Pv0\0"
// (0x50 0x76 0x30 0x00) for v0, "Pv1\0" for v1. The trailing NUL also serves as
// the SP 800-108 label/context separator. Per the spec, the version number may
// be OR'd into the third byte of the base label.
func (v ICXVersion) label() [4]byte {
	return [4]byte{0x50, 0x76, 0x30 | byte(v), 0x00}
}

// Valid reports whether v is a supported cipher suite. Callers must reject
// unsupported versions before deriving keys (fail-closed), so KeyLen/label are
// never asked to map an unknown version.
func (v ICXVersion) Valid() bool { return v == AESGCM128 || v == AESGCM256 }

// KeyLen returns the derived SA key length in bytes for the version: 16 for
// AESGCM128, 32 for AESGCM256. Only valid versions reach the KDF (guarded by
// DeriveSAKey).
func (v ICXVersion) KeyLen() int {
	if v == AESGCM256 {
		return 32
	}
	return 16
}

// DeriveSAKey derives a PSP security-association key from a 256-bit master key
// and a 32-bit SPI, exactly per the PSP Architecture Specification: a NIST
// SP 800-108 counter-mode KDF whose PRF is AES-CMAC (see cmac.go). Each PRF
// input block is the 16-byte concatenation
//
//	counter(4) || label(4) || context=SPI(4) || length-in-bits(4)
//
// all in network byte order. A 128-bit key needs one block (counter=1); a
// 256-bit key needs two (counter=1, counter=2) concatenated.
//
// The caller is responsible for selecting which master key to pass based on the
// SPI's most-significant bit (the PSP master-key selector); the SPI is fed into
// the KDF context verbatim, MSB included, so the derivation is bound to it.
func DeriveSAKey(masterKey []byte, spi uint32, v ICXVersion) ([]byte, error) {
	if len(masterKey) != MasterKeyLen {
		return nil, fmt.Errorf("psp: master key must be %d bytes, got %d", MasterKeyLen, len(masterKey))
	}
	if !v.Valid() {
		return nil, fmt.Errorf("psp: unsupported cipher suite %d", v)
	}

	keyLen := v.KeyLen()
	bitLen := uint32(keyLen * 8)
	label := v.label()
	blocks := (keyLen + 15) / 16

	out := make([]byte, 0, blocks*16)
	for i := 1; i <= blocks; i++ {
		var in [16]byte
		binary.BigEndian.PutUint32(in[0:4], uint32(i)) // counter
		copy(in[4:8], label[:])                        // label
		binary.BigEndian.PutUint32(in[8:12], spi)      // context = SPI
		binary.BigEndian.PutUint32(in[12:16], bitLen)  // length (bits)
		mac, err := aesCMAC(masterKey, in[:])
		if err != nil {
			return nil, err
		}
		out = append(out, mac...)
	}
	return out[:keyLen], nil
}
