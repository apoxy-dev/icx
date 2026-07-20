// Package control implements ICX's key-establishment control plane (a QUIC/mTLS
// channel) and the PSP-model key derivation that turns an authenticated,
// forward-secret session into per-Security-Association AEAD keys for the
// existing Geneve/AF_XDP data plane.
//
// The cryptographic primitives (SP 800-108/AES-CMAC KDF and the SPI bit
// layout) live in the stdlib-only leaf package psp, shared with the data-plane
// handler; this package re-exports them so its API is unchanged.
package control

import "github.com/apoxy-dev/icx/psp"

// ICXVersion is an AEAD cipher-suite codepoint for an SA. See psp.ICXVersion.
type ICXVersion = psp.ICXVersion

const (
	// AESGCM128 selects AES-GCM-128: a 16-byte SA key. The ICX default.
	AESGCM128 = psp.AESGCM128
	// AESGCM256 selects AES-GCM-256: a 32-byte SA key. The CNSA / 256-bit path.
	AESGCM256 = psp.AESGCM256
)

// MasterKeyLen is the required length of a PSP master key (256 bits).
const MasterKeyLen = psp.MasterKeyLen

// DeriveSAKey derives a PSP security-association key from a 256-bit master key
// and a 32-bit SPI per the PSP Architecture Specification. See psp.DeriveSAKey.
func DeriveSAKey(masterKey []byte, spi uint32, v ICXVersion) ([]byte, error) {
	return psp.DeriveSAKey(masterKey, spi, v)
}
