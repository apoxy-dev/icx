// Package control implements ICX's key-establishment control plane (a QUIC/mTLS
// channel) and the PSP-model key derivation that turns an authenticated,
// forward-secret session into per-Security-Association AEAD keys for the
// existing Geneve/AF_XDP data plane.
//
// This file implements AES-CMAC (NIST SP 800-38B / RFC 4493), the
// pseudorandom function underlying the PSP SP 800-108 key-derivation function
// (see kdf.go). CMAC is built directly on the FIPS-validated crypto/aes block
// cipher so the whole derivation stays inside the Go FIPS 140-3 module.
package control

import (
	"crypto/aes"
	"crypto/cipher"
)

// cmacRb is the GF(2^128) reduction constant for a 128-bit block (RFC 4493 §2.3).
const cmacRb = 0x87

// aesCMAC computes the AES-CMAC of msg under key k. k must be a valid AES key
// (16, 24, or 32 bytes); the PSP KDF always uses a 32-byte (AES-256) master
// key. The tag is always 16 bytes (the AES block size).
func aesCMAC(k, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cmacWithBlock(block, msg), nil
}

// cmacWithBlock computes AES-CMAC using a pre-constructed block cipher.
func cmacWithBlock(block cipher.Block, msg []byte) []byte {
	const bs = aes.BlockSize // 16

	// Subkey generation (RFC 4493 §2.3): L = AES_K(0^128); K1 = dbl(L);
	// K2 = dbl(K1).
	l := make([]byte, bs)
	block.Encrypt(l, l)
	k1 := dbl(l)
	k2 := dbl(k1)

	// Determine the number of blocks and whether the final block is complete.
	n := (len(msg) + bs - 1) / bs
	lastComplete := n != 0 && len(msg)%bs == 0
	if n == 0 {
		n = 1 // empty message uses a single (padded) block
	}

	// Final block: XOR with K1 if the last block is complete, else pad with
	// 10* and XOR with K2.
	last := make([]byte, bs)
	if lastComplete {
		xorInto(last, msg[(n-1)*bs:], k1)
	} else {
		rem := msg[(n-1)*bs:]
		copy(last, rem)
		last[len(rem)] = 0x80
		xorInto(last, last, k2)
	}

	// CBC-MAC chain over all but the last block, then the final block.
	x := make([]byte, bs)
	y := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		xorInto(y, x, msg[i*bs:(i+1)*bs])
		block.Encrypt(x, y)
	}
	xorInto(y, x, last)
	block.Encrypt(x, y)
	return x
}

// dbl performs the GF(2^128) left-shift-and-reduce used in CMAC subkey
// generation: out = (in << 1), XOR'd with Rb if the high bit of in was set.
func dbl(in []byte) []byte {
	out := make([]byte, len(in))
	var carry byte
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	if carry != 0 {
		out[len(out)-1] ^= cmacRb
	}
	return out
}

// xorInto writes a XOR b into dst. dst, a, and b must be the same length.
func xorInto(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}
