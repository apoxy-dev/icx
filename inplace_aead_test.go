package icx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// These tests prove the one irreducible security property the shared-UMEM
// zero-copy datapath depends on: that performing AES-GCM Open/Seal *in place*
// — with the destination slice aliasing the source at the SAME start offset —
// produces byte-for-byte identical output to the cross-buffer calls the handler
// uses today.
//
// Why this matters: today PhyToVirt/VirtToPhy decrypt/encrypt from one frame
// (UMEM) into a different frame, so dst and src never alias. The zero-copy
// datapath shares one UMEM frame between the phy and virt sockets, so the
// transform must operate within a single frame: Open writes plaintext over the
// ciphertext, Seal writes ciphertext over the plaintext. Go's crypto/cipher GCM
// permits this ONLY for exact overlap (dst and src share a start pointer) and
// panics ("invalid buffer overlap") for inexact overlap. Getting the offset
// wrong by even one byte is therefore not a silent corruption — it is a panic —
// but a wrong-but-aligned offset could silently produce different bytes, so we
// assert byte equality, not just "no panic".
//
// The frame layout mirrors the handler exactly: additionalData (the marshalled
// Geneve header prefix) sits immediately before the ciphertext in the same
// buffer, and dst is taken as buf[ctStart:ctStart] (zero-length, same start as
// the ciphertext). See handler.go PhyToVirt/VirtToPhy.

func newTestGCM(t *testing.T) cipher.AEAD {
	t.Helper()
	key := make([]byte, 16) // AES-128, as icx uses
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return gcm
}

// makeNonce builds a 12-byte GCM nonce of the shape the handler uses: a 4-byte
// prefix (unused-by-us) plus an 8-byte big-endian TX counter.
func makeNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// TestInPlaceSealMatchesCrossBuffer proves Seal with dst aliasing the plaintext
// (the encap case) equals the cross-buffer Seal used today.
func TestInPlaceSealMatchesCrossBuffer(t *testing.T) {
	gcm := newTestGCM(t)
	const hdrLen = 16 // stand-in for a marshalled Geneve header (the AEAD aad)

	for _, ptLen := range []int{0, 1, 16, 17, 1280, 1400, 1450} {
		plaintext := make([]byte, ptLen)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatalf("rand plaintext: %v", err)
		}
		aad := make([]byte, hdrLen)
		if _, err := rand.Read(aad); err != nil {
			t.Fatalf("rand aad: %v", err)
		}
		nonce := makeNonce(42)

		// Reference: cross-buffer Seal into a fresh dst (today's call shape:
		// Seal(payload[hdrLen:hdrLen], nonce, ipPacket, payload[:hdrLen])).
		want := gcm.Seal(nil, nonce, plaintext, aad)

		// In-place: a single frame holding [aad][plaintext] contiguously, with
		// room to the right for the 16-byte tag. dst = frame[ctStart:ctStart]
		// aliases the plaintext at the same start offset.
		frame := make([]byte, hdrLen+ptLen+gcm.Overhead())
		copy(frame[:hdrLen], aad)
		copy(frame[hdrLen:hdrLen+ptLen], plaintext)
		ctStart := hdrLen
		got := gcm.Seal(frame[ctStart:ctStart], nonce, frame[ctStart:ctStart+ptLen], frame[:hdrLen])

		if !bytes.Equal(got, want) {
			t.Fatalf("ptLen=%d: in-place Seal != cross-buffer Seal\n in-place=%x\n cross   =%x", ptLen, got, want)
		}
		// The aad region must be untouched by Seal.
		if !bytes.Equal(frame[:hdrLen], aad) {
			t.Fatalf("ptLen=%d: Seal clobbered the aad/header region", ptLen)
		}
	}
}

// TestInPlaceOpenMatchesCrossBuffer proves Open with dst aliasing the ciphertext
// (the decap case) equals the cross-buffer Open used today.
func TestInPlaceOpenMatchesCrossBuffer(t *testing.T) {
	gcm := newTestGCM(t)
	const hdrLen = 16

	for _, ptLen := range []int{0, 1, 16, 17, 1280, 1400, 1450} {
		plaintext := make([]byte, ptLen)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatalf("rand plaintext: %v", err)
		}
		aad := make([]byte, hdrLen)
		if _, err := rand.Read(aad); err != nil {
			t.Fatalf("rand aad: %v", err)
		}
		nonce := makeNonce(7)
		ciphertext := gcm.Seal(nil, nonce, plaintext, aad) // ptLen + tag

		// Reference: cross-buffer Open into a fresh dst.
		want, err := gcm.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			t.Fatalf("ptLen=%d: reference Open failed: %v", ptLen, err)
		}

		// In-place: frame holds [aad][ciphertext]; dst aliases the ciphertext.
		frame := make([]byte, hdrLen+len(ciphertext))
		copy(frame[:hdrLen], aad)
		copy(frame[hdrLen:], ciphertext)
		ctStart := hdrLen
		got, err := gcm.Open(frame[ctStart:ctStart], nonce, frame[ctStart:ctStart+len(ciphertext)], frame[:hdrLen])
		if err != nil {
			t.Fatalf("ptLen=%d: in-place Open failed: %v", ptLen, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("ptLen=%d: in-place Open != cross-buffer Open\n in-place=%x\n cross   =%x", ptLen, got, want)
		}
		if !bytes.Equal(frame[:hdrLen], aad) {
			t.Fatalf("ptLen=%d: Open clobbered the aad/header region", ptLen)
		}
	}
}

// TestInPlaceRoundTrip proves Open(Seal(x)) == x entirely in place within one
// frame, across randomized sizes — the end-to-end encap-then-decap path the
// zero-copy forwarder will exercise.
func TestInPlaceRoundTrip(t *testing.T) {
	gcm := newTestGCM(t)
	const hdrLen = 8

	for i := 0; i < 256; i++ {
		ptLen := i * 7 % 1500
		plaintext := make([]byte, ptLen)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatalf("rand plaintext: %v", err)
		}
		orig := append([]byte(nil), plaintext...)
		aad := make([]byte, hdrLen)
		if _, err := rand.Read(aad); err != nil {
			t.Fatalf("rand aad: %v", err)
		}
		nonce := makeNonce(uint64(i))

		// Frame: [aad][plaintext][tag headroom].
		frame := make([]byte, hdrLen+ptLen+gcm.Overhead())
		copy(frame[:hdrLen], aad)
		copy(frame[hdrLen:hdrLen+ptLen], plaintext)
		ctStart := hdrLen

		sealed := gcm.Seal(frame[ctStart:ctStart], nonce, frame[ctStart:ctStart+ptLen], frame[:hdrLen])
		opened, err := gcm.Open(frame[ctStart:ctStart], nonce, frame[ctStart:ctStart+len(sealed)], frame[:hdrLen])
		if err != nil {
			t.Fatalf("i=%d ptLen=%d: in-place round-trip Open failed: %v", i, ptLen, err)
		}
		if !bytes.Equal(opened, orig) {
			t.Fatalf("i=%d ptLen=%d: round-trip mismatch", i, ptLen)
		}
	}
}

// TestInexactOverlapPanics documents the boundary the offset math must respect:
// an Open/Seal whose dst is offset by one byte from the source (inexact overlap)
// panics. This guards against a future refactor that shifts the in-place offset
// off the source start — it would fail loudly here rather than silently in the
// datapath.
func TestInexactOverlapPanics(t *testing.T) {
	gcm := newTestGCM(t)
	const hdrLen = 8
	plaintext := make([]byte, 64)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand: %v", err)
	}
	aad := make([]byte, hdrLen)
	nonce := makeNonce(1)
	ct := gcm.Seal(nil, nonce, plaintext, aad)

	frame := make([]byte, hdrLen+len(ct)+8)
	copy(frame[hdrLen:], ct)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected a panic for inexact (off-by-one) overlap, got none")
		}
	}()
	// dst starts one byte AFTER the ciphertext start: inexact overlap → panic.
	_, _ = gcm.Open(frame[hdrLen+1:hdrLen+1], nonce, frame[hdrLen:hdrLen+len(ct)], aad)
}
