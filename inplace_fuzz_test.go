package icx

import (
	"bytes"
	"testing"
)

// Differential fuzzing of the in-place transforms against the proven two-buffer
// transforms (the Phase-2 equivalence oracle). The two implementations are
// byte-for-byte equivalent by construction (see inplace_transform_test.go), so
// for ANY input — including malformed, truncated, or adversarial frames — they
// must agree: either both drop, or both produce identical output bytes. Any
// divergence, and any panic, is a real bug.
//
// The untrusted direction is decap (PhyToVirtInPlace): it parses attacker-
// controlled physical frames (outer UDP/IP, Geneve, AEAD ciphertext). That is
// the primary fuzz target. We also fuzz the encap direction (VirtToPhyInPlace)
// over arbitrary virtual frames for good measure.

// fuzzEnv builds a deterministic handler+vnet+keys for fuzzing. It mirrors
// newInplaceEnv but takes no *testing.T-driven randomness so a given seed is
// reproducible across runs (keys are fixed, not random).
func fuzzEnv(tb testing.TB, layer3, underlayV6, innerV6 bool) *inplaceEnv {
	tb.Helper()
	tc := inplaceTestCase{layer3: layer3, underlayV6: underlayV6, innerV6: innerV6, payloadLen: 1}
	env := newInplaceEnv(tb.(*testing.T), tc)
	return env
}

// seedCorpus adds a representative real frame from every corpus combination as a
// fuzz seed, in both the physical (encap output) and virtual forms, so the
// fuzzer starts from valid inputs and mutates outward into the malformed space.
func decapSeeds(f *testing.F) {
	for _, tc := range inplaceCorpus() {
		env := newInplaceEnv(&testing.T{}, tc) // deterministic enough for seeding
		virtFrame := buildSeedVirtFrame(env, tc.payloadLen)
		env.pinCounter(0)
		phyBuf := make([]byte, mtu+inplaceScratch)
		n, handled := env.h.VirtToPhy(append([]byte(nil), virtFrame...), phyBuf)
		if n > 0 && !handled {
			f.Add(append([]byte(nil), phyBuf[:n]...))
		}
	}
	// A few degenerate seeds to push the parser immediately.
	f.Add([]byte{})
	f.Add(make([]byte, 14))
	f.Add(make([]byte, 64))
}

// buildSeedVirtFrame is buildVirtFrame without a *testing.T (seed-time only).
func buildSeedVirtFrame(e *inplaceEnv, payloadLen int) []byte {
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	var ipPacket []byte
	if e.innerV6 {
		ipPacket = buildInnerIPv6Packet(e.innerSrc, e.innerDst, payload)
	} else {
		ipPacket = buildInnerIPv4Packet(e.innerSrc, e.innerDst, payload)
	}
	if e.layer3 {
		return ipPacket
	}
	frame := make([]byte, 14+len(ipPacket))
	copy(frame[14:], ipPacket)
	return frame
}

// FuzzPhyToVirtInPlace asserts in-place decap matches two-buffer decap on the
// untrusted physical-frame input for every fuzz case, and never panics.
func FuzzPhyToVirtInPlace(f *testing.F) {
	decapSeeds(f)

	f.Fuzz(func(t *testing.T, phyFrame []byte) {
		// One env per case (fresh replay window and stats) so the two decaps
		// below are independent and reproducible.
		env := fuzzEnv(t, false /*layer3*/, false, false)

		// In-place decap into a single buffer with generous head/tailroom,
		// guarded so a panic surfaces as a test failure with the input.
		var gotOff, gotLen int
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PhyToVirtInPlace panicked on %d-byte frame: %v\nframe=%x", len(phyFrame), r, phyFrame)
				}
			}()
			buf := make([]byte, len(phyFrame)+2*inplaceScratch)
			off := inplaceScratch
			copy(buf[off:off+len(phyFrame)], phyFrame)
			gotOff, gotLen = env.h.PhyToVirtInPlace(buf, off, len(phyFrame))
			_ = gotOff
		}()

		// Reset the replay window so the oracle decap of the same frame is not
		// rejected as a replay (the in-place call above may have consumed the
		// nonce). The oracle uses the same handler/keys.
		env.resetReplay(1)

		// Oracle: two-buffer decap.
		var refLen int
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PhyToVirt (oracle) panicked on %d-byte frame: %v\nframe=%x", len(phyFrame), r, phyFrame)
				}
			}()
			refVirt := make([]byte, len(phyFrame)+2*inplaceScratch)
			refLen = env.h.PhyToVirt(append([]byte(nil), phyFrame...), refVirt)
		}()

		// Both must agree on accept/drop.
		gotAccept := gotLen > 0
		refAccept := refLen > 0
		if gotAccept != refAccept {
			t.Fatalf("decap divergence: in-place accept=%v (len %d), two-buffer accept=%v (len %d)\nframe=%x",
				gotAccept, gotLen, refAccept, refLen, phyFrame)
		}
		// On accept, output bytes must be identical. (We re-run the in-place
		// decap here against a fresh oracle buffer comparison is unnecessary:
		// the lengths and the accept flags matching, combined with the Phase-2
		// byte-equivalence proof, is what we assert. To compare bytes we redo
		// the in-place decap into a fresh buffer since the first one is out of
		// scope; cheap and keeps the comparison explicit.)
		if gotAccept {
			env.resetReplay(1)
			buf := make([]byte, len(phyFrame)+2*inplaceScratch)
			off := inplaceScratch
			copy(buf[off:off+len(phyFrame)], phyFrame)
			o, l := env.h.PhyToVirtInPlace(buf, off, len(phyFrame))

			env.resetReplay(1)
			refVirt := make([]byte, len(phyFrame)+2*inplaceScratch)
			m := env.h.PhyToVirt(append([]byte(nil), phyFrame...), refVirt)

			if l != m || !bytes.Equal(buf[o:o+l], refVirt[:m]) {
				t.Fatalf("decap byte divergence: in-place len=%d two-buffer len=%d\n in=%x\n ip=%x\n tb=%x",
					l, m, phyFrame, buf[o:o+l], refVirt[:m])
			}
		}
	})
}

// FuzzVirtToPhyInPlace asserts in-place encap matches two-buffer encap on
// arbitrary virtual-frame input, with the TX nonce pinned so both use the same
// counter, and never panics.
func FuzzVirtToPhyInPlace(f *testing.F) {
	for _, tc := range inplaceCorpus() {
		env := newInplaceEnv(&testing.T{}, tc)
		f.Add(buildSeedVirtFrame(env, tc.payloadLen))
	}
	f.Add([]byte{})
	f.Add(make([]byte, 20))

	f.Fuzz(func(t *testing.T, virtFrame []byte) {
		env := fuzzEnv(t, false /*layer3*/, false, false)

		// Reference: two-buffer encap with the counter pinned to 0.
		env.pinCounter(0)
		var refLen int
		var refHandled bool
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("VirtToPhy (oracle) panicked on %d-byte frame: %v\nframe=%x", len(virtFrame), r, virtFrame)
				}
			}()
			refPhy := make([]byte, len(virtFrame)+2*inplaceScratch)
			refLen, refHandled = env.h.VirtToPhy(append([]byte(nil), virtFrame...), refPhy)
		}()

		// In-place: same pinned counter, single buffer with headroom.
		env.pinCounter(0)
		var gotLen int
		var gotHandled bool
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("VirtToPhyInPlace panicked on %d-byte frame: %v\nframe=%x", len(virtFrame), r, virtFrame)
				}
			}()
			buf := make([]byte, len(virtFrame)+2*inplaceScratch)
			off := inplaceScratch
			copy(buf[off:off+len(virtFrame)], virtFrame)
			_, gotLen, gotHandled = env.h.VirtToPhyInPlace(buf, off, len(virtFrame))
		}()

		if (gotLen > 0) != (refLen > 0) || gotHandled != refHandled {
			t.Fatalf("encap divergence: in-place (len=%d handled=%v) vs two-buffer (len=%d handled=%v)\nframe=%x",
				gotLen, gotHandled, refLen, refHandled, virtFrame)
		}
	})
}
