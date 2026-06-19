package icx

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	"log/slog"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/icx/geneve"
	"github.com/apoxy-dev/icx/udp"
)

// quietLogs silences the handler's per-frame slog.Warn drops for the duration of
// a test that deliberately feeds malformed frames, restoring the default logger
// after. Without it the adversarial test floods stderr with one WARN per drop.
func quietLogs(t *testing.T) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// Multiqueue concurrency stress tests.
//
// The forwarder runs ONE goroutine per NIC queue (forwarder.processFrames), and
// every one of those goroutines calls into the SAME shared *icx.Handler:
// VirtToPhyInPlace (encap), PhyToVirtInPlace (decap), ToPhyInPlace (keepalive).
// So the handler's per-VNI state — txCipher.counter (the AES-GCM nonce source),
// the rxCiphers replay filters, the stats counters, the route tables — is touched
// by N goroutines at once. These tests reproduce that exact access pattern in
// userspace (no AF_XDP / no hardware needed: the root package builds everywhere)
// and assert the two security invariants that a multiqueue race would break:
//
//	S1 (nonce uniqueness): no two encaps, across any number of concurrent
//	    queue goroutines, ever emit the same AES-GCM nonce (epoch‖counter).
//	S2 (anti-replay):       a frame replayed concurrently across queues is
//	    accepted at most once.
//
// Run with -race to also catch data races on the shared handler state. A failure
// here is a real, shippable multiqueue defect, not a harness artifact.

// extractTxNonce parses the 12-byte AEAD nonce (the Geneve TxCounter option value)
// out of an encap output frame. The output is always an IPv4-underlay physical
// frame in these tests, so the Geneve header sits at the fixed IPv4 payload
// offset. Returns false if the frame is too short or carries no TxCounter option.
func extractTxNonce(phyFrame []byte) (nonce [12]byte, ok bool) {
	payloadOffset := udp.PayloadOffsetIPv4 // Eth(14)+IPv4(20)+UDP(8) = 42
	if len(phyFrame) < payloadOffset+8 {
		return nonce, false
	}
	var hdr geneve.Header
	if _, err := hdr.UnmarshalBinary(phyFrame[payloadOffset:]); err != nil {
		return nonce, false
	}
	for i := 0; i < hdr.NumOptions; i++ {
		if hdr.Options[i].Type == geneve.OptionTypeTxCounter {
			copy(nonce[:], hdr.Options[i].Value[:12])
			return nonce, true
		}
	}
	return nonce, false
}

// mqEnv builds a shared handler+vnet for the concurrency tests: L3 mode, IPv4
// underlay and inner (so extractTxNonce's fixed offset holds), one installed
// rx==tx key so an encap output round-trips through decap on the same handler.
func mqEnv(t *testing.T) *inplaceEnv {
	t.Helper()
	return newInplaceEnv(t, inplaceTestCase{
		name: "mq", layer3: true, underlayV6: false, innerV6: false, payloadLen: 64,
	})
}

// TestMultiQueueNonceUniqueness drives N concurrent encap goroutines through one
// shared handler and asserts every emitted AES-GCM nonce is unique — the S1
// invariant under the forwarder's real multiqueue access pattern. A duplicate
// nonce means two queue goroutines sealed different plaintext under the same
// (key, nonce): catastrophic GCM reuse.
func TestMultiQueueNonceUniqueness(t *testing.T) {
	env := mqEnv(t)
	template := env.buildVirtFrame(t, 64)

	const (
		goroutines = 8
		perG       = 30000
	)
	noncesByG := make([][][12]byte, goroutines)

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			buf := make([]byte, mtu+2*inplaceScratch)
			off := inplaceScratch
			local := make([][12]byte, 0, perG)
			for i := 0; i < perG; i++ {
				// Encap is in place and overwrites buf; re-seat the virtual
				// frame each iteration so every call sees a valid inner packet.
				copy(buf[off:off+len(template)], template)
				gotOff, gotLen, handled := env.h.VirtToPhyInPlace(buf, off, len(template))
				if handled || gotLen <= 0 {
					continue
				}
				if n, ok := extractTxNonce(buf[gotOff : gotOff+gotLen]); ok {
					local = append(local, n)
				}
			}
			noncesByG[g] = local
		}(g)
	}
	wg.Wait()

	seen := make(map[[12]byte]struct{}, goroutines*perG)
	total, dups := 0, 0
	for _, local := range noncesByG {
		for _, n := range local {
			total++
			if _, ok := seen[n]; ok {
				dups++
			} else {
				seen[n] = struct{}{}
			}
		}
	}
	require.Greater(t, total, 0, "no successful encaps")
	if dups > 0 {
		t.Fatalf("S1 VIOLATION: %d duplicate AES-GCM nonces across %d concurrent encaps (%d goroutines) — GCM nonce reuse",
			dups, total, goroutines)
	}
	// The atomic counter must have handed out exactly `total` distinct values
	// 1..total, so the max low-8-byte counter equals total with no gaps.
	var maxCtr uint64
	for n := range seen {
		if c := binary.BigEndian.Uint64(n[4:]); c > maxCtr {
			maxCtr = c
		}
	}
	require.Equal(t, uint64(total), maxCtr,
		"counter values should be a dense 1..N range; gap/overlap implies a lost or duplicated increment")
	t.Logf("multiqueue nonce-uniqueness: %d encaps / %d goroutines, 0 duplicates, dense counter range", total, goroutines)
}

// TestMultiQueueReplayExactlyOnce builds K distinct valid frames and fires G
// concurrent decaps of independent copies of EACH frame at one shared handler.
// Every distinct frame must be accepted exactly once: the per-rxCipher
// replay.Filter is shared across all queue goroutines, so this exercises
// concurrent ValidateCounter on the same filter — the S2 invariant under
// multiqueue. More than K total accepts means the shared filter let a replay
// through under concurrency.
func TestMultiQueueReplayExactlyOnce(t *testing.T) {
	env := mqEnv(t)
	template := env.buildVirtFrame(t, 64)

	const (
		frames         = 1500 // distinct counters 1..frames
		decapsPerFrame = 8    // concurrent decap attempts on the same frame
	)

	phyFrames := make([][]byte, frames)
	for k := 0; k < frames; k++ {
		buf := make([]byte, mtu+2*inplaceScratch)
		off := inplaceScratch
		copy(buf[off:off+len(template)], template)
		gotOff, gotLen, handled := env.h.VirtToPhyInPlace(buf, off, len(template))
		require.False(t, handled)
		require.Greater(t, gotLen, 0)
		phyFrames[k] = append([]byte(nil), buf[gotOff:gotOff+gotLen]...)
	}
	// Fresh replay window: the encaps above never touched RX state, but be
	// explicit so the test is order-independent.
	env.resetReplay(1)

	var accepted int64
	var wg sync.WaitGroup
	for k := 0; k < frames; k++ {
		for g := 0; g < decapsPerFrame; g++ {
			wg.Add(1)
			go func(frame []byte) {
				defer wg.Done()
				buf := make([]byte, len(frame)+2*inplaceScratch)
				off := inplaceScratch
				copy(buf[off:off+len(frame)], frame)
				if _, l := env.h.PhyToVirtInPlace(buf, off, len(frame)); l > 0 {
					atomic.AddInt64(&accepted, 1)
				}
			}(phyFrames[k])
		}
	}
	wg.Wait()

	if int(accepted) != frames {
		t.Fatalf("S2 VIOLATION: expected exactly %d accepts (one per distinct frame), got %d — the shared replay.Filter accepted a replay under concurrency",
			frames, accepted)
	}
	t.Logf("multiqueue replay: %d distinct frames x %d concurrent decaps -> exactly %d accepts", frames, decapsPerFrame, accepted)
}

// TestMultiQueueConcurrentAdversarial hammers the shared handler with adversarial
// frames (random bytes, single-bit-flipped valid frames, and valid frames) from
// N goroutines doing encap and decap at once. It asserts the handler never panics
// under concurrent malformed input — the handler's own length/IsValid guards are
// the contract; the forwarder's safeTransform recover() is only a backstop. Run
// under -race, it also catches data races the deterministic tests above might miss.
func TestMultiQueueConcurrentAdversarial(t *testing.T) {
	quietLogs(t)
	env := mqEnv(t)
	valid := env.buildVirtFrame(t, 64)

	const (
		goroutines = 8
		perG       = 40000
	)
	var panics int64
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(int64(seed) + 1))
			buf := make([]byte, mtu+2*inplaceScratch)
			off := inplaceScratch
			for i := 0; i < perG; i++ {
				func() {
					defer func() {
						if r := recover(); r != nil {
							atomic.AddInt64(&panics, 1)
							t.Errorf("datapath panic on concurrent adversarial input: %v", r)
						}
					}()
					var frame []byte
					switch rng.Intn(3) {
					case 0: // random bytes
						frame = make([]byte, rng.Intn(256))
						rng.Read(frame)
					case 1: // bit-flipped valid frame
						frame = append([]byte(nil), valid...)
						if len(frame) > 0 {
							frame[rng.Intn(len(frame))] ^= byte(1 + rng.Intn(255))
						}
					default: // pristine valid frame
						frame = valid
					}
					l := len(frame)
					if l > mtu {
						l = mtu
					}
					copy(buf[off:off+l], frame[:l])
					if rng.Intn(2) == 0 {
						env.h.VirtToPhyInPlace(buf, off, l)
					} else {
						env.h.PhyToVirtInPlace(buf, off, l)
					}
				}()
			}
		}(g)
	}
	wg.Wait()
	if panics > 0 {
		t.Fatalf("%d datapath panics under concurrent adversarial input", panics)
	}
}

// TestMultiQueueDecapDuringRekeyRace reproduces the data race on
// receiveCipher.expiresAt: the control-plane install path grace-clamps the
// previous RX cipher's expiry in place (installKeys) while the datapath decap
// goroutines read that same field. rxCiphers is a sync.Map, which synchronizes
// only the slot pointer, not the pointee — so the in-place write of a multi-word
// time.Time races the unsynchronized reads. Under -race this fails until
// expiresAt is made an atomic. (The encap-only TestMultiQueueRekeyUnderLoad
// could not catch it: the race needs a concurrent DECAP reader.)
func TestMultiQueueDecapDuringRekeyRace(t *testing.T) {
	env := mqEnv(t)
	template := env.buildVirtFrame(t, 64)

	// One valid epoch-1 frame the decap readers replay. Decap reads the epoch-1
	// rxCipher's expiresAt on every call (before Open), which is exactly the field
	// the rekey grace-clamp mutates.
	buf := make([]byte, mtu+2*inplaceScratch)
	off := inplaceScratch
	copy(buf[off:off+len(template)], template)
	gotOff, gotLen, handled := env.h.VirtToPhyInPlace(buf, off, len(template))
	require.False(t, handled)
	require.Greater(t, gotLen, 0)
	epoch1Frame := append([]byte(nil), buf[gotOff:gotOff+gotLen]...)

	const readers = 6
	var stop int64
	var ready, wg sync.WaitGroup
	ready.Add(readers)
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rbuf := make([]byte, len(epoch1Frame)+2*inplaceScratch)
			roff := inplaceScratch
			first := true
			for atomic.LoadInt64(&stop) == 0 {
				copy(rbuf[roff:roff+len(epoch1Frame)], epoch1Frame)
				env.h.PhyToVirtInPlace(rbuf, roff, len(epoch1Frame)) // reads rxCipher.expiresAt
				if first {
					ready.Done()
					first = false
				}
			}
		}()
	}
	ready.Wait() // all readers are spinning on epoch-1 decap

	// Install epoch 2: installKeys grace-clamps epoch-1's expiresAt in place while
	// the readers are reading it. The readers keep reading epoch-1 during the grace
	// window, so post-clamp reads with no happens-before edge are flagged too.
	var rxK, txK [16]byte
	_, _ = crand.Read(rxK[:])
	_, _ = crand.Read(txK[:])
	require.NoError(t, env.h.UpdateVirtualNetworkKeys(env.vni, 2, rxK, txK, time.Now().Add(time.Hour)))

	time.Sleep(20 * time.Millisecond) // let readers iterate across the clamp
	atomic.StoreInt64(&stop, 1)
	wg.Wait()
}

// TestMultiQueueRekeyUnderLoad runs N encap goroutines while a separate goroutine
// rotates the transmit SA through the production install path (distinct fresh keys,
// strictly increasing epoch) — the control plane rekeying mid-datapath. It asserts
// every emitted nonce (epoch‖counter) stays globally unique across the rotations:
// a fresh epoch resets the counter to zero, but because the epoch differs no
// (epoch, counter) pair — and, since each epoch carries a fresh key, no
// (key, nonce) pair — ever repeats. A torn txCipher swap, a reused epoch, or a
// carried-over counter would surface here as a duplicate nonce. Run under -race
// for the txCipher.Store-vs-Load and rxCiphers grace-clamp races.
func TestMultiQueueRekeyUnderLoad(t *testing.T) {
	env := mqEnv(t)
	template := env.buildVirtFrame(t, 64)

	const (
		goroutines = 6
		perG       = 25000
	)
	noncesByG := make([][][12]byte, goroutines)

	var stop int64
	var rotWg, encWg sync.WaitGroup

	rotWg.Add(1)
	go func() {
		defer rotWg.Done()
		epoch := uint32(2) // epoch 1 is the initial install from newInplaceEnv
		for atomic.LoadInt64(&stop) == 0 {
			var rxK, txK [16]byte
			_, _ = crand.Read(rxK[:])
			_, _ = crand.Read(txK[:])
			// Production path: rejects equal rx/tx keys and non-monotone epoch.
			_ = env.h.UpdateVirtualNetworkKeys(env.vni, epoch, rxK, txK, time.Now().Add(time.Hour))
			epoch++
		}
	}()

	for g := 0; g < goroutines; g++ {
		encWg.Add(1)
		go func(g int) {
			defer encWg.Done()
			buf := make([]byte, mtu+2*inplaceScratch)
			off := inplaceScratch
			local := make([][12]byte, 0, perG)
			for i := 0; i < perG; i++ {
				copy(buf[off:off+len(template)], template)
				gotOff, gotLen, handled := env.h.VirtToPhyInPlace(buf, off, len(template))
				if handled || gotLen <= 0 {
					continue
				}
				if n, ok := extractTxNonce(buf[gotOff : gotOff+gotLen]); ok {
					local = append(local, n)
				}
			}
			noncesByG[g] = local
		}(g)
	}

	encWg.Wait()
	atomic.StoreInt64(&stop, 1)
	rotWg.Wait()

	seen := make(map[[12]byte]struct{}, goroutines*perG)
	total, dups, epochs := 0, 0, map[uint32]struct{}{}
	for _, local := range noncesByG {
		for _, n := range local {
			total++
			epochs[binary.BigEndian.Uint32(n[:4])] = struct{}{}
			if _, ok := seen[n]; ok {
				dups++
			} else {
				seen[n] = struct{}{}
			}
		}
	}
	require.Greater(t, total, 0, "no successful encaps")
	if dups > 0 {
		t.Fatalf("S1 VIOLATION under rekey: %d duplicate nonces across %d encaps spanning %d epochs",
			dups, total, len(epochs))
	}
	t.Logf("multiqueue rekey-under-load: %d encaps / %d goroutines spanning %d epochs, 0 duplicate nonces",
		total, goroutines, len(epochs))
}
