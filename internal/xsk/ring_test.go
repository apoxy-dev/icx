//go:build linux

package xsk

import (
	"sync/atomic"
	"testing"
	"unsafe"
)

// newTestRing builds a ring over plain Go-allocated memory (no mmap/kernel), so
// the SPSC index math — reserve/submit/peek/release, the cached prod/cons, free
// vs available, and free-running uint32 wraparound — can be exercised in a unit
// test. The "kernel" side is simulated by the test advancing the opposite index.
func newTestRing(size uint32) (*ring, []Desc, *uint32, *uint32) {
	descs := make([]Desc, size)
	var prod, cons uint32
	r := &ring{
		producer: &prod,
		consumer: &cons,
		desc:     unsafe.Pointer(&descs[0]),
		mask:     size - 1,
		size:     size,
	}
	return r, descs, &prod, &cons
}

func TestRingProducerReserveSubmit(t *testing.T) {
	r, _, prod, cons := newTestRing(8)

	// Empty ring: all 8 slots free.
	start, got := r.reserve(8)
	if got != 8 || start != 0 {
		t.Fatalf("reserve(8) on empty = (start=%d,got=%d), want (0,8)", start, got)
	}
	for i := uint32(0); i < got; i++ {
		*at[Desc](r, start+i) = Desc{Addr: uint64(i), Len: i}
	}
	r.submit(got)
	if *prod != 8 {
		t.Fatalf("producer index = %d, want 8", *prod)
	}

	// Full ring: no free slots until the consumer (kernel) advances.
	if _, got := r.reserve(1); got != 0 {
		t.Fatalf("reserve(1) on full = %d, want 0", got)
	}

	// Simulate kernel consuming 3.
	*cons = 3
	if _, got := r.reserve(8); got != 3 {
		t.Fatalf("reserve(8) after kernel consumed 3 = %d, want 3", got)
	}
	// Slots must land at masked indices 0,1,2 (free-running 8,9,10).
	for i, want := range map[uint32]uint32{8: 0, 9: 1, 10: 2} {
		if (i & r.mask) != want {
			t.Fatalf("idx %d masks to %d, want %d", i, i&r.mask, want)
		}
	}
}

// TestRingShortWriteDoesNotOverpublish is the regression test for the scaffold
// bug the review caught: reserving N slots but writing/submitting fewer (k<N)
// must advance and publish the producer index by exactly k, never by N. An
// over-publish would expose unwritten ring slots (garbage descriptors) to the
// kernel. This is the FILL-short-on-frames path in UMEM.Fill, exercised here at
// the ring layer.
func TestRingShortWriteDoesNotOverpublish(t *testing.T) {
	r, _, prod, _ := newTestRing(16)

	start, got := r.reserve(10)
	if got != 10 || start != 0 {
		t.Fatalf("reserve(10) = (start=%d,got=%d), want (0,10)", start, got)
	}
	// Simulate a short allocation: only 3 descriptors actually written.
	const written = 3
	for i := uint32(0); i < written; i++ {
		*at[Desc](r, start+i) = Desc{Addr: uint64(i)}
	}
	r.submit(written)

	if *prod != written {
		t.Fatalf("producer index = %d after writing %d of 10 reserved; want %d (over-publish exposes garbage slots)", *prod, written, written)
	}
	if r.cachedProducer != written {
		t.Fatalf("cachedProducer = %d, want %d (cached index desynced from published)", r.cachedProducer, written)
	}

	// The next reserve must see the remaining 13 free slots and start at 3, not 10.
	start, got = r.reserve(16)
	if start != written {
		t.Fatalf("next reserve start = %d, want %d", start, written)
	}
	if got != 16-written {
		t.Fatalf("next reserve got = %d, want %d", got, 16-written)
	}
}

// TestRingSubmitReleaseZeroNoop confirms the empty-path guard: submit(0)/release(0)
// must not touch the kernel-shared index word (cacheline-bounce nit).
func TestRingSubmitReleaseZeroNoop(t *testing.T) {
	r, _, prod, cons := newTestRing(8)
	*prod, *cons = 5, 2
	r.cachedProducer, r.cachedConsumer = 5, 2

	r.submit(0)
	if *prod != 5 {
		t.Fatalf("submit(0) wrote producer = %d, want 5 (must be no-op)", *prod)
	}
	r.release(0)
	if *cons != 2 {
		t.Fatalf("release(0) wrote consumer = %d, want 2 (must be no-op)", *cons)
	}
}

func TestRingConsumerPeekRelease(t *testing.T) {
	r, descs, prod, cons := newTestRing(8)

	// Nothing produced yet.
	if _, got := r.peek(8); got != 0 {
		t.Fatalf("peek on empty = %d, want 0", got)
	}

	// Simulate kernel producing 5 descriptors.
	for i := uint32(0); i < 5; i++ {
		descs[i] = Desc{Addr: uint64(100 + i), Len: i}
	}
	*prod = 5

	start, got := r.peek(8)
	if got != 5 || start != 0 {
		t.Fatalf("peek = (start=%d,got=%d), want (0,5)", start, got)
	}
	for i := uint32(0); i < got; i++ {
		d := *at[Desc](r, start+i)
		if d.Addr != uint64(100+i) {
			t.Fatalf("desc[%d].Addr = %d, want %d", i, d.Addr, 100+i)
		}
	}
	r.release(got)
	if *cons != 5 {
		t.Fatalf("consumer index = %d, want 5", *cons)
	}
	if _, got := r.peek(8); got != 0 {
		t.Fatalf("peek after draining = %d, want 0", got)
	}
}

// TestRingWraparound drives indices past uint32 max to confirm free-running
// wraparound is handled by unsigned subtraction, not equality.
func TestRingWraparound(t *testing.T) {
	r, descs, prod, cons := newTestRing(8)
	_ = descs

	// Place both cached and shared indices near the uint32 boundary, ring empty.
	// near is a runtime value (not a const) so near+8 is a runtime wraparound,
	// which is exactly the free-running behavior under test — a const near+8
	// would be a compile-time overflow error.
	near := ^uint32(0) - 2 // 2^32 - 3
	*prod, *cons = near, near
	r.cachedProducer, r.cachedConsumer = near, near

	// Producer should see a full ring of free slots.
	start, got := r.reserve(8)
	if got != 8 {
		t.Fatalf("reserve(8) near wrap = %d, want 8", got)
	}
	if start != near {
		t.Fatalf("reserve start = %d, want %d", start, near)
	}
	for i := uint32(0); i < got; i++ {
		*at[Desc](r, start+i) = Desc{Addr: uint64(i)}
	}
	r.submit(got)
	// Producer index wrapped: near + 8 overflows past 2^32.
	if want := near + 8; *prod != want {
		t.Fatalf("producer after wrap = %d, want %d", *prod, want)
	}

	// Consumer peeks across the wrap boundary; subtraction (prod-cons) == 8.
	start, got = r.peek(8)
	if got != 8 {
		t.Fatalf("peek across wrap = %d, want 8 (prod-cons must use unsigned sub)", got)
	}
	// First produced slot was at masked index (near & 7).
	if (start & r.mask) != (near & r.mask) {
		t.Fatalf("peek start masks to %d, want %d", start&r.mask, near&r.mask)
	}
	r.release(got)
}

// TestRingConcurrentProducer is the real memory-ordering test: WE are the
// producer (reserve/submit, the code under test) and a second goroutine plays
// the kernel consumer using raw atomics on the same shared words — an
// independent SPSC counterparty, exactly like the real kernel on another CPU.
//
// Run under -race, this validates the producer's store-RELEASE / consumer's
// load-ACQUIRE pairing: the kernel reads descs[idx] as a PLAIN read, ordered
// after our descriptor write ONLY by the atomic producer store(submit)→load
// pairing. If submit used a plain store (the slavc/xdp bug), the race detector
// would flag the descriptor read/write as a data race and the sequence check
// would observe torn/garbage Addrs. A clean -race run is the property we want.
func TestRingConcurrentProducer(t *testing.T) {
	const (
		N    = 1 << 20
		size = 1024
	)
	r, descs, prod, cons := newTestRing(size)

	errc := make(chan error, 1)
	done := make(chan struct{})
	go func() { // simulated kernel consumer
		defer close(done)
		var c uint32
		next := uint64(0)
		for next < N {
			p := atomic.LoadUint32(prod) // acquire: see our published descriptors
			for c != p {
				d := descs[c&(size-1)] // plain read, ordered after submit's release
				if d.Addr != next {
					select {
					case errc <- errSeq(next, d.Addr):
					default:
					}
					return
				}
				next++
				c++
			}
			atomic.StoreUint32(cons, c) // release: free the slots back to us
		}
	}()

	sent := uint64(0)
	for sent < N {
		start, n := r.reserve(64)
		for i := uint32(0); i < n; i++ {
			*at[Desc](r, start+i) = Desc{Addr: sent}
			sent++
		}
		r.submit(n)
	}
	<-done
	select {
	case err := <-errc:
		t.Fatal(err)
	default:
	}
}

// TestRingConcurrentConsumer is the mirror: the kernel goroutine produces (raw
// atomics) and WE consume via peek/release. Under -race this validates the
// consumer's load-ACQUIRE (peek) / store-RELEASE (release) against an
// independent producer — the RX/COMPLETION direction.
func TestRingConcurrentConsumer(t *testing.T) {
	const (
		N    = 1 << 20
		size = 1024
	)
	r, descs, prod, cons := newTestRing(size)

	go func() { // simulated kernel producer
		var p uint32
		sent := uint64(0)
		for sent < N {
			c := atomic.LoadUint32(cons) // acquire: how far we've consumed
			free := uint32(size) - (p - c)
			for free > 0 && sent < N {
				descs[p&(size-1)] = Desc{Addr: sent} // plain write
				p++
				sent++
				free--
			}
			atomic.StoreUint32(prod, p) // release: publish to us
		}
	}()

	next := uint64(0)
	for next < N {
		start, n := r.peek(256)
		for i := uint32(0); i < n; i++ {
			d := *at[Desc](r, start+i)
			if d.Addr != next {
				t.Fatalf("consumer saw Addr=%d, want %d (torn/reordered read)", d.Addr, next)
			}
			next++
		}
		r.release(n)
	}
}

func errSeq(want, got uint64) error {
	return &seqError{want: want, got: got}
}

type seqError struct{ want, got uint64 }

func (e *seqError) Error() string {
	return "kernel observed out-of-order/torn descriptor: got Addr=" +
		itoa(e.got) + ", want " + itoa(e.want)
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TestRingFreeAndAvailable(t *testing.T) {
	r, _, _, cons := newTestRing(16)

	if f := r.freeSlots(); f != 16 {
		t.Fatalf("freeSlots empty = %d, want 16", f)
	}
	if a := r.available(); a != 0 {
		t.Fatalf("available empty = %d, want 0", a)
	}

	// Producer adds 10.
	_, got := r.reserve(10)
	r.submit(got)
	if f := r.freeSlots(); f != 6 {
		t.Fatalf("freeSlots after 10 = %d, want 6", f)
	}

	// Kernel (consumer) drains 4. freeSlots is an accurate query: it does the
	// acquiring load of the kernel-published consumer EVERY call, so it observes
	// the drain immediately and reports 10. (The old code only refreshed when the
	// cached count hit exactly 0, so a partial drain left freeSlots — and the
	// NumFreeTxSlots/NumFilled/NumTransmitted derived from it — frozen at a stale
	// value once the producer went idle, starving the forwarder's flow control and
	// wedging the datapath. APO-803.)
	*cons = 4
	if f := r.freeSlots(); f != 10 {
		t.Fatalf("freeSlots after kernel drained 4 = %d, want 10 (always refreshes)", f)
	}
	// reserve also observes the kernel's progress (it refreshes when the cached
	// free space is too small for the request).
	if _, got := r.reserve(16); got != 10 {
		t.Fatalf("reserve(16) after kernel drained 4 = %d, want 10", got)
	}
}

// TestRingAbsentRingNoPanic covers the RX-only/TX-only socket case: a skipped
// direction leaves a zero-value ring (size==0, nil producer/consumer pointers).
// reserve/peek/available/freeSlots must treat it as a permanently empty/full
// no-op instead of dereferencing the nil index pointer. Without the size==0
// guard these panic with a nil-pointer deref on the slow path.
func TestRingAbsentRingNoPanic(t *testing.T) {
	var r ring // zero value: size 0, producer/consumer nil

	if start, got := r.reserve(8); start != 0 || got != 0 {
		t.Fatalf("absent reserve = (%d,%d), want (0,0)", start, got)
	}
	if start, got := r.peek(8); start != 0 || got != 0 {
		t.Fatalf("absent peek = (%d,%d), want (0,0)", start, got)
	}
	if a := r.available(); a != 0 {
		t.Fatalf("absent available = %d, want 0", a)
	}
	if f := r.freeSlots(); f != 0 {
		t.Fatalf("absent freeSlots = %d, want 0", f)
	}
	// submit/release of 0 are already no-ops; ensure they don't deref either.
	r.submit(0)
	r.release(0)
}
