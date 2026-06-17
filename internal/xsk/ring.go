//go:build linux

package xsk

import (
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ring is one AF_XDP single-producer/single-consumer ring. The producer and
// consumer index words live in kernel-shared mmap memory; one side of every
// ring is the kernel on another CPU. All access to those words goes through
// sync/atomic to get the acquire/release ordering the XSK ABI requires and to
// stop the Go compiler from caching/hoisting them (see package doc).
//
// The ring is element-type agnostic: it tracks indices and hands the caller a
// masked slot index, and the caller writes/reads the typed descriptor at that
// slot (addr at[uint64] for FILL/COMPLETION, Desc at[Desc] for RX/TX). desc is
// the base of the descriptor area within the ring mmap.
//
// cachedProducer/cachedConsumer mirror the shared words so the hot path can
// compute free/available space without touching the shared cacheline on every
// call (the libbpf cached-prod/cached-cons optimization). They are owned solely
// by this process's producer or consumer side and are never read by the kernel.
type ring struct {
	producer *uint32 // shared with kernel
	consumer *uint32 // shared with kernel
	flags    *uint32 // shared with kernel; XDP_RING_NEED_WAKEUP lives here

	cachedProducer uint32 // process-local mirror of *producer
	cachedConsumer uint32 // process-local mirror of *consumer

	desc unsafe.Pointer // base of the descriptor area
	mask uint32         // size-1; size is a power of two
	size uint32
}

// at returns a typed pointer to ring slot idx (idx is already free-running; it
// is masked here). T must match the ring's element type (uint64 for
// FILL/COMPLETION, Desc for RX/TX); using the wrong T is a programming error.
func at[T any](r *ring, idx uint32) *T {
	var zero T
	off := uintptr(idx&r.mask) * unsafe.Sizeof(zero)
	return (*T)(unsafe.Add(r.desc, off))
}

// --- producer side (FILL, TX): we produce, kernel consumes ---

// reserve reports room for up to n entries: the starting free-running index and
// how many slots are free (got <= n). It does NOT advance any index — the caller
// writes up to got descriptors at [start, start+got) via at(), then calls
// submit(k) with the number it actually wrote (k <= got). The producer index is
// advanced and published only by submit, so writing fewer than reserved is
// always safe and can never publish unwritten slots to the kernel.
//
// (This mirrors the consumer side, where peek does not advance and release(k) is
// authoritative. The earlier asymmetry — reserve advancing cachedProducer while
// submit ignored its count — let a short write over-publish the FILL ring.)
func (r *ring) reserve(n uint32) (start uint32, got uint32) {
	if r.size == 0 {
		return 0, 0 // absent ring (RX-only/TX-only socket): no slots, no nil deref
	}
	free := r.size - (r.cachedProducer - r.cachedConsumer)
	if free < n {
		// Refresh our view of how far the kernel has consumed.
		// load-ACQUIRE: nothing below may be hoisted above this read.
		r.cachedConsumer = atomic.LoadUint32(r.consumer)
		free = r.size - (r.cachedProducer - r.cachedConsumer)
	}
	if n > free {
		n = free
	}
	return r.cachedProducer, n
}

// submit advances the producer index by exactly n (the number the caller wrote)
// and publishes it. store-RELEASE: all descriptor writes above are globally
// visible before the kernel can observe the bumped producer index. A zero count
// is a no-op so the kernel-shared cacheline is not bounced on the empty path.
func (r *ring) submit(n uint32) {
	if n == 0 {
		return
	}
	r.cachedProducer += n
	atomic.StoreUint32(r.producer, r.cachedProducer)
}

// --- consumer side (RX, COMPLETION): kernel produces, we consume ---

// peek returns up to n entries the kernel has produced: the starting
// free-running index and how many are available (got <= n). It does NOT advance
// any index — the caller reads up to got descriptors at [start, start+got) via
// at() and then calls release(k) with the number it actually consumed (k <= got).
func (r *ring) peek(n uint32) (start uint32, got uint32) {
	if r.size == 0 {
		return 0, 0 // absent ring: nothing to consume, no nil deref
	}
	avail := r.cachedProducer - r.cachedConsumer
	if avail < n {
		// load-ACQUIRE: descriptor reads below must not be hoisted above this.
		r.cachedProducer = atomic.LoadUint32(r.producer)
		avail = r.cachedProducer - r.cachedConsumer
	}
	if n > avail {
		n = avail
	}
	return r.cachedConsumer, n
}

// release returns n consumed entries to the kernel.
// store-RELEASE: all descriptor reads above complete before the kernel can
// observe the advanced consumer index and recycle those slots. A zero count is
// a no-op so the kernel-shared cacheline is not bounced on the empty path.
func (r *ring) release(n uint32) {
	if n == 0 {
		return
	}
	r.cachedConsumer += n
	atomic.StoreUint32(r.consumer, r.cachedConsumer)
}

// --- shared helpers ---

// available reports how many entries the consumer side can read without a
// syscall, refreshing the cached producer index with an acquiring load.
func (r *ring) available() uint32 {
	if r.size == 0 {
		return 0 // absent ring: never any entries, no nil deref
	}
	avail := r.cachedProducer - r.cachedConsumer
	if avail == 0 {
		r.cachedProducer = atomic.LoadUint32(r.producer)
		avail = r.cachedProducer - r.cachedConsumer
	}
	return avail
}

// freeSlots reports how many entries the producer side can add, with an
// acquiring load of the kernel-published consumer index every call.
//
// Unlike reserve (which only refreshes when the cached count is too small to
// satisfy a specific request, the libbpf optimization), this is a standalone
// QUERY whose result is taken as the accurate current free count — the forwarder
// derives NumFreeTxSlots / NumFilled / NumTransmitted from it and uses them for
// flow-control (e.g. bounding virt.Fill by phy.NumFreeTxSlots). The old code only
// refreshed cachedConsumer when free hit exactly 0, so once the kernel partially
// drained the ring and the producer went idle, cachedConsumer went stale and the
// derived counts froze (free reading ~1 forever, NumTransmitted ~size-1 forever)
// — silently starving the reservation logic and wedging the datapath (APO-803).
// The kernel only ever advances the consumer (monotonic, frees space), so an
// unconditional acquiring load can only move free up and never reads torn — it is
// always correct, and the extra cacheline read per call is negligible next to the
// wedge it prevents.
func (r *ring) freeSlots() uint32 {
	if r.size == 0 {
		return 0 // absent ring: no slots to produce into, no nil deref
	}
	r.cachedConsumer = atomic.LoadUint32(r.consumer)
	return r.size - (r.cachedProducer - r.cachedConsumer)
}

// needsWakeup reports whether the kernel has asked to be woken (poll for
// RX/FILL, sendto for TX) for this ring. Only meaningful when the socket was
// bound with XDP_USE_NEED_WAKEUP; otherwise flags is nil and we always wake.
func (r *ring) needsWakeup() bool {
	if r.flags == nil {
		return true
	}
	return atomic.LoadUint32(r.flags)&unix.XDP_RING_NEED_WAKEUP != 0
}
