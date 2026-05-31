//go:build linux

package xsk

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// UMEM is the shared frame memory region and the frame-ownership allocator. It
// deliberately does NOT hold the FILL/COMPLETION rings: under XDP_SHARED_UMEM
// across different netdevs/queues (the forwarder's zero-copy case), each socket
// needs its OWN fill/comp/rx/tx rings, all drawing from this one frame pool.
// (Confirmed empirically: the FIRST socket REUSES regFD and binds normally; each
// later socket binds XDP_SHARED_UMEM + sxdp_shared_umem_fd=regFD with its own
// rings. A never-bound fd as the shared ref fails with EBADF — the kernel needs
// the referenced fd already bound.) So the rings live on Socket; the UMEM is just
// memory + allocator + the registration fd that sockets reference.
//
// Zero-copy forwarding: a frame received on one socket's RX ring is transmitted
// on another socket's TX ring by handing over the SAME descriptor — same UMEM
// addr, no copy — because both sockets share this frame pool. The frame is
// reclaimed via the transmitting socket's COMPLETION ring back into the pool.
//
// Frame ownership is a single LIFO free-frame stack: a frame is "free" iff it
// sits on the stack. There is exactly one ownership structure (unlike slavc/xdp's
// two independent freeRX/freeTX arrays that could double-allocate a frame), so a
// frame can never be believed free by two paths at once. mu guards it because
// multiple socket goroutines allocate/free from the one shared pool.
type UMEM struct {
	mem       []byte // the mmap'd frame area: NumFrames*FrameSize bytes
	frameSize uint64
	numFrames uint32

	mu   sync.Mutex
	free []uint32

	regFD   int  // AF_XDP fd holding XDP_UMEM_REG; the first socket reuses & binds it
	claimed bool // set once the first NewSocket has reused regFD (see claimFirst)
}

// frameAddr converts a frame index to its UMEM byte offset (the Desc.Addr).
func (u *UMEM) frameAddr(idx uint32) uint64 { return uint64(idx) * u.frameSize }

// frameIndex converts a UMEM byte offset back to a frame index. Addr may carry
// an in-frame offset (headroom/packet start); we floor to the chunk.
func (u *UMEM) frameIndex(addr uint64) uint32 { return uint32(addr / u.frameSize) }

// claimFirst reports whether the calling NewSocket is the FIRST socket on this
// UMEM. The first socket REUSES the UMEM registration fd (regFD) and binds
// normally; every later socket gets its own fd and binds XDP_SHARED_UMEM
// referencing regFD. The kernel requires that referenced fd to already be bound
// (else EBADF), so the registration fd must become a real, bound socket — which
// is exactly the first. Only the first caller per UMEM gets true.
func (u *UMEM) claimFirst() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.claimed {
		return false
	}
	u.claimed = true
	return true
}

// unclaimFirst rolls back a claimFirst when the first socket's setup fails before
// it is bound, so a later retry can again reuse regFD instead of (wrongly)
// binding shared against a still-unbound fd.
func (u *UMEM) unclaimFirst() {
	u.mu.Lock()
	u.claimed = false
	u.mu.Unlock()
}

// Frame returns the byte slice for descriptor d, bounded to a SINGLE frame, or
// nil if d.Addr is outside the UMEM. The three-index slice caps capacity at the
// frame boundary so a handler that re-slices to cap cannot scribble into the
// adjacent frame (the slavc/xdp GetFrame footgun, where cap ran to the end of
// the whole UMEM). Both the lower bound (Addr in range) and the upper bound (len
// clamped to the frame boundary) are checked, so a malformed/foreign descriptor
// — a bad Addr, an oversized Len, or an in-frame headroom offset — returns nil or
// a clamped frame rather than panicking the datapath. This matters on the RX /
// zero-copy-handoff path, where d.Addr is not necessarily one this process
// produced.
func (u *UMEM) Frame(d Desc) []byte {
	if d.Addr >= uint64(len(u.mem)) {
		return nil
	}
	start := d.Addr
	frameEnd := (uint64(u.frameIndex(d.Addr)) + 1) * u.frameSize
	end := d.Addr + uint64(d.Len)
	if end > frameEnd {
		end = frameEnd
	}
	return u.mem[start:end:frameEnd]
}

// FrameFull returns the full frame chunk for the frame containing d.Addr (len ==
// cap == FrameSize) for producers that need to write a fresh frame, or nil if
// d.Addr is outside the UMEM.
func (u *UMEM) FrameFull(d Desc) []byte {
	if d.Addr >= uint64(len(u.mem)) {
		return nil
	}
	base := uint64(u.frameIndex(d.Addr)) * u.frameSize
	return u.mem[base : base+u.frameSize : base+u.frameSize]
}

// Alloc pops up to n free frames and appends them to dst as descriptors with
// Addr set and Len = FrameSize, ready to fill and Transmit. It may append fewer
// than n (down to zero) when the pool is short; callers MUST handle a short
// return — this is the contract slavc/xdp callers violated by panicking on a
// short GetDescs. Used for the scheduled/keepalive TX and any non-zero-copy
// path; the zero-copy path instead hands an RX descriptor straight to Transmit.
func (u *UMEM) Alloc(dst []Desc, n int) []Desc {
	if n <= 0 {
		return dst
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if n > len(u.free) {
		n = len(u.free)
	}
	top := len(u.free) - n
	for _, idx := range u.free[top:] {
		dst = append(dst, Desc{Addr: u.frameAddr(idx), Len: uint32(u.frameSize)})
	}
	u.free = u.free[:top]
	return dst
}

// Free returns the frames referenced by descs to the pool. Use it for RX frames
// the handler dropped and for TX frames Alloc'd but not transmitted, so they
// re-enter circulation instead of leaking. Each frame must be Free'd exactly
// once (or reclaimed via a socket's Complete for TX'd frames), never both.
func (u *UMEM) Free(descs []Desc) {
	if len(descs) == 0 {
		return
	}
	u.mu.Lock()
	for _, d := range descs {
		u.free = append(u.free, u.frameIndex(d.Addr))
	}
	u.mu.Unlock()
}

// allocInto pops up to n free frame indices into dst (caller holds no lock).
// Returns the possibly-shorter slice. Used by Socket.Fill.
func (u *UMEM) allocInto(dst []uint32, n int) []uint32 {
	if n <= 0 {
		return dst
	}
	u.mu.Lock()
	if n > len(u.free) {
		n = len(u.free)
	}
	top := len(u.free) - n
	dst = append(dst, u.free[top:]...)
	u.free = u.free[:top]
	u.mu.Unlock()
	return dst
}

// freeIdx returns frame indices to the pool. Used by Socket.Complete.
func (u *UMEM) freeIdx(idxs []uint32) {
	if len(idxs) == 0 {
		return
	}
	u.mu.Lock()
	u.free = append(u.free, idxs...)
	u.mu.Unlock()
}

// NumFreeFrames reports how many frames are currently allocatable.
func (u *UMEM) NumFreeFrames() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.free)
}

// FD returns the registration fd that sockets reference via XDP_SHARED_UMEM.
func (u *UMEM) FD() int { return u.regFD }

// Close munmaps the frame area and closes the registration fd. Call it only
// after every Socket bound to this UMEM has been Closed (the kernel refcounts
// the UMEM, but closing the regFD while sockets still reference it is closing
// out from under them). Errors are joined so one failure does not skip the rest.
func (u *UMEM) Close() error {
	var errs []error
	if u.mem != nil {
		if err := unix.Munmap(u.mem); err != nil {
			errs = append(errs, err)
		}
		u.mem = nil
	}
	if u.regFD != -1 {
		if err := unix.Close(u.regFD); err != nil {
			errs = append(errs, err)
		}
		u.regFD = -1
	}
	if len(errs) > 0 {
		return fmt.Errorf("xsk: UMEM close: %w", errs[0])
	}
	return nil
}
