//go:build linux

package xsk

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// Socket is an AF_XDP socket bound to one (ifindex, queueID), backed by a shared
// UMEM. It owns all four rings — FILL, COMPLETION, RX, TX — because under
// XDP_SHARED_UMEM across different netdevs/queues each socket needs its own
// (see UMEM doc). The frame memory and the free-frame allocator live in the
// shared UMEM; the rings here are private to this socket.
//
// A Socket is single-threaded: one goroutine drives Fill/Receive/Transmit/
// Complete for it, matching the SPSC ring contract (the kernel is the other
// party on each ring). The forwarder pins one goroutine per queue
// (runtime.LockOSThread). The four rings are therefore lock-free; only the
// shared UMEM free-frame pool is mutex-guarded, since sibling sockets draw from
// it too.
type Socket struct {
	fd      int
	ifindex int
	queueID int
	umem    *UMEM
	// sharesUMEMFD is true for the FIRST socket on the UMEM, which reuses the
	// UMEM registration fd; its Close must NOT close the fd (UMEM.Close owns it).
	sharesUMEMFD bool

	fillRing ring
	compRing ring
	rxRing   ring
	txRing   ring

	fillMmap []byte
	compMmap []byte
	rxMmap   []byte
	txMmap   []byte

	// scratch reused by Fill/Complete to avoid per-call allocation.
	fillScratch []uint32
	compScratch []uint32

	opts Options
}

// FD returns the socket file descriptor (for poll and registration in an
// xsks_map so the XDP program can redirect RX traffic to this socket).
func (s *Socket) FD() int { return s.fd }

// UMEM returns the shared UMEM backing this socket.
func (s *Socket) UMEM() *UMEM { return s.umem }

// Fill hands up to n free frames to the kernel on this socket's FILL ring so it
// can receive into them, returning how many were queued (bounded by free
// FILL-ring slots AND free frames in the shared pool). submit publishes exactly
// the count written, so a short pool fills fewer slots and never exposes an
// unwritten slot to the kernel.
func (s *Socket) Fill(n int) int {
	start, got := s.fillRing.reserve(uint32(n))
	if got == 0 {
		return 0
	}
	s.fillScratch = s.umem.allocInto(s.fillScratch[:0], int(got))
	got = uint32(len(s.fillScratch))
	for i := uint32(0); i < got; i++ {
		*at[uint64](&s.fillRing, start+i) = s.umem.frameAddr(s.fillScratch[i])
	}
	s.fillRing.submit(got)
	return int(got)
}

// Complete reclaims up to n frames the kernel finished transmitting on this
// socket's COMPLETION ring back into the shared free pool, returning how many
// were reclaimed.
func (s *Socket) Complete(n int) int {
	start, got := s.compRing.peek(uint32(n))
	if got == 0 {
		return 0
	}
	s.compScratch = s.compScratch[:0]
	for i := uint32(0); i < got; i++ {
		addr := *at[uint64](&s.compRing, start+i)
		s.compScratch = append(s.compScratch, s.umem.frameIndex(addr))
	}
	s.compRing.release(got)
	s.umem.freeIdx(s.compScratch)
	return int(got)
}

// Receive consumes up to n frames the kernel produced on the RX ring, appending
// the descriptors to dst and returning it. Returns into a caller-owned slice
// (no shared scratch buffer aliasing footgun). The frames referenced by the
// returned descriptors are owned by the caller until either handed to a TX ring
// (Transmit) or released back to the shared pool (ReleaseRX).
func (s *Socket) Receive(dst []Desc, n int) []Desc {
	start, got := s.rxRing.peek(uint32(n))
	for i := uint32(0); i < got; i++ {
		dst = append(dst, *at[Desc](&s.rxRing, start+i))
	}
	s.rxRing.release(got)
	return dst
}

// ReleaseRX returns RX frames to the shared free pool without transmitting them
// (the drop path), so they re-enter circulation instead of leaking. Thin alias
// for UMEM.Free, kept on Socket for symmetry with Receive.
func (s *Socket) ReleaseRX(descs []Desc) {
	s.umem.Free(descs)
}

// Transmit queues descs on the TX ring and kicks the kernel if needed. It
// returns the number actually queued (bounded by free TX-ring slots) and an
// error. Unlike slavc/xdp it NEVER panics: an unexpected sendto errno is
// returned so the caller can treat link-down conditions as a graceful shutdown.
//
// The descriptors' frames must be owned by the caller (freshly received or
// Alloc'd). The queued descs[:n] are handed to the kernel and reclaimed later
// via Complete. IMPORTANT: when n < len(descs) (TX ring full), the tail
// descs[n:] was NOT queued and its frames are still owned by the caller — the
// caller MUST UMEM.Free(descs[n:]) (or retry it) or those frames leak. This is
// the explicit ownership rule that replaces slavc/xdp's silently-dropped tail.
func (s *Socket) Transmit(descs []Desc) (int, error) {
	start, got := s.txRing.reserve(uint32(len(descs)))
	for i := uint32(0); i < got; i++ {
		*at[Desc](&s.txRing, start+i) = descs[i]
	}
	s.txRing.submit(got)
	if got == 0 {
		return 0, nil
	}
	if err := s.kick(); err != nil {
		return int(got), err
	}
	return int(got), nil
}

// kick wakes the kernel to process the TX ring, but only if NEED_WAKEUP says it
// is required (or the socket was not bound with NEED_WAKEUP, in which case we
// always kick). Recoverable conditions (EINTR retried; EAGAIN/EBUSY benign) are
// not errors; anything else is returned, not panicked.
func (s *Socket) kick() error {
	if !s.txRing.needsWakeup() {
		return nil
	}
	for {
		_, _, errno := unix.Syscall6(unix.SYS_SENDTO, uintptr(s.fd),
			0, 0, uintptr(unix.MSG_DONTWAIT), 0, 0)
		switch errno {
		case 0:
			return nil
		case unix.EINTR:
			continue
		case unix.EAGAIN, unix.EBUSY:
			return nil
		default:
			return fmt.Errorf("xsk: sendto kick: %w", errno)
		}
	}
}

// NeedsRxWakeup reports whether the kernel wants a poll() wakeup to make RX/FILL
// progress (XDP_USE_NEED_WAKEUP). When false, the forwarder can skip the poll.
func (s *Socket) NeedsRxWakeup() bool { return s.fillRing.needsWakeup() }

// NumReceived reports how many RX descriptors are available to consume.
func (s *Socket) NumReceived() int { return int(s.rxRing.available()) }

// NumFreeTxSlots reports how many TX-ring slots are free to produce into.
func (s *Socket) NumFreeTxSlots() int { return int(s.txRing.freeSlots()) }

// NumFreeFillSlots reports how many FILL-ring slots are free to produce into.
func (s *Socket) NumFreeFillSlots() int { return int(s.fillRing.freeSlots()) }

// NumCompleted reports how many frames are waiting on the COMPLETION ring to be
// reclaimed via Complete.
func (s *Socket) NumCompleted() int { return int(s.compRing.available()) }

// NumTransmitted reports how many descriptors are queued on the TX ring that the
// kernel has not yet consumed (in-flight), for POLLOUT gating. Derived from the
// ring indices, so it cannot drift the way slavc/xdp's hand-maintained counter
// did.
func (s *Socket) NumTransmitted() int {
	return int(s.txRing.size - s.txRing.freeSlots())
}

// Close munmaps this socket's four rings and closes its fd — unless this is the
// first socket on the UMEM, which reuses the UMEM registration fd (UMEM.Close
// owns and closes that). It does NOT close the shared UMEM; the caller owns that
// and must Close it after all its sockets are closed. Errors are joined.
func (s *Socket) Close() error {
	var errs []error
	for _, m := range [][]byte{s.fillMmap, s.compMmap, s.rxMmap, s.txMmap} {
		if m != nil {
			if err := unix.Munmap(m); err != nil {
				errs = append(errs, err)
			}
		}
	}
	s.fillMmap, s.compMmap, s.rxMmap, s.txMmap = nil, nil, nil, nil
	// The first socket shares the UMEM registration fd; UMEM.Close owns and
	// closes it. Only a socket with its own fd closes it here.
	if s.fd != -1 && !s.sharesUMEMFD {
		if err := unix.Close(s.fd); err != nil {
			errs = append(errs, err)
		}
	}
	s.fd = -1
	return errors.Join(errs...)
}

// (NewUMEM / NewSocket constructors live in setup_linux.go.)
