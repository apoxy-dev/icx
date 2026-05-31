//go:build linux

package xsk

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Desc is an XDP Rx/Tx descriptor: {Addr uint64; Len uint32; Options uint32}.
// It is an alias for the kernel ABI struct so callers can set .Len/.Addr
// directly and slices of Desc map straight onto the ring memory.
type Desc = unix.XDPDesc

// Options configure a UMEM and its sockets. All ring sizes must be powers of
// two; NumFrames must be >= the sum of frames that can be in flight across the
// FILL/RX/TX/COMPLETION rings.
type Options struct {
	// NumFrames is the number of frames in the UMEM (frame pool size).
	NumFrames int
	// FrameSize is the size of each frame in bytes; must be a power of two
	// (chunk size). 2048 or 4096 are typical.
	FrameSize int

	FillRingNumDescs       int
	CompletionRingNumDescs int
	RxRingNumDescs         int
	TxRingNumDescs         int

	// UseNeedWakeup binds with XDP_USE_NEED_WAKEUP so the kernel can tell us
	// when a poll()/sendto() wakeup is actually required, eliding syscalls.
	UseNeedWakeup bool
	// ZeroCopy requests XDP_ZEROCOPY at bind. If the driver does not support
	// it, NewSocket fails rather than silently falling back; callers that want
	// a fallback should retry with ZeroCopy=false (XDP_COPY).
	ZeroCopy bool
}

// DefaultOptions mirror sane high-throughput defaults (icx currently uses
// NumFrames=8192, FrameSize=2048, all rings=4096).
var DefaultOptions = Options{
	NumFrames:              8192,
	FrameSize:              2048,
	FillRingNumDescs:       4096,
	CompletionRingNumDescs: 4096,
	RxRingNumDescs:         4096,
	TxRingNumDescs:         4096,
}

func isPow2(n int) bool { return n > 0 && (n&(n-1)) == 0 }

func (o Options) validate() error {
	if !isPow2(o.FrameSize) {
		return fmt.Errorf("xsk: FrameSize must be a power of two, got %d", o.FrameSize)
	}
	for name, v := range map[string]int{
		"FillRingNumDescs":       o.FillRingNumDescs,
		"CompletionRingNumDescs": o.CompletionRingNumDescs,
		"RxRingNumDescs":         o.RxRingNumDescs,
		"TxRingNumDescs":         o.TxRingNumDescs,
	} {
		if v != 0 && !isPow2(v) {
			return fmt.Errorf("xsk: %s must be zero or a power of two, got %d", name, v)
		}
	}
	if o.RxRingNumDescs == 0 && o.TxRingNumDescs == 0 {
		return fmt.Errorf("xsk: RxRingNumDescs and TxRingNumDescs cannot both be zero")
	}
	if o.NumFrames <= 0 {
		return fmt.Errorf("xsk: NumFrames must be > 0, got %d", o.NumFrames)
	}
	// Floor for forward progress: enough frames to prime the FILL ring and still
	// have a TX batch. Fill/Alloc handle a short pool gracefully (they return
	// fewer than requested rather than over-publishing — the slavc/xdp bug), so
	// this is a sane minimum, not a hard ABI requirement.
	//
	// To fully saturate every ring without ever stalling for frames, size
	// NumFrames >= FillRingNumDescs + RxRingNumDescs + TxRingNumDescs +
	// CompletionRingNumDescs, since a frame can be outstanding in any of those
	// four rings at once. (A shared UMEM should also scale by socket count.)
	if minFrames := o.FillRingNumDescs + o.TxRingNumDescs; o.NumFrames < minFrames {
		return fmt.Errorf("xsk: NumFrames (%d) < FillRingNumDescs+TxRingNumDescs (%d); frame pool too small for forward progress",
			o.NumFrames, minFrames)
	}
	return nil
}

// Stats reports ring progress counters plus the kernel-side XDP statistics.
type Stats struct {
	Filled      uint64
	Received    uint64
	Transmitted uint64
	Completed   uint64
	KernelStats unix.XDPStatistics
}
