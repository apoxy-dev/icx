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
	// ForceCopy requests XDP_COPY at bind, pinning the socket to copy mode even
	// on a zero-copy-capable driver. The shared-UMEM datapath needs the FIRST
	// (phy) socket pinned to copy so the kernel does not ZC-DMA-map the UMEM to
	// one netdev, which would make the second (shared) bind fail EOPNOTSUPP. Set
	// it on the phy socket only — XDP_COPY on the shared bind itself is EINVAL.
	ForceCopy bool

	// BusyPoll, when > 0, enables socket busy polling on the socket (Linux >=
	// 5.11): a poll()/recvmsg() on this fd drives the bound netdev's NAPI inline
	// on the calling core, instead of waiting for the NIC IRQ's RX softirq to run
	// on its own (IRQ-affined) core. It is the AF_XDP analogue of a DPDK poll-mode
	// driver and removes the IRQ-core contention a pinned datapath thread
	// otherwise hits (APO-670). The value is the SO_BUSY_POLL timeout in
	// microseconds (a value around 20 is typical). The per-netdev
	// napi_defer_hard_irqs/gro_flush_timeout knobs that make the IRQ deferral
	// actually engage are set out of band (the forwarder does it); without them
	// busy poll still runs but the hard IRQ keeps firing in parallel.
	BusyPoll int
	// BusyPollBudget caps how many packets one busy-poll NAPI pass processes
	// (SO_BUSY_POLL_BUDGET). Zero uses DefaultBusyPollBudget when BusyPoll > 0,
	// and is ignored entirely when BusyPoll == 0.
	BusyPollBudget int
}

// DefaultBusyPollBudget is the SO_BUSY_POLL_BUDGET used when BusyPoll is enabled
// but BusyPollBudget is left zero. It mirrors NAPI_POLL_WEIGHT (the per-poll
// packet budget the kernel uses for ordinary softirq NAPI) and the value in the
// kernel's Documentation/networking/af_xdp.rst busy-poll example.
const DefaultBusyPollBudget = 64

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
	if o.BusyPoll < 0 {
		return fmt.Errorf("xsk: BusyPoll must be >= 0 (microseconds), got %d", o.BusyPoll)
	}
	if o.BusyPollBudget < 0 {
		return fmt.Errorf("xsk: BusyPollBudget must be >= 0, got %d", o.BusyPollBudget)
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
