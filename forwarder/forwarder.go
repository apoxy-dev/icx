//go:build linux

package forwarder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/internal/xsk"
	"github.com/apoxy-dev/icx/queues"
)

// Handler decapsulates and encapsulates frames between the physical and virtual
// interfaces, operating IN PLACE on a single shared-UMEM frame: it is handed the
// frame buffer and the (offset, length) window of the input packet within it,
// and returns the (offset, length) window of the output packet within the SAME
// buffer. The output overlaps the input — no copy between separate buffers — so a
// frame received on one socket is transformed and transmitted on the other
// without ever leaving the UMEM. *icx.Handler implements this; its in-place
// transforms are byte-for-byte equivalent to the cross-buffer ones (kept for
// non-zero-copy callers).
type Handler interface {
	// PhyToVirtInPlace converts a physical frame to a virtual frame (typically
	// decapsulation), in place within buf. The input physical frame is
	// buf[off:off+length]; it returns the (offset, length) window of the
	// resulting virtual frame within buf, or length 0 to drop.
	PhyToVirtInPlace(buf []byte, off, length int) (outOff, outLen int)
	// VirtToPhyInPlace converts a virtual frame to a physical frame (typically
	// encapsulation), in place within buf. It returns the (offset, length) window
	// of the resulting physical frame within buf, or length 0 to drop. handled
	// reports an immediate local reply (ARP/ND) that must be transmitted back on
	// the virtual interface rather than forwarded to the physical one.
	VirtToPhyInPlace(buf []byte, off, length int) (outOff, outLen int, handled bool)
	// ToPhyInPlace is called periodically to let the handler emit scheduled
	// frames (e.g. keep-alives) to the physical interface, built in place within
	// buf starting at off. It returns the (offset, length) window of the frame,
	// or length 0 when there is nothing to send.
	ToPhyInPlace(buf []byte, off int) (outOff, outLen int)
}

type ForwarderOption func(*forwarderOptions) error

type forwarderOptions struct {
	phyName        string
	virtName       string
	phyFilter      *filter.Program
	pcapWriter     *pcapgo.Writer
	pinCPU         bool
	numQueues      int
	busyPoll       int
	busyPollBudget int
}

func defaultForwarderOptions() forwarderOptions {
	return forwarderOptions{
		phyName:  "eth0",
		virtName: "tun0",
		pinCPU:   true,
	}
}

// WithPhyName sets the name of the physical interface to use.
// Defaults to "eth0".
func WithPhyName(name string) ForwarderOption {
	return func(o *forwarderOptions) error {
		o.phyName = name
		return nil
	}
}

// WithVirtName sets the name of the virtual interface to use.
// Defaults to "tun0".
func WithVirtName(name string) ForwarderOption {
	return func(o *forwarderOptions) error {
		o.virtName = name
		return nil
	}
}

// WithPcapWriter sets a pcap writer to log all frames sent and received on both
// interfaces. If nil, no pcap logging is performed.
func WithPcapWriter(writer *pcapgo.Writer) ForwarderOption {
	return func(o *forwarderOptions) error {
		o.pcapWriter = writer
		return nil
	}
}

// WithPhyFilter sets a custom XDP filter program to use on the physical interface.
// If nil, a default filter is created that accepts all Geneve packets addressed
// to the default port (6081).
func WithPhyFilter(prog *filter.Program) ForwarderOption {
	return func(o *forwarderOptions) error {
		o.phyFilter = prog
		return nil
	}
}

// WithCPUPinning controls whether each per-queue datapath goroutine pins its
// (LockOSThread'd) OS thread to a distinct CPU drawn from the process's allowed
// affinity mask. Enabled by default: the per-queue loops are long-lived busy
// pollers, so keeping each one resident on one core cuts the cross-core cache and
// scheduler churn the unpinned default incurred (APO-670). Disable it on
// oversubscribed or shared hosts where the dedicated-core assumption does not
// hold.
func WithCPUPinning(enabled bool) ForwarderOption {
	return func(o *forwarderOptions) error {
		o.pinCPU = enabled
		return nil
	}
}

// WithNumQueues overrides the number of per-queue datapath sockets to create,
// instead of deriving it from the NIC's reported channel count. A non-positive
// value (the default) keeps the auto-derived count. This is needed on devices
// whose ethtool channel count exceeds the number of AF_XDP-bindable queues — for
// example SR-IOV VFs, which advertise the PF's max channels but only expose a
// couple of real queues, so binding the surplus queues fails with EINVAL.
func WithNumQueues(n int) ForwarderOption {
	return func(o *forwarderOptions) error {
		o.numQueues = n
		return nil
	}
}

// WithBusyPoll enables AF_XDP socket busy polling on every datapath socket. usecs
// is the SO_BUSY_POLL timeout in microseconds (around 20 is typical); usecs <= 0
// leaves busy poll disabled (the default). budget caps how many packets one
// busy-poll NAPI pass processes (SO_BUSY_POLL_BUDGET); budget <= 0 uses
// xsk.DefaultBusyPollBudget.
//
// Busy polling makes the forwarder's own poll() drive the NIC's NAPI inline, on
// the datapath thread's core, instead of relying on the NIC IRQ's RX softirq
// running on a separate (IRQ-affined) core. Combined with the per-netdev
// napi_defer_hard_irqs/gro_flush_timeout knobs this also sets (and restores on
// Close), it is the AF_XDP equivalent of a DPDK poll-mode driver: the RX path no
// longer needs the IRQ core at all. That removes the contention which made a
// naively pinned datapath thread (WithCPUPinning) collapse ~10x when it landed on
// the NIC RX softirq core (APO-670). Like CPU pinning, busy poll burns the core
// at 100%, so enable it only on a dedicated datapath host. Requires Linux >= 5.11.
func WithBusyPoll(usecs, budget int) ForwarderOption {
	return func(o *forwarderOptions) error {
		o.busyPoll = usecs
		o.busyPollBudget = budget
		return nil
	}
}

// socketOpts are the per-socket ring sizes and the shared-UMEM frame-pool size.
// One UMEM per queue now backs BOTH the phy and virt sockets (the zero-copy
// datapath: a frame received on one interface is transformed in place and
// transmitted on the other, never leaving the pool). That pool therefore feeds
// eight rings — FILL/RX/TX/COMPLETION on each of the two sockets — so to never
// stall for frames we size it to cover all of them at once:
// 2 sockets x (Fill+Rx+Tx+Comp) = 2 x 16384 = 32768 frames (64 MiB at 2 KiB
// frames). FrameSize 2048 leaves the kernel's 256-byte RX headroom plus room for
// a full inner packet and the outer Eth/IP/UDP+Geneve headers and GCM tag the
// encap path prepends/appends in place.
var socketOpts = xsk.Options{
	NumFrames:              32768,
	FrameSize:              2048,
	FillRingNumDescs:       4096,
	CompletionRingNumDescs: 4096,
	RxRingNumDescs:         4096,
	TxRingNumDescs:         4096,
}

// phySockOpts returns the bind options for the FIRST (phy) socket. On a
// zero-copy-capable NIC (mlx5/ixgbe), a best-effort bind grabs driver zero-copy
// and DMA-maps the shared UMEM to the phy, after which the shared virt (veth)
// bind fails EOPNOTSUPP (APO-800). Pinning the phy to XDP_COPY keeps the UMEM
// shareable across both sockets, which the in-place handoff datapath requires.
// Busy poll (if enabled) applies to the phy socket too — it is the NIC RX path
// whose softirq otherwise contends with a pinned datapath thread (APO-670).
func (f *Forwarder) phySockOpts() xsk.Options {
	so := socketOpts
	so.ForceCopy = true
	so.BusyPoll = f.busyPoll
	so.BusyPollBudget = f.busyPollBudget
	return so
}

// virtSockOpts returns the bind options for the virt (veth) socket, which shares
// the phy's UMEM. It carries the same busy-poll setting so both ends of the
// in-place handoff drive their NAPI inline on the datapath thread's core.
func (f *Forwarder) virtSockOpts() xsk.Options {
	so := socketOpts
	so.BusyPoll = f.busyPoll
	so.BusyPollBudget = f.busyPollBudget
	return so
}

// napiDeferHardIRQs and napiGROFlushTimeoutNS are the per-netdev NAPI-defer knob
// values busy poll sets, mirroring the kernel's Documentation/networking/af_xdp.rst
// busy-poll example: defer up to 2 hard IRQs and hold GRO for 200µs, which is the
// window in which the application's busy poll is expected to drive the next NAPI
// run instead of the hard IRQ re-arming.
const (
	napiDeferHardIRQs     = 2
	napiGROFlushTimeoutNS = 200000
)

// enableNapiDefer sets dev's napi_defer_hard_irqs and gro_flush_timeout sysfs
// knobs so socket busy poll takes NAPI over from the hard IRQ: with them set the
// kernel stops re-arming the NIC's hard IRQ after a NAPI run and instead waits for
// the application's busy poll to drive the next one — moving the RX softirq off
// its own IRQ-affined core onto the datapath thread's core. Without them
// SO_PREFER_BUSY_POLL still busy-polls, but the hard IRQ keeps firing in parallel
// and the IRQ-core contention busy poll is meant to remove (APO-670) persists.
//
// Best-effort: a read/write failure is logged, not fatal (the per-socket
// setsockopts are the real contract; this is host tuning, and some virtual
// netdevs do not expose the knobs). The returned closure restores the prior values
// on Close so the forwarder does not permanently retune the host NIC.
func enableNapiDefer(dev string) func() {
	var restores []func()
	for _, knob := range []struct {
		name string
		val  int
	}{
		{"napi_defer_hard_irqs", napiDeferHardIRQs},
		{"gro_flush_timeout", napiGROFlushTimeoutNS},
	} {
		path := filepath.Join("/sys/class/net", dev, knob.name)
		prior, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("busy-poll: cannot read NAPI-defer knob (leaving unchanged)",
				slog.String("dev", dev), slog.String("knob", knob.name), slog.Any("error", err))
			continue
		}
		if err := os.WriteFile(path, []byte(strconv.Itoa(knob.val)), 0o644); err != nil {
			slog.Warn("busy-poll: cannot set NAPI-defer knob; busy poll will run but the hard IRQ keeps firing",
				slog.String("dev", dev), slog.String("knob", knob.name), slog.Any("error", err))
			continue
		}
		priorVal := strings.TrimSpace(string(prior))
		restorePath := path
		restores = append(restores, func() {
			if err := os.WriteFile(restorePath, []byte(priorVal), 0o644); err != nil {
				slog.Warn("busy-poll: failed to restore NAPI-defer knob",
					slog.String("path", restorePath), slog.String("value", priorVal), slog.Any("error", err))
			}
		})
	}
	return func() {
		for _, r := range restores {
			r()
		}
	}
}

// txBatchSize mirrors the kernel's copy-mode TX_BATCH_SIZE: xsk_generic_xmit
// pulls at most this many descriptors off the TX ring per sendto (and never pulls
// autonomously). flushTx kicks repeatedly because of it.
const txBatchSize = 32

// maxTxDrainKicks bounds flushTx's kicks per call so even a fully backed-up TX
// ring (TxRingNumDescs deep) can drain in a single pass without unbounded
// syscalls. The no-progress break ends the loop early on the common path.
var maxTxDrainKicks = socketOpts.TxRingNumDescs/txBatchSize + 1

// flushTx drains a socket's copy-mode TX ring by kicking until it empties or the
// kernel stops accepting descriptors (sndbuf / completion-ring full — the next
// Complete frees that). Without it, a single post-Transmit kick submits only
// txBatchSize frames to the driver and the rest of the batch is stranded once the
// producer goes idle: the ~288-frame copy-mode stall (APO-801). It is a cheap
// no-op (one ring read) when the TX ring is empty, and elides its kicks when the
// socket is draining under NEED_WAKEUP.
func flushTx(s *xsk.Socket) error {
	for i := 0; i < maxTxDrainKicks; i++ {
		before := s.NumTransmitted()
		if before == 0 {
			return nil
		}
		if err := s.Kick(); err != nil {
			return err
		}
		if s.NumTransmitted() >= before {
			// Kernel accepted nothing this round (back-pressure); the queued
			// descriptors stay put until a Complete frees sndbuf/CQ space.
			return nil
		}
	}
	return nil
}

// minInPlaceHeadroom is the largest outer-header prepend the in-place encap
// performs: udp.PayloadOffsetIPv6 (62) + the fixed 32-byte Geneve header = 94
// bytes. The zero-copy datapath rests on the kernel leaving at least this many
// bytes of in-frame headroom before RX data; in aligned mode with
// UmemReg.Headroom == 0 that reserve is XDP_PACKET_HEADROOM (256), asserted by
// TestForwarderRXHeadroom. VirtToPhyInPlace's own phyStart < 0 guard keeps a
// short headroom from corrupting memory, but it would degrade SILENTLY into a
// 100% encap drop. forwardInPlace asserts the real, kernel-produced offset
// against this floor so that ABI violation is loud once instead of invisible.
const minInPlaceHeadroom = 94

// headroomWarnOnce ensures the headroom-floor violation is logged at most once
// per process: if the kernel ever grants too little headroom it does so for
// every frame, and a per-packet log would flood.
var headroomWarnOnce sync.Once

// Forwarder splices frames between a physical and a virtual interface using XDP sockets.
// It uses a handler to convert frames between the two interfaces.
type Forwarder struct {
	handler      Handler
	phyFilter    *filter.Program
	pcapWriterMu sync.Mutex
	pcapWriter   *pcapgo.Writer
	phyLink      netlink.Link
	virtLink     netlink.Link
	phy          []*xsk.Socket
	virtFilter   *filter.Program
	virt         []*xsk.Socket
	// umems[q] is the single UMEM shared by phy[q] and virt[q] — the frame pool
	// both sockets draw from, which is what makes the zero-copy in-place handoff
	// between them possible. Each is Closed exactly once, after both its sockets.
	umems     []*xsk.UMEM
	closeOnce sync.Once
	// pinCPU pins each per-queue goroutine's OS thread to a distinct CPU (APO-670).
	pinCPU bool
	// busyPoll (>0) enables AF_XDP socket busy poll at this SO_BUSY_POLL timeout in
	// microseconds; busyPollBudget caps the per-pass NAPI budget (APO-670).
	busyPoll       int
	busyPollBudget int
	// napiDeferRestore holds closures that put the per-netdev NAPI-defer sysfs
	// knobs back to their pre-forwarder values on Close, so enabling busy poll does
	// not permanently retune the host NIC. Empty when busy poll is disabled.
	napiDeferRestore []func()
}

// NewForwarder creates a new Forwarder with the given handler and options.
func NewForwarder(handler Handler, opts ...ForwarderOption) (*Forwarder, error) {
	options := defaultForwarderOptions()
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}

	slog.Debug("Creating forwarder",
		slog.String("phyName", options.phyName),
		slog.String("virtName", options.virtName))

	// Attach the RX-redirect programs in SKB/generic mode. The shared-UMEM
	// datapath runs in copy mode (phyBindOpts forces XDP_COPY so the UMEM stays
	// shareable across the phy and virt sockets — APO-800). On a native-XDP-capable
	// NIC (e.g. ixgbe) a NATIVE-mode redirect program reconfigures the driver's TX
	// rings, and copy-mode AF_XDP TX frames then never reach the wire — the driver
	// silently drops them while still producing completions (proven on real ixgbe:
	// with a native program nic_tx_delta=0 at 934k "completed"/s; in SKB mode the
	// same blast egresses 934k pps). SKB mode runs the redirect in the generic XDP
	// hook, leaving the driver's TX path untouched, and still steers RX into the
	// AF_XDP sockets — which is all the copy-mode datapath needs. (APO-803.)
	filter.AttachFlags = unix.XDP_FLAGS_SKB_MODE

	phyLink, err := netlink.LinkByName(options.phyName)
	if err != nil {
		return nil, fmt.Errorf("failed to find physical interface %s: %w", options.phyName, err)
	}

	virtLink, err := netlink.LinkByName(options.virtName)
	if err != nil {
		return nil, fmt.Errorf("failed to find virtual interface %s: %w", options.virtName, err)
	}

	phyNumQueues, err := queues.NumQueues(phyLink)
	if err != nil {
		return nil, fmt.Errorf("failed to get number of queues for physical device %s: %w", options.phyName, err)
	}

	virtNumQueues, err := queues.NumQueues(virtLink)
	if err != nil {
		return nil, fmt.Errorf("failed to get number of queues for virtual device %s: %w", options.virtName, err)
	}

	// Allow capping the queue count below what the NICs report (e.g. SR-IOV VFs that
	// advertise the PF's max channels but only expose a couple of AF_XDP-bindable
	// queues). Applied before the equality check so an over-reporting phy can be
	// paired with a smaller virt.
	if options.numQueues > 0 {
		if options.numQueues > phyNumQueues || options.numQueues > virtNumQueues {
			return nil, fmt.Errorf("WithNumQueues(%d) exceeds device queue counts (phy %d, virt %d)",
				options.numQueues, phyNumQueues, virtNumQueues)
		}
		phyNumQueues = options.numQueues
		virtNumQueues = options.numQueues
	}

	if phyNumQueues != virtNumQueues {
		return nil, fmt.Errorf("physical and virtual interfaces must have the same number of queues, got %d and %d",
			phyNumQueues, virtNumQueues)
	}

	f := &Forwarder{
		handler:        handler,
		phyFilter:      options.phyFilter,
		pcapWriter:     options.pcapWriter,
		phyLink:        phyLink,
		virtLink:       virtLink,
		pinCPU:         options.pinCPU,
		busyPoll:       options.busyPoll,
		busyPollBudget: options.busyPollBudget,
	}

	// Defer the NIC's hard IRQ to the application's busy poll (and restore on
	// Close). Done before any socket binds so the very first RX is already driven
	// by busy poll rather than a softirq on the IRQ core. Best-effort per knob; the
	// per-socket setsockopts in NewSocket are the hard contract.
	if f.busyPoll > 0 {
		f.napiDeferRestore = append(f.napiDeferRestore,
			enableNapiDefer(phyLink.Attrs().Name),
			enableNapiDefer(virtLink.Attrs().Name))
	}

	// Any error after this point must release everything created so far. closeInternal
	// tolerates partial construction (nil filters, short socket slices), so a single
	// deferred call replaces the previous per-error-path cleanup (which leaked on the
	// virtFilter creation path).
	success := false
	defer func() {
		if !success {
			_ = f.closeInternal()
		}
	}()

	// If no filter was provided, create a default one that filters on the physical interface and
	// accepts all Geneve packets addressed to the default port.
	if f.phyFilter == nil {
		const defaultPort = 6081

		f.phyFilter, err = filter.Geneve(
			&net.UDPAddr{
				IP:   net.IPv4zero,
				Port: defaultPort,
			},
			&net.UDPAddr{
				IP:   net.IPv6zero,
				Port: defaultPort,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create XDP ingress filter: %w", err)
		}
	}

	if err := f.phyFilter.Attach(phyLink.Attrs().Index); err != nil {
		return nil, fmt.Errorf("failed to attach XDP ingress filter: %w", err)
	}

	// One shared UMEM per queue, bound FIRST by the phy socket (which reuses the
	// UMEM registration fd and binds normally); the virt socket binds the same
	// UMEM with XDP_SHARED_UMEM below. The UMEM is recorded in f.umems before the
	// socket attempt so the deferred closeInternal releases it even if the bind
	// fails.
	for queueID := 0; queueID < phyNumQueues; queueID++ {
		umem, err := xsk.NewUMEM(socketOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create shared UMEM: %w", err)
		}
		f.umems = append(f.umems, umem)

		sk, err := xsk.NewSocket(umem, phyLink.Attrs().Index, queueID, f.phySockOpts())
		if err != nil {
			return nil, fmt.Errorf("failed to create physical XDP socket: %w", err)
		}
		f.phy = append(f.phy, sk)

		if err := f.phyFilter.Register(queueID, sk.FD()); err != nil {
			return nil, fmt.Errorf("failed to register socket with XDP filter: %w", err)
		}
	}

	f.virtFilter, err = filter.All()
	if err != nil {
		return nil, fmt.Errorf("failed to create catch all virtual filter: %w", err)
	}

	if err := f.virtFilter.Attach(virtLink.Attrs().Index); err != nil {
		return nil, fmt.Errorf("failed to attach virtual filter: %w", err)
	}

	// Each virt socket shares its queue's phy UMEM (already bound above), binding
	// with XDP_SHARED_UMEM against the now-bound registration fd.
	for queueID := 0; queueID < virtNumQueues; queueID++ {
		sk, err := xsk.NewSocket(f.umems[queueID], virtLink.Attrs().Index, queueID, f.virtSockOpts())
		if err != nil {
			return nil, fmt.Errorf("failed to create virtual XDP socket: %w", err)
		}
		f.virt = append(f.virt, sk)

		if err := f.virtFilter.Register(queueID, sk.FD()); err != nil {
			return nil, fmt.Errorf("failed to register socket with virtual filter: %w", err)
		}
	}

	success = true
	return f, nil
}

// closeInternal tears down every resource the Forwarder owns, joining errors so
// one failure does not skip the rest. It tolerates partial construction so it can
// double as the error-path cleanup in NewForwarder. Each socket is Closed before
// its UMEM (the UMEM owns the registration fd). The XDP programs are both
// Detached and Closed — the previous implementation only Detached, leaking the
// program/map fds, and detached the virtual filter via the physical link's index.
func (f *Forwarder) closeInternal() error {
	var errs []error

	if f.phyFilter != nil {
		if err := f.phyFilter.Detach(f.phyLink.Attrs().Index); err != nil {
			errs = append(errs, fmt.Errorf("failed to detach phy XDP filter: %w", err))
		}
	}
	if f.virtFilter != nil {
		if err := f.virtFilter.Detach(f.virtLink.Attrs().Index); err != nil {
			errs = append(errs, fmt.Errorf("failed to detach virt XDP filter: %w", err))
		}
	}

	// Close every socket before any UMEM: each UMEM is shared by a phy/virt pair
	// and owns the registration fd the first (phy) socket reused, so it must
	// outlive both its sockets. (The previous per-socket sk.UMEM().Close() would
	// now double-close the shared UMEM.)
	slog.Debug("Closing physical XDP sockets")
	for _, sk := range f.phy {
		if err := sk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close phy XDP socket: %w", err))
		}
	}

	slog.Debug("Closing virtual XDP sockets")
	for _, sk := range f.virt {
		if err := sk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close virt XDP socket: %w", err))
		}
	}

	slog.Debug("Closing shared UMEMs")
	for _, umem := range f.umems {
		if err := umem.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close shared UMEM: %w", err))
		}
	}

	if f.phyFilter != nil {
		if err := f.phyFilter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close phy filter program: %w", err))
		}
	}
	if f.virtFilter != nil {
		if err := f.virtFilter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close virt filter program: %w", err))
		}
	}

	// Put the NIC's NAPI-defer knobs back the way busy poll found them, so a
	// forwarder that enabled busy poll does not leave the host NIC retuned.
	for _, restore := range f.napiDeferRestore {
		restore()
	}

	return errors.Join(errs...)
}

// Close tears down the forwarder. It is idempotent and returns the join of all
// teardown errors (the previous implementation discarded them with a bare
// "return nil", making Start's closeErr check dead).
func (f *Forwarder) Close() (err error) {
	f.closeOnce.Do(func() {
		err = f.closeInternal()
	})
	return err
}

func (f *Forwarder) Start(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	// Snapshot the allowed CPU mask ONCE here, on the (unpinned) caller's thread,
	// so every per-queue goroutine pins against the same full set. Reading it
	// inside each goroutine would be fragile: a worker thread the Go runtime
	// recycles from an already-pinned one would see a narrowed mask and mis-spread.
	// nil (pinning off or mask unreadable) leaves all queues unpinned (APO-670).
	var pinCPUs []int
	if f.pinCPU {
		pinCPUs = allowedCPUs()
	}

	for queueID := range f.phy {
		g.Go(func() error {
			return f.processFrames(ctx, queueID, pinCPUs)
		})
	}

	// Wait for cancellation or a worker error.
	err := g.Wait()

	// Now it is safe to close sockets/filters; workers have stopped touching them.
	if closeErr := f.Close(); err == nil && closeErr != nil {
		err = closeErr
	}

	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("error while processing frames: %w", err)
	}

	return nil
}

// allowedCPUs returns the sorted CPU indices in the process's affinity mask
// (cgroup cpuset / taskset-aware), or nil if it cannot be read. Called once,
// before any thread is pinned, so it reflects the full inherited mask.
func allowedCPUs() []int {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		slog.Warn("CPU pinning skipped: cannot read CPU affinity", slog.Any("error", err))
		return nil
	}
	var cpus []int
	for i := 0; i < len(set)*64; i++ {
		if set.IsSet(i) {
			cpus = append(cpus, i)
		}
	}
	if len(cpus) == 0 {
		return nil
	}
	return cpus
}

// pinThreadToCPU pins the calling OS thread (already locked to this goroutine via
// runtime.LockOSThread) to cpus[queueID mod len], so a per-queue datapath loop
// keeps its UMEM rings and working set resident on one core instead of migrating
// between them — cutting the cross-core cache traffic and scheduler churn the
// unpinned busy loop otherwise incurred (APO-670). cpus is the snapshot from
// allowedCPUs, so the target is always inside the inherited cpuset (container
// safe). Best-effort: a failure is logged and the thread left unpinned, never
// failing the datapath.
func pinThreadToCPU(queueID int, cpus []int) {
	cpu := cpus[queueID%len(cpus)]
	var set unix.CPUSet
	set.Set(cpu)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		slog.Warn("CPU pinning failed",
			slog.Int("queueID", queueID), slog.Int("cpu", cpu), slog.Any("error", err))
		return
	}
	slog.Debug("Pinned queue goroutine to CPU",
		slog.Int("queueID", queueID), slog.Int("cpu", cpu))
}

func (f *Forwarder) processFrames(ctx context.Context, queueID int, pinCPUs []int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if len(pinCPUs) > 0 {
		pinThreadToCPU(queueID, pinCPUs)
	}

	phy := f.phy[queueID]
	virt := f.virt[queueID]
	umem := f.umems[queueID] // shared by phy and virt; the in-place handoff pool

	// Per-goroutine scratch, reused across iterations. processFrames owns queueID
	// exclusively (one goroutine per queue, SPSC rings), so these are race-free
	// without synchronization. The forward batches (fwd/back/free) are sized to
	// the RX ring: every received descriptor is routed to exactly one of them, so
	// no single batch can exceed the number received (<= RxRingNumDescs) and their
	// appends never reallocate — keeping the backing arrays stable across calls.
	var rxScratch, schedScratch []xsk.Desc
	fwd := make([]xsk.Desc, 0, socketOpts.RxRingNumDescs)
	back := make([]xsk.Desc, 0, socketOpts.RxRingNumDescs)
	free := make([]xsk.Desc, 0, socketOpts.RxRingNumDescs)

	for {
		// Close() is racy so use context cancellation here.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Reserve space in the physical rx queue (bounded by what virt can transmit).
		if n := min(phy.NumFilled()+phy.NumFreeFillSlots(), virt.NumFreeTxSlots()); n > 0 {
			if need := n - phy.NumFilled(); need > 0 {
				phy.Fill(need)
			}
		}

		// Reserve space in the virt rx queue (bounded by what phy can transmit).
		if n := min(virt.NumFilled()+virt.NumFreeFillSlots(), phy.NumFreeTxSlots()); n > 0 {
			if need := n - virt.NumFilled(); need > 0 {
				virt.Fill(need)
			}
		}

		// Drive any queued copy-mode TX out to the driver before sleeping in poll.
		// The kernel pulls only txBatchSize descriptors per kick and never on its
		// own, so a batch larger than that — or any tail left after the producer
		// goes idle — needs repeated kicks or it strands in the ring (APO-801).
		if err := flushTx(phy); err != nil {
			return fmt.Errorf("failed to drain phy TX: %w", err)
		}
		if err := flushTx(virt); err != nil {
			return fmt.Errorf("failed to drain virt TX: %w", err)
		}

		// If either TX ring still holds un-drained descriptors, cap the poll sleep
		// at 1ms rather than the 100ms idle cap so we loop back promptly to reclaim
		// completions and keep kicking (copy-mode TX completion has no poll event of
		// its own — there is nothing to wake us when the COMPLETION ring fills). The
		// poll MUST actually block for (up to) that 1ms: it is the CPU yield that
		// lets the softirq/NAPI producing those TX completions run. poll() therefore
		// does not arm POLLOUT for a not-full TX ring (which the kernel reports
		// ready at < 50% full, collapsing the sleep to ~0 and starving the
		// completion softirq — APO-803). Otherwise sleep until RX-readable or 100ms.
		timeout := 100 * time.Millisecond
		if phy.NumTransmitted() > 0 || virt.NumTransmitted() > 0 {
			timeout = time.Millisecond
		}
		if err := poll(phy, virt, timeout); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return err
			}
			return fmt.Errorf("failed to poll XSKs: %w", err)
		}

		// Reclaim completed TX frames back into the shared pool.
		if numCompleted := phy.NumCompleted(); numCompleted > 0 {
			phy.Complete(numCompleted)
		}
		if numCompleted := virt.NumCompleted(); numCompleted > 0 {
			virt.Complete(numCompleted)
		}

		// Emit every scheduled frame (keep-alive) that is due this pass, built in
		// place in a freshly allocated frame and transmitted on phy. ToPhyInPlace
		// returns at most ONE network's keep-alive per call, so emitting once per loop
		// served N due networks only one-per-poll — up to N x the idle poll quantum
		// (100ms) of latency on the Nth network's keep-alive, long enough to let its
		// NAT mapping lapse on an otherwise idle queue (APO-679). Drain until nothing
		// is due (outLen == 0) or the phy TX ring fills: the loop is bounded by the
		// number of due networks and the free TX slots, and a network that cannot send
		// (no installed/expired key, counter overflow) yields outLen == 0, so it stops
		// the drain rather than spinning.
		for phy.NumFreeTxSlots() > 0 {
			schedScratch = umem.Alloc(schedScratch[:0], 1)
			if len(schedScratch) != 1 {
				break // pool momentarily exhausted; retry next loop
			}
			base, _ := frameBaseOff(schedScratch[0].Addr)
			buf := umem.FrameFull(schedScratch[0])
			outOff, outLen := f.handler.ToPhyInPlace(buf, 0)
			if buf == nil || outLen == 0 {
				// Nothing more due; return the unused frame to the pool and stop.
				umem.Free(schedScratch)
				break
			}
			schedScratch[0].Addr = base + uint64(outOff)
			schedScratch[0].Len = uint32(outLen)
			if f.pcapWriter != nil {
				f.writePcap(umem.Frame(schedScratch[0]))
			}
			if n, err := phy.Transmit(schedScratch); err != nil {
				return fmt.Errorf("failed to transmit scheduled frame: %w", err)
			} else if n < 1 {
				umem.Free(schedScratch)
				slog.Warn("Dropped scheduled-to-phy frame", slog.Int("queueID", queueID))
				break // TX ring full; resume the drain next loop
			}
		}

		// Physical -> virtual (decapsulation).
		if numReceived := phy.NumReceived(); numReceived > 0 {
			rxDescs := phy.Receive(rxScratch[:0], numReceived)
			rxScratch = rxDescs[:0]

			slog.Debug("Received frames from physical device",
				slog.Int("queueID", queueID),
				slog.Int("numReceived", len(rxDescs)))

			if err := f.forwardInPlace(queueID, umem, phy, virt, rxDescs, f.phyToVirt, fwd, back, free); err != nil {
				return err
			}
		}

		// Virtual -> physical (encapsulation, with ARP/ND loopback).
		if numReceived := virt.NumReceived(); numReceived > 0 {
			rxDescs := virt.Receive(rxScratch[:0], numReceived)
			rxScratch = rxDescs[:0]

			slog.Debug("Received frames from virtual device",
				slog.Int("queueID", queueID),
				slog.Int("numReceived", len(rxDescs)))

			if err := f.forwardInPlace(queueID, umem, virt, phy, rxDescs, f.virtToPhy, fwd, back, free); err != nil {
				return err
			}
		}
	}
}

// datapathPanicOnce bounds the recovered-panic log to a single emission so a
// crafted frame that trips an unguarded path cannot also flood the logs. Each
// such frame is still dropped and the queue keeps running.
var datapathPanicOnce sync.Once

// safeTransform runs an in-place transform but converts a panic into a frame
// drop. The transforms are written to drop malformed frames rather than panic
// (see the length/IsValid guards in handler.go), so this is a last-resort
// backstop: the processFrames loop holds runtime.LockOSThread and has no other
// recovery, so a single panicking packet would otherwise tear down the whole
// queue goroutine (and, via errgroup, the forwarder). It also contains the GCM
// inexact-overlap panic class that the in-place aliasing contract relies on.
func safeTransform(fn inPlaceFn, buf []byte, off, length int) (outOff, outLen int, handled bool) {
	defer func() {
		if r := recover(); r != nil {
			datapathPanicOnce.Do(func() {
				slog.Error("recovered panic in datapath transform; dropping frame and continuing",
					slog.Any("panic", r),
					slog.String("stack", string(debug.Stack())))
			})
			outOff, outLen, handled = 0, 0, false
		}
	}()
	return fn(buf, off, length)
}

// inPlaceFn transforms the packet at buf[off:off+length] in place and returns
// the (offset, length) window of the output within buf, plus handled: true when
// the handler produced an immediate local reply that must be transmitted back on
// the SOURCE socket (ARP/ND) rather than forwarded to the destination. A
// non-positive outLen means "drop" (the frame is returned to the pool).
type inPlaceFn func(buf []byte, off, length int) (outOff, outLen int, handled bool)

// phyToVirt adapts the handler's decapsulation transform (which never produces a
// loopback reply) to inPlaceFn.
func (f *Forwarder) phyToVirt(buf []byte, off, length int) (int, int, bool) {
	outOff, outLen := f.handler.PhyToVirtInPlace(buf, off, length)
	return outOff, outLen, false
}

// virtToPhy adapts the handler's encapsulation transform to inPlaceFn; its
// handled flag routes ARP/ND replies back onto the source (virtual) socket.
func (f *Forwarder) virtToPhy(buf []byte, off, length int) (int, int, bool) {
	return f.handler.VirtToPhyInPlace(buf, off, length)
}

// forwardInPlace runs each received descriptor through fn in place on the shared
// UMEM and transmits the transformed frame on dstSock — or back on srcSock when
// fn reports handled (an ARP/ND reply). It is zero-copy: every TX descriptor
// points at a retargeted window of its own RX frame, so no bytes are copied
// between buffers and no second frame is allocated.
//
// Ownership: the received frames are owned by this goroutine until each is either
// queued on a TX ring (then reclaimed via that socket's Complete) or returned to
// the shared pool. Dropped frames and the untransmitted tail of a short Transmit
// are Freed exactly once here. fwd/back/free are caller-owned scratch with
// capacity >= len(rxDescs); they are reset and reused, never grown.
func (f *Forwarder) forwardInPlace(
	queueID int,
	umem *xsk.UMEM,
	srcSock, dstSock *xsk.Socket,
	rxDescs []xsk.Desc,
	fn inPlaceFn,
	fwd, back, free []xsk.Desc,
) error {
	if len(rxDescs) == 0 {
		return nil
	}

	fwd, back, free = fwd[:0], back[:0], free[:0]
	for _, d := range rxDescs {
		base, off := frameBaseOff(d.Addr)
		if off < minInPlaceHeadroom {
			// The kernel granted less RX headroom than the in-place encap needs
			// to prepend the outer Eth/IP/UDP + Geneve headers. The encap path's
			// phyStart < 0 guard keeps this memory-safe, but every outbound packet
			// would then drop silently. Make the ABI violation loud (once) rather
			// than fail invisibly forever; the decap direction does not depend on
			// this floor, so keep forwarding.
			headroomWarnOnce.Do(func() {
				slog.Error("RX headroom below in-place encap floor; check UMEM registration / XDP mode",
					slog.Int("inFrameOffset", off),
					slog.Int("required", minInPlaceHeadroom))
			})
		}
		buf := umem.FrameFull(d)
		if buf == nil {
			// Foreign/malformed descriptor; return it to the pool.
			free = append(free, d)
			continue
		}

		outOff, outLen, handled := safeTransform(fn, buf, off, int(d.Len))
		if outLen <= 0 {
			free = append(free, d)
			continue
		}

		// Retarget the SAME frame's descriptor to the output window.
		d.Addr = base + uint64(outOff)
		d.Len = uint32(outLen)

		if f.pcapWriter != nil {
			f.writePcap(umem.Frame(d))
		}

		if handled {
			back = append(back, d)
		} else {
			fwd = append(fwd, d)
		}
	}

	// Forward batch to the destination socket.
	if len(fwd) > 0 {
		n, err := dstSock.Transmit(fwd)
		if n < len(fwd) {
			slog.Debug("Failed to transmit all forwarded frames",
				slog.Int("queueID", queueID),
				slog.Int("populated", len(fwd)),
				slog.Int("numTransmitted", n))
			umem.Free(fwd[n:])
		}
		if err != nil {
			// Shutting down: return the not-yet-queued frames so nothing leaks.
			umem.Free(back)
			umem.Free(free)
			return fmt.Errorf("failed to transmit frames: %w", err)
		}
	}

	// Loopback batch (ARP/ND replies) back to the source socket.
	if len(back) > 0 {
		n, err := srcSock.Transmit(back)
		if n < len(back) {
			slog.Debug("Failed to transmit all loopback frames",
				slog.Int("queueID", queueID),
				slog.Int("populated", len(back)),
				slog.Int("numTransmitted", n))
			umem.Free(back[n:])
		}
		if err != nil {
			umem.Free(free)
			return fmt.Errorf("failed to transmit loopback frames: %w", err)
		}
	}

	if len(free) > 0 {
		umem.Free(free)
	}
	return nil
}

// writePcap records one frame to the pcap writer under the writer lock.
func (f *Forwarder) writePcap(frame []byte) {
	f.pcapWriterMu.Lock()
	defer f.pcapWriterMu.Unlock()
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(frame),
		Length:        len(frame),
	}
	_ = f.pcapWriter.WritePacket(ci, frame)
}

// frameBaseOff splits a UMEM descriptor address into its chunk-aligned frame base
// and the in-frame offset of the packet (the RX headroom the kernel leaves, or
// the start an in-place transform chose). FrameSize is a power of two, so the
// base is a cheap mask. The base lets a retargeted descriptor address a new
// window within the same frame: newAddr = base + newOffset.
func frameBaseOff(addr uint64) (base uint64, off int) {
	base = addr &^ uint64(socketOpts.FrameSize-1)
	return base, int(addr - base)
}

func poll(phy, virt *xsk.Socket, timeout time.Duration) (err error) {
	var pfds [2]unix.PollFd
	pfds[0].Fd = int32(phy.FD())
	pfds[1].Fd = int32(virt.FD())

	closedFlags := int16(unix.POLLHUP | unix.POLLERR | unix.POLLNVAL)
	pfds[0].Events = closedFlags
	pfds[1].Events = closedFlags

	if phy.NumFilled() > 0 {
		pfds[0].Events |= unix.POLLIN
	}
	if virt.NumFilled() > 0 {
		pfds[1].Events |= unix.POLLIN
	}

	// POLLOUT is deliberately NOT armed for an outstanding-but-not-full TX ring.
	// In copy mode the kernel reports xsk POLLOUT-ready whenever the TX ring is
	// < 50% full, so arming it here makes poll() return immediately under TX
	// back-pressure (ring barely full, sndbuf saturated) — defeating the CPU
	// yield this poll exists to perform and busy-spinning the pinned datapath
	// thread, which starves the softirq that completes copy-mode TX (APO-803).
	// We drive the TX ring with explicit kicks (flushTx), not POLLOUT, so the
	// only thing POLLOUT would buy is a wakeup on TX-ring space — and the timeout
	// already bounds that.

	for err = unix.EINTR; err == unix.EINTR; {
		_, err = unix.Poll(pfds[:], int(timeout.Milliseconds()))
	}
	if err != nil {
		return err
	}

	if pfds[0].Revents&closedFlags != 0 || pfds[1].Revents&closedFlags != 0 {
		return os.ErrClosed
	}

	return nil
}
