//go:build linux

package forwarder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"runtime/debug"
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
	phyName    string
	virtName   string
	phyFilter  *filter.Program
	pcapWriter *pcapgo.Writer
}

func defaultForwarderOptions() forwarderOptions {
	return forwarderOptions{
		phyName:  "eth0",
		virtName: "tun0",
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

	if phyNumQueues != virtNumQueues {
		return nil, fmt.Errorf("physical and virtual interfaces must have the same number of queues, got %d and %d",
			phyNumQueues, virtNumQueues)
	}

	f := &Forwarder{
		handler:    handler,
		phyFilter:  options.phyFilter,
		pcapWriter: options.pcapWriter,
		phyLink:    phyLink,
		virtLink:   virtLink,
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

		sk, err := xsk.NewSocket(umem, phyLink.Attrs().Index, queueID, socketOpts)
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
		sk, err := xsk.NewSocket(f.umems[queueID], virtLink.Attrs().Index, queueID, socketOpts)
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

	for queueID := range f.phy {
		g.Go(func() error {
			return f.processFrames(ctx, queueID)
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

func (f *Forwarder) processFrames(ctx context.Context, queueID int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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

		if err := poll(phy, virt, 100*time.Millisecond); err != nil {
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

		// Emit any scheduled frame (e.g. keep-alive) once per loop, built in place
		// in a freshly allocated frame and transmitted on phy.
		if phy.NumFreeTxSlots() > 0 {
			if schedScratch = umem.Alloc(schedScratch[:0], 1); len(schedScratch) == 1 {
				base, _ := frameBaseOff(schedScratch[0].Addr)
				buf := umem.FrameFull(schedScratch[0])
				outOff, outLen := f.handler.ToPhyInPlace(buf, 0)
				if buf != nil && outLen > 0 {
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
					}
				} else {
					// Nothing to send; return the unused frame to the pool.
					umem.Free(schedScratch)
				}
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
	if phy.NumTransmitted() > 0 {
		pfds[0].Events |= unix.POLLOUT
	}

	if virt.NumFilled() > 0 {
		pfds[1].Events |= unix.POLLIN
	}
	if virt.NumTransmitted() > 0 {
		pfds[1].Events |= unix.POLLOUT
	}

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
