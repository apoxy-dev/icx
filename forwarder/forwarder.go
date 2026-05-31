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

// Decapsulate and encapsulate frames between physical and virtual interfaces.
type Handler interface {
	// PhyToVirt converts a physical frame to a virtual frame typically by performing decapsulation.
	// Returns the length of the resulting virtual frame.
	PhyToVirt(phyFrame, virtFrame []byte) int
	// VirtToPhy converts a virtual frame to a physical frame typically by performing encapsulation.
	// Returns the length of the resulting physical frame.
	VirtToPhy(virtFrame, phyFrame []byte) (length int, loopback bool)
	// ToPhy is called periodically to allow the handler to send
	// scheduled frames to the physical interface, e.g. keep-alive packets.
	// Returns the length of the resulting physical frame.
	ToPhy(phyFrame []byte) int
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

// socketOpts are the per-socket UMEM/ring sizes. The defaults are far too small
// for high-throughput NICs, so we size up. Each socket owns its own UMEM (the
// copy datapath: a frame received on one interface is transformed into a frame
// drawn from the other interface's pool). NumFrames must be >= Fill+Tx for
// forward progress; we give the same 8192 frames the previous implementation
// used, shared across all four rings rather than statically half-partitioned.
var socketOpts = xsk.Options{
	NumFrames:              8192,
	FrameSize:              2048,
	FillRingNumDescs:       4096,
	CompletionRingNumDescs: 4096,
	RxRingNumDescs:         4096,
	TxRingNumDescs:         4096,
}

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
	closeOnce    sync.Once
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

	for queueID := 0; queueID < phyNumQueues; queueID++ {
		sk, err := newSocket(phyLink.Attrs().Index, queueID)
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

	for queueID := 0; queueID < virtNumQueues; queueID++ {
		sk, err := newSocket(virtLink.Attrs().Index, queueID)
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

// newSocket creates a UMEM and a socket bound to it on (ifindex, queueID). If the
// socket fails to bind, the orphan UMEM is closed before returning so it does not
// leak (it is not yet owned by the Forwarder).
func newSocket(ifindex, queueID int) (*xsk.Socket, error) {
	umem, err := xsk.NewUMEM(socketOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create UMEM: %w", err)
	}
	sk, err := xsk.NewSocket(umem, ifindex, queueID, socketOpts)
	if err != nil {
		_ = umem.Close()
		return nil, fmt.Errorf("failed to create XDP socket: %w", err)
	}
	return sk, nil
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

	slog.Debug("Closing physical XDP sockets")
	for _, sk := range f.phy {
		if err := sk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close phy XDP socket: %w", err))
		}
		if err := sk.UMEM().Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close phy UMEM: %w", err))
		}
	}

	slog.Debug("Closing virtual XDP sockets")
	for _, sk := range f.virt {
		if err := sk.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close virt XDP socket: %w", err))
		}
		if err := sk.UMEM().Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close virt UMEM: %w", err))
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
	phyUMEM := phy.UMEM()
	virtUMEM := virt.UMEM()

	// Per-goroutine scratch slices, reused across iterations. processFrames owns
	// queueID exclusively (one goroutine per queue, SPSC rings), so these are
	// race-free without synchronization.
	var rxScratch, txScratch []xsk.Desc

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

		// Reclaim completed TX frames back into each socket's pool.
		if numCompleted := phy.NumCompleted(); numCompleted > 0 {
			phy.Complete(numCompleted)
		}
		if numCompleted := virt.NumCompleted(); numCompleted > 0 {
			virt.Complete(numCompleted)
		}

		// Try to emit any scheduled frames (e.g. keep-alives) once per loop.
		if phy.NumFreeTxSlots() > 0 {
			if txDescs := phyUMEM.Alloc(txScratch[:0], 1); len(txDescs) == 1 {
				txFrame := phyUMEM.FrameFull(txDescs[0])
				frameLen := f.handler.ToPhy(txFrame)
				if frameLen > 0 {
					txDescs[0].Len = uint32(frameLen)
					if n, err := phy.Transmit(txDescs); err != nil {
						return fmt.Errorf("failed to transmit scheduled frame: %w", err)
					} else if n < 1 {
						phyUMEM.Free(txDescs)
						slog.Warn("Dropped scheduled-to-phy frame", slog.Int("queueID", queueID))
					}
				} else {
					// Nothing to send; return the unused frame to the pool.
					phyUMEM.Free(txDescs)
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

			if err := f.transform(queueID, phyUMEM, virtUMEM, virt, rxDescs, f.handlePhyToVirt); err != nil {
				return err
			}
			// RX frames are consumed; return them to the phy pool for refilling.
			phyUMEM.Free(rxDescs)
		}

		// Virtual -> physical (encapsulation, with loopback).
		if numReceived := virt.NumReceived(); numReceived > 0 {
			rxDescs := virt.Receive(rxScratch[:0], numReceived)
			rxScratch = rxDescs[:0]

			slog.Debug("Received frames from virtual device",
				slog.Int("queueID", queueID),
				slog.Int("numReceived", len(rxDescs)))

			if err := f.transform(queueID, virtUMEM, phyUMEM, phy, rxDescs, f.handleVirtToPhy); err != nil {
				return err
			}
			virtUMEM.Free(rxDescs)
		}
	}
}

// transformFn populates dst frame txFrame from source frame rxFrame and returns
// the resulting length. A non-positive length means "drop" (no TX desc consumed).
// A transformFn may itself emit frames (e.g. ARP/ND/loopback replies) and return
// 0 to indicate it handled the frame without producing a forward-path TX frame.
type transformFn func(queueID int, rxFrame, txFrame []byte) int

// transform runs the RX descriptors through fn, allocating one TX frame per
// forwarded packet from dstUMEM, and transmits the populated frames on dstSock.
// Ownership: every TX frame Alloc'd but not handed to the kernel (skips + the
// untransmitted tail) is Freed back to dstUMEM. The loop is bounded by the number
// of TX frames actually allocated, fixing the out-of-range panic the previous
// implementation hit when the TX pool under-delivered relative to RX.
func (f *Forwarder) transform(
	queueID int,
	srcUMEM, dstUMEM *xsk.UMEM,
	dstSock *xsk.Socket,
	rxDescs []xsk.Desc,
	fn transformFn,
) error {
	if len(rxDescs) == 0 {
		return nil
	}

	txDescs := dstUMEM.Alloc(nil, len(rxDescs))
	populated := 0
	for i := range rxDescs {
		if populated >= len(txDescs) {
			// TX pool exhausted; remaining RX frames are dropped this round.
			break
		}
		rxFrame := srcUMEM.Frame(rxDescs[i])
		txFrame := dstUMEM.FrameFull(txDescs[populated])
		if rxFrame == nil || txFrame == nil {
			continue
		}

		frameLen := fn(queueID, rxFrame, txFrame)
		if frameLen <= 0 {
			continue
		}

		txDescs[populated].Len = uint32(frameLen)
		populated++

		if f.pcapWriter != nil {
			f.pcapWriterMu.Lock()
			ci := gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: frameLen,
				Length:        frameLen,
			}
			_ = f.pcapWriter.WritePacket(ci, txFrame[:frameLen])
			f.pcapWriterMu.Unlock()
		}
	}

	transmitted := 0
	if populated > 0 {
		n, err := dstSock.Transmit(txDescs[:populated])
		if err != nil {
			return fmt.Errorf("failed to transmit frames: %w", err)
		}
		transmitted = n
		if n < populated {
			slog.Debug("Failed to transmit all frames",
				slog.Int("queueID", queueID),
				slog.Int("populated", populated),
				slog.Int("numTransmitted", n))
		}
	}

	// Free every Alloc'd TX frame the kernel did not take: the untransmitted tail
	// [transmitted:populated) and the unused slots [populated:len(txDescs)). These
	// are contiguous as [transmitted:len(txDescs)).
	if transmitted < len(txDescs) {
		dstUMEM.Free(txDescs[transmitted:])
	}
	return nil
}

// handlePhyToVirt is the decapsulation transform.
func (f *Forwarder) handlePhyToVirt(_ int, rxFrame, txFrame []byte) int {
	return f.handler.PhyToVirt(rxFrame, txFrame)
}

// handleVirtToPhy is the encapsulation transform. When the handler reports a
// loopback frame, it is written back onto the virtual socket instead of being
// forwarded to the physical socket, and 0 is returned so no phy TX frame is
// consumed.
func (f *Forwarder) handleVirtToPhy(queueID int, rxFrame, txFrame []byte) int {
	frameLen, loopback := f.handler.VirtToPhy(rxFrame, txFrame)
	if !loopback {
		return frameLen
	}
	if frameLen <= 0 {
		return 0
	}

	// Loopback: copy the produced frame back onto the virtual socket.
	virt := f.virt[queueID]
	virtUMEM := virt.UMEM()
	loopDescs := virtUMEM.Alloc(nil, 1)
	if len(loopDescs) != 1 {
		slog.Debug("Dropped loopback frame (no free frame)", slog.Int("queueID", queueID))
		return 0
	}
	loopFrame := virtUMEM.FrameFull(loopDescs[0])
	loopDescs[0].Len = uint32(copy(loopFrame, txFrame[:frameLen]))
	if n, err := virt.Transmit(loopDescs); err != nil {
		slog.Warn("Loopback transmit failed", slog.Int("queueID", queueID), slog.Any("error", err))
		virtUMEM.Free(loopDescs)
	} else if n < 1 {
		virtUMEM.Free(loopDescs)
		slog.Debug("Dropped loopback frame", slog.Int("queueID", queueID))
	}
	return 0
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
