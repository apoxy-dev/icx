// Package netstack implements the netstack VTEP datapath driver: it splices a
// gVisor channel.Endpoint (the overlay-side, userspace L3 link) to the ICX
// engine, moving encap'd frames over an injected underlay transport.
//
// It is the unprivileged, software-only driver of the vtep family. The driver
// owns neither the gVisor stack nor the underlay socket — both are injected by
// the consumer:
//
//   - apoxy-cli builds a full netstack.Stack (SOCKS, SNAT, TCP/UDP forwarders)
//     and supplies its channel.Endpoint plus an l2pc-backed underlay.
//   - clrk attaches to the sentry's existing netstack (the geneve0 NIC) and
//     supplies its own UDP underlay socket.
//
// Both consume the same engine + pump; only the stack construction and the
// underlay differ. This is the consumer-locality seam: the overlay consumer
// lives inside a userspace netstack, so the driver is software.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/icx/vtep"
	"golang.org/x/sync/errgroup"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// maxBatchSize bounds how many frames the outbound pump coalesces into a single
// underlay write. It matches the underlay's own batch ceiling.
const maxBatchSize = 64

// defaultFlushInterval is how often the outbound pump flushes engine-scheduled
// frames (keep-alives via EngineXfrm.ToPhy) when there is no overlay traffic.
const defaultFlushInterval = 100 * time.Millisecond

// Underlay is the physical/underlay frame transport the datapath reads encap'd
// frames from and writes them to. apoxy-cli's *l2pc.L2PacketConn satisfies this
// via a thin adapter; clrk supplies its own UDP-backed implementation.
//
// The datapath does not own the underlay's lifecycle — the consumer closes it.
// Closing the underlay is also what unblocks a running Run: ReadFrame must
// return an error satisfying errors.Is(err, net.ErrClosed) once closed.
type Underlay interface {
	// ReadFrame reads a single underlay frame into buf, returning its length.
	// A length of 0 with a nil error is skipped.
	ReadFrame(buf []byte) (int, error)
	// WriteFrames writes a batch of underlay frames, returning the number actually
	// sent. A short write (n < len(frames)) is permitted — a batched datagram send
	// can put fewer frames on the wire than offered (EAGAIN, a mid-batch error, or
	// a platform whose batch syscall degrades to one message per call). The datapath
	// drains the unsent suffix (frames[n:]) by calling again, so implementations
	// must NOT silently drop the tail. A zero return with a nil error is treated as
	// a stall. The frames are owned by the caller and remain valid only until the
	// call returns, so implementations must not retain them.
	WriteFrames(frames [][]byte) (int, error)
}

// Config configures a Datapath. Engine, Endpoint and Underlay are required.
type Config struct {
	// Engine is the ICX engine performing encap/decap + crypto. *icx.Handler
	// satisfies this; it must be configured in layer3 mode.
	Engine vtep.EngineXfrm
	// Endpoint is the overlay-side gVisor link endpoint. The consumer owns the
	// enclosing stack.Stack and NIC; the datapath only reads/injects frames.
	Endpoint *channel.Endpoint
	// Underlay is the encap'd-frame transport. See Underlay.
	Underlay Underlay
	// FlushInterval overrides how often scheduled frames are flushed. Zero uses
	// defaultFlushInterval.
	FlushInterval time.Duration
}

// Datapath splices a channel.Endpoint to the ICX engine over an underlay. It
// implements vtep.Datapath.
type Datapath struct {
	engine   vtep.EngineXfrm
	ep       *channel.Endpoint
	underlay Underlay
	flush    time.Duration

	// wake coalesces outbound notifications from the endpoint (capacity 1). It is
	// deliberately never closed: WriteNotify can fire from stack goroutines at any
	// time, including concurrently with shutdown, and a send on a closed channel
	// panics. Shutdown is signalled via done instead.
	wake chan struct{}
	// done is closed once by Close to stop the outbound pump.
	done chan struct{}
	// notifyHandle is the endpoint write-notification registration. Close releases
	// it so the stack stops invoking WriteNotify once the datapath is torn down
	// (the endpoint and its stack outlive the datapath when the consumer reuses
	// them, so leaving it registered would leak the datapath and keep firing).
	notifyHandle *channel.NotificationHandle

	// running guards against a second Run on the same Datapath, which would start
	// a duplicate inbound pump racing on the same endpoint/underlay.
	running atomic.Bool

	pktPool   sync.Pool
	closeOnce sync.Once
}

var _ vtep.Datapath = (*Datapath)(nil)

// New creates a Datapath. It registers for endpoint write notifications; the
// pumps do not run until Run is called.
func New(cfg Config) (*Datapath, error) {
	if cfg.Engine == nil {
		return nil, fmt.Errorf("netstack datapath: engine is required")
	}
	if cfg.Endpoint == nil {
		return nil, fmt.Errorf("netstack datapath: endpoint is required")
	}
	if cfg.Underlay == nil {
		return nil, fmt.Errorf("netstack datapath: underlay is required")
	}
	flush := cfg.FlushInterval
	if flush <= 0 {
		flush = defaultFlushInterval
	}
	d := &Datapath{
		engine:   cfg.Engine,
		ep:       cfg.Endpoint,
		underlay: cfg.Underlay,
		flush:    flush,
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
		pktPool: sync.Pool{
			New: func() any {
				b := make([]byte, 0, 65535)
				return &b
			},
		},
	}
	d.notifyHandle = d.ep.AddNotify(d)
	return d, nil
}

// WriteNotify is invoked by the channel endpoint when netstack has an outbound
// packet ready. It coalesces a wakeup; draining and batching happen in the
// outbound pump. It is safe to call concurrently with Close: wake is never
// closed, so the send either buffers (capacity 1) or falls through to default.
func (d *Datapath) WriteNotify() {
	select {
	case d.wake <- struct{}{}:
	default:
		// Already awake; coalesce.
	}
}

// Close stops the datapath's outbound pump and detaches from the endpoint. It
// does not close the injected endpoint's stack or the underlay — those are the
// consumer's to close. Closing the underlay is what unblocks the inbound pump.
//
// Detaching the endpoint (RemoveNotify) happens first so the stack stops
// invoking WriteNotify, then done is closed to stop the outbound pump. wake is
// never closed, so a WriteNotify racing with teardown can't panic.
func (d *Datapath) Close() error {
	d.closeOnce.Do(func() {
		if d.notifyHandle != nil {
			d.ep.RemoveNotify(d.notifyHandle)
		}
		close(d.done)
	})
	return nil
}

// Run drives the two pump loops and blocks until shutdown. Cancelling ctx (or
// calling Close) stops the outbound pump; the inbound pump unblocks only when
// the consumer closes the injected underlay, since its blocking ReadFrame can't
// be interrupted otherwise. Therefore Run returns once BOTH have happened —
// cancelling ctx alone is not sufficient, the consumer must also close the
// underlay (apoxy-cli's ICXNetwork.Close and clrk's sentry teardown both do).
// A nil return means a clean shutdown. Run must not be called more than once.
func (d *Datapath) Run(ctx context.Context) error {
	if !d.running.CompareAndSwap(false, true) {
		return fmt.Errorf("netstack datapath: Run already called")
	}

	g, ctx := errgroup.WithContext(ctx)

	// On cancellation, stop the outbound pump. The inbound pump unblocks when
	// the consumer closes the underlay.
	g.Go(func() error {
		<-ctx.Done()
		_ = d.Close()
		return nil
	})

	g.Go(d.outbound)
	g.Go(d.inbound)

	if err := g.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("netstack datapath splicing failed: %w", err)
	}
	return nil
}

// outbound pumps netstack (L3) -> engine -> underlay (batched).
func (d *Datapath) outbound() error {
	type owned struct {
		frame []byte
		buf   *[]byte // owner to return to the pool
	}
	putOwned := func(v []owned) {
		for i := range v {
			if v[i].buf != nil {
				d.pktPool.Put(v[i].buf)
				v[i].buf = nil
			}
			v[i].frame = nil
		}
	}

	// Per-iteration scratch reused across cycles to avoid allocs.
	var (
		batchOwned [maxBatchSize]owned
		batchOut   [maxBatchSize][]byte
	)

	ticker := time.NewTicker(d.flush)
	defer ticker.Stop()

	for {
		// Wake on endpoint notify or periodic tick; stop on Close.
		select {
		case <-d.done:
			return net.ErrClosed
		case <-d.wake:
		case <-ticker.C:
		}

		batch := batchOwned[:]
		count := 0

		ensureBuf := func(i int) *[]byte {
			b := batch[i].buf
			if b == nil {
				b = d.pktPool.Get().(*[]byte)
				batch[i].buf = b
			}
			*b = (*b)[:cap(*b)]
			return b
		}

		// Drain the endpoint fully into the batch (encap via VirtToPhy).
		for count < maxBatchSize {
			pkt := d.ep.Read()
			if pkt == nil {
				break
			}
			view := pkt.ToView()
			pkt.DecRef()

			ip := view.AsSlice() // raw L3 bytes
			b := ensureBuf(count)
			// The second result (local-reply flag) is only ever set when the
			// engine runs in L2 mode to answer ARP/ND inline; this driver presents
			// an L3 VTEP and requires a layer3-configured engine, so it is always
			// false here. A future L2 consumer would need to re-inject the reply.
			n, _ := d.engine.VirtToPhy(ip, *b)
			view.Release() // VirtToPhy copied into b; return the pooled view.
			if n > 0 {
				batch[count].frame = (*b)[:n]
				count++
			}
		}

		// Coalesce engine-scheduled frames (keep-alives via ToPhy) onto the
		// same batch.
		for count < maxBatchSize {
			b := ensureBuf(count)
			if n := d.engine.ToPhy(*b); n > 0 {
				batch[count].frame = (*b)[:n]
				count++
			} else {
				break
			}
		}

		if count == 0 {
			putOwned(batch)
			continue
		}

		out := batchOut[:count]
		for i := 0; i < count; i++ {
			out[i] = batch[i].frame
		}
		// Drain short writes: WriteFrames may report fewer frames sent than
		// offered, leaving an unsent suffix. Loop over it so the tail of a batch
		// is never silently dropped, regardless of the underlay implementation.
		// The frames stay valid until putOwned below.
		var writeErr error
		for len(out) > 0 {
			n, err := d.underlay.WriteFrames(out)
			if n > 0 {
				out = out[n:]
			}
			if err != nil {
				writeErr = err
				break
			}
			if n == 0 {
				writeErr = fmt.Errorf("netstack datapath: underlay write stalled, %d frames undelivered", len(out))
				break
			}
		}
		putOwned(batch)
		if writeErr != nil {
			if errors.Is(writeErr, net.ErrClosed) {
				return writeErr
			}
			slog.Warn("Error writing batched underlay frames", slog.Any("error", writeErr))
			continue
		}
	}
}

// inbound pumps underlay -> engine -> netstack (L3 inject).
func (d *Datapath) inbound() error {
	for {
		phyFrame := d.pktPool.Get().(*[]byte)
		*phyFrame = (*phyFrame)[:cap(*phyFrame)]

		n, err := d.underlay.ReadFrame(*phyFrame)
		if err != nil {
			d.pktPool.Put(phyFrame)
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			slog.Warn("Error reading frame from underlay", slog.Any("error", err))
			continue
		}
		if n == 0 {
			d.pktPool.Put(phyFrame)
			continue
		}

		virtFrame := d.pktPool.Get().(*[]byte)
		*virtFrame = (*virtFrame)[:cap(*virtFrame)]

		vn := d.engine.PhyToVirt((*phyFrame)[:n], *virtFrame)
		d.pktPool.Put(phyFrame)

		if vn == 0 {
			d.pktPool.Put(virtFrame)
			continue
		}

		payload := (*virtFrame)[:vn] // raw IP (L3)
		switch payload[0] >> 4 {
		case header.IPv4Version:
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(payload),
			})
			d.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
			pkb.DecRef()
		case header.IPv6Version:
			pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(payload),
			})
			d.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
			pkb.DecRef()
		default:
			// Unknown L3 version; drop silently.
		}
		d.pktPool.Put(virtFrame)
	}
}
