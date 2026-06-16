// Package tun implements the tun VTEP datapath driver: it splices a kernel
// /dev/net/tun device (the overlay-side, L3 link the consumer routes to) to the
// ICX engine, moving encap'd frames over a UDP-socket underlay.
//
// It is the kernel-device, NET_ADMIN-only driver of the vtep family. Unlike the
// netstack driver — which is handed both its endpoint and underlay by the
// consumer and only drives the pump — the tun driver OWNS both the TUN device
// and the UDP socket and tears them down on Close (see vtep.Datapath). This is
// the consumer-locality seam for a normal kernel-socket process (Envoy on the
// backplane): the overlay consumer reaches overlay backends by kernel route, so
// the VTEP must present a kernel device it can route to.
//
// The engine speaks full Ethernet+IP+UDP+Geneve frames on the physical side
// (udp.Encode/udp.Decode own the outer stack); the backplane pod has NET_ADMIN
// but no CAP_NET_RAW, so the underlay is a plain UDP socket and the driver's
// Underlay implementation peels the outer headers on TX and synthesizes them on
// RX (see udpUnderlay). The driver drives the engine strictly through the
// cross-buffer EngineXfrm contract — never the in-place forwarder.Handler path,
// whose shared-UMEM / exact-GCM-overlap contract a copy-based driver cannot
// honor.
package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apoxy-dev/icx/vtep"
	"golang.org/x/sync/errgroup"
)

const (
	// defaultFlushInterval is how often the keep-alive pump flushes
	// engine-scheduled frames (EngineXfrm.ToPhy) when there is no overlay traffic.
	defaultFlushInterval = 100 * time.Millisecond

	// defaultInnerMTU is the mandatory static inner-MTU clamp for a software/TUN
	// VTEP. icx has no PMTUD, so an inner packet whose encapsulated size exceeds
	// the underlay path MTU would be black-holed; 1280 (the IPv6 minimum MTU) is
	// the universally safe floor (seam doc Risk 3 / APO-794).
	defaultInnerMTU = 1280

	// maxFrameSize bounds a single underlay/decap scratch buffer.
	maxFrameSize = 65535

	// encapHeadroom bounds the outer-header + AEAD-tag overhead added to an inner
	// packet on encap: udp.PayloadOffsetIPv6 (62) + the 32-byte Geneve header +
	// the 16-byte AES-GCM tag = 110. Rounded up for alignment slack.
	encapHeadroom = 128

	// tunHeadroom is extra room in a TUN read buffer beyond offset+MTU, for the
	// device's virtio-net header prefix (the device is created with IFF_VNET_HDR).
	tunHeadroom = 64

	// maxErrorBackoff caps the interruptible sleep a pump takes after consecutive
	// non-closed read errors, so a wedged device/socket cannot peg a core.
	maxErrorBackoff = time.Second
	// maxConsecReadErrors is how many consecutive non-closed read errors a pump
	// tolerates before treating the device/socket as fatally wedged and returning,
	// so Run tears down and a supervisor can learn and restart rather than the
	// datapath warning-storming forever.
	maxConsecReadErrors = 16
)

// Device is the overlay-side L3 TUN device the driver owns. It is the subset of
// golang.zx2c4.com/wireguard/tun.Device the datapath uses; the real /dev/net/tun
// device (device_linux.go) and the in-memory test fake both satisfy it. Packets
// are raw L3 IP (the device is opened IFF_NO_PI); Read/Write take a fixed offset
// (Config.DeviceOffset) so the device implementation has the headroom it needs.
type Device interface {
	// Read reads up to len(bufs) packets, writing packet i into bufs[i][offset:]
	// and its length into sizes[i] (len(sizes) >= len(bufs)); returns the packet
	// count. It blocks until at least one packet is available or the device is
	// closed (after which it returns a closed error).
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	// Write writes len(bufs) packets, taking packet i from bufs[i][offset:].
	Write(bufs [][]byte, offset int) (int, error)
	// BatchSize is the max number of packets a single Read/Write handles.
	BatchSize() int
	io.Closer
}

// Underlay is the encap'd-frame transport the driver owns. It carries full
// Ethernet+IP+UDP+Geneve "phy" frames to/from the engine — the same contract the
// netstack driver's Underlay uses — peeling the outer headers onto a UDP socket
// internally (see udpUnderlay). It additionally satisfies io.Closer because the
// tun driver owns the socket's lifecycle; closing it unblocks a running
// inbound pump.
type Underlay interface {
	// ReadFrame reads a single underlay frame into buf, returning its length. A
	// length of 0 with a nil error is skipped. Once Close has been called it must
	// return an error satisfying errors.Is(err, net.ErrClosed).
	ReadFrame(buf []byte) (int, error)
	// WriteFrames writes a batch of full phy frames, returning the number actually
	// sent. A short write (n < len(frames)) is permitted; the datapath drains the
	// unsent suffix by calling again, so implementations must not drop the tail. A
	// zero return with a nil error is treated as a stall. The frames are owned by
	// the caller and valid only until the call returns.
	WriteFrames(frames [][]byte) (int, error)
	io.Closer
}

// Config configures a Datapath. Engine, Device and Underlay are required.
type Config struct {
	// Engine is the ICX engine performing encap/decap + crypto. *icx.Handler
	// satisfies this; it must be configured in layer3 mode (WithLayer3VirtFrames),
	// since the TUN device carries raw L3 inner packets.
	Engine vtep.EngineXfrm
	// Device is the overlay-side TUN device. The driver owns it and closes it on
	// Close.
	Device Device
	// Underlay is the encap'd-frame transport. The driver owns it and closes it on
	// Close.
	Underlay Underlay
	// DeviceOffset is the read/write headroom offset into Device buffers. The real
	// wireguard TUN needs >= virtioNetHdrLen (10); device_linux.go uses 16. The
	// test fake uses 0. Negative values are treated as 0.
	DeviceOffset int
	// InnerMTU is the overlay MTU; 0 uses defaultInnerMTU (1280). It sizes the TUN
	// read/decap buffers and must not exceed what the underlay path can carry.
	InnerMTU int
	// FlushInterval overrides how often scheduled (keep-alive) frames are flushed.
	// Zero uses defaultFlushInterval.
	FlushInterval time.Duration
}

// Datapath splices a TUN device to the ICX engine over a UDP underlay. It
// implements vtep.Datapath.
type Datapath struct {
	engine   vtep.EngineXfrm
	dev      Device
	underlay Underlay
	offset   int
	innerMTU int
	flush    time.Duration

	// running guards against a second Run, which would start duplicate pumps
	// racing on the same device/underlay.
	running atomic.Bool
	// closed is set by Close so Run can reject a call after Close per the contract.
	closed atomic.Bool

	// done is closed once by Close to stop the keep-alive pump (the data pumps
	// stop when their blocking device/underlay read returns a closed error).
	done      chan struct{}
	closeOnce sync.Once
}

var _ vtep.Datapath = (*Datapath)(nil)

// New creates a Datapath over an injected device and underlay. The pumps do not
// run until Run is called.
func New(cfg Config) (*Datapath, error) {
	if cfg.Engine == nil {
		return nil, fmt.Errorf("tun datapath: engine is required")
	}
	if cfg.Device == nil {
		return nil, fmt.Errorf("tun datapath: device is required")
	}
	if cfg.Underlay == nil {
		return nil, fmt.Errorf("tun datapath: underlay is required")
	}
	flush := cfg.FlushInterval
	if flush <= 0 {
		flush = defaultFlushInterval
	}
	mtu := cfg.InnerMTU
	if mtu <= 0 {
		mtu = defaultInnerMTU
	}
	off := cfg.DeviceOffset
	if off < 0 {
		off = 0
	}
	return &Datapath{
		engine:   cfg.Engine,
		dev:      cfg.Device,
		underlay: cfg.Underlay,
		offset:   off,
		innerMTU: mtu,
		flush:    flush,
		done:     make(chan struct{}),
	}, nil
}

// Close stops the datapath and releases the device and underlay it owns. It is
// safe to call after Run returns and idempotent. Closing the device unblocks the
// outbound pump; closing the underlay unblocks the inbound pump; closing done
// stops the keep-alive pump.
func (d *Datapath) Close() error {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		close(d.done)
		_ = d.dev.Close()
		_ = d.underlay.Close()
	})
	return nil
}

// Run drives the pump loops and blocks until shutdown. Cancelling ctx (or calling
// Close) tears down the device and underlay, which unblocks the data pumps; Run
// then returns. A nil return means a clean shutdown. Run must not be called more
// than once, nor after Close.
func (d *Datapath) Run(ctx context.Context) error {
	if !d.running.CompareAndSwap(false, true) {
		return fmt.Errorf("tun datapath: Run already called")
	}
	if d.closed.Load() {
		return fmt.Errorf("tun datapath: Run called after Close")
	}

	g, ctx := errgroup.WithContext(ctx)

	// On cancellation, tear down so the blocking pumps unblock and return.
	g.Go(func() error {
		<-ctx.Done()
		_ = d.Close()
		return nil
	})

	g.Go(d.outbound)
	g.Go(d.inbound)
	g.Go(d.keepalive)

	if err := g.Wait(); err != nil && !isClosedErr(err) {
		return fmt.Errorf("tun datapath splicing failed: %w", err)
	}
	return nil
}

// outbound pumps TUN (overlay L3) -> engine -> underlay (batched encap).
func (d *Datapath) outbound() error {
	bs := d.dev.BatchSize()
	if bs < 1 {
		bs = 1
	}
	readBufLen := d.offset + d.innerMTU + tunHeadroom
	// Size the encap buffer for the largest inner packet the read buffer can admit
	// (innerMTU+tunHeadroom) plus the outer/Geneve/tag overhead, so a packet in the
	// (innerMTU, innerMTU+tunHeadroom] range encaps instead of being dropped by the
	// VirtToPhy (APO-667) bound.
	encBufLen := d.innerMTU + tunHeadroom + encapHeadroom

	readBufs := make([][]byte, bs)
	encBufs := make([][]byte, bs)
	for i := 0; i < bs; i++ {
		readBufs[i] = make([]byte, readBufLen)
		encBufs[i] = make([]byte, encBufLen)
	}
	sizes := make([]int, bs)
	frames := make([][]byte, 0, bs)
	consecErr := 0

	for {
		n, err := d.dev.Read(readBufs, sizes, d.offset)
		if err != nil {
			if isClosedErr(err) {
				return net.ErrClosed
			}
			consecErr++
			slog.Warn("tun datapath: error reading from device",
				slog.Any("error", err), slog.Int("consecutive", consecErr))
			if consecErr >= maxConsecReadErrors {
				return fmt.Errorf("tun datapath: device read failed %d times consecutively: %w", consecErr, err)
			}
			if !d.backoffOnError(consecErr) {
				return net.ErrClosed
			}
			continue
		}
		consecErr = 0

		frames = frames[:0]
		for i := 0; i < n; i++ {
			if sizes[i] <= 0 || d.offset+sizes[i] > len(readBufs[i]) {
				// Defensive: the device contract is single <= MTU packets, but never
				// slice past the buffer if it ever reports an oversized length.
				continue
			}
			inner := readBufs[i][d.offset : d.offset+sizes[i]]
			m, loop := d.engine.VirtToPhy(inner, encBufs[i])
			if loop {
				// The local-reply flag is only set in L2 mode (an inline ARP/ND
				// reply that must go back out the overlay). The tun VTEP is L3, so
				// this is never expected; drop defensively rather than mis-route it
				// onto the underlay.
				slog.Debug("tun datapath: unexpected L2 local-reply in L3 mode, dropping")
				continue
			}
			if m > 0 {
				frames = append(frames, encBufs[i][:m])
			}
		}
		if len(frames) == 0 {
			continue
		}
		if err := d.writeFrames(frames); err != nil {
			if isClosedErr(err) {
				return net.ErrClosed
			}
			slog.Warn("tun datapath: error writing underlay frames", slog.Any("error", err))
		}
	}
}

// inbound pumps underlay -> engine -> TUN (decap + L3 inject).
func (d *Datapath) inbound() error {
	phyBuf := make([]byte, maxFrameSize)
	// virtBuf must hold the full decapsulated inner packet at the device offset.
	// PhyToVirt does NOT bound its output to the destination buffer — the APO-667
	// seal-overflow bound covers encap only, and AES-GCM Open appends, reallocating
	// (and mis-placing the plaintext) if the destination is too small. A peer
	// holding the SA key can emit an inner packet up to the underlay frame size, so
	// size for the worst case (matching the netstack driver's 65535 buffers) rather
	// than the local MTU clamp.
	virtBuf := make([]byte, d.offset+maxFrameSize)
	writeBatch := make([][]byte, 1)
	consecErr := 0

	for {
		n, err := d.underlay.ReadFrame(phyBuf)
		if err != nil {
			if isClosedErr(err) {
				return net.ErrClosed
			}
			consecErr++
			slog.Warn("tun datapath: error reading underlay frame",
				slog.Any("error", err), slog.Int("consecutive", consecErr))
			if consecErr >= maxConsecReadErrors {
				return fmt.Errorf("tun datapath: underlay read failed %d times consecutively: %w", consecErr, err)
			}
			if !d.backoffOnError(consecErr) {
				return net.ErrClosed
			}
			continue
		}
		consecErr = 0
		if n == 0 {
			continue
		}

		// Decap into virtBuf at the device offset so the packet can be handed to
		// Device.Write without a copy.
		m := d.engine.PhyToVirt(phyBuf[:n], virtBuf[d.offset:])
		if m == 0 {
			continue
		}
		if d.offset+m > len(virtBuf) {
			// Unreachable given virtBuf is sized to maxFrameSize, but never slice
			// past the buffer if that ever changes.
			slog.Warn("tun datapath: decapsulated packet exceeds buffer, dropping", slog.Int("len", m))
			continue
		}
		writeBatch[0] = virtBuf[:d.offset+m]
		if _, err := d.dev.Write(writeBatch, d.offset); err != nil {
			if isClosedErr(err) {
				return net.ErrClosed
			}
			slog.Warn("tun datapath: error writing to device", slog.Any("error", err))
		}
	}
}

// keepalive pumps engine-scheduled frames (EngineXfrm.ToPhy keep-alives) to the
// underlay on a flush ticker. The data pumps cannot coalesce these the way the
// netstack driver does, because the TUN Read blocks; a dedicated ticker pump is
// the cross-buffer-equivalent way to flush them with no overlay traffic.
func (d *Datapath) keepalive() error {
	bs := d.dev.BatchSize()
	if bs < 1 {
		bs = 1
	}
	encBufs := make([][]byte, bs)
	for i := range encBufs {
		// Size like the outbound encap buffer (tracks the configured MTU + overhead)
		// rather than a fixed default, so a future scheduled-frame type that carries
		// a payload cannot under-size the buffer. Today ToPhy emits only empty-payload
		// keep-alives, so this is headroom, not a live requirement.
		encBufs[i] = make([]byte, d.innerMTU+encapHeadroom)
	}
	frames := make([][]byte, 0, bs)

	ticker := time.NewTicker(d.flush)
	defer ticker.Stop()

	for {
		select {
		case <-d.done:
			return nil
		case <-ticker.C:
		}

		frames = frames[:0]
		for i := 0; i < bs; i++ {
			m := d.engine.ToPhy(encBufs[i])
			if m == 0 {
				break
			}
			frames = append(frames, encBufs[i][:m])
		}
		if len(frames) == 0 {
			continue
		}
		if err := d.writeFrames(frames); err != nil {
			if isClosedErr(err) {
				return nil // shutting down
			}
			slog.Warn("tun datapath: error writing keep-alive frames", slog.Any("error", err))
		}
	}
}

// backoffOnError sleeps a bounded, escalating delay after `consec` consecutive
// non-closed read errors so a wedged device/socket cannot peg a core. It returns
// false if the datapath is shutting down (the caller should then return), true to
// retry. The sleep is interruptible by Close.
func (d *Datapath) backoffOnError(consec int) bool {
	delay := time.Duration(consec) * 10 * time.Millisecond
	if delay > maxErrorBackoff {
		delay = maxErrorBackoff
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-d.done:
		return false
	case <-timer.C:
		return true
	}
}

// writeFrames writes a batch to the underlay, draining short writes so the tail
// of a batch is never silently dropped.
func (d *Datapath) writeFrames(frames [][]byte) error {
	for len(frames) > 0 {
		n, err := d.underlay.WriteFrames(frames)
		if n > 0 {
			frames = frames[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("tun datapath: underlay write stalled, %d frames undelivered", len(frames))
		}
	}
	return nil
}

// isClosedErr reports whether err is the benign "the device/socket was closed"
// signal that means a clean shutdown. It covers net.ErrClosed, os.ErrClosed, and
// the wireguard TUN's textual close error.
func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrClosed) ||
		strings.Contains(err.Error(), "closed")
}
