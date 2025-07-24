//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/icx/filter"
)

// Decapsulate and encapsulate frames between physical and virtual interfaces.
type Handler interface {
	// PhyToVirt converts a physical frame to a virtual frame typically by performing decapsulation.
	// Returns the length of the resulting virtual frame.
	PhyToVirt(phyFrame, virtFrame []byte) int
	// VirtToPhy converts a virtual frame to a physical frame typically by performing encapsulation.
	// Returns the length of the resulting physical frame.
	VirtToPhy(virtFrame, phyFrame []byte) (length int, loopback bool)
}

// Tunnel splices frames between a physical and a virtual interface using XDP sockets.
// It uses a handler to convert frames between the two interfaces.
type Tunnel struct {
	handler      Handler
	phyFilter    *xdp.Program
	pcapWriterMu sync.Mutex
	pcapWriter   *pcapgo.Writer
	link         netlink.Link
	phy          []*xdp.Socket
	virtFilter   *xdp.Program
	virt         []*xdp.Socket
	closeOnce    sync.Once
}

func NewTunnel(phyName, virtName string, phyFilter *xdp.Program, handler Handler, pcapWriter *pcapgo.Writer) (*Tunnel, error) {
	slog.Debug("Creating tunnel",
		slog.String("phyName", phyName),
		slog.String("virtName", virtName))

	phyLink, err := netlink.LinkByName(phyName)
	if err != nil {
		return nil, fmt.Errorf("failed to find physical interface %s: %w", phyName, err)
	}

	virtLink, err := netlink.LinkByName(virtName)
	if err != nil {
		return nil, fmt.Errorf("failed to find virtual interface %s: %w", virtName, err)
	}

	phyNumQueues, err := NumQueues(phyLink)
	if err != nil {
		return nil, fmt.Errorf("failed to get number of queues for physical device %s: %w", phyName, err)
	}

	virtNumQueues, err := NumQueues(virtLink)
	if err != nil {
		return nil, fmt.Errorf("failed to get number of queues for virtual device %s: %w", virtName, err)
	}

	if phyNumQueues != virtNumQueues {
		return nil, fmt.Errorf("physical and virtual interfaces must have the same number of queues, got %d and %d",
			phyNumQueues, virtNumQueues)
	}

	// Defaults are far too small for high throughput nics.
	socketOpts := &xdp.SocketOptions{
		NumFrames:              8192,
		FrameSize:              2048,
		FillRingNumDescs:       4096,
		CompletionRingNumDescs: 4096,
		RxRingNumDescs:         4096,
		TxRingNumDescs:         4096,
	}

	if err := phyFilter.Attach(phyLink.Attrs().Index); err != nil {
		return nil, fmt.Errorf("failed to attach XDP ingress filter: %w", err)
	}

	phy := make([]*xdp.Socket, 0, phyNumQueues)
	for queueID := 0; queueID < phyNumQueues; queueID++ {
		xsk, err := xdp.NewSocket(phyLink.Attrs().Index, queueID, socketOpts)
		if err != nil {
			_ = phyFilter.Detach(phyLink.Attrs().Index)
			for _, xsk := range phy {
				_ = xsk.Close()
			}
			return nil, fmt.Errorf("failed to create XDP socket: %w", err)
		}

		phy = append(phy, xsk)

		if err := phyFilter.Register(queueID, xsk.FD()); err != nil {
			_ = phyFilter.Detach(phyLink.Attrs().Index)
			for _, xsk := range phy {
				_ = xsk.Close()
			}
			return nil, fmt.Errorf("failed to register socket with XDP filter: %w", err)
		}
	}

	virtFilter, err := filter.All()
	if err != nil {
		return nil, fmt.Errorf("failed to create catch all virtual filter: %w", err)
	}

	if err := virtFilter.Attach(virtLink.Attrs().Index); err != nil {
		_ = phyFilter.Detach(phyLink.Attrs().Index)
		for _, xsk := range phy {
			_ = xsk.Close()
		}
		return nil, fmt.Errorf("failed to attach virtual filter: %w", err)
	}

	virt := make([]*xdp.Socket, 0, virtNumQueues)
	for queueID := 0; queueID < virtNumQueues; queueID++ {
		xsk, err := xdp.NewSocket(virtLink.Attrs().Index, queueID, socketOpts)
		if err != nil {
			_ = phyFilter.Detach(phyLink.Attrs().Index)
			_ = virtFilter.Detach(virtLink.Attrs().Index)
			for _, xsk := range phy {
				_ = xsk.Close()
			}
			for _, xsk := range virt {
				_ = xsk.Close()
			}
			return nil, fmt.Errorf("failed to create XDP socket: %w", err)
		}

		virt = append(virt, xsk)

		if err := virtFilter.Register(queueID, xsk.FD()); err != nil {
			_ = phyFilter.Detach(phyLink.Attrs().Index)
			_ = virtFilter.Detach(virtLink.Attrs().Index)
			for _, xsk := range phy {
				_ = xsk.Close()
			}
			for _, xsk := range virt {
				_ = xsk.Close()
			}
			return nil, fmt.Errorf("failed to register socket with virtual filter: %w", err)
		}
	}

	return &Tunnel{
		handler:    handler,
		phyFilter:  phyFilter,
		pcapWriter: pcapWriter,
		link:       phyLink,
		phy:        phy,
		virtFilter: virtFilter,
		virt:       virt,
	}, nil
}

func (t *Tunnel) Close() (err error) {
	t.closeOnce.Do(func() {
		if err = t.phyFilter.Detach(t.link.Attrs().Index); err != nil {
			err = fmt.Errorf("failed to detach XDP filter: %w", err)
			return
		}

		slog.Debug("Closing physical XDP sockets")

		for _, xsk := range t.phy {
			if err = xsk.Close(); err != nil {
				err = fmt.Errorf("failed to close XDP socket: %w", err)
				return
			}
		}

		slog.Debug("Closing virtual XDP sockets")

		for _, xsk := range t.virt {
			if err = xsk.Close(); err != nil {
				err = fmt.Errorf("failed to close XDP socket: %w", err)
				return
			}
		}
	})

	return nil
}

func (t *Tunnel) Start(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-ctx.Done()

		slog.Debug("Context canceled, closing tunnel")

		if err := t.Close(); err != nil {
			slog.Error("Failed to close tunnel", slog.Any("error", err))
		}
		return nil
	})

	for queueID := range t.phy {
		g.Go(func() error {
			return t.processFrames(queueID)
		})
	}

	if err := g.Wait(); err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("error while processing frames: %w", err)
	}

	return nil
}

func (t *Tunnel) processFrames(queueID int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	for {
		// Reserve space in the physical rx queue
		if n := min(t.phy[queueID].NumFilled()+t.phy[queueID].NumFreeFillSlots(), t.virt[queueID].NumFreeTxSlots()); n > 0 {
			if t.phy[queueID].NumFilled() < n {
				t.phy[queueID].Fill(t.phy[queueID].GetDescs(n-t.phy[queueID].NumFilled(), true))
			}
		}

		// Reserve space in the virt rx queue
		if n := min(t.virt[queueID].NumFilled()+t.virt[queueID].NumFreeFillSlots(), t.phy[queueID].NumFreeTxSlots()); n > 0 {
			if t.virt[queueID].NumFilled() < n {
				t.virt[queueID].Fill(t.virt[queueID].GetDescs(n-t.virt[queueID].NumFilled(), true))
			}
		}

		if err := poll(t.phy[queueID], t.virt[queueID], 100*time.Millisecond); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return err
			}

			return fmt.Errorf("failed to poll XSKs: %w", err)
		}

		if numCompleted := t.phy[queueID].NumCompleted(); numCompleted > 0 {
			t.phy[queueID].Complete(numCompleted)
		}

		if numCompleted := t.virt[queueID].NumCompleted(); numCompleted > 0 {
			t.virt[queueID].Complete(numCompleted)
		}

		// Did we receive any frames from the physical device?
		if numReceived := t.phy[queueID].NumReceived(); numReceived > 0 {
			rxDescs := t.phy[queueID].Receive(numReceived)
			txDescs := t.virt[queueID].GetDescs(numReceived, false)

			slog.Debug("Received frames from physical device",
				slog.Int("queueID", queueID),
				slog.Int("numReceived", numReceived))

			var populatedDescs int
			for i := range rxDescs {
				rxFrame := t.phy[queueID].GetFrame(rxDescs[i])
				txFrame := t.virt[queueID].GetFrame(txDescs[populatedDescs])

				frameLen := t.handler.PhyToVirt(rxFrame, txFrame)
				if frameLen <= 0 {
					continue
				}

				txDescs[populatedDescs].Len = uint32(frameLen)
				populatedDescs++

				if t.pcapWriter != nil {
					t.pcapWriterMu.Lock()
					ci := gopacket.CaptureInfo{
						Timestamp:     time.Now(),
						CaptureLength: len(rxFrame),
						Length:        len(rxFrame),
					}
					_ = t.pcapWriter.WritePacket(ci, rxFrame)
					t.pcapWriterMu.Unlock()
				}
			}
			if populatedDescs > 0 {
				if numTransmitted := t.virt[queueID].Transmit(txDescs[:populatedDescs]); numTransmitted < populatedDescs {
					slog.Debug("Failed to transmit all frames to virtual device",
						slog.Int("queueID", queueID),
						slog.Int("numReceived", numReceived),
						slog.Int("numTransmitted", numTransmitted))
				}
			}
		}

		// Did we receive any frames from the virtual device?
		if numReceived := t.virt[queueID].NumReceived(); numReceived > 0 {
			rxDescs := t.virt[queueID].Receive(numReceived)
			txDescs := t.phy[queueID].GetDescs(numReceived, false)

			slog.Debug("Received frames from virtual device",
				slog.Int("queueID", queueID),
				slog.Int("numReceived", numReceived))

			var populatedDescs int
			for i := range rxDescs {
				rxFrame := t.virt[queueID].GetFrame(rxDescs[i])
				txFrame := t.phy[queueID].GetFrame(txDescs[populatedDescs])

				frameLen, loopback := t.handler.VirtToPhy(rxFrame, txFrame)
				if !loopback {
					if frameLen <= 0 {
						continue
					}

					txDescs[populatedDescs].Len = uint32(frameLen)
					populatedDescs++
				} else {
					// Write back to the virt socket for loopback.
					if loopDescs := t.virt[queueID].GetDescs(1, false); len(loopDescs) == 1 {
						loopFrame := t.virt[queueID].GetFrame(loopDescs[0])
						loopDescs[0].Len = uint32(copy(loopFrame, txFrame[:frameLen]))
						if transmitted := t.virt[queueID].Transmit(loopDescs); transmitted < 1 {
							slog.Debug("Dropped loopback frame", slog.Int("queueID", queueID))
						}
					} else {
						slog.Debug("Dropped loopback frame", slog.Int("queueID", queueID))
					}
				}

				if t.pcapWriter != nil {
					t.pcapWriterMu.Lock()
					ci := gopacket.CaptureInfo{
						Timestamp:     time.Now(),
						CaptureLength: len(txFrame),
						Length:        len(txFrame),
					}
					_ = t.pcapWriter.WritePacket(ci, txFrame)
					t.pcapWriterMu.Unlock()
				}
			}
			if populatedDescs > 0 {
				if numTransmitted := t.phy[queueID].Transmit(txDescs[:populatedDescs]); numTransmitted < populatedDescs {
					slog.Debug("Failed to transmit all frames to physical device",
						slog.Int("queueID", queueID),
						slog.Int("numReceived", numReceived),
						slog.Int("numTransmitted", numTransmitted))
				}
			}
		}
	}
}

func poll(phy, virt *xdp.Socket, timeout time.Duration) (err error) {
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
