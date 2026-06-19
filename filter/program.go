//go:build linux

package filter

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// AttachFlags are the flags passed when attaching the XDP program to an
// interface. Zero lets the kernel choose the attach mode (native driver XDP if
// the driver supports it, otherwise generic/SKB), matching the behaviour icx
// inherited from github.com/slavc/xdp.
//
// IMPORTANT: on drivers that support native XDP (e.g. ixgbe), the kernel's
// default (native) attach RECONFIGURES the NIC's TX rings, and copy-mode AF_XDP
// TX frames then never egress — the driver silently drops them while still
// producing completions (proven on ixgbe: nic_tx_delta=0). The shared-UMEM
// forwarder runs in copy mode (it cannot use driver zero-copy — see
// forwarder.phyBindOpts), so it sets this to XDP_FLAGS_SKB_MODE, which leaves the
// driver's TX path untouched and lets the generic-XDP hook still redirect RX into
// the AF_XDP sockets. A future driver-zero-copy datapath would use native mode.
var AttachFlags = 0

// Program is a loaded XDP redirect program plus the maps that steer packets into
// AF_XDP sockets. It owns the eBPF program (xdp_sock_prog), the per-queue config
// map (qidconf_map) that gates which RX queues redirect, and the XSKMAP
// (xsks_map) that maps a queue index to a bound socket fd.
//
// This replaces github.com/slavc/xdp's Program type: icx built it by hand from a
// cilium/ebpf collection (see All/Geneve) and only ever used Attach/Detach/
// Register/Unregister/Close, so the in-repo version carries just those, with no
// dependency on the upstream library.
type Program struct {
	Program *ebpf.Program
	Queues  *ebpf.Map // qidconf_map: rx_queue_index -> enabled(1)
	Sockets *ebpf.Map // xsks_map (XSKMAP): rx_queue_index -> socket fd
}

// Attach attaches the XDP program to the interface, replacing any program
// already attached there (idempotent: a stale program from a previous run is
// removed first).
func (p *Program) Attach(ifindex int) error {
	if err := removeProgram(ifindex); err != nil {
		return err
	}
	return attachProgram(ifindex, p.Program)
}

// Detach removes the XDP program from the interface.
func (p *Program) Detach(ifindex int) error {
	return removeProgram(ifindex)
}

// Register makes the socket fd the redirect target for packets arriving on
// queueID: it points the XSKMAP entry at the fd and enables redirect for that
// queue in qidconf_map. The XSKMAP must be written before qidconf is enabled so
// the program never redirects to an empty XSKMAP slot.
func (p *Program) Register(queueID int, fd int) error {
	if err := p.Sockets.Put(uint32(queueID), uint32(fd)); err != nil {
		return fmt.Errorf("failed to update xsks_map: %w", err)
	}
	if err := p.Queues.Put(uint32(queueID), uint32(1)); err != nil {
		return fmt.Errorf("failed to update qidconf_map: %w", err)
	}
	return nil
}

// Unregister disables redirect for queueID and drops its XSKMAP entry. qidconf is
// cleared first so the program stops redirecting before the socket fd is removed.
//
// qidconf_map is a BPF_MAP_TYPE_ARRAY, whose elements cannot be deleted (the
// kernel returns EINVAL); the disable is therefore a Put(queueID, 0), not a
// Delete. The previous Delete always errored on the array map and returned before
// ever clearing the XSKMAP entry, leaving the socket fd a live redirect target —
// so per-queue teardown never actually unregistered anything.
func (p *Program) Unregister(queueID int) error {
	if err := p.Queues.Put(uint32(queueID), uint32(0)); err != nil {
		return fmt.Errorf("failed to clear qidconf_map entry: %w", err)
	}
	if err := p.Sockets.Delete(uint32(queueID)); err != nil {
		return fmt.Errorf("failed to delete xsks_map entry: %w", err)
	}
	return nil
}

// Close releases the program and both maps. Errors are joined so one failure
// does not skip closing the rest. Unlike the old library this is actually called
// (the forwarder leaked these fds by only Detaching), so the program/map fds are
// freed on teardown.
func (p *Program) Close() error {
	var errs []error
	if p.Sockets != nil {
		if err := p.Sockets.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close xsks_map: %w", err))
		}
		p.Sockets = nil
	}
	if p.Queues != nil {
		if err := p.Queues.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close qidconf_map: %w", err))
		}
		p.Queues = nil
	}
	if p.Program != nil {
		if err := p.Program.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close XDP program: %w", err))
		}
		p.Program = nil
	}
	return errors.Join(errs...)
}

// attachProgram attaches prog to the interface by ifindex.
func attachProgram(ifindex int, prog *ebpf.Program) error {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("link by index %d: %w", ifindex, err)
	}
	if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), AttachFlags); err != nil {
		return fmt.Errorf("attach XDP program to ifindex %d: %w", ifindex, err)
	}
	return nil
}

// removeProgram detaches any XDP program from the interface and waits for the
// detach to take effect. It is a no-op if nothing is attached.
func removeProgram(ifindex int) error {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("link by index %d: %w", ifindex, err)
	}
	if !isXdpAttached(link) {
		return nil
	}
	// Detach with the SAME mode flags the program was attached with. A program in
	// the generic/SKB slot (AttachFlags == XDP_FLAGS_SKB_MODE) is NOT removed by a
	// flags=0 detach (that targets the native slot), so LinkSetXdpFd(link, -1)
	// would silently no-op and the poll below would spin forever — hanging Close
	// (and leaking the program). Passing AttachFlags removes the right slot.
	if err := netlink.LinkSetXdpFdWithFlags(link, -1, AttachFlags); err != nil {
		return fmt.Errorf("detach XDP program from ifindex %d: %w", ifindex, err)
	}
	// The detach is asynchronous; poll (bounded) until the link reports no XDP
	// program so a subsequent Attach does not race the teardown. The bound turns a
	// stuck detach into a loud error instead of an unbounded hang.
	for i := 0; i < 50; i++ {
		link, err = netlink.LinkByIndex(ifindex)
		if err != nil {
			return fmt.Errorf("link by index %d: %w", ifindex, err)
		}
		if !isXdpAttached(link) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("XDP program still attached to ifindex %d after detach", ifindex)
}

func isXdpAttached(link netlink.Link) bool {
	attrs := link.Attrs()
	return attrs != nil && attrs.Xdp != nil && attrs.Xdp.Attached
}
