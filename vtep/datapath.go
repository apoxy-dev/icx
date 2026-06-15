// Package vtep defines the seam between the ICX engine (encap/decap + crypto,
// implemented by *icx.Handler) and the I/O driver that moves frames between the
// engine and the outside world. One engine drives many driver shapes:
//
//   - afxdp    veth + driver-XDP NIC, zero-copy, privileged. Drives the engine
//     through the in-place forwarder.Handler contract. Used for the per-node /
//     tunnelproxy VTEP.
//   - tun      kernel /dev/net/tun + userspace splice, NET_ADMIN. Drives the
//     engine through EngineXfrm (cross-buffer). Used for the backplane/Envoy
//     cluster VTEP, where the overlay consumer is a kernel-socket process.
//   - netstack gVisor channel.Endpoint + UDP PacketConn, unprivileged. Drives
//     the engine through EngineXfrm. Used for the clrk sentry VTEP, where the
//     overlay consumer lives inside a userspace netstack.
//
// The driver is selected by where the overlay consumer lives, not by a generic
// "device vs software" toggle. All three implement Datapath over the same
// engine; only the I/O plumbing differs.
package vtep

import (
	"context"
	"io"

	"github.com/apoxy-dev/icx"
)

// Datapath is one VTEP I/O driver. It pumps frames through the engine between
// the overlay-side device (or software endpoint) and the underlay transport.
// Drivers that own their device/underlay (afxdp, tun) tear them down on Close;
// the netstack driver is given both by the consumer and only drives the pump.
type Datapath interface {
	// Run drives the I/O loop, blocking until shutdown, then returns. Cancelling
	// ctx stops the send path. For drivers handed an injected underlay (netstack),
	// the receive path stops only when the consumer closes that underlay, so Run
	// returns once both have happened — cancelling ctx alone may not suffice.
	// A nil return means a clean shutdown. Run must not be called more than once.
	Run(ctx context.Context) error

	// Close stops the datapath. Drivers that own their underlay/device release
	// them here; drivers handed an injected underlay leave its lifecycle to the
	// consumer. Safe to call after Run returns; Run must not be called after Close.
	io.Closer
}

// EngineXfrm is the cross-buffer transform contract that copy-based drivers
// (tun, netstack) call into. Each method reads from one buffer and writes the
// transformed frame into a distinct buffer, which suits drivers that cannot
// share a single UMEM with the NIC. It is byte-for-byte equivalent to the
// in-place forwarder.Handler contract that the zero-copy afxdp driver uses;
// keeping the two equivalent is a maintained invariant (see cp_wire tests).
//
// *icx.Handler satisfies this interface — see the assertion below.
type EngineXfrm interface {
	// PhyToVirt decapsulates a physical (underlay) frame into virt, returning
	// the number of bytes written, or 0 to drop.
	PhyToVirt(phy, virt []byte) int

	// VirtToPhy encapsulates a virtual (overlay) frame into phy, returning the
	// number of bytes written and whether the frame was instead handled as an
	// immediate local reply (ARP/ND) that must go back out the overlay side.
	VirtToPhy(virt, phy []byte) (int, bool)

	// ToPhy lets the engine emit a scheduled frame (e.g. a keep-alive) into
	// phy, returning the number of bytes written, or 0 when there is nothing
	// to send.
	ToPhy(phy []byte) int
}

// Compile-time guarantee that the ICX engine satisfies the cross-buffer seam.
// If the engine's signatures drift, this fails to build rather than silently
// diverging from the driver contract.
var _ EngineXfrm = (*icx.Handler)(nil)
