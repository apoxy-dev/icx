//go:build linux

// Package afxdp adapts the zero-copy AF_XDP forwarder.Forwarder to the
// vtep.Datapath seam. It is the privileged, kernel-zero-copy driver of the vtep
// family (veth + driver-XDP NIC, shared UMEM, in-place transform), used for the
// per-node / tunnelproxy VTEP where the overlay consumer is the host kernel.
//
// Unlike the netstack and tun drivers — which drive the engine through the
// cross-buffer EngineXfrm contract — the AF_XDP driver keeps the in-place
// forwarder.Handler contract and its shared-UMEM zero-copy fast path entirely
// internally. This wrapper is a pure lifecycle adapter (Run/Close delegate to the
// forwarder's existing per-queue poll loop); it deliberately does not route the
// hot path through EngineXfrm, whose copy-based contract would forfeit the
// zero-copy handoff. The forwarder's in-place loop, shared UMEM, and
// minInPlaceHeadroom invariant are untouched.
package afxdp

import (
	"context"

	"github.com/apoxy-dev/icx/forwarder"
	"github.com/apoxy-dev/icx/vtep"
)

// Datapath wraps a *forwarder.Forwarder so it satisfies vtep.Datapath. The
// wrapped forwarder owns its veth/XDP device and AF_XDP underlay and releases
// them on Close.
type Datapath struct {
	fwd *forwarder.Forwarder
}

var _ vtep.Datapath = (*Datapath)(nil)

// Wrap adapts an already-constructed forwarder.Forwarder (built via
// forwarder.NewForwarder with the desired phy/virt/filter options) to the
// vtep.Datapath interface. The caller transfers ownership: the returned
// Datapath's Close closes the forwarder.
func Wrap(fwd *forwarder.Forwarder) *Datapath {
	return &Datapath{fwd: fwd}
}

// Run drives the forwarder's per-queue poll loop, blocking until ctx is
// cancelled or a queue errors, then returns. Run must not be called more than
// once (the forwarder's own guards apply).
func (d *Datapath) Run(ctx context.Context) error {
	return d.fwd.Start(ctx)
}

// Close releases the forwarder's device and AF_XDP resources. It is idempotent
// and safe to call after Run returns.
func (d *Datapath) Close() error {
	return d.fwd.Close()
}
