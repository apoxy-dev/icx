//go:build linux

package forwarder_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/forwarder"
)

// TestForwarderRejectsLayer3Handler proves NewForwarder fails closed when handed
// a handler in layer3 mode (WithLayer3VirtFrames). The forwarder's virtual
// interface is an L2 veth; an in-place L3 decap writes a raw IP packet onto it,
// which the veth silently drops — the symptom that wedged a real-hardware
// userspace-tun <-> AF_XDP A/B to zero decap with no error. The guard runs before
// any NIC binding, so this needs no NET_ADMIN or real interface. An L3 peer still
// interoperates with the forwarder on the wire (see icx.TestCrossModeVTEPInterop);
// the forwarder side must simply be L2.
func TestForwarderRejectsLayer3Handler(t *testing.T) {
	h, err := icx.NewHandler(
		icx.WithLocalAddr(&tcpip.FullAddress{
			Addr: tcpip.AddrFromSlice(net.IPv4(192, 168, 1, 1).To4()),
			Port: 6081,
		}),
		icx.WithLayer3VirtFrames(),
	)
	require.NoError(t, err)

	_, err = forwarder.NewForwarder(h,
		forwarder.WithPhyName("icx-nope-phy"),
		forwarder.WithVirtName("icx-nope-virt"),
	)
	require.Error(t, err, "NewForwarder must reject a layer3 handler")
	require.Contains(t, err.Error(), "layer3")
}
