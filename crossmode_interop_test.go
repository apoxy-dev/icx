package icx

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestCrossModeVTEPInterop proves that a userspace tun VTEP (L3 inner frames,
// vtep/tun) and an AF_XDP forwarder VTEP (L2/veth inner frames, the forwarder
// path) interoperate on the wire in BOTH directions.
//
// The two modes differ only in how they frame the INNER packet toward their
// local virtual interface — a raw IP packet for the L3 (TUN) side, an
// Ethernet-framed IP packet for the L2 (veth) side. What goes on the wire is
// identical: both Seal the same inner IP packet (L2 strips the 14-byte Ethernet
// header before Seal, handler.go:1240; L3 Seals the raw IP directly), wrapped in
// the same Geneve+AES-GCM. So a frame encapped by one mode MUST decapsulate
// under the other. This is the realistic mixed deployment: a userspace peer
// (vtep/tun) talking to an accelerated peer (AF_XDP forwarder).
//
// Regression intent: a real-hardware A/B mistakenly ran the AF_XDP/veth decap
// side in L3 mode (WithLayer3VirtFrames), whose in-place decap emits a raw IP
// packet onto a veth — which the veth silently drops. The correct config is the
// forwarder in L2 (its only valid mode with a veth virt); this test pins that
// the L2 decap accepts the L3 peer's frames, and the L3 decap accepts the L2
// peer's frames.
func TestCrossModeVTEPInterop(t *testing.T) {
	localAddr, remoteAddr := underlayAddrs(false)
	key := generateKey(t)
	const vni = uint(100)
	routes := []Route{{
		Src: netip.MustParsePrefix("10.0.1.0/24"),
		Dst: netip.MustParsePrefix("10.0.1.0/24"),
	}}
	virtMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	srcMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")

	// L3 peer (userspace vtep/tun-like): raw IP virtual frames.
	l3 := newTestHandler(t, WithLocalAddr(localAddr), WithLayer3VirtFrames())
	require.NoError(t, l3.AddVirtualNetwork(vni, remoteAddr, routes))
	require.NoError(t, l3.InstallKeysForTest(vni, 1, key, key, time.Now().Add(time.Hour)))

	// L2 peer (AF_XDP forwarder-like): Ethernet-framed virtual frames.
	l2 := newTestHandler(t, WithLocalAddr(localAddr), WithVirtMAC(virtMAC), WithSourceMAC(srcMAC))
	require.NoError(t, l2.AddVirtualNetwork(vni, remoteAddr, routes))
	require.NoError(t, l2.InstallKeysForTest(vni, 1, key, key, time.Now().Add(time.Hour)))

	inner := buildInnerIPv4Packet(
		netip.MustParseAddr("10.0.1.5"),
		netip.MustParseAddr("10.0.1.6"),
		[]byte("cross-mode-vtep-interop-canary"),
	)

	// inPlaceDecap runs the in-place decap (the forwarder's PhyToVirtInPlace seam)
	// of wireFrame under h, mirroring the forwarder's UMEM buffer layout (frame at
	// an offset with generous head/tailroom).
	inPlaceDecap := func(h *Handler, wireFrame []byte) (out []byte, ok bool) {
		buf := make([]byte, len(wireFrame)+2*inplaceScratch)
		off := inplaceScratch
		copy(buf[off:off+len(wireFrame)], wireFrame)
		gotOff, gotLen := h.PhyToVirtInPlace(buf, off, len(wireFrame))
		if gotLen == 0 {
			return nil, false
		}
		return buf[gotOff : gotOff+gotLen], true
	}

	// Direction 1: L3 (tun) encap  ->  L2 (forwarder) in-place decap.
	t.Run("tunL3_encap_to_forwarderL2_decap", func(t *testing.T) {
		phyBuf := make([]byte, len(inner)+inplaceScratch)
		n, handled := l3.VirtToPhy(append([]byte(nil), inner...), phyBuf)
		require.False(t, handled)
		require.Greater(t, n, 0, "L3 tun encap should succeed")

		out, ok := inPlaceDecap(l2, phyBuf[:n])
		require.True(t, ok, "L2 forwarder decap must ACCEPT the L3 tun peer's frame (interop)")
		require.GreaterOrEqual(t, len(out), header.EthernetMinimumSize)
		// L2 decap output = freshly written Ethernet header + the inner IP packet.
		require.Equal(t, inner, out[header.EthernetMinimumSize:], "recovered inner IP must match the tun's")
	})

	// Direction 2: L2 (forwarder) encap  ->  L3 (tun) in-place decap.
	t.Run("forwarderL2_encap_to_tunL3_decap", func(t *testing.T) {
		ethFrame := make([]byte, header.EthernetMinimumSize+len(inner))
		header.Ethernet(ethFrame).Encode(&header.EthernetFields{
			SrcAddr: srcMAC, DstAddr: virtMAC, Type: header.IPv4ProtocolNumber,
		})
		copy(ethFrame[header.EthernetMinimumSize:], inner)

		phyBuf := make([]byte, len(ethFrame)+inplaceScratch)
		n, handled := l2.VirtToPhy(append([]byte(nil), ethFrame...), phyBuf)
		require.False(t, handled)
		require.Greater(t, n, 0, "L2 forwarder encap should succeed")

		out, ok := inPlaceDecap(l3, phyBuf[:n])
		require.True(t, ok, "L3 tun decap must ACCEPT the L2 forwarder peer's frame (interop)")
		// L3 decap output = the raw inner IP packet, no Ethernet header.
		require.Equal(t, inner, out, "recovered raw inner IP must match the forwarder's")
	})
}
