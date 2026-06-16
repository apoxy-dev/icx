package icx

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// These tests are the regression for the routing-trie operator-error family:
//   APO-653 (S10) two vnets with identical Src+Dst silently overwrite each other,
//   APO-654 (S11) removing one vnet blackholes another sharing a Dst (+ node leak),
//   APO-663 (S20) the management plane located the per-Dst srcTrie by LPM, so a
//                 nested Dst landed (and clobbered) the broader entry.
// They drive the management API and assert routing via RouteLookupForTest, which
// mirrors the data-path lookup in VirtToPhy.

func newRoutingTestHandler(t *testing.T) *Handler {
	t.Helper()
	h, err := NewHandler(
		WithLocalAddr(&tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: 6081}),
		WithLayer3VirtFrames(),
	)
	require.NoError(t, err)
	return h
}

func rt(srcCIDR, dstCIDR string) Route {
	return Route{Src: netip.MustParsePrefix(srcCIDR), Dst: netip.MustParsePrefix(dstCIDR)}
}

func remote(ip string) *tcpip.FullAddress {
	return &tcpip.FullAddress{Addr: tcpip.AddrFrom4(netip.MustParseAddr(ip).As4()), Port: 6081}
}

func lookup(t *testing.T, h *Handler, src, dst string) (uint, bool) {
	t.Helper()
	return h.RouteLookupForTest(netip.MustParseAddr(src), netip.MustParseAddr(dst))
}

// APO-653 (S10): a second network with an identical Src+Dst route must be
// rejected, not silently overwrite the first network's egress.
func TestAddRejectsDuplicateSrcDst(t *testing.T) {
	h := newRoutingTestHandler(t)
	require.NoError(t, h.AddVirtualNetwork(100, remote("10.0.0.1"), []Route{rt("192.168.1.0/24", "10.1.0.0/24")}))

	err := h.AddVirtualNetwork(200, remote("10.0.0.2"), []Route{rt("192.168.1.0/24", "10.1.0.0/24")})
	require.Error(t, err, "duplicate Src+Dst must be rejected, not silently overwrite")

	// The original network still owns the route.
	vni, ok := lookup(t, h, "192.168.1.5", "10.1.0.5")
	require.True(t, ok)
	require.Equal(t, uint(100), vni)

	// The rejected add left no partial state: VNI 200 was never created.
	require.Error(t, h.RemoveVirtualNetwork(200), "VNI 200 must not have been created")
}

// APO-654 (S11): removing a network only removes the routes it owns, and an
// emptied Dst entry is reclaimed rather than leaking.
func TestRemovePreservesSiblingAndReclaimsEmptyEntry(t *testing.T) {
	h := newRoutingTestHandler(t)
	// Two networks share Dst=10.1.0.0/24 but have distinct Src prefixes.
	require.NoError(t, h.AddVirtualNetwork(100, remote("10.0.0.1"), []Route{rt("192.168.1.0/24", "10.1.0.0/24")}))
	require.NoError(t, h.AddVirtualNetwork(101, remote("10.0.0.2"), []Route{rt("192.168.2.0/24", "10.1.0.0/24")}))
	require.Equal(t, 1, h.DstEntryCountForTest(), "a shared Dst is a single entry")

	// Removing 100 must not blackhole 101.
	require.NoError(t, h.RemoveVirtualNetwork(100))
	_, ok := lookup(t, h, "192.168.1.5", "10.1.0.5")
	require.False(t, ok, "removed network's route is gone")
	vni, ok := lookup(t, h, "192.168.2.5", "10.1.0.5")
	require.True(t, ok, "sibling sharing the Dst must still route")
	require.Equal(t, uint(101), vni)
	require.Equal(t, 1, h.DstEntryCountForTest(), "entry survives while a sibling owns it")

	// Removing the last owner reclaims the Dst entry (no unbounded node growth).
	require.NoError(t, h.RemoveVirtualNetwork(101))
	require.Equal(t, 0, h.DstEntryCountForTest(), "emptied Dst entry must be reclaimed")
	_, ok = lookup(t, h, "192.168.2.5", "10.1.0.5")
	require.False(t, ok)
}

// APO-663 (S20): a Dst nested inside another network's broader Dst gets its own
// entry (exact-match keying), so it neither clobbers the broad network nor
// depends on it. Uses the same Src for both to make the overwrite visible.
func TestNestedDstExactKeying(t *testing.T) {
	h := newRoutingTestHandler(t)
	require.NoError(t, h.AddVirtualNetwork(100, remote("10.0.0.1"), []Route{rt("172.16.0.0/16", "10.0.0.0/16")}))
	require.NoError(t, h.AddVirtualNetwork(200, remote("10.0.0.2"), []Route{rt("172.16.0.0/16", "10.0.5.0/24")}))
	require.Equal(t, 2, h.DstEntryCountForTest(), "a nested Dst must be its own entry")

	// The nested range resolves to the nested network (more specific Dst).
	vni, ok := lookup(t, h, "172.16.0.1", "10.0.5.1")
	require.True(t, ok)
	require.Equal(t, uint(200), vni)

	// The broad range outside the nested one must still resolve to the broad
	// network — the nested add did not clobber it (the S20+S10 misroute).
	vni, ok = lookup(t, h, "172.16.0.1", "10.0.4.1")
	require.True(t, ok)
	require.Equal(t, uint(100), vni)

	// Removing the nested network leaves the broad one intact.
	require.NoError(t, h.RemoveVirtualNetwork(200))
	vni, ok = lookup(t, h, "172.16.0.1", "10.0.4.1")
	require.True(t, ok)
	require.Equal(t, uint(100), vni)
	require.Equal(t, 1, h.DstEntryCountForTest())
}

// APO-653 via Update: an update whose new routes collide with another network is
// rejected and rolls back atomically — the network keeps its original routes.
func TestUpdateRoutesAtomicOnConflict(t *testing.T) {
	h := newRoutingTestHandler(t)
	require.NoError(t, h.AddVirtualNetwork(1, remote("10.0.0.1"), []Route{rt("192.168.1.0/24", "10.1.0.0/24")}))
	require.NoError(t, h.AddVirtualNetwork(2, remote("10.0.0.2"), []Route{rt("192.168.2.0/24", "10.2.0.0/24")}))

	// Update VNI 2 to a set colliding with VNI 1 -> reject + roll back.
	err := h.UpdateVirtualNetworkRoutes(2, []Route{rt("192.168.1.0/24", "10.1.0.0/24")})
	require.Error(t, err)

	// VNI 2 keeps its original route; VNI 1 still owns the contested one.
	vni, ok := lookup(t, h, "192.168.2.5", "10.2.0.5")
	require.True(t, ok, "VNI 2's original route must survive a rejected update")
	require.Equal(t, uint(2), vni)
	vni, ok = lookup(t, h, "192.168.1.5", "10.1.0.5")
	require.True(t, ok)
	require.Equal(t, uint(1), vni)
}

// A non-conflicting update swaps the route set and reclaims the old entry.
func TestUpdateRoutesSucceeds(t *testing.T) {
	h := newRoutingTestHandler(t)
	require.NoError(t, h.AddVirtualNetwork(1, remote("10.0.0.1"), []Route{rt("192.168.1.0/24", "10.1.0.0/24")}))

	require.NoError(t, h.UpdateVirtualNetworkRoutes(1, []Route{rt("192.168.9.0/24", "10.9.0.0/24")}))

	_, ok := lookup(t, h, "192.168.1.5", "10.1.0.5")
	require.False(t, ok, "old route must be gone")
	vni, ok := lookup(t, h, "192.168.9.5", "10.9.0.5")
	require.True(t, ok)
	require.Equal(t, uint(1), vni)
	require.Equal(t, 1, h.DstEntryCountForTest(), "old Dst entry reclaimed, one new entry")
}

// Re-adding the same network's routes (idempotent within one vnet) is allowed —
// the collision guard only rejects a *different* owner.
func TestAddVirtualNetworkDuplicateRouteSameVnetOK(t *testing.T) {
	h := newRoutingTestHandler(t)
	require.NoError(t, h.AddVirtualNetwork(1, remote("10.0.0.1"), []Route{
		rt("192.168.1.0/24", "10.1.0.0/24"),
		rt("192.168.1.0/24", "10.1.0.0/24"),
	}))
	vni, ok := lookup(t, h, "192.168.1.5", "10.1.0.5")
	require.True(t, ok)
	require.Equal(t, uint(1), vni)
}
