//go:build linux

package mac_test

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx/mac"
	"github.com/apoxy-dev/icx/permissions"
)

func TestMACResolve(t *testing.T) {
	netAdmin, _ := permissions.IsNetAdmin()
	if !netAdmin {
		t.Skip("Skipping test because it requires NET_ADMIN capabilities")
	}

	ip := tcpip.AddrFromSlice(net.ParseIP("8.8.8.8").To4())

	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	require.NoError(t, err)

	var defaultLink netlink.Link
	for _, route := range routes {
		if (route.Dst == nil || route.Dst.IP.IsUnspecified()) && route.Gw != nil {
			defaultLink, err = netlink.LinkByIndex(route.LinkIndex)
			require.NoError(t, err)
			break
		}
	}
	// This test resolves a real next-hop MAC, so it needs a real default gateway
	// to ARP. A hermetic CI container (e.g. the Dagger test sandbox) has outbound
	// NAT but not necessarily a default-gateway FIB entry the resolver can look
	// up — the amd64 runner has none while the arm64 one does. Skip rather than
	// fail where the prerequisite is absent; arm64 CI and local runs still cover
	// mac.Resolve. (The old --network host harness always had host routing.)
	if defaultLink == nil {
		t.Skip("no default IPv4 gateway route in this environment; mac.Resolve needs a real next hop")
	}

	// delete the next-hop neighbor entry before calling Resolve
	if err := clearNextHopNeighbor(defaultLink, ip); err != nil {
		t.Skipf("cannot look up a route to the next hop in this environment: %v", err)
	}

	addrs, err := netlink.AddrList(defaultLink, netlink.FAMILY_V4)
	require.NoError(t, err)
	require.NotEmpty(t, addrs)

	srcAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(addrs[0].IP.To4()),
	}

	hwAddr, err := mac.Resolve(t.Context(), defaultLink, srcAddr, ip)
	require.NoError(t, err)
	require.NotNil(t, hwAddr)
}

func clearNextHopNeighbor(link netlink.Link, ip tcpip.Address) error {
	ipSlice := net.IP(ip.AsSlice())
	routes, err := netlink.RouteGet(ipSlice)
	if err != nil || len(routes) == 0 {
		return fmt.Errorf("route lookup failed: %w", err)
	}
	route := routes[0]

	nextHop := ipSlice
	if route.Gw != nil {
		nextHop = route.Gw
	}

	family := netlink.FAMILY_V6
	if nextHop.To4() != nil {
		family = netlink.FAMILY_V4
	}

	ne := &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		Family:    family,
		IP:        nextHop,
	}
	// Best effort: the kernel only needs LinkIndex+IP(+Family) to delete.
	return netlink.NeighDel(ne)
}
