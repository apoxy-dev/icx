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
	require.NotNil(t, defaultLink, "default link not found")

	// delete the next-hop neighbor entry before calling Resolve
	require.NoError(t, clearNextHopNeighbor(defaultLink, ip))

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
