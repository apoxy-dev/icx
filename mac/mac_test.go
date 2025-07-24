//go:build linux

package mac_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx/mac"
)

func TestMACResolve(t *testing.T) {
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
