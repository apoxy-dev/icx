//go:build linux

package tunnel_test

import (
	"testing"

	"github.com/apoxy-dev/icx/tunnel"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func TestNumQueues(t *testing.T) {
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

	numQueues, err := tunnel.NumQueues(defaultLink)
	require.NoError(t, err)

	require.Greater(t, numQueues, 0, "number of queues should be greater than 0")
}
