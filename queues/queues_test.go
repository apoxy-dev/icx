//go:build linux

package queues_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/apoxy-dev/icx/queues"
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

	numQueues, err := queues.NumQueues(defaultLink)
	require.NoError(t, err)

	require.Greater(t, numQueues, 0, "number of queues should be greater than 0")
}
