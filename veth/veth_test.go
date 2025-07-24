//go:build linux

package veth_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/apoxy-dev/icx/permissions"
	"github.com/apoxy-dev/icx/tunnel"
	"github.com/apoxy-dev/icx/veth"
)

func TestVeth(t *testing.T) {
	netAdmin, _ := permissions.IsNetAdmin()
	if !netAdmin {
		t.Skip("Skipping test because it requires NET_ADMIN capabilities")
	}

	// Create a veth pair with specific parameters
	name := "testveth0"
	numQueues := 2
	mtu := 1500

	handle, err := veth.Create(name, numQueues, mtu)
	if err != nil {
		t.Fatalf("Failed to create veth pair: %v", err)
	}
	t.Cleanup(func() {
		require.NoError(t, handle.Close())
	})

	// Check if the link was created successfully
	link, err := netlink.LinkByName(name)
	require.NoError(t, err, "Failed to find link by name %s", name)

	require.Equal(t, mtu, link.Attrs().MTU)

	actualNumQueues, err := tunnel.NumQueues(link)
	require.NoError(t, err, "Failed to get number of queues for link %s", name)
	require.Equal(t, numQueues, actualNumQueues)

	// Check if the peer link exists
	peerName := handle.Peer.Attrs().Name
	peerLink, err := netlink.LinkByName(peerName)
	require.NoError(t, err, "Failed to find peer link by name %s", peerName)

	require.Equal(t, mtu, peerLink.Attrs().MTU)

	// Close the handle and check if the links are deleted
	require.NoError(t, handle.Close())

	_, err = netlink.LinkByName(name)
	require.Error(t, err, "Expected error when looking for deleted link %s", name)
}
