//go:build linux

package queues

import (
	"errors"
	"fmt"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func NumQueues(link netlink.Link) (int, error) {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return 0, fmt.Errorf("failed to create ethtool handle: %w", err)
	}
	defer ethHandle.Close()

	// ethtool GetChannels returns the CURRENT configured RX/TX/combined channel
	// counts for the interface (the Channels struct also carries MaxRx/MaxTx/
	// MaxCombined for the maxima, which we do not use). On a driver that does not
	// implement get-channels it returns ENOTSUP, which we tolerate and fall back to
	// the netdev's allocated NumRxQueues/NumTxQueues below.
	channels, err := ethHandle.GetChannels(link.Attrs().Name)
	if err != nil && !errors.Is(err, unix.ENOTSUP) {
		return -1, fmt.Errorf("failed to get channels: %w", err)
	}

	numRxQueues := int(channels.RxCount)
	numTxQueues := int(channels.TxCount)

	if channels.CombinedCount > 0 {
		numRxQueues = int(channels.CombinedCount)
		numTxQueues = int(channels.CombinedCount)
	}

	if numRxQueues == 0 {
		numRxQueues = link.Attrs().NumRxQueues
	}
	if numTxQueues == 0 {
		numTxQueues = link.Attrs().NumTxQueues
	}

	if numRxQueues != numTxQueues {
		return -1, fmt.Errorf("asymmetric RX (%d) and TX (%d) queues are not supported", numRxQueues, numTxQueues)
	}

	return numRxQueues, nil
}
