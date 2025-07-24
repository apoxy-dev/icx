//go:build linux

package veth

import (
	"fmt"
	"net"
	"regexp"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Handle represents a veth pair with its associated links.
type Handle struct {
	Link netlink.Link
	Peer netlink.Link
}

func (h *Handle) Close() error {
	_, err := netlink.LinkByName(h.Link.Attrs().Name)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil // Link already deleted, nothing to do
		}
		return fmt.Errorf("failed to get link %s: %w", h.Link.Attrs().Name, err)
	}

	if err := netlink.LinkSetDown(h.Link); err != nil {
		return fmt.Errorf("failed to set link %s down: %w", h.Link.Attrs().Name, err)
	}

	if err := netlink.LinkDel(h.Link); err != nil {
		return fmt.Errorf("failed to delete link %s: %w", h.Link.Attrs().Name, err)
	}

	return nil
}

// Create creates a veth pair with the specified name, number of queues, and MTU.
func Create(name string, numQueues, mtu int) (*Handle, error) {
	srcMAC := tcpip.GetRandMacAddr()
	dstMAC := tcpip.GetRandMacAddr()

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name:         name,
			MTU:          mtu,
			NumTxQueues:  numQueues,
			NumRxQueues:  numQueues,
			HardwareAddr: net.HardwareAddr(dstMAC),
		},
		PeerName:         generatePeerName(name),
		PeerMTU:          uint32(mtu),
		PeerNumTxQueues:  uint32(numQueues),
		PeerNumRxQueues:  uint32(numQueues),
		PeerHardwareAddr: net.HardwareAddr(srcMAC),
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("failed to create veth pair: %w", err)
	}

	link, err := netlink.LinkByName(veth.Name)
	if err != nil {
		_ = netlink.LinkDel(veth)
		return nil, fmt.Errorf("failed to get link by name %s: %w", veth.Name, err)
	}

	peer, err := netlink.LinkByName(veth.PeerName)
	if err != nil {
		_ = netlink.LinkDel(veth)
		return nil, fmt.Errorf("failed to get peer link by name %s: %w", veth.PeerName, err)
	}

	h := &Handle{
		Link: link,
		Peer: peer,
	}

	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("failed to create ethtool handle: %w", err)
	}
	defer ethHandle.Close()

	_, err = ethHandle.SetChannels(veth.Name, ethtool.Channels{
		TxCount: uint32(numQueues),
		RxCount: uint32(numQueues),
	})
	if err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("failed to set channels for %s: %w", veth.Name, err)
	}

	_, err = ethHandle.SetChannels(veth.PeerName, ethtool.Channels{
		TxCount: uint32(numQueues),
		RxCount: uint32(numQueues),
	})
	if err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("failed to set channels for %s: %w", veth.PeerName, err)
	}

	off := map[string]bool{
		"rx-checksum":            false,
		"tx-checksum-ip-generic": false,
		"tx-checksum-ipv4":       false,
		"tx-checksum-ipv6":       false,
	}

	if err := ethHandle.Change(veth.Name, off); err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("disable checksum offload on %s: %w", veth.Name, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("failed to set link %s up: %w", veth.Name, err)
	}

	if err := netlink.LinkSetUp(peer); err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("failed to set peer link %s up: %w", veth.PeerName, err)
	}

	return h, nil
}

func generatePeerName(name string) string {
	re := regexp.MustCompile(`^(.*?)(\d+)?$`)
	matches := re.FindStringSubmatch(name)
	if len(matches) == 3 {
		base := matches[1]
		suffix := matches[2]
		return base + "-xdp" + suffix
	}
	return name + "-xdp"
}
