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

	// Disable offloads on BOTH ends of the pair. The previous code disabled only
	// checksum offload, and only on veth.Name — leaving GSO/GRO/TSO/LRO on and the
	// peer untouched. With segmentation/aggregation offload on, the veth hands the
	// AF_XDP socket 64 KiB super-frames that overflow the 2 KiB UMEM frame, so bulk
	// TCP silently drops while small packets/pings survive (APO-802). The XDP path
	// also needs checksum offload off because the encap works on raw bytes.
	if err := disableOffloads(ethHandle, veth.Name); err != nil {
		_ = h.Close()
		return nil, err
	}
	if err := disableOffloads(ethHandle, veth.PeerName); err != nil {
		_ = h.Close()
		return nil, err
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

// offloadsToDisable are the netdev features that must be OFF for the AF_XDP
// datapath. Checksum offload must be off because the in-place encap rewrites raw
// bytes; the segmentation/aggregation offloads (GSO/GRO/TSO/LRO/USO) must be off
// because with them on the stack hands the AF_XDP socket frames far larger than
// one UMEM frame, which the datapath cannot represent (APO-802). Names are the
// kernel ethtool feature strings (as in `ethtool -k`), not the short -K flags.
var offloadsToDisable = []string{
	// checksum
	"rx-checksum",
	"tx-checksum-ip-generic",
	"tx-checksum-ipv4",
	"tx-checksum-ipv6",
	// generic segmentation (gso) and receive (gro) offload
	"tx-generic-segmentation",
	"rx-gro",
	"rx-gro-list",
	// TCP segmentation offload (tso) leaves
	"tx-tcp-segmentation",
	"tx-tcp6-segmentation",
	"tx-tcp-ecn-segmentation",
	"tx-tcp-mangleid-segmentation",
	// UDP segmentation (uso) and large receive (lro) offload
	"tx-udp-segmentation",
	"rx-lro",
}

// disableOffloads turns off every feature in offloadsToDisable that the device
// actually exposes AND currently has enabled, so an unsupported or already-off
// leaf (e.g. rx-lro, which veth reports fixed-off) is skipped rather than turned
// into a hard error. Reading the live feature set keeps this robust across
// kernels where the available leaves differ.
func disableOffloads(eth *ethtool.Ethtool, name string) error {
	have, err := eth.Features(name)
	if err != nil {
		return fmt.Errorf("read features for %s: %w", name, err)
	}
	off := make(map[string]bool, len(offloadsToDisable))
	for _, f := range offloadsToDisable {
		if cur, ok := have[f]; ok && cur {
			off[f] = false
		}
	}
	if len(off) == 0 {
		return nil
	}
	if err := eth.Change(name, off); err != nil {
		return fmt.Errorf("disable offloads on %s: %w", name, err)
	}
	return nil
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
