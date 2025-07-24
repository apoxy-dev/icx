//go:build linux

package mac

import (
	"context"
	"fmt"
	"math"
	"net"

	"github.com/avast/retry-go/v4"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Resolve resolves the MAC address for the given IP address using the provided link.
// If the IP is not directly reachable, it resolves the MAC of the next-hop gateway.
func Resolve(ctx context.Context, link netlink.Link, srcAddr *tcpip.FullAddress, ip tcpip.Address) (tcpip.LinkAddress, error) {
	ipSlice := net.IP(ip.AsSlice())

	// Determine the correct next-hop IP: either the target IP or its gateway.
	routes, err := netlink.RouteGet(ipSlice)
	if err != nil || len(routes) == 0 {
		return "", fmt.Errorf("failed to get route to %s: %w", ip, err)
	}
	route := routes[0]

	// Sanity check: ensure the route uses the expected network interface.
	if route.LinkIndex != link.Attrs().Index {
		return "", fmt.Errorf("route to %s uses interface index %d, expected %d", ip, route.LinkIndex, link.Attrs().Index)
	}

	// Decide whether to resolve MAC of the destination IP or the gateway IP.
	nextHop := ipSlice
	if route.Gw != nil {
		nextHop = route.Gw
	}

	// Attempt to find the MAC address in the neighbor table first.
	mac, err := searchNeighborList(link, nextHop)
	if err == nil {
		return mac, nil
	}

	dstAddr := &net.UDPAddr{
		IP:   ipSlice,
		Port: math.MaxUint16,
	}

	var dstMAC tcpip.LinkAddress
	err = retry.Do(
		func() error {
			laddr := &net.UDPAddr{
				IP:   net.IP(srcAddr.Addr.AsSlice()),
				Port: int(srcAddr.Port),
			}

			// Trigger OS neighbor resolution by sending a dummy packet.
			conn, err := net.DialUDP("udp", laddr, dstAddr)
			if err != nil {
				return fmt.Errorf("failed to trigger neighbor resolution: %w", err)
			}
			defer func() {
				_ = conn.Close()
			}()

			// Sending an empty UDP packet
			if _, err := conn.Write(nil); err != nil {
				return fmt.Errorf("failed to write to UDP: %w", err)
			}

			// Try to resolve the MAC again after triggering.
			dstMAC, err = searchNeighborList(link, nextHop)
			if err != nil {
				return err
			}

			return nil
		},
		retry.Context(ctx),
	)
	if err != nil {
		return "", fmt.Errorf("failed to resolve MAC address for %s (next hop %s): %w", ip, nextHop, err)
	}

	return dstMAC, nil
}

// searchNeighborList looks up the MAC address of a given IP in the neighbor table
// for the specified link.
func searchNeighborList(link netlink.Link, ip net.IP) (tcpip.LinkAddress, error) {
	var family int
	if ip.To4() != nil {
		family = netlink.FAMILY_V4
	} else {
		family = netlink.FAMILY_V6
	}

	neighs, err := netlink.NeighList(link.Attrs().Index, family)
	if err != nil {
		return "", fmt.Errorf("failed to list neighbors: %w", err)
	}

	for _, n := range neighs {
		if n.IP.Equal(ip) && n.HardwareAddr != nil &&
			(n.State == netlink.NUD_REACHABLE || n.State == netlink.NUD_STALE || n.State == netlink.NUD_DELAY) {
			return tcpip.LinkAddress(n.HardwareAddr), nil
		}
	}

	return "", fmt.Errorf("MAC not yet resolved for %s", ip)
}
