package icx

import (
	"net/netip"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// VirtualNetwork describes a configured virtual network.
type VirtualNetwork struct {
	// VNI is the virtual network identifier.
	VNI uint
	// RemoteAddr is the address of the remote endpoint.
	RemoteAddr tcpip.FullAddress
	// Addrs is the list of local IP prefixes.
	Addrs []netip.Prefix
	// KeyEpoch is the current key epoch.
	KeyEpoch uint32
	// Stats is a statistics snapshot.
	Stats VirtualNetworkStats
}

// VirtualNetworkStats is a statistics snapshot for a virtual network.
type VirtualNetworkStats struct {
	// VNI is the virtual network identifier.
	VNI uint
	// KeyEpoch is the current key epoch.
	KeyEpoch uint32
	// KeyRotations is the number of key rotations that have occurred.
	KeyRotations uint32

	// RXPackets is the number of received packets.
	RXPackets uint64
	// RXBytes is the number of bytes received.
	RXBytes uint64
	// RXDropsNoKey is the number of received packets dropped due to a missing key.
	RXDropsNoKey uint64
	// RXDropsExpiredKey is the number of received packets dropped due to an expired key.
	RXDropsExpiredKey uint64
	// RXReplayDrops is the number of received packets dropped due to a potential replay attack.
	RXReplayDrops uint64
	// RXDecryptErrors is the number of received packets that failed decryption.
	RXDecryptErrors uint64
	// RXInvalidSrc is the number of received packets with an invalid source address.
	RXInvalidSrc uint64

	// TXPackets is the number of transmitted packets.
	TXPackets uint64
	// TXBytes is the number of bytes transmitted.
	TXBytes uint64
	// TXErrors is the number of transmission errors.
	TXErrors uint64

	// LastRX is the timestamp of the last received packet.
	LastRX time.Time
	// LastTX is the timestamp of the last transmitted packet.
	LastTX time.Time
}
