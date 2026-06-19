//go:build linux

package forwarder_test

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/forwarder"
	"github.com/apoxy-dev/icx/permissions"
	"github.com/apoxy-dev/icx/veth"
)

// TestForwarderCryptoMultiQueue drives the REAL AF_XDP crypto datapath through a
// MULTI-QUEUE forwarder: phy and virt veths with several queues, so NewForwarder
// binds one phy/virt socket pair per queue and Start spawns one processFrames
// goroutine per queue — all decapsulating through the SAME shared *icx.Handler at
// once. TestForwarderCryptoRoundTrip covers only the single-queue path; this test
// closes the multiqueue seam on a real kernel.
//
// It injects many distinct inner flows. With WithSourcePortHashing on the encap
// side, each flow gets a different outer UDP source port, so the veth's RX hashing
// spreads the encapsulated frames across the queues and several processFrames
// goroutines do real concurrent decap work. The assertion is that EVERY distinct
// flow's canary is recovered on the virt side: a wedged or mis-bound queue
// goroutine would silently swallow the flows hashed to it, and a concurrency bug
// in the shared handler would corrupt or drop frames. Run under -race (the dagger
// Integration lane default) it also exercises the N-goroutine datapath for data
// races that the single-queue tests cannot reach.
func TestForwarderCryptoMultiQueue(t *testing.T) {
	netAdmin, _ := permissions.IsNetAdmin()
	if !netAdmin {
		t.Skip("Skipping test because it requires NET_ADMIN capabilities")
	}

	const numQueues = 4

	phyDev, err := veth.Create("icx-mqphy", numQueues, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, phyDev.Close()) })

	virtDev, err := veth.Create("icx-mqvirt", numQueues, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, virtDev.Close()) })

	virtMAC := tcpip.LinkAddress(virtDev.Peer.Attrs().HardwareAddr)

	localUnderlay := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 1).To4()),
		Port:     6081,
		LinkAddr: tcpip.LinkAddress("\x02\x00\x00\x00\x0a\x01"),
	}
	remoteUnderlay := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 2).To4()),
		Port:     6081,
		LinkAddr: tcpip.LinkAddress("\x02\x00\x00\x00\x0a\x02"),
	}

	const vni uint = 0x1234
	prefix := netip.MustParsePrefix("10.99.0.0/24")
	routes := []icx.Route{{Src: prefix, Dst: prefix}}

	var abKey, encapRx, hTx [16]byte
	copy(abKey[:], []byte("icx-mq-rndtrip-k"))
	copy(encapRx[:], []byte("icx-mq-encap-rx!"))
	copy(hTx[:], []byte("icx-mq-decap-tx!"))
	expires := time.Now().Add(time.Hour)

	// The forwarder's handler: decapsulates inbound frames with rxKey=abKey.
	h, err := icx.NewHandler(
		icx.WithLocalAddr(localUnderlay),
		icx.WithVirtMAC(virtMAC),
	)
	require.NoError(t, err)
	require.NoError(t, h.AddVirtualNetwork(vni, remoteUnderlay, routes))
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 1, abKey, hTx, expires))

	// Offline peer that mints genuinely-encrypted frames with txKey=abKey. Source-
	// port hashing makes each inner flow take a distinct outer UDP source port, so
	// the veth spreads the frames across the phy's RX queues.
	encapH, err := icx.NewHandler(
		icx.WithLocalAddr(localUnderlay),
		icx.WithVirtMAC(virtMAC),
		icx.WithSourcePortHashing(),
	)
	require.NoError(t, err)
	require.NoError(t, encapH.AddVirtualNetwork(vni, remoteUnderlay, routes))
	require.NoError(t, encapH.UpdateVirtualNetworkKeys(vni, 1, encapRx, abKey, expires))

	// No WithPhyFilter: use the production default phy filter (filter.Geneve on UDP
	// 6081), so this test also exercises the geneve.c XDP program — the production
	// ingress path, which no other test covers — under multiqueue. The injected
	// frames carry outer UDP dst port 6081, matching the filter's wildcard bind.
	fwd, err := forwarder.NewForwarder(h,
		forwarder.WithPhyName(phyDev.Peer.Attrs().Name),
		forwarder.WithVirtName(virtDev.Peer.Attrs().Name),
	)
	require.NoError(t, err)

	// Start the forwarder and shut it down cleanly at test end (cancel + wait for
	// Start to self-close); see runForwarder for why a t.Cleanup(fwd.Close()) races
	// the still-running datapath goroutines.
	runForwarder(t, fwd)

	// Build a distinct inner flow per canary: distinct inner source address (within
	// the route prefix) and a unique 32-byte canary payload, so a recovered frame
	// is unambiguously attributable to its flow. Distinct sources => distinct flow
	// hashes => distinct outer source ports => RX-queue spread.
	const flows = 16
	innerIPs := make([][]byte, flows)
	virtFrames := make([][]byte, flows)
	for k := 0; k < flows; k++ {
		canary := []byte(fmt.Sprintf("icx-mq-canary-%02d-padding-xxxxx", k))
		ethL := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x99, byte(0x10 + k)},
			DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x02},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ipL := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IPv4(10, 99, 0, byte(10+k)),
			DstIP:    net.IPv4(10, 99, 0, 200),
		}
		udpL := &layers.UDP{SrcPort: layers.UDPPort(1234 + k), DstPort: 5678}
		require.NoError(t, udpL.SetNetworkLayerForChecksum(ipL))
		sb := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(sb,
			gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
			ethL, ipL, udpL, gopacket.Payload(canary)))
		virtFrames[k] = sb.Bytes()
		innerIPs[k] = append([]byte(nil), virtFrames[k][14:]...) // IP packet the forwarder recovers
	}

	// Raw reader on the virt peer's far end.
	recvFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(recvFD) })
	require.NoError(t, unix.Bind(recvFD, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  virtDev.Link.Attrs().Index,
	}))

	// Raw sender on the phy peer's far end.
	sendFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(sendFD) })
	phyDstMAC := phyDev.Peer.Attrs().HardwareAddr
	phySrcMAC := phyDev.Link.Attrs().HardwareAddr
	sa := &unix.SockaddrLinklayer{Ifindex: phyDev.Link.Attrs().Index, Halen: 6}
	copy(sa.Addr[:], phyDstMAC)

	// Let the forwarder bind all queues and attach XDP.
	time.Sleep(500 * time.Millisecond)

	seen := make([]bool, flows)
	remaining := flows
	recvBuf := make([]byte, 2048)
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) && remaining > 0 {
		// Inject one fresh encrypted frame for every flow this round (fresh nonce
		// each time, so none is dropped as a replay).
		for k := 0; k < flows; k++ {
			phyBuf := make([]byte, 2048)
			n, handled := encapH.VirtToPhy(virtFrames[k], phyBuf)
			require.Greater(t, n, 0)
			require.False(t, handled)
			enc := phyBuf[:n]
			copy(enc[0:6], phyDstMAC)
			copy(enc[6:12], phySrcMAC)
			require.NoError(t, unix.Sendto(sendFD, enc, 0, sa))
		}

		// Drain and attribute whatever decapped frames arrived.
		pfd := []unix.PollFd{{Fd: int32(recvFD), Events: unix.POLLIN}}
		_, _ = unix.Poll(pfd, 200)
		for {
			nr, _, rerr := unix.Recvfrom(recvFD, recvBuf, unix.MSG_DONTWAIT)
			if rerr != nil || nr <= 0 {
				break
			}
			frame := recvBuf[:nr]
			for k := 0; k < flows; k++ {
				if seen[k] {
					continue
				}
				if len(frame) >= 14+len(innerIPs[k]) && bytes.Equal(frame[14:14+len(innerIPs[k])], innerIPs[k]) {
					seen[k] = true
					remaining--
				}
			}
		}
	}

	if remaining > 0 {
		var missing []int
		for k := 0; k < flows; k++ {
			if !seen[k] {
				missing = append(missing, k)
			}
		}
		t.Fatalf("multiqueue decap dropped %d/%d flows (missing flow indices %v); a queue goroutine wedged or mis-bound, or the shared handler corrupted frames under concurrency",
			remaining, flows, missing)
	}
}
