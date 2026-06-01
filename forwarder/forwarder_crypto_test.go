//go:build linux

package forwarder_test

import (
	"bytes"
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
	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/forwarder"
	"github.com/apoxy-dev/icx/permissions"
	"github.com/apoxy-dev/icx/veth"
)

// TestForwarderCryptoRoundTrip drives a REAL icx crypto Handler (Geneve + UDP +
// AES-GCM-128) through the real AF_XDP forwarder datapath over veth. TestForwarder
// proves only the shared-UMEM descriptor plumbing — it uses an identity handler
// that never encrypts. This test closes that seam: it injects a genuinely
// encrypted physical frame at the forwarder's phy ingress and asserts the
// forwarder decapsulates it in place and emits the recovered inner packet on the
// virt interface, byte-for-byte.
//
// Construction (single self-keyed handler, option (b1) from the test plan):
//   - One *icx.Handler with a single shared key and one route whose Src and Dst
//     both cover the inner addresses, so a frame its two-buffer VirtToPhy encaps
//     can be decapped by its in-place PhyToVirtInPlace (decap looks the vnet up
//     by VNI and validates the inner source against route.Dst; it does NOT check
//     the outer underlay source, so a self-encap/decap loop is valid).
//   - The encap is done OFFLINE with VirtToPhy to mint a real encrypted frame;
//     the frame is injected via a raw AF_PACKET socket on the phy peer (the same
//     XDP-redirect primitive TestForwarderRXHeadroom uses), and the decapped
//     inner frame is read with a second raw socket on the virt peer.
func TestForwarderCryptoRoundTrip(t *testing.T) {
	netAdmin, _ := permissions.IsNetAdmin()
	if !netAdmin {
		t.Skip("Skipping test because it requires NET_ADMIN capabilities")
	}

	// phy/virt veth pairs. The forwarder binds to the .Peer ends; we inject on
	// phy.Link and read on virt.Link (the opposite ends), mirroring TestForwarder.
	phyDev, err := veth.Create("icx-cphy", 1, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, phyDev.Close()) })

	virtDev, err := veth.Create("icx-cvirt", 1, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, virtDev.Close()) })

	phyFilter, err := filter.All()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, phyFilter.Close()) })

	// The handler writes this MAC as the Ethernet destination of every decapped
	// frame; pin it to the virt interface's real MAC and assert it on the wire.
	virtMAC := tcpip.LinkAddress(virtDev.Peer.Attrs().HardwareAddr)

	// Underlay (outer) addressing. The exact values are self-consistent because
	// the same handler both encaps and decaps; only the family (IPv4) matters for
	// header sizing. LinkAddrs are overwritten before injection (see below).
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

	h, err := icx.NewHandler(
		icx.WithLocalAddr(localUnderlay),
		icx.WithVirtMAC(virtMAC),
	)
	require.NoError(t, err)

	const vni uint = 0x1234
	prefix := netip.MustParsePrefix("10.99.0.0/24")
	require.NoError(t, h.AddVirtualNetwork(vni, remoteUnderlay,
		[]icx.Route{{Src: prefix, Dst: prefix}}))

	var key [16]byte
	copy(key[:], []byte("icx-roundtrip-k!"))
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 1, key, key, time.Now().Add(time.Hour)))

	// Build the forwarder with the REAL handler (not the identity pipe).
	fwd, err := forwarder.NewForwarder(h,
		forwarder.WithPhyName(phyDev.Peer.Attrs().Name),
		forwarder.WithPhyFilter(phyFilter),
		forwarder.WithVirtName(virtDev.Peer.Attrs().Name),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, fwd.Close()) })

	go func() { _ = fwd.Start(t.Context()) }()

	// The inner virtual frame: [Ethernet][IPv4][UDP][canary payload]. Inner src
	// and dst both sit inside the route prefix so encap routing and decap source
	// validation both pass. The canary payload makes the decapped frame
	// unmistakable amid any link-local noise on the veth.
	canary := []byte("icx-crypto-roundtrip-canary-0001")
	ethL := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x01},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0x99, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipL := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IPv4(10, 99, 0, 1),
		DstIP:    net.IPv4(10, 99, 0, 2),
	}
	udpL := &layers.UDP{SrcPort: 1234, DstPort: 5678}
	require.NoError(t, udpL.SetNetworkLayerForChecksum(ipL))
	sb := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(sb,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ethL, ipL, udpL, gopacket.Payload(canary)))
	virtFrame := sb.Bytes()
	innerIP := virtFrame[14:] // the IP packet the forwarder must recover

	// Raw reader on the virt peer's far end: the decapped frame the forwarder
	// transmits on virt.Peer arrives here.
	recvFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(recvFD) })
	require.NoError(t, unix.Bind(recvFD, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  virtDev.Link.Attrs().Index,
	}))

	// Raw sender on the phy peer's far end: a frame sent here ingresses phy.Peer,
	// where the XDP program redirects it into the forwarder's phy socket.
	sendFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(sendFD) })
	phyDstMAC := phyDev.Peer.Attrs().HardwareAddr // forwarder's phy ingress
	phySrcMAC := phyDev.Link.Attrs().HardwareAddr
	sa := &unix.SockaddrLinklayer{Ifindex: phyDev.Link.Attrs().Index, Halen: 6}
	copy(sa.Addr[:], phyDstMAC)

	// Let the forwarder finish binding both sockets and attaching XDP.
	time.Sleep(500 * time.Millisecond)

	recvBuf := make([]byte, 2048)
	var found bool
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && !found {
		// Mint a fresh encrypted frame each iteration: VirtToPhy advances the TX
		// counter, so every injected frame carries a unique nonce and clears the
		// replay filter.
		phyBuf := make([]byte, 2048)
		n, handled := h.VirtToPhy(virtFrame, phyBuf)
		require.Greater(t, n, 0, "offline encap produced no frame")
		require.False(t, handled)
		enc := phyBuf[:n]

		// Steer the outer frame to the forwarder's phy ingress (udp.Encode wrote
		// the underlay LinkAddrs; the XDP redirect is MAC-agnostic but we set a
		// real dst/src to mirror TestForwarderRXHeadroom).
		copy(enc[0:6], phyDstMAC)
		copy(enc[6:12], phySrcMAC)
		require.NoError(t, unix.Sendto(sendFD, enc, 0, sa))

		// Drain whatever arrived on the virt side and look for our inner packet.
		pfd := []unix.PollFd{{Fd: int32(recvFD), Events: unix.POLLIN}}
		_, _ = unix.Poll(pfd, 200)
		for {
			nr, _, rerr := unix.Recvfrom(recvFD, recvBuf, unix.MSG_DONTWAIT)
			if rerr != nil || nr <= 0 {
				break
			}
			frame := recvBuf[:nr]
			if len(frame) >= 14+len(innerIP) && bytes.Equal(frame[14:14+len(innerIP)], innerIP) {
				// The forwarder rewrote the Ethernet header with virtMAC as dst.
				require.Equal(t, []byte(virtMAC), frame[0:6],
					"decapped frame Ethernet destination should be the configured virt MAC")
				found = true
				break
			}
		}
	}

	require.True(t, found,
		"forwarder did not emit the decapsulated inner packet on the virt interface; "+
			"the real crypto decap over the AF_XDP datapath failed")
}
