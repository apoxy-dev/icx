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

// TestForwarderOuterSrcValidation proves S7 (APO-650) end to end through the REAL
// AF_XDP datapath, not just the handler API. With WithOuterSrcValidation enabled
// on the forwarder's handler, a frame whose outer underlay source IS the
// configured peer is decapsulated and emitted on the virt interface, while a
// frame identical in every respect EXCEPT a non-peer outer source is dropped
// before decryption — it never reaches the virt interface, and the handler
// attributes the drop to RXDropsBadPeer.
//
// Both injected frames carry valid keys, VNI, counter, and in-prefix inner
// addresses, so the ONLY thing that can drop the bad one is the outer-source
// check — which is exactly what RXDropsBadPeer isolates.
func TestForwarderOuterSrcValidation(t *testing.T) {
	netAdmin, _ := permissions.IsNetAdmin()
	if !netAdmin {
		t.Skip("Skipping test because it requires NET_ADMIN capabilities")
	}

	phyDev, err := veth.Create("icx-s7phy", 1, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, phyDev.Close()) })

	virtDev, err := veth.Create("icx-s7virt", 1, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, virtDev.Close()) })

	phyFilter, err := filter.All()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, phyFilter.Close()) })

	virtMAC := tcpip.LinkAddress(virtDev.Peer.Attrs().HardwareAddr)

	// Underlay addressing: h's local end, the legitimate peer (h's RemoteAddr),
	// and a non-peer source the bad frame is minted from.
	localUnderlay := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 1).To4()),
		Port:     6081,
		LinkAddr: tcpip.LinkAddress("\x02\x00\x00\x00\x0a\x01"),
	}
	peerUnderlay := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 2).To4()),
		Port:     6081,
		LinkAddr: tcpip.LinkAddress("\x02\x00\x00\x00\x0a\x02"),
	}
	wrongUnderlay := &tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 99).To4()),
		Port:     6081,
		LinkAddr: tcpip.LinkAddress("\x02\x00\x00\x00\x0a\x63"),
	}

	const vni uint = 0x1234
	prefix := netip.MustParsePrefix("10.99.0.0/24")
	routes := []icx.Route{{Src: prefix, Dst: prefix}}

	var abKey, encapRx, hTx [16]byte
	copy(abKey[:], []byte("icx-s7-roundtr!!"))
	copy(encapRx[:], []byte("icx-s7-encap-rx!"))
	copy(hTx[:], []byte("icx-s7-decap-tx!"))
	expires := time.Now().Add(time.Hour)

	// The forwarder's handler: decapsulates with rxKey=abKey and ENFORCES the
	// outer source == its configured peer (peerUnderlay).
	h, err := icx.NewHandler(
		icx.WithLocalAddr(localUnderlay),
		icx.WithVirtMAC(virtMAC),
		icx.WithOuterSrcValidation(),
	)
	require.NoError(t, err)
	require.NoError(t, h.AddVirtualNetwork(vni, peerUnderlay, routes))
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 1, abKey, hTx, expires))

	// goodEncap mints frames sourced from peerUnderlay (== h's RemoteAddr).
	goodEncap := mintHandler(t, peerUnderlay, localUnderlay, vni, routes, encapRx, abKey, expires)
	// badEncap mints frames sourced from wrongUnderlay (a non-peer).
	badEncap := mintHandler(t, wrongUnderlay, localUnderlay, vni, routes, encapRx, abKey, expires)

	fwd, err := forwarder.NewForwarder(h,
		forwarder.WithPhyName(phyDev.Peer.Attrs().Name),
		forwarder.WithPhyFilter(phyFilter),
		forwarder.WithVirtName(virtDev.Peer.Attrs().Name),
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, fwd.Close()) })
	go func() { _ = fwd.Start(t.Context()) }()

	// Distinct canary payloads so a leaked bad frame is unmistakable on virt. The
	// handlers are L2: VirtToPhy takes the full Ethernet frame, while the decapped
	// frame on virt carries a rewritten Ethernet header, so matches are on the
	// inner IP slice (frame[14:]).
	goodVirt := buildInner(t, []byte("icx-s7-GOOD-source-canary-000001"))
	goodIP := goodVirt[14:]
	badVirt := buildInner(t, []byte("icx-s7-BAD-source-canary-00000002"))
	badIP := badVirt[14:]

	recvFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(recvFD) })
	require.NoError(t, unix.Bind(recvFD, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  virtDev.Link.Attrs().Index,
	}))

	sendFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(sendFD) })
	phyDstMAC := phyDev.Peer.Attrs().HardwareAddr
	phySrcMAC := phyDev.Link.Attrs().HardwareAddr
	sa := &unix.SockaddrLinklayer{Ifindex: phyDev.Link.Attrs().Index, Halen: 6}
	copy(sa.Addr[:], phyDstMAC)

	// Let the forwarder finish binding both sockets and attaching XDP.
	time.Sleep(500 * time.Millisecond)

	inject := func(enc []byte) {
		copy(enc[0:6], phyDstMAC)
		copy(enc[6:12], phySrcMAC)
		require.NoError(t, unix.Sendto(sendFD, enc, 0, sa))
	}
	// seenOnVirt drains the virt socket and reports whether any frame carried the
	// given inner packet.
	recvBuf := make([]byte, 2048)
	seenOnVirt := func(inner []byte) bool {
		pfd := []unix.PollFd{{Fd: int32(recvFD), Events: unix.POLLIN}}
		_, _ = unix.Poll(pfd, 200)
		for {
			nr, _, rerr := unix.Recvfrom(recvFD, recvBuf, unix.MSG_DONTWAIT)
			if rerr != nil || nr <= 0 {
				return false
			}
			frame := recvBuf[:nr]
			if len(frame) >= 14+len(inner) && bytes.Equal(frame[14:14+len(inner)], inner) {
				return true
			}
		}
	}

	vnet, ok := h.GetVirtualNetwork(vni)
	require.True(t, ok)

	// 1) Bad source first (so no replay state yet): keep injecting until the handler
	// charges RXDropsBadPeer (proving a bad frame traversed XDP+forwarder and hit
	// the outer-source check), and assert the inner never surfaces on virt. Minting
	// a fresh frame each time advances the nonce so replay can never be the reason a
	// later one is dropped.
	badDeadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(badDeadline) && vnet.Stats.RXDropsBadPeer.Load() == 0 {
		phyBuf := make([]byte, 2048)
		n, handled := badEncap.VirtToPhy(badVirt, phyBuf)
		require.Greater(t, n, 0)
		require.False(t, handled)
		inject(phyBuf[:n])
		require.False(t, seenOnVirt(badIP), "a non-peer-sourced frame must not be decapped to virt")
	}
	require.NotZero(t, vnet.Stats.RXDropsBadPeer.Load(),
		"the forwarder's handler must have dropped at least one non-peer frame via the outer-source check")
	require.Zero(t, vnet.Stats.RXPackets.Load(), "no bad frame was accepted")

	// 2) Good source: retry mint+inject until the decapped inner appears on virt,
	// proving the same datapath accepts a peer-sourced frame with S7 enabled.
	var goodSeen bool
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) && !goodSeen {
		phyBuf := make([]byte, 2048)
		n, handled := goodEncap.VirtToPhy(goodVirt, phyBuf)
		require.Greater(t, n, 0)
		require.False(t, handled)
		inject(phyBuf[:n])
		goodSeen = seenOnVirt(goodIP)
	}
	require.True(t, goodSeen, "a peer-sourced frame must be decapsulated to virt with S7 enabled")
}

// mintHandler builds an offline peer handler that mints encrypted frames sourced
// from `local`, addressed to `remote`, sharing the given VNI/routes/keys.
func mintHandler(t *testing.T, local, remote *tcpip.FullAddress, vni uint, routes []icx.Route, rxKey, txKey [16]byte, expires time.Time) *icx.Handler {
	t.Helper()
	h, err := icx.NewHandler(
		icx.WithLocalAddr(local),
		icx.WithVirtMAC(tcpip.LinkAddress("\x02\x00\x00\x00\xee\x01")),
	)
	require.NoError(t, err)
	require.NoError(t, h.AddVirtualNetwork(vni, remote, routes))
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 1, rxKey, txKey, expires))
	return h
}

// buildInner serializes an [Ethernet][IPv4][UDP][payload] virtual frame with
// inner addresses inside 10.99.0.0/24 (so the inner src/dst validation passes).
func buildInner(t *testing.T, canary []byte) []byte {
	t.Helper()
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
	return sb.Bytes()
}
