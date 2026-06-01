//go:build linux

package forwarder_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/internal/xsk"
	"github.com/apoxy-dev/icx/permissions"
	"github.com/apoxy-dev/icx/veth"
)

// TestForwarderRXHeadroom is the kernel-ABI guard for the zero-copy in-place
// datapath. The whole design rests on one assumption: when the kernel writes a
// received frame into a UMEM chunk, it leaves enough headroom BEFORE the packet
// data for the in-place encap path to prepend the outer Eth/IP/UDP + Geneve
// headers (PayloadOffsetIPv6 62 + Geneve 32 = 94 bytes, the largest prepend).
// In aligned chunk mode with UmemReg.Headroom == 0 (how the forwarder registers
// its UMEM) that headroom is XDP_PACKET_HEADROOM == 256 bytes.
//
// If this assumption were false, VirtToPhyInPlace's `phyStart < 0` guard would
// silently drop every outbound packet rather than corrupt memory — a safe but
// total failure that TestForwarder cannot catch (its identity handler never
// prepends headers). So we assert the real, kernel-produced RX descriptor offset
// directly: send a raw frame into the veth and observe where in its frame chunk
// the kernel placed it after the XDP redirect into the AF_XDP socket.
func TestForwarderRXHeadroom(t *testing.T) {
	netAdmin, _ := permissions.IsNetAdmin()
	if !netAdmin {
		t.Skip("Skipping test because it requires NET_ADMIN capabilities")
	}

	const (
		frameSize         = 2048
		xdpPacketHeadroom = 256 // kernel's aligned-mode reserve before RX data
		// minInPlaceHeadroom is the largest outer-header prepend the in-place
		// encap performs: PayloadOffsetIPv6 (62) + the fixed Geneve header (32).
		// This is the hard correctness floor; the assertion below also pins the
		// exact observed value so an ABI change surfaces loudly.
		minInPlaceHeadroom = 94
	)

	dev, err := veth.Create("icx-hr", 1, 1500)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dev.Close()) })

	phyIdx := dev.Link.Attrs().Index
	peerIdx := dev.Peer.Attrs().Index
	phyMAC := dev.Link.Attrs().HardwareAddr
	peerMAC := dev.Peer.Attrs().HardwareAddr

	opts := xsk.Options{
		NumFrames:              256,
		FrameSize:              frameSize,
		FillRingNumDescs:       64,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         64,
		TxRingNumDescs:         64,
	}
	umem, err := xsk.NewUMEM(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = umem.Close() })
	sk, err := xsk.NewSocket(umem, phyIdx, 0, opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sk.Close() })

	// Steer all frames arriving on the phy interface into the socket — the same
	// XDP redirect wiring the forwarder uses, which TestForwarder proves works on
	// this veth.
	prog, err := filter.All()
	require.NoError(t, err)
	t.Cleanup(func() { _ = prog.Close() })
	require.NoError(t, prog.Attach(phyIdx))
	t.Cleanup(func() { _ = prog.Detach(phyIdx) })
	require.NoError(t, prog.Register(0, sk.FD()))

	// Prime the FILL ring so the kernel has chunks to receive into. The kernel
	// hands these chunk-base addresses back on RX offset by its headroom.
	require.Equal(t, 32, sk.Fill(32))

	// Raw sender bound to the peer end: a frame sent out the peer arrives on the
	// phy ingress, where the XDP program redirects it into the socket.
	sendFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(sendFD) })

	frame := make([]byte, 64)
	copy(frame[0:6], phyMAC)          // dst = phy
	copy(frame[6:12], peerMAC)        // src = peer
	frame[12], frame[13] = 0x08, 0x00 // EtherType IPv4 (payload is don't-care)
	sa := &unix.SockaddrLinklayer{Ifindex: peerIdx, Halen: 6}
	copy(sa.Addr[:], phyMAC)

	// Send frames until at least one is redirected onto the RX ring, or time out.
	// veth delivery + XDP redirect is effectively immediate; the loop just absorbs
	// scheduling jitter (mirrors the deadline pattern in the xsk TX tests).
	var got []xsk.Desc
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(got) == 0 {
		require.NoError(t, unix.Sendto(sendFD, frame, 0, sa))
		pfd := []unix.PollFd{{Fd: int32(sk.FD()), Events: unix.POLLIN}}
		_, _ = unix.Poll(pfd, 200)
		got = sk.Receive(got[:0], 16)
	}
	require.NotEmpty(t, got, "no frame was redirected onto the AF_XDP RX ring")

	for _, d := range got {
		off := d.Addr % frameSize
		// The semantic guarantee the in-place encap depends on:
		require.GreaterOrEqualf(t, off, uint64(minInPlaceHeadroom),
			"RX headroom %d < %d: in-place encap could not prepend outer headers",
			off, minInPlaceHeadroom)
		// Pin the exact aligned-mode ABI value so a regression is unambiguous:
		require.Equalf(t, uint64(xdpPacketHeadroom), off,
			"expected aligned-mode XDP_PACKET_HEADROOM (%d), got in-frame offset %d",
			xdpPacketHeadroom, off)
	}
	sk.ReleaseRX(got)
}

// htons converts a uint16 to network byte order for the AF_PACKET protocol field
// (the test host is little-endian aarch64/amd64).
func htons(v uint16) uint16 { return v<<8 | v>>8 }
