package icx_test

import (
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx"
)

func TestHandler(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	localAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}

	peerAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}

	virtMAC := tcpip.GetRandMacAddr()

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	h, err := icx.NewHandler(icx.WithLocalAddr(localAddr),
		icx.WithVirtMAC(virtMAC),
		icx.WithSourcePortHashing(),
		icx.WithKeepAliveInterval(500*time.Millisecond),
	)
	require.NoError(t, err)

	wildcardPrefix := netip.MustParsePrefix("0.0.0.0/0")

	err = h.AddVirtualNetwork(0x12345, peerAddr, []icx.Route{{Src: wildcardPrefix, Dst: wildcardPrefix}})
	require.NoError(t, err)

	err = h.UpdateVirtualNetworkKeys(0x12345, 1, key, key, time.Now().Add(time.Hour))
	require.NoError(t, err)

	virtFrame := makeIPv4UDPEthernetFrame(virtMAC)

	phyFrame := make([]byte, 1500)
	frameLen, loopback := h.VirtToPhy(virtFrame, phyFrame)
	require.NotZero(t, frameLen)
	require.False(t, loopback)

	receivedFrame := make([]byte, 1500)
	decodedLen := h.PhyToVirt(phyFrame[:frameLen], receivedFrame)
	require.NotZero(t, decodedLen)

	receivedFrame = receivedFrame[:decodedLen]

	require.Equal(t, virtFrame[header.EthernetMinimumSize:], receivedFrame[header.EthernetMinimumSize:])

	eth := header.Ethernet(receivedFrame)

	require.Equal(t, virtMAC, eth.DestinationAddress())

	frameLen = h.ToPhy(phyFrame)
	require.NotZero(t, frameLen)

	require.NoError(t, h.RemoveVirtualNetwork(0x12345))

	frameLen, loopback = h.VirtToPhy(virtFrame, phyFrame)
	require.Zero(t, frameLen)
	require.False(t, loopback)

	frameLen = h.ToPhy(phyFrame)
	require.Zero(t, frameLen)
}

func TestHandler_Layer3(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	localAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}

	peerAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	// Create handler with layer3 mode enabled
	h, err := icx.NewHandler(icx.WithLocalAddr(localAddr),
		icx.WithLayer3VirtFrames(),
		icx.WithSourcePortHashing())
	require.NoError(t, err)

	privatePrefix := netip.MustParsePrefix("192.168.1.0/24")
	err = h.AddVirtualNetwork(0x12345, peerAddr, []icx.Route{{Src: privatePrefix, Dst: privatePrefix}})
	require.NoError(t, err)

	err = h.UpdateVirtualNetworkKeys(0x12345, 1, key, key, time.Now().Add(time.Hour))
	require.NoError(t, err)

	ipPacket := makeIPv4UDPPacket()

	phyFrame := make([]byte, 1500)
	frameLen, loopback := h.VirtToPhy(ipPacket, phyFrame)
	require.NotZero(t, frameLen)
	require.False(t, loopback)

	decoded := make([]byte, 1500)
	decodedLen := h.PhyToVirt(phyFrame[:frameLen], decoded)
	require.NotZero(t, decodedLen)

	require.Equal(t, ipPacket, decoded[:decodedLen])

	require.NoError(t, h.RemoveVirtualNetwork(0x12345))
}

func TestHandler_Layer3_IPv6(t *testing.T) {
	localAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}
	peerAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	h, err := icx.NewHandler(
		icx.WithLocalAddr(localAddr),
		icx.WithLayer3VirtFrames(),
	)
	require.NoError(t, err)

	// Prefix contains src 2001:db8::1
	privatePrefix := netip.MustParsePrefix("2001:db8::/64")
	require.NoError(t, h.AddVirtualNetwork(0x45678, peerAddr, []icx.Route{{Src: privatePrefix, Dst: privatePrefix}}))
	require.NoError(t, h.UpdateVirtualNetworkKeys(0x45678, 1, key, key, time.Now().Add(time.Hour)))

	ip6 := makeIPv6UDPPacket()
	phy := make([]byte, 1500)

	n, loop := h.VirtToPhy(ip6, phy)
	require.NotZero(t, n)
	require.False(t, loop)

	out := make([]byte, 1500)
	m := h.PhyToVirt(phy[:n], out)
	require.Equal(t, len(ip6), m)
	require.Equal(t, ip6, out[:m])
}

func TestUpdateVirtualNetworkRoutes(t *testing.T) {
	localAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}
	peerAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	h, err := icx.NewHandler(
		icx.WithLocalAddr(localAddr),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)

	// Start with a prefix that contains 192.168.1.2 (dst of our inner packet)
	privatePrefix := netip.MustParsePrefix("192.168.1.0/24")
	err = h.AddVirtualNetwork(0x23456, peerAddr, []icx.Route{{Src: privatePrefix, Dst: privatePrefix}})
	require.NoError(t, err)
	require.NoError(t, h.UpdateVirtualNetworkKeys(0x23456, 1, key, key, time.Now().Add(time.Hour)))

	virt := makeIPv4UDPEthernetFrame(tcpip.GetRandMacAddr())
	phy := make([]byte, 1500)

	// Should select this virtual network (address mapping exists).
	n, loop := h.VirtToPhy(virt, phy)
	require.NotZero(t, n)
	require.False(t, loop)

	// Now change allowed addresses to *not* include 192.168.1.2.
	privatePrefix = netip.MustParsePrefix("10.0.0.0/8")
	err = h.UpdateVirtualNetworkRoutes(0x23456, []icx.Route{{Src: privatePrefix, Dst: privatePrefix}})
	require.NoError(t, err)

	// Mapping removed -> VirtToPhy should drop as unknown tunnel destination address.
	n, loop = h.VirtToPhy(virt, phy)
	require.Zero(t, n)
	require.False(t, loop)

	// Add back a prefix which matches the destination again.
	privatePrefix = netip.MustParsePrefix("192.168.1.0/24")
	err = h.UpdateVirtualNetworkRoutes(0x23456, []icx.Route{{Src: privatePrefix, Dst: privatePrefix}})
	require.NoError(t, err)

	n, loop = h.VirtToPhy(virt, phy)
	require.NotZero(t, n)
	require.False(t, loop)
}

func TestKeyRotation(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}

	local := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}
	peer := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}

	var k1, k2, k3, k4 [16]byte
	copy(k1[:], []byte("aaaaaaaaaaaaaaaa"))
	copy(k2[:], []byte("bbbbbbbbbbbbbbbb"))
	copy(k3[:], []byte("cccccccccccccccc"))
	copy(k4[:], []byte("dddddddddddddddd"))

	h, err := icx.NewHandler(
		icx.WithLocalAddr(local),
		icx.WithLayer3VirtFrames(),
		icx.WithClock(clk),
	)
	require.NoError(t, err)

	const vni = 0x4242
	privatePrefix := netip.MustParsePrefix("192.168.1.0/24")
	require.NoError(t, h.AddVirtualNetwork(vni, peer, []icx.Route{{Src: privatePrefix, Dst: privatePrefix}}))

	// Epoch 1
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 1, k1, k1, clk.Now().Add(time.Hour)))

	ip := makeIPv4UDPPacket()
	phy := make([]byte, 2000)
	out := make([]byte, 2000)

	// Create TWO distinct epoch-1 ciphertexts (different TX counters), but do not decode them yet.
	n, loop := h.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	epoch1A := append([]byte(nil), phy[:n]...)

	n, loop = h.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	epoch1B := append([]byte(nil), phy[:n]...)

	// Rotate to epoch 2; epoch 1 gets grace
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 2, k2, k2, clk.Now().Add(time.Hour)))

	// Within grace: one of the saved epoch-1 frames must decrypt.
	m := h.PhyToVirt(epoch1A, out)
	require.Equal(t, len(ip), m)
	require.Equal(t, ip, out[:m])

	// After grace: the *other* (previously unseen) epoch-1 frame must now be rejected.
	clk.Advance(31 * time.Second)
	m = h.PhyToVirt(epoch1B, out[:cap(out)])
	require.Zero(t, m)

	// Produce a single epoch-2 ciphertext and save it for later.
	n, loop = h.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	epoch2A := append([]byte(nil), phy[:n]...)

	// Rotate to epoch 3 (starts grace for epoch 2)
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 3, k3, k3, clk.Now().Add(time.Hour)))

	// Let epoch-2 grace expire.
	clk.Advance(31 * time.Second)

	// Rotate to epoch 4; expired RX keys should be swept here
	require.NoError(t, h.UpdateVirtualNetworkKeys(vni, 4, k4, k4, clk.Now().Add(time.Hour)))

	// The saved epoch-2 frame should now be rejected (no matching key after cleanup).
	m = h.PhyToVirt(epoch2A, out[:cap(out)])
	require.Zero(t, m)

	// Sanity: current epoch (4) packets still round-trip.
	n, loop = h.VirtToPhy(ip, phy)
	require.NotZero(t, n)
	require.False(t, loop)
	m = h.PhyToVirt(phy[:n], out[:cap(out)])
	require.Equal(t, len(ip), m)
	require.Equal(t, ip, out[:m])
}

func TestARPRequest_Loopback(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	localAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}
	virtMAC := tcpip.GetRandMacAddr()

	h, err := icx.NewHandler(
		icx.WithLocalAddr(localAddr),
		icx.WithVirtMAC(virtMAC), // L2 mode -> virtMAC required
	)
	require.NoError(t, err)

	// Build a minimal ARP request (who-has 192.168.1.2 tell 192.168.1.1).
	arpReq := makeARPEthernetRequestFrame(
		tcpip.GetRandMacAddr(),
		net.IPv4(192, 168, 1, 1),
		net.IPv4(192, 168, 1, 2),
	)

	phy := make([]byte, 2000)

	// ARP should be answered locally with an immediate ARP reply (loopback).
	n, loop := h.VirtToPhy(arpReq, phy)
	require.NotZero(t, n)
	require.True(t, loop)

	// Validate ARP reply.
	eth := header.Ethernet(phy[:n])
	require.Equal(t, header.ARPProtocolNumber, eth.Type())

	arp := phy[header.EthernetMinimumSize:n]
	require.GreaterOrEqual(t, len(arp), 28)

	// Opcode (bytes 6:8) == 2 for reply.
	op := binary.BigEndian.Uint16(arp[6:8])
	require.Equal(t, uint16(2), op, "expected ARP reply opcode")

	// Sender/target protocol addresses are swapped.
	spa := net.IP(arp[14:18])
	tpa := net.IP(arp[24:28])
	require.Equal(t, net.IPv4(192, 168, 1, 2).To4(), spa.To4())
	require.Equal(t, net.IPv4(192, 168, 1, 1).To4(), tpa.To4())
}

func TestNeighborSolicitation_Loopback(t *testing.T) {
	localAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}
	peerAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}
	virtMAC := tcpip.GetRandMacAddr()

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	h, err := icx.NewHandler(
		icx.WithLocalAddr(localAddr),
		icx.WithVirtMAC(virtMAC),
	)
	require.NoError(t, err)

	privatePrefix := netip.MustParsePrefix("2001:db8::/64")
	require.NoError(t, h.AddVirtualNetwork(0x56789, peerAddr, []icx.Route{{Src: privatePrefix, Dst: privatePrefix}}))
	require.NoError(t, h.UpdateVirtualNetworkKeys(0x56789, 1, key, key, time.Now().Add(time.Hour)))

	nsFrame := makeIPv6NeighborSolicitationEthernetFrame()
	phy := make([]byte, 2000)

	// Should be handled locally with an immediate NA reply (loopback).
	n, loop := h.VirtToPhy(nsFrame, phy)
	require.NotZero(t, n)
	require.True(t, loop)
}

func TestGetAndListVirtualNetworks(t *testing.T) {
	localAddr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}
	peerA := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}
	peerB := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 3).To4()),
		Port: 4322,
	}

	h, err := icx.NewHandler(
		icx.WithLocalAddr(localAddr),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()),
	)
	require.NoError(t, err)

	prefixA := netip.MustParsePrefix("192.0.2.0/24")
	prefixB := netip.MustParsePrefix("203.0.113.0/24")
	require.NoError(t, h.AddVirtualNetwork(10, peerA, []icx.Route{{Src: prefixA, Dst: prefixA}}))
	require.NoError(t, h.AddVirtualNetwork(5, peerB, []icx.Route{{Src: prefixB, Dst: prefixB}}))

	// GetVirtualNetwork
	v, ok := h.GetVirtualNetwork(10)
	require.True(t, ok)
	require.Equal(t, uint(10), v.ID)

	_, ok = h.GetVirtualNetwork(999)
	require.False(t, ok)

	// ListVirtualNetworks should be sorted by VNI.
	list := h.ListVirtualNetworks()
	require.Len(t, list, 2)
	require.Equal(t, uint(5), list[0].ID)
	require.Equal(t, uint(10), list[1].ID)
}

func BenchmarkHandler(b *testing.B) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	localAddr := mustNewFullAddress("10.0.0.1:6081")
	remoteAddr := mustNewFullAddress("10.0.0.2:6081")

	h, err := icx.NewHandler(icx.WithLocalAddr(localAddr),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()))
	require.NoError(b, err)

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	const vni = 0x12345

	privatePrefix := netip.MustParsePrefix("192.168.1.0/24")
	err = h.AddVirtualNetwork(vni, remoteAddr, []icx.Route{{Src: privatePrefix, Dst: privatePrefix}})
	require.NoError(b, err)

	err = h.UpdateVirtualNetworkKeys(0x12345, 1, key, key, time.Now().Add(time.Hour))
	require.NoError(b, err)

	virtMAC := tcpip.GetRandMacAddr()
	virtFrame := makeIPv4UDPEthernetFrame(virtMAC)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		phyFrame := make([]byte, 1500)
		decodedFrame := make([]byte, 1400)

		for pb.Next() {
			n, _ := h.VirtToPhy(virtFrame, phyFrame)
			require.NotZero(b, n, "Failed to encode frame")

			n = h.PhyToVirt(phyFrame, decodedFrame)
			require.NotZero(b, n, "Failed to decode frame")
		}
	})
}

func makeIPv4UDPEthernetFrame(virtMAC tcpip.LinkAddress) []byte {
	ipPacket := makeIPv4UDPPacket()

	frame := make([]byte, header.EthernetMinimumSize+len(ipPacket))
	copy(frame[header.EthernetMinimumSize:], ipPacket)

	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.GetRandMacAddr(),
		DstAddr: tcpip.GetRandMacAddr(),
		Type:    header.IPv4ProtocolNumber,
	})

	return frame
}

func makeIPv4UDPPacket() []byte {
	ipPacket := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)

	ip := header.IPv4(ipPacket)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(ipPacket)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 1).To4()),
		DstAddr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 2).To4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udp := header.UDP(ipPacket[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: 1234,
		DstPort: 5678,
		Length:  header.UDPMinimumSize,
	})

	return ipPacket
}

func makeIPv6UDPPacket() []byte {
	packet := make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize)
	ip6 := header.IPv6(packet)
	ip6.Encode(&header.IPv6Fields{
		PayloadLength:     header.UDPMinimumSize,
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16Slice(net.ParseIP("2001:db8::1").To16()),
		DstAddr:           tcpip.AddrFrom16Slice(net.ParseIP("2001:db8::2").To16()),
	})
	udp := header.UDP(packet[header.IPv6MinimumSize:])
	udp.Encode(&header.UDPFields{
		SrcPort: 1234,
		DstPort: 5678,
		Length:  header.UDPMinimumSize,
	})
	return packet
}

func makeARPEthernetRequestFrame(srcMAC tcpip.LinkAddress, srcIP, dstIP net.IP) []byte {
	// ARP payload layout (28 bytes total for Ethernet/IPv4):
	//  0-1:  HW type (1 = Ethernet)
	//  2-3:  Proto type (0x0800 = IPv4)
	//    4:  HW addr len (6)
	//    5:  Proto addr len (4)
	//  6-7:  Opcode (1 = request)
	//  8-13: Sender HW addr (6)
	// 14-17: Sender Proto addr (4)
	// 18-23: Target HW addr (6) -> zero for request
	// 24-27: Target Proto addr (4)

	arpPayload := make([]byte, 28)
	binary.BigEndian.PutUint16(arpPayload[0:2], 1)              // HW type: Ethernet
	binary.BigEndian.PutUint16(arpPayload[2:4], uint16(0x0800)) // Proto: IPv4
	arpPayload[4] = 6                                           // HW len
	arpPayload[5] = 4                                           // Proto len
	binary.BigEndian.PutUint16(arpPayload[6:8], 1)              // Opcode: request
	copy(arpPayload[8:14], []byte(srcMAC))                      // Sender MAC
	copy(arpPayload[14:18], srcIP.To4())                        // Sender IP
	// Target MAC (18:24) left zero for request
	copy(arpPayload[24:28], dstIP.To4()) // Target IP

	frame := make([]byte, header.EthernetMinimumSize+len(arpPayload))
	copy(frame[header.EthernetMinimumSize:], arpPayload)

	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: srcMAC,
		DstAddr: tcpip.GetRandMacAddr(), // arbitrary; not relevant for loopback decision
		Type:    header.ARPProtocolNumber,
	})
	return frame
}

func makeIPv6NeighborSolicitationEthernetFrame() []byte {
	// Minimal NS: IPv6 + ICMPv6 (type 135) + 16-byte target address.
	const nsPayloadLen = header.ICMPv6NeighborSolicitMinimumSize
	total := header.EthernetMinimumSize + header.IPv6MinimumSize + nsPayloadLen
	frame := make([]byte, total)

	ipPayload := frame[header.EthernetMinimumSize:]
	ip6 := header.IPv6(ipPayload)
	ip6.Encode(&header.IPv6Fields{
		PayloadLength:     nsPayloadLen,
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          255,
		SrcAddr:           tcpip.AddrFrom16Slice(net.ParseIP("2001:db8::1").To16()),
		DstAddr:           tcpip.AddrFrom16Slice(net.ParseIP("ff02::1:ff00:2").To16()), // solicited-node multicast (example)
	})
	icmp := ipPayload[header.IPv6MinimumSize:]
	icmp[0] = byte(header.ICMPv6NeighborSolicit) // type 135
	icmp[1] = 0                                  // code
	// checksum left 0; handler doesn't validate it for loopback decision
	// Target Address (16 bytes) starts at offset 8
	copy(icmp[8:24], net.ParseIP("2001:db8::2").To16())
	// zero out reserved (4 bytes) and leave options empty
	binary.BigEndian.PutUint32(icmp[4:8], 0)

	eth := header.Ethernet(frame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.GetRandMacAddr(),
		DstAddr: tcpip.GetRandMacAddr(),
		Type:    header.IPv6ProtocolNumber,
	})
	return frame
}

func mustNewFullAddress(addrPortStr string) *tcpip.FullAddress {
	addrPort := netip.MustParseAddrPort(addrPortStr)

	switch addrPort.Addr().BitLen() {
	case 32:
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4Slice(addrPort.Addr().AsSlice()),
			Port: addrPort.Port(),
		}
	case 128:
		return &tcpip.FullAddress{
			Addr: tcpip.AddrFrom16Slice(addrPort.Addr().AsSlice()),
			Port: addrPort.Port(),
		}
	default:
		panic("Unsupported IP address length")
	}
}

// fakeClock lets us control time for grace/expiry testing.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }
