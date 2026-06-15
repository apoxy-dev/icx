package netstack

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// fakeEngine is an identity EngineXfrm: encap/decap are byte copies with no
// crypto, so a frame written by netstack comes out of the underlay verbatim and
// vice versa. This isolates the pump's batch/pool/lifecycle logic from the real
// engine, which is exercised elsewhere (cp_wire).
type fakeEngine struct{}

func (fakeEngine) VirtToPhy(virt, phy []byte) (int, bool) { return copy(phy, virt), false }
func (fakeEngine) PhyToVirt(phy, virt []byte) int         { return copy(virt, phy) }
func (fakeEngine) ToPhy(phy []byte) int                   { return 0 }

// fakeUnderlay is an in-memory underlay: inbound frames are fed via in, outbound
// frames are captured on out. ReadFrame unblocks with net.ErrClosed on Close.
type fakeUnderlay struct {
	in        chan []byte
	out       chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeUnderlay() *fakeUnderlay {
	return &fakeUnderlay{
		in:     make(chan []byte, 16),
		out:    make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func (u *fakeUnderlay) ReadFrame(buf []byte) (int, error) {
	select {
	case f := <-u.in:
		return copy(buf, f), nil
	case <-u.closed:
		return 0, net.ErrClosed
	}
}

func (u *fakeUnderlay) WriteFrames(frames [][]byte) (int, error) {
	for _, f := range frames {
		cp := make([]byte, len(f))
		copy(cp, f)
		select {
		case u.out <- cp:
		case <-u.closed:
			return 0, net.ErrClosed
		}
	}
	return len(frames), nil
}

func (u *fakeUnderlay) Close() { u.closeOnce.Do(func() { close(u.closed) }) }

const testMTU = 1500

// newTestStack builds a minimal L3 netstack with the channel endpoint as its
// only NIC, addressed at addr.
func newTestStack(t *testing.T, ep *channel.Endpoint, addr tcpip.Address) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	const nicID = 1
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix:  addr.WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	if err := s.SetSpoofing(nicID, true); err != nil {
		t.Fatalf("SetSpoofing: %v", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		t.Fatalf("SetPromiscuousMode: %v", err)
	}
	return s
}

func startDatapath(t *testing.T, eng vtepEngine, ep *channel.Endpoint, u *fakeUnderlay) func() {
	t.Helper()
	dp, err := New(Config{Engine: eng, Endpoint: ep, Underlay: u, FlushInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := dp.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	return func() {
		// Cancel stops the outbound pump; closing the underlay unblocks the
		// inbound read. A real consumer (apoxy-cli's router) does both in its
		// Close, so Run returns only once the transport is torn down.
		cancel()
		u.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("datapath Run did not return after shutdown")
		}
	}
}

// vtepEngine is an alias so the helper signature reads clearly; New takes the
// real vtep.EngineXfrm.
type vtepEngine = interface {
	VirtToPhy(virt, phy []byte) (int, bool)
	PhyToVirt(phy, virt []byte) int
	ToPhy(phy []byte) int
}

// TestDatapath_Outbound drives a UDP packet out of the netstack and asserts the
// engine-encap'd frame lands on the underlay with its payload intact.
func TestDatapath_Outbound(t *testing.T) {
	ep := channel.New(16, testMTU, "")
	local := tcpip.AddrFromSlice([]byte{10, 0, 0, 1})
	s := newTestStack(t, ep, local)
	defer s.Close()

	u := newFakeUnderlay()
	defer u.Close()
	stop := startDatapath(t, fakeEngine{}, ep, u)
	defer stop()

	// Dial a UDP socket on the stack and send a packet to an off-host address;
	// the stack emits it on the channel endpoint, which the outbound pump reads.
	conn, err := gonet.DialUDP(s, &tcpip.FullAddress{
		NIC: 1, Addr: local, Port: 12345,
	}, &tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice([]byte{10, 0, 0, 9}), Port: 9999,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer conn.Close()

	payload := []byte("world")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case frame := <-u.out:
		ip := header.IPv4(frame)
		if !ip.IsValid(len(frame)) {
			t.Fatalf("captured frame is not a valid IPv4 packet (%d bytes)", len(frame))
		}
		if got := ip.TransportProtocol(); got != udp.ProtocolNumber {
			t.Fatalf("transport proto = %d, want UDP", got)
		}
		udpHdr := header.UDP(ip.Payload())
		if string(udpHdr.Payload()) != string(payload) {
			t.Fatalf("payload = %q, want %q", udpHdr.Payload(), payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for outbound frame on underlay")
	}
}

// TestDatapath_Inbound feeds a crafted IPv4/UDP packet through the underlay and
// asserts it is decap'd and delivered to a netstack UDP listener.
func TestDatapath_Inbound(t *testing.T) {
	ep := channel.New(16, testMTU, "")
	local := tcpip.AddrFromSlice([]byte{10, 0, 0, 1})
	s := newTestStack(t, ep, local)
	defer s.Close()

	u := newFakeUnderlay()
	defer u.Close()
	stop := startDatapath(t, fakeEngine{}, ep, u)
	defer stop()

	// Listen on the stack for the inbound UDP packet.
	rconn, err := gonet.DialUDP(s, &tcpip.FullAddress{
		NIC: 1, Addr: local, Port: 5000,
	}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("listen DialUDP: %v", err)
	}
	defer rconn.Close()

	src := tcpip.AddrFromSlice([]byte{10, 0, 0, 2})
	frame := buildUDPv4(t, src, local, 4444, 5000, []byte("hello"))

	if err := rconn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	u.in <- frame

	got := make([]byte, 64)
	n, err := rconn.Read(got)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got[:n]) != "hello" {
		t.Fatalf("payload = %q, want %q", got[:n], "hello")
	}
}

// TestDatapath_CloseThenNotifyNoPanic is a regression test: the stack may invoke
// WriteNotify from its own goroutines concurrently with (or after) shutdown.
// Close must not make that a send-on-closed-channel panic.
func TestDatapath_CloseThenNotifyNoPanic(t *testing.T) {
	ep := channel.New(16, testMTU, "")
	local := tcpip.AddrFromSlice([]byte{10, 0, 0, 1})
	s := newTestStack(t, ep, local)
	defer s.Close()

	u := newFakeUnderlay()
	defer u.Close()

	dp, err := New(Config{Engine: fakeEngine{}, Endpoint: ep, Underlay: u, FlushInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Close detaches the notify handle and stops the pump. A WriteNotify racing
	// in afterwards must not panic — wake is never closed.
	if err := dp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i := 0; i < 1000; i++ {
		dp.WriteNotify() // would panic pre-fix (send on closed channel)
	}
}

// TestDatapath_RunTwiceRejected asserts a second Run is refused rather than
// starting a duplicate inbound pump racing on the same endpoint/underlay.
func TestDatapath_RunTwiceRejected(t *testing.T) {
	ep := channel.New(16, testMTU, "")
	local := tcpip.AddrFromSlice([]byte{10, 0, 0, 1})
	s := newTestStack(t, ep, local)
	defer s.Close()

	u := newFakeUnderlay()
	defer u.Close()

	dp, err := New(Config{Engine: fakeEngine{}, Endpoint: ep, Underlay: u, FlushInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()

	// Tear the first Run down cleanly (cancel stops outbound, Close unblocks
	// inbound), then confirm it returned before attempting a second Run.
	cancel()
	u.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("first Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Run did not return")
	}

	if err := dp.Run(context.Background()); err == nil {
		t.Fatal("second Run returned nil, want already-called error")
	}
}

// buildUDPv4 hand-builds an IPv4/UDP packet with valid checksums.
func buildUDPv4(t *testing.T, src, dst tcpip.Address, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	const ipHdrLen = header.IPv4MinimumSize
	udpLen := header.UDPMinimumSize + len(payload)
	total := ipHdrLen + udpLen
	buf := make([]byte, total)

	ip := header.IPv4(buf[:ipHdrLen])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         64,
		Protocol:    uint8(udp.ProtocolNumber),
		SrcAddr:     src,
		DstAddr:     dst,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udpHdr := header.UDP(buf[ipHdrLen:])
	udpHdr.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(udpLen),
	})
	copy(buf[ipHdrLen+header.UDPMinimumSize:], payload)
	xsum := header.PseudoHeaderChecksum(udp.ProtocolNumber, src, dst, uint16(udpLen))
	xsum = checksum.Checksum(payload, xsum)
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))

	return buf
}
