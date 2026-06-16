package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// fakeDevice is an in-memory Device: inner packets to hand to Read are pushed on
// readCh; packets captured from Write land on written. Close unblocks a pending
// Read with net.ErrClosed.
type fakeDevice struct {
	readCh    chan []byte
	written   chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	batch     int
}

func newFakeDevice(batch int) *fakeDevice {
	if batch < 1 {
		batch = 1
	}
	return &fakeDevice{
		readCh:  make(chan []byte, 16),
		written: make(chan []byte, 16),
		closed:  make(chan struct{}),
		batch:   batch,
	}
}

func (f *fakeDevice) BatchSize() int { return f.batch }

func (f *fakeDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p := <-f.readCh:
		n := copy(bufs[0][offset:], p)
		sizes[0] = n
		return 1, nil
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

func (f *fakeDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := append([]byte(nil), b[offset:]...)
		select {
		case f.written <- pkt:
		case <-f.closed:
			return 0, net.ErrClosed
		}
	}
	return len(bufs), nil
}

func (f *fakeDevice) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

// fakeUnderlay is an in-memory Underlay carrying opaque phy frames: inbound
// frames are fed on in, outbound frames captured on out. ReadFrame unblocks with
// net.ErrClosed on Close.
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
		cp := append([]byte(nil), f...)
		select {
		case u.out <- cp:
		case <-u.closed:
			return 0, net.ErrClosed
		}
	}
	return len(frames), nil
}

func (u *fakeUnderlay) Close() error {
	u.closeOnce.Do(func() { close(u.closed) })
	return nil
}

// fakeEngine is an identity EngineXfrm used to isolate pump/lifecycle logic from
// crypto. If toPhyFrame is non-nil, ToPhy emits a copy of it (one per call),
// exercising the keep-alive pump.
type fakeEngine struct {
	toPhyFrame []byte
}

func (e *fakeEngine) VirtToPhy(virt, phy []byte) (int, bool) { return copy(phy, virt), false }
func (e *fakeEngine) PhyToVirt(phy, virt []byte) int         { return copy(virt, phy) }
func (e *fakeEngine) ToPhy(phy []byte) int {
	if e.toPhyFrame == nil {
		return 0
	}
	return copy(phy, e.toPhyFrame)
}

// startRun runs dp.Run in a goroutine and returns a teardown that closes the
// datapath and waits for Run to return.
func startRun(t *testing.T, dp *Datapath) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := dp.Run(ctx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	return func() {
		cancel()
		_ = dp.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("datapath Run did not return after shutdown")
		}
	}
}

func TestOutboundPlumbing(t *testing.T) {
	dev := newFakeDevice(1)
	ul := newFakeUnderlay()
	dp, err := New(Config{Engine: &fakeEngine{}, Device: dev, Underlay: ul})
	require.NoError(t, err)
	stop := startRun(t, dp)
	defer stop()

	pkt := []byte("inner-overlay-packet")
	dev.readCh <- append([]byte(nil), pkt...)

	select {
	case got := <-ul.out:
		require.Equal(t, pkt, got, "outbound: identity engine must surface the inner packet on the underlay")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: outbound packet never reached the underlay")
	}
}

func TestInboundPlumbing(t *testing.T) {
	dev := newFakeDevice(1)
	ul := newFakeUnderlay()
	dp, err := New(Config{Engine: &fakeEngine{}, Device: dev, Underlay: ul})
	require.NoError(t, err)
	stop := startRun(t, dp)
	defer stop()

	frame := []byte("encapd-underlay-frame")
	ul.in <- append([]byte(nil), frame...)

	select {
	case got := <-dev.written:
		require.Equal(t, frame, got, "inbound: identity engine must surface the underlay frame on the device")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: inbound frame never reached the device")
	}
}

func TestKeepalivePlumbing(t *testing.T) {
	ka := []byte("keep-alive-frame")
	dev := newFakeDevice(1)
	ul := newFakeUnderlay()
	dp, err := New(Config{
		Engine:        &fakeEngine{toPhyFrame: ka},
		Device:        dev,
		Underlay:      ul,
		FlushInterval: 5 * time.Millisecond,
	})
	require.NoError(t, err)
	stop := startRun(t, dp)
	defer stop()

	select {
	case got := <-ul.out:
		require.Equal(t, ka, got, "keep-alive: ToPhy frames must be flushed to the underlay")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: no keep-alive frame flushed")
	}
}

func TestCloseStopsRun(t *testing.T) {
	dev := newFakeDevice(1)
	ul := newFakeUnderlay()
	dp, err := New(Config{Engine: &fakeEngine{}, Device: dev, Underlay: ul})
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- dp.Run(context.Background()) }()

	// Let the pumps start, then Close and require a prompt clean return.
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, dp.Close())

	select {
	case err := <-done:
		require.NoError(t, err, "Run must return nil after Close")
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}

func TestRunTwiceErrors(t *testing.T) {
	dev := newFakeDevice(1)
	ul := newFakeUnderlay()
	dp, err := New(Config{Engine: &fakeEngine{}, Device: dev, Underlay: ul})
	require.NoError(t, err)
	stop := startRun(t, dp)
	defer stop()

	time.Sleep(20 * time.Millisecond)
	require.Error(t, dp.Run(context.Background()), "second Run must be rejected")
}

func TestRunAfterCloseErrors(t *testing.T) {
	dev := newFakeDevice(1)
	ul := newFakeUnderlay()
	dp, err := New(Config{Engine: &fakeEngine{}, Device: dev, Underlay: ul})
	require.NoError(t, err)
	require.NoError(t, dp.Close())
	require.Error(t, dp.Run(context.Background()), "Run after Close must be rejected per the contract")
}

func TestNewValidatesConfig(t *testing.T) {
	_, err := New(Config{Device: newFakeDevice(1), Underlay: newFakeUnderlay()})
	require.Error(t, err, "missing engine")
	_, err = New(Config{Engine: &fakeEngine{}, Underlay: newFakeUnderlay()})
	require.Error(t, err, "missing device")
	_, err = New(Config{Engine: &fakeEngine{}, Device: newFakeDevice(1)})
	require.Error(t, err, "missing underlay")
}

// --- Integration: two real *icx.Handler engines over a real loopback UDP
// underlay, spliced through fake TUN devices. Exercises the full datapath —
// cross-buffer encap/decap + AEAD + Geneve + the peel/synthesize UDP underlay —
// end to end, with no kernel TUN device. ---

func newPeerHandler(t *testing.T, localIP tcpip.Address, localPort uint16, remoteIP tcpip.Address, remotePort uint16, vni uint) *icx.Handler {
	t.Helper()
	h, err := icx.NewHandler(
		icx.WithLocalAddr(&tcpip.FullAddress{Addr: localIP, Port: localPort}),
		icx.WithLayer3VirtFrames(),
	)
	require.NoError(t, err)
	prefix := netip.MustParsePrefix("192.168.1.0/24")
	require.NoError(t, h.AddVirtualNetwork(vni,
		&tcpip.FullAddress{Addr: remoteIP, Port: remotePort},
		[]icx.Route{{Src: prefix, Dst: prefix}}))
	return h
}

func makeInnerIPv4UDP() []byte {
	b := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(b)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte{192, 168, 1, 1}),
		DstAddr:     tcpip.AddrFrom4([4]byte{192, 168, 1, 2}),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(b[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: 1234, DstPort: 5678, Length: header.UDPMinimumSize})
	return b
}

func makeSizedInnerIPv4(t *testing.T, total int) []byte {
	t.Helper()
	require.GreaterOrEqual(t, total, header.IPv4MinimumSize+header.UDPMinimumSize)
	b := make([]byte, total)
	ip := header.IPv4(b)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte{192, 168, 1, 1}),
		DstAddr:     tcpip.AddrFrom4([4]byte{192, 168, 1, 2}),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	u := header.UDP(b[header.IPv4MinimumSize:])
	u.Encode(&header.UDPFields{SrcPort: 1234, DstPort: 5678, Length: uint16(total - header.IPv4MinimumSize)})
	return b
}

// TestInboundOversizedDecapNoPanic is the regression for the inbound decap-buffer
// bound: a peer holding the SA key can encapsulate an inner packet larger than the
// receiver's MTU clamp, and PhyToVirt's AES-GCM Open does not bound its output to
// the destination buffer. An undersized inbound buffer would slice out of range
// (panic) on the decapsulated length. The frame is pre-built with a large encap
// buffer so the APO-667 *encap* bound does not drop it, then fed straight to the
// receiver datapath.
func TestInboundOversizedDecapNoPanic(t *testing.T) {
	const vni = uint(7)
	lo := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})
	hA := newPeerHandler(t, lo, 6081, lo, 6081, vni)
	hB := newPeerHandler(t, lo, 6081, lo, 6081, vni)

	const spiAB, spiBA = uint32(0x0A0A0A0A), uint32(0x0B0B0B0B)
	var keyAB, keyBA [16]byte
	for i := range keyAB {
		keyAB[i] = 0xAA
		keyBA[i] = 0xBB
	}
	exp := time.Now().Add(time.Hour)
	require.NoError(t, hA.UpdateVirtualNetworkSAs(vni, spiBA, spiAB, keyBA, keyAB, exp))
	require.NoError(t, hB.UpdateVirtualNetworkSAs(vni, spiAB, spiBA, keyAB, keyBA, exp))

	// 4000-byte inner packet: far above the 1280 clamp + the old inbound buffer.
	largeInner := makeSizedInnerIPv4(t, 4000)
	phy := make([]byte, maxFrameSize)
	m, loop := hA.VirtToPhy(largeInner, phy)
	require.False(t, loop)
	require.NotZero(t, m, "encap with a large buffer must not be dropped")

	devB := newFakeDevice(1)
	ulB := newFakeUnderlay()
	dpB, err := New(Config{Engine: hB, Device: devB, Underlay: ulB, FlushInterval: time.Hour})
	require.NoError(t, err)
	stop := startRun(t, dpB)
	defer stop()

	ulB.in <- append([]byte(nil), phy[:m]...)
	select {
	case got := <-devB.written:
		require.Equal(t, largeInner, got, "oversized inner packet must decapsulate intact, not panic")
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: oversized inner packet never decapsulated")
	}
}

func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	return c
}

func TestDatapathIntegrationRoundTrip(t *testing.T) {
	const vni = uint(7)

	connA := mustListenUDP(t)
	connB := mustListenUDP(t)
	portA := uint16(connA.LocalAddr().(*net.UDPAddr).Port)
	portB := uint16(connB.LocalAddr().(*net.UDPAddr).Port)
	lo := tcpip.AddrFrom4([4]byte{127, 0, 0, 1})

	hA := newPeerHandler(t, lo, portA, lo, portB, vni)
	hB := newPeerHandler(t, lo, portB, lo, portA, vni)

	// Directional SAs: A's TX SPI/key == B's RX SPI/key and vice versa. The keys
	// differ per direction (the production seam rejects equal rx/tx keys).
	const spiAB, spiBA = uint32(0x0A0A0A0A), uint32(0x0B0B0B0B)
	var keyAB, keyBA [16]byte
	for i := range keyAB {
		keyAB[i] = 0xAA
		keyBA[i] = 0xBB
	}
	exp := time.Now().Add(time.Hour)
	require.NoError(t, hA.UpdateVirtualNetworkSAs(vni, spiBA, spiAB, keyBA, keyAB, exp))
	require.NoError(t, hB.UpdateVirtualNetworkSAs(vni, spiAB, spiBA, keyAB, keyBA, exp))

	uuA, err := newUDPUnderlay(connA)
	require.NoError(t, err)
	uuB, err := newUDPUnderlay(connB)
	require.NoError(t, err)
	devA := newFakeDevice(1)
	devB := newFakeDevice(1)

	// Long flush interval: keep keep-alives out of the assertions.
	dpA, err := New(Config{Engine: hA, Device: devA, Underlay: uuA, FlushInterval: time.Hour})
	require.NoError(t, err)
	dpB, err := New(Config{Engine: hB, Device: devB, Underlay: uuB, FlushInterval: time.Hour})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = dpA.Run(ctx) }()
	go func() { defer wg.Done(); _ = dpB.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = dpA.Close()
		_ = dpB.Close()
		wg.Wait()
	})

	inner := makeInnerIPv4UDP()

	// A -> B
	devA.readCh <- append([]byte(nil), inner...)
	select {
	case got := <-devB.written:
		require.Equal(t, inner, got, "B must receive A's decapsulated inner packet")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: A->B inner packet never reached B")
	}

	// B -> A
	devB.readCh <- append([]byte(nil), inner...)
	select {
	case got := <-devA.written:
		require.Equal(t, inner, got, "A must receive B's decapsulated inner packet")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: B->A inner packet never reached A")
	}
}
