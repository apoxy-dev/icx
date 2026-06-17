//go:build linux

package xsk

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Real-kernel integration tests for the AF_XDP setup path (NewUMEM/NewSocket,
// ring mmaps, shared-UMEM bind, Fill/Transmit/Complete). They require
// CAP_NET_ADMIN and a kernel with CONFIG_XDP_SOCKETS; run them in a privileged
// container via `dagger call test` — skipped otherwise.
//
// They exercise the syscall/mmap/bind wiring directly, on ARM64 under
// OrbStack/colima — the weak-memory arch the old slavc/xdp failed on. The RX
// (kernel-produces) path needs an XDP redirect program steering packets into the
// socket; that is covered by the forwarder integration test once ported. Here we
// validate the UMEM/shared-bind, the producer->kernel->completion path, and the
// shared frame pool across two sockets on two different netdevs.

func requireAFXDP(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("AF_XDP integration test requires root (CAP_NET_ADMIN)")
	}
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		t.Skipf("AF_XDP socket() unavailable on this kernel: %v", err)
	}
	_ = unix.Close(fd)
}

// makeVeth creates a veth pair, brings both ends up, and returns the ifindex of
// the named end plus automatic cleanup.
func makeVeth(t *testing.T, name, peer string) int {
	t.Helper()
	if l, err := netlink.LinkByName(name); err == nil {
		_ = netlink.LinkDel(l)
	}
	la := netlink.NewLinkAttrs()
	la.Name = name
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: peer}); err != nil {
		t.Fatalf("create veth %s/%s: %v", name, peer, err)
	}
	t.Cleanup(func() {
		if l, err := netlink.LinkByName(name); err == nil {
			_ = netlink.LinkDel(l)
		}
	})
	for _, n := range []string{name, peer} {
		l, err := netlink.LinkByName(n)
		if err != nil {
			t.Fatalf("LinkByName %s: %v", n, err)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatalf("LinkSetUp %s: %v", n, err)
		}
	}
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName %s: %v", name, err)
	}
	return l.Attrs().Index
}

func smallOpts() Options {
	return Options{
		NumFrames:              256,
		FrameSize:              2048,
		FillRingNumDescs:       64,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         64,
		TxRingNumDescs:         64,
	}
}

// TestAFXDP_NewSocketLifecycle validates NewUMEM+NewSocket+Close: the full
// register/mmap/shared-bind sequence and clean teardown (incl. the ring munmaps
// the old library leaked).
func TestAFXDP_NewSocketLifecycle(t *testing.T) {
	requireAFXDP(t)
	ifindex := makeVeth(t, "icxxsk0", "icxxsk0p")

	umem, err := NewUMEM(smallOpts())
	if err != nil {
		t.Fatalf("NewUMEM: %v", err)
	}
	s, err := NewSocket(umem, ifindex, 0, smallOpts())
	if err != nil {
		t.Fatalf("NewSocket: %v", err)
	}
	if got := umem.NumFreeFrames(); got != 256 {
		t.Fatalf("NumFreeFrames after create = %d, want 256", got)
	}
	if got := s.NumFreeTxSlots(); got != 64 {
		t.Fatalf("NumFreeTxSlots = %d, want 64", got)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("socket Close: %v", err)
	}
	if err := umem.Close(); err != nil {
		t.Fatalf("umem Close: %v", err)
	}
}

// TestAFXDP_TxCompletion is the end-to-end producer path: Alloc frames, write
// into them, Transmit (sendto kick), and confirm the kernel returns them on the
// COMPLETION ring. Proves the TX ring mmap, the shared bind, the store-RELEASE
// producer publish, and Complete reclaiming into the shared pool.
func TestAFXDP_TxCompletion(t *testing.T) {
	requireAFXDP(t)
	ifindex := makeVeth(t, "icxxsk1", "icxxsk1p")

	umem, err := NewUMEM(smallOpts())
	if err != nil {
		t.Fatalf("NewUMEM: %v", err)
	}
	t.Cleanup(func() { _ = umem.Close() })
	s, err := NewSocket(umem, ifindex, 0, smallOpts())
	if err != nil {
		t.Fatalf("NewSocket: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const nTx = 8
	descs := umem.Alloc(nil, nTx)
	if len(descs) != nTx {
		t.Fatalf("Alloc(%d) = %d frames", nTx, len(descs))
	}
	for i := range descs {
		descs[i].Len = 64
		f := umem.Frame(descs[i])
		for j := range f {
			f[j] = 0xff
		}
	}

	freeBefore := umem.NumFreeFrames()
	n, err := s.Transmit(descs)
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if n != nTx {
		t.Fatalf("Transmit queued %d of %d", n, nTx)
	}
	if got := umem.NumFreeFrames(); got != freeBefore {
		t.Fatalf("free frames changed before completion: %d -> %d", freeBefore, got)
	}

	deadline := time.Now().Add(3 * time.Second)
	reclaimed := 0
	for reclaimed < nTx && time.Now().Before(deadline) {
		c := s.Complete(nTx - reclaimed)
		reclaimed += c
		if c == 0 {
			pollFD(t, s.FD(), 200*time.Millisecond)
		}
	}
	if reclaimed != nTx {
		t.Fatalf("reclaimed %d of %d completions before timeout", reclaimed, nTx)
	}
	if got := umem.NumFreeFrames(); got != freeBefore+nTx {
		t.Fatalf("free frames after completion = %d, want %d", got, freeBefore+nTx)
	}
}

// TestAFXDP_FillRing validates the FILL producer path: hand frames to the kernel
// on the socket's FILL ring and confirm the shared pool shrinks by the queued
// count and the FILL ring reports them outstanding.
func TestAFXDP_FillRing(t *testing.T) {
	requireAFXDP(t)
	ifindex := makeVeth(t, "icxxsk2", "icxxsk2p")

	umem, err := NewUMEM(smallOpts())
	if err != nil {
		t.Fatalf("NewUMEM: %v", err)
	}
	t.Cleanup(func() { _ = umem.Close() })
	s, err := NewSocket(umem, ifindex, 0, smallOpts())
	if err != nil {
		t.Fatalf("NewSocket: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	freeBefore := umem.NumFreeFrames()
	const nFill = 32
	got := s.Fill(nFill)
	if got != nFill {
		t.Fatalf("Fill(%d) = %d", nFill, got)
	}
	if free := umem.NumFreeFrames(); free != freeBefore-nFill {
		t.Fatalf("free frames after Fill = %d, want %d", free, freeBefore-nFill)
	}
	if slots := s.NumFreeFillSlots(); slots != smallOpts().FillRingNumDescs-nFill {
		t.Fatalf("free FILL slots after Fill = %d, want %d", slots, smallOpts().FillRingNumDescs-nFill)
	}
}

// TestAFXDP_SharedUMEMCrossDev is the zero-copy primitive: ONE shared UMEM
// backing TWO sockets on TWO different netdevs. A frame allocated from the
// shared pool is transmitted from socket B (the other device) and reclaimed via
// B's COMPLETION ring back into the SAME pool — i.e. a frame can move between
// sockets with no copy and the single free-frame stack stays consistent. This
// is exactly the cross-device XDP_SHARED_UMEM bind the forwarder needs.
func TestAFXDP_SharedUMEMCrossDev(t *testing.T) {
	requireAFXDP(t)
	ifA := makeVeth(t, "icxsa", "icxsap")
	ifB := makeVeth(t, "icxsb", "icxsbp")

	umem, err := NewUMEM(smallOpts())
	if err != nil {
		t.Fatalf("NewUMEM: %v", err)
	}
	t.Cleanup(func() { _ = umem.Close() })

	sa, err := NewSocket(umem, ifA, 0, smallOpts())
	if err != nil {
		t.Fatalf("NewSocket A: %v", err)
	}
	t.Cleanup(func() { _ = sa.Close() })
	sb, err := NewSocket(umem, ifB, 0, smallOpts())
	if err != nil {
		t.Fatalf("NewSocket B (shared UMEM, different dev): %v", err)
	}
	t.Cleanup(func() { _ = sb.Close() })

	if got := umem.NumFreeFrames(); got != 256 {
		t.Fatalf("shared pool free = %d, want 256 (one pool for both sockets)", got)
	}

	// Allocate from the shared pool, transmit on B, reclaim on B.
	const nTx = 8
	descs := umem.Alloc(nil, nTx)
	if len(descs) != nTx {
		t.Fatalf("Alloc = %d", len(descs))
	}
	for i := range descs {
		descs[i].Len = 64
		f := umem.Frame(descs[i])
		for j := range f {
			f[j] = 0xab
		}
	}
	freeBefore := umem.NumFreeFrames() // 256 - 8
	n, err := sb.Transmit(descs)
	if err != nil || n != nTx {
		t.Fatalf("B.Transmit = (%d,%v), want (%d,nil)", n, err, nTx)
	}

	deadline := time.Now().Add(3 * time.Second)
	reclaimed := 0
	for reclaimed < nTx && time.Now().Before(deadline) {
		c := sb.Complete(nTx - reclaimed)
		reclaimed += c
		if c == 0 {
			pollFD(t, sb.FD(), 200*time.Millisecond)
		}
	}
	if reclaimed != nTx {
		t.Fatalf("B reclaimed %d of %d", reclaimed, nTx)
	}
	if got := umem.NumFreeFrames(); got != freeBefore+nTx {
		t.Fatalf("shared pool after B completion = %d, want %d", got, freeBefore+nTx)
	}
	// Socket A can now allocate those same frames back from the shared pool.
	if got := umem.NumFreeFrames(); got != 256 {
		t.Fatalf("shared pool fully restored = %d, want 256", got)
	}
}

// TestAFXDP_TxDrainBeyondBatch exercises the copy-mode TX drain (APO-801) and
// proves Socket.Kick keeps the ring moving past the kernel's per-sendto batch
// limit. In copy/generic mode the kernel pulls at most TX_BATCH_SIZE — 32 —
// descriptors off the TX ring per sendto and never pulls on its own, so the
// single kick inside Transmit cannot drain a queue larger than 32: the tail stays
// in the ring, its frames never reach the COMPLETION ring, and once the producer
// goes idle the pool bleeds out and the datapath wedges (measured on virtio:
// transmitted=2304 completed=288 — exactly 9 kicks x 32 — then frozen). The fix
// is to keep kicking (Socket.Kick) until the ring drains. The existing
// TxCompletion test sends only 8 frames — under the batch limit — so it never
// exercised this; this one sends well over it.
//
// IMPORTANT — environment: the stall manifests only with ASYNCHRONOUS TX
// completion (real NIC / virtio-net, where the skb is freed later by a TX
// IRQ/NAPI). On veth the peer consumes and frees the skb synchronously inside the
// sendto, so a single kick drains the whole ring and the cap never bites — this
// test then hits the skip below. CI runs on veth, so it self-skips there and is a
// live guard only where the cap is observable; the virtio reproduction is the
// real proof (cmd/txblast -drain=false vs -drain=true).
func TestAFXDP_TxDrainBeyondBatch(t *testing.T) {
	requireAFXDP(t)
	ifindex := makeVeth(t, "icxdrain", "icxdrainp")

	// veth has no zero-copy AF_XDP driver, so the socket binds in generic/copy
	// mode without forcing it (forcing XDP_COPY on veth is EINVAL — see bindFlags).
	opts := Options{
		NumFrames:              256,
		FrameSize:              2048,
		FillRingNumDescs:       64,
		CompletionRingNumDescs: 128,
		RxRingNumDescs:         64,
		TxRingNumDescs:         128,
	}
	umem, err := NewUMEM(opts)
	if err != nil {
		t.Fatalf("NewUMEM: %v", err)
	}
	t.Cleanup(func() { _ = umem.Close() })
	s, err := NewSocket(umem, ifindex, 0, opts)
	if err != nil {
		t.Fatalf("NewSocket: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	const nTx = 100 // > TX_BATCH_SIZE (32): one kick cannot drain this
	descs := umem.Alloc(nil, nTx)
	if len(descs) != nTx {
		t.Fatalf("Alloc(%d) = %d", nTx, len(descs))
	}
	for i := range descs {
		descs[i].Len = 64
		f := umem.Frame(descs[i])
		for j := range f {
			f[j] = 0xff
		}
	}

	freeBefore := umem.NumFreeFrames() // 256 - 100
	n, err := s.Transmit(descs)        // queues all 100, kicks exactly once
	if err != nil {
		t.Fatalf("Transmit: %v", err)
	}
	if n != nTx {
		t.Fatalf("Transmit queued %d of %d (TX ring too small?)", n, nTx)
	}

	// Reclaim completions for a short window WITHOUT re-kicking. A single kick
	// drains at most TX_BATCH_SIZE, so completions must plateau below nTx with the
	// rest still queued on the TX ring — the stall signature.
	completed := 0
	deadline := time.Now().Add(500 * time.Millisecond)
	for completed < nTx && time.Now().Before(deadline) {
		c := s.Complete(nTx)
		completed += c
		if c == 0 {
			pollFD(t, s.FD(), 50*time.Millisecond)
		}
	}
	if completed >= nTx {
		t.Skipf("kernel drained all %d frames on a single kick (no TX_BATCH_SIZE cap here); "+
			"nothing to regress in this environment", nTx)
	}
	t.Logf("stall reproduced: after one kick %d/%d completed, %d still queued on TX ring",
		completed, nTx, s.NumTransmitted())

	// The fix: keep kicking until the ring drains, reclaiming completions so the
	// kernel's sndbuf/completion ring never wedges. Bounded by a deadline so a
	// stuck kernel fails the test rather than hanging it.
	drainDeadline := time.Now().Add(3 * time.Second)
	for s.NumTransmitted() > 0 && time.Now().Before(drainDeadline) {
		before := s.NumTransmitted()
		if err := s.Kick(); err != nil {
			t.Fatalf("Kick: %v", err)
		}
		completed += s.Complete(nTx)
		if s.NumTransmitted() >= before {
			// No TX-ring progress this round (transient sndbuf/CQ back-pressure);
			// let pending completions free space before kicking again.
			pollFD(t, s.FD(), 50*time.Millisecond)
		}
	}
	if rem := s.NumTransmitted(); rem != 0 {
		t.Fatalf("TX ring did not drain: %d descriptors still queued after Kick loop", rem)
	}

	// Reclaim the final completions; every frame must come back to the pool.
	deadline = time.Now().Add(3 * time.Second)
	for completed < nTx && time.Now().Before(deadline) {
		c := s.Complete(nTx)
		completed += c
		if c == 0 {
			pollFD(t, s.FD(), 100*time.Millisecond)
		}
	}
	if completed != nTx {
		t.Fatalf("after Kick drain: %d/%d completed — drain did not unstall TX", completed, nTx)
	}
	if got := umem.NumFreeFrames(); got != freeBefore+nTx {
		t.Fatalf("pool after full drain = %d, want %d", got, freeBefore+nTx)
	}
}

func pollFD(t *testing.T, fd int, d time.Duration) {
	t.Helper()
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT | unix.POLLIN}}
	for {
		_, err := unix.Poll(pfd, int(d.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return
	}
}
