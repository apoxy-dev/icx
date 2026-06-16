package icx

// Benchmarks that empirically measure whether taking sync.RWMutex.RLock per
// packet on the route-lookup path is a multi-core scalability bottleneck.
//
// BenchmarkRouteLookupRLockParallel exercises the real per-packet path:
// networksByAddressMu.RLock(); two trie Finds; RUnlock (via RouteLookupForTest,
// the export_test.go seam used by VirtToPhy). Under b.RunParallel, RWMutex.RLock
// increments/decrements a shared readerCount atomic on every call; that cache
// line bounces between cores, so ns/op should RISE as -cpu grows even though
// readers never block each other.
//
// BenchmarkRouteLookupAtomicParallel is the CONTROL: it does the identical two
// trie Finds behind an atomic.Pointer snapshot load (a lock-free read), so it
// isolates the RWMutex cost from the raw trie-find cost. It should stay roughly
// flat (or even improve) as -cpu grows.

import (
	"fmt"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/phemmer/go-iptrie"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// numBenchNetworks is the number of distinct virtual networks (and distinct
// routes) populated into the routing trie. ~256 spreads lookups across varied
// trie nodes so no single hot key dominates.
const numBenchNetworks = 256

// benchSink is a process-global accumulator the parallel loops publish into so
// the compiler cannot eliminate the lookup work as dead code.
var benchSink atomic.Uint64

// benchRoute returns the (src, dst) prefix pair and a pair of addresses that
// resolve inside those prefixes for network index i. Dst is spread across
// 10.<a>.<b>.0/24 and Src across 192.168.<c>.0/24, giving numBenchNetworks
// distinct routes that all coexist in the trie.
func benchRoute(i int) (srcPfx, dstPfx netip.Prefix, srcAddr, dstAddr netip.Addr) {
	a := byte(i / 256)        // 0 for i<256
	b := byte(i % 256)        // 0..255
	c := byte(i % 256)        // 0..255 — distinct Src /24 per network
	dstPfx = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", a, b))
	srcPfx = netip.MustParsePrefix(fmt.Sprintf("192.168.%d.0/24", c))
	// Pick host .7 inside each /24 so the lookup lands on a real route.
	dstAddr = netip.AddrFrom4([4]byte{10, a, b, 7})
	srcAddr = netip.AddrFrom4([4]byte{192, 168, c, 7})
	return
}

// newBenchHandler builds a Handler populated with numBenchNetworks distinct
// routes via the production AddVirtualNetwork management API.
func newBenchHandler(tb testing.TB) *Handler {
	tb.Helper()
	h, err := NewHandler(
		WithLocalAddr(&tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: 6081}),
		WithLayer3VirtFrames(),
	)
	if err != nil {
		tb.Fatalf("NewHandler: %v", err)
	}
	for i := 0; i < numBenchNetworks; i++ {
		srcPfx, dstPfx, _, _ := benchRoute(i)
		remote := &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, byte(i % 256)}),
			Port: 6081,
		}
		if err := h.AddVirtualNetwork(uint(i+1), remote, []Route{{Src: srcPfx, Dst: dstPfx}}); err != nil {
			tb.Fatalf("AddVirtualNetwork(%d): %v", i+1, err)
		}
	}
	return h
}

// BenchmarkRouteLookupRLockParallel measures the real per-packet route lookup,
// which takes networksByAddressMu.RLock around two trie Finds. Run with
// -cpu=1,2,4,8(,16): rising ns/op is the signature of RWMutex.RLock cache-line
// contention on the shared readerCount atomic.
func BenchmarkRouteLookupRLockParallel(b *testing.B) {
	h := newBenchHandler(b)

	// Sanity: confirm a representative lookup resolves before timing.
	{
		_, _, srcAddr, dstAddr := benchRoute(0)
		if _, ok := h.RouteLookupForTest(srcAddr, dstAddr); !ok {
			b.Fatalf("setup lookup did not resolve")
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		// Per-goroutine counter so each iteration hits a different route
		// rather than one hot key.
		var n int
		var sink uint
		for pb.Next() {
			_, _, srcAddr, dstAddr := benchRoute(n % numBenchNetworks)
			vni, ok := h.RouteLookupForTest(srcAddr, dstAddr)
			if ok {
				sink += vni // consume the result to defeat dead-code elimination
			}
			n++
		}
		// Publish sink so the optimizer cannot drop the loop body.
		benchSink.Add(uint64(sink))
	})
}

// BenchmarkRouteLookupAtomicParallel is the CONTROL. It performs the identical
// two trie Finds (byDst.Find -> *dstEntry, then srcTrie.Find) behind an
// atomic.Pointer snapshot load with NO mutex. The snapshot is populated from the
// SAME tries the Handler built, so the per-lookup work is byte-for-byte the same
// as the RLock benchmark minus the lock. Under -cpu sweep it should stay roughly
// flat, isolating the raw trie-find cost from the RWMutex cost.
func BenchmarkRouteLookupAtomicParallel(b *testing.B) {
	h := newBenchHandler(b)

	// Build the snapshot from the handler's own data-path trie so the control
	// walks the identical structure. dstEntry (with its srcTrie field) is a
	// package-internal type, reused directly here.
	type snapshot struct {
		byDst *iptrie.Trie
	}
	var ptr atomic.Pointer[snapshot]
	ptr.Store(&snapshot{byDst: h.networksByAddress})

	// Sanity: confirm the lock-free path resolves the same way.
	{
		_, _, srcAddr, dstAddr := benchRoute(0)
		snap := ptr.Load()
		v := snap.byDst.Find(dstAddr)
		if v == nil {
			b.Fatalf("setup atomic dst lookup did not resolve")
		}
		if sv := v.(*dstEntry).srcTrie.Find(srcAddr); sv == nil {
			b.Fatalf("setup atomic src lookup did not resolve")
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var n int
		var sink uint
		for pb.Next() {
			_, _, srcAddr, dstAddr := benchRoute(n % numBenchNetworks)
			snap := ptr.Load()
			v := snap.byDst.Find(dstAddr)
			if v != nil {
				if sv := v.(*dstEntry).srcTrie.Find(srcAddr); sv != nil {
					sink += sv.(*VirtualNetwork).ID // consume to defeat DCE
				}
			}
			n++
		}
		benchSink.Add(uint64(sink))
	})
}
