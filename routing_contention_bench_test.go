package icx

// Benchmarks that empirically measure the per-packet route-lookup cost as a
// multi-core scalability question, and lock in the P12/APO-675 fix.
//
// BenchmarkRouteLookupParallel exercises the REAL per-packet path: a single
// lock-free h.routes.Load() (the copy-on-write snapshot) then two trie Finds, via
// RouteLookupForTest — the export_test.go seam VirtToPhy/VirtToPhyInPlace share.
// Because the published table is immutable, readers take no lock, so ns/op should
// stay roughly flat as -cpu grows.
//
// BenchmarkRouteLookupRLockParallel is the CONTROL preserving the pre-fix shape:
// the identical two trie Finds wrapped in a sync.RWMutex.RLock/RUnlock. Under
// b.RunParallel, RWMutex.RLock increments/decrements a shared readerCount atomic
// on every call; that cache line bounces between cores, so ns/op should RISE as
// -cpu grows even though readers never block each other. Run both with
// -cpu=1,2,4,8,16: the gap between the rising control and the flat real path is
// the contention this fix removed.

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

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
	a := byte(i / 256) // 0 for i<256
	b := byte(i % 256) // 0..255
	c := byte(i % 256) // 0..255 — distinct Src /24 per network
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

// BenchmarkRouteLookupParallel measures the real per-packet route lookup after
// P12: a lock-free routes.Load() snapshot plus two trie Finds (via
// RouteLookupForTest). Run with -cpu=1,2,4,8(,16): ns/op should stay roughly flat
// because no per-packet lock is taken.
func BenchmarkRouteLookupParallel(b *testing.B) {
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
		// Per-goroutine counter so each iteration hits a different route rather
		// than one hot key.
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

// BenchmarkRouteLookupRLockParallel is the CONTROL. It performs the identical two
// trie Finds against the published snapshot, but wrapped in a shared
// sync.RWMutex.RLock — the pre-P12 shape. Under -cpu sweep it should RISE as the
// shared readerCount atomic bounces between cores, isolating the RWMutex cost from
// the raw trie-find cost the flat BenchmarkRouteLookupParallel measures.
func BenchmarkRouteLookupRLockParallel(b *testing.B) {
	h := newBenchHandler(b)
	// One shared snapshot + one shared RWMutex, exactly as the old per-packet path
	// loaded a single trie under a single networksByAddressMu.
	rtbl := h.routes.Load()
	var mu sync.RWMutex

	// Sanity: confirm the locked path resolves the same way.
	{
		_, _, srcAddr, dstAddr := benchRoute(0)
		mu.RLock()
		v := rtbl.byDst.Find(dstAddr)
		if v == nil {
			b.Fatalf("setup dst lookup did not resolve")
		}
		if sv := v.(*roDstEntry).srcTrie.Find(srcAddr); sv == nil {
			b.Fatalf("setup src lookup did not resolve")
		}
		mu.RUnlock()
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var n int
		var sink uint
		for pb.Next() {
			_, _, srcAddr, dstAddr := benchRoute(n % numBenchNetworks)
			mu.RLock()
			v := rtbl.byDst.Find(dstAddr)
			if v != nil {
				if sv := v.(*roDstEntry).srcTrie.Find(srcAddr); sv != nil {
					sink += sv.(*VirtualNetwork).ID // consume to defeat DCE
				}
			}
			mu.RUnlock()
			n++
		}
		benchSink.Add(uint64(sink))
	})
}
