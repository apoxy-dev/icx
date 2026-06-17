package icx

// Measures the multi-core contention on the per-VNI Statistics block (P8/APO-672).
// The forwarder runs one processFrames goroutine per NIC queue and each bumps the
// SAME vnet.Stats counters, so under -cpu the atomic RMWs serialize on shared
// cache lines.
//
//   SharedAggregate — all goroutines RMW one (real, cache-line-padded) Statistics,
//                     exactly today's model. Run benchstat against a pre-P8 base
//                     ref to see the ~2x the hot-counter padding bought:
//                       dagger call benchstat --src=. --base-ref=<pre-P8> \
//                         --pkgs=./. --pattern 'BenchmarkStatsParallel_SharedAggregate$' --cpu 1,2,4,8
//   PerQueueShard   — each goroutine RMWs its own Statistics shard: the lock-free
//                     ideal. The residual SharedAggregate-vs-PerQueueShard gap is
//                     the per-counter TRUE sharing that only a full per-queue shard
//                     removes — deferred, because that needs the exported Stats read
//                     API and the Datapath interface to change.
//
// Run: go test -run '^$' -bench 'BenchmarkStatsParallel' -cpu=1,2,4,8 .

import (
	"sync/atomic"
	"testing"
)

// bumpRX/bumpTX mirror the hot-path success writes exactly: RX bumps the
// RXPackets/RXBytes/LastRXUnixNano trio (inplace_transform.go:323-325), TX bumps
// the TXPackets/TXBytes/LastTXUnixNano trio (inplace_transform.go:683-685).
func bumpRX(s *Statistics, n uint64) {
	s.RXPackets.Add(1)
	s.RXBytes.Add(n)
	s.LastRXUnixNano.Store(int64(n))
}

func bumpTX(s *Statistics, n uint64) {
	s.TXPackets.Add(1)
	s.TXBytes.Add(n)
	s.LastTXUnixNano.Store(int64(n))
}

// BenchmarkStatsParallel_SharedAggregate has every queue goroutine RMW one shared
// Statistics — even goroutines drive the RX trio, odd ones the TX trio, so the
// run exercises both true sharing (same counter, many cores) and false sharing
// (RX vs TX counters on adjacent lines), exactly as the symmetric forwarder does.
func BenchmarkStatsParallel_SharedAggregate(b *testing.B) {
	var s Statistics
	var gid atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		rx := gid.Add(1)%2 == 0
		var n uint64
		for pb.Next() {
			if rx {
				bumpRX(&s, n)
			} else {
				bumpTX(&s, n)
			}
			n++
		}
	})
}

// BenchmarkStatsParallel_PerQueueShard is the CONTROL: each goroutine owns its own
// Statistics shard, so there is no cross-core coherence traffic. It should stay
// flat as -cpu grows, bounding the headroom a per-queue shard would recover.
func BenchmarkStatsParallel_PerQueueShard(b *testing.B) {
	const shards = 256
	arr := make([]Statistics, shards)
	var gid atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		id := gid.Add(1)
		s := &arr[id%shards]
		rx := id%2 == 0
		var n uint64
		for pb.Next() {
			if rx {
				bumpRX(s, n)
			} else {
				bumpTX(s, n)
			}
			n++
		}
	})
}
