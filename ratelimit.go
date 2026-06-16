package icx

import (
	"sync/atomic"
	"time"
)

// rxRateLimiter is a coarse, lock-free fixed-window limiter that caps how many
// frames per virtual network reach the expensive AES-GCM Open on the RX path. It
// exists to shed an off-path flood of forgeable VNI=1/epoch=1 frames before they
// burn crypto CPU (and, pre-S2, mutated replay state) on the pinned per-queue
// threads (APO-655).
//
// It is deliberately approximate. The window reset races benignly: if several
// queue goroutines observe the same elapsed window concurrently, only the one
// that wins the CompareAndSwap resets the counter, and a handful of increments
// from the losers may be wiped or double-counted across the boundary. Exact
// fairness is not needed to bound a flood — the guarantee is simply that no more
// than roughly `limit` frames per window proceed to Open, which is what caps the
// CPU. It is created only when a positive limit is configured; the RX hot path
// skips it entirely via a nil check when disabled, so the zero-copy datapath
// keeps its zero-overhead default.
type rxRateLimiter struct {
	limit       int64 // max admitted frames per window
	windowNanos int64 // window length in nanoseconds
	windowStart atomic.Int64
	count       atomic.Int64
}

// subWindowsPerSec divides the configured per-second budget into shorter windows
// so the admitted burst is bounded to ~pps/subWindowsPerSec rather than a whole
// second's worth arriving at once.
const subWindowsPerSec = 10

// newRxRateLimiter builds a limiter admitting at most pps frames per second,
// enforced over a 1/subWindowsPerSec-second window. pps must be > 0 (callers gate
// on the configured limit before constructing one).
func newRxRateLimiter(pps int) *rxRateLimiter {
	limit := int64(pps) / subWindowsPerSec
	if limit < 1 {
		// Honour very small configured rates: admit at least one frame per window
		// rather than rounding down to zero (which would drop everything).
		limit = 1
	}
	return &rxRateLimiter{
		limit:       limit,
		windowNanos: int64(time.Second) / subWindowsPerSec,
	}
}

// allow reports whether a frame may proceed to Open at time nowNanos, counting it
// against the current window. When the current window has fully elapsed it claims
// a fresh one (resetting the count) before admitting against it.
func (r *rxRateLimiter) allow(nowNanos int64) bool {
	ws := r.windowStart.Load()
	if nowNanos-ws >= r.windowNanos {
		// Window elapsed: try to open a fresh one. Only the CAS winner resets the
		// counter; concurrent losers simply count against the new window.
		if r.windowStart.CompareAndSwap(ws, nowNanos) {
			r.count.Store(0)
		}
	}
	return r.count.Add(1) <= r.limit
}
