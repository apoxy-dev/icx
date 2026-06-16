package icx

import "testing"

// TestRxRateLimiterFixedWindow: each window admits exactly `limit` frames, and a
// fresh window refills the budget.
func TestRxRateLimiterFixedWindow(t *testing.T) {
	rl := newRxRateLimiter(50) // 50 pps / 10 sub-windows = 5 per window
	if rl.limit != 5 {
		t.Fatalf("limit = %d, want 5", rl.limit)
	}

	base := int64(1_000_000_000)
	admitted := 0
	for i := 0; i < 20; i++ {
		if rl.allow(base) {
			admitted++
		}
	}
	if admitted != 5 {
		t.Fatalf("first window admitted %d, want 5", admitted)
	}

	admitted = 0
	for i := 0; i < 20; i++ {
		if rl.allow(base + rl.windowNanos) {
			admitted++
		}
	}
	if admitted != 5 {
		t.Fatalf("second window admitted %d, want 5", admitted)
	}
}

// TestRxRateLimiterMinimumOne: a configured rate below one-per-window still admits
// at least one frame per window rather than rounding down to zero (deny-all).
func TestRxRateLimiterMinimumOne(t *testing.T) {
	rl := newRxRateLimiter(1)
	if rl.limit != 1 {
		t.Fatalf("limit = %d, want 1", rl.limit)
	}
	if !rl.allow(0) {
		t.Fatal("first frame must be admitted")
	}
	if rl.allow(0) {
		t.Fatal("second frame in the same window must be dropped")
	}
}

// TestRxRateLimiterSustainedRate: across a full second of evenly-spaced windows,
// the limiter admits ~pps frames in total.
func TestRxRateLimiterSustainedRate(t *testing.T) {
	rl := newRxRateLimiter(100) // 10 per 100ms window
	now := int64(5_000_000_000)
	admitted := 0
	for w := 0; w < subWindowsPerSec; w++ {
		ts := now + int64(w)*rl.windowNanos
		for i := 0; i < 100; i++ {
			if rl.allow(ts) {
				admitted++
			}
		}
	}
	if admitted != 100 {
		t.Fatalf("admitted %d over one second, want 100 (pps)", admitted)
	}
}
