package control

import (
	"errors"
	"testing"
	"time"
)

// newTestVNIAllocator returns an allocator over a tiny VNI space with a
// controllable clock, so exhaustion and quarantine expiry are testable
// without 16M allocations.
func newTestVNIAllocator(grace time.Duration, max uint32) (*VNIAllocator, *time.Time) {
	now := time.Unix(1000, 0)
	a := NewVNIAllocator(grace)
	a.max = max
	a.now = func() time.Time { return now }
	return a, &now
}

func TestVNIAllocatorQuarantine(t *testing.T) {
	const grace = 30 * time.Second
	a, now := newTestVNIAllocator(grace, 3)

	// Drain the space: 1, 2, 3 then exhausted.
	for want := uint32(1); want <= 3; want++ {
		got, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", want, err)
		}
		if got != want {
			t.Fatalf("Allocate #%d = %d, want %d", want, got, want)
		}
	}
	if _, err := a.Allocate(); !errors.Is(err, ErrVNIExhausted) {
		t.Fatalf("Allocate on full space: %v, want ErrVNIExhausted", err)
	}

	// A released VNI must stay unmintable for the full grace window even
	// under exhaustion pressure.
	a.Release(2)
	if _, err := a.Allocate(); !errors.Is(err, ErrVNIExhausted) {
		t.Fatalf("Allocate inside quarantine: %v, want ErrVNIExhausted", err)
	}
	*now = now.Add(grace - time.Nanosecond)
	if _, err := a.Allocate(); !errors.Is(err, ErrVNIExhausted) {
		t.Fatalf("Allocate at grace boundary: %v, want ErrVNIExhausted", err)
	}

	// After grace it is mintable again.
	*now = now.Add(time.Nanosecond)
	got, err := a.Allocate()
	if err != nil {
		t.Fatalf("Allocate after grace: %v", err)
	}
	if got != 2 {
		t.Fatalf("Allocate after grace = %d, want the quarantined 2", got)
	}
	if a.Live() != 3 {
		t.Fatalf("Live() = %d, want 3", a.Live())
	}
}

func TestVNIAllocatorDoubleReleaseExtendsQuarantine(t *testing.T) {
	const grace = 30 * time.Second
	a, now := newTestVNIAllocator(grace, 1)

	if _, err := a.Allocate(); err != nil {
		t.Fatal(err)
	}
	a.Release(1)
	// A second release halfway through must extend the window, not shorten it.
	*now = now.Add(grace / 2)
	a.Release(1)
	*now = now.Add(grace / 2)
	if _, err := a.Allocate(); !errors.Is(err, ErrVNIExhausted) {
		t.Fatalf("Allocate after original deadline: %v, want ErrVNIExhausted (window extended)", err)
	}
	*now = now.Add(grace / 2)
	if _, err := a.Allocate(); err != nil {
		t.Fatalf("Allocate after extended deadline: %v", err)
	}
}

func TestVNIAllocatorReleaseUnknownQuarantines(t *testing.T) {
	a, _ := newTestVNIAllocator(time.Minute, 2)
	// Releasing a never-allocated VNI is conservative: it quarantines it.
	a.Release(1)
	got, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if got != 2 {
		t.Fatalf("Allocate = %d, want 2 (1 quarantined by stray release)", got)
	}
	// Out-of-range releases are no-ops.
	a.Release(0)
	a.Release(3)
}

// TestVNIAllocatorPrunesExpiredQuarantine pins the quarantine-map leak fix:
// under low-occupancy churn the forward scan never revisits released VNIs, so
// without an explicit sweep the quarantined map would grow without bound. After
// grace, a single operation must drop every expired entry.
func TestVNIAllocatorPrunesExpiredQuarantine(t *testing.T) {
	const grace = 30 * time.Second
	a, now := newTestVNIAllocator(grace, 1000)

	for i := 0; i < 200; i++ {
		v, err := a.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		a.Release(v)
	}
	a.mu.Lock()
	q := len(a.quarantined)
	a.mu.Unlock()
	if q == 0 {
		t.Fatal("expected quarantine entries before grace elapses")
	}

	*now = now.Add(grace + time.Nanosecond)
	if _, err := a.Allocate(); err != nil {
		t.Fatalf("Allocate after grace: %v", err)
	}
	a.mu.Lock()
	q, ql := len(a.quarantined), len(a.expiry)
	a.mu.Unlock()
	if q != 0 {
		t.Fatalf("quarantine map not pruned: %d entries remain", q)
	}
	if ql != 0 {
		t.Fatalf("expiry queue not drained: %d entries remain", ql)
	}
}

func TestVNIAllocatorCyclesBeforeReuse(t *testing.T) {
	// With zero grace, reuse is still deferred until the space wraps: after
	// allocating and releasing 1, the next mint is 2, not 1 again.
	a, _ := newTestVNIAllocator(0, 4)
	got, err := a.Allocate()
	if err != nil || got != 1 {
		t.Fatalf("Allocate = %d, %v; want 1", got, err)
	}
	a.Release(1)
	got, err = a.Allocate()
	if err != nil || got != 2 {
		t.Fatalf("Allocate after release = %d, %v; want 2 (scan resumes past last)", got, err)
	}
}
