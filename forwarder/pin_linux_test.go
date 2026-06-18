//go:build linux

package forwarder

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// TestAllowedCPUs checks the affinity snapshot matches what the kernel reports
// for this process: same count, every returned index actually set, and sorted.
func TestAllowedCPUs(t *testing.T) {
	var mask unix.CPUSet
	if err := unix.SchedGetaffinity(0, &mask); err != nil {
		t.Skipf("cannot read CPU affinity: %v", err)
	}
	cpus := allowedCPUs()
	if mask.Count() == 0 {
		if cpus != nil {
			t.Fatalf("empty mask should yield nil, got %v", cpus)
		}
		return
	}
	if len(cpus) != mask.Count() {
		t.Fatalf("allowedCPUs len = %d, kernel Count = %d", len(cpus), mask.Count())
	}
	for i, cpu := range cpus {
		if !mask.IsSet(cpu) {
			t.Fatalf("allowedCPUs[%d]=%d not in the affinity mask", i, cpu)
		}
		if i > 0 && cpu <= cpus[i-1] {
			t.Fatalf("allowedCPUs not strictly ascending at %d: %v", i, cpus)
		}
	}
}

// TestPinThreadToCPU asserts that pinning narrows the calling thread to exactly
// the expected single CPU and that distinct queue IDs spread round-robin over the
// allowed set. It restores the full mask before each pin (in production each queue
// goroutine starts on a fresh thread carrying the full inherited mask, so reading
// allowedCPUs once up front and indexing it is what spreads them).
func TestPinThreadToCPU(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var base unix.CPUSet
	if err := unix.SchedGetaffinity(0, &base); err != nil {
		t.Skipf("cannot read CPU affinity: %v", err)
	}
	cpus := allowedCPUs()
	if len(cpus) == 0 {
		t.Skip("no CPUs in affinity mask")
	}
	defer unix.SchedSetaffinity(0, &base) // restore the original mask

	// Cover wrap-around past the CPU count.
	for q := 0; q < len(cpus)*2+1; q++ {
		if err := unix.SchedSetaffinity(0, &base); err != nil {
			t.Fatalf("reset affinity: %v", err)
		}
		pinThreadToCPU(q, cpus)

		var got unix.CPUSet
		if err := unix.SchedGetaffinity(0, &got); err != nil {
			t.Fatalf("get affinity after pin: %v", err)
		}
		if got.Count() != 1 {
			t.Fatalf("queue %d: expected exactly 1 CPU after pin, got %d", q, got.Count())
		}
		want := cpus[q%len(cpus)]
		if !got.IsSet(want) {
			t.Fatalf("queue %d: expected pin to CPU %d, mask does not have it", q, want)
		}
	}
}
