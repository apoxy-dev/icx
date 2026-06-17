package icx

// Verifies P11/APO-674: at the default info level, the per-packet drop branches
// must not allocate. It drives the cheapest off-path-reachable drop — an
// otherwise well-formed frame whose VNI is not installed — which lands on the
// guarded "unknown VNI" debug log before any crypto. Without the debugDropEnabled
// guard, building the discarded slog record (variadic boxing of slog.Uint64)
// costs ~2 allocs/frame; with it, zero. A forged-packet flood lands exactly here,
// so this is the path that must stay allocation-free.
//
// Run: go test -run TestDropPathAllocFree .

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDropPathAllocFree(t *testing.T) {
	// Pin the default logger to info with a discard handler so the assertion does
	// not depend on ambient test logging configuration; restore it afterwards.
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	env := newInplaceEnv(t, inplaceTestCase{layer3: true, underlayV6: false, innerV6: false, payloadLen: 64})

	// Build a fully valid physical frame, then remove the network so the same frame
	// now drops at the unknown-VNI check (before Open) — no crafted/corrupt bytes,
	// just a valid frame whose VNI is no longer installed.
	inner := buildInnerIPv4Packet(env.innerSrc, env.innerDst, make([]byte, 64))
	env.pinCounter(0)
	phy := make([]byte, mtu+inplaceScratch)
	n, handled := env.h.VirtToPhy(inner, phy)
	require.NotZero(t, n)
	require.False(t, handled)
	frame := append([]byte(nil), phy[:n]...)

	require.NoError(t, env.h.RemoveVirtualNetwork(env.vni))

	off := inplaceScratch
	buf := make([]byte, mtu+2*inplaceScratch)
	copy(buf[off:off+len(frame)], frame)

	// Sanity: the path really drops (zero-length output window). The drop happens
	// before any in-place write, so buf is left intact and can be reused below.
	if _, m := env.h.PhyToVirtInPlace(buf, off, len(frame)); m != 0 {
		t.Fatalf("expected unknown-VNI drop, got window len %d", m)
	}

	avg := testing.AllocsPerRun(200, func() {
		env.h.PhyToVirtInPlace(buf, off, len(frame))
	})
	// Guarded: ~0 allocs. Unguarded (pre-fix): ~2 allocs from the discarded record.
	// Assert < 1 so the result is robust to rare sync.Pool/GC noise while still
	// cleanly distinguishing the fixed path from the allocating one.
	require.Less(t, avg, 1.0, "unknown-VNI drop path must be allocation-free at info level")
}
