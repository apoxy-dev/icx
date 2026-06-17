package icx

// Verifies P5/APO-668: the TX path skips the redundant outer UDP checksum on an
// IPv4 underlay (emitting the legal RFC 768 zero checksum) while still computing
// it on IPv6 (where zero is illegal) and when the operator forces it on for
// middlebox compatibility. The encapsulated payload is already AES-GCM
// authenticated and the ICX RX path decodes with skipChecksumValidation, so the
// elided checksum costs nothing in integrity and the zero-checksum frame still
// round-trips through PhyToVirt.
//
// Run: go test -run TestOuterUDPChecksum .
//      go test -run '^$' -bench 'VirtToPhy_(Skip|Compute)Checksum' -benchmem .

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx/udp"
)

// txChecksumEnv builds an L3 handler on the requested underlay family and returns
// it plus an inner IPv4 packet whose addresses resolve to its single route.
func txChecksumEnv(t *testing.T, underlayV6 bool, extra ...HandlerOption) (*inplaceEnv, []byte) {
	t.Helper()
	tc := inplaceTestCase{layer3: true, underlayV6: underlayV6, innerV6: false, payloadLen: 64}
	env := newInplaceEnv(t, tc, extra...)
	payload := make([]byte, 64)
	inner := buildInnerIPv4Packet(env.innerSrc, env.innerDst, payload)
	return env, inner
}

// outerUDP returns the outer UDP header of a physical frame for the given underlay
// family, so a test can read the checksum field the TX path wrote.
func outerUDP(frame []byte, underlayV6 bool) header.UDP {
	if underlayV6 {
		ip := header.IPv6(frame[header.EthernetMinimumSize:])
		return header.UDP(ip.Payload())
	}
	ip := header.IPv4(frame[header.EthernetMinimumSize:])
	return header.UDP(ip.Payload())
}

// txOuterFrame runs one cross-buffer encap with a pinned counter and returns the
// resulting physical frame.
func txOuterFrame(t *testing.T, env *inplaceEnv, inner []byte) []byte {
	t.Helper()
	env.pinCounter(0)
	phy := make([]byte, mtu+inplaceScratch)
	n, handled := env.h.VirtToPhy(inner, phy)
	require.NotZero(t, n, "encap dropped")
	require.False(t, handled)
	return append([]byte(nil), phy[:n]...)
}

func TestOuterUDPChecksum(t *testing.T) {
	t.Run("ipv4_default_skips", func(t *testing.T) {
		env, inner := txChecksumEnv(t, false)
		frame := txOuterFrame(t, env, inner)
		require.Equal(t, uint16(0), outerUDP(frame, false).Checksum(),
			"IPv4 underlay should emit a zero (skipped) outer UDP checksum by default")

		// The zero-checksum frame must still round-trip: the handler's RX path
		// decodes with skipChecksumValidation, so it does not reject checksum 0.
		env.resetReplay(1)
		virt := make([]byte, mtu+inplaceScratch)
		m := env.h.PhyToVirt(frame, virt)
		require.NotZero(t, m, "zero-checksum frame failed to decode on RX")
		require.Equal(t, inner, virt[:m], "round-trip inner packet mismatch")
	})

	t.Run("ipv4_forced_computes_valid", func(t *testing.T) {
		env, inner := txChecksumEnv(t, false, WithOuterUDPChecksum())
		frame := txOuterFrame(t, env, inner)
		require.NotEqual(t, uint16(0), outerUDP(frame, false).Checksum(),
			"WithOuterUDPChecksum should compute a non-zero checksum on IPv4")
		// A full checksum-validating decode must accept it (proves it is correct,
		// not just non-zero).
		_, err := udp.Decode(frame, nil, false)
		require.NoError(t, err, "forced IPv4 checksum must validate")
	})

	t.Run("ipv6_always_computes_valid", func(t *testing.T) {
		env, inner := txChecksumEnv(t, true)
		frame := txOuterFrame(t, env, inner)
		require.NotEqual(t, uint16(0), outerUDP(frame, true).Checksum(),
			"IPv6 underlay must always compute the outer UDP checksum (zero is illegal)")
		_, err := udp.Decode(frame, nil, false)
		require.NoError(t, err, "IPv6 checksum must validate")
	})
}

// benchTxChecksumHandler builds the minimal L3 IPv4-underlay handler used by the
// checksum A/B benchmarks, with the given extra options.
func benchTxChecksumHandler(b *testing.B, extra ...HandlerOption) (*Handler, []byte, []byte) {
	b.Helper()
	local, remote := underlayAddrs(false)
	opts := append([]HandlerOption{WithLocalAddr(local), WithLayer3VirtFrames()}, extra...)
	h, err := NewHandler(opts...)
	if err != nil {
		b.Fatalf("NewHandler: %v", err)
	}
	const vni = uint(100)
	routes := []Route{{Src: netip.MustParsePrefix("10.0.1.0/24"), Dst: netip.MustParsePrefix("10.0.1.0/24")}}
	var key [16]byte
	copy(key[:], "0123456789abcdef")
	if err := h.AddVirtualNetwork(vni, remote, routes); err != nil {
		b.Fatalf("AddVirtualNetwork: %v", err)
	}
	if err := h.InstallKeysForTest(vni, 1, key, key, time.Now().Add(time.Hour)); err != nil {
		b.Fatalf("InstallKeysForTest: %v", err)
	}
	payload := make([]byte, benchInnerPayload)
	inner := buildInnerIPv4Packet(netip.MustParseAddr("10.0.1.5"), netip.MustParseAddr("10.0.1.6"), payload)
	phy := make([]byte, mtu+inplaceScratch)
	return h, inner, phy
}

// runTxChecksumBench drives VirtToPhy in a tight loop. The counter climbs freely
// (TX seal does not gate on replay), so no per-iteration reset is needed.
func runTxChecksumBench(b *testing.B, h *Handler, inner, phy []byte) {
	b.SetBytes(int64(len(inner)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n, _ := h.VirtToPhy(inner, phy); n == 0 {
			b.Fatal("encap dropped")
		}
	}
}

// BenchmarkVirtToPhy_SkipChecksum measures the default IPv4 TX path (outer UDP
// checksum skipped). BenchmarkVirtToPhy_ComputeChecksum forces the checksum on,
// so benchstat over the pair isolates the per-frame cost P5 removed:
//
//	go test -run '^$' -bench 'VirtToPhy_(Skip|Compute)Checksum' -benchmem .
func BenchmarkVirtToPhy_SkipChecksum(b *testing.B) {
	h, inner, phy := benchTxChecksumHandler(b)
	runTxChecksumBench(b, h, inner, phy)
}

func BenchmarkVirtToPhy_ComputeChecksum(b *testing.B) {
	h, inner, phy := benchTxChecksumHandler(b, WithOuterUDPChecksum())
	runTxChecksumBench(b, h, inner, phy)
}
