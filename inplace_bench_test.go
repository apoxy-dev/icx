package icx

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// Micro-benchmarks isolating the per-frame cost of the in-place transforms
// against the two-buffer transforms. These measure the CPU/allocation cost of
// the transform itself (crypto + header work +/- the cross-buffer copy); they do
// NOT measure the datapath-level zero-copy win (eliminating a frame copy AND a
// second UMEM allocation between the phy and virt sockets), which only shows up
// in the forwarder over real sockets. Read them as "the transform is at least as
// cheap in place," with the larger systemic win on top of that.
//
// Run: go test -run '^$' -bench 'InPlace|CrossBuffer' -benchmem .

// benchInner sizes the inner IPv4+UDP payload so the encapsulated frame is a
// realistic ~1300-byte MTU-class packet.
const benchInnerPayload = 1200

func benchEnv(b *testing.B, layer3 bool) *inplaceEnv {
	b.Helper()
	tc := inplaceTestCase{layer3: layer3, underlayV6: false, innerV6: false, payloadLen: benchInnerPayload}
	// newInplaceEnv takes *testing.T; build the handler directly here instead so
	// we can drive it from a *testing.B.
	return newBenchEnv(b, tc)
}

// newBenchEnv mirrors newInplaceEnv for a *testing.B (no require/*testing.T).
func newBenchEnv(b *testing.B, tc inplaceTestCase) *inplaceEnv {
	b.Helper()
	virtMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	srcMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")
	localAddr, remoteAddr := underlayAddrs(tc.underlayV6)

	opts := []HandlerOption{WithLocalAddr(localAddr)}
	if tc.layer3 {
		opts = append(opts, WithLayer3VirtFrames())
	} else {
		opts = append(opts, WithVirtMAC(virtMAC), WithSourceMAC(srcMAC))
	}
	h, err := NewHandler(opts...)
	if err != nil {
		b.Fatalf("NewHandler: %v", err)
	}

	const vni = uint(100)
	routes := []Route{{Src: netip.MustParsePrefix("10.0.1.0/24"), Dst: netip.MustParsePrefix("10.0.1.0/24")}}
	var key [16]byte
	copy(key[:], "0123456789abcdef")
	if err := h.AddVirtualNetwork(vni, remoteAddr, routes); err != nil {
		b.Fatalf("AddVirtualNetwork: %v", err)
	}
	if err := h.InstallKeysForTest(vni, 1, key, key, time.Now().Add(time.Hour)); err != nil {
		b.Fatalf("InstallKeysForTest: %v", err)
	}
	vnet, ok := h.GetVirtualNetwork(vni)
	if !ok {
		b.Fatal("vnet missing")
	}
	return &inplaceEnv{
		h: h, vni: vni, vnet: vnet,
		innerSrc: netip.MustParseAddr("10.0.1.5"), innerDst: netip.MustParseAddr("10.0.1.6"),
		underlayV6: tc.underlayV6, innerV6: tc.innerV6, layer3: tc.layer3,
	}
}

// BenchmarkVirtToPhy_CrossBuffer measures two-buffer encap (separate src/dst).
func BenchmarkVirtToPhy_CrossBuffer(b *testing.B) {
	env := benchEnv(b, true)
	virt := buildBenchVirt(env)
	phy := make([]byte, mtu+inplaceScratch)
	b.SetBytes(int64(len(virt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		env.pinCounter(0)
		if n, _ := env.h.VirtToPhy(virt, phy); n == 0 {
			b.Fatal("encap dropped")
		}
	}
}

// BenchmarkVirtToPhy_InPlace measures in-place encap (single shared buffer).
func BenchmarkVirtToPhy_InPlace(b *testing.B) {
	env := benchEnv(b, true)
	virt := buildBenchVirt(env)
	buf := make([]byte, mtu+2*inplaceScratch)
	off := inplaceScratch
	b.SetBytes(int64(len(virt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf[off:off+len(virt)], virt)
		env.pinCounter(0)
		if _, n, _ := env.h.VirtToPhyInPlace(buf, off, len(virt)); n == 0 {
			b.Fatal("encap dropped")
		}
	}
}

// BenchmarkPhyToVirt_CrossBuffer measures two-buffer decap (separate src/dst).
func BenchmarkPhyToVirt_CrossBuffer(b *testing.B) {
	env := benchEnv(b, true)
	phy := buildBenchPhy(b, env)
	virt := make([]byte, mtu+inplaceScratch)
	b.SetBytes(int64(len(phy)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		env.resetReplay(1)
		if n := env.h.PhyToVirt(phy, virt); n == 0 {
			b.Fatal("decap dropped")
		}
	}
}

// BenchmarkPhyToVirt_InPlace measures in-place decap (single shared buffer).
func BenchmarkPhyToVirt_InPlace(b *testing.B) {
	env := benchEnv(b, true)
	phy := buildBenchPhy(b, env)
	buf := make([]byte, mtu+2*inplaceScratch)
	off := inplaceScratch
	b.SetBytes(int64(len(phy)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf[off:off+len(phy)], phy)
		env.resetReplay(1)
		if _, n := env.h.PhyToVirtInPlace(buf, off, len(phy)); n == 0 {
			b.Fatal("decap dropped")
		}
	}
}

// buildBenchVirt builds the L3 virtual frame (raw inner IPv4+UDP) for the env.
func buildBenchVirt(env *inplaceEnv) []byte {
	payload := make([]byte, benchInnerPayload)
	for i := range payload {
		payload[i] = byte(i)
	}
	return buildInnerIPv4Packet(env.innerSrc, env.innerDst, payload)
}

// buildBenchPhy builds a real encrypted physical frame via the encap path.
func buildBenchPhy(b *testing.B, env *inplaceEnv) []byte {
	b.Helper()
	virt := buildBenchVirt(env)
	env.pinCounter(0)
	phy := make([]byte, mtu+inplaceScratch)
	n, handled := env.h.VirtToPhy(virt, phy)
	if n == 0 || handled {
		b.Fatalf("failed to build phy frame: n=%d handled=%v", n, handled)
	}
	return append([]byte(nil), phy[:n]...)
}
