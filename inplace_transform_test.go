package icx

import (
	"bytes"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// mtu is the inner IP payload budget used to size the test corpus and buffers.
const mtu = 1400

// newTestHandler builds a Handler for the in-place equivalence tests. It is an
// in-package helper so the tests (package icx) can reach unexported state such
// as VirtualNetwork.txCipher to pin the TX counter for deterministic nonces.
func newTestHandler(t *testing.T, opts ...HandlerOption) *Handler {
	t.Helper()
	h, err := NewHandler(opts...)
	require.NoError(t, err)
	return h
}

// generateKey returns a random AES-128 key.
func generateKey(t *testing.T) [16]byte {
	t.Helper()
	var k [16]byte
	_, err := rand.Read(k[:])
	require.NoError(t, err)
	return k
}

// underlayAddrs returns the local and remote underlay addresses for the given
// address family, with deterministic non-empty LinkAddrs so that the outer
// Ethernet header written by udp.Encode is fully determined by the handler
// configuration (and therefore identical between the two-buffer and in-place
// paths). Without explicit LinkAddrs, gvisor's eth.Encode would leave the
// MAC fields as whatever was already in the destination buffer, which differs
// between a freshly-zeroed reference buffer and a reused in-place buffer.
func underlayAddrs(v6 bool) (local, remote *tcpip.FullAddress) {
	localMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x0a\x01")
	remoteMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x0a\x02")
	if v6 {
		local = &tcpip.FullAddress{Addr: tcpip.AddrFromSlice(net.ParseIP("fd00::1").To16()), Port: 12345, LinkAddr: localMAC}
		remote = &tcpip.FullAddress{Addr: tcpip.AddrFromSlice(net.ParseIP("fd00::2").To16()), Port: 54321, LinkAddr: remoteMAC}
		return local, remote
	}
	local = &tcpip.FullAddress{Addr: tcpip.AddrFromSlice(net.ParseIP("192.168.1.1").To4()), Port: 12345, LinkAddr: localMAC}
	remote = &tcpip.FullAddress{Addr: tcpip.AddrFromSlice(net.ParseIP("192.168.1.2").To4()), Port: 54321, LinkAddr: remoteMAC}
	return local, remote
}

// These tests prove the Phase-2 in-place (shape-A) transforms are byte-for-byte
// equivalent to the existing two-buffer PhyToVirt/VirtToPhy/ToPhy transforms,
// over a corpus of REAL Geneve+UDP+AEAD packets (not synthetic stand-ins).
//
// The corpus exercises IPv4 and IPv6 inner packets, small and MTU-sized
// payloads, and both layer2 and layer3 modes. For each case we:
//
//	(a) DECAP byte-equivalence: build a real physical frame by running the
//	    existing VirtToPhy, then assert PhyToVirtInPlace's output bytes equal
//	    PhyToVirt's output bytes.
//	(b) ENCAP byte-equivalence: PIN the TX counter to the same value before each
//	    call (so both encaps use the same nonce), then assert VirtToPhyInPlace's
//	    output bytes equal VirtToPhy's output bytes.
//	(c) ENCAP round-trip: decap the in-place encap output with the existing
//	    two-buffer PhyToVirt and assert the recovered inner IP packet equals the
//	    original.

// inplaceTestCase describes one entry in the equivalence corpus.
type inplaceTestCase struct {
	name       string
	layer3     bool
	underlayV6 bool // underlay (outer) address family
	innerV6    bool // inner IP packet address family
	payloadLen int
}

func inplaceCorpus() []inplaceTestCase {
	var cases []inplaceTestCase
	for _, mode := range []struct {
		name   string
		layer3 bool
	}{
		{"l2", false},
		{"l3", true},
	} {
		for _, under := range []struct {
			name string
			v6   bool
		}{
			{"under4", false},
			{"under6", true},
		} {
			for _, inner := range []struct {
				name string
				v6   bool
			}{
				{"inner4", false},
				{"inner6", true},
			} {
				for _, pl := range []struct {
					name string
					n    int
				}{
					{"small", 1},
					{"med", 200},
					{"mtu", mtu - 64}, // leave room for inner IP+UDP within MTU
				} {
					cases = append(cases, inplaceTestCase{
						name:       mode.name + "/" + under.name + "/" + inner.name + "/" + pl.name,
						layer3:     mode.layer3,
						underlayV6: under.v6,
						innerV6:    inner.v6,
						payloadLen: pl.n,
					})
				}
			}
		}
	}
	return cases
}

// inplaceEnv bundles a handler configured for one corpus entry plus the
// addresses needed to build/validate frames.
type inplaceEnv struct {
	h          *Handler
	vni        uint
	vnet       *VirtualNetwork
	innerSrc   netip.Addr
	innerDst   netip.Addr
	underlayV6 bool
	innerV6    bool
	layer3     bool
}

func newInplaceEnv(t *testing.T, tc inplaceTestCase, extra ...HandlerOption) *inplaceEnv {
	t.Helper()

	virtMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	srcMAC := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")

	localAddr, remoteAddr := underlayAddrs(tc.underlayV6)

	opts := []HandlerOption{WithLocalAddr(localAddr)}
	if tc.layer3 {
		opts = append(opts, WithLayer3VirtFrames())
	} else {
		opts = append(opts, WithVirtMAC(virtMAC), WithSourceMAC(srcMAC))
	}
	opts = append(opts, extra...)
	h := newTestHandler(t, opts...)

	vni := uint(100)

	// The handler routes a virtual frame by (dst -> src): VirtToPhy looks up the
	// inner packet's DESTINATION in the route.Dst trie and its SOURCE in the
	// route.Src trie. So the inner packet's src must fall within route.Src and
	// its dst within route.Dst. On decap (PhyToVirt) the recovered packet's
	// SOURCE is validated against the vnet's route.Dst prefixes, so the inner
	// src must also fall within route.Dst. We therefore use overlapping /24
	// (or /64) prefixes for both Src and Dst so both validations pass.
	var src, dst netip.Addr
	var routes []Route
	if tc.innerV6 {
		src = netip.MustParseAddr("fd01::5")
		dst = netip.MustParseAddr("fd01::6")
		routes = []Route{{
			Src: netip.MustParsePrefix("fd01::/64"),
			Dst: netip.MustParsePrefix("fd01::/64"),
		}}
	} else {
		src = netip.MustParseAddr("10.0.1.5")
		dst = netip.MustParseAddr("10.0.1.6")
		routes = []Route{{
			Src: netip.MustParsePrefix("10.0.1.0/24"),
			Dst: netip.MustParsePrefix("10.0.1.0/24"),
		}}
	}

	// Use a single key for both RX and TX so that frames encrypted with the TX
	// cipher can be decrypted with the RX cipher (the round-trip and decap
	// equivalence tests run encap then decap on the same handler). This loopback
	// shape requires the unguarded InstallKeysForTest seam: the production
	// UpdateVirtualNetworkKeys rejects equal rx/tx keys (real peers use distinct
	// per-direction keys).
	key := generateKey(t)
	require.NoError(t, h.AddVirtualNetwork(vni, remoteAddr, routes))
	require.NoError(t, h.InstallKeysForTest(vni, 1, key, key, time.Now().Add(time.Hour)))

	vnet, ok := h.GetVirtualNetwork(vni)
	require.True(t, ok)

	return &inplaceEnv{
		h:          h,
		vni:        vni,
		vnet:       vnet,
		innerSrc:   src,
		innerDst:   dst,
		underlayV6: tc.underlayV6,
		innerV6:    tc.innerV6,
		layer3:     tc.layer3,
	}
}

// buildInnerIPv4Packet builds a raw IPv4+UDP packet (no Ethernet header).
func buildInnerIPv4Packet(srcIP, dstIP netip.Addr, payload []byte) []byte {
	frame := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv4(frame)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(frame)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(srcIP.AsSlice()),
		DstAddr:     tcpip.AddrFromSlice(dstIP.AsSlice()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	udp := header.UDP(frame[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{SrcPort: 12345, DstPort: 54321, Length: uint16(header.UDPMinimumSize + len(payload))})
	copy(frame[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	return frame
}

// buildInnerIPv6Packet builds a raw IPv6+UDP packet (no Ethernet header).
func buildInnerIPv6Packet(srcIP, dstIP netip.Addr, payload []byte) []byte {
	frame := make([]byte, header.IPv6MinimumSize+header.UDPMinimumSize+len(payload))
	ip := header.IPv6(frame)
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.UDPMinimumSize + len(payload)),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFromSlice(srcIP.AsSlice()),
		DstAddr:           tcpip.AddrFromSlice(dstIP.AsSlice()),
	})
	udp := header.UDP(frame[header.IPv6MinimumSize:])
	udp.Encode(&header.UDPFields{SrcPort: 12345, DstPort: 54321, Length: uint16(header.UDPMinimumSize + len(payload))})
	copy(frame[header.IPv6MinimumSize+header.UDPMinimumSize:], payload)
	return frame
}

// buildVirtFrame returns the virtual frame the handler expects for this env:
// a raw IP packet in L3 mode, or an Ethernet-framed IP packet in L2 mode.
func (e *inplaceEnv) buildVirtFrame(t *testing.T, payloadLen int) []byte {
	t.Helper()
	payload := make([]byte, payloadLen)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	var ipPacket []byte
	if e.innerV6 {
		ipPacket = buildInnerIPv6Packet(e.innerSrc, e.innerDst, payload)
	} else {
		ipPacket = buildInnerIPv4Packet(e.innerSrc, e.innerDst, payload)
	}
	if e.layer3 {
		return ipPacket
	}
	// L2: prepend an Ethernet header.
	frame := make([]byte, header.EthernetMinimumSize+len(ipPacket))
	eth := header.Ethernet(frame)
	ethType := header.IPv4ProtocolNumber
	if e.innerV6 {
		ethType = header.IPv6ProtocolNumber
	}
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01"),
		DstAddr: tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02"),
		Type:    tcpip.NetworkProtocolNumber(ethType),
	})
	copy(frame[header.EthernetMinimumSize:], ipPacket)
	return frame
}

// pinCounter resets the TX counter so the next Seal uses nonce counter==n+1.
func (e *inplaceEnv) pinCounter(n uint64) {
	tc := e.vnet.txCipher.Load()
	tc.counter.Store(n)
}

// resetReplay clears the replay filter for the given epoch's RX cipher so that
// a previously-accepted nonce can be accepted again. The decap equivalence test
// decaps the SAME physical frame twice (once via the two-buffer PhyToVirt, once
// via the in-place path); without resetting the replay window between them the
// second decap would be rejected as a replay (returning a drop), which is
// correct production behaviour but not what we are exercising here.
func (e *inplaceEnv) resetReplay(epoch uint32) {
	v, ok := e.vnet.rxCiphers.Load(epoch)
	if !ok {
		return
	}
	rc := v.(*receiveCipher)
	rc.replayFilter.Reset()
}

const inplaceScratch = 256 // generous head/tail room used by the test buffers

// TestInPlaceEncapByteEquivalence proves VirtToPhyInPlace produces byte-identical
// output to the two-buffer VirtToPhy when both use the same pinned nonce, and
// that the in-place encap output round-trips back to the original inner packet.
func TestInPlaceEncapByteEquivalence(t *testing.T) {
	for _, tc := range inplaceCorpus() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env := newInplaceEnv(t, tc)
			virtFrame := env.buildVirtFrame(t, tc.payloadLen)

			// Reference: two-buffer VirtToPhy with the counter pinned to 0 (so
			// the nonce uses counter value 1).
			env.pinCounter(0)
			refPhy := make([]byte, mtu+inplaceScratch)
			refLen, refHandled := env.h.VirtToPhy(append([]byte(nil), virtFrame...), refPhy)
			require.False(t, refHandled, "reference encap should not be locally handled")
			require.Greater(t, refLen, 0, "reference encap should succeed")
			refOut := append([]byte(nil), refPhy[:refLen]...)

			// In-place: place the virtual frame in a single buffer at an offset
			// that leaves enough headroom for the outer+Geneve prepend and
			// tailroom for the tag. Pin the counter to 0 again so the nonce
			// matches the reference.
			//
			// Headroom needed in front of the inner IP packet = PayloadOffset
			// (<=62) + Geneve (32) = 94 bytes. In L2 mode the inner IP packet
			// starts 14 bytes into the virtual frame, so place the virtual
			// frame at offset (94 - ethOffset) at minimum; use a generous
			// inplaceScratch.
			buf := make([]byte, mtu+2*inplaceScratch)
			off := inplaceScratch
			copy(buf[off:off+len(virtFrame)], virtFrame)

			env.pinCounter(0)
			gotOff, gotLen, gotHandled := env.h.VirtToPhyInPlace(buf, off, len(virtFrame))
			require.False(t, gotHandled, "in-place encap should not be locally handled")
			require.Greater(t, gotLen, 0, "in-place encap should succeed")
			gotOut := buf[gotOff : gotOff+gotLen]

			if !bytes.Equal(gotOut, refOut) {
				t.Fatalf("encap byte mismatch (len got=%d ref=%d)\n got=%x\n ref=%x", gotLen, refLen, gotOut, refOut)
			}

			// (c) Round-trip: decap the in-place encap output with the existing
			// two-buffer PhyToVirt and confirm the recovered inner IP packet
			// equals the original.
			//
			// Use a fresh handler-side RX path: PhyToVirt validates the inner
			// source address against the vnet's allowed Dst prefixes, and our
			// inner src is inside that prefix, so it will accept.
			virtOut := make([]byte, mtu+inplaceScratch)
			m := env.h.PhyToVirt(append([]byte(nil), gotOut...), virtOut)
			require.Greater(t, m, 0, "round-trip decap should succeed")

			// Compare the recovered inner IP packet to the original inner IP
			// packet (strip the Ethernet header in L2 mode on both sides).
			var wantInner, gotInner []byte
			if env.layer3 {
				wantInner = virtFrame
				gotInner = virtOut[:m]
			} else {
				wantInner = virtFrame[header.EthernetMinimumSize:]
				gotInner = virtOut[header.EthernetMinimumSize:m]
			}
			assert.Equal(t, wantInner, gotInner, "round-trip inner packet mismatch")
		})
	}
}

// TestInPlaceEncapByteEquivalenceWithSourcePortHash proves the in-place and
// cross-buffer encaps stay byte-identical with WithSourcePortHashing enabled — the
// configuration the CLI ships by default. The outer UDP source port is a hash of the
// inner packet; VirtToPhyInPlace must hash the PLAINTEXT inner packet (captured before
// its in-place Seal overwrites that region with ciphertext) exactly as the
// cross-buffer VirtToPhy does. If it instead hashed the post-Seal ciphertext, the two
// paths would emit different source ports and the frame bytes would diverge — this is
// the regression guard for that seal-before-hash bug, which the base equivalence corpus
// misses because it never enables source-port hashing.
func TestInPlaceEncapByteEquivalenceWithSourcePortHash(t *testing.T) {
	for _, tc := range inplaceCorpus() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env := newInplaceEnv(t, tc, WithSourcePortHashing())
			virtFrame := env.buildVirtFrame(t, tc.payloadLen)

			env.pinCounter(0)
			refPhy := make([]byte, mtu+inplaceScratch)
			refLen, refHandled := env.h.VirtToPhy(append([]byte(nil), virtFrame...), refPhy)
			require.False(t, refHandled)
			require.Greater(t, refLen, 0)
			refOut := append([]byte(nil), refPhy[:refLen]...)

			buf := make([]byte, mtu+2*inplaceScratch)
			off := inplaceScratch
			copy(buf[off:off+len(virtFrame)], virtFrame)

			env.pinCounter(0)
			gotOff, gotLen, gotHandled := env.h.VirtToPhyInPlace(buf, off, len(virtFrame))
			require.False(t, gotHandled)
			require.Greater(t, gotLen, 0)
			gotOut := buf[gotOff : gotOff+gotLen]

			if !bytes.Equal(gotOut, refOut) {
				t.Fatalf("encap byte mismatch with source-port hashing (len got=%d ref=%d)\n got=%x\n ref=%x", gotLen, refLen, gotOut, refOut)
			}
		})
	}
}

// TestVirtToPhyInPlaceDropsExpiredKey covers the in-place TX expiry gate (APO-656)
// directly: the byte-equivalence oracle installs a live key and so never reaches the
// expired branch in VirtToPhyInPlace/ToPhyInPlace. Installing an already-expired SA and
// driving the in-place encap asserts it fails closed and charges TXDropsExpiredKey.
func TestVirtToPhyInPlaceDropsExpiredKey(t *testing.T) {
	tc := inplaceTestCase{layer3: true, underlayV6: false, innerV6: false, payloadLen: 16}
	env := newInplaceEnv(t, tc)

	// Re-install the SA with an expiry already in the past (newInplaceEnv installed a
	// live one). InstallKeysForTest is the unguarded seam, so a lower-or-reused epoch is fine.
	key := generateKey(t)
	require.NoError(t, env.h.InstallKeysForTest(env.vni, 2, key, key, time.Now().Add(-time.Hour)))

	virtFrame := env.buildVirtFrame(t, tc.payloadLen)
	buf := make([]byte, mtu+2*inplaceScratch)
	off := inplaceScratch
	copy(buf[off:off+len(virtFrame)], virtFrame)

	_, gotLen, handled := env.h.VirtToPhyInPlace(buf, off, len(virtFrame))
	require.False(t, handled)
	require.Zero(t, gotLen, "in-place TX must fail closed under an expired key")
	require.Equal(t, uint64(1), env.vnet.Stats.TXDropsExpiredKey.Load(), "drop attributed to TX key expiry")
}

// TestInPlaceDecapByteEquivalence proves PhyToVirtInPlace produces byte-identical
// output to the two-buffer PhyToVirt over real encrypted physical frames.
func TestInPlaceDecapByteEquivalence(t *testing.T) {
	for _, tc := range inplaceCorpus() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env := newInplaceEnv(t, tc)
			virtFrame := env.buildVirtFrame(t, tc.payloadLen)

			// Build a REAL physical frame via the existing encap path.
			env.pinCounter(0)
			phyBuf := make([]byte, mtu+inplaceScratch)
			phyLen, handled := env.h.VirtToPhy(append([]byte(nil), virtFrame...), phyBuf)
			require.False(t, handled)
			require.Greater(t, phyLen, 0)
			phyFrame := append([]byte(nil), phyBuf[:phyLen]...)

			// Reference: two-buffer PhyToVirt.
			refVirt := make([]byte, mtu+inplaceScratch)
			refLen := env.h.PhyToVirt(append([]byte(nil), phyFrame...), refVirt)
			require.Greater(t, refLen, 0, "reference decap should succeed")
			refOut := append([]byte(nil), refVirt[:refLen]...)

			// In-place: place the physical frame in a single buffer (with
			// headroom in front in L2 mode for the Ethernet header that decap
			// prepends; there is always >=14 bytes of consumed-outer-header
			// headroom within the frame itself, so no extra leading offset is
			// required, but we add some anyway to exercise non-zero offsets).
			buf := make([]byte, mtu+2*inplaceScratch)
			off := inplaceScratch
			copy(buf[off:off+len(phyFrame)], phyFrame)

			// The reference PhyToVirt above already consumed this nonce in the
			// replay filter; reset it so the in-place decap of the identical
			// frame is accepted and we can compare output bytes.
			env.resetReplay(1)

			gotOff, gotLen := env.h.PhyToVirtInPlace(buf, off, len(phyFrame))
			require.Greater(t, gotLen, 0, "in-place decap should succeed")
			gotOut := buf[gotOff : gotOff+gotLen]

			if !bytes.Equal(gotOut, refOut) {
				t.Fatalf("decap byte mismatch (len got=%d ref=%d)\n got=%x\n ref=%x", gotLen, refLen, gotOut, refOut)
			}
		})
	}
}

// TestInPlaceToPhyByteEquivalence proves ToPhyInPlace (keep-alive) produces
// byte-identical output to the two-buffer ToPhy when both use the same pinned
// nonce, and that the keep-alive decaps as an authenticated out-of-band message.
func TestInPlaceToPhyByteEquivalence(t *testing.T) {
	for _, underlayV6 := range []bool{false, true} {
		underlayV6 := underlayV6
		name := "under4"
		if underlayV6 {
			name = "under6"
		}
		t.Run(name, func(t *testing.T) {
			tc := inplaceTestCase{underlayV6: underlayV6, innerV6: false, layer3: true, payloadLen: 1}
			interval := 10 * time.Second
			// newInplaceEnv does not set a keep-alive interval, so build a
			// dedicated handler that has one.
			env := newInplaceEnvKeepAlive(t, tc, interval)

			// Reference: two-buffer ToPhy with the counter pinned to 0.
			env.pinCounter(0)
			env.vnet.Stats.LastKeepAliveUnixNano.Store(0)
			refPhy := make([]byte, mtu+inplaceScratch)
			refLen := env.h.ToPhy(refPhy)
			require.Greater(t, refLen, 0, "reference keep-alive should be produced")
			refOut := append([]byte(nil), refPhy[:refLen]...)

			// In-place: pin the counter and the keep-alive timestamp identically.
			env.pinCounter(0)
			env.vnet.Stats.LastKeepAliveUnixNano.Store(0)
			buf := make([]byte, mtu+2*inplaceScratch)
			off := inplaceScratch
			gotOff, gotLen := env.h.ToPhyInPlace(buf, off)
			require.Greater(t, gotLen, 0, "in-place keep-alive should be produced")
			gotOut := buf[gotOff : gotOff+gotLen]

			if !bytes.Equal(gotOut, refOut) {
				t.Fatalf("keep-alive byte mismatch (len got=%d ref=%d)\n got=%x\n ref=%x", gotLen, refLen, gotOut, refOut)
			}

			// The keep-alive must decap as an out-of-band message (ProtocolType
			// 0): PhyToVirt returns 0 (drop) but increments RXPackets.
			before := env.vnet.Stats.RXPackets.Load()
			virtOut := make([]byte, mtu+inplaceScratch)
			m := env.h.PhyToVirt(append([]byte(nil), gotOut...), virtOut)
			require.Equal(t, 0, m, "keep-alive decap should return 0 (out-of-band)")
			require.Equal(t, before+1, env.vnet.Stats.RXPackets.Load(), "keep-alive should count as an RX packet")
		})
	}
}

// newInplaceEnvKeepAlive is like newInplaceEnv but configures a keep-alive
// interval on the handler.
func newInplaceEnvKeepAlive(t *testing.T, tc inplaceTestCase, interval time.Duration) *inplaceEnv {
	t.Helper()

	localAddr, remoteAddr := underlayAddrs(tc.underlayV6)

	h := newTestHandler(t,
		WithLocalAddr(localAddr),
		WithLayer3VirtFrames(),
		WithKeepAliveInterval(interval),
	)

	vni := uint(100)
	routes := []Route{{
		Src: netip.MustParsePrefix("10.0.1.0/24"),
		Dst: netip.MustParsePrefix("10.0.1.0/24"),
	}}
	key := generateKey(t)
	require.NoError(t, h.AddVirtualNetwork(vni, remoteAddr, routes))
	require.NoError(t, h.InstallKeysForTest(vni, 1, key, key, time.Now().Add(time.Hour)))
	vnet, ok := h.GetVirtualNetwork(vni)
	require.True(t, ok)

	return &inplaceEnv{
		h:          h,
		vni:        vni,
		vnet:       vnet,
		underlayV6: tc.underlayV6,
		layer3:     true,
	}
}
