package icx

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// These tests are the APO-667 regression: the encap transforms must bound the inner
// IP packet so the ciphertext + AEAD tag cannot be sealed past the end of the
// destination buffer. The realistic overflow is by up to the tag length — an inner
// packet that nearly fills the frame leaves < tagLen bytes of tailroom, so the GCM
// tag spills past the frame edge. Each test gives the transform a buffer whose
// backing array continues past its length (the way a UMEM frame slice's backing
// array continues into the adjacent frame, and the shape an external EngineXfrm /
// vtep caller can pass) and plants a canary in that tail; the canary must remain
// untouched, i.e. the oversized packet must be dropped before Seal, not sealed over
// the neighbour.

// buildSizedInnerIPv4 builds a raw IPv4+UDP packet whose total length is exactly n
// bytes. Src/dst sit inside the test route prefixes so the encap trie lookup
// succeeds and execution reaches the seal-bound guard.
func buildSizedInnerIPv4(t *testing.T, src, dst netip.Addr, n int) []byte {
	t.Helper()
	require.GreaterOrEqual(t, n, header.IPv4MinimumSize+header.UDPMinimumSize,
		"requested inner packet smaller than an IPv4+UDP header")
	payload := make([]byte, n-header.IPv4MinimumSize-header.UDPMinimumSize)
	pkt := buildInnerIPv4Packet(src, dst, payload)
	require.Len(t, pkt, n)
	return pkt
}

// TestVirtToPhyInPlaceDropsOversizedInner covers the UMEM (in-place) encap path.
func TestVirtToPhyInPlaceDropsOversizedInner(t *testing.T) {
	env := newInplaceEnv(t, inplaceTestCase{layer3: true, payloadLen: 1})
	tagLen := env.vnet.txCipher.Load().Overhead()

	const (
		frameLen  = 2048
		canaryLen = 64
		off       = 96 // realistic RX headroom (>= minInPlaceHeadroom)
	)

	backing := make([]byte, frameLen+canaryLen)
	for i := frameLen; i < len(backing); i++ {
		backing[i] = 0xAB
	}
	buf := backing[:frameLen] // len == frameLen, cap == frameLen+canaryLen

	// ptLen is chosen so the inner packet still fits within the logical frame
	// (off+ptLen <= frameLen) but the tag does not (off+ptLen+tagLen > frameLen).
	ptLen := frameLen - off - tagLen + 8
	require.LessOrEqual(t, off+ptLen, frameLen, "inner packet itself must fit in the frame")
	require.Greater(t, off+ptLen+tagLen, frameLen, "tag must overflow the frame edge")

	inner := buildSizedInnerIPv4(t, env.innerSrc, env.innerDst, ptLen)
	copy(buf[off:], inner)

	before := env.vnet.Stats.TXErrors.Load()
	gotOff, gotLen, handled := env.h.VirtToPhyInPlace(buf, off, len(inner))

	require.False(t, handled)
	require.Equal(t, 0, gotLen, "oversized inner packet must be dropped")
	require.Equal(t, dropWindowOffset, gotOff)
	require.Equal(t, before+1, env.vnet.Stats.TXErrors.Load(), "drop must count as a TX error")

	for i := frameLen; i < len(backing); i++ {
		require.Equalf(t, byte(0xAB), backing[i],
			"byte %d past the frame was overwritten — Seal overflowed into the adjacent UMEM frame", i)
	}
}

// TestVirtToPhyInPlaceAcceptsMaxSizedInner pins the boundary: the largest inner
// packet whose ciphertext+tag exactly reaches the frame edge must still encapsulate
// (the guard rejects only strictly-past-the-edge, no off-by-one).
func TestVirtToPhyInPlaceAcceptsMaxSizedInner(t *testing.T) {
	env := newInplaceEnv(t, inplaceTestCase{layer3: true, payloadLen: 1})
	tagLen := env.vnet.txCipher.Load().Overhead()

	const (
		frameLen = 2048
		off      = 96
	)
	maxPtLen := frameLen - off - tagLen // off+maxPtLen+tagLen == frameLen exactly

	buf := make([]byte, frameLen)
	inner := buildSizedInnerIPv4(t, env.innerSrc, env.innerDst, maxPtLen)
	copy(buf[off:], inner)

	gotOff, gotLen, handled := env.h.VirtToPhyInPlace(buf, off, len(inner))
	require.False(t, handled)
	require.Greater(t, gotLen, 0, "the max-sized inner packet must still encapsulate")
	require.GreaterOrEqual(t, gotOff, 0)
	require.LessOrEqual(t, gotOff+gotLen, frameLen, "output must stay within the frame")
}

// TestVirtToPhyDropsOversizedInner covers the two-buffer (copy) encap path.
func TestVirtToPhyDropsOversizedInner(t *testing.T) {
	env := newInplaceEnv(t, inplaceTestCase{layer3: true, payloadLen: 1})
	tagLen := env.vnet.txCipher.Load().Overhead()

	const (
		phyLen    = 2048
		canaryLen = 64
	)
	payloadOff := header.EthernetMinimumSize + header.IPv4MinimumSize + header.UDPMinimumSize // IPv4 underlay

	backing := make([]byte, phyLen+canaryLen)
	for i := phyLen; i < len(backing); i++ {
		backing[i] = 0xCD
	}
	phyFrame := backing[:phyLen] // len == phyLen, cap == phyLen+canaryLen

	// Size the inner packet so hdr(32)+ptLen+tag just exceeds the available payload
	// room (phyLen-payloadOff), forcing the tag past the frame edge.
	ptLen := phyLen - payloadOff - geneveHdrLen - tagLen + 8
	inner := buildSizedInnerIPv4(t, env.innerSrc, env.innerDst, ptLen)

	before := env.vnet.Stats.TXErrors.Load()
	gotLen, handled := env.h.VirtToPhy(inner, phyFrame)

	require.False(t, handled)
	require.Equal(t, 0, gotLen, "oversized inner packet must be dropped")
	require.Equal(t, before+1, env.vnet.Stats.TXErrors.Load(), "drop must count as a TX error")

	for i := phyLen; i < len(backing); i++ {
		require.Equalf(t, byte(0xCD), backing[i],
			"byte %d past phyFrame was overwritten — Seal overflowed the destination buffer", i)
	}
}
