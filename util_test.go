package icx

import (
	"crypto/aes"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// TestHeaderLengthCountsAllOptions is the APO-665 regression: headerLength() must
// marshal the full 2-option Geneve header (geneveHdrLen = 32 bytes), not the 8-byte
// base. The bug was a missing NumOptions on the header literal, which made
// MarshalBinary skip both options and report only the base length — undercounting
// encapsulation overhead by 24 bytes and inflating the MTU advertised by MTU().
func TestHeaderLengthCountsAllOptions(t *testing.T) {
	got := headerLength()
	if got != geneveHdrLen {
		t.Fatalf("headerLength() = %d, want %d (the fixed 2-option header); "+
			"encap overhead is undercounted by %d bytes", got, geneveHdrLen, geneveHdrLen-got)
	}
}

// TestMTUDeductsFullEncapOverhead asserts MTU() subtracts the complete outer
// encapsulation stack — including the full 32-byte Geneve header — and rounds down
// to a whole AES block. Before the APO-665 fix the Geneve term was 8 instead of 32,
// so MTU() over-advertised by 24 bytes and the inner stack could emit packets whose
// encapsulated size exceeded the path MTU (fragmentation / black-holing).
func TestMTUDeductsFullEncapOverhead(t *testing.T) {
	const pathMTU = 1500
	overhead := header.IPv6MinimumSize + header.UDPMinimumSize + geneveHdrLen + aes.BlockSize
	want := pathMTU - overhead
	want -= want % aes.BlockSize

	if got := MTU(pathMTU); got != want {
		t.Fatalf("MTU(%d) = %d, want %d (deducting %d bytes of overhead)", pathMTU, got, want, overhead)
	}
}
