package icx

import (
	"testing"

	"github.com/apoxy-dev/icx/geneve"
)

// TestGeneveHdrLenMatchesConstant pins the assumption baked into the in-place
// encap: the handler's fixed 2-option Geneve header (8 base + 8 epoch + 16
// txcounter) marshals to exactly geneveHdrLen (32) bytes. VirtToPhyInPlace
// computes geneveStart = ipStart - geneveHdrLen BEFORE marshalling, so if the
// geneve package ever changes the option encoding or alignment, the headroom
// math would be off and the runtime length check (hdrLen != geneveHdrLen) would
// silently drop every encapsulated frame. This turns that drift into a build
// failure instead. The header is constructed exactly as VirtToPhyInPlace builds
// it (inplace_transform.go).
func TestGeneveHdrLenMatchesConstant(t *testing.T) {
	hdr := geneve.Header{
		NumOptions: 2,
		Critical:   true,
		Options: [geneve.MaxOptions]geneve.Option{
			{Class: geneve.ClassExperimental, Type: geneve.OptionTypeKeyEpoch, Length: 1},
			{Class: geneve.ClassExperimental, Type: geneve.OptionTypeTxCounter, Length: 3},
		},
	}

	buf := make([]byte, 64)
	n, err := hdr.MarshalBinary(buf)
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if n != geneveHdrLen {
		t.Fatalf("geneve header marshalled to %d bytes, but geneveHdrLen = %d; "+
			"in-place encap headroom math is wrong", n, geneveHdrLen)
	}
}
