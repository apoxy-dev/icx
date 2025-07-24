package geneve_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx/geneve"
)

func TestGeneveHeaderMarshalUnmarshal(t *testing.T) {
	orig := geneve.Header{
		Version:      0x1,
		OAM:          true,
		Critical:     true,
		ProtocolType: uint16(header.IPv4ProtocolNumber),
		VNI:          0xABCDEF,
		NumOptions:   2,
		Options: [geneve.MaxOptions]geneve.Option{
			{
				Class:  0x0102,
				Type:   0x1,
				Length: 1,
				Value:  [geneve.MaxValueLength]byte{0xDE, 0xAD, 0xBE, 0xEF},
			},
			{
				Class:  0xFF00,
				Type:   0x2,
				Length: 2,
				Value:  [geneve.MaxValueLength]byte{0xBA, 0xAD, 0xF0, 0x0D, 0xBE, 0xEF, 0xCA, 0xFE},
			},
		},
	}

	// Allocate a large enough buffer
	buf := make([]byte, 128)
	n, err := orig.MarshalBinary(buf)
	require.NoError(t, err)
	require.Greater(t, n, 0)

	// Unmarshal into a new header
	var decoded geneve.Header
	n, err = decoded.UnmarshalBinary(buf[:n])
	require.NoError(t, err)
	require.Greater(t, n, 0)

	// Check fixed header fields
	require.Equal(t, orig.Version, decoded.Version)
	require.Equal(t, orig.OAM, decoded.OAM)
	require.Equal(t, orig.Critical, decoded.Critical)
	require.Equal(t, orig.ProtocolType, decoded.ProtocolType)
	require.Equal(t, orig.VNI, decoded.VNI)
	require.Equal(t, orig.NumOptions, decoded.NumOptions)

	// Check options
	for i := 0; i < orig.NumOptions; i++ {
		want := orig.Options[i]
		got := decoded.Options[i]
		require.Equal(t, want.Class, got.Class)
		require.Equal(t, want.Type, got.Type)
		require.Equal(t, want.Value, got.Value)
	}
}
