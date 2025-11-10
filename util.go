package icx

import (
	"crypto/aes"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx/geneve"
)

// MTU returns the maximum transmission unit for a virtual network.
func MTU(pathMTU int) int {
	mtu := pathMTU - header.IPv6MinimumSize - header.UDPMinimumSize - headerLength() - aes.BlockSize
	// Round to nearest whole AES block (16 bytes)
	if mtu%aes.BlockSize != 0 {
		mtu -= mtu % aes.BlockSize
	}
	return mtu
}

// Calculate Geneve header length with our full set of options.
func headerLength() int {
	hdr := geneve.Header{
		Options: [geneve.MaxOptions]geneve.Option{
			{
				Class:  geneve.ClassExperimental,
				Type:   geneve.OptionTypeKeyEpoch,
				Length: 1,
			},
			{
				Class:  geneve.ClassExperimental,
				Type:   geneve.OptionTypeTxCounter,
				Length: 3,
			},
		},
	}

	payload := make([]byte, 1500)
	hdrLen, err := hdr.MarshalBinary(payload)
	if err != nil {
		panic("failed to marshal Geneve header for MTU calculation")
	}

	return hdrLen
}
