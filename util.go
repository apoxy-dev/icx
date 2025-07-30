package icx

import (
	"crypto/aes"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// MTU returns the maximum transmission unit for a virtual network.
func MTU(pathMTU int) int {
	mtu := pathMTU - header.IPv6MinimumSize - header.UDPMinimumSize - HeaderSize - aes.BlockSize
	// Round to nearest whole AES block (16 bytes)
	if mtu%aes.BlockSize != 0 {
		mtu -= mtu % aes.BlockSize
	}
	return mtu
}
