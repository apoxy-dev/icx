//go:build linux

package permissions

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

func IsNetAdmin() (bool, error) {
	// Check if we are running as root
	if unix.Geteuid() == 0 {
		return true, nil
	}

	// Get the current process's capabilities
	var capData unix.CapUserData
	var capHeader unix.CapUserHeader

	// Set the version to the latest version
	capHeader.Version = unix.LINUX_CAPABILITY_VERSION_3

	// Get capabilities
	err := unix.Capget(&capHeader, &capData)
	if err != nil {
		return false, fmt.Errorf("failed to get capabilities: %v", err)
	}

	// Check if the NET_ADMIN capability is present
	netAdminMask := uint32(1) << (linux.CAP_NET_ADMIN % 32)
	if capData.Effective&(netAdminMask) != 0 {
		return true, nil
	}

	return false, nil
}
