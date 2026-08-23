//go:build linux

package forwarder_test

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/apoxy-dev/icx/permissions"
)

// requireForwarderEnv skips the test when the host cannot run the AF_XDP
// datapath. The forwarder needs NET_ADMIN to create veth pairs and load the
// XDP program, and a kernel with CONFIG_XDP_SOCKETS to bind AF_XDP sockets.
// Some CI runner kernels (for example the Blacksmith arm64 image) ship
// without AF_XDP, and the test must skip there instead of fail.
func requireForwarderEnv(t *testing.T) {
	t.Helper()
	netAdmin, _ := permissions.IsNetAdmin()
	if !netAdmin {
		t.Skip("Skipping test because it requires NET_ADMIN capabilities")
	}
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		t.Skipf("AF_XDP socket() unavailable on this kernel: %v", err)
	}
	_ = unix.Close(fd)
}
