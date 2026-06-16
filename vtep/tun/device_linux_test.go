//go:build linux

package tun

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/apoxy-dev/icx"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// TestOpenRealDeviceSmoke exercises the real /dev/net/tun device-creation glue:
// CreateTUN + offload-disable + netlink addr/route/MTU + the UDP underlay bind,
// then a Run/Close lifecycle. It requires NET_ADMIN and /dev/net/tun, so it skips
// in unprivileged CI; the datapath logic itself is covered cross-platform by
// TestDatapathIntegrationRoundTrip.
func TestOpenRealDeviceSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (NET_ADMIN + /dev/net/tun)")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skipf("no /dev/net/tun: %v", err)
	}

	h, err := icx.NewHandler(
		icx.WithLocalAddr(&tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), Port: 6081}),
		icx.WithLayer3VirtFrames(),
	)
	require.NoError(t, err)

	dp, err := Open(OpenConfig{
		Engine:       h,
		Name:         "", // let the kernel pick a free name
		OverlayAddrs: []netip.Prefix{netip.MustParsePrefix("192.168.77.1/24")},
		// Route both the connected prefix (which assigning the OverlayAddr already
		// auto-installs — exercises the idempotent RouteReplace path) and a distinct
		// remote overlay prefix (the realistic backplane shape).
		Routes: []netip.Prefix{
			netip.MustParsePrefix("192.168.77.0/24"),
			netip.MustParsePrefix("10.99.0.0/24"),
		},
		InnerMTU:     defaultInnerMTU,
		UnderlayBind: netip.MustParseAddrPort("127.0.0.1:0"),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dp.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()
	require.NoError(t, dp.Close())

	select {
	case err := <-done:
		require.NoError(t, err, "Run must shut down cleanly")
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after Close")
	}
}
