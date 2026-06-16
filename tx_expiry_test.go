package icx_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"
)

// APO-656 (S13): once the transmit SA's key expires, the TX path must fail closed
// — drop the frame and charge TXDropsExpiredKey — rather than keep sealing
// indefinitely under a stale key. RX already enforces expiry; this makes the
// guarantee symmetric. Driven by a fake clock so expiry is deterministic.
func TestTXDropsOnExpiredKey(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	local, remote := addr("10.0.0.1"), addr("10.0.0.2")

	h, err := icx.NewHandler(
		icx.WithLocalAddr(&tcpip.FullAddress{Addr: local, Port: 6081}),
		icx.WithLayer3VirtFrames(),
		icx.WithClock(clk),
		icx.WithKeepAliveInterval(25*time.Second),
	)
	require.NoError(t, err)
	require.NoError(t, h.AddVirtualNetwork(rxHardenVNI, &tcpip.FullAddress{Addr: remote, Port: 6081}, wildcardRoutes()))
	// Install with an expiry one hour ahead of the (fake) clock.
	require.NoError(t, h.InstallKeysForTest(rxHardenVNI, 1, sharedKey(), sharedKey(), clk.now.Add(time.Hour)))

	inner := innerIPv4(netip.MustParseAddr("10.0.1.5"), netip.MustParseAddr("10.0.1.6"))
	phy := make([]byte, 2048)

	vnet, ok := h.GetVirtualNetwork(rxHardenVNI)
	require.True(t, ok)

	// Before expiry: TX seals normally.
	n, loop := h.VirtToPhy(inner, phy)
	require.NotZero(t, n, "TX must seal while the key is valid")
	require.False(t, loop)
	require.Zero(t, vnet.Stats.TXDropsExpiredKey.Load())

	// Advance past expiry: data-path TX fails closed.
	clk.Advance(2 * time.Hour)
	n, loop = h.VirtToPhy(inner, phy)
	require.Zero(t, n, "TX must drop once the key has expired")
	require.False(t, loop)
	require.Equal(t, uint64(1), vnet.Stats.TXDropsExpiredKey.Load(), "drop is attributed to TX key expiry")

	// Keep-alives (ToPhy) fail closed under the same expired key, too. The network is
	// due a keep-alive (none sent yet), so ToPhy reaches — and is stopped by — the
	// expiry gate rather than returning early.
	require.Zero(t, h.ToPhy(phy), "keep-alive must not seal under an expired key")
	require.Equal(t, uint64(2), vnet.Stats.TXDropsExpiredKey.Load(), "keep-alive expiry drop is counted too")
}
