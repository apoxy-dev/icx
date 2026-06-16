package icx_test

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"
)

// APO-652 (S9): the RX validation path reads a virtual network's allowed routes
// per packet with no lock, while UpdateVirtualNetworkRoutes replaces them. Once
// the field is published through an atomic.Pointer the two no longer race on the
// slice header. This stresses that pairing — concurrent accessor reads against a
// writer swapping the route set — and is meaningful only under `go test -race`.
func TestAllowedRoutesConcurrentUpdateNoRace(t *testing.T) {
	local, remote := addr("10.0.0.1"), addr("10.0.0.2")
	h, err := icx.NewHandler(
		icx.WithLocalAddr(&tcpip.FullAddress{Addr: local, Port: 6081}),
		icx.WithLayer3VirtFrames(),
	)
	require.NoError(t, err)
	require.NoError(t, h.AddVirtualNetwork(rxHardenVNI, &tcpip.FullAddress{Addr: remote, Port: 6081}, wildcardRoutes()))

	vnet, ok := h.GetVirtualNetwork(rxHardenVNI)
	require.True(t, ok)

	sets := [][]icx.Route{
		{{Src: netip.MustParsePrefix("10.0.1.0/24"), Dst: netip.MustParsePrefix("10.0.1.0/24")}},
		{{Src: netip.MustParsePrefix("10.0.2.0/24"), Dst: netip.MustParsePrefix("10.0.2.0/24")}},
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers mimic the RX hot path: load and iterate the route snapshot.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					for _, r := range vnet.AllowedRoutes() {
						_ = r.Src.Contains(netip.MustParseAddr("10.0.1.5"))
					}
				}
			}
		}()
	}

	// Writer swaps the whole route set repeatedly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			if err := h.UpdateVirtualNetworkRoutes(rxHardenVNI, sets[i%len(sets)]); err != nil {
				t.Errorf("UpdateVirtualNetworkRoutes: %v", err)
				break
			}
		}
		close(stop)
	}()

	wg.Wait()
}
