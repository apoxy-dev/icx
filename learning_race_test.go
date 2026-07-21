package icx_test

// Race coverage for authenticated source learning (APO-740): concurrent RX
// queues learning from alternating outer sources while TX readers consume the
// endpoint. Run under -race: the invariant is simply that the atomic
// publish/load discipline holds — no torn endpoint, no data race — while the
// damping CAS elects learners among racing queues.

import (
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSourceLearningConcurrent(t *testing.T) {
	rx := newLearningReceiver(t, nil)
	sender := newLearningSender(t, net.IPv4(10, 0, 0, 2), 4321, learnKey)

	// Pre-seal frames from ONE sender so the shared replay window sees each
	// counter exactly once, then rewrite alternating outer sources to force
	// endpoint churn under load.
	const frames = 400
	sealed := make([][]byte, frames)
	for i := range sealed {
		sealed[i] = sealFrame(t, sender)
		if i%2 == 1 {
			rewriteOuterSrcIPv4(sealed[i], net.IPv4(10, 0, 0, 3), 9999)
		}
	}

	vnet, ok := rx.GetVirtualNetwork(learnVNI)
	require.True(t, ok)

	// Two RX queues splitting the frame list (out-of-order counters are fine:
	// the replay window accepts any fresh counter within its span), racing a TX
	// reader that consumes the endpoint until they finish.
	var rxWG sync.WaitGroup
	for q := range 2 {
		rxWG.Add(1)
		go func() {
			defer rxWG.Done()
			out := make([]byte, 2000)
			for i := q; i < frames; i += 2 {
				rx.PhyToVirt(sealed[i], out)
			}
		}()
	}

	// t.Errorf (not require.*) inside the goroutine: FailNow is only valid from
	// the test goroutine, per the repo's race-test convention.
	done := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		phy := make([]byte, 2000)
		for {
			select {
			case <-done:
				return
			default:
			}
			if remote := vnet.RemoteAddr(); remote != nil {
				// The endpoint must always be one of the two sources, whole.
				if remote.Port != 4321 && remote.Port != 9999 {
					t.Errorf("torn or foreign endpoint observed: %v port %d", remote.Addr, remote.Port)
					return
				}
			}
			rx.VirtToPhy(makeIPv4UDPPacket(), phy)
		}
	}()

	rxWG.Wait()
	close(done)
	readerWG.Wait()

	// Every frame authenticated, so an endpoint must have been learned.
	require.NotNil(t, vnet.RemoteAddr())
	require.NotZero(t, vnet.Stats.RXLearnedRemotes.Load())
}
