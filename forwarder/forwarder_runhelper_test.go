//go:build linux

package forwarder_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/apoxy-dev/icx/forwarder"
)

// runForwarder starts fwd under a cancellable context and registers a cleanup
// that cancels it and waits for Start to return. Start owns teardown: after its
// per-queue goroutines stop (g.Wait) it self-closes the forwarder, so the sockets
// and UMEMs are torn down only once nothing is still touching them.
//
// Tests must NOT instead call fwd.Close() from a t.Cleanup while Start is running:
// that munmaps the rings and closes the sockets WHILE the per-queue
// poll()/forwardInPlace goroutines are still reading them — a data race the -race
// detector flags and a real use-after-free. The single-queue tests hid it (one
// goroutine, usually already exited by cleanup time); the multiqueue datapath
// makes the overlap reliable. Production never hits it (cli drives Start via the
// vtep seam and never calls Close concurrently — Start self-closes on return).
func runForwarder(t *testing.T, fwd *forwarder.Forwarder) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fwd.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("forwarder Start returned error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("forwarder did not shut down within 5s of context cancel")
		}
	})
}
