//go:build linux

package forwarder

import (
	"testing"

	"github.com/apoxy-dev/icx/internal/xsk"
)

// TestWithBusyPollPlumbing checks that WithBusyPoll records the timeout/budget and
// that both socket-option builders propagate them, while preserving the
// shared-UMEM copy-mode invariant: only the phy socket forces XDP_COPY.
func TestWithBusyPollPlumbing(t *testing.T) {
	var o forwarderOptions
	if err := WithBusyPoll(25, 8)(&o); err != nil {
		t.Fatalf("WithBusyPoll: %v", err)
	}
	if o.busyPoll != 25 || o.busyPollBudget != 8 {
		t.Fatalf("option fields = (%d,%d), want (25,8)", o.busyPoll, o.busyPollBudget)
	}

	f := &Forwarder{busyPoll: o.busyPoll, busyPollBudget: o.busyPollBudget}

	phy := f.phySockOpts()
	if phy.BusyPoll != 25 || phy.BusyPollBudget != 8 {
		t.Fatalf("phySockOpts busy poll = (%d,%d), want (25,8)", phy.BusyPoll, phy.BusyPollBudget)
	}
	if !phy.ForceCopy {
		t.Fatal("phySockOpts must keep ForceCopy (shared-UMEM requires the phy in copy mode)")
	}

	virt := f.virtSockOpts()
	if virt.BusyPoll != 25 || virt.BusyPollBudget != 8 {
		t.Fatalf("virtSockOpts busy poll = (%d,%d), want (25,8)", virt.BusyPoll, virt.BusyPollBudget)
	}
	if virt.ForceCopy {
		t.Fatal("virtSockOpts must NOT force copy (XDP_COPY on the shared bind is EINVAL)")
	}
}

// TestBusyPollDisabledByDefault asserts the default forwarder leaves busy poll
// off, so the existing (softirq-driven) datapath is unchanged unless opted in.
func TestBusyPollDisabledByDefault(t *testing.T) {
	var f Forwarder // zero value: busyPoll == 0
	if got := f.phySockOpts().BusyPoll; got != 0 {
		t.Fatalf("default phySockOpts BusyPoll = %d, want 0 (busy poll off)", got)
	}
	if got := f.virtSockOpts().BusyPoll; got != 0 {
		t.Fatalf("default virtSockOpts BusyPoll = %d, want 0 (busy poll off)", got)
	}
	// Sanity: DefaultBusyPollBudget only applies inside xsk when BusyPoll > 0.
	if xsk.DefaultBusyPollBudget <= 0 {
		t.Fatalf("DefaultBusyPollBudget = %d, want > 0", xsk.DefaultBusyPollBudget)
	}
}
