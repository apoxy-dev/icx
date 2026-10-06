//go:build linux

package filter

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// requireLoad fails the test with the full verifier log when a program did
// not load. A process with no rights to load BPF programs gets skipOrFail.
func requireLoad(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.EPERM) {
		skipOrFail(t, "cannot load BPF programs: %v", err)
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		t.Fatalf("the kernel rejects the program: %v\n%+v", err, ve)
	}
	require.NoError(t, err)
}

// loadChain loads a relay program and puts it behind a Geneve program, where
// the kernel checks it again.
func loadChain(t *testing.T, cfg RelayConfig) error {
	r, err := NewRelay(cfg)
	if err != nil {
		return err
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := noXSK(); err != nil {
		t.Logf("the relay program does not go behind the Geneve program: the kernel has no AF_XDP sockets: %v", err)
		return nil
	}
	g, err := Geneve()
	if err != nil {
		return err
	}
	t.Cleanup(func() { _ = g.Close() })
	return g.Chain(r.Program())
}

// TestProgramsLoad loads each program in each build that the loaders can ask
// for. The kernel test of the CI runs it on each kernel that icx supports.
func TestProgramsLoad(t *testing.T) {
	type loadCase struct {
		name string
		// load loads the programs of the case. They close with the test.
		load func(t *testing.T) error
	}
	closeWith := func(t *testing.T, p *Program, err error) error {
		if err == nil {
			t.Cleanup(func() { _ = p.Close() })
		}
		return err
	}
	cases := []loadCase{
		{"all", func(t *testing.T) error {
			needXSK(t)
			p, err := All()
			return closeWith(t, p, err)
		}},
		{"geneve", func(t *testing.T) error {
			needXSK(t)
			p, err := Geneve(
				&net.UDPAddr{IP: relay4.AsSlice(), Port: relayPort},
				&net.UDPAddr{IP: relay6.AsSlice(), Port: relayPort},
			)
			return closeWith(t, p, err)
		}},
	}

	meters := []struct {
		name string
		cfg  RelayConfig
	}{
		{"no meter", RelayConfig{}},
		{"lane meter", RelayConfig{LaneRate: 1e6, LaneBurst: 1e5}},
		{"tunnel limit", RelayConfig{TunnelRate: 1e6, TunnelBurst: 1e5}},
		{"lane meter and tunnel limit", RelayConfig{LaneRate: 1e6, LaneBurst: 1e5, TunnelRate: 1e6, TunnelBurst: 1e5}},
	}
	sends := []struct {
		name     string
		redirect bool
	}{
		{"XDP_TX", false},
		{"redirect", true},
	}
	hops := []struct {
		name  string
		cache time.Duration
	}{
		{"route lookup", 0},
		{"next hop cache", time.Second},
	}
	for _, m := range meters {
		for _, s := range sends {
			for _, h := range hops {
				cfg := m.cfg
				cfg.Port, cfg.MaxLen = relayPort, testMaxLen
				cfg.Redirect, cfg.NextHopCache = s.redirect, h.cache
				cases = append(cases, loadCase{
					"relay/" + m.name + "/" + s.name + "/" + h.name,
					func(t *testing.T) error { return loadChain(t, cfg) },
				})
			}
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { requireLoad(t, tc.load(t)) })
	}
}
