//go:build linux

package filter

import (
	"errors"
	"net"
	"testing"

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

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { requireLoad(t, tc.load(t)) })
	}
}
