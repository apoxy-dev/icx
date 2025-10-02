package addrselect_test

import (
	"net"
	"testing"

	"github.com/apoxy-dev/icx/addrselect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func fa(s string) *tcpip.FullAddress {
	ip := net.ParseIP(s)
	if ip == nil {
		return &tcpip.FullAddress{}
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // ensure 4-byte form for IPv4
	}
	return &tcpip.FullAddress{Addr: tcpip.AddrFromSlice(ip)}
}

func TestPick(t *testing.T) {
	t.Run("empty list returns nil", func(t *testing.T) {
		var l addrselect.AddressList
		got := l.Pick(fa("10.0.0.1"))
		assert.Nil(t, got)
	})

	t.Run("nil remote returns nil", func(t *testing.T) {
		l := addrselect.AddressList{fa("10.0.0.1")}
		got := l.Pick(nil)
		assert.Nil(t, got)
	})

	t.Run("family filter IPv4 only with best prefix", func(t *testing.T) {
		remote := fa("192.168.1.77")

		best := fa("192.168.1.1") // longest common prefix with remote
		v4other := fa("10.0.0.1")
		v6 := fa("2001:db8::1")

		l := addrselect.AddressList{v6, v4other, best}
		got := l.Pick(remote)
		require.NotNil(t, got)
		assert.Same(t, best, got)
	})

	t.Run("family filter IPv6 only with best prefix", func(t *testing.T) {
		remote := fa("2001:db8:abcd::42")

		v4 := fa("172.16.0.1")
		best := fa("2001:db8:abcd::1")
		v6other := fa("2001:db8:ffff::1")

		l := addrselect.AddressList{v4, v6other, best}
		got := l.Pick(remote)
		require.NotNil(t, got)
		assert.Same(t, best, got)
	})

	t.Run("no same-family candidates falls back to first", func(t *testing.T) {
		remote := fa("2001:db8::99")
		first := fa("10.0.0.1")
		l := addrselect.AddressList{first, fa("10.0.0.2")}

		got := l.Pick(remote)
		require.NotNil(t, got)
		assert.Same(t, first, got)
	})

	t.Run("single candidate after family filter is returned", func(t *testing.T) {
		remote := fa("fd00::abcd")
		onlyV6 := fa("fd00::1")
		l := addrselect.AddressList{fa("192.168.1.1"), onlyV6}

		got := l.Pick(remote)
		require.NotNil(t, got)
		assert.Same(t, onlyV6, got)
	})

	t.Run("tie on longest common prefix keeps earliest candidate", func(t *testing.T) {
		remote := fa("10.1.2.3")
		// Both share the same prefix length with remote ("10.1" -> 16 bits)
		first := fa("10.1.9.9")
		second := fa("10.1.200.200")
		l := addrselect.AddressList{first, second, fa("192.168.0.1")}

		got := l.Pick(remote)
		require.NotNil(t, got)
		assert.Same(t, first, got, "stable tie-break should keep the first best candidate")
	})
}
