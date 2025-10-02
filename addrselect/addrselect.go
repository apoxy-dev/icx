package addrselect

import (
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
)

type AddressList []*tcpip.FullAddress

// Pick chooses the best local underlay address for a given remote underlay address.
func (l AddressList) Pick(remote *tcpip.FullAddress) *tcpip.FullAddress {
	if len(l) == 0 || remote == nil {
		return nil
	}

	remoteIP, ok := netip.AddrFromSlice(remote.Addr.AsSlice())
	if !ok {
		return l[0]
	}

	// Filter by address family (IPv4/IPv6).
	cands := make([]*tcpip.FullAddress, 0, len(l))
	needV4 := remoteIP.Is4()
	for _, a := range l {
		if a == nil {
			continue
		}
		isV4 := a.Addr.Len() == net.IPv4len
		if isV4 == needV4 {
			cands = append(cands, a)
		}
	}

	if len(cands) == 0 {
		// No same-family address; fall back.
		return l[0]
	}
	if len(cands) == 1 {
		return cands[0]
	}

	// Among same-family candidates, pick the one with the longest common prefix.
	best := cands[0]
	bestLCP := -1
	remoteBytes := remoteIP.AsSlice()
	for _, a := range cands {
		localIP, ok := netip.AddrFromSlice(a.Addr.AsSlice())
		if !ok {
			continue
		}
		lcp := commonPrefixBits(remoteBytes, localIP.AsSlice())
		if lcp > bestLCP {
			bestLCP = lcp
			best = a
		}
	}
	return best
}

// commonPrefixBits returns the number of leading equal bits between a and b.
func commonPrefixBits(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	bits := 0
	for i := 0; i < n; i++ {
		if a[i] == b[i] {
			bits += 8
			continue
		}
		x := a[i] ^ b[i]
		// Count leading zeros in x (8-bit)
		for j := 7; j >= 0; j-- {
			if (x>>uint(j))&1 == 0 {
				bits++
			} else {
				return bits
			}
		}
	}
	return bits
}
