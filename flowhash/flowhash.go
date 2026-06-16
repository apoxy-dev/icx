package flowhash

import (
	"bytes"
	"log/slog"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// FNV-1a 64-bit constants. The flow hash steers ECMP only; it is deliberately a
// fast NON-cryptographic hash, not a security primitive, and sits outside the
// FIPS crypto boundary.
const (
	fnvOffset uint64 = 14695981039346656037
	fnvPrime  uint64 = 1099511628211
)

// Hash computes a symmetric, keyed flow hash for the given IP packet. It returns a
// 16-bit value derived from the source/destination IP addresses and the L4
// source/destination ports (for TCP/UDP), or the protocol number otherwise,
// canonicalized so the two directions of a flow hash identically (stable ECMP). If
// the packet is invalid or the IP version unsupported it returns 0.
//
// key is a per-session secret mixed into the hash: it makes the resulting outer
// UDP source port no longer a public function of the inner 5-tuple, so an off-path
// observer cannot fingerprint or correlate inner flows from it (APO-661). Both
// directions on one handler share the key, preserving the symmetric ECMP property
// within a session while denying an outsider the mapping.
func Hash(key uint64, ipPacket []byte) uint16 {
	// Assemble the canonical 5-tuple bytes into a stack buffer (no heap alloc): up
	// to 32 bytes of address (IPv6 src+dst) plus 4 bytes of ports.
	var buf [36]byte
	n := 0

	var protoNumber uint8
	var payload []byte

	ipVersion := ipPacket[0] >> 4

	switch ipVersion {
	case 4: // IPv4
		ip := header.IPv4(ipPacket)
		if !ip.IsValid(len(ip)) {
			slog.Warn("Invalid IPv4 header, skipping flow hash calculation")
			return 0
		}
		srcIP := ipPacket[12:16]
		dstIP := ipPacket[16:20]

		if bytes.Compare(srcIP, dstIP) <= 0 {
			n += copy(buf[n:], ipPacket[12:20])
		} else {
			n += copy(buf[n:], dstIP)
			n += copy(buf[n:], srcIP)
		}

		protoNumber = ip.Protocol()
		payload = ip.Payload()
	case 6: // IPv6
		ip := header.IPv6(ipPacket)
		if !ip.IsValid(len(ip)) {
			slog.Warn("Invalid IPv6 header, skipping flow hash calculation")
			return 0
		}
		srcIP := ipPacket[8:24]
		dstIP := ipPacket[24:40]

		if bytes.Compare(srcIP, dstIP) <= 0 {
			n += copy(buf[n:], ipPacket[8:40])
		} else {
			n += copy(buf[n:], dstIP)
			n += copy(buf[n:], srcIP)
		}

		protoNumber = ip.NextHeader()
		payload = ip.Payload()
	default:
		slog.Debug("Unsupported IP version, skipping flow hash calculation")
		return 0
	}

	switch protoNumber {
	case uint8(header.TCPProtocolNumber), uint8(header.UDPProtocolNumber):
		srcPort := payload[:2]
		dstPort := payload[2:4]

		if bytes.Compare(srcPort, dstPort) <= 0 {
			n += copy(buf[n:], payload[:4])
		} else {
			n += copy(buf[n:], dstPort)
			n += copy(buf[n:], srcPort)
		}
	default:
		buf[n] = protoNumber
		n++
	}

	return uint16(hash64(key, buf[:n]))
}

// hash64 is FNV-1a with its offset basis perturbed by a secret key. FNV-1a's
// multiply step is non-linear, so — unlike the previous CRC32, whose affinity let
// an observer solve for the seed from a single (input, output) sample — the keyed
// mapping cannot be reproduced without the key.
func hash64(key uint64, b []byte) uint64 {
	h := fnvOffset ^ key
	for _, c := range b {
		h ^= uint64(c)
		h *= fnvPrime
	}
	return h
}

// MapToEphemeralPort maps a given hash value to the ephemeral port range (49152-65535).
func MapToEphemeralPort(hash uint16) uint16 {
	const (
		ephemeralMin = 49152
		ephemeralMax = 65535
	)

	span := uint32(ephemeralMax-ephemeralMin) + 1
	return uint16(uint32(ephemeralMin) + (uint32(hash) % span))
}
