package flowhash

import (
	"bytes"
	"hash/crc32"
	"log/slog"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// So we can take advantage of hardware-accelerated CRC32 instructions.
var table = crc32.MakeTable(crc32.Castagnoli)

// FlowHash computes a symmetric flow hash for the given Ethernet type and data.
// It returns a 32-bit hash value based on the source and destination IP addresses,
// source and destination ports (for TCP/UDP), and the protocol number for other protocols.
// If the data is invalid or the Ethernet type is unsupported, it returns 0.
func Hash(data []byte) uint16 {
	var protoNumber uint8
	var payload []byte
	var crc uint32 = 0

	ipVersion := data[0] >> 4

	switch ipVersion {
	case 4: // IPv4
		ip := header.IPv4(data)
		if !ip.IsValid(len(ip)) {
			slog.Warn("Invalid IPv4 header, skipping flow hash calculation")
			return 0
		}
		srcIP := data[12:16]
		dstIP := data[16:20]

		if bytes.Compare(srcIP, dstIP) <= 0 {
			crc = crc32.Update(crc, table, data[12:20])
		} else {
			crc = crc32.Update(crc, table, dstIP)
			crc = crc32.Update(crc, table, srcIP)
		}

		protoNumber = ip.Protocol()
		payload = ip.Payload()
	case 6: // IPv6
		ip := header.IPv6(data)
		if !ip.IsValid(len(ip)) {
			slog.Warn("Invalid IPv6 header, skipping flow hash calculation")
			return 0
		}
		srcIP := data[8:24]
		dstIP := data[24:40]

		if bytes.Compare(srcIP, dstIP) <= 0 {
			crc = crc32.Update(crc, table, data[8:40])
		} else {
			crc = crc32.Update(crc, table, dstIP)
			crc = crc32.Update(crc, table, srcIP)
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
			crc = crc32.Update(crc, table, payload[:4])
		} else {
			crc = crc32.Update(crc, table, dstPort)
			crc = crc32.Update(crc, table, srcPort)
		}
	default:
		crc = crc32.Update(crc, table, []byte{protoNumber})
	}

	return uint16(crc & 0xFFFF)
}
