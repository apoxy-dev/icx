package udp_test

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx/udp"
)

func TestEncodeDecode_IPv4(t *testing.T) {
	const frameSize = 1500
	const payloadText = "Hello, UDP over Ethernet!"

	src := tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 1).To4()),
		Port:     12345,
		LinkAddr: tcpip.GetRandMacAddr(),
	}
	dst := tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 2).To4()),
		Port:     54321,
		LinkAddr: tcpip.GetRandMacAddr(),
	}

	payload := []byte(payloadText)

	t.Run("Valid", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv4:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), false)
		require.NoError(t, err)

		var decodedAddr tcpip.FullAddress
		decodedPayload, err := udp.Decode(frame[:n], &decodedAddr, false)
		require.NoError(t, err)
		require.Equal(t, src.Addr.String(), decodedAddr.Addr.String())
		require.Equal(t, src.Port, decodedAddr.Port)
		require.Equal(t, payload, decodedPayload)
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv4:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), false)
		require.NoError(t, err)

		// Corrupt the first byte of the payload
		frame[udp.PayloadOffsetIPv4] ^= 0xFF

		_, err = udp.Decode(frame[:n], nil, false)
		require.Error(t, err)
	})
}

func TestEncodeDecode_IPv6(t *testing.T) {
	const frameSize = 1500
	const payloadText = "Hello, UDP over Ethernet!"

	src := tcpip.FullAddress{
		Addr:     tcpip.AddrFrom16Slice(net.ParseIP("2001:db8::1").To16()),
		Port:     12345,
		LinkAddr: tcpip.GetRandMacAddr(),
	}
	dst := tcpip.FullAddress{
		Addr:     tcpip.AddrFrom16Slice(net.ParseIP("2001:db8::2").To16()),
		Port:     54321,
		LinkAddr: tcpip.GetRandMacAddr(),
	}

	payload := []byte(payloadText)

	t.Run("Valid", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv6:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), false)
		require.NoError(t, err)

		var decodedAddr tcpip.FullAddress
		decodedPayload, err := udp.Decode(frame[:n], &decodedAddr, false)
		require.NoError(t, err)
		require.Equal(t, src.Addr.String(), decodedAddr.Addr.String())
		require.Equal(t, src.Port, decodedAddr.Port)
		require.Equal(t, payload, decodedPayload)
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv6:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), false)
		require.NoError(t, err)

		// Corrupt the first byte of the payload
		frame[udp.PayloadOffsetIPv6] ^= 0xFF

		_, err = udp.Decode(frame[:n], nil, false)
		require.Error(t, err)
	})
}

func BenchmarkEncode_IPv4(b *testing.B) {
	const payloadSize = 512

	src := tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 1).To4()),
		Port:     12345,
		LinkAddr: tcpip.GetRandMacAddr(),
	}

	dst := tcpip.FullAddress{
		Addr:     tcpip.AddrFrom4Slice(net.IPv4(192, 168, 1, 2).To4()),
		Port:     54321,
		LinkAddr: tcpip.GetRandMacAddr(),
	}

	frameSize := udp.PayloadOffsetIPv4 + payloadSize
	frame := make([]byte, frameSize)

	_, err := rand.Read(frame[udp.PayloadOffsetIPv4 : udp.PayloadOffsetIPv4+payloadSize])
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := udp.Encode(frame, &src, &dst, payloadSize, true)
		if err != nil {
			b.Fatalf("failed to encode: %v", err)
		}
	}
}

func BenchmarkEncode_IPv6(b *testing.B) {
	const payloadSize = 512

	src := tcpip.FullAddress{
		Addr:     tcpip.AddrFrom16Slice(net.ParseIP("2001:db8::1").To16()),
		Port:     12345,
		LinkAddr: tcpip.GetRandMacAddr(),
	}

	dst := tcpip.FullAddress{
		Addr:     tcpip.AddrFrom16Slice(net.ParseIP("2001:db8::2").To16()),
		Port:     54321,
		LinkAddr: tcpip.GetRandMacAddr(),
	}

	frameSize := udp.PayloadOffsetIPv6 + payloadSize
	frame := make([]byte, frameSize)

	_, err := rand.Read(frame[udp.PayloadOffsetIPv6 : udp.PayloadOffsetIPv6+payloadSize])
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := udp.Encode(frame, &src, &dst, payloadSize, true)
		if err != nil {
			b.Fatalf("failed to encode: %v", err)
		}
	}
}

// TestDecodeMalformedNoPanic pins the fix for a remote-triggerable panic: a
// frame whose IP header is valid but declares a UDP payload shorter than the
// 8-byte UDP header made header.UDP accessors index past the slice and panic
// ([8:4]). Decode must return an error, never panic. (Found by the in-place
// transform differential fuzzer.)
func TestDecodeMalformedNoPanic(t *testing.T) {
	cases := map[string][]byte{
		// EtherType IPv6, next-header UDP (0x11), IP payloadLength = 4 (< 8),
		// followed by only 4 bytes — the exact frame the fuzzer minimized to.
		"ipv6 udp payload len 4": []byte("000000000000\x86\xdda000\x00\x04\x110000000000000000000000000000000000000"),
		// Truncated to just under an Ethernet header.
		"runt": make([]byte, 8),
		// Ethernet header only, IPv4 ethertype, no IP header.
		"eth only ipv4": append(make([]byte, 12), 0x08, 0x00),
		// Ethernet header only, IPv6 ethertype, no IP header.
		"eth only ipv6": append(make([]byte, 12), 0x86, 0xdd),
		"empty":         {},
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := udp.Decode(frame, nil, true)
				require.Error(t, err)
			})
		})
	}
}
