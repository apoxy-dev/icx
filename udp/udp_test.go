package udp_test

import (
	"crypto/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

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

		n, err := udp.Encode(frame, &src, &dst, len(payload), false, false)
		require.NoError(t, err)

		var decodedAddr tcpip.FullAddress
		decodedPayload, err := udp.Decode(frame[:n], &decodedAddr, false, false)
		require.NoError(t, err)
		require.Equal(t, src.Addr.String(), decodedAddr.Addr.String())
		require.Equal(t, src.Port, decodedAddr.Port)
		require.Equal(t, payload, decodedPayload)
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv4:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), false, false)
		require.NoError(t, err)

		// Corrupt the first byte of the payload
		frame[udp.PayloadOffsetIPv4] ^= 0xFF

		_, err = udp.Decode(frame[:n], nil, false, false)
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

		n, err := udp.Encode(frame, &src, &dst, len(payload), false, false)
		require.NoError(t, err)

		var decodedAddr tcpip.FullAddress
		decodedPayload, err := udp.Decode(frame[:n], &decodedAddr, false, false)
		require.NoError(t, err)
		require.Equal(t, src.Addr.String(), decodedAddr.Addr.String())
		require.Equal(t, src.Port, decodedAddr.Port)
		require.Equal(t, payload, decodedPayload)
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		frame := make([]byte, frameSize)
		copy(frame[udp.PayloadOffsetIPv6:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), false, false)
		require.NoError(t, err)

		// Corrupt the first byte of the payload
		frame[udp.PayloadOffsetIPv6] ^= 0xFF

		_, err = udp.Decode(frame[:n], nil, false, false)
		require.Error(t, err)
	})
}

func TestEncodeDecode_IPv4_Layer3(t *testing.T) {
	const frameSize = 1500
	const payloadText = "Hello, UDP over IPv4 Layer3!"

	src := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 1).To4()),
		Port: 1234,
	}
	dst := tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.IPv4(10, 0, 0, 2).To4()),
		Port: 4321,
	}

	payload := []byte(payloadText)

	t.Run("Valid", func(t *testing.T) {
		frame := make([]byte, frameSize)
		offset := header.IPv4MinimumSize + header.UDPMinimumSize
		copy(frame[offset:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), true, false)
		require.NoError(t, err)

		var decodedAddr tcpip.FullAddress
		decodedPayload, err := udp.Decode(frame[:n], &decodedAddr, true, false)
		require.NoError(t, err)
		require.Equal(t, src.Addr.String(), decodedAddr.Addr.String())
		require.Equal(t, src.Port, decodedAddr.Port)
		require.Equal(t, payload, decodedPayload)
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		frame := make([]byte, frameSize)
		offset := header.IPv4MinimumSize + header.UDPMinimumSize
		copy(frame[offset:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), true, false)
		require.NoError(t, err)

		// Corrupt payload
		frame[offset] ^= 0xFF

		_, err = udp.Decode(frame[:n], nil, true, false)
		require.Error(t, err)
	})
}

func TestEncodeDecode_IPv6_Layer3(t *testing.T) {
	const frameSize = 1500
	const payloadText = "Hello, UDP over IPv6 Layer3!"

	src := tcpip.FullAddress{
		Addr: tcpip.AddrFrom16Slice(net.ParseIP("fd00::1").To16()),
		Port: 5678,
	}
	dst := tcpip.FullAddress{
		Addr: tcpip.AddrFrom16Slice(net.ParseIP("fd00::2").To16()),
		Port: 8765,
	}

	payload := []byte(payloadText)

	t.Run("Valid", func(t *testing.T) {
		frame := make([]byte, frameSize)
		offset := header.IPv6MinimumSize + header.UDPMinimumSize
		copy(frame[offset:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), true, false)
		require.NoError(t, err)

		var decodedAddr tcpip.FullAddress
		decodedPayload, err := udp.Decode(frame[:n], &decodedAddr, true, false)
		require.NoError(t, err)
		require.Equal(t, src.Addr.String(), decodedAddr.Addr.String())
		require.Equal(t, src.Port, decodedAddr.Port)
		require.Equal(t, payload, decodedPayload)
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		frame := make([]byte, frameSize)
		offset := header.IPv6MinimumSize + header.UDPMinimumSize
		copy(frame[offset:], payload)

		n, err := udp.Encode(frame, &src, &dst, len(payload), true, false)
		require.NoError(t, err)

		// Corrupt payload
		frame[offset] ^= 0xFF

		_, err = udp.Decode(frame[:n], nil, true, false)
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
		_, err := udp.Encode(frame, &src, &dst, payloadSize, false, true)
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
		_, err := udp.Encode(frame, &src, &dst, payloadSize, false, true)
		if err != nil {
			b.Fatalf("failed to encode: %v", err)
		}
	}
}
