package control

import (
	"encoding/binary"
	"fmt"
	"io"
)

// The control-plane SA-setup protocol runs over a bidirectional QUIC stream
// after the mTLS handshake. Because both peers derive the identical PSP master
// keys from the TLS exporter, no key material is ever exchanged — peers only
// announce the SPI on which each will RECEIVE, and derive every key locally.
//
// Frame = uint16 big-endian length prefix + payload. Messages are small and
// fixed today; the leading protocol-version + type bytes leave room to grow
// (lifetimes, capabilities, rekey signalling) without breaking the framing.

const (
	// ProtocolVersion is the control-plane wire-protocol version.
	ProtocolVersion = 1
	// maxFrameLen bounds a single control frame (these are tiny; the cap just
	// stops a peer from forcing a large allocation).
	maxFrameLen = 4096
)

type msgType uint8

const (
	msgSAOffer msgType = 1
)

// saOffer announces the SPI on which the sender will RECEIVE data-plane traffic
// for the given cipher suite. The peer derives the key for this SPI and uses it
// as its TX key; the sender uses it as its RX key.
type saOffer struct {
	Version ICXVersion
	RxSPI   uint32
}

const saOfferLen = 1 + 1 + 1 + 4 // protoVer + type + suite + rxSPI

func (o saOffer) marshal() []byte {
	b := make([]byte, saOfferLen)
	b[0] = ProtocolVersion
	b[1] = byte(msgSAOffer)
	b[2] = byte(o.Version)
	binary.BigEndian.PutUint32(b[3:], o.RxSPI)
	return b
}

func parseSAOffer(b []byte) (saOffer, error) {
	if len(b) != saOfferLen {
		return saOffer{}, fmt.Errorf("control: SA offer wrong size %d, want %d", len(b), saOfferLen)
	}
	if b[0] != ProtocolVersion {
		return saOffer{}, fmt.Errorf("control: unsupported protocol version %d", b[0])
	}
	if msgType(b[1]) != msgSAOffer {
		return saOffer{}, fmt.Errorf("control: expected SA offer, got message type %d", b[1])
	}
	return saOffer{
		Version: ICXVersion(b[2]),
		RxSPI:   binary.BigEndian.Uint32(b[3:7]),
	}, nil
}

// writeFrame writes a length-prefixed control frame.
func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameLen {
		return fmt.Errorf("control: frame too large (%d)", len(payload))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readFrame reads a single length-prefixed control frame.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if int(n) > maxFrameLen {
		return nil, fmt.Errorf("control: frame too large (%d)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readSAOffer(r io.Reader) (saOffer, error) {
	b, err := readFrame(r)
	if err != nil {
		return saOffer{}, err
	}
	return parseSAOffer(b)
}
