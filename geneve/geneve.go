package geneve

import (
	"encoding/binary"
	"errors"
)

const (
	// Reserved for experimental use.
	ClassExperimental = 0xFF00
	// Indicates that the option is critical.
	OptionTypeCritical = 0x80
	// Maximum number of options that can be included in a Geneve header.
	// This is not part of the RFC but a practical limit for this implementation.
	MaxOptions = 2
	// Maximum length of a Geneve option value in bytes.
	// This is not part of the RFC but a practical limit for this implementation.
	MaxValueLength = 12
)

// Option represents a Geneve option as defined in RFC 8926.
type Option struct {
	Class  uint16               // Defines the namespace for the option (IANA-assigned).
	Type   uint8                // Unique within the option class.
	Length int                  // Length of the option value in 4-byte units.
	Value  [MaxValueLength]byte // The value of the option (4-byte aligned).
}

// Header represents the Geneve header structure as defined in RFC 8926.
type Header struct {
	Version      uint8              // Version (2 bits)
	OAM          bool               // OAM Flag (1 bit) - Set if the packet is OAM (Operations, Administration, Maintenance).
	Critical     bool               // Critical Flag (1 bit) - Indicates if the presence of unknown options must cause the receiver to drop the packet
	ProtocolType uint16             // Protocol Type (16 bits) - EtherType of the encapsulated payload.
	VNI          uint32             // Virtual Network Identifier (VNI) (24 bits) - Identifies the virtual network.
	NumOptions   int                // Number of populated options
	Options      [MaxOptions]Option // Options (variable length) - A list of options that can be included in the header.
}

func (h *Header) MarshalBinary(data []byte) (int, error) {
	optsLen := 0
	for i := 0; i < h.NumOptions; i++ {
		valLen := 4 * h.Options[i].Length
		optLen := 4 + valLen
		optLen = (optLen + 3) &^ 3 // align to 4 bytes
		optsLen += optLen
	}
	if len(data) < 8+optsLen {
		return 0, errors.New("buffer too small")
	}

	data[0] = (h.Version&0x3)<<6 | uint8(optsLen/4)
	data[1] = 0
	if h.OAM {
		data[1] |= 0x80
	}
	if h.Critical {
		data[1] |= 0x40
	}
	binary.BigEndian.PutUint16(data[2:4], h.ProtocolType)
	data[4] = byte(h.VNI >> 16)
	data[5] = byte(h.VNI >> 8)
	data[6] = byte(h.VNI)
	data[7] = 0 // Reserved

	offset := 8
	for i := 0; i < h.NumOptions; i++ {
		opt := h.Options[i]
		valLen := 4 * opt.Length
		padLen := (4 - (valLen % 4)) % 4
		totalLen := 4 + valLen + padLen
		if offset+totalLen > len(data) {
			return 0, errors.New("buffer too small for options")
		}

		binary.BigEndian.PutUint16(data[offset:], opt.Class)
		data[offset+2] = opt.Type
		data[offset+3] = uint8((valLen + padLen) / 4)
		offset += 4

		copy(data[offset:], opt.Value[:valLen])
		offset += valLen

		for j := 0; j < padLen; j++ {
			data[offset] = 0
			offset++
		}
	}
	return offset, nil
}

func (h *Header) UnmarshalBinary(data []byte) (int, error) {
	if len(data) < 8 {
		return 0, errors.New("data too short for base header")
	}

	h.Version = data[0] >> 6
	optsLen := int(data[0]&0x3F) * 4
	h.OAM = data[1]&0x80 != 0
	h.Critical = data[1]&0x40 != 0
	h.ProtocolType = binary.BigEndian.Uint16(data[2:4])
	h.VNI = uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])

	if len(data) < 8+optsLen {
		return 0, errors.New("data too short for options")
	}

	offset := 8
	h.NumOptions = 0
	for offset < 8+optsLen && h.NumOptions < MaxOptions {
		if offset+4 > len(data) {
			return 0, errors.New("incomplete option header")
		}

		class := binary.BigEndian.Uint16(data[offset:])
		typ := data[offset+2]
		lengthUnits := data[offset+3] & 0x3F
		optLen := 4 + int(lengthUnits)*4
		if optLen < 4 || offset+optLen > len(data) {
			return 0, errors.New("invalid option length")
		}

		valLen := optLen - 4
		valStart := offset + 4
		valEnd := valStart + valLen
		if valEnd > len(data) {
			return 0, errors.New("invalid option value end. exceeds data length")
		}

		h.Options[h.NumOptions] = Option{
			Class:  class,
			Type:   typ,
			Length: int(valLen / 4),
		}
		copy(h.Options[h.NumOptions].Value[:], data[valStart:valEnd])
		h.NumOptions++
		offset += optLen
	}

	return offset, nil
}
