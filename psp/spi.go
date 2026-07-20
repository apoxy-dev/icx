package psp

import "fmt"

// Role identifies which peer allocated an SPI. The two directions MUST use
// distinct SPIs, otherwise both directions would derive the same key
// (txKey == rxKey). Partitioning the SPI space by role guarantees distinctness
// even though both peers allocate independently from the shared master keys.
type Role uint8

const (
	Initiator Role = iota // canonical lower static key; the connecting side
	Responder             // the accepting side
)

// Peer returns the opposite role.
func (r Role) Peer() Role { return r ^ 1 }

// SPI bit layout (PSP keeps the SPI opaque except for the MSB master-key
// selector; we additionally reserve one bit to partition by allocating role):
//
//	bit31      master-key index (PSP)
//	bit30      allocating role (0=initiator, 1=responder)
//	bits[29:0] per-(index,role) counter, 1..2^30-1 (0 reserved)
const (
	spiRoleShift = 30
	// SPICounterMax is the largest usable per-(index,role) counter value
	// (2^30-1); 0 is reserved.
	SPICounterMax = (uint32(1) << spiRoleShift) - 1
	spiLowMask    = uint32(0x7fffffff) // low 31 bits (PSP: must be non-zero)
)

// MasterKeyIndex returns which master key (0 or 1) an SPI selects: per PSP, the
// most-significant bit of the SPI.
func MasterKeyIndex(spi uint32) int { return int(spi >> 31) }

// RoleOf reports which role allocated an SPI, per the role bit (bit30). It is
// the inverse of the role argument to MakeSPI and lets a peer validate that an
// announced RX SPI was allocated by the opposite role, preserving the SPI-space
// partition that keeps tx and rx keys distinct.
func RoleOf(spi uint32) Role { return Role((spi >> spiRoleShift) & 1) }

// ReservedSPI reports whether spi is reserved (low 31 bits zero). PSP reserves
// the all-zero counter in each master-key half; installs must reject it.
func ReservedSPI(spi uint32) bool { return spi&spiLowMask == 0 }

// MakeSPI composes an SPI from the active master-key index, the allocating role
// and a per-(index,role) counter.
func MakeSPI(masterKeyIndex int, role Role, counter uint32) (uint32, error) {
	if masterKeyIndex < 0 || masterKeyIndex >= NumMasterKeys {
		return 0, fmt.Errorf("psp: master key index must be 0..%d", NumMasterKeys-1)
	}
	if role > Responder {
		return 0, fmt.Errorf("psp: invalid role %d", role)
	}
	if counter == 0 || counter > SPICounterMax {
		return 0, fmt.Errorf("psp: SPI counter out of range (1..%d)", SPICounterMax)
	}
	return uint32(masterKeyIndex)<<31 | uint32(role)<<spiRoleShift | counter, nil
}

// EpochSPIs maps a symmetric per-connection (epoch, role) pair onto the SPI
// layout at master-key index 0: the local receive SPI carries the local role's
// bit, the transmit SPI the peer role's bit, both with counter = epoch. The two
// peers of a connection call it with opposite roles and the same epoch and
// obtain mirrored (rxSPI, txSPI) pairs, so each direction derives a distinct
// key from the shared master secret. Errors if epoch is 0 or above
// SPICounterMax; it never truncates.
func EpochSPIs(local Role, epoch uint32) (rxSPI, txSPI uint32, err error) {
	rxSPI, err = MakeSPI(0, local, epoch)
	if err != nil {
		return 0, 0, err
	}
	txSPI, err = MakeSPI(0, local.Peer(), epoch)
	if err != nil {
		return 0, 0, err
	}
	return rxSPI, txSPI, nil
}
