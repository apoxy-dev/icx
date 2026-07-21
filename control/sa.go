package control

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/apoxy-dev/icx/psp"
)

// numMasterKeys is the PSP master-key count: one active, one retained for
// in-flight SAs during rotation (the MSB of the SPI selects between them).
const numMasterKeys = psp.NumMasterKeys

// MasterKeys holds the two 256-bit PSP master keys. They are seeded from the
// forward-secret TLS exporter (see ExportRootSecret) and live only in RAM; they
// are never persisted, so a recorded session cannot be decrypted once they are
// dropped — this is where the forward secrecy reaches the data plane.
type MasterKeys struct {
	keys [numMasterKeys][MasterKeyLen]byte
}

// masterKeyInfo domain-separates the master-key derivation from any other use
// of the root secret.
const masterKeyInfo = "icx psp master keys v1"

// DeriveMasterKeys expands the TLS-exported root secret into the two PSP master
// keys via HKDF-SHA-256 (FIPS SP 800-56C). Both peers feed the identical root
// secret and therefore derive the identical master keys, so each can compute
// any SA key locally from its SPI — no key material ever crosses the wire.
func DeriveMasterKeys(rootSecret []byte) (*MasterKeys, error) {
	if len(rootSecret) < RootSecretLen {
		return nil, fmt.Errorf("control: root secret must be >= %d bytes, got %d", RootSecretLen, len(rootSecret))
	}
	okm, err := hkdf.Key(sha256.New, rootSecret, nil, masterKeyInfo, numMasterKeys*MasterKeyLen)
	if err != nil {
		return nil, fmt.Errorf("control: derive master keys: %w", err)
	}
	mk := &MasterKeys{}
	for i := range mk.keys {
		copy(mk.keys[i][:], okm[i*MasterKeyLen:(i+1)*MasterKeyLen])
	}
	return mk, nil
}

// MasterKeyIndex returns which master key (0 or 1) an SPI selects: per PSP, the
// most-significant bit of the SPI. See psp.MasterKeyIndex.
func MasterKeyIndex(spi uint32) int { return psp.MasterKeyIndex(spi) }

// RoleOf reports which role allocated an SPI, per the role bit (bit30). See
// psp.RoleOf.
func RoleOf(spi uint32) Role { return psp.RoleOf(spi) }

// ReservedSPI reports whether an SPI's low 31 bits are zero, which the PSP spec
// reserves and the allocator never issues. See psp.ReservedSPI.
func ReservedSPI(spi uint32) bool { return psp.ReservedSPI(spi) }

// SA is a unidirectional PSP security association: an SPI, the derived AES-GCM
// key, and the cipher suite (which fixes the key length / cipher).
type SA struct {
	SPI     uint32
	Key     []byte
	Version ICXVersion
}

// DeriveSA derives the SA key for spi using the master key its MSB selects.
func (m *MasterKeys) DeriveSA(spi uint32, v ICXVersion) (*SA, error) {
	if psp.ReservedSPI(spi) {
		return nil, errors.New("control: SPI low 31 bits must be non-zero (zero is reserved)")
	}
	key, err := DeriveSAKey(m.keys[MasterKeyIndex(spi)][:], spi, v)
	if err != nil {
		return nil, err
	}
	return &SA{SPI: spi, Key: key, Version: v}, nil
}

// Role identifies which peer allocated an SPI; the SPI space is partitioned by
// role so the two directions always derive distinct keys. See psp.Role.
type Role = psp.Role

const (
	Initiator = psp.Initiator
	Responder = psp.Responder
)

// spiCounterMask is the largest usable per-(index,role) SPI counter value.
const spiCounterMask = psp.SPICounterMax

// MakeSPI composes an SPI from the active master-key index, the allocating role
// and a per-(index,role) counter. See psp.MakeSPI for the bit layout.
func MakeSPI(masterKeyIndex int, role Role, counter uint32) (uint32, error) {
	return psp.MakeSPI(masterKeyIndex, role, counter)
}

// ErrSPIExhausted is returned by Allocate when the 2^30 counter space for a
// master-key index is used up. It is a TERMINAL condition: the only remedy is
// master-key rotation, which this build does not yet support (the active master-key
// index is fixed at 0). Callers treat it as a non-retryable, fail-closed error rather
// than looping a reconnect.
var ErrSPIExhausted = errors.New("control: SPI counter space exhausted; master-key rotation required")

// SPIAllocator hands out monotonically increasing, collision-free SPIs for one
// peer's role. SPIs are never reused within a master-key generation (PSP
// requirement); exhaustion of the 2^30 counter space forces a master-key
// rotation.
type SPIAllocator struct {
	role Role
	mu   sync.Mutex
	next [numMasterKeys]uint32
}

// NewSPIAllocator returns an allocator for the given role.
func NewSPIAllocator(role Role) *SPIAllocator { return &SPIAllocator{role: role} }

// Allocate returns the next SPI for the active master-key index.
func (a *SPIAllocator) Allocate(masterKeyIndex int) (uint32, error) {
	if masterKeyIndex < 0 || masterKeyIndex >= numMasterKeys {
		return 0, fmt.Errorf("control: master key index must be 0..%d", numMasterKeys-1)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Check before incrementing so an exhausted counter stays pinned at the
	// ceiling (spiCounterMask is the last usable value) rather than wrapping.
	if a.next[masterKeyIndex] >= spiCounterMask {
		return 0, fmt.Errorf("%w (master key %d)", ErrSPIExhausted, masterKeyIndex)
	}
	a.next[masterKeyIndex]++
	return MakeSPI(masterKeyIndex, a.role, a.next[masterKeyIndex])
}
