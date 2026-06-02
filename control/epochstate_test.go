package control

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSPIAllocatorSeedFloor(t *testing.T) {
	a := NewSPIAllocator(Initiator)
	// Fresh allocator starts at counter 1.
	spi, err := a.Allocate(0)
	require.NoError(t, err)
	require.Equal(t, uint32(1), spi&spiCounterMask)

	// Seeding above the current position jumps the next allocation past the floor.
	a.SeedFloor(0, 1000)
	spi, err = a.Allocate(0)
	require.NoError(t, err)
	require.Equal(t, uint32(1001), spi&spiCounterMask)

	// Seeding at or below the current position is a no-op (monotonic).
	a.SeedFloor(0, 5)
	spi, err = a.Allocate(0)
	require.NoError(t, err)
	require.Equal(t, uint32(1002), spi&spiCounterMask)

	// SeedFloor masks off the role/index bits: a full initiator SPI seeds by counter.
	a.SeedFloor(0, 2000)
	spi, err = a.Allocate(0)
	require.NoError(t, err)
	require.Equal(t, uint32(2001), spi&spiCounterMask)

	// Out-of-range index is ignored, not a panic.
	a.SeedFloor(99, 1<<20)
}

func TestSPIAllocatorExhaustion(t *testing.T) {
	a := NewSPIAllocator(Initiator)
	a.SeedFloor(0, spiCounterMask-1)
	// The terminal counter (spiCounterMask) is still allocatable.
	spi, err := a.Allocate(0)
	require.NoError(t, err)
	require.Equal(t, spiCounterMask, spi&spiCounterMask)
	// The next allocation exhausts the space with the sentinel error.
	_, err = a.Allocate(0)
	require.ErrorIs(t, err, ErrSPIExhausted)
	// Exhaustion is sticky.
	_, err = a.Allocate(0)
	require.ErrorIs(t, err, ErrSPIExhausted)
}

func TestSeedWithMargin(t *testing.T) {
	require.Equal(t, uint32(1000+epochSeedMargin), seedWithMargin(1000))
	require.Equal(t, uint32(epochSeedMargin), seedWithMargin(0))
	// Near the ceiling, clamp to spiCounterMask-1 so the seeded allocator can still
	// hand out the terminal counter before exhausting.
	require.Equal(t, spiCounterMask-1, seedWithMargin(spiCounterMask))
	require.Equal(t, spiCounterMask-1, seedWithMargin(spiCounterMask-1))
	require.Equal(t, spiCounterMask-1, seedWithMargin(spiCounterMask-2))
}

func newTestStore(t *testing.T) (*FileEpochStore, *Identity, *Identity) {
	t.Helper()
	local, err := GenerateIdentity()
	require.NoError(t, err)
	peer, err := GenerateIdentity()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "epoch.state")
	s, err := NewFileEpochStore(path, local, peer.PublicKey())
	require.NoError(t, err)
	return s, local, peer
}

func TestFileEpochStoreRoundTrip(t *testing.T) {
	s, _, _ := newTestStore(t)

	// Absent file => first run (ok=false, nil error).
	hw, ok, err := s.Load()
	require.NoError(t, err)
	require.False(t, ok)
	require.Zero(t, hw)

	require.NoError(t, s.Store(42))
	hw, ok, err = s.Load()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint32(42), hw)

	// Overwrite (atomic replace) with a higher value.
	require.NoError(t, s.Store(99))
	hw, ok, err = s.Load()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint32(99), hw)
}

func TestFileEpochStoreMACStableAcrossInstances(t *testing.T) {
	local, err := GenerateIdentity()
	require.NoError(t, err)
	peer, err := GenerateIdentity()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "epoch.state")

	s1, err := NewFileEpochStore(path, local, peer.PublicKey())
	require.NoError(t, err)
	require.NoError(t, s1.Store(7))

	// A second store built from the SAME identity+peer (i.e. a restart) must verify
	// the MAC and load the value — the MAC key derivation is stable.
	s2, err := NewFileEpochStore(path, local, peer.PublicKey())
	require.NoError(t, err)
	hw, ok, err := s2.Load()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, uint32(7), hw)
}

func TestFileEpochStoreRejectsWrongIdentity(t *testing.T) {
	local, err := GenerateIdentity()
	require.NoError(t, err)
	other, err := GenerateIdentity()
	require.NoError(t, err)
	peer, err := GenerateIdentity()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "epoch.state")

	s, err := NewFileEpochStore(path, local, peer.PublicKey())
	require.NoError(t, err)
	require.NoError(t, s.Store(5))

	// A different local identity derives a different MAC key → verification fails
	// (and it is an error, NOT a silent first-run).
	bad, err := NewFileEpochStore(path, other, peer.PublicKey())
	require.NoError(t, err)
	_, ok, err := bad.Load()
	require.Error(t, err)
	require.False(t, ok)
}

func TestFileEpochStoreRejectsWrongPeer(t *testing.T) {
	local, err := GenerateIdentity()
	require.NoError(t, err)
	peer, err := GenerateIdentity()
	require.NoError(t, err)
	otherPeer, err := GenerateIdentity()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "epoch.state")

	s, err := NewFileEpochStore(path, local, peer.PublicKey())
	require.NoError(t, err)
	require.NoError(t, s.Store(5))

	// Same identity, different peer → pin mismatch → error.
	bad, err := NewFileEpochStore(path, local, otherPeer.PublicKey())
	require.NoError(t, err)
	_, ok, err := bad.Load()
	require.Error(t, err)
	require.False(t, ok)
}

func TestFileEpochStoreRejectsCorruption(t *testing.T) {
	// Flipping a byte in any region (magic, version, pin, high-water, mac) must be
	// detected as an error, never silently accepted or treated as first-run.
	// Cover every region's first byte (incl. the reserved flags byte and the
	// region boundaries offPin/offMAC) to prove the whole prefix is MAC-protected.
	for _, off := range []int{0, offVersion, offFlags, offPin, offHighWater, offMAC, offMAC + 1, epochStateLen - 1} {
		s, _, _ := newTestStore(t)
		require.NoError(t, s.Store(123))
		buf, err := os.ReadFile(s.path)
		require.NoError(t, err)
		buf[off] ^= 0xff
		require.NoError(t, os.WriteFile(s.path, buf, 0o600))
		_, ok, err := s.Load()
		require.Error(t, err, "corruption at offset %d must be rejected", off)
		require.False(t, ok)
	}
}

func TestFileEpochStoreRejectsBadLength(t *testing.T) {
	for _, n := range []int{0, 1, epochStateLen - 1, epochStateLen + 1} {
		s, _, _ := newTestStore(t)
		require.NoError(t, os.WriteFile(s.path, make([]byte, n), 0o600))
		_, ok, err := s.Load()
		require.Error(t, err, "length %d must be a clean error, not a panic or first-run", n)
		require.False(t, ok)
	}
}

func TestFileEpochStoreRejectsOutOfRangeHighWater(t *testing.T) {
	s, _, _ := newTestStore(t)
	// A validly-MAC'd record whose high-water exceeds the counter space must be
	// rejected (it cannot have come from a real allocator).
	buf := s.marshal(spiCounterMask + 1)
	require.NoError(t, os.WriteFile(s.path, buf, 0o600))
	_, ok, err := s.Load()
	require.Error(t, err)
	require.False(t, ok)
}

func TestFileEpochStoreUnreadableIsError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	s, _, _ := newTestStore(t)
	require.NoError(t, s.Store(11))
	require.NoError(t, os.Chmod(s.path, 0o000))
	t.Cleanup(func() { _ = os.Chmod(s.path, 0o600) })
	// A present-but-unreadable file is a real error (so --require-state fails closed),
	// NOT a first-run.
	_, ok, err := s.Load()
	require.Error(t, err)
	require.False(t, ok)
}

// TestFileEpochStoreLayout pins the on-disk byte layout (field order, endianness, MAC
// scope and key derivation) via an independent recomputation, so an accidental change
// to any of them is caught.
func TestFileEpochStoreLayout(t *testing.T) {
	local, err := GenerateIdentity()
	require.NoError(t, err)
	peer, err := GenerateIdentity()
	require.NoError(t, err)
	s, err := NewFileEpochStore(filepath.Join(t.TempDir(), "epoch.state"), local, peer.PublicKey())
	require.NoError(t, err)

	const hw = uint32(0x01020304)
	got := s.marshal(hw)
	require.Len(t, got, epochStateLen)

	var scalar [32]byte
	local.priv.D.FillBytes(scalar[:])
	macKey, err := hkdf.Key(sha256.New, scalar[:], nil, stateMACInfo, 32)
	require.NoError(t, err)
	lDER, err := x509.MarshalPKIXPublicKey(local.PublicKey())
	require.NoError(t, err)
	pDER, err := x509.MarshalPKIXPublicKey(peer.PublicKey())
	require.NoError(t, err)
	ph := sha256.New()
	ph.Write(lDER)
	ph.Write(pDER)

	want := make([]byte, epochStateLen)
	copy(want[0:4], "ICXE")
	want[4] = 1
	want[5] = 0
	copy(want[6:38], ph.Sum(nil))
	binary.BigEndian.PutUint32(want[38:42], hw)
	m := hmac.New(sha256.New, macKey)
	m.Write(want[:42])
	copy(want[42:], m.Sum(nil))

	require.Equal(t, want, got)
}

// fakeEpochStore is an in-memory EpochStore for the persister/Tunnel tests. It can be
// reused across a simulated process restart (the persisted value survives).
type fakeEpochStore struct {
	mu       sync.Mutex
	high     uint32
	has      bool
	loadErr  error
	storeErr error
	stores   int
	loads    int
}

func (f *fakeEpochStore) Load() (uint32, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	if f.loadErr != nil {
		return 0, false, f.loadErr
	}
	return f.high, f.has, nil
}

func (f *fakeEpochStore) counts() (loads, stores int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loads, f.stores
}

func (f *fakeEpochStore) Store(v uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stores++
	if f.storeErr != nil {
		return f.storeErr
	}
	f.high, f.has = v, true
	return nil
}

func (f *fakeEpochStore) set(v uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.high, f.has = v, true
}

func (f *fakeEpochStore) loaded() (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.high, f.has
}

func TestEpochPersisterCoalesceAndFlush(t *testing.T) {
	fs := &fakeEpochStore{}
	p := newEpochPersister(fs, 0, time.Now().UnixNano())
	defer p.stop()

	for _, v := range []uint32{1, 2, 3, 7, 5} {
		p.request(v)
	}
	// The persister catches up to the highest requested value; lower/stale values are
	// coalesced or ignored (Store is monotonic in the persister).
	require.Eventually(t, func() bool {
		hw, ok := fs.loaded()
		return ok && hw == 7
	}, 2*time.Second, 5*time.Millisecond)
	require.Zero(t, p.failures.Load())
}

func TestEpochPersisterFatalUnderRequireState(t *testing.T) {
	fs := &fakeEpochStore{storeErr: errors.New("disk full")}
	p := newEpochPersister(fs, 0, time.Now().UnixNano())
	defer p.stop()

	// The persister attempts each distinct requested value once (it does not retry a
	// failed value), so consecutive failures climb one per new request — exactly as a
	// failing disk accrues one failure per rekey. Drive several, waiting for each to
	// register so they are not coalesced.
	for v := int64(1); v <= 5; v++ {
		p.request(uint32(v))
		require.Eventually(t, func() bool {
			return p.failures.Load() >= v
		}, 2*time.Second, 5*time.Millisecond)
	}

	// Without require-state, a failing store is best-effort (never fatal).
	require.NoError(t, p.fatal(false, 5, time.Now(), 3, time.Hour))

	// With require-state, failures past the threshold are fatal.
	require.ErrorIs(t, p.fatal(true, 5, time.Now(), 3, time.Hour), errEpochPersistStalled)
}

// TestEpochPersisterRequestKeepsMax exercises request()'s keep-max coalescing in
// isolation — with no goroutine draining, a lower request must not displace a queued
// higher value (flush's own monotonic guard would otherwise mask a broken request()).
func TestEpochPersisterRequestKeepsMax(t *testing.T) {
	p := &epochPersister{reqCh: make(chan uint32, 1)} // no run() goroutine
	p.request(7)
	p.request(5) // lower
	p.request(3) // lower
	select {
	case v := <-p.reqCh:
		require.Equal(t, uint32(7), v, "the higher queued value must survive a lower request")
	default:
		t.Fatal("expected a coalesced value in the mailbox")
	}
}

func TestEpochPersisterFatalOnStall(t *testing.T) {
	fs := &fakeEpochStore{}
	// Seed lastOK far in the past and leave a value un-persisted (high < target).
	p := newEpochPersister(fs, 0, time.Now().Add(-time.Hour).UnixNano())
	defer p.stop()
	// target (5) is ahead of what the store holds (0) and lastOK is stale → stalled.
	require.ErrorIs(t, p.fatal(true, 5, time.Now(), 100, time.Minute), errEpochPersistStalled)
	// No un-persisted work → not stalled even with a stale lastOK.
	require.NoError(t, p.fatal(true, 0, time.Now(), 100, time.Minute))

	// A successful store clears the stall: high catches up to the target and lastOK is
	// refreshed, so the tripwire un-latches.
	p.request(5)
	require.Eventually(t, func() bool {
		hw, ok := fs.loaded()
		return ok && hw == 5
	}, 2*time.Second, 5*time.Millisecond)
	require.NoError(t, p.fatal(true, 5, time.Now(), 100, time.Minute), "stall must clear once the store catches up")
}
