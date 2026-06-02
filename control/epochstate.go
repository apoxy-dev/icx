package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// This file implements the durable epoch high-water that lets a one-sided restart
// of the control-plane INITIATOR recover seamlessly (Phase 5 item #1).
//
// Why only the initiator: the shared data-plane epoch is the initiator-allocated
// SPI counter (see SharedEpoch). On every (re)connect the per-session SPI allocator
// resets to 1, so the survivor's strictly-increasing epoch guard (handler.go) would
// reject the regressed epoch. The Tunnel fixes this by seeding the new session's
// allocator above an epoch high-water it carries forward: in memory (covers a
// transient reconnect and a responder restart, where the surviving initiator never
// lost the value) and, when an EpochStore is configured, on durable storage (covers
// an initiator restart, where the value must outlive the process). The responder's
// high-water is not load-bearing, so durable state is consulted only on the
// initiator.
//
// Safety note: the epoch is a data-plane SELECTOR, not a nonce. Reusing an epoch
// VALUE across sessions is harmless because every QUIC session derives fresh master
// keys from a fresh ECDHE exporter (no 0-RTT), so the AES-GCM (key, nonce) pair never
// repeats. The persisted high-water therefore only needs integrity, not rollback
// resistance — see EpochStore.

// EpochStore persists the data-plane epoch high-water across process restarts.
type EpochStore interface {
	// Load returns the persisted high-water. ok is false with a nil error ONLY when
	// no state has been written yet (first run); every other condition — unreadable
	// file, truncation, bad magic/version, identity-pair pin mismatch, MAC failure,
	// out-of-range value — returns a non-nil error so a fail-closed caller
	// (--require-state) can refuse to start rather than silently resetting to zero.
	Load() (highWater uint32, ok bool, err error)
	// Store durably writes highWater (fsync of the file, atomic rename into place,
	// fsync of the directory). It may block on disk I/O; callers persist off the
	// hot path (see epochPersister).
	Store(highWater uint32) error
}

// On-disk format (fixed 74 bytes). The MAC covers bytes [0:42); the mac occupies
// [42:74). A future non-zero flags value must be byte-identical on Store and Load.
const (
	epochStateMagic   = "ICXE"
	epochStateVersion = 1
	epochStateLen     = 4 + 1 + 1 + 32 + 4 + 32 // magic|version|flags|pin|highWater|mac

	offVersion   = 4
	offFlags     = 5
	offPin       = 6
	offHighWater = 38
	offMAC       = 42 // == end of MAC-covered prefix

	// stateMACInfo domain-separates the epoch-state MAC key from any other use of
	// the identity key.
	stateMACInfo = "icx epoch-state hmac v1"
)

// FileEpochStore is a file-backed EpochStore. The record is integrity-protected by
// an HMAC keyed from the local identity and bound (via the pin) to the exact
// (local, peer) identity pair, so a file cannot be silently swapped between tunnels
// or nodes. One file per (local, peer) tunnel; it must NOT be shared between
// processes (concurrent writers).
//
// What the MAC defends: accidental corruption/bit-rot (rejected on Load) and forgery
// of a chosen high-water by anyone without the identity key (HMAC). What it does NOT
// defend: rollback-replay of an older, validly-signed file, or deletion (an absent
// file is indistinguishable from a genuine first run). Those need a hardware
// monotonic counter and are out of scope; --require-state is an integrity tripwire
// against corruption, not an anti-rollback control. This is acceptable because, per
// the safety note above, even a rolled-back or absent high-water cannot cause AES-GCM
// nonce reuse on the data plane (keys are per-session ephemeral) — the only
// consequence is a transient one-sided-restart-style outage.
type FileEpochStore struct {
	path   string
	macKey []byte
	pin    [32]byte
}

// NewFileEpochStore builds a file-backed store at path, keyed from local and bound to
// the (local, peer) identity pair.
func NewFileEpochStore(path string, local *Identity, peerPub *ecdsa.PublicKey) (*FileEpochStore, error) {
	if path == "" {
		return nil, errors.New("control: epoch state path is empty")
	}
	if local == nil || peerPub == nil {
		return nil, errors.New("control: epoch state requires local identity and peer key")
	}
	// Validate the parent directory up front so a missing/unwritable state directory
	// fails fast at construction. Without this, os.ReadFile on a path whose parent is
	// missing reports fs.ErrNotExist, which Load would (correctly) treat as a genuine
	// first run — masking the misconfiguration so even --require-state starts happily
	// and only fails closed several rekeys later when the first Store cannot create a
	// temp file.
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("control: epoch state directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("control: epoch state directory %q is not a directory", dir)
	}
	macKey, err := stateMACKey(local)
	if err != nil {
		return nil, err
	}
	pin, err := identityPairPin(local.PublicKey(), peerPub)
	if err != nil {
		return nil, err
	}
	// Best-effort sweep of temp files orphaned by a crash between CreateTemp and rename
	// in a prior run (safe at construction: no Store is in flight, and the store is
	// not shared between processes).
	if matches, gerr := filepath.Glob(filepath.Join(dir, ".icx-epoch-*.tmp")); gerr == nil {
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
	return &FileEpochStore{path: path, macKey: macKey, pin: pin}, nil
}

// stateMACKey derives the HMAC key from the identity. The IKM is the fixed-width
// (32-byte, left-zero-padded) P-256 private scalar — a mathematical value that is
// stable across Go releases — NOT the PKCS#8 DER, whose byte layout is an
// implementation detail a toolchain upgrade could perturb and thereby silently
// invalidate every previously-written MAC. Deriving the MAC key from the identity
// (rather than a separate secret) intentionally overloads one key across roles; the
// HKDF info string domain-separates it, and the consequence is that the epoch-state
// MAC lifetime equals the identity-key lifetime — rotating the identity resets the
// durable epoch state.
func stateMACKey(local *Identity) ([]byte, error) {
	var scalar [32]byte
	local.priv.D.FillBytes(scalar[:])
	key, err := hkdf.Key(sha256.New, scalar[:], nil, stateMACInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("control: derive epoch-state MAC key: %w", err)
	}
	return key, nil
}

// identityPairPin binds a state file to the exact (local, peer) pair so it cannot be
// confused with another tunnel's file even under the same identity.
func identityPairPin(local, peer *ecdsa.PublicKey) ([32]byte, error) {
	var pin [32]byte
	l, err := x509.MarshalPKIXPublicKey(local)
	if err != nil {
		return pin, fmt.Errorf("control: marshal local key: %w", err)
	}
	p, err := x509.MarshalPKIXPublicKey(peer)
	if err != nil {
		return pin, fmt.Errorf("control: marshal peer key: %w", err)
	}
	h := sha256.New()
	h.Write(l)
	h.Write(p)
	copy(pin[:], h.Sum(nil))
	return pin, nil
}

func (s *FileEpochStore) marshal(highWater uint32) []byte {
	buf := make([]byte, epochStateLen)
	copy(buf[0:offVersion], epochStateMagic)
	buf[offVersion] = epochStateVersion
	buf[offFlags] = 0 // reserved
	copy(buf[offPin:offHighWater], s.pin[:])
	binary.BigEndian.PutUint32(buf[offHighWater:offMAC], highWater)
	mac := hmac.New(sha256.New, s.macKey)
	mac.Write(buf[:offMAC])
	copy(buf[offMAC:], mac.Sum(nil))
	return buf
}

// Load reads and verifies the state file. See EpochStore.Load for the ok/err contract.
func (s *FileEpochStore) Load() (uint32, bool, error) {
	buf, err := os.ReadFile(s.path)
	if err != nil {
		// fs.ErrNotExist is the ONLY signal that maps to "first run"; every other
		// open/read error (EACCES, EIO, ENOTDIR, dangling symlink, ...) is a real
		// failure so --require-state fails closed instead of starting fresh.
		if errors.Is(err, fs.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("control: read epoch state %q: %w", s.path, err)
	}
	// Length is validated strictly before any field slicing so a truncated or
	// zero-length file returns a clean error rather than panicking.
	if len(buf) != epochStateLen {
		return 0, false, fmt.Errorf("control: epoch state %q is %d bytes, want %d (corrupt/truncated)", s.path, len(buf), epochStateLen)
	}
	if string(buf[0:offVersion]) != epochStateMagic {
		return 0, false, fmt.Errorf("control: epoch state %q has bad magic", s.path)
	}
	if buf[offVersion] != epochStateVersion {
		return 0, false, fmt.Errorf("control: epoch state %q has unsupported version %d", s.path, buf[offVersion])
	}
	if !bytes.Equal(buf[offPin:offHighWater], s.pin[:]) {
		return 0, false, fmt.Errorf("control: epoch state %q identity-pair pin mismatch (wrong peer or identity key)", s.path)
	}
	mac := hmac.New(sha256.New, s.macKey)
	mac.Write(buf[:offMAC])
	if !hmac.Equal(buf[offMAC:], mac.Sum(nil)) {
		return 0, false, fmt.Errorf("control: epoch state %q MAC verification failed (corrupt or tampered)", s.path)
	}
	hw := binary.BigEndian.Uint32(buf[offHighWater:offMAC])
	if hw > spiCounterMask {
		return 0, false, fmt.Errorf("control: epoch state %q high-water %d exceeds max %d", s.path, hw, spiCounterMask)
	}
	return hw, true, nil
}

// Store atomically and durably writes highWater. It writes a uniquely-named temp file
// in the target directory (so overlapping writers cannot collide on a shared temp
// name), fsyncs it, renames it over the target (atomic replace), then fsyncs the
// directory so the rename — the durable commit point — survives a crash.
func (s *FileEpochStore) Store(highWater uint32) (err error) {
	buf := s.marshal(highWater)
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".icx-epoch-*.tmp")
	if err != nil {
		return fmt.Errorf("control: create temp epoch state in %q: %w", dir, err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(buf); err != nil {
		return fmt.Errorf("control: write epoch state: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("control: fsync epoch state: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("control: close epoch state: %w", err)
	}
	if err = os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("control: rename epoch state into place: %w", err)
	}
	committed = true
	if derr := fsyncDir(dir); derr != nil {
		// The rename succeeded, so the new high-water IS in the file; only the
		// durability of the directory ENTRY across a power loss is unconfirmed. On
		// filesystems where directory fsync is unsupported (some overlay/network FS)
		// this fails every time. Treat it as success for bookkeeping — returning an
		// error here would wrongly count a durable write as a failure and could fail a
		// healthy node closed under --require-state — but warn so a genuinely failing
		// device is visible.
		slog.Warn("control: epoch state written but directory fsync failed; value is durable, crash-durability of the rename is unconfirmed",
			slog.Any("error", derr))
	}
	return nil
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Tunables for the durable-epoch machinery. Defaults live on the Tunnel so tests can
// override them; the constants below are the shared, non-overridable parameters.
const (
	// epochSeedMargin is how far above the carried-forward high-water the initiator
	// seeds each new session's allocator (see seedWithMargin). The worst case it must
	// cover is the survivor holding ~2 generations beyond the initiator's known
	// high-water (durable-restart persistence lag) and 1 generation beyond it on a
	// torn-exchange reconnect, so a margin >= 2 is sufficient; 8 is slack against any
	// future rekey pipelining. It is applied per session, so each reconnect/restart
	// spends up to margin epochs — negligible against the 2^30 counter space (a
	// reconnect every second for years before it matters).
	epochSeedMargin = 8

	// persistShutdownGrace bounds how long stop() waits for the persister goroutine to
	// drain before abandoning it, so a wedged Store (uninterruptible fsync on a dying
	// disk) cannot pin shutdown — and the --require-state fail-closed error can still
	// reach the errgroup.
	persistShutdownGrace = 3 * time.Second

	defaultMaxStoreFailures    = 5
	defaultPersistStallTimeout = 60 * time.Second
)

// errEpochPersistStalled is returned from Run (initiator, --require-state only) when
// durable persistence has fallen far enough behind that seamless restart recovery is
// no longer guaranteed. It is fatal/non-retryable: the operator asked to fail closed.
var errEpochPersistStalled = errors.New("control: durable epoch persistence is failing")

// seedWithMargin computes the allocator seed floor for a carried-forward high-water:
// hw + epochSeedMargin, clamped to spiCounterMask-1. It is applied at SEED time (every
// new session on the initiator), so the margin covers BOTH gaps that can leave the
// seed at or below what the surviving peer already retained:
//
//   - the durable persistence gap on an initiator restart (the on-disk value lags the
//     survivor by up to ~2 generations); and
//   - the torn-exchange lead on an in-memory reconnect: a session can tear after the
//     responder committed epoch E but before the initiator recorded it (recordInstalled
//     runs only on a successful install), leaving the initiator's high-water one behind
//     the responder's. Without a margin the initiator would re-offer E and the
//     responder's strictly-increasing guard would reject it — a one-generation
//     data-plane black-hole. The margin (>= 2) seeds strictly above E, so the guard
//     accepts.
//
// The clamp is one below the ceiling so the seeded allocator can still hand out the
// terminal counter spiCounterMask before exhausting (clamping to spiCounterMask itself
// would make the very first Allocate fail). Reaching the clamp is the exhaustion
// warning threshold.
func seedWithMargin(hw uint32) uint32 {
	const ceil = spiCounterMask - 1
	if hw >= ceil || hw+epochSeedMargin > ceil {
		return ceil
	}
	return hw + epochSeedMargin
}

// epochPersister owns the EpochStore and writes to it from a single dedicated
// goroutine, so an fsync on a degraded disk never blocks the Tunnel's run loop (which
// also drives reconnect and rekey). Requests are coalesced through a one-slot mailbox
// — only the latest high-water matters — and the in-memory high-water remains the
// source of truth, so a late or dropped write merely widens the rollback gap (which
// the seed margin absorbs) rather than corrupting anything.
type epochPersister struct {
	store    EpochStore
	reqCh    chan uint32
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once

	high     atomic.Uint32 // last value successfully stored
	failures atomic.Int64  // consecutive Store failures
	lastOK   atomic.Int64  // unix nanos of the last successful store (or start)
}

func newEpochPersister(store EpochStore, startHigh uint32, nowNanos int64) *epochPersister {
	p := &epochPersister{
		store:  store,
		reqCh:  make(chan uint32, 1),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	p.high.Store(startHigh)
	p.lastOK.Store(nowNanos)
	go p.run()
	return p
}

func (p *epochPersister) run() {
	defer close(p.doneCh)
	for {
		select {
		case <-p.stopCh:
			// Best-effort final flush of any queued value on clean shutdown.
			select {
			case v := <-p.reqCh:
				p.flush(v)
			default:
			}
			return
		case v := <-p.reqCh:
			p.flush(v)
		}
	}
}

func (p *epochPersister) flush(v uint32) {
	if v <= p.high.Load() {
		return // already durable (coalesced no-op)
	}
	if err := p.store.Store(v); err != nil {
		n := p.failures.Add(1)
		slog.Error("control: failed to persist epoch high-water; one-sided-restart recovery is degrading (set --require-state to fail closed)",
			slog.Uint64("highWater", uint64(v)), slog.Int64("consecutiveFailures", n), slog.Any("error", err))
		return
	}
	p.failures.Store(0)
	p.high.Store(v)
	p.lastOK.Store(time.Now().UnixNano())
}

// request enqueues v as the latest high-water to persist, coalescing with any value
// still queued by keeping the LARGER of the two — so a request can never drop a higher
// high-water (requests are monotonic in normal use, but keeping the max is robust
// regardless). It never blocks (single producer: the Tunnel's run goroutine).
func (p *epochPersister) request(v uint32) {
	for {
		select {
		case p.reqCh <- v:
			return
		case old := <-p.reqCh:
			if old > v {
				v = old
			}
		}
	}
}

// fatal reports whether durable persistence has degraded past the point of guaranteed
// recovery, but only under requireState (otherwise persistence is best-effort).
// target is the latest in-memory high-water the caller wants durable. It trips on
// SUSTAINED failure (>= maxFailures consecutive Store errors) or a HUNG store (un-
// persisted work with no progress for longer than stall). Intermittent slowness does
// not trip it, and need not: each success coalesces to and stores the latest
// high-water, so recovery never falls materially behind.
func (p *epochPersister) fatal(requireState bool, target uint32, now time.Time, maxFailures int64, stall time.Duration) error {
	if !requireState {
		return nil
	}
	if f := p.failures.Load(); f >= maxFailures {
		return fmt.Errorf("%w: %d consecutive store failures", errEpochPersistStalled, f)
	}
	// Also catch a silently hung store (no error, no progress) once there is
	// un-persisted work that has not advanced for too long.
	if target > p.high.Load() && now.Sub(time.Unix(0, p.lastOK.Load())) > stall {
		return fmt.Errorf("%w: durable high-water stalled > %s behind the live epoch", errEpochPersistStalled, stall)
	}
	return nil
}

// stop signals the persister to exit and waits for it, but only up to
// persistShutdownGrace: a Store wedged in an uninterruptible fsync would otherwise
// pin the goroutine forever and, since Run defers Close which calls stop, prevent the
// process from exiting (and prevent a --require-state fatal from reaching the
// errgroup). The wedged goroutine is then abandoned (the OS reaps it at exit).
func (p *epochPersister) stop() {
	p.stopOnce.Do(func() { close(p.stopCh) })
	select {
	case <-p.doneCh:
	case <-time.After(persistShutdownGrace):
		slog.Warn("control: epoch-state persister did not stop within grace; abandoning a stuck store write")
	}
}
