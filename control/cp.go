package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// This file is the control-plane orchestrator: it drives the QUIC/mTLS session
// (control/transport.go) and feeds the negotiated SAs into the data plane via an
// SAInstaller, so the CLI stays thin and the wiring is unit-testable off Linux.
//
// Data-plane epoch model (this build): the handler carries a SINGLE 32-bit epoch
// per security association for both simplex directions (handler.go), while the
// control plane allocates a DISTINCT, role-partitioned SPI per direction. We bridge
// the two with SharedEpoch: both peers install the same scalar epoch (the
// initiator-allocated SPI) but derive DISTINCT per-direction keys from the distinct
// SPIs, so AES-GCM nonce uniqueness rests on the keys differing (the handler's
// rxKey != txKey guard), exactly as documented at handler.go. Carrying the genuine
// per-direction SPI on the wire (true per-direction nonce spaces) is the additive
// UpdateVirtualNetworkSAs follow-up (Option C); it is intentionally out of scope here.
//
// Because the per-session SPI allocator resets on every (re)connect, the shared epoch
// would regress to 1 and the survivor's strictly-increasing epoch guard would reject
// it. The Tunnel carries an epoch high-water forward and seeds each new session's
// allocator above it (in memory always; durably via an EpochStore on the initiator)
// so reconnects and one-sided restarts keep the epoch monotonic — see
// control/epochstate.go.

// Mode is the keying mode selected from the CLI flags.
type Mode int

const (
	ModeNone Mode = iota
	// ModeStatic is the legacy static pre-shared keys loaded from an INI file.
	ModeStatic
	// ModeControlPlane is the QUIC/mTLS control plane with ephemeral, forward-secret,
	// per-session keys.
	ModeControlPlane
)

func (m Mode) String() string {
	switch m {
	case ModeStatic:
		return "static"
	case ModeControlPlane:
		return "control-plane"
	default:
		return "none"
	}
}

// SelectMode resolves the keying mode from which flags are set, fail-closed.
// Exactly one mode must be configured: either static keys (--key-file) OR the
// control plane (--identity-key AND --peer-key). Any other combination — both, the
// control plane half-configured, or nothing — is an error. There is deliberately no
// silent fallback from the control plane to static keys.
func SelectMode(hasKeyFile, hasIdentity, hasPeer bool) (Mode, error) {
	cp := hasIdentity || hasPeer
	switch {
	case hasKeyFile && cp:
		return ModeNone, errors.New("conflicting keying modes: set --key-file (static) OR --identity-key/--peer-key (control plane), not both")
	case cp:
		if !hasIdentity || !hasPeer {
			return ModeNone, errors.New("control-plane mode requires both --identity-key and --peer-key")
		}
		return ModeControlPlane, nil
	case hasKeyFile:
		return ModeStatic, nil
	default:
		return ModeNone, errors.New("no keying configured: set --key-file (static) or --identity-key and --peer-key (control plane)")
	}
}

// CanonicalInitiator reports whether the local node is the control-plane initiator
// — the peer that dials. The role is elected deterministically from the two pinned
// identities so both ends agree with zero configuration (WireGuard-style): the node
// whose SubjectPublicKeyInfo DER sorts lower is the initiator, the other listens.
// Identical keys are rejected — a node must not tunnel to itself, and equal keys
// would make both ends pick the same role (double-dial / double-listen deadlock).
func CanonicalInitiator(localPub, peerPub *ecdsa.PublicKey) (bool, error) {
	if localPub == nil || peerPub == nil {
		return false, errors.New("control: nil identity key")
	}
	if PublicKeyEqual(localPub, peerPub) {
		return false, errors.New("control: local and peer identity keys are identical; peers must have distinct keys")
	}
	l, err := x509.MarshalPKIXPublicKey(localPub)
	if err != nil {
		return false, fmt.Errorf("control: marshal local key: %w", err)
	}
	p, err := x509.MarshalPKIXPublicKey(peerPub)
	if err != nil {
		return false, fmt.Errorf("control: marshal peer key: %w", err)
	}
	return bytes.Compare(l, p) < 0, nil
}

// roleBit is the SPI bit that encodes the allocating role (see sa.go): the
// initiator allocates SPIs with this bit clear, the responder with it set.
const roleBit = uint32(1) << spiRoleShift

// SharedEpoch derives the single data-plane epoch both peers install for a
// negotiated SA generation. Of the two role-partitioned SPIs the peer holds
// ({Tx, Rx}), exactly one was allocated by the initiator (role bit clear); both
// peers select that one and compute the identical value, because the initiator's
// Rx SPI is the responder's Tx SPI. The epoch is what lands in the Geneve key-epoch
// option and nonce[:4]; the distinct per-direction KEYS still come from the distinct
// SPIs, so the two directions never share a (key, nonce) pair.
//
// This selection is well-defined only while the master-key index (SPI bit31) is 0
// for both directions, which holds until master-key rotation is introduced; rotation
// is a known incompatibility for the shared-epoch bridge and is the trigger for the
// per-direction-SPI follow-up.
func SharedEpoch(sas *DirectionalSAs) (uint32, error) {
	if sas == nil || sas.Tx == nil || sas.Rx == nil {
		return 0, errors.New("control: nil SAs")
	}
	if MasterKeyIndex(sas.Tx.SPI) != 0 || MasterKeyIndex(sas.Rx.SPI) != 0 {
		return 0, errors.New("control: SharedEpoch requires master-key index 0 (rotation not yet supported)")
	}
	txInitiator := sas.Tx.SPI&roleBit == 0
	rxInitiator := sas.Rx.SPI&roleBit == 0
	if txInitiator == rxInitiator {
		return 0, fmt.Errorf("control: SAs are not role-partitioned (tx=%#08x rx=%#08x)", sas.Tx.SPI, sas.Rx.SPI)
	}
	if txInitiator {
		return sas.Tx.SPI, nil
	}
	return sas.Rx.SPI, nil
}

// SAInstaller installs a negotiated SA generation into the data plane. epoch is the
// shared data-plane epoch (see SharedEpoch); rxKey/txKey are the 16-byte AES-128 keys
// for the receive/transmit directions. The installer owns the key lifetime/expiry and
// is expected to enforce the handler's fail-closed guards (non-zero, strictly
// increasing epoch, rxKey != txKey). A returned error is treated as a rejected
// rotation, not a session failure.
type SAInstaller func(epoch uint32, rxKey, txKey [16]byte) error

// Default lifecycle timings; overridable on Tunnel for tests.
const (
	defaultPerExchangeTimeout = 10 * time.Second
	defaultReconnectBackoff   = 5 * time.Second
)

// Tunnel runs the control-plane lifecycle for one peer: it establishes the QUIC/mTLS
// session, performs the initial SA negotiation and install (fail-closed) in Bringup,
// and then keeps the SAs fresh in Run — the initiator drives rekeys on a timer, the
// responder serves them from an accept loop. A Tunnel is not safe for concurrent use;
// Bringup then Run are called once each, in that order.
type Tunnel struct {
	local     *Identity
	peerPub   *ecdsa.PublicKey
	conn      net.PacketConn
	peerAddr  net.Addr
	rekeyIvl  time.Duration
	install   SAInstaller
	initiator bool

	// Durable/in-memory epoch high-water (initiator only; see control/epochstate.go).
	// epochSeed seeds each new session's RX allocator so the shared epoch keeps
	// increasing across a reconnect/restart instead of resetting to 1; installedHigh
	// is the latest installed epoch (the persist target / stall reference); store and
	// persist add durability for an initiator restart.
	store         EpochStore
	requireState  bool
	epochSeed     uint32
	installedHigh uint32
	persist       *epochPersister

	// tunables (defaults set by NewTunnel; tests may override)
	perExchangeTimeout  time.Duration
	reconnectBackoff    time.Duration
	maxStoreFailures    int64
	persistStallTimeout time.Duration

	ln   *Listener // responder only; persists across reconnects
	sess *Session
}

// TunnelConfig is the immutable configuration for a Tunnel.
type TunnelConfig struct {
	// Local is this node's long-term identity (its private key).
	Local *Identity
	// PeerPub is the pinned public key of the single expected peer.
	PeerPub *ecdsa.PublicKey
	// Conn is the bound control-plane UDP socket (separate from the Geneve data port).
	Conn net.PacketConn
	// PeerAddr is the peer's control-plane address (peer IP + control port).
	PeerAddr net.Addr
	// RekeyInterval is how often the initiator negotiates a fresh SA generation.
	RekeyInterval time.Duration
	// EpochStore, when non-nil, persists the data-plane epoch high-water so a restart
	// of the elected INITIATOR recovers seamlessly. It is consulted only when this
	// node is the initiator — the responder's high-water is not load-bearing (the
	// shared epoch is always the initiator-allocated SPI). A responder configured with
	// a store leaves it inert. nil disables durable persistence (a transient reconnect
	// and a responder restart still recover via the in-memory high-water; only a
	// one-sided initiator restart needs the store).
	EpochStore EpochStore
	// RequireState makes durable epoch state fail closed instead of degrading: a
	// corrupt/unreadable state file fails Bringup, and persistently failing/stalled
	// stores fail Run. It requires EpochStore. It is an integrity tripwire against
	// accidental corruption, NOT an anti-rollback/anti-deletion control.
	RequireState bool
}

// NewTunnel validates the config, elects the canonical role, and returns a Tunnel
// ready for Bringup. It does no I/O.
func NewTunnel(cfg TunnelConfig, install SAInstaller) (*Tunnel, error) {
	if cfg.Local == nil || cfg.PeerPub == nil {
		return nil, errors.New("control: tunnel requires local identity and peer key")
	}
	if cfg.Conn == nil || cfg.PeerAddr == nil {
		return nil, errors.New("control: tunnel requires a control socket and peer address")
	}
	if install == nil {
		return nil, errors.New("control: tunnel requires an SA installer")
	}
	if cfg.RekeyInterval <= 0 {
		return nil, errors.New("control: rekey interval must be positive")
	}
	if cfg.RequireState && cfg.EpochStore == nil {
		return nil, errors.New("control: RequireState requires an EpochStore")
	}
	initiator, err := CanonicalInitiator(cfg.Local.PublicKey(), cfg.PeerPub)
	if err != nil {
		return nil, err
	}
	return &Tunnel{
		local:               cfg.Local,
		peerPub:             cfg.PeerPub,
		conn:                cfg.Conn,
		peerAddr:            cfg.PeerAddr,
		rekeyIvl:            cfg.RekeyInterval,
		install:             install,
		initiator:           initiator,
		store:               cfg.EpochStore,
		requireState:        cfg.RequireState,
		perExchangeTimeout:  defaultPerExchangeTimeout,
		reconnectBackoff:    defaultReconnectBackoff,
		maxStoreFailures:    defaultMaxStoreFailures,
		persistStallTimeout: defaultPersistStallTimeout,
	}, nil
}

// Initiator reports the elected role (true = this node dials).
func (t *Tunnel) Initiator() bool { return t.initiator }

// Bringup establishes the session and performs the first SA negotiation and install.
// It is synchronous and FAIL-CLOSED: it returns an error (and installs nothing) if
// the handshake, negotiation, or install fails, so the caller must not start the data
// plane until Bringup succeeds.
func (t *Tunnel) Bringup(ctx context.Context) (err error) {
	if err = t.loadEpochState(); err != nil {
		return err
	}
	// loadEpochState may have started the persister goroutine; reap it if Bringup
	// fails so a caller that drops the Tunnel on a Bringup error does not leak it.
	defer func() {
		if err != nil && t.persist != nil {
			t.persist.stop()
			t.persist = nil
		}
	}()
	if err = t.establish(ctx); err != nil {
		return fmt.Errorf("control: establish session: %w", err)
	}
	if err = t.negotiateAndInstall(ctx); err != nil {
		t.closeSession()
		return fmt.Errorf("control: initial SA negotiation: %w", err)
	}
	role := "responder"
	if t.initiator {
		role = "initiator"
	}
	slog.Info("control plane established", slog.String("role", role),
		slog.String("peer", t.peerAddr.String()),
		slog.Bool("durableEpochState", t.persist != nil))
	return nil
}

// loadEpochState reads the durable epoch high-water and starts the persister. It is a
// no-op except on the initiator with a configured store — the responder's high-water
// is not load-bearing (see control/epochstate.go), so a responder configured with a
// store leaves it inert (and --require-state does not gate the responder). It runs at
// the start of Bringup so NewTunnel stays I/O-free.
func (t *Tunnel) loadEpochState() error {
	if t.store == nil {
		return nil
	}
	if !t.initiator {
		slog.Info("control: durable epoch state inactive on this node (responder role; the shared epoch is initiator-driven). Ensure the elected initiator also has a state file")
		return nil
	}
	hw, ok, err := t.store.Load()
	if err != nil {
		if t.requireState {
			return fmt.Errorf("control: durable epoch state is unreadable and --require-state is set: %w", err)
		}
		slog.Error("control: epoch state unreadable; starting fresh — a one-sided initiator restart will not recover until state is re-persisted. Use --require-state to fail closed instead",
			slog.Any("error", err))
		hw, ok = 0, false
	}
	start := uint32(0)
	if ok {
		// epochSeed/installedHigh track the EXACT high-water; the margin is applied at
		// seed time in establish (see seedWithMargin), so it covers both the durable
		// gap here and the torn-reconnect lead later.
		t.epochSeed = hw
		t.installedHigh = hw
		start = hw
		slog.Info("control: loaded durable epoch high-water",
			slog.Uint64("highWater", uint64(hw)), slog.Uint64("seed", uint64(seedWithMargin(hw))))
		if seedWithMargin(hw) >= spiCounterMask-1 {
			slog.Warn("control: epoch counter space is nearly exhausted; master-key rotation will be required (the control plane will fail closed when it runs out)",
				slog.Uint64("highWater", uint64(hw)), slog.Uint64("ceiling", uint64(spiCounterMask)))
		}
	}
	t.persist = newEpochPersister(t.store, start, time.Now().UnixNano())
	return nil
}

// Run keeps the SAs fresh until ctx is cancelled. The initiator rekeys on its timer
// (and reacts promptly to session loss via the QUIC connection context); the
// responder serves rekeys from a blocking accept loop. A failed negotiation is
// session-fatal: the session is torn down and re-established (fresh, aligned
// allocators) rather than retried on a dead session. Control-plane failures are NOT
// returned: they drive reconnect-with-backoff indefinitely, so Run effectively
// returns only when ctx is cancelled (clean shutdown). If the control plane cannot
// re-establish, the data plane fails closed when the installed keys expire — Run does
// not proactively tear it down. Bringup must have succeeded first.
func (t *Tunnel) Run(ctx context.Context) error {
	defer t.Close()
	if t.initiator {
		return t.runInitiator(ctx)
	}
	return t.runResponder(ctx)
}

func (t *Tunnel) runInitiator(ctx context.Context) error {
	ticker := time.NewTicker(t.rekeyIvl)
	defer ticker.Stop()
	for {
		// A clean shutdown takes priority over the fail-closed tripwire: returning a
		// fatal error here on the way out would mis-report a deliberate stop as a
		// failure (non-zero exit). Mirror the ctx.Err() guards on the other terminal
		// arms below.
		if ctx.Err() != nil {
			return nil
		}
		// Fail closed (only under --require-state) if durable persistence has fallen
		// far enough behind that a restart could no longer recover.
		if err := t.epochPersistFatal(time.Now()); err != nil {
			return err
		}
		sessLost := t.sessionDone()
		select {
		case <-ctx.Done():
			return nil
		case <-sessLost:
			slog.Warn("control: session lost, reconnecting")
			if err := t.reestablish(ctx); err != nil {
				return err
			}
		case <-ticker.C:
			exCtx, cancel := context.WithTimeout(ctx, t.perExchangeTimeout)
			err := t.negotiateAndInstall(exCtx)
			cancel()
			if err == nil {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			if isFatalCP(err) {
				// SPI-space exhaustion is terminal (master-key rotation, unsupported,
				// is the only remedy); reconnecting would just hot-loop. Fail closed.
				return err
			}
			// Epoch regression after a reconnect is now prevented by seeding the
			// allocator from the epoch high-water (see installSAs / loadEpochState);
			// installSAs still swallows a stray rejection, so any error here is a
			// genuine session/transport failure.
			slog.Warn("control: rekey failed, reconnecting", slog.Any("error", err))
			if err := t.reestablish(ctx); err != nil {
				return err
			}
		}
	}
}

func (t *Tunnel) runResponder(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		// The accept loop blocks in NegotiateSAs' AcceptStream until the initiator
		// drives the next rekey; the long-lived ctx (no per-exchange deadline) lets it
		// wait across the whole interval, and QUIC's MaxIdleTimeout bounds a half-open
		// exchange. Errors are session-fatal → reconnect.
		if err := t.negotiateAndInstall(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("control: SA negotiation failed, reconnecting", slog.Any("error", err))
			if err := t.reestablish(ctx); err != nil {
				return err
			}
		}
	}
}

// negotiateAndInstall runs one SA exchange on the live session and installs the
// result. installSAs swallows a rotation rejection (returns nil) so it does not look
// like a transport failure; a non-nil error here means the wire exchange failed.
func (t *Tunnel) negotiateAndInstall(ctx context.Context) error {
	sas, err := t.sess.NegotiateSAs(ctx, PSPv0)
	if err != nil {
		return err
	}
	return t.installSAs(sas)
}

// installSAs validates the negotiated SAs fail-closed (PSPv0, 16-byte keys),
// computes the shared epoch, and hands them to the installer. Seeding the allocator
// from the epoch high-water (see recordInstalled / loadEpochState) keeps the epoch
// strictly increasing across reconnects/restarts, so the monotonicity guard should
// accept every generation in normal operation. A rejection is still swallowed as
// defense-in-depth (e.g. with no durable state after a one-sided initiator restart,
// or a responder whose floor is not seeded): the previously installed keys keep
// forwarding and the data plane fails closed on their own expiry.
func (t *Tunnel) installSAs(sas *DirectionalSAs) error {
	if sas.Tx.Version != PSPv0 || sas.Rx.Version != PSPv0 {
		return fmt.Errorf("control: only PSPv0/AES-128 is supported in this build (tx=%d rx=%d)", sas.Tx.Version, sas.Rx.Version)
	}
	if len(sas.Rx.Key) != 16 || len(sas.Tx.Key) != 16 {
		return fmt.Errorf("control: expected 16-byte SA keys (rx=%d tx=%d)", len(sas.Rx.Key), len(sas.Tx.Key))
	}
	epoch, err := SharedEpoch(sas)
	if err != nil {
		return err
	}
	var rxKey, txKey [16]byte
	copy(rxKey[:], sas.Rx.Key)
	copy(txKey[:], sas.Tx.Key)
	if err := t.install(epoch, rxKey, txKey); err != nil {
		slog.Warn("control: SA install rejected; keeping current keys until they expire (seed the epoch floor / configure --state-file for seamless recovery)",
			slog.Uint64("epoch", uint64(epoch)), slog.Any("error", err))
		return nil
	}
	t.recordInstalled(epoch)
	slog.Debug("control: installed SA generation", slog.Uint64("epoch", uint64(epoch)))
	return nil
}

// recordInstalled advances the initiator's in-memory epoch high-water after a
// successful install and asks the persister to make it durable. It is initiator-only:
// only the initiator's allocator feeds the shared epoch, so only its high-water needs
// to be carried forward. The enqueue never blocks (the persister fsyncs off this
// goroutine).
func (t *Tunnel) recordInstalled(epoch uint32) {
	if !t.initiator {
		return
	}
	if epoch > t.epochSeed {
		t.epochSeed = epoch
	}
	if epoch > t.installedHigh {
		t.installedHigh = epoch
	}
	if t.persist != nil {
		t.persist.request(t.installedHigh)
	}
}

// establish opens a fresh session: the initiator dials, the responder accepts on a
// listener it keeps across reconnects.
func (t *Tunnel) establish(ctx context.Context) error {
	if t.initiator {
		sess, err := Dial(ctx, t.conn, t.peerAddr, t.local, t.peerPub)
		if err != nil {
			return err
		}
		t.sess = sess
		// Seed THIS session's allocator above the epoch high-water (plus a margin) so
		// the shared epoch keeps climbing across the reconnect rather than resetting to
		// 1, AND stays strictly above what the survivor retained even if the last
		// exchange tore after the responder committed but before we recorded it (see
		// seedWithMargin). A fresh start (no high-water) seeds 0 → epoch 1, unchanged.
		// Only the initiator is seeded: SharedEpoch always selects the
		// initiator-allocated SPI, so the responder's allocator is cosmetic to the wire
		// epoch.
		if t.epochSeed > 0 {
			t.sess.SeedRxFloor(seedWithMargin(t.epochSeed))
		}
		return nil
	}
	if t.ln == nil {
		ln, err := Listen(t.conn, t.local, t.peerPub)
		if err != nil {
			return err
		}
		t.ln = ln
	}
	sess, err := t.ln.Accept(ctx)
	if err != nil {
		return err
	}
	t.sess = sess
	return nil
}

// reestablish tears down the dead session and re-establishes one, backing off
// between attempts so a persistent failure does not hot-loop. It returns an error
// only if ctx is cancelled while waiting.
func (t *Tunnel) reestablish(ctx context.Context) error {
	t.closeSession()
	for attempt := 0; ; attempt++ {
		// Try immediately on the first attempt; back off only between retries so a
		// transient loss recovers without an added backoff of latency.
		if attempt > 0 && !sleepCtx(ctx, t.reconnectBackoff) {
			return ctx.Err()
		}
		if err := t.establish(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			slog.Warn("control: reconnect attempt failed", slog.Any("error", err))
			continue
		}
		// Re-key immediately on the new session so traffic resumes without waiting a
		// full interval. The new session's allocator is seeded from the epoch
		// high-water (establish), so the epoch keeps increasing and the install is
		// accepted; a transport error drops back to another reconnect attempt.
		exCtx, cancel := context.WithTimeout(ctx, t.perExchangeTimeout)
		err := t.negotiateAndInstall(exCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			if isFatalCP(err) {
				// Exhaustion is terminal — re-seeding the same exhausted floor would
				// hot-loop. Surface it so Run returns and fails closed.
				return err
			}
			slog.Warn("control: post-reconnect negotiation failed", slog.Any("error", err))
			t.closeSession()
			continue
		}
		return ctx.Err()
	}
}

// sessionDone returns the current session's done channel, or nil (which blocks
// forever in a select) if there is no live session.
func (t *Tunnel) sessionDone() <-chan struct{} {
	if t.sess == nil {
		return nil
	}
	return t.sess.Context().Done()
}

func (t *Tunnel) closeSession() {
	if t.sess != nil {
		_ = t.sess.Close()
		t.sess = nil
	}
}

// epochPersistFatal reports a fatal error if durable persistence has degraded past
// the point of guaranteed recovery (only under --require-state; otherwise nil).
func (t *Tunnel) epochPersistFatal(now time.Time) error {
	if t.persist == nil {
		return nil
	}
	return t.persist.fatal(t.requireState, t.installedHigh, now, t.maxStoreFailures, t.persistStallTimeout)
}

// isFatalCP reports whether err is a terminal, non-retryable control-plane error that
// must stop Run rather than drive a reconnect.
func isFatalCP(err error) bool {
	return errors.Is(err, ErrSPIExhausted) || errors.Is(err, errEpochPersistStalled)
}

// Close releases the session, stops the persister, and (responder) the listener. It is
// idempotent.
func (t *Tunnel) Close() error {
	t.closeSession()
	if t.persist != nil {
		t.persist.stop()
	}
	if t.ln != nil {
		err := t.ln.Close()
		t.ln = nil
		return err
	}
	return nil
}

// sleepCtx waits for d or until ctx is done. It reports false if ctx was cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
