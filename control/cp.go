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
// Data-plane SA model (PSP, per-direction): the handler installs two simplex SAs per
// generation (handler.go: UpdateVirtualNetworkSAs), each selected by its own
// role-partitioned SPI. NegotiateSAs gives each peer a DirectionalSAs{Rx, Tx} where Rx
// is the SPI this peer allocated (our receive SPI) and Tx is the peer's receive SPI
// (what we transmit to). Both peers derive every key locally from the shared master
// keys, so nothing but the SPIs crosses the wire. Each direction therefore has its own
// nonce space, separated by the SPI itself (the role bit) on top of the distinct
// per-direction key.
//
// No persisted epoch state is needed for recovery. The per-session SPI allocator resets
// on every (re)connect, so a fresh session's SPIs start low again — but that is SAFE
// because every reconnect is a fresh ECDHE handshake (no 0-RTT, no resumption; enforced
// in transport.go) yielding fresh master keys, so a reused SPI value derives a different
// key and the data-plane nonce never repeats. The handler's install guard therefore
// accepts the reset SPI (it rejects only a re-install of the currently-live transmit
// SPI), which makes a transient reconnect and a one-sided restart of either peer recover
// seamlessly with zero on-disk state.

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

// SAInstaller installs a negotiated SA generation into the data plane. rxSPI is our
// receive SPI (we decrypt inbound frames under it); txSPI is the peer's receive SPI (we
// encrypt outbound frames to it); rxKey/txKey are the 16-byte AES-128 keys for those
// directions. The installer owns the key lifetime/expiry and is expected to enforce the
// handler's fail-closed guards (non-zero, strictly increasing per-direction SPIs,
// rxKey != txKey). A returned error is treated as a rejected rotation, not a session
// failure.
type SAInstaller func(rxSPI, txSPI uint32, rxKey, txKey [16]byte) error

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

	// tunables (defaults set by NewTunnel; tests may override)
	perExchangeTimeout time.Duration
	reconnectBackoff   time.Duration

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
	initiator, err := CanonicalInitiator(cfg.Local.PublicKey(), cfg.PeerPub)
	if err != nil {
		return nil, err
	}
	return &Tunnel{
		local:              cfg.Local,
		peerPub:            cfg.PeerPub,
		conn:               cfg.Conn,
		peerAddr:           cfg.PeerAddr,
		rekeyIvl:           cfg.RekeyInterval,
		install:            install,
		initiator:          initiator,
		perExchangeTimeout: defaultPerExchangeTimeout,
		reconnectBackoff:   defaultReconnectBackoff,
	}, nil
}

// Initiator reports the elected role (true = this node dials).
func (t *Tunnel) Initiator() bool { return t.initiator }

// Bringup establishes the session and performs the first SA negotiation and install.
// It is synchronous and FAIL-CLOSED: it returns an error (and installs nothing) if
// the handshake, negotiation, or install fails, so the caller must not start the data
// plane until Bringup succeeds.
func (t *Tunnel) Bringup(ctx context.Context) (err error) {
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
		slog.String("peer", t.peerAddr.String()))
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
		if ctx.Err() != nil {
			return nil
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
			// installSAs swallows an install rejection, so any error here is a genuine
			// session/transport failure → reconnect (which derives fresh keys).
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
// result. installSAs swallows an install rejection (returns nil) so it does not look
// like a transport failure; a non-nil error here means the wire exchange failed.
func (t *Tunnel) negotiateAndInstall(ctx context.Context) error {
	sas, err := t.sess.NegotiateSAs(ctx, AESGCM128)
	if err != nil {
		return err
	}
	return t.installSAs(sas)
}

// installSAs validates the negotiated SAs fail-closed (AES-GCM-128, 16-byte keys) and hands
// the two per-direction SPIs/keys to the installer. Every session derives fresh keys
// (fresh ECDHE; see transport.go), so the handler accepts the install even when the
// per-session allocator reset the SPIs to a low value after a reconnect. An install
// rejection is swallowed as defense-in-depth (e.g. the handler refusing to reset its
// currently-live transmit SPI): the previously installed keys keep forwarding and the
// data plane fails closed on their own expiry.
func (t *Tunnel) installSAs(sas *DirectionalSAs) error {
	if sas.Tx.Version != AESGCM128 || sas.Rx.Version != AESGCM128 {
		return fmt.Errorf("control: only the AES-GCM-128 cipher suite is supported in this build (tx=%d rx=%d)", sas.Tx.Version, sas.Rx.Version)
	}
	if len(sas.Rx.Key) != 16 || len(sas.Tx.Key) != 16 {
		return fmt.Errorf("control: expected 16-byte SA keys (rx=%d tx=%d)", len(sas.Rx.Key), len(sas.Tx.Key))
	}
	var rxKey, txKey [16]byte
	copy(rxKey[:], sas.Rx.Key)
	copy(txKey[:], sas.Tx.Key)
	if err := t.install(sas.Rx.SPI, sas.Tx.SPI, rxKey, txKey); err != nil {
		slog.Warn("control: SA install rejected; keeping current keys until they expire",
			slog.Uint64("rxSPI", uint64(sas.Rx.SPI)), slog.Uint64("txSPI", uint64(sas.Tx.SPI)), slog.Any("error", err))
		return nil
	}
	slog.Debug("control: installed SA generation",
		slog.Uint64("rxSPI", uint64(sas.Rx.SPI)), slog.Uint64("txSPI", uint64(sas.Tx.SPI)))
	return nil
}

// establish opens a fresh session: the initiator dials, the responder accepts on a
// listener it keeps across reconnects. The new session's SPI allocator starts fresh
// (low) — safe because the session's keys are also fresh (see installSAs / transport.go).
func (t *Tunnel) establish(ctx context.Context) error {
	if t.initiator {
		sess, err := Dial(ctx, t.conn, t.peerAddr, t.local, t.peerPub)
		if err != nil {
			return err
		}
		t.sess = sess
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
		// full interval. The new session's SPI allocator starts fresh (low) again, but the
		// install is still accepted because the new session derives FRESH master keys
		// (fresh ECDHE; see transport.go), so a reset/regressed SPI is paired with a fresh
		// key and the data-plane nonce never repeats. A transport error drops back to
		// another reconnect attempt.
		exCtx, cancel := context.WithTimeout(ctx, t.perExchangeTimeout)
		err := t.negotiateAndInstall(exCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			if isFatalCP(err) {
				// SPI counter-space exhaustion (ErrSPIExhausted) is terminal: it requires
				// master-key rotation, which this build does not support, and a fresh
				// allocator would just exhaust again. Surface it so Run returns and fails
				// closed rather than hot-looping reconnects.
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

// isFatalCP reports whether err is a terminal, non-retryable control-plane error that
// must stop Run rather than drive a reconnect.
func isFatalCP(err error) bool {
	return errors.Is(err, ErrSPIExhausted)
}

// Close releases the session and (responder) the listener. It is idempotent.
func (t *Tunnel) Close() error {
	t.closeSession()
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
