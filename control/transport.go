package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// appErrNormal is the QUIC application close code used for a clean shutdown.
const appErrNormal quic.ApplicationErrorCode = 0

// activeMasterKeyIndex is the master key used for new SAs in this first
// generation. Master-key rotation (PSP's double-rotation) is layered on later;
// for now both peers always use index 0.
const activeMasterKeyIndex = 0

// defaultQUICConfig is the control-plane QUIC configuration. Notably it does NOT
// enable 0-RTT, so every (re)handshake is a full ECDHE exchange — fresh keys
// per session, i.e. forward secrecy by construction.
func defaultQUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: 10 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      10 * time.Second,
		MaxIncomingStreams:   4,
	}
}

// Session is an established control-plane connection: an authenticated,
// forward-secret QUIC/mTLS channel plus the PSP master keys derived from its
// TLS exporter. From a Session, peers negotiate the per-direction SAs whose
// keys feed the Geneve/AF_XDP data plane.
type Session struct {
	conn       *quic.Conn
	role       Role
	masterKeys *MasterKeys
	rxAlloc    *SPIAllocator
}

// Dial establishes the initiator side of a control session to peerAddr over the
// already-bound UDP socket pconn, authenticating as local and pinning peerPub.
func Dial(ctx context.Context, pconn net.PacketConn, peerAddr net.Addr, local *Identity, peerPub *ecdsa.PublicKey) (*Session, error) {
	tlsConf, err := ClientTLSConfig(local, peerPub)
	if err != nil {
		return nil, err
	}
	conn, err := quic.Dial(ctx, pconn, peerAddr, tlsConf, defaultQUICConfig())
	if err != nil {
		return nil, fmt.Errorf("control: dial: %w", err)
	}
	return newSession(ctx, conn, Initiator)
}

// Listener accepts inbound control sessions on a UDP socket. The underlying
// quic.Transport performs Retry-based source-address validation and enforces
// QUIC's 3x anti-amplification limit, which is the handshake-flood defense.
type Listener struct {
	ln *quic.Listener
	tr *quic.Transport
}

// Listen returns a control-plane listener on pconn that authenticates as local
// and pins peerPub.
func Listen(pconn net.PacketConn, local *Identity, peerPub *ecdsa.PublicKey) (*Listener, error) {
	tlsConf, err := ServerTLSConfig(local, peerPub)
	if err != nil {
		return nil, err
	}
	return listen(pconn, tlsConf, defaultQUICConfig())
}

// keyPlaneMaxConcurrentStreams bounds how many in-flight per-sandbox exchange
// streams a single key-plane session may have open at once. Each exchange is a
// short request/reply on its own stream that roundTrip/ServeKeyPlane open,
// drain to EOF, and retire — so this caps CONCURRENT sandbox starts on one
// worker session, not the lifetime total. Raising it trades responder memory
// for burst headroom; exceeding it makes the next OpenStreamSync block (not
// fail) until an earlier exchange's stream retires.
const keyPlaneMaxConcurrentStreams = 256

// ListenPeers returns a multi-peer control-plane listener: any peer whose
// identity key passes authorize may establish a session. This is the
// key-plane trust model (one responder, many authorized initiators — see
// ServeKeyPlane); the symmetric 1:1 tunnel keeps using Listen. The QUIC
// config allows a deeper incoming-stream window than the 1:1 tunnel because
// each sandbox start opens a short-lived exchange stream and starts arrive in
// bursts.
func ListenPeers(pconn net.PacketConn, local *Identity, authorize PeerAuthorizer) (*Listener, error) {
	tlsConf, err := ServerTLSConfigAuth(local, authorize)
	if err != nil {
		return nil, err
	}
	cfg := defaultQUICConfig()
	cfg.MaxIncomingStreams = keyPlaneMaxConcurrentStreams
	return listen(pconn, tlsConf, cfg)
}

func listen(pconn net.PacketConn, tlsConf *tls.Config, cfg *quic.Config) (*Listener, error) {
	tr := &quic.Transport{Conn: pconn}
	ln, err := tr.Listen(tlsConf, cfg)
	if err != nil {
		_ = tr.Close()
		return nil, fmt.Errorf("control: listen: %w", err)
	}
	return &Listener{ln: ln, tr: tr}, nil
}

// Accept blocks until a peer completes the mTLS handshake, then returns the
// established session (responder role).
func (l *Listener) Accept(ctx context.Context) (*Session, error) {
	conn, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return newSession(ctx, conn, Responder)
}

// Addr returns the local address the listener is bound to.
func (l *Listener) Addr() net.Addr { return l.ln.Addr() }

// Close tears down the listener and its transport.
func (l *Listener) Close() error {
	err := l.ln.Close()
	if cerr := l.tr.Close(); err == nil {
		err = cerr
	}
	return err
}

// newSession waits for the handshake, derives the master keys from the TLS
// exporter, and returns the ready session.
func newSession(ctx context.Context, conn *quic.Conn, role Role) (*Session, error) {
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		_ = conn.CloseWithError(appErrNormal, "handshake cancelled")
		return nil, ctx.Err()
	}

	// Assert the negotiated ALPN explicitly. TLS already fails the handshake when
	// NextProtos don't overlap (both sides advertise only ALPN), but enforcing the
	// invariant in code keeps it true if NextProtos is ever widened, and makes the
	// guarantee auditable rather than implied.
	state := conn.ConnectionState()
	tlsState := state.TLS
	if tlsState.NegotiatedProtocol != ALPN {
		_ = conn.CloseWithError(appErrNormal, "alpn mismatch")
		return nil, fmt.Errorf("control: unexpected ALPN %q, want %q", tlsState.NegotiatedProtocol, ALPN)
	}

	// Enforce a FRESH ECDHE handshake: refuse a resumed session or 0-RTT. The data
	// plane's nonce-uniqueness guarantee rests on every session deriving fresh master
	// keys (so a reset/regressed SPI is always paired with a fresh key — see
	// handler.UpdateVirtualNetworkSAs). Resumption is already disabled in the TLS config
	// (SessionTicketsDisabled), so this is a fail-closed backstop against a silent
	// regression rather than an expected path.
	if tlsState.DidResume {
		_ = conn.CloseWithError(appErrNormal, "session resumption forbidden")
		return nil, errors.New("control: TLS session was resumed; a fresh ECDHE handshake is required for data-plane nonce safety")
	}
	if state.Used0RTT {
		_ = conn.CloseWithError(appErrNormal, "0-RTT forbidden")
		return nil, errors.New("control: connection used 0-RTT; a fresh ECDHE handshake is required for data-plane nonce safety")
	}

	root, err := ExportRootSecret(tlsState)
	if err != nil {
		_ = conn.CloseWithError(appErrNormal, "exporter failure")
		return nil, err
	}
	mk, err := DeriveMasterKeys(root)
	if err != nil {
		_ = conn.CloseWithError(appErrNormal, "key derivation failure")
		return nil, err
	}
	return &Session{
		conn:       conn,
		role:       role,
		masterKeys: mk,
		rxAlloc:    NewSPIAllocator(role),
	}, nil
}

// Role reports whether this peer is the initiator or responder.
func (s *Session) Role() Role { return s.role }

// MasterKeys returns the PSP master keys derived from this session.
func (s *Session) MasterKeys() *MasterKeys { return s.masterKeys }

// TLSState returns the negotiated TLS connection state (version, cipher suite,
// peer certificate). Useful for logging and for asserting the FIPS suite.
func (s *Session) TLSState() tls.ConnectionState { return s.conn.ConnectionState().TLS }

// PeerPublicKey returns the peer's authenticated identity key — the leaf
// certificate's ECDSA key, already verified by the handshake's authorizer.
// On a multi-peer responder this is how a session maps back to which
// initiator it belongs to.
func (s *Session) PeerPublicKey() (*ecdsa.PublicKey, error) {
	certs := s.conn.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("control: peer presented no certificate")
	}
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("control: peer certificate key is not ECDSA")
	}
	return pub, nil
}

// Context returns a context that is cancelled when the underlying QUIC connection
// closes (peer close, idle timeout, or transport error). RunTunnel selects on it to
// detect session loss promptly rather than waiting for the next rekey tick.
func (s *Session) Context() context.Context { return s.conn.Context() }

// Close cleanly shuts the session down.
func (s *Session) Close() error { return s.conn.CloseWithError(appErrNormal, "") }

// DirectionalSAs is a peer's pair of simplex SAs for one session generation:
// Tx is what we encrypt outbound with (the peer's RX SPI), Rx is what we
// decrypt inbound with (our own RX SPI).
type DirectionalSAs struct {
	Tx *SA
	Rx *SA
}

// NegotiateSAs runs the SA-setup exchange over a fresh QUIC stream and returns
// the tx/rx SAs for cipher suite v. Each peer allocates and announces its own RX
// SPI; both then derive every key locally from the shared master keys. The
// initiator writes first, the responder replies, so there is no deadlock.
//
// This round-trip is also the mutual key-confirmation: in TLS 1.3 mutual auth
// the initiator's handshake completes before the responder verifies the
// initiator's certificate, so a successful Dial does NOT prove the peer accepted
// us. A peer that fails to pin us tears the connection down, which makes this
// exchange fail. Callers MUST therefore treat a successful NegotiateSAs — not a
// successful Dial/Accept — as the precondition for installing keys (fail-closed).
//
// Concurrency: NOT safe for unmatched concurrent calls on one Session. It pairs
// one initiator OpenStreamSync with one responder AcceptStream, so call it
// sequentially, or have both peers issue the same number of concurrent calls
// (≤ MaxIncomingStreams); a surplus initiator call blocks until a matching
// responder call or the ctx deadline.
func (s *Session) NegotiateSAs(ctx context.Context, v ICXVersion) (*DirectionalSAs, error) {
	if !v.valid() {
		return nil, fmt.Errorf("control: unsupported cipher suite %d", v)
	}
	myRxSPI, err := s.rxAlloc.Allocate(activeMasterKeyIndex)
	if err != nil {
		return nil, err
	}
	offer := saOffer{Version: v, RxSPI: myRxSPI}

	var stream *quic.Stream
	if s.role == Initiator {
		stream, err = s.conn.OpenStreamSync(ctx)
	} else {
		stream, err = s.conn.AcceptStream(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("control: open SA-setup stream: %w", err)
	}
	defer stream.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(dl)
	}

	var peer saOffer
	if s.role == Initiator {
		if err := writeFrame(stream, offer.marshal()); err != nil {
			return nil, fmt.Errorf("control: send SA offer: %w", err)
		}
		if peer, err = readSAOffer(stream); err != nil {
			return nil, fmt.Errorf("control: read peer SA offer: %w", err)
		}
	} else {
		if peer, err = readSAOffer(stream); err != nil {
			return nil, fmt.Errorf("control: read peer SA offer: %w", err)
		}
		if err := writeFrame(stream, offer.marshal()); err != nil {
			return nil, fmt.Errorf("control: send SA offer: %w", err)
		}
	}

	return s.deriveDirectional(v, myRxSPI, peer)
}

// deriveDirectional derives the tx/rx SAs and enforces the txKey != rxKey
// invariant (the role-partitioned SPI space guarantees distinct SPIs, but we
// assert on the derived keys as a belt-and-suspenders check).
func (s *Session) deriveDirectional(v ICXVersion, myRxSPI uint32, peer saOffer) (*DirectionalSAs, error) {
	if peer.Version != v {
		return nil, fmt.Errorf("control: cipher suite mismatch: local %d, peer %d", v, peer.Version)
	}
	// The peer's RX SPI is attacker-influenced on the multi-peer key plane, so
	// enforce the role-partition invariant before deriving a key from it: a
	// peer-allocated SPI MUST carry the opposite role bit and the active
	// master-key index. Without this a malicious initiator could announce an SPI
	// inside the responder's own role/index partition, making the responder's TX
	// key for one exchange collide byte-for-byte with an RX key its allocator
	// later mints for a different VNI — same key, same SPI, distinct SA, i.e.
	// catastrophic (key, nonce) reuse the per-exchange tx!=rx guard cannot see.
	if MasterKeyIndex(peer.RxSPI) != activeMasterKeyIndex {
		return nil, fmt.Errorf("control: peer SPI uses inactive master-key index %d", MasterKeyIndex(peer.RxSPI))
	}
	if RoleOf(peer.RxSPI) == s.role {
		return nil, errors.New("control: peer SPI collides with the local role partition (SPI spoofing)")
	}
	rx, err := s.masterKeys.DeriveSA(myRxSPI, v)
	if err != nil {
		return nil, fmt.Errorf("control: derive rx SA: %w", err)
	}
	tx, err := s.masterKeys.DeriveSA(peer.RxSPI, v)
	if err != nil {
		return nil, fmt.Errorf("control: derive tx SA: %w", err)
	}
	if bytes.Equal(tx.Key, rx.Key) {
		return nil, errors.New("control: tx and rx SA keys collided")
	}
	return &DirectionalSAs{Tx: tx, Rx: rx}, nil
}
