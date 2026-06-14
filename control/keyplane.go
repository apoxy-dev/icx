package control

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// The key plane is the multi-peer, client/server use of the control session:
// many initiators (e.g. worker pods) each hold one session to a responder
// (the tunnel terminator), and over that session run one short exchange per
// virtual network they want keyed (e.g. per sandbox). The initiator announces
// its RX SPI and the overlay address; the responder allocates a VNI plus its
// own RX SPI, derives the per-direction SAs from the session master keys, and
// installs its side through the KeyGranter before replying. PSP derivation
// makes concurrent grants on one session safe: distinct SPIs derive distinct
// keys, so no two grants ever share a (key, nonce) space.
//
// Roles are fixed (the dialer requests, the listener grants) — the
// WireGuard-style canonical-role election in cp.go only fits the symmetric
// 1:1 tunnel.
//
// Like NegotiateSAs, a completed exchange — not a completed handshake — is
// the mutual key confirmation; callers must not install or use keys unless
// RequestKeys returns successfully.

// Key-plane message types (the shared msgType space is anchored by
// msgSAOffer in protocol.go).
const (
	msgKeyRequest msgType = 2
	msgKeyGrant   msgType = 3
	msgVNIRelease msgType = 4
	msgReleaseAck msgType = 5
)

// grantStatus is the responder's wire verdict on a key request or release.
type grantStatus uint8

const (
	grantOK        grantStatus = 0
	grantRejected  grantStatus = 1
	grantExhausted grantStatus = 2 // VNI space full — transient (releases/quarantine free it).
	// grantSPIExhausted is the responder's per-session RX-SPI counter exhaustion:
	// terminal for this session (only a fresh ECDHE reconnect recovers), distinct
	// from the transient grantExhausted so the initiator does not hot-loop retry.
	grantSPIExhausted grantStatus = 3
)

// keyStreamTimeout bounds a single responder-side exchange: how long
// serveKeyStream waits for a request frame (and for the peer's FIN while
// draining) before abandoning the stream. It keeps a peer that opens a stream
// and then stalls from parking a goroutine and a stream slot until QUIC's 30s
// idle timeout, and bounds ServeKeyPlane's teardown wait.
const keyStreamTimeout = 10 * time.Second

// ErrGrantRejected is returned by RequestKeys/ReleaseKeys when the responder
// refused the request. The responder deliberately does not say why
// (authorization detail stays server-side).
var ErrGrantRejected = errors.New("control: key request rejected by responder")

// keyRequest is the initiator half of one exchange: the SPI it will RECEIVE
// on and the overlay address it wants keyed. The address is opaque to the
// control plane — the responder's KeyGranter gives it meaning.
type keyRequest struct {
	PSPVersion PSPVersion
	RxSPI      uint32
	Addr       netip.Addr
}

const keyRequestLen = 1 + 1 + 1 + 4 + 16 // protoVer + type + pspVer + rxSPI + addr

func (r keyRequest) marshal() []byte {
	b := make([]byte, keyRequestLen)
	b[0] = ProtocolVersion
	b[1] = byte(msgKeyRequest)
	b[2] = byte(r.PSPVersion)
	binary.BigEndian.PutUint32(b[3:], r.RxSPI)
	a16 := r.Addr.As16()
	copy(b[7:], a16[:])
	return b
}

func parseKeyRequest(b []byte) (keyRequest, error) {
	if len(b) != keyRequestLen {
		return keyRequest{}, fmt.Errorf("control: key request wrong size %d, want %d", len(b), keyRequestLen)
	}
	if b[0] != ProtocolVersion {
		return keyRequest{}, fmt.Errorf("control: unsupported protocol version %d", b[0])
	}
	if msgType(b[1]) != msgKeyRequest {
		return keyRequest{}, fmt.Errorf("control: expected key request, got message type %d", b[1])
	}
	return keyRequest{
		PSPVersion: PSPVersion(b[2]),
		RxSPI:      binary.BigEndian.Uint32(b[3:7]),
		// Unmap so a native IPv4 overlay address round-trips to itself rather
		// than to its ::ffff: 4-in-6 form, which compares unequal and would make
		// the granter see a different address than the initiator announced.
		Addr: netip.AddrFrom16([16]byte(b[7:23])).Unmap(),
	}, nil
}

// keyGrant is the responder half: its own RX SPI and the allocated VNI, or a
// non-OK status with both fields zero.
type keyGrant struct {
	Status     grantStatus
	PSPVersion PSPVersion
	RxSPI      uint32
	VNI        uint32
}

const keyGrantLen = 1 + 1 + 1 + 1 + 4 + 4 // protoVer + type + status + pspVer + rxSPI + vni

func (g keyGrant) marshal() []byte {
	b := make([]byte, keyGrantLen)
	b[0] = ProtocolVersion
	b[1] = byte(msgKeyGrant)
	b[2] = byte(g.Status)
	b[3] = byte(g.PSPVersion)
	binary.BigEndian.PutUint32(b[4:], g.RxSPI)
	binary.BigEndian.PutUint32(b[8:], g.VNI)
	return b
}

func parseKeyGrant(b []byte) (keyGrant, error) {
	if len(b) != keyGrantLen {
		return keyGrant{}, fmt.Errorf("control: key grant wrong size %d, want %d", len(b), keyGrantLen)
	}
	if b[0] != ProtocolVersion {
		return keyGrant{}, fmt.Errorf("control: unsupported protocol version %d", b[0])
	}
	if msgType(b[1]) != msgKeyGrant {
		return keyGrant{}, fmt.Errorf("control: expected key grant, got message type %d", b[1])
	}
	return keyGrant{
		Status:     grantStatus(b[2]),
		PSPVersion: PSPVersion(b[3]),
		RxSPI:      binary.BigEndian.Uint32(b[4:8]),
		VNI:        binary.BigEndian.Uint32(b[8:12]),
	}, nil
}

// vniRelease tells the responder a granted VNI is dead (e.g. its sandbox
// exited) so it can start the quarantine clock.
type vniRelease struct {
	VNI uint32
}

const vniReleaseLen = 1 + 1 + 4 // protoVer + type + vni

func (r vniRelease) marshal() []byte {
	b := make([]byte, vniReleaseLen)
	b[0] = ProtocolVersion
	b[1] = byte(msgVNIRelease)
	binary.BigEndian.PutUint32(b[2:], r.VNI)
	return b
}

func parseVNIRelease(b []byte) (vniRelease, error) {
	if len(b) != vniReleaseLen {
		return vniRelease{}, fmt.Errorf("control: VNI release wrong size %d, want %d", len(b), vniReleaseLen)
	}
	if b[0] != ProtocolVersion {
		return vniRelease{}, fmt.Errorf("control: unsupported protocol version %d", b[0])
	}
	if msgType(b[1]) != msgVNIRelease {
		return vniRelease{}, fmt.Errorf("control: expected VNI release, got message type %d", b[1])
	}
	return vniRelease{VNI: binary.BigEndian.Uint32(b[2:6])}, nil
}

// releaseAck acknowledges a vniRelease.
type releaseAck struct {
	Status grantStatus
}

const releaseAckLen = 1 + 1 + 1 // protoVer + type + status

func (a releaseAck) marshal() []byte {
	return []byte{ProtocolVersion, byte(msgReleaseAck), byte(a.Status)}
}

func parseReleaseAck(b []byte) (releaseAck, error) {
	if len(b) != releaseAckLen {
		return releaseAck{}, fmt.Errorf("control: release ack wrong size %d, want %d", len(b), releaseAckLen)
	}
	if b[0] != ProtocolVersion {
		return releaseAck{}, fmt.Errorf("control: unsupported protocol version %d", b[0])
	}
	if msgType(b[1]) != msgReleaseAck {
		return releaseAck{}, fmt.Errorf("control: expected release ack, got message type %d", b[1])
	}
	return releaseAck{Status: grantStatus(b[2])}, nil
}

// KeyGrant is the initiator's result of one per-network key exchange: the
// VNI the responder allocated and the per-direction SAs, derived locally
// (key material never crossed the wire).
type KeyGrant struct {
	VNI uint32
	SAs *DirectionalSAs
}

// RequestKeys runs one key-plane exchange on an initiator session: it asks
// the responder to key addr, and returns the granted VNI plus the derived
// per-direction SAs. Each call allocates a fresh SPI, so concurrent calls on
// one session are safe and every grant has distinct keys. On
// ErrVNIExhausted/ErrSPIExhausted the session is useless for new grants;
// existing grants keep working until released or rotated.
func (s *Session) RequestKeys(ctx context.Context, v PSPVersion, addr netip.Addr) (*KeyGrant, error) {
	if s.role != Initiator {
		return nil, errors.New("control: RequestKeys requires the initiator role")
	}
	if !v.valid() {
		return nil, fmt.Errorf("control: unsupported PSP version %d", v)
	}
	if !addr.IsValid() {
		return nil, errors.New("control: invalid overlay address")
	}
	myRxSPI, err := s.rxAlloc.Allocate(activeMasterKeyIndex)
	if err != nil {
		return nil, err
	}

	req := keyRequest{PSPVersion: v, RxSPI: myRxSPI, Addr: addr}
	respBytes, err := s.roundTrip(ctx, req.marshal())
	if err != nil {
		return nil, err
	}
	grant, err := parseKeyGrant(respBytes)
	if err != nil {
		return nil, err
	}
	if grant.Status != grantOK {
		return nil, statusToError(grant.Status)
	}
	if grant.VNI == 0 || grant.VNI > MaxVNI {
		// The responder allocated and installed under this VNI before replying;
		// release it so a bad grant does not linger until session teardown.
		s.bestEffortRelease(grant.VNI)
		return nil, fmt.Errorf("control: responder granted out-of-range VNI %d", grant.VNI)
	}
	sas, err := s.deriveDirectional(v, myRxSPI, saOffer{PSPVersion: grant.PSPVersion, RxSPI: grant.RxSPI})
	if err != nil {
		s.bestEffortRelease(grant.VNI)
		return nil, err
	}
	return &KeyGrant{VNI: grant.VNI, SAs: sas}, nil
}

// statusToError maps a non-OK grant status to the typed error a caller acts on:
// VNI exhaustion is transient (retry later), SPI exhaustion is terminal (only a
// fresh session recovers), and anything else is an opaque rejection.
func statusToError(s grantStatus) error {
	switch s {
	case grantExhausted:
		return ErrVNIExhausted
	case grantSPIExhausted:
		return ErrSPIExhausted
	default:
		return ErrGrantRejected
	}
}

// bestEffortRelease releases a VNI the responder granted but that the initiator
// could not accept (out-of-range VNI, key-derivation failure). It runs on a
// fresh short timeout so it works even when the caller's context is already
// done, and only logs on failure — the session-teardown sweep is the backstop.
func (s *Session) bestEffortRelease(vni uint32) {
	ctx, cancel := context.WithTimeout(context.Background(), keyStreamTimeout)
	defer cancel()
	if err := s.ReleaseKeys(ctx, vni); err != nil {
		slog.Warn("Failed to release VNI the initiator could not accept", "vni", vni, "error", err)
	}
}

// ReleaseKeys tells the responder the VNI's network is gone, starting its
// quarantine. The grant's SAs must not be used after this returns.
func (s *Session) ReleaseKeys(ctx context.Context, vni uint32) error {
	if s.role != Initiator {
		return errors.New("control: ReleaseKeys requires the initiator role")
	}
	respBytes, err := s.roundTrip(ctx, vniRelease{VNI: vni}.marshal())
	if err != nil {
		return err
	}
	ack, err := parseReleaseAck(respBytes)
	if err != nil {
		return err
	}
	if ack.Status != grantOK {
		return ErrGrantRejected
	}
	return nil
}

// roundTrip opens a fresh stream, sends one frame, and reads one reply frame.
// It then drains the stream to EOF so quic-go retires the bidi stream and
// replenishes the session's stream-count credit; without that drain every
// exchange leaks a stream slot and the session can no longer open streams once
// the initial MaxIncomingStreams credit is spent.
func (s *Session) roundTrip(ctx context.Context, payload []byte) ([]byte, error) {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("control: open key-plane stream: %w", err)
	}
	// Once the stream is open a blocked readFrame is interruptible only by a
	// deadline or by closing the stream, so wire ctx cancellation (not just a
	// deadline) to do exactly that; stop() disarms it on the normal path.
	stop := context.AfterFunc(ctx, func() {
		stream.CancelRead(0)
		_ = stream.Close()
	})
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(dl)
	}
	if err := writeFrame(stream, payload); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return nil, fmt.Errorf("control: send key-plane request: %w", err)
	}
	// Half-close the send side now that the request is complete: sending FIN
	// before reading lets the responder retire its stream without blocking, and
	// is required for our own stream to retire.
	_ = stream.Close()
	resp, err := readFrame(stream)
	if err != nil {
		stream.CancelRead(0)
		return nil, fmt.Errorf("control: read key-plane response: %w", err)
	}
	_, _ = io.Copy(io.Discard, stream) // consume the responder's FIN so the stream retires.
	return resp, nil
}

// KeyGranter is the responder's policy seam. Grant must atomically allocate a
// VNI for addr and install the responder-side SAs (sas.Rx decrypts traffic
// arriving FROM the peer's network, sas.Tx encrypts traffic sent back TO it)
// before returning; a returned error rejects the request and installs
// nothing. Release must uninstall the VNI's SAs and start its quarantine, and
// should be idempotent — an explicit release and the session-teardown sweep can
// each target the same VNI under crash/disconnect races. Both must be safe for
// concurrent use across sessions; returning ErrVNIExhausted from Grant maps to a
// typed rejection on the wire, any other error to a generic one (the error text
// never reaches the peer).
type KeyGranter interface {
	Grant(peer *ecdsa.PublicKey, addr netip.Addr, sas *DirectionalSAs) (vni uint32, err error)
	Release(peer *ecdsa.PublicKey, vni uint32) error
}

// ServeKeyPlane serves key-plane exchanges on a responder session until ctx
// is cancelled or the session dies. On return it releases every VNI still
// granted on this session — for a peer that crashed without releasing, this
// is what starts the quarantine clock. Returns nil on ctx cancellation, the
// session error otherwise.
func (s *Session) ServeKeyPlane(ctx context.Context, granter KeyGranter) error {
	if s.role != Responder {
		return errors.New("control: ServeKeyPlane requires the responder role")
	}
	peerPub, err := s.PeerPublicKey()
	if err != nil {
		return err
	}

	granted := make(map[uint32]struct{})
	var mu sync.Mutex
	// LIFO defers: wait for in-flight streams first, then release leftovers.
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for vni := range granted {
			if err := granter.Release(peerPub, vni); err != nil {
				slog.Error("Failed to release VNI on session teardown", "vni", vni, "error", err)
			}
		}
	}()
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		stream, err := s.conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("control: key-plane session closed: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer drainClose(stream)
			s.serveKeyStream(stream, peerPub, granter, granted, &mu)
		}()
	}
}

// drainClose half-closes the stream's send side and reads its receive side to
// EOF (bounded by the stream deadline). quic-go retires a bidi stream — and
// returns its stream-count credit to the peer — only once BOTH halves are done;
// a lone readFrame leaves the receive half open, so without this drain a
// long-lived session leaks stream credit and eventually cannot open streams.
func drainClose(stream *quic.Stream) {
	_ = stream.Close()
	if _, err := io.Copy(io.Discard, stream); err != nil {
		stream.CancelRead(0) // peer did not FIN before the deadline; force the receive side shut.
	}
}

// serveKeyStream handles one exchange: a single request frame and its reply.
func (s *Session) serveKeyStream(stream *quic.Stream, peerPub *ecdsa.PublicKey, granter KeyGranter, granted map[uint32]struct{}, mu *sync.Mutex) {
	// Bound the whole exchange so a peer that opens a stream and stalls cannot
	// park this goroutine (and a stream slot) until the QUIC idle timeout.
	_ = stream.SetDeadline(time.Now().Add(keyStreamTimeout))
	frame, err := readFrame(stream)
	if err != nil {
		slog.Debug("control: read key-plane frame", "error", err)
		return
	}
	if len(frame) < 2 || frame[0] != ProtocolVersion {
		slog.Debug("control: malformed key-plane frame")
		return
	}
	switch msgType(frame[1]) {
	case msgKeyRequest:
		s.handleKeyRequest(stream, frame, peerPub, granter, granted, mu)
	case msgVNIRelease:
		s.handleVNIRelease(stream, frame, peerPub, granter, granted, mu)
	default:
		slog.Debug("control: unexpected key-plane message type", "type", frame[1])
	}
}

func (s *Session) handleKeyRequest(stream *quic.Stream, frame []byte, peerPub *ecdsa.PublicKey, granter KeyGranter, granted map[uint32]struct{}, mu *sync.Mutex) {
	reject := func(status grantStatus) {
		_ = writeFrame(stream, keyGrant{Status: status}.marshal())
	}
	req, err := parseKeyRequest(frame)
	if err != nil {
		slog.Debug("control: malformed key request", "error", err)
		reject(grantRejected)
		return
	}
	if !req.PSPVersion.valid() || !req.Addr.IsValid() {
		reject(grantRejected)
		return
	}
	myRxSPI, err := s.rxAlloc.Allocate(activeMasterKeyIndex)
	if err != nil {
		slog.Warn("Key-plane SPI space exhausted; peer must reconnect for fresh keys", "error", err)
		reject(grantSPIExhausted)
		return
	}
	sas, err := s.deriveDirectional(req.PSPVersion, myRxSPI, saOffer{PSPVersion: req.PSPVersion, RxSPI: req.RxSPI})
	if err != nil {
		slog.Warn("Failed to derive key-plane SAs", "error", err)
		reject(grantRejected)
		return
	}
	vni, err := granter.Grant(peerPub, req.Addr, sas)
	if err != nil {
		if errors.Is(err, ErrVNIExhausted) {
			slog.Warn("VNI space exhausted", "addr", req.Addr)
			reject(grantExhausted)
		} else {
			slog.Info("Key request rejected", "addr", req.Addr, "error", err)
			reject(grantRejected)
		}
		return
	}
	if vni == 0 || vni > MaxVNI {
		// Defensive: a broken granter must never put an out-of-range VNI on the
		// wire or into the tracked set. Release whatever it installed and reject.
		slog.Error("Granter returned out-of-range VNI", "vni", vni, "addr", req.Addr)
		if rerr := granter.Release(peerPub, vni); rerr != nil {
			slog.Error("Failed to release out-of-range VNI", "vni", vni, "error", rerr)
		}
		reject(grantRejected)
		return
	}
	mu.Lock()
	granted[vni] = struct{}{}
	mu.Unlock()
	// If this write fails the initiator never learns the grant and will retry
	// with a fresh exchange; the orphaned grant is intentionally NOT released
	// here (the write error is ambiguous — the peer may have received it) and
	// is cleaned up by the session-teardown release instead.
	if err := writeFrame(stream, keyGrant{Status: grantOK, PSPVersion: req.PSPVersion, RxSPI: myRxSPI, VNI: vni}.marshal()); err != nil {
		slog.Warn("Failed to send key grant; grant will be reclaimed on session teardown", "vni", vni, "error", err)
	}
}

func (s *Session) handleVNIRelease(stream *quic.Stream, frame []byte, peerPub *ecdsa.PublicKey, granter KeyGranter, granted map[uint32]struct{}, mu *sync.Mutex) {
	rel, err := parseVNIRelease(frame)
	if err != nil {
		slog.Debug("control: malformed VNI release", "error", err)
		_ = writeFrame(stream, releaseAck{Status: grantRejected}.marshal())
		return
	}
	// Session isolation: a peer may only release VNIs granted on ITS session.
	mu.Lock()
	_, ours := granted[rel.VNI]
	mu.Unlock()
	if !ours {
		_ = writeFrame(stream, releaseAck{Status: grantRejected}.marshal())
		return
	}
	// Stop tracking the VNI BEFORE invoking Release: whatever Release's outcome,
	// this session has handed the VNI back, so the teardown sweep must not
	// release it again (a non-idempotent granter would be double-uninstalled).
	mu.Lock()
	delete(granted, rel.VNI)
	mu.Unlock()
	if err := granter.Release(peerPub, rel.VNI); err != nil {
		slog.Error("Failed to release VNI", "vni", rel.VNI, "error", err)
		_ = writeFrame(stream, releaseAck{Status: grantRejected}.marshal())
		return
	}
	_ = writeFrame(stream, releaseAck{Status: grantOK}.marshal())
}
