package icx

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phemmer/go-iptrie"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx/addrselect"
	"github.com/apoxy-dev/icx/flowhash"
	"github.com/apoxy-dev/icx/geneve"
	"github.com/apoxy-dev/icx/ndproxy"
	"github.com/apoxy-dev/icx/proxyarp"
	"github.com/apoxy-dev/icx/replay"
	"github.com/apoxy-dev/icx/udp"
)

const (
	// How long to continue accepting packets with an old key after a new key is set.
	keyGracePeriod = 30 * time.Second
)

// Statistics for a virtual network.
// cacheLinePad is the assumed cache-line size. The hot per-VNI counters are
// padded to it so the per-direction forwarder goroutines do not false-share a
// line (P8/APO-672).
const cacheLinePad = 64

type Statistics struct {
	// Hot success counters. Bumped on EVERY successful RX/TX by every per-queue
	// forwarder goroutine, so each sits on its own cache line: the per-direction
	// writers no longer false-share, and — being separated from the cold drop/error
	// counters below — a forged-frame flood hammering a drop counter cannot
	// invalidate a success-path line (P8/APO-672). The padding costs ~one cache line
	// per counter per VNI (one Statistics per network, never per packet), which is
	// negligible, and roughly halves the multi-core RMW cost under load. The residual
	// per-counter true sharing (many cores bumping the SAME counter) is only removed
	// by a full per-queue shard, deliberately deferred to avoid changing the exported
	// Stats read API and the Datapath interface.

	// RXPackets is the number of received packets.
	RXPackets atomic.Uint64
	_         [cacheLinePad - 8]byte
	// RXBytes is the number of bytes received.
	RXBytes atomic.Uint64
	_       [cacheLinePad - 8]byte
	// LastRXUnixNano is the timestamp of the last received packet.
	LastRXUnixNano atomic.Int64
	_              [cacheLinePad - 8]byte
	// TXPackets is the number of transmitted packets.
	TXPackets atomic.Uint64
	_         [cacheLinePad - 8]byte
	// TXBytes is the number of bytes transmitted.
	TXBytes atomic.Uint64
	_       [cacheLinePad - 8]byte
	// LastTXUnixNano is the timestamp of the last transmitted packet.
	LastTXUnixNano atomic.Int64
	_              [cacheLinePad - 8]byte

	// Cold counters. Bumped only on the drop/error/keep-alive paths, so they stay
	// packed together and off the hot success lines above.

	// RXDropsNoKey is the number of received packets dropped due to a missing key.
	RXDropsNoKey atomic.Uint64
	// RXDropsExpiredKey is the number of received packets dropped due to an expired key.
	RXDropsExpiredKey atomic.Uint64
	// RXReplayDrops is the number of received packets dropped due to a potential replay attack.
	RXReplayDrops atomic.Uint64
	// RXDecryptErrors is the number of received packets that failed decryption.
	RXDecryptErrors atomic.Uint64
	// RXDropsSPIMismatch is the number of received packets dropped because the
	// SPI bound into the AEAD nonce (nonce[:4]) did not match the key epoch the
	// frame selected — a malformed or tampered frame (APO-644).
	RXDropsSPIMismatch atomic.Uint64
	// RXInvalidSrc is the number of received packets with an invalid source address.
	RXInvalidSrc atomic.Uint64
	// RXInvalidDst is the number of received packets dropped because the decrypted
	// inner destination address fell outside every allowed route.Src prefix — the
	// destination-side half of cryptokey routing that RX previously skipped (APO-649).
	RXInvalidDst atomic.Uint64
	// RXDropsBadPeer is the number of received packets dropped because the outer
	// underlay source IP did not match the configured peer (APO-650). Only counted
	// when outer-source validation is enabled (WithOuterSrcValidation).
	RXDropsBadPeer atomic.Uint64
	// RXRateLimitDrops is the number of received packets dropped before AES-GCM Open
	// by the per-network RX rate limiter (APO-655). Only counted when a limit is
	// configured (WithRXRateLimit).
	RXRateLimitDrops atomic.Uint64
	// TXErrors is the number of transmission errors.
	TXErrors atomic.Uint64
	// TXDropsExpiredKey is the number of outbound frames dropped because the transmit
	// SA's key had expired (APO-656). RX enforces key expiry; this makes TX fail closed
	// symmetrically instead of sealing indefinitely under a stale key.
	TXDropsExpiredKey atomic.Uint64
	// LastKeepAliveUnixNano is the timestamp of the last transmitted keep-alive packet.
	LastKeepAliveUnixNano atomic.Int64
}

// Route represents a source/destination address prefix pair allowed for a virtual network.
type Route struct {
	// Src is the source address prefix.
	Src netip.Prefix
	// Dst is the destination address prefix.
	Dst netip.Prefix
}

// Receiver cipher state.
type receiveCipher struct {
	cipher.AEAD
	expiresAt    time.Time
	replayFilter replay.Filter
}

// Transmit cipher state.
type transmitCipher struct {
	cipher.AEAD
	epoch uint32
	// expiresAt is the transmit SA's expiry. TX fails closed once it passes (APO-656),
	// mirroring the receiveCipher.expiresAt enforcement, so a node whose control plane
	// stops rekeying stops emitting under the stale key instead of sealing forever.
	expiresAt time.Time
	// key is the transmit key, retained so the TX anti-reset guard can distinguish a
	// genuine double-install of the live SA (same SPI AND same key) from a fresh-session
	// install that merely reused the SPI value under a new key (see UpdateVirtualNetworkSAs).
	key     [16]byte
	counter atomic.Uint64
}

// The state associated with each virtual network.
type VirtualNetwork struct {
	// ID is the virtual network identifier.
	ID uint
	// RemoteAddr is the address of the remote endpoint.
	RemoteAddr *tcpip.FullAddress
	// allowedRoutes is the list of allowed source/destination address prefix pairs for
	// this virtual network, published atomically (APO-652): the RX validation hot path
	// Loads a stable slice snapshot while UpdateVirtualNetworkRoutes Stores a whole
	// replacement, so a reader and the writer never race on the slice header. Read it
	// through the AllowedRoutes accessor.
	allowedRoutes atomic.Pointer[[]Route]
	// Statistics associated with this virtual network.
	Stats Statistics
	// Internal state (not exposed)
	rxCiphers sync.Map
	txCipher  atomic.Pointer[transmitCipher]
	// rxEpoch is the currently-installed receive SPI (0 = none). Under per-direction
	// SPIs the receive and transmit SPIs differ, so the previous RX cipher can no longer
	// be found via txCipher.epoch; rxEpoch anchors the prior receive SA so installKeys
	// can grace-clamp it. It is NOT a monotonicity guard and need NOT be monotone — it
	// simply tracks the most recently installed receive SPI and may regress when a fresh
	// session resets the allocator (the receive side emits no nonce, so a reused receive
	// SPI is harmless: its replay filter is rebuilt with the fresh key).
	rxEpoch atomic.Uint32
	// rxLimiter bounds how many frames per second reach the AES-GCM Open on the RX
	// path, shedding an off-path flood of forgeable VNI/epoch frames before they burn
	// crypto CPU (APO-655). nil when no limit is configured, in which case the hot
	// path skips it entirely.
	rxLimiter *rxRateLimiter
}

// AllowedRoutes returns a snapshot of the virtual network's allowed routes. The
// slice is published atomically (APO-652) and must be treated as read-only: a
// concurrent UpdateVirtualNetworkRoutes replaces the whole slice rather than
// mutating it in place, so a caller keeps a consistent (if possibly older) view.
func (v *VirtualNetwork) AllowedRoutes() []Route {
	if p := v.allowedRoutes.Load(); p != nil {
		return *p
	}
	return nil
}

// Clock provides time to the handler. Tests can inject a fake clock.
type Clock interface {
	Now() time.Time
}

// realClock uses the system time.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// debugDropEnabled reports whether the default logger would emit a Debug record.
// The per-packet RX/TX drop branches consult it before building slog arguments so
// that, at the default info level, they pay neither the variadic boxing of typed
// attrs (~1 alloc each) nor netip.Addr.String() (~2 allocs) for a record that is
// then discarded — which matters most when a forged-packet flood lands those drop
// branches on the hot path (APO-674). The per-reason Stats counters are bumped
// unconditionally, so suppressing the unbuilt log loses no operational signal.
func debugDropEnabled() bool {
	return slog.Default().Enabled(context.Background(), slog.LevelDebug)
}

type HandlerOption func(*handlerOptions) error

type handlerOptions struct {
	localAddrs        addrselect.List
	virtMAC           tcpip.LinkAddress
	srcMAC            tcpip.LinkAddress
	sourcePortHashing bool
	layer3            bool
	keepAliveInterval *time.Duration
	clock             Clock
	// validateOuterSrc, when set, makes the RX path drop any frame whose outer
	// underlay source IP does not match the receiving network's configured peer
	// (RemoteAddr) before any crypto/replay work (APO-650).
	validateOuterSrc bool
	// rxRateLimitPPS, when > 0, caps how many frames per second per virtual network
	// may reach the AES-GCM Open on the RX path (APO-655). 0 disables the limiter.
	rxRateLimitPPS int
	// forceOuterUDPChecksum, when set, makes the TX path compute the outer UDP
	// checksum even on an IPv4 underlay, where it is otherwise skipped (the legal
	// RFC 768 zero checksum) to avoid a redundant software pass over the already
	// AES-GCM-authenticated payload. See WithOuterUDPChecksum (APO-668).
	forceOuterUDPChecksum bool
}

func defaultHandlerOptions() handlerOptions {
	return handlerOptions{
		srcMAC: tcpip.GetRandMacAddr(),
		clock:  realClock{},
	}
}

// WithLocalAddr sets the local UDP endpoint used as the source for
// encapsulated packets. This option is required. If multiple
// addresses are provided, the best one is chosen per packet based
// on the remote address.
//
// If WithSourcePortHashing is enabled, the Port field of this address is
// overridden per packet with a hash of the inner flow. Otherwise, the Port
// specified here is used as-is.
func WithLocalAddr(a *tcpip.FullAddress) HandlerOption {
	return func(opts *handlerOptions) error {
		opts.localAddrs = append(opts.localAddrs, a)
		return nil
	}
}

// WithVirtMAC sets the MAC address used for the virtual interface in L2 mode.
// This is required when not running in L3 mode (see WithLayer3VirtFrames).
// Ignored when L3 mode is enabled.
func WithVirtMAC(mac tcpip.LinkAddress) HandlerOption {
	return func(opts *handlerOptions) error {
		opts.virtMAC = mac
		return nil
	}
}

// WithSourceMAC overrides the synthetic source MAC used for L2 frames and for
// ProxyARP replies. By default, a random MAC is generated at handler creation.
// Ignored when L3 mode is enabled.
func WithSourceMAC(mac tcpip.LinkAddress) HandlerOption {
	return func(opts *handlerOptions) error {
		opts.srcMAC = mac
		return nil
	}
}

// WithSourcePortHashing enables per-packet UDP source-port selection based on
// a hash of the inner IP flow. This improves ECMP distribution in the underlay.
// When enabled, it overrides the Port from WithLocalAddr for each packet.
func WithSourcePortHashing() HandlerOption {
	return func(opts *handlerOptions) error {
		opts.sourcePortHashing = true
		return nil
	}
}

// WithLayer3VirtFrames configures the handler for L3 mode, where virtual frames
// are raw IP packets (no Ethernet header). Default is L2 mode (Ethernet frames).
func WithLayer3VirtFrames() HandlerOption {
	return func(opts *handlerOptions) error {
		opts.layer3 = true
		return nil
	}
}

// WithKeepAliveInterval configures the handler to send keep-alive packets
// on each virtual network at the given interval. If nil or zero, no keep-alives
// are sent.
// A value of between 10 and 30s is recommended to keep NAT mappings alive.
func WithKeepAliveInterval(interval time.Duration) HandlerOption {
	return func(opts *handlerOptions) error {
		if interval <= 0 {
			opts.keepAliveInterval = nil
		}
		opts.keepAliveInterval = &interval
		return nil
	}
}

// WithClock overrides the time source used by the handler (useful for tests).
func WithClock(c Clock) HandlerOption {
	return func(opts *handlerOptions) error {
		if c == nil {
			c = realClock{}
		}
		opts.clock = c
		return nil
	}
}

// WithOuterSrcValidation makes the RX path verify that each frame's outer
// underlay source IP matches the receiving virtual network's configured peer
// (RemoteAddr) and drop it otherwise, before any per-packet crypto or replay
// work (APO-650). Only the IP is checked, not the UDP source port, so it is
// compatible with source-port hashing (which rewrites the port per packet).
//
// This suits the single-static-peer deployment the CLI ships. It is left off by
// default in the library because a peer behind asymmetric routing/NAT (whose
// packets arrive from an address other than the one we send to) would otherwise
// be silently dropped; enable it when the peer's source address is stable.
func WithOuterSrcValidation() HandlerOption {
	return func(opts *handlerOptions) error {
		opts.validateOuterSrc = true
		return nil
	}
}

// WithRXRateLimit caps how many frames per second per virtual network may reach
// the AES-GCM Open on the RX path, bounding the CPU an off-path flood of
// forgeable VNI/epoch frames can burn (APO-655). pps <= 0 disables the limiter
// (the default), preserving the zero-overhead datapath; a positive value should
// be set comfortably above the tunnel's expected legitimate peak, since
// legitimate and attacker traffic share the per-network budget.
func WithRXRateLimit(pps int) HandlerOption {
	return func(opts *handlerOptions) error {
		if pps < 0 {
			pps = 0
		}
		opts.rxRateLimitPPS = pps
		return nil
	}
}

// WithOuterUDPChecksum forces the TX path to compute the outer UDP checksum on an
// IPv4 underlay. By default it is skipped: the encapsulated payload is already
// AES-GCM-authenticated with the full Geneve header as AAD, the ICX RX path does
// not validate the outer UDP checksum (udp.Decode runs with skipChecksumValidation),
// and a zero UDP checksum is legal on IPv4 (RFC 768) — so the per-packet software
// checksum over the whole ciphertext is pure overhead (APO-668, ~25% of VirtToPhy
// CPU on an MTU-class frame). Enable this only if a middlebox on the underlay drops
// or mishandles zero-checksum UDP. On an IPv6 underlay a zero UDP checksum is illegal,
// so the checksum is always computed regardless of this option.
func WithOuterUDPChecksum() HandlerOption {
	return func(opts *handlerOptions) error {
		opts.forceOuterUDPChecksum = true
		return nil
	}
}

// skipOuterUDPChecksum reports whether the TX path may emit a zero outer UDP
// checksum for a frame destined to remote. True only for an IPv4 underlay — where
// a zero checksum is legal (RFC 768) and the ICX RX ignores it — and only when the
// operator has not forced the checksum on for middlebox compatibility (APO-668).
// On IPv6 a zero UDP checksum is illegal, so this always returns false and the
// checksum is computed.
func (h *Handler) skipOuterUDPChecksum(remote *tcpip.FullAddress) bool {
	return !h.opts.forceOuterUDPChecksum && remote.Addr.Len() == net.IPv4len
}

// roDstEntry is the published, read-only inner node of the routing snapshot: the
// Src-prefix trie (LPM) for one Dst prefix. It is built fresh on every route
// change and never mutated after publication, so the data path reads it with no
// lock.
type roDstEntry struct {
	srcTrie *iptrie.Trie // Src prefix (LPM) -> *VirtualNetwork
}

// routeTable is an immutable snapshot of the data-path routing structure,
// published via Handler.routes (atomic.Pointer) and read with a single lock-free
// atomic load on the TX hot path. Writers never mutate a published table: under
// routesMu they rebuild a fresh one from the dstEntries management index and swap
// it in (copy-on-write). This removes the per-packet networksByAddressMu.RLock
// cache-line bounce that serialized the TX route lookup across all NIC-queue
// goroutines (P12/APO-675); and because a published srcTrie is never mutated, the
// two-tier lookup stays race-free with zero reader synchronization.
type routeTable struct {
	byDst *iptrie.Trie // Dst prefix (LPM) -> *roDstEntry
}

// Handler processes encapsulated Geneve traffic for one or more virtual
// networks. It performs encryption/decryption, replay protection, address
// validation, and translation between physical and virtual frame formats.
type Handler struct {
	opts        *handlerOptions
	networkByID sync.Map // Maps VNI to network
	// routesMu serializes route-table writers (Add/Remove/UpdateVirtualNetworkRoutes).
	// It is NEVER taken on the data path — readers load the published snapshot from
	// `routes` with a single atomic load — so per-packet route lookups never contend
	// a lock.
	routesMu sync.Mutex
	// routes is the lock-free, copy-on-write data-path routing snapshot. Always
	// non-nil after NewHandler; the TX path resolves a frame with routes.Load() and
	// two trie Finds, taking no lock (P12/APO-675).
	routes atomic.Pointer[routeTable]
	// dstEntries is the management-plane source of truth: EXACT Dst prefix -> (EXACT
	// Src prefix -> owning vnet). Add/Remove/Update address routes by their exact
	// prefix, not by LPM containment, so a nested Dst lands in its own entry
	// (APO-663). Guarded by routesMu and never read by the data path; the published
	// `routes` snapshot is rebuilt from it on every change.
	dstEntries map[netip.Prefix]map[netip.Prefix]*VirtualNetwork
	proxyARP   *proxyarp.ProxyARP
	ndProxy    *ndproxy.NDProxy
	hdrPool    *sync.Pool
	clock      Clock
	// flowHashKey is a random per-handler secret keying the source-port flow hash,
	// so the outer UDP source port is not a public function of the inner 5-tuple an
	// off-path observer could fingerprint (APO-661). Fixed for the handler's life so
	// a flow's port stays stable (ECMP); shared by both TX paths.
	flowHashKey uint64
}

// NewHandler returns a new Handler configured with the given options.
// It validates required parameters and allocates internal state for
// managing virtual networks and packet processing.
func NewHandler(opts ...HandlerOption) (*Handler, error) {
	options := defaultHandlerOptions()
	for _, opt := range opts {
		if err := opt(&options); err != nil {
			return nil, err
		}
	}

	if len(options.localAddrs) == 0 {
		return nil, fmt.Errorf("local address must be set")
	}

	if options.virtMAC == "" && !options.layer3 {
		return nil, fmt.Errorf("virtual MAC must be set for L2 mode")
	}

	hdrPool := &sync.Pool{
		New: func() any {
			return &geneve.Header{}
		},
	}

	// Random per-handler key for the source-port flow hash (APO-661). Sourced from
	// the SP 800-90A DRBG (crypto/rand) so it is unpredictable to an off-path observer.
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("failed to seed flow-hash key: %w", err)
	}

	h := &Handler{
		opts:        &options,
		dstEntries:  make(map[netip.Prefix]map[netip.Prefix]*VirtualNetwork),
		proxyARP:    proxyarp.NewProxyARP(options.srcMAC),
		ndProxy:     ndproxy.NewNDProxy(options.srcMAC),
		hdrPool:     hdrPool,
		clock:       options.clock,
		flowHashKey: binary.BigEndian.Uint64(seed[:]),
	}
	// Publish an initial empty routing snapshot so the lock-free data path always
	// finds a non-nil table to Load.
	h.routes.Store(&routeTable{byDst: iptrie.NewTrie()})
	return h, nil
}

// checkRouteCollisionsLocked returns an error if any of routes would route an
// exact (Dst, Src) prefix pair already owned by a different virtual network —
// rather than letting the insert silently overwrite it (APO-653). The caller
// must hold routesMu.
func (h *Handler) checkRouteCollisionsLocked(routes []Route, vnet *VirtualNetwork) error {
	for _, route := range routes {
		dst, src := route.Dst.Masked(), route.Src.Masked()
		if owners := h.dstEntries[dst]; owners != nil {
			if owner, ok := owners[src]; ok && owner != vnet {
				return fmt.Errorf("route Src=%s Dst=%s already routed to VNI %d", src, dst, owner.ID)
			}
		}
	}
	return nil
}

// addRouteLocked registers route -> vnet in the exact-match management index. It
// must be called only after checkRouteCollisionsLocked has passed for these
// routes, so it never clobbers a different vnet's slot. The caller must hold
// routesMu and must republish the data-path snapshot with rebuildRoutesLocked once
// its batch of route mutations is complete.
func (h *Handler) addRouteLocked(route Route, vnet *VirtualNetwork) {
	dst, src := route.Dst.Masked(), route.Src.Masked()
	owners := h.dstEntries[dst]
	if owners == nil {
		owners = make(map[netip.Prefix]*VirtualNetwork)
		h.dstEntries[dst] = owners
	}
	owners[src] = vnet
}

// removeRouteLocked unregisters route, but only if it is currently owned by vnet
// (APO-654) — so decommissioning one network never deletes a route a different
// network still owns. When a Dst entry's last route is removed it is dropped so
// empty nodes do not accumulate (APO-654). The caller must hold routesMu and must
// republish the data-path snapshot with rebuildRoutesLocked once its batch of
// route mutations is complete.
func (h *Handler) removeRouteLocked(route Route, vnet *VirtualNetwork) {
	dst, src := route.Dst.Masked(), route.Src.Masked()
	owners := h.dstEntries[dst]
	if owners == nil || owners[src] != vnet {
		return
	}
	delete(owners, src)
	if len(owners) == 0 {
		delete(h.dstEntries, dst)
	}
}

// rebuildRoutesLocked rebuilds the immutable data-path routing snapshot from the
// dstEntries management index and publishes it atomically (copy-on-write). The
// caller must hold routesMu. Cost is O(total routes); it runs only on
// management-plane route changes, never on the data path. The freshly built tries
// share nothing with the previously published snapshot, so any in-flight lock-free
// reader keeps using the old table safely until its next Load.
func (h *Handler) rebuildRoutesLocked() {
	byDst := iptrie.NewTrie()
	for dst, owners := range h.dstEntries {
		srcTrie := iptrie.NewTrie()
		for src, vnet := range owners {
			srcTrie.Insert(src, vnet)
		}
		byDst.Insert(dst, &roDstEntry{srcTrie: srcTrie})
	}
	h.routes.Store(&routeTable{byDst: byDst})
}

// AddVirtualNetwork adds a new network with the given VNI and remote address.
func (h *Handler) AddVirtualNetwork(vni uint, remoteAddr *tcpip.FullAddress, allowedRoutes []Route) error {
	if _, exists := h.networkByID.Load(vni); exists {
		return fmt.Errorf("network with VNI %d already exists", vni)
	}

	vnet := &VirtualNetwork{
		ID:         vni,
		RemoteAddr: remoteAddr,
	}
	vnet.allowedRoutes.Store(&allowedRoutes)
	if h.opts.rxRateLimitPPS > 0 {
		vnet.rxLimiter = newRxRateLimiter(h.opts.rxRateLimitPPS)
	}

	h.routesMu.Lock()
	defer h.routesMu.Unlock()

	// Reject the whole add if any route would take over a slot already owned by a
	// different network, instead of silently overwriting it (APO-653). Validate
	// before mutating so a conflict leaves no partial state.
	if err := h.checkRouteCollisionsLocked(allowedRoutes, vnet); err != nil {
		return err
	}
	for _, route := range allowedRoutes {
		h.addRouteLocked(route, vnet)
	}
	// Publish the rebuilt data-path snapshot, then expose the VNI — so the VNI is
	// never visible with a half-applied routing table.
	h.rebuildRoutesLocked()
	h.networkByID.Store(vni, vnet)

	return nil
}

// RemoveVirtualNetwork removes a network by its VNI.
func (h *Handler) RemoveVirtualNetwork(vni uint) error {
	value, exists := h.networkByID.Load(vni)
	if !exists {
		return fmt.Errorf("network with VNI %d does not exist", vni)
	}
	vnet := value.(*VirtualNetwork)

	h.networkByID.Delete(vni)

	// Remove only the routes this vnet owns, so removing it never blackholes a
	// different network that shares a Dst prefix (APO-654).
	h.routesMu.Lock()
	for _, route := range vnet.AllowedRoutes() {
		h.removeRouteLocked(route, vnet)
	}
	h.rebuildRoutesLocked()
	h.routesMu.Unlock()

	return nil
}

// UpdateVirtualNetworkRoutes updates the allowed routes for a virtual network.
func (h *Handler) UpdateVirtualNetworkRoutes(vni uint, allowedRoutes []Route) error {
	v, ok := h.networkByID.Load(vni)
	if !ok {
		return fmt.Errorf("VNI %d not found", vni)
	}
	vnet := v.(*VirtualNetwork)

	h.routesMu.Lock()
	defer h.routesMu.Unlock()

	// Mutate the management index (invisible to the lock-free data path until we
	// republish). Remove this vnet's current routes, then validate the new set
	// against the routes that remain (other networks). On conflict, restore the old
	// routes and return WITHOUT republishing: the data path still sees the original
	// snapshot, so the update is atomic — it never leaves the network partially
	// routed or silently steals another network's slot (APO-653).
	for _, route := range vnet.AllowedRoutes() {
		h.removeRouteLocked(route, vnet)
	}
	if err := h.checkRouteCollisionsLocked(allowedRoutes, vnet); err != nil {
		for _, route := range vnet.AllowedRoutes() {
			h.addRouteLocked(route, vnet)
		}
		return err
	}
	for _, route := range allowedRoutes {
		h.addRouteLocked(route, vnet)
	}
	vnet.allowedRoutes.Store(&allowedRoutes)
	// Publish the new routing table in one atomic swap, so readers transition from
	// the complete old set to the complete new set with no half-applied state.
	h.rebuildRoutesLocked()

	return nil
}

// UpdateVirtualNetworkSAs installs/rotates a virtual network's pair of simplex
// security associations (PSP model). It must be called at least once every 24
// hours or after replay.RekeyAfterMessages messages.
//
// rxSPI and txSPI are the per-direction 32-bit SPIs that select the receive and
// transmit SAs. Each is carried in the Geneve key-epoch option and bound into the
// high 4 bytes of its direction's AES-GCM nonce (nonce = SPI‖counter):
//   - rxSPI is OUR receive SPI — the one we allocated and the peer encrypts to. We
//     store the RX cipher under it and look inbound frames up by it. Inbound frames
//     carry rxSPI in their key-epoch option (== the sender's txSPI).
//   - txSPI is the PEER's receive SPI — the one we encrypt to. We stamp it into the
//     key-epoch option and nonce[:4] of every outbound frame.
//
// The two SPIs are distinct (the control plane partitions the SPI space by role,
// see control/sa.go), so each direction has its own nonce space.
//
// This entry point is for the CONTROL PLANE, where every SA generation carries a
// FRESH per-session key (each QUIC reconnect is a fresh ECDHE handshake — no 0-RTT,
// no session resumption, enforced in control/transport.go). That freshness is what
// guarantees the nonce-uniqueness invariant — no (key, nonce=SPI‖counter) pair ever
// repeats — across rekeys, reconnects and restarts:
//   - within a session the receive-SPI allocator is monotonic, so a given SPI value
//     is handed out once and its reset-to-zero counter is always a fresh nonce space;
//   - across sessions the master keys are fresh, so even a reused SPI value derives a
//     different key. SPIs may therefore reset to 1 on a reconnect and be re-accepted
//     here at a LOWER value than before — which is exactly what makes a one-sided
//     restart recover seamlessly with no persisted state.
//
// Three fail-closed guards apply: non-zero SPIs, distinct rx/tx keys, and a TX
// anti-reset check that rejects re-installing the CURRENTLY-live transmit SA — same SPI
// AND same key (the only in-process action that would reset a live counter under an
// unchanged key — a defensive backstop against a double-install/retry). A txSPI that
// merely reuses the live SPI value under a FRESH key (the transient-reconnect case) is
// accepted, as is any lower-or-higher txSPI; safety rests on the fresh-key guarantee
// above, not on monotonicity.
// Callers must serialize installs per VNI; the guard→install sequence is not
// internally locked (the control plane is single-threaded per Tunnel). Manually-keyed
// SAs that lack per-session key freshness should use the strictly-guarded single-epoch
// UpdateVirtualNetworkKeys seam instead.
func (h *Handler) UpdateVirtualNetworkSAs(vni uint, rxSPI, txSPI uint32, rxKey, txKey [16]byte, expiresAt time.Time) error {
	value, ok := h.networkByID.Load(vni)
	if !ok {
		return fmt.Errorf("VNI %d not found", vni)
	}
	vnet := value.(*VirtualNetwork)

	// Reserved-SPI guard: SPI 0 is reserved. Rejecting it keeps the data plane's
	// accepted SPI space aligned with the control plane, which never emits an SPI
	// whose low 31 bits are zero (control/sa.go), and refuses to write the all-zero
	// nonce prefix that predated the SPI binding.
	if rxSPI == 0 || txSPI == 0 {
		return errors.New("rx and tx SPIs must be non-zero")
	}

	// TX anti-reset guard: reject re-installing the SA that is currently live for
	// transmit — same SPI AND same key. That pair is the only in-process action that would
	// reset the TX counter to zero under a key already used at that SPI (a GCM nonce-reuse
	// hazard): a defensive backstop against an accidental double-install/retry of the
	// identical generation. The key comparison is load-bearing, not cosmetic: on a transient
	// reconnect the receive-SPI allocator resets to a low value, so the new transmit SPI can
	// COLLIDE with the still-live one — but it arrives under a FRESH master key (every session
	// is a fresh ECDHE handshake; resumption and 0-RTT are disabled and asserted in
	// control/transport.go), so its from-zero counter is a fresh nonce space and the install
	// is safe. Comparing the SPI alone would spuriously reject that legitimate recovery. A
	// different SPI is likewise always accepted. There is deliberately no RX monotonicity
	// guard — the receive side never emits a nonce, so a reused receive SPI is harmless (its
	// per-SA replay filter is rebuilt with the fresh key); rxEpoch is tracked only to
	// grace-clamp the previous receive cipher (see installKeys).
	if cur := vnet.txCipher.Load(); cur != nil && txSPI == cur.epoch && txKey == cur.key {
		return fmt.Errorf("tx SA (SPI %d) is already live; refusing to reset its counter", txSPI)
	}

	// Distinct-key guard. Under per-direction SPIs the role bit already separates the
	// two directions' nonce spaces, so this is belt-and-suspenders. Real peers always
	// derive distinct per-direction keys (control.DeriveSA over role-partitioned SPIs),
	// so this never rejects a legitimate install.
	if rxKey == txKey {
		return errors.New("rx and tx keys must differ: each direction requires its own key")
	}

	return h.installKeys(vnet, rxSPI, txSPI, rxKey, txKey, expiresAt)
}

// UpdateVirtualNetworkKeys installs a single epoch (SPI) for BOTH simplex directions,
// separated only by the distinct rx/tx keys. It is the simple manual-keying seam — used
// by tests and by embedders that drive their own keying rather than the QUIC control
// plane (which installs genuine per-direction SAs via UpdateVirtualNetworkSAs).
//
// It enforces a STRICT monotonicity guard: the epoch must strictly increase within the
// process. That stops a caller from reinstalling an older-or-equal epoch with a reused
// key, which would reset the GCM counter under an already-used (epoch, key) and repeat a
// nonce. The guard cannot see across process restarts, so a caller that supplies a key
// which SURVIVES restarts (e.g. one read from disk) MUST advance the epoch past the last
// value used in any prior run — otherwise the from-zero counter reuses nonces under the
// persisted key. The control plane sidesteps this entirely by deriving a fresh key per
// session; manual callers own the invariant.
//
// Callers must serialize installs per VNI.
func (h *Handler) UpdateVirtualNetworkKeys(vni uint, epoch uint32, rxKey, txKey [16]byte, expiresAt time.Time) error {
	value, ok := h.networkByID.Load(vni)
	if !ok {
		return fmt.Errorf("VNI %d not found", vni)
	}
	vnet := value.(*VirtualNetwork)

	if epoch == 0 {
		return errors.New("epoch (SPI) must be non-zero")
	}
	// Strict monotonicity: a manual-keyed caller has no per-session key freshness to fall
	// back on, so the epoch must strictly increase or a reset counter could reuse a nonce.
	if cur := vnet.txCipher.Load(); cur != nil && epoch <= cur.epoch {
		return fmt.Errorf("epoch must be monotonically increasing: new %d <= current %d", epoch, cur.epoch)
	}
	if rxKey == txKey {
		return errors.New("rx and tx keys must differ: each direction requires its own key")
	}

	return h.installKeys(vnet, epoch, epoch, rxKey, txKey, expiresAt)
}

// installKeys builds and installs the RX/TX ciphers for a generation, applies the 30s
// grace period to the previous RX key, and sweeps expired RX keys. It is the unguarded
// mechanism behind UpdateVirtualNetworkSAs; the SPI/key guards live in that caller.
func (h *Handler) installKeys(vnet *VirtualNetwork, rxSPI, txSPI uint32, rxKey, txKey [16]byte, expiresAt time.Time) error {
	// Clamp the previous RX key to a 30s grace window. The previous receive SA is
	// keyed by the previous receive SPI (vnet.rxEpoch) — NOT by txCipher.epoch, which
	// under per-direction SPIs is the previous TRANSMIT SPI (the peer's receive SPI)
	// and would point at the wrong slot. The grace lets the survivor keep decrypting
	// in-flight frames under the old key across a make-before-break rotation. Across a
	// reconnect the previous and new receive SPIs differ (the new session's allocator
	// reset to a low value while the old SPI was higher), so they occupy distinct
	// rxCiphers slots and both stay live through the grace window. The rare exception —
	// a fresh allocator climbing back to a still-graced old SPI within 30s — simply
	// overwrites that slot with the fresh key; only late frames under the old key at
	// that exact SPI are lost, which is acceptable post-reconnect.
	if prevRxSPI := vnet.rxEpoch.Load(); prevRxSPI != 0 && prevRxSPI != rxSPI {
		if prevCipherAny, ok := vnet.rxCiphers.Load(prevRxSPI); ok {
			if prevCipher, ok := prevCipherAny.(*receiveCipher); ok {
				graceExpiry := h.clock.Now().Add(keyGracePeriod)
				if prevCipher.expiresAt.After(graceExpiry) {
					prevCipher.expiresAt = graceExpiry
				}
			}
		}
	}

	// Delete expired keys (to free key material from memory). This sweeps rxCiphers
	// only; it does not touch vnet.rxEpoch (which is overwritten on the next install).
	now := h.clock.Now()
	vnet.rxCiphers.Range(func(key, value any) bool {
		cipher := value.(*receiveCipher)
		if cipher.expiresAt.Before(now) {
			vnet.rxCiphers.Delete(key)
		}
		return true
	})

	rxBlock, err := aes.NewCipher(rxKey[:])
	if err != nil {
		return fmt.Errorf("failed to create RX cipher: %w", err)
	}
	rxCipher, err := cipher.NewGCM(rxBlock)
	if err != nil {
		return fmt.Errorf("failed to create RX GCM: %w", err)
	}

	txBlock, err := aes.NewCipher(txKey[:])
	if err != nil {
		return fmt.Errorf("failed to create TX cipher: %w", err)
	}
	txCipher, err := cipher.NewGCM(txBlock)
	if err != nil {
		return fmt.Errorf("failed to create TX GCM: %w", err)
	}

	// Install RX before TX (make-before-break): store the receive cipher and record the
	// currently-installed receive SPI (rxEpoch) first, so we can decrypt the peer's
	// new-generation frames before we start emitting our own under the new transmit SPI.
	vnet.rxCiphers.Store(rxSPI, &receiveCipher{
		AEAD:      rxCipher,
		expiresAt: expiresAt,
	})
	vnet.rxEpoch.Store(rxSPI)

	// A fresh transmitCipher resets the TX counter to zero for the new transmit SPI.
	// This is load-bearing for nonce uniqueness: the AES-GCM nonce is txSPI‖counter, so
	// each transmit SPI MUST begin its own counter at zero. Safety across rekeys, reconnects
	// and restarts rests on each generation pairing that from-zero counter with a FRESH
	// per-session key (fresh ECDHE; no resumption/0-RTT), so even a reused or regressed SPI
	// value derives a different key and the (key, nonce) pair never repeats. A refactor that
	// carried the counter across installs would reintroduce reuse. The key is retained so the
	// TX anti-reset guard can reject a literal double-install of this same live SA.
	vnet.txCipher.Store(&transmitCipher{
		AEAD:      txCipher,
		epoch:     txSPI,
		key:       txKey,
		expiresAt: expiresAt,
	})

	return nil
}

// GetVirtualNetwork retrieves a virtual network by its VNI.
func (h *Handler) GetVirtualNetwork(vni uint) (*VirtualNetwork, bool) {
	value, ok := h.networkByID.Load(vni)
	if !ok {
		return nil, false
	}
	return value.(*VirtualNetwork), true
}

// ListVirtualNetworks returns a snapshot of all configured virtual networks.
func (h *Handler) ListVirtualNetworks() []*VirtualNetwork {
	var out []*VirtualNetwork
	h.networkByID.Range(func(_, value any) bool {
		vnet := value.(*VirtualNetwork)
		out = append(out, vnet)
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// txKeyExpired reports whether vnet's transmit SA has expired as of now, recording
// the drop (TXDropsExpiredKey + a debug log) when it has. It is the single
// fail-closed expiry check shared by all four TX seal sites — VirtToPhy/ToPhy and
// their in-place twins — so the cross-buffer and in-place datapaths stay identical
// and cannot drift (APO-656). The log is at Debug, not Warn: once a key expires this
// fires on every outbound frame, so a Warn would flood at line rate — and by then the
// peer's RX key has expired too, so the tunnel is already down.
func (h *Handler) txKeyExpired(vnet *VirtualNetwork, txCipher *transmitCipher, now time.Time) bool {
	if txCipher.expiresAt.Before(now) {
		slog.Debug("Dropping frame: transmit key expired, rotate the key")
		vnet.Stats.TXDropsExpiredKey.Add(1)
		return true
	}
	return false
}

// PhyToVirt converts a physical frame to a virtual frame typically by performing decapsulation.
// Returns the length of the resulting virtual frame.
func (h *Handler) PhyToVirt(phyFrame, virtFrame []byte) int {
	// Capture the outer underlay source only when peer-source validation is on
	// (APO-650); otherwise pass nil so udp.Decode skips the address copy.
	var outerSrc tcpip.FullAddress
	var outerSrcPtr *tcpip.FullAddress
	if h.opts.validateOuterSrc {
		outerSrcPtr = &outerSrc
	}

	payload, err := udp.Decode(phyFrame, outerSrcPtr, true)
	if err != nil {
		slog.Warn("Failed to decode UDP frame", slog.Any("error", err))
		return 0
	}

	hdr := h.hdrPool.Get().(*geneve.Header)
	defer func() {
		h.hdrPool.Put(hdr)
	}()

	hdrLen, err := hdr.UnmarshalBinary(payload)
	if err != nil {
		slog.Warn("Failed to unmarshal Geneve header", slog.Any("error", err))
		return 0
	}

	// Is it a valid VNI?
	value, exists := h.networkByID.Load(uint(hdr.VNI))
	if !exists {
		if debugDropEnabled() {
			slog.Debug("Dropping frame with unknown VNI", slog.Uint64("vni", uint64(hdr.VNI)))
		}
		return 0
	}
	vnet := value.(*VirtualNetwork)

	// Drop frames whose outer underlay source does not match the configured peer
	// before any crypto/replay work (APO-650). Only the IP is compared (the UDP
	// source port is rewritten per packet by source-port hashing). A nil
	// RemoteAddr under an enabled check fails closed.
	if h.opts.validateOuterSrc && (vnet.RemoteAddr == nil || outerSrc.Addr != vnet.RemoteAddr.Addr) {
		if debugDropEnabled() {
			slog.Debug("Dropping frame: outer source does not match configured peer",
				slog.String("outerSrc", outerSrc.Addr.String()))
		}
		vnet.Stats.RXDropsBadPeer.Add(1)
		return 0
	}

	var nonce []byte
	var epoch uint32
	for i := 0; i < hdr.NumOptions; i++ {
		// Take the option by pointer, not value. A value copy of geneve.Option
		// embeds a [12]byte Value, and because nonce = opt.Value[:12] is consumed
		// after the loop by Open, escape analysis would move that copy to the heap
		// (~2 allocs / received packet, paid even by forged frames that drop before
		// Open). The pointer keeps nonce backed by the pooled header. (APO-673)
		opt := &hdr.Options[i]
		if opt.Class == geneve.ClassExperimental {
			switch opt.Type {
			case geneve.OptionTypeTxCounter:
				// Require the declared 12-byte (Length=3) value so nonce[:4] (the
				// SPI) and the counter are provably sender-written, not stale pooled
				// bytes from a short/malformed option — keeps the SPI-mismatch drop
				// attribution honest. A wrong length leaves nonce nil → the
				// "Expected TX counter" drop below.
				if opt.Length == 3 {
					nonce = opt.Value[:12]
				}
			case geneve.OptionTypeKeyEpoch:
				epoch = binary.BigEndian.Uint32(opt.Value[:4])
			}
		}
	}
	if len(nonce) == 0 {
		slog.Warn("Expected TX counter in Geneve header options")
		return 0
	}

	rxCipherAny, ok := vnet.rxCiphers.Load(epoch)
	if !ok {
		// Probably a delayed packet with an old key.
		if debugDropEnabled() {
			slog.Debug("No matching RX key for epoch", slog.Uint64("epoch", uint64(epoch)))
		}
		vnet.Stats.RXDropsNoKey.Add(1)
		return 0
	}

	rxCipher := rxCipherAny.(*receiveCipher)
	if rxCipher.expiresAt.Before(h.clock.Now()) {
		if debugDropEnabled() {
			slog.Debug("Epoch key expired", slog.Uint64("epoch", uint64(epoch)))
		}
		vnet.Stats.RXDropsExpiredKey.Add(1)
		// Delete expired key (to free key material from memory)
		vnet.rxCiphers.Delete(epoch)
		return 0
	}

	// Verify the SPI bound into the nonce matches the receive SPI that selected this
	// SA (nonce = SPI‖counter). Under per-direction SPIs the inbound key-epoch option
	// carries the sender's transmit SPI, which is exactly our receive SPI; a conformant
	// sender always sets nonce[:4] to that same value, so a mismatch is a malformed or
	// tampered frame. GCM would also reject it at Open (the nonce and the header both
	// feed the tag), but the explicit check makes the binding auditable and gives a
	// precise drop reason. (APO-644)
	if spi := binary.BigEndian.Uint32(nonce[:4]); spi != epoch {
		if debugDropEnabled() {
			slog.Debug("Dropping frame: nonce SPI does not match key epoch",
				slog.Uint64("epoch", uint64(epoch)), slog.Uint64("nonceSPI", uint64(spi)))
		}
		vnet.Stats.RXDropsSPIMismatch.Add(1)
		return 0
	}

	// Rate-limit the costly AES-GCM Open per network (APO-655). Placed after the
	// cheap VNI/key/SPI checks so only frames that would otherwise be authenticated
	// consume budget, and before Open so a flood cannot burn crypto CPU.
	if vnet.rxLimiter != nil && !vnet.rxLimiter.allow(h.clock.Now().UnixNano()) {
		if debugDropEnabled() {
			slog.Debug("Dropping frame: RX rate limit exceeded", slog.Uint64("vni", uint64(hdr.VNI)))
		}
		vnet.Stats.RXRateLimitDrops.Add(1)
		return 0
	}

	txCounter := binary.BigEndian.Uint64(nonce[4:])

	var ipPacket []byte
	if h.opts.layer3 {
		ipPacket = virtFrame[:0]
	} else {
		ipPacket = virtFrame[header.EthernetMinimumSize:header.EthernetMinimumSize]
	}

	ipPacket, err = rxCipher.Open(ipPacket, nonce, payload[hdrLen:], payload[:hdrLen])
	if err != nil {
		slog.Warn("Failed to decrypt payload", slog.Any("error", err))
		vnet.Stats.RXDecryptErrors.Add(1)
		return 0
	}

	// Anti-replay AFTER authentication (APO-645/S2): ValidateCounter both checks
	// and advances the sliding window, so it must run only on a packet whose tag
	// has verified. Running it before Open let an attacker who can spoof the
	// outer 4-tuple advance the window with a forged high counter and wedge the
	// real peer (whose in-window counters are then rejected as "behind window").
	if !rxCipher.replayFilter.ValidateCounter(txCounter, replay.RejectAfterMessages) {
		// Delayed packets can cause some unnecessary noise here.
		if debugDropEnabled() {
			slog.Debug("Replay filter rejected frame", slog.Uint64("txCounter", txCounter))
		}
		vnet.Stats.RXReplayDrops.Add(1)
		return 0
	}

	// Is it an authenticated out-of-band message?
	if hdr.ProtocolType == 0 {
		slog.Debug("Dropping out-of-band message")
		// Treat as a (zero-byte) virtual packet receive for stats purposes.
		vnet.Stats.RXPackets.Add(1)
		vnet.Stats.RXBytes.Add(uint64(len(ipPacket)))
		vnet.Stats.LastRXUnixNano.Store(h.clock.Now().UnixNano())
		return 0
	}

	// A non-OOB frame whose authenticated payload is empty has no version nibble;
	// ipPacket[0] would panic. An authenticated peer can craft one. (APO-647/S4)
	if len(ipPacket) == 0 {
		slog.Warn("Dropping empty decrypted payload")
		vnet.Stats.RXInvalidSrc.Add(1)
		return 0
	}

	ipVersion := ipPacket[0] >> 4

	// Get the source and destination addresses of the decrypted frame. Both feed
	// the cryptokey-routing check below: the inner source against the allowed
	// route.Dst prefixes (remote side) and the inner destination against the
	// allowed route.Src prefixes (local side).
	var srcAddr, dstAddr netip.Addr
	switch ipVersion {
	case header.IPv4Version:
		// The src/dst accessors index up to IPv4MinimumSize; a decrypted packet
		// shorter than that (a peer with valid keys can send one) would panic.
		if len(ipPacket) < header.IPv4MinimumSize {
			slog.Warn("Truncated IPv4 packet after decryption")
			vnet.Stats.RXInvalidSrc.Add(1)
			return 0
		}
		var ok bool
		ipHdr := header.IPv4(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 address in frame")
			vnet.Stats.RXInvalidSrc.Add(1)
			return 0
		}
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 destination address in frame")
			vnet.Stats.RXInvalidSrc.Add(1)
			return 0
		}
	case header.IPv6Version:
		if len(ipPacket) < header.IPv6MinimumSize {
			slog.Warn("Truncated IPv6 packet after decryption")
			vnet.Stats.RXInvalidSrc.Add(1)
			return 0
		}
		var ok bool
		ipHdr := header.IPv6(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 address in frame")
			vnet.Stats.RXInvalidSrc.Add(1)
			return 0
		}
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 destination address in frame")
			vnet.Stats.RXInvalidSrc.Add(1)
			return 0
		}
	default:
		slog.Warn("Unsupported IP version", slog.Int("version", int(ipVersion)))
		vnet.Stats.RXInvalidSrc.Add(1)
		return 0
	}

	// Confirm the inner addresses are authorized for this virtual network in a
	// single pass: the source must fall within an allowed route.Dst prefix (the
	// remote side) and the destination within an allowed route.Src prefix (the
	// local side). The destination half is the cryptokey-routing check RX
	// previously omitted (APO-649), confining a peer to the local subnets it is
	// permitted to deliver to.
	var validSrc, validDst bool
	for _, route := range vnet.AllowedRoutes() {
		if !validSrc && route.Dst.Contains(srcAddr) {
			validSrc = true
		}
		if !validDst && route.Src.Contains(dstAddr) {
			validDst = true
		}
		if validSrc && validDst {
			break
		}
	}
	if !validSrc {
		if debugDropEnabled() {
			slog.Debug("Dropping frame with invalid tunnel source address", slog.String("srcAddr", srcAddr.String()))
		}
		vnet.Stats.RXInvalidSrc.Add(1)
		return 0
	}
	if !validDst {
		if debugDropEnabled() {
			slog.Debug("Dropping frame with invalid tunnel destination address", slog.String("dstAddr", dstAddr.String()))
		}
		vnet.Stats.RXInvalidDst.Add(1)
		return 0
	}

	// Success: count bytes/packets and timestamp
	vnet.Stats.RXPackets.Add(1)
	vnet.Stats.RXBytes.Add(uint64(len(ipPacket)))
	vnet.Stats.LastRXUnixNano.Store(h.clock.Now().UnixNano())

	if h.opts.layer3 {
		return len(ipPacket)
	}

	// If we are in layer 2 mode, we need to attach an Ethernet header.
	eth := header.Ethernet(virtFrame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: h.opts.srcMAC,
		DstAddr: h.opts.virtMAC,
		Type: func() tcpip.NetworkProtocolNumber {
			if ipVersion == header.IPv6Version {
				return header.IPv6ProtocolNumber
			}
			return header.IPv4ProtocolNumber
		}(),
	})

	return header.EthernetMinimumSize + len(ipPacket)
}

// VirtToPhy converts a virtual frame to a physical frame typically by performing encapsulation.
// Returns the length of the resulting physical frame.
func (h *Handler) VirtToPhy(virtFrame, phyFrame []byte) (int, bool) {
	ipPacket := virtFrame

	if !h.opts.layer3 {
		// A virtual frame shorter than an Ethernet header cannot be parsed;
		// eth.Type() would index past the slice and panic. Drop it (the datapath
		// must never panic on a malformed frame).
		if len(virtFrame) < header.EthernetMinimumSize {
			if debugDropEnabled() {
				slog.Debug("Dropping runt virtual frame", slog.Int("frameSize", len(virtFrame)))
			}
			return 0, false
		}

		eth := header.Ethernet(virtFrame)
		ethType := eth.Type()

		// Handle ARP requests with an immediate local reply.
		if ethType == header.ARPProtocolNumber {
			frameLen, err := h.proxyARP.Reply(virtFrame, phyFrame)
			if err != nil {
				slog.Warn("Failed to handle ARP request", slog.Any("error", err))
			} else {
				return frameLen, true
			}
		}

		// Handle IPv6 Neighbor Solicitation with an immediate local NA reply.
		if ethType == header.IPv6ProtocolNumber {
			ipPayload := virtFrame[header.EthernetMinimumSize:]
			if len(ipPayload) >= header.IPv6MinimumSize {
				ip6 := header.IPv6(ipPayload)
				if ip6.IsValid(len(ipPayload)) && ip6.TransportProtocol() == header.ICMPv6ProtocolNumber {
					icmp := ip6.Payload()
					// ICMPv6 type 135 = Neighbor Solicitation.
					if len(icmp) >= header.ICMPv6NeighborSolicitMinimumSize && icmp[0] == byte(header.ICMPv6NeighborSolicit) {
						frameLen, err := h.ndProxy.Reply(virtFrame, phyFrame)
						if err != nil {
							slog.Warn("Failed to handle ND request", slog.Any("error", err))
						} else {
							return frameLen, true
						}
					}
				}
			}
		}

		// Drop non ip frames
		if ethType != header.IPv4ProtocolNumber && ethType != header.IPv6ProtocolNumber {
			if debugDropEnabled() {
				slog.Debug("Dropping non-IP frame",
					slog.Int("frameSize", len(virtFrame)),
					slog.Int("ethType", int(ethType)))
			}
			return 0, false
		}

		// Strip off the ethernet header
		ipPacket = virtFrame[header.EthernetMinimumSize:]
	}

	// An empty IP packet (e.g. a frame that is exactly an Ethernet header, or a
	// zero-length layer3 frame) has no version nibble to read; ipPacket[0] would
	// panic. Drop it.
	if len(ipPacket) == 0 {
		slog.Debug("Dropping empty virtual frame")
		return 0, false
	}

	ipVersion := ipPacket[0] >> 4

	// Get the tunnel destination address for the IP packet.
	var srcAddr, dstAddr netip.Addr
	switch ipVersion {
	case header.IPv4Version:
		// The src/dst accessors index up to IPv4MinimumSize; a shorter packet
		// (the version nibble says IPv4 but the header is truncated) would panic.
		if len(ipPacket) < header.IPv4MinimumSize {
			if debugDropEnabled() {
				slog.Debug("Dropping truncated IPv4 frame", slog.Int("frameSize", len(ipPacket)))
			}
			return 0, false
		}
		var ok bool
		ipHdr := header.IPv4(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 source address in frame")
			return 0, false
		}
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 destination address in frame")
			return 0, false
		}
	case header.IPv6Version:
		// Likewise the IPv6 accessors index up to IPv6MinimumSize.
		if len(ipPacket) < header.IPv6MinimumSize {
			if debugDropEnabled() {
				slog.Debug("Dropping truncated IPv6 frame", slog.Int("frameSize", len(ipPacket)))
			}
			return 0, false
		}
		var ok bool
		ipHdr := header.IPv6(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 source address in frame")
			return 0, false
		}
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 destination address in frame")
			return 0, false
		}
	}

	// Find the virtual network by the destination then source address (both LPM)
	// via a single lock-free load of the copy-on-write routing snapshot (P12/APO-675).
	// The published table is immutable — writers swap in a freshly built one — so the
	// two-tier lookup is race-free with no per-packet RLock.
	rt := h.routes.Load()
	value := rt.byDst.Find(dstAddr)
	if value == nil {
		if debugDropEnabled() {
			slog.Debug("Dropping frame with unknown destination address", slog.String("dstAddr", dstAddr.String()))
		}
		return 0, false
	}
	srcValue := value.(*roDstEntry).srcTrie.Find(srcAddr)
	if srcValue == nil {
		if debugDropEnabled() {
			slog.Debug("Dropping frame with unknown source address", slog.String("srcAddr", srcAddr.String()))
		}
		return 0, false
	}
	vnet := srcValue.(*VirtualNetwork)

	hdr := h.hdrPool.Get().(*geneve.Header)
	defer func() {
		h.hdrPool.Put(hdr)
	}()

	*hdr = geneve.Header{
		VNI:        uint32(vnet.ID),
		NumOptions: 2,
		Critical:   true,
		Options: [geneve.MaxOptions]geneve.Option{
			{
				Class:  geneve.ClassExperimental,
				Type:   geneve.OptionTypeKeyEpoch,
				Length: 1,
			},
			{
				Class:  geneve.ClassExperimental,
				Type:   geneve.OptionTypeTxCounter,
				Length: 3,
			},
		},
	}

	txCipher := vnet.txCipher.Load()
	if txCipher == nil {
		slog.Warn("TX cipher not available")
		vnet.Stats.TXErrors.Add(1)
		return 0, false
	}

	// Fail closed once the transmit SA expires (APO-656): see txKeyExpired. Mirrors
	// VirtToPhyInPlace.
	if h.txKeyExpired(vnet, txCipher, h.clock.Now()) {
		return 0, false
	}

	binary.BigEndian.PutUint32(hdr.Options[0].Value[:4], txCipher.epoch)

	if txCipher.counter.Load() >= replay.RekeyAfterMessages {
		slog.Warn("TX counter overflow, you must rotate the key")
		vnet.Stats.TXErrors.Add(1)
		return 0, false
	}

	// nonce = txSPI‖counter: bind this direction's transmit SPI (the peer's receive
	// SPI) into the high 4 bytes. Under per-direction SPIs this prefix differs from the
	// receive direction's, so the SPI itself separates the two directions' nonce spaces
	// (on top of the distinct rx/tx keys); the receiver reconstructs the same SPI from
	// its key-epoch option and rejects any frame whose nonce[:4] does not match. The low
	// 8 bytes are the per-SA monotonic counter. Both halves must be written before Seal.
	nonce := hdr.Options[1].Value[:12]
	binary.BigEndian.PutUint32(nonce[:4], txCipher.epoch)
	binary.BigEndian.PutUint64(nonce[4:], txCipher.counter.Add(1))

	switch ipVersion {
	case header.IPv4Version:
		hdr.ProtocolType = uint16(header.IPv4ProtocolNumber)
	case header.IPv6Version:
		hdr.ProtocolType = uint16(header.IPv6ProtocolNumber)
	default:
		slog.Warn("Unsupported IP version", slog.Int("version", int(ipVersion)))
		vnet.Stats.TXErrors.Add(1)
		return 0, false
	}

	var payload []byte
	if vnet.RemoteAddr.Addr.Len() == net.IPv4len {
		payload = phyFrame[udp.PayloadOffsetIPv4:]
	} else {
		payload = phyFrame[udp.PayloadOffsetIPv6:]
	}

	hdrLen, err := hdr.MarshalBinary(payload)
	if err != nil {
		slog.Warn("Failed to marshal Geneve header", slog.Any("error", err))
		vnet.Stats.TXErrors.Add(1)
		return 0, false
	}

	// Bound the inner packet so the ciphertext + AEAD tag fit within phyFrame.
	// Seal appends ptLen+Overhead() bytes after the Geneve header; an oversized
	// inner packet would otherwise overflow phyFrame (when its capacity exceeds
	// its length) or force Seal to silently reallocate onto the heap, so the
	// ciphertext would not land in the frame udp.Encode/the caller transmits.
	// Drop instead (APO-667).
	if hdrLen+len(ipPacket)+txCipher.Overhead() > len(payload) {
		if debugDropEnabled() {
			slog.Debug("Dropping oversized inner packet for encap",
				slog.Int("innerLen", len(ipPacket)),
				slog.Int("payloadLen", len(payload)))
		}
		vnet.Stats.TXErrors.Add(1)
		return 0, false
	}

	encryptedFrameLen := len(txCipher.Seal(payload[hdrLen:hdrLen], nonce, ipPacket, payload[:hdrLen]))

	// Underlay source selection.
	best := h.opts.localAddrs.Select(vnet.RemoteAddr)
	if best == nil {
		slog.Warn("No local underlay addresses configured")
		vnet.Stats.TXErrors.Add(1)
		return 0, false
	}

	localAddr := *best
	if h.opts.sourcePortHashing {
		localAddr.Port = flowhash.MapToEphemeralPort(flowhash.Hash(h.flowHashKey, ipPacket))
	}

	frameLen, err := udp.Encode(phyFrame, &localAddr, vnet.RemoteAddr, hdrLen+encryptedFrameLen, h.skipOuterUDPChecksum(vnet.RemoteAddr))
	if err != nil {
		slog.Warn("Failed to encode UDP frame", slog.Any("error", err))
		vnet.Stats.TXErrors.Add(1)
		return 0, false
	}

	// Success: count bytes/packets and timestamp
	vnet.Stats.TXPackets.Add(1)
	vnet.Stats.TXBytes.Add(uint64(len(ipPacket)))
	vnet.Stats.LastTXUnixNano.Store(h.clock.Now().UnixNano())

	return frameLen, false
}

// ToPhy is called periodically to allow the handler to send
// scheduled frames to the physical interface, e.g. keep-alive packets.
// Returns the length of the resulting physical frame.
func (h *Handler) ToPhy(phyFrame []byte) int {
	if h.opts.keepAliveInterval == nil || *h.opts.keepAliveInterval <= 0 {
		return 0
	}
	interval := *h.opts.keepAliveInterval
	now := h.clock.Now()

	// Pick a virtual network that's due.
	var vnet *VirtualNetwork
	h.networkByID.Range(func(_, v any) bool {
		vn := v.(*VirtualNetwork)
		last := time.Unix(0, vn.Stats.LastKeepAliveUnixNano.Load())
		if last.IsZero() || now.Sub(last) >= interval {
			vnet = vn
			return false
		}
		return true
	})
	if vnet == nil {
		return 0
	}

	txCipher := vnet.txCipher.Load()
	if txCipher == nil {
		// No key yet, not really an error for keep-alives.
		return 0
	}

	// Fail closed once the transmit SA expires (APO-656): no point keeping a NAT
	// mapping warm under a key the peer would reject. Mark the network serviced so an
	// expired key does not leave it perpetually "due" — re-selected, re-logged and
	// re-counted on every poll. Mirrors ToPhyInPlace.
	if h.txKeyExpired(vnet, txCipher, now) {
		vnet.Stats.LastKeepAliveUnixNano.Store(now.UnixNano())
		return 0
	}

	if txCipher.counter.Load() >= replay.RekeyAfterMessages {
		slog.Warn("TX counter overflow, rotate the key")
		vnet.Stats.TXErrors.Add(1)
		return 0
	}

	hdr := h.hdrPool.Get().(*geneve.Header)
	defer h.hdrPool.Put(hdr)

	*hdr = geneve.Header{
		VNI:        uint32(vnet.ID),
		NumOptions: 2,
		Critical:   true,
		Options: [geneve.MaxOptions]geneve.Option{
			{
				Class:  geneve.ClassExperimental,
				Type:   geneve.OptionTypeKeyEpoch,
				Length: 1,
			},
			{
				Class:  geneve.ClassExperimental,
				Type:   geneve.OptionTypeTxCounter,
				Length: 3,
			},
		},
		ProtocolType: 0, // EtherType Unknown - indicates no inner payload.
	}

	// Fill options: epoch + nonce/counter
	binary.BigEndian.PutUint32(hdr.Options[0].Value[:4], txCipher.epoch)
	// nonce = txSPI‖counter: bind this direction's transmit SPI (the peer's receive
	// SPI) into the high 4 bytes. Under per-direction SPIs this prefix differs from the
	// receive direction's, so the SPI itself separates the two directions' nonce spaces
	// (on top of the distinct rx/tx keys); the receiver reconstructs the same SPI from
	// its key-epoch option and rejects any frame whose nonce[:4] does not match. The low
	// 8 bytes are the per-SA monotonic counter. Both halves must be written before Seal.
	nonce := hdr.Options[1].Value[:12]
	binary.BigEndian.PutUint32(nonce[:4], txCipher.epoch)
	binary.BigEndian.PutUint64(nonce[4:], txCipher.counter.Add(1))

	// Place Geneve payload inside outer UDP frame.
	var payload []byte
	if vnet.RemoteAddr.Addr.Len() == net.IPv4len {
		payload = phyFrame[udp.PayloadOffsetIPv4:]
	} else {
		payload = phyFrame[udp.PayloadOffsetIPv6:]
	}

	// Marshal Geneve header.
	hdrLen, err := hdr.MarshalBinary(payload)
	if err != nil {
		slog.Warn("Marshal Geneve header failed", slog.Any("error", err))
		vnet.Stats.TXErrors.Add(1)
		return 0
	}

	// AEAD over EMPTY inner payload -> ciphertext is just the tag.
	plaintext := []byte(nil)
	ct := txCipher.Seal(payload[hdrLen:hdrLen], nonce, plaintext, payload[:hdrLen])
	encLen := len(ct) // AEAD tag length

	// Underlay source selection.
	best := h.opts.localAddrs.Select(vnet.RemoteAddr)
	if best == nil {
		slog.Warn("No local underlay addresses configured")
		vnet.Stats.TXErrors.Add(1)
		return 0
	}
	localAddr := *best

	// Finish outer UDP/IP/Ethernet
	totalGeneveLen := hdrLen + encLen
	frameLen, err := udp.Encode(phyFrame, &localAddr, vnet.RemoteAddr, totalGeneveLen, h.skipOuterUDPChecksum(vnet.RemoteAddr))
	if err != nil {
		slog.Warn("UDP encode failed", slog.Any("error", err))
		vnet.Stats.TXErrors.Add(1)
		return 0
	}

	// Stats: treat as a (zero-byte) virtual packet send.
	vnet.Stats.TXPackets.Add(1)
	vnet.Stats.LastTXUnixNano.Store(now.UnixNano())
	vnet.Stats.LastKeepAliveUnixNano.Store(now.UnixNano())

	return frameLen
}
