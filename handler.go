package icx

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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
	// The size of the Geneve header with icx options.
	HeaderSize = 32
	// How long to continue accepting packets with an old key after a new key is set.
	keyGracePeriod = 30 * time.Second
)

// Receiver cipher state.
type receiveCipher struct {
	cipher.AEAD
	expiresAt    time.Time
	replayFilter replay.Filter
}

// Transmit cipher state.
type transmitCipher struct {
	cipher.AEAD
	epoch   uint32
	counter atomic.Uint64
}

// Statistics for a virtual network.
type Statistics struct {
	// RXPackets is the number of received packets.
	RXPackets atomic.Uint64
	// RXBytes is the number of bytes received.
	RXBytes atomic.Uint64
	// RXDropsNoKey is the number of received packets dropped due to a missing key.
	RXDropsNoKey atomic.Uint64
	// RXDropsExpiredKey is the number of received packets dropped due to an expired key.
	RXDropsExpiredKey atomic.Uint64
	// RXReplayDrops is the number of received packets dropped due to a potential replay attack.
	RXReplayDrops atomic.Uint64
	// RXDecryptErrors is the number of received packets that failed decryption.
	RXDecryptErrors atomic.Uint64
	// RXInvalidSrc is the number of received packets with an invalid source address.
	RXInvalidSrc atomic.Uint64
	// TXPackets is the number of transmitted packets.
	TXPackets atomic.Uint64
	// TXBytes is the number of bytes transmitted.
	TXBytes atomic.Uint64
	// TXErrors is the number of transmission errors.
	TXErrors atomic.Uint64
	// LastRXUnixNano is the timestamp of the last received packet.
	LastRXUnixNano atomic.Int64
	// LastTXUnixNano is the timestamp of the last transmitted packet.
	LastTXUnixNano atomic.Int64
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

// The state associated with each virtual network.
type VirtualNetwork struct {
	// ID is the virtual network identifier.
	ID uint
	// RemoteAddr is the address of the remote endpoint.
	RemoteAddr *tcpip.FullAddress
	// AllowedRoutes is the list of allowed source/destination address prefix pairs for this virtual network.
	AllowedRoutes []Route
	// Statistics associated with this virtual network.
	Stats Statistics
	// Internal state (not exposed)
	rxCiphers sync.Map
	txCipher  atomic.Pointer[transmitCipher]
}

// Clock provides time to the handler. Tests can inject a fake clock.
type Clock interface {
	Now() time.Time
}

// realClock uses the system time.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type HandlerOption func(*handlerOptions) error

type handlerOptions struct {
	localAddrs        addrselect.List
	virtMAC           tcpip.LinkAddress
	srcMAC            tcpip.LinkAddress
	sourcePortHashing bool
	layer3            bool
	keepAliveInterval *time.Duration
	clock             Clock
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

// Handler processes encapsulated Geneve traffic for one or more virtual
// networks. It performs encryption/decryption, replay protection, address
// validation, and translation between physical and virtual frame formats.
type Handler struct {
	opts                *handlerOptions
	networkByID         sync.Map     // Maps VNI to network
	networksByAddressMu sync.RWMutex // Protects networksByAddress
	networksByAddress   *iptrie.Trie // Two tier trie: dstAddr -> srcAddr -> network
	proxyARP            *proxyarp.ProxyARP
	ndProxy             *ndproxy.NDProxy
	hdrPool             *sync.Pool
	clock               Clock
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

	return &Handler{
		opts:              &options,
		networksByAddress: iptrie.NewTrie(),
		proxyARP:          proxyarp.NewProxyARP(options.srcMAC),
		ndProxy:           ndproxy.NewNDProxy(options.srcMAC),
		hdrPool:           hdrPool,
		clock:             options.clock,
	}, nil
}

// AddVirtualNetwork adds a new network with the given VNI and remote address.
func (h *Handler) AddVirtualNetwork(vni uint, remoteAddr *tcpip.FullAddress, allowedRoutes []Route) error {
	if _, exists := h.networkByID.Load(vni); exists {
		return fmt.Errorf("network with VNI %d already exists", vni)
	}

	vnet := &VirtualNetwork{
		ID:            vni,
		RemoteAddr:    remoteAddr,
		AllowedRoutes: allowedRoutes,
	}

	h.networkByID.Store(vni, vnet)

	// Insert all allowed routes for this vnet
	h.networksByAddressMu.Lock()
	for _, route := range allowedRoutes {
		value := h.networksByAddress.Find(route.Dst.Addr())
		if value == nil {
			value = iptrie.NewTrie()
			h.networksByAddress.Insert(route.Dst, value)
		}
		srcTrie := value.(*iptrie.Trie)
		srcTrie.Insert(route.Src, vnet)
	}
	h.networksByAddressMu.Unlock()

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

	// Remove all allowed routes for this vnet
	h.networksByAddressMu.Lock()
	for _, route := range vnet.AllowedRoutes {
		value := h.networksByAddress.Find(route.Dst.Addr())
		if value != nil {
			srcTrie := value.(*iptrie.Trie)
			srcTrie.Remove(route.Src)
			// Library doesn't expose a way to easily check if the trie is empty.
		}
	}
	h.networksByAddressMu.Unlock()

	return nil
}

// UpdateVirtualNetworkRoutes updates the allowed routes for a virtual network.
func (h *Handler) UpdateVirtualNetworkRoutes(vni uint, allowedRoutes []Route) error {
	v, ok := h.networkByID.Load(vni)
	if !ok {
		return fmt.Errorf("VNI %d not found", vni)
	}
	vnet := v.(*VirtualNetwork)

	// Remove all old allowed routes for this vnet, then insert the new ones.
	h.networksByAddressMu.Lock()
	for _, route := range vnet.AllowedRoutes {
		value := h.networksByAddress.Find(route.Dst.Addr())
		if value != nil {
			srcTrie := value.(*iptrie.Trie)
			srcTrie.Remove(route.Src)
			// Library doesn't expose a way to easily check if the trie is empty.
		}
	}

	// Insert all new allowed routes for this vnet
	for _, route := range allowedRoutes {
		value := h.networksByAddress.Find(route.Dst.Addr())
		if value == nil {
			value = iptrie.NewTrie()
			h.networksByAddress.Insert(route.Dst, value)
		}
		srcTrie := value.(*iptrie.Trie)
		srcTrie.Insert(route.Src, vnet)
	}
	h.networksByAddressMu.Unlock()

	// Update vnet state
	vnet.AllowedRoutes = allowedRoutes

	return nil
}

// UpdateVirtualNetworkKeys sets/rotates the encryption keys for a virtual network.
// This must be called atleast once every 24 hours or after `replay.RekeyAfterMessages`
// messages. The epoch must be a monotonically increasing value.
func (h *Handler) UpdateVirtualNetworkKeys(vni uint, epoch uint32, rxKey, txKey [16]byte, expiresAt time.Time) error {
	value, ok := h.networkByID.Load(vni)
	if !ok {
		return fmt.Errorf("VNI %d not found", vni)
	}
	vnet := value.(*VirtualNetwork)

	// Set grace period (30s) on the previous RX key, if it exists
	if txCipher := vnet.txCipher.Load(); txCipher != nil {
		prevEpoch := txCipher.epoch
		if prevEpoch != epoch {
			if prevCipherAny, ok := vnet.rxCiphers.Load(prevEpoch); ok {
				if prevCipher, ok := prevCipherAny.(*receiveCipher); ok {
					graceExpiry := h.clock.Now().Add(keyGracePeriod)
					// Clamp the expiry to now+gracePeriod now that we have rotated.
					if prevCipher.expiresAt.After(graceExpiry) {
						prevCipher.expiresAt = graceExpiry
					}
				}
			}
		}
	}

	// Delete expired keys (to free key material from memory)
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

	vnet.rxCiphers.Store(epoch, &receiveCipher{
		AEAD:      rxCipher,
		expiresAt: expiresAt,
	})

	vnet.txCipher.Store(&transmitCipher{
		AEAD:  txCipher,
		epoch: epoch,
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

// PhyToVirt converts a physical frame to a virtual frame typically by performing decapsulation.
// Returns the length of the resulting virtual frame.
func (h *Handler) PhyToVirt(phyFrame, virtFrame []byte) int {
	payload, err := udp.Decode(phyFrame, nil, true)
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
		slog.Debug("Dropping frame with unknown VNI", slog.Uint64("vni", uint64(hdr.VNI)))
		return 0
	}
	vnet := value.(*VirtualNetwork)

	var nonce []byte
	var epoch uint32
	for i := 0; i < hdr.NumOptions; i++ {
		opt := hdr.Options[i]
		if opt.Class == geneve.ClassExperimental {
			switch opt.Type {
			case geneve.OptionTypeTxCounter:
				nonce = opt.Value[:12]
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
		slog.Debug("No matching RX key for epoch", slog.Uint64("epoch", uint64(epoch)))
		vnet.Stats.RXDropsNoKey.Add(1)
		return 0
	}

	rxCipher := rxCipherAny.(*receiveCipher)
	if rxCipher.expiresAt.Before(h.clock.Now()) {
		slog.Debug("Epoch key expired", slog.Uint64("epoch", uint64(epoch)))
		vnet.Stats.RXDropsExpiredKey.Add(1)
		// Delete expired key (to free key material from memory)
		vnet.rxCiphers.Delete(epoch)
		return 0
	}

	txCounter := binary.BigEndian.Uint64(nonce[4:])

	if !rxCipher.replayFilter.ValidateCounter(txCounter, replay.RejectAfterMessages) {
		// Delayed packets can cause some uneccesary noise here.
		slog.Debug("Replay filter rejected frame", slog.Uint64("txCounter", txCounter))
		vnet.Stats.RXReplayDrops.Add(1)
		return 0
	}

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

	// Is it an authenticated out-of-band message?
	if hdr.ProtocolType == 0 {
		slog.Debug("Dropping out-of-band message")
		// Treat as a (zero-byte) virtual packet receive for stats purposes.
		vnet.Stats.RXPackets.Add(1)
		vnet.Stats.RXBytes.Add(uint64(len(ipPacket)))
		vnet.Stats.LastRXUnixNano.Store(h.clock.Now().UnixNano())
		return 0
	}

	ipVersion := ipPacket[0] >> 4

	// Get the source address of the decrypted frame.
	var srcAddr netip.Addr
	switch ipVersion {
	case header.IPv4Version:
		var ok bool
		ipHdr := header.IPv4(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 address in frame")
			vnet.Stats.RXInvalidSrc.Add(1)
			return 0
		}
	case header.IPv6Version:
		var ok bool
		ipHdr := header.IPv6(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 address in frame")
			vnet.Stats.RXInvalidSrc.Add(1)
			return 0
		}
	default:
		slog.Warn("Unsupported IP version", slog.Int("version", int(ipVersion)))
		vnet.Stats.RXInvalidSrc.Add(1)
		return 0
	}

	// Confirm that the source address is valid for the virtual network (ala allowed_ips).
	var validSrcAddr bool
	for _, route := range vnet.AllowedRoutes {
		if route.Dst.Contains(srcAddr) {
			validSrcAddr = true
			break
		}
	}
	if !validSrcAddr {
		slog.Debug("Dropping frame with invalid tunnel source address", slog.String("srcAddr", srcAddr.String()))
		vnet.Stats.RXInvalidSrc.Add(1)
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
			slog.Debug("Dropping non-IP frame",
				slog.Int("frameSize", len(virtFrame)),
				slog.Int("ethType", int(ethType)))
			return 0, false
		}

		// Strip off the ethernet header
		ipPacket = virtFrame[header.EthernetMinimumSize:]
	}

	ipVersion := ipPacket[0] >> 4

	// Get the tunnel destination address for the IP packet.
	var srcAddr, dstAddr netip.Addr
	switch ipVersion {
	case header.IPv4Version:
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

	// Find the virtual network by the destination and source addresses.
	h.networksByAddressMu.RLock()
	value := h.networksByAddress.Find(dstAddr)
	h.networksByAddressMu.RUnlock()
	if value == nil {
		slog.Debug("Dropping frame with unknown destination address", slog.String("dstAddr", dstAddr.String()))
		return 0, false
	}
	srcTrie := value.(*iptrie.Trie)

	value = srcTrie.Find(srcAddr)
	if value == nil {
		slog.Debug("Dropping frame with unknown source address", slog.String("srcAddr", srcAddr.String()))
		return 0, false
	}
	vnet := value.(*VirtualNetwork)

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

	binary.BigEndian.PutUint32(hdr.Options[0].Value[:4], txCipher.epoch)

	if txCipher.counter.Load() >= replay.RekeyAfterMessages {
		slog.Warn("TX counter overflow, you must rotate the key")
		vnet.Stats.TXErrors.Add(1)
		return 0, false
	}

	nonce := hdr.Options[1].Value[:12]
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

	encryptedFrameLen := len(txCipher.Seal(payload[hdrLen:hdrLen], nonce, ipPacket, payload[:hdrLen]))

	best := h.opts.localAddrs.Select(vnet.RemoteAddr)
	if best == nil {
		slog.Warn("No local underlay addresses configured")
		vnet.Stats.TXErrors.Add(1)
		return 0, false
	}

	localAddr := *best
	if h.opts.sourcePortHashing {
		localAddr.Port = flowhash.Hash(ipPacket)
	}

	frameLen, err := udp.Encode(phyFrame, &localAddr, vnet.RemoteAddr, hdrLen+encryptedFrameLen, false)
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
		slog.Warn("keep-alive: TX cipher not available")
		vnet.Stats.TXErrors.Add(1)
		return 0
	}
	if txCipher.counter.Load() >= replay.RekeyAfterMessages {
		slog.Warn("keep-alive: TX counter overflow, rotate the key")
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
	nonce := hdr.Options[1].Value[:12]
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
		slog.Warn("keep-alive: marshal Geneve header failed", slog.Any("error", err))
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
		slog.Warn("keep-alive: no local underlay addresses configured")
		vnet.Stats.TXErrors.Add(1)
		return 0
	}
	localAddr := *best // keep configured source port for stability

	// Finish outer UDP/IP/Ethernet
	totalGeneveLen := hdrLen + encLen
	frameLen, err := udp.Encode(phyFrame, &localAddr, vnet.RemoteAddr, totalGeneveLen, false)
	if err != nil {
		slog.Warn("keep-alive: UDP encode failed", slog.Any("error", err))
		vnet.Stats.TXErrors.Add(1)
		return 0
	}

	// Stats: treat as a (zero-byte) virtual packet send.
	vnet.Stats.TXPackets.Add(1)
	vnet.Stats.LastTXUnixNano.Store(now.UnixNano())
	vnet.Stats.LastKeepAliveUnixNano.Store(now.UnixNano())

	return frameLen
}
