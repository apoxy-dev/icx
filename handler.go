package icx

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/dpeckett/triemap"

	"github.com/apoxy-dev/icx/flowhash"
	"github.com/apoxy-dev/icx/geneve"
	"github.com/apoxy-dev/icx/proxyarp"
	"github.com/apoxy-dev/icx/replay"
	"github.com/apoxy-dev/icx/udp"
)

const (
	// The size of the GENEVE header with icx options.
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

// statistics for a virtual network.
type stats struct {
	keyEpoch          atomic.Uint32
	keyRotations      atomic.Uint32
	rxPackets         atomic.Uint64
	rxBytes           atomic.Uint64
	rxDropsNoKey      atomic.Uint64
	rxDropsExpiredKey atomic.Uint64
	rxReplayDrops     atomic.Uint64
	rxDecryptErrors   atomic.Uint64
	rxInvalidSrc      atomic.Uint64
	txPackets         atomic.Uint64
	txBytes           atomic.Uint64
	txErrors          atomic.Uint64
	lastRXUnixNano    atomic.Int64
	lastTXUnixNano    atomic.Int64
}

func (s *stats) snapshot(vni uint) VirtualNetworkStats {
	lastRX := time.Unix(0, s.lastRXUnixNano.Load())
	lastTX := time.Unix(0, s.lastTXUnixNano.Load())
	return VirtualNetworkStats{
		VNI:               vni,
		KeyEpoch:          s.keyEpoch.Load(),
		KeyRotations:      s.keyRotations.Load(),
		RXPackets:         s.rxPackets.Load(),
		RXBytes:           s.rxBytes.Load(),
		RXDropsNoKey:      s.rxDropsNoKey.Load(),
		RXDropsExpiredKey: s.rxDropsExpiredKey.Load(),
		RXReplayDrops:     s.rxReplayDrops.Load(),
		RXDecryptErrors:   s.rxDecryptErrors.Load(),
		RXInvalidSrc:      s.rxInvalidSrc.Load(),
		TXPackets:         s.txPackets.Load(),
		TXBytes:           s.txBytes.Load(),
		TXErrors:          s.txErrors.Load(),
		LastRX:            lastRX,
		LastTX:            lastTX,
	}
}

// The state associated with each virtual network.
type virtualNetwork struct {
	id         uint
	remoteAddr *tcpip.FullAddress
	rxCiphers  sync.Map
	txCipher   atomic.Pointer[transmitCipher]
	addrs      []netip.Prefix
	stats      stats
}

type HandlerOption func(*handlerOptions) error

type handlerOptions struct {
	localAddr         *tcpip.FullAddress
	virtMAC           tcpip.LinkAddress
	srcMAC            tcpip.LinkAddress
	sourcePortHashing bool
	layer3            bool
}

func defaultHandlerOptions() handlerOptions {
	return handlerOptions{
		srcMAC:            tcpip.GetRandMacAddr(),
		sourcePortHashing: false,
		layer3:            false,
	}
}

// WithLocalAddr sets the local UDP endpoint used as the source for
// encapsulated packets. This option is required.
//
// If WithSourcePortHashing is enabled, the Port field of this address is
// overridden per packet with a hash of the inner flow. Otherwise, the Port
// specified here is used as-is.
func WithLocalAddr(a *tcpip.FullAddress) HandlerOption {
	return func(opts *handlerOptions) error {
		opts.localAddr = a
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
// are raw IP packets (no Ethernet header). In this mode:
//   - VirtToPhy expects an IP packet as input.
//   - PhyToVirt returns a decrypted IP packet.
//   - WithVirtMAC and WithSourceMAC are ignored.
//
// Default is L2 mode (Ethernet frames).
func WithLayer3VirtFrames() HandlerOption {
	return func(opts *handlerOptions) error {
		opts.layer3 = true
		return nil
	}
}

// Handler processes encapsulated GENEVE traffic for one or more virtual
// networks. It performs encryption/decryption, replay protection, address
// validation, and translation between physical and virtual frame formats.
//
// A Handler tracks virtual networks by VNI and allowed address prefixes,
// supports both L2 and L3 operation, and is safe for concurrent use.
type Handler struct {
	opts             *handlerOptions
	networkByID      sync.Map                          // Maps VNI to network
	networkByAddress *triemap.TrieMap[*virtualNetwork] // Maps tunnel destination address to network
	proxyARP         *proxyarp.ProxyARP
	hdrPool          *sync.Pool
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

	if options.localAddr == nil {
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
		opts:             &options,
		networkByAddress: triemap.New[*virtualNetwork](),
		proxyARP:         proxyarp.NewProxyARP(options.srcMAC),
		hdrPool:          hdrPool,
	}, nil
}

// AddVirtualNetwork adds a new network with the given VNI and remote address.
func (h *Handler) AddVirtualNetwork(vni uint, remoteAddr *tcpip.FullAddress, addrs []netip.Prefix) error {
	if _, exists := h.networkByID.Load(vni); exists {
		return fmt.Errorf("network with VNI %d already exists", vni)
	}

	net := &virtualNetwork{
		id:         vni,
		remoteAddr: remoteAddr,
		addrs:      addrs,
	}

	h.networkByID.Store(vni, net)
	for _, addr := range addrs {
		h.networkByAddress.Insert(addr, net)
	}

	return nil
}

// RemoveVirtualNetwork removes a network by its VNI.
func (h *Handler) RemoveVirtualNetwork(vni uint) error {
	value, exists := h.networkByID.Load(vni)
	if !exists {
		return fmt.Errorf("network with VNI %d does not exist", vni)
	}
	h.networkByID.Delete(vni)

	net := value.(*virtualNetwork)
	h.networkByAddress.RemoveValue(net)

	return nil
}

// UpdateVirtualNetworkKeys sets/rotates the encryption keys for a virtual network.
// This must be called atleast once every 24 hours or after `replay.RekeyAfterMessages`
// messages.
func (h *Handler) UpdateVirtualNetworkKeys(vni uint, epoch uint32, rxKey, txKey [16]byte, expiresAt time.Time) error {
	value, ok := h.networkByID.Load(vni)
	if !ok {
		return fmt.Errorf("VNI %d not found", vni)
	}
	vnet := value.(*virtualNetwork)

	// Set grace period (30s) on the previous RX key, if it exists
	if txCipher := vnet.txCipher.Load(); txCipher != nil {
		prevEpoch := txCipher.epoch
		if prevEpoch != epoch {
			if prevCipherAny, ok := vnet.rxCiphers.Load(prevEpoch); ok {
				if prevCipher, ok := prevCipherAny.(*receiveCipher); ok {
					prevCipher.expiresAt = time.Now().Add(keyGracePeriod)
				}
			}
		}
	}

	// Delete expired keys (to free key material from memory)
	now := time.Now()
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

	vnet.stats.keyEpoch.Store(epoch)
	vnet.stats.keyRotations.Add(1)

	return nil
}

// StatsForVNI returns a snapshot for a single virtual network.
func (h *Handler) StatsForVNI(vni uint) (VirtualNetworkStats, bool) {
	v, ok := h.networkByID.Load(vni)
	if !ok {
		return VirtualNetworkStats{}, false
	}
	vnet := v.(*virtualNetwork)
	return vnet.stats.snapshot(vnet.id), true
}

// AllStats returns snapshots for all currently registered virtual networks.
func (h *Handler) AllStats() []VirtualNetworkStats {
	var out []VirtualNetworkStats
	h.networkByID.Range(func(_, value any) bool {
		vnet := value.(*virtualNetwork)
		out = append(out, vnet.stats.snapshot(vnet.id))
		return true
	})
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
		slog.Warn("Failed to unmarshal GENEVE header", slog.Any("error", err))
		return 0
	}

	// Is it a valid VNI?
	value, exists := h.networkByID.Load(uint(hdr.VNI))
	if !exists {
		slog.Debug("Dropping frame with unknown VNI", slog.Uint64("vni", uint64(hdr.VNI)))
		return 0
	}
	vnet := value.(*virtualNetwork)

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
		slog.Warn("Expected TX counter in GENEVE header options")
		return 0
	}

	rxCipherAny, ok := vnet.rxCiphers.Load(epoch)
	if !ok {
		// Probably a delayed packet with an old key.
		slog.Debug("No matching RX key for epoch", slog.Uint64("epoch", uint64(epoch)))
		vnet.stats.rxDropsNoKey.Add(1)
		return 0
	}

	rxCipher := rxCipherAny.(*receiveCipher)
	if rxCipher.expiresAt.Before(time.Now()) {
		slog.Debug("Epoch key expired", slog.Uint64("epoch", uint64(epoch)))
		vnet.stats.rxDropsExpiredKey.Add(1)
		// Delete expired key (to free key material from memory)
		vnet.rxCiphers.Delete(epoch)
		return 0
	}

	txCounter := binary.BigEndian.Uint64(nonce[4:])

	if !rxCipher.replayFilter.ValidateCounter(txCounter, replay.RejectAfterMessages) {
		// Delayed packets can cause some uneccesary noise here.
		slog.Debug("Replay filter rejected frame", slog.Uint64("txCounter", txCounter))
		vnet.stats.rxReplayDrops.Add(1)
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
		vnet.stats.rxDecryptErrors.Add(1)
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
			vnet.stats.rxInvalidSrc.Add(1)
			return 0
		}
	case header.IPv6Version:
		var ok bool
		ipHdr := header.IPv6(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 address in frame")
			vnet.stats.rxInvalidSrc.Add(1)
			return 0
		}
	default:
		slog.Warn("Unsupported IP version", slog.Int("version", int(ipVersion)))
		vnet.stats.rxInvalidSrc.Add(1)
		return 0
	}

	// Confirm that the source address is valid for the virtual network (ala allowed_ips).
	var validSrcAddr bool
	for _, prefix := range vnet.addrs {
		if prefix.Contains(srcAddr) {
			validSrcAddr = true
			break
		}
	}
	if !validSrcAddr {
		slog.Debug("Dropping frame with invalid tunnel source address", slog.String("srcAddr", srcAddr.String()))
		vnet.stats.rxInvalidSrc.Add(1)
		return 0
	}

	// Success: count bytes/packets and timestamp
	vnet.stats.rxPackets.Add(1)
	vnet.stats.rxBytes.Add(uint64(len(ipPacket)))
	vnet.stats.lastRXUnixNano.Store(time.Now().UnixNano())

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
// VirtToPhy converts a virtual frame to a physical frame typically by performing encapsulation.
// Returns the length of the resulting physical frame.
func (h *Handler) VirtToPhy(virtFrame, phyFrame []byte) (int, bool) {
	ipPacket := virtFrame

	if !h.opts.layer3 {
		eth := header.Ethernet(virtFrame)
		ethType := eth.Type()

		if ethType == header.ARPProtocolNumber {
			// Immediately reply to the ARP request with a loopback response.
			frameLen, err := h.proxyARP.Reply(virtFrame, phyFrame)
			if err != nil {
				slog.Warn("Failed to handle ARP request", slog.Any("error", err))
				return 0, false
			}

			return frameLen, true
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
	var dstAddr netip.Addr
	switch ipVersion {
	case header.IPv4Version:
		var ok bool
		ipHdr := header.IPv4(ipPacket)
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 address in frame")
			return 0, false
		}
	case header.IPv6Version:
		var ok bool
		ipHdr := header.IPv6(ipPacket)
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 address in frame")
			return 0, false
		}
	}

	// Find the virtual network by the destination address.
	vnet, ok := h.networkByAddress.Get(dstAddr)
	if !ok {
		slog.Debug("Dropping frame with unknown tunnel destination address", slog.String("dstAddr", dstAddr.String()))
		return 0, false
	}

	hdr := h.hdrPool.Get().(*geneve.Header)
	defer func() {
		h.hdrPool.Put(hdr)
	}()

	*hdr = geneve.Header{
		VNI:        uint32(vnet.id),
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
		vnet.stats.txErrors.Add(1)
		return 0, false
	}

	binary.BigEndian.PutUint32(hdr.Options[0].Value[:4], txCipher.epoch)

	if txCipher.counter.Load() >= replay.RekeyAfterMessages {
		slog.Warn("TX counter overflow, you must rotate the key")
		vnet.stats.txErrors.Add(1)
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
		vnet.stats.txErrors.Add(1)
		return 0, false
	}

	var payload []byte
	if vnet.remoteAddr.Addr.Len() == net.IPv4len {
		payload = phyFrame[udp.PayloadOffsetIPv4:]
	} else {
		payload = phyFrame[udp.PayloadOffsetIPv6:]
	}

	hdrLen, err := hdr.MarshalBinary(payload)
	if err != nil {
		slog.Warn("Failed to marshal GENEVE header", slog.Any("error", err))
		vnet.stats.txErrors.Add(1)
		return 0, false
	}

	encryptedFrameLen := len(txCipher.Seal(payload[hdrLen:hdrLen], nonce, ipPacket, payload[:hdrLen]))

	localAddr := *h.opts.localAddr
	if h.opts.sourcePortHashing {
		localAddr.Port = flowhash.Hash(ipPacket)
	}

	frameLen, err := udp.Encode(phyFrame, &localAddr, vnet.remoteAddr, hdrLen+encryptedFrameLen, false)
	if err != nil {
		slog.Warn("Failed to encode UDP frame", slog.Any("error", err))
		vnet.stats.txErrors.Add(1)
		return 0, false
	}

	// Success: count bytes/packets and timestamp
	vnet.stats.txPackets.Add(1)
	vnet.stats.txBytes.Add(uint64(len(ipPacket)))
	vnet.stats.lastTXUnixNano.Store(time.Now().UnixNano())

	return frameLen, false
}
