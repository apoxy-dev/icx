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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/dpeckett/triemap"

	"github.com/apoxy-dev/icx/flowhash"
	"github.com/apoxy-dev/icx/geneve"
	"github.com/apoxy-dev/icx/proxyarp"
	"github.com/apoxy-dev/icx/replay"
	"github.com/apoxy-dev/icx/tunnel"
	"github.com/apoxy-dev/icx/udp"
)

// The size of the GENEVE header with icx options.
const HeaderSize = 32

var _ tunnel.Handler = (*Handler)(nil)

// The state associated with each virtual network.
type virtualNetwork struct {
	id           uint // The VNI of the network
	remoteAddr   *tcpip.FullAddress
	rxCipher     cipher.AEAD
	txCipher     cipher.AEAD
	txCounter    atomic.Uint64
	replayFilter replay.Filter
	tunnelAddrs  []netip.Prefix
}

type Handler struct {
	localAddr         *tcpip.FullAddress                // Local address of the physical interface (will be used as source address for UDP frames)
	virtMAC           tcpip.LinkAddress                 // Mac address of the virtual interface
	fakeSrcMAC        tcpip.LinkAddress                 // Fake source MAC address for virtual L2 frames
	networkByID       sync.Map                          // Maps VNI to network
	networkByAddress  *triemap.TrieMap[*virtualNetwork] // Maps tunnel destination address to network
	proxyARP          *proxyarp.ProxyARP
	hdrPool           *sync.Pool
	sourcePortHashing bool
}

func NewHandler(localAddr *tcpip.FullAddress, virtMAC tcpip.LinkAddress, sourcePortHashing bool) (*Handler, error) {
	fakeSrcMAC := tcpip.GetRandMacAddr()

	hdrPool := &sync.Pool{
		New: func() any {
			return &geneve.Header{}
		},
	}

	return &Handler{
		localAddr:         localAddr,
		virtMAC:           virtMAC,
		fakeSrcMAC:        fakeSrcMAC,
		networkByAddress:  triemap.New[*virtualNetwork](),
		proxyARP:          proxyarp.NewProxyARP(fakeSrcMAC),
		sourcePortHashing: sourcePortHashing,
		hdrPool:           hdrPool,
	}, nil
}

// AddVirtualNetwork adds a new network with the given VNI and remote address.
func (h *Handler) AddVirtualNetwork(vni uint, remoteAddr *tcpip.FullAddress, rxKey, txKey [16]byte, tunnelAddrs []netip.Prefix) error {
	if _, exists := h.networkByID.Load(vni); exists {
		return fmt.Errorf("network with VNI %d already exists", vni)
	}

	rxBlock, err := aes.NewCipher(rxKey[:])
	if err != nil {
		return fmt.Errorf("failed to create AES cipher for RX: %w", err)
	}
	rxCipher, err := cipher.NewGCM(rxBlock)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher for RX: %w", err)
	}

	txBlock, err := aes.NewCipher(txKey[:])
	if err != nil {
		return fmt.Errorf("failed to create AES cipher for TX: %w", err)
	}
	txCipher, err := cipher.NewGCM(txBlock)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher for TX: %w", err)
	}

	net := &virtualNetwork{
		id:          vni,
		remoteAddr:  remoteAddr,
		rxCipher:    rxCipher,
		txCipher:    txCipher,
		tunnelAddrs: tunnelAddrs,
	}

	h.networkByID.Store(vni, net)
	for _, addr := range tunnelAddrs {
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

	// TODO: implement key rotation using epochs.

	var nonce []byte
	for i := 0; i < hdr.NumOptions; i++ {
		if hdr.Options[i].Class == geneve.ClassExperimental && hdr.Options[i].Type == geneve.OptionTypeTxCounter {
			nonce = hdr.Options[i].Value[:12]
			break
		}
	}
	if len(nonce) == 0 {
		slog.Warn("Expected TX counter in GENEVE header options")
		return 0
	}

	txCounter := binary.BigEndian.Uint64(nonce[4:])

	if !vnet.replayFilter.ValidateCounter(txCounter, replay.RejectAfterMessages) {
		// Delayed packets can cause some uneccesary noise here.
		slog.Debug("Replay filter rejected frame", slog.Uint64("txCounter", txCounter))
		return 0
	}

	decryptedFrame, err := vnet.rxCipher.Open(virtFrame[header.EthernetMinimumSize:header.EthernetMinimumSize], nonce, payload[hdrLen:], payload[:hdrLen])
	if err != nil {
		slog.Warn("Failed to decrypt payload", slog.Any("error", err))
		return 0
	}

	isIPv6 := decryptedFrame[0]>>4 == header.IPv6Version

	// Get the source address of the decrypted frame.
	var srcAddr netip.Addr
	if isIPv6 {
		var ok bool
		ipHdr := header.IPv6(decryptedFrame)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 address in frame")
			return 0
		}
	} else {
		var ok bool
		ipHdr := header.IPv4(decryptedFrame)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 address in frame")
			return 0
		}
	}

	// Confirm that the source address is valid for the virtual network (ala allowed_ips).
	var validSrcAddr bool
	for _, prefix := range vnet.tunnelAddrs {
		// The list of prefixes is going to be very small.
		if prefix.Contains(srcAddr) {
			validSrcAddr = true
			break
		}
	}
	if !validSrcAddr {
		slog.Debug("Dropping frame with invalid tunnel source address", slog.String("srcAddr", srcAddr.String()))
		return 0
	}

	eth := header.Ethernet(virtFrame)
	eth.Encode(&header.EthernetFields{
		SrcAddr: h.fakeSrcMAC,
		DstAddr: h.virtMAC,
		Type: func() tcpip.NetworkProtocolNumber {
			if isIPv6 {
				return header.IPv6ProtocolNumber
			}
			return header.IPv4ProtocolNumber
		}(),
	})

	return header.EthernetMinimumSize + len(decryptedFrame)
}

// VirtToPhy converts a virtual frame to a physical frame typically by performing encapsulation.
// Returns the length of the resulting physical frame.
func (h *Handler) VirtToPhy(virtFrame, phyFrame []byte) (int, bool) {
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
	virtFrame = virtFrame[header.EthernetMinimumSize:]

	// Get the tunnel destination address for the IP packet.
	var dstAddr netip.Addr
	switch ethType {
	case header.IPv4ProtocolNumber:
		var ok bool
		ipHdr := header.IPv4(virtFrame)
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 address in frame")
			return 0, false
		}
	case header.IPv6ProtocolNumber:
		var ok bool
		ipHdr := header.IPv6(virtFrame)
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
				// TODO: implement key rotation using epochs.

			},
			{
				Class:  geneve.ClassExperimental,
				Type:   geneve.OptionTypeTxCounter,
				Length: 3,
			},
		},
	}

	nonce := hdr.Options[1].Value[:12]
	binary.BigEndian.PutUint64(nonce[4:], vnet.txCounter.Add(1))

	ipVersion := virtFrame[0] >> 4
	switch ipVersion {
	case 4:
		hdr.ProtocolType = uint16(header.IPv4ProtocolNumber)
	case 6:
		hdr.ProtocolType = uint16(header.IPv6ProtocolNumber)
	default:
		slog.Warn("Unsupported IP version", slog.Int("version", int(ipVersion)))
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
		return 0, false
	}

	encryptedFrameLen := len(vnet.txCipher.Seal(payload[hdrLen:hdrLen], nonce, virtFrame, payload[:hdrLen]))

	localAddr := *h.localAddr
	if h.sourcePortHashing {
		localAddr.Port = flowhash.Hash(virtFrame)
	}

	frameLen, err := udp.Encode(phyFrame, &localAddr, vnet.remoteAddr, hdrLen+encryptedFrameLen, false)
	if err != nil {
		slog.Warn("Failed to encode UDP frame", slog.Any("error", err))
		return 0, false
	}

	return frameLen, false
}
