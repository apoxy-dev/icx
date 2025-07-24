package icx

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx/flowhash"
	"github.com/apoxy-dev/icx/geneve"
	"github.com/apoxy-dev/icx/proxyarp"
	"github.com/apoxy-dev/icx/replay"
	"github.com/apoxy-dev/icx/tunnel"
	"github.com/apoxy-dev/icx/udp"
)

var _ tunnel.Handler = (*Handler)(nil)

type Handler struct {
	localAddr         *tcpip.FullAddress
	peerAddr          *tcpip.FullAddress
	virtualNetworkID  uint
	virtMAC           tcpip.LinkAddress
	sourcePortHashing bool
	fakeSrcMAC        tcpip.LinkAddress // Fake source MAC address for virtual L2 frames
	proxyARP          *proxyarp.ProxyARP
	rxCipher          cipher.AEAD
	txCipher          cipher.AEAD
	txCounter         atomic.Uint64
	replayFilter      replay.Filter
	hdrPool           *sync.Pool
}

func NewHandler(localAddr, peerAddr *tcpip.FullAddress, virtMAC tcpip.LinkAddress, virtualNetworkID uint, rxKey, txKey [16]byte, sourcePortHashing bool) (*Handler, error) {
	fakeSrcMAC := tcpip.GetRandMacAddr()

	rxBlock, err := aes.NewCipher(rxKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher for RX: %w", err)
	}

	rxCipher, err := cipher.NewGCM(rxBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher for RX: %w", err)
	}

	txBlock, err := aes.NewCipher(txKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher for TX: %w", err)
	}

	txCipher, err := cipher.NewGCM(txBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher for TX: %w", err)
	}

	hdrPool := &sync.Pool{
		New: func() any {
			return &geneve.Header{}
		},
	}

	return &Handler{
		localAddr:         localAddr,
		peerAddr:          peerAddr,
		virtMAC:           virtMAC,
		sourcePortHashing: sourcePortHashing,
		fakeSrcMAC:        fakeSrcMAC,
		proxyARP:          proxyarp.NewProxyARP(fakeSrcMAC),
		rxCipher:          rxCipher,
		txCipher:          txCipher,
		hdrPool:           hdrPool,
	}, nil
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

	if hdr.VNI != uint32(h.virtualNetworkID) {
		slog.Debug("Dropping frame with mismatched VNI",
			slog.Uint64("expected", uint64(h.virtualNetworkID)),
			slog.Uint64("received", uint64(hdr.VNI)))
		return 0
	}

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

	if !h.replayFilter.ValidateCounter(txCounter, replay.RejectAfterMessages) {
		// Delayed packets can cause some uneccesary noise here.
		slog.Debug("Replay filter rejected frame", slog.Uint64("txCounter", txCounter))
		return 0
	}

	decryptedFrame, err := h.rxCipher.Open(virtFrame[header.EthernetMinimumSize:header.EthernetMinimumSize], nonce, payload[hdrLen:], payload[:hdrLen])
	if err != nil {
		slog.Warn("Failed to decrypt payload", slog.Any("error", err))
		return 0
	}

	isIPv6 := virtFrame[header.EthernetMinimumSize]>>4 == header.IPv6Version

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

	hdr := h.hdrPool.Get().(*geneve.Header)
	defer func() {
		h.hdrPool.Put(hdr)
	}()

	*hdr = geneve.Header{
		VNI:        uint32(h.virtualNetworkID),
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
	binary.BigEndian.PutUint64(nonce[4:], h.txCounter.Add(1))

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
	if h.peerAddr.Addr.Len() == net.IPv4len {
		payload = phyFrame[udp.PayloadOffsetIPv4:]
	} else {
		payload = phyFrame[udp.PayloadOffsetIPv6:]
	}

	hdrLen, err := hdr.MarshalBinary(payload)
	if err != nil {
		slog.Warn("Failed to marshal GENEVE header", slog.Any("error", err))
		return 0, false
	}

	encryptedFrameLen := len(h.txCipher.Seal(payload[hdrLen:hdrLen], nonce, virtFrame, payload[:hdrLen]))

	localAddr := *h.localAddr
	if h.sourcePortHashing {
		localAddr.Port = flowhash.Hash(virtFrame)
	}

	frameLen, err := udp.Encode(phyFrame, &localAddr, h.peerAddr, hdrLen+encryptedFrameLen, false)
	if err != nil {
		slog.Warn("Failed to encode UDP frame", slog.Any("error", err))
		return 0, false
	}

	return frameLen, false
}
