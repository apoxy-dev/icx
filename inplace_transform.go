package icx

import (
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/phemmer/go-iptrie"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/icx/flowhash"
	"github.com/apoxy-dev/icx/geneve"
	"github.com/apoxy-dev/icx/replay"
	"github.com/apoxy-dev/icx/udp"
)

// Phase 2: in-place (shape-A) AEAD decap/encap helpers.
//
// These methods operate on a SINGLE backing buffer that holds one frame,
// described by an (offset, length) window. They return the (offset, length)
// window of the OUTPUT frame within the SAME buffer. The output overlaps the
// input. This mirrors a shared-UMEM zero-copy frame: one buffer is handed
// between the phy and virt sockets, so decap writes plaintext over the
// ciphertext region and encap writes ciphertext+headers around the plaintext,
// all within the one frame.
//
// The irreducible safety invariant (proven in inplace_aead_test.go): Go
// crypto/cipher GCM permits dst aliasing src ONLY at the SAME start offset
// (exact overlap) and PANICS on inexact overlap. Hence both helpers below use
// the exact-overlap form:
//
//	decap: gcm.Open(buf[ctStart:ctStart], nonce, buf[ctStart:ctStart+ctLen], aad)
//	encap: gcm.Seal(buf[ptStart:ptStart], nonce, buf[ptStart:ptStart+ptLen], aad)
//
// where ctStart == ptStart, so plaintext is written over the ciphertext (and
// vice versa) at the same start pointer. Headers are placed BEFORE that start
// (headroom) and the 16-byte GCM tag lands AFTER (tailroom).
//
// These helpers are byte-for-byte equivalent to the cross-buffer
// PhyToVirt/VirtToPhy/ToPhy transforms (see inplace_transform_test.go). They do
// NOT modify the existing transforms; they reuse the same udp/geneve/cipher
// helpers, slog logging, stats counters, and header pool.

// dropWindow is the sentinel returned on every drop path: a zero-length window.
const dropWindowOffset = 0

// PhyToVirtInPlace performs decapsulation IN PLACE within buf.
//
// On entry, buf[off:off+length] holds the physical frame
// ([outer Eth/IP/UDP][Geneve][ciphertext+tag]). On success it returns the
// (offset, length) window within buf where the resulting virtual frame lives:
//   - layer3: the raw inner IP packet (plaintext written over the ciphertext).
//   - layer2: a freshly written 14-byte Ethernet header immediately followed by
//     the inner IP packet, placed in the headroom that previously held the
//     consumed outer/Geneve headers.
//
// On any drop (bad UDP, bad Geneve, unknown VNI, no nonce, no/expired key,
// replay, decrypt failure, out-of-band, invalid src) it returns a zero-length
// window (length 0), matching every early-return in PhyToVirt. The crypto and
// validation logic is identical to PhyToVirt; only dst aliasing differs.
func (h *Handler) PhyToVirtInPlace(buf []byte, off, length int) (int, int) {
	phyFrame := buf[off : off+length]

	payload, err := udp.Decode(phyFrame, nil, true)
	if err != nil {
		slog.Warn("Failed to decode UDP frame", slog.Any("error", err))
		return dropWindowOffset, 0
	}

	// payload is a subslice of phyFrame (hence of buf). Compute its absolute
	// start within buf so we can build exact-overlap windows.
	payloadStart := off + (len(phyFrame) - len(payload))

	hdr := h.hdrPool.Get().(*geneve.Header)
	defer func() {
		h.hdrPool.Put(hdr)
	}()

	hdrLen, err := hdr.UnmarshalBinary(payload)
	if err != nil {
		slog.Warn("Failed to unmarshal Geneve header", slog.Any("error", err))
		return dropWindowOffset, 0
	}

	// Is it a valid VNI?
	value, exists := h.networkByID.Load(uint(hdr.VNI))
	if !exists {
		slog.Debug("Dropping frame with unknown VNI", slog.Uint64("vni", uint64(hdr.VNI)))
		return dropWindowOffset, 0
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
		return dropWindowOffset, 0
	}

	rxCipherAny, ok := vnet.rxCiphers.Load(epoch)
	if !ok {
		// Probably a delayed packet with an old key.
		slog.Debug("No matching RX key for epoch", slog.Uint64("epoch", uint64(epoch)))
		vnet.Stats.RXDropsNoKey.Add(1)
		return dropWindowOffset, 0
	}

	rxCipher := rxCipherAny.(*receiveCipher)
	if rxCipher.expiresAt.Before(h.clock.Now()) {
		slog.Debug("Epoch key expired", slog.Uint64("epoch", uint64(epoch)))
		vnet.Stats.RXDropsExpiredKey.Add(1)
		// Delete expired key (to free key material from memory)
		vnet.rxCiphers.Delete(epoch)
		return dropWindowOffset, 0
	}

	txCounter := binary.BigEndian.Uint64(nonce[4:])

	if !rxCipher.replayFilter.ValidateCounter(txCounter, replay.RejectAfterMessages) {
		// Delayed packets can cause some uneccesary noise here.
		slog.Debug("Replay filter rejected frame", slog.Uint64("txCounter", txCounter))
		vnet.Stats.RXReplayDrops.Add(1)
		return dropWindowOffset, 0
	}

	// In-place decap: the ciphertext (payload[hdrLen:]) lives at ctStart within
	// buf; we open it onto itself at the SAME start (exact overlap), so the
	// plaintext is written over the ciphertext region. The AAD is the Geneve
	// header (payload[:hdrLen]), which sits immediately before the ciphertext
	// and is left untouched by Open.
	ctStart := payloadStart + hdrLen
	ctLen := len(payload) - hdrLen
	aad := buf[payloadStart : payloadStart+hdrLen]

	ipPacket, err := rxCipher.Open(buf[ctStart:ctStart], nonce, buf[ctStart:ctStart+ctLen], aad)
	if err != nil {
		slog.Warn("Failed to decrypt payload", slog.Any("error", err))
		vnet.Stats.RXDecryptErrors.Add(1)
		return dropWindowOffset, 0
	}

	// Is it an authenticated out-of-band message?
	if hdr.ProtocolType == 0 {
		slog.Debug("Dropping out-of-band message")
		// Treat as a (zero-byte) virtual packet receive for stats purposes.
		vnet.Stats.RXPackets.Add(1)
		vnet.Stats.RXBytes.Add(uint64(len(ipPacket)))
		vnet.Stats.LastRXUnixNano.Store(h.clock.Now().UnixNano())
		return dropWindowOffset, 0
	}

	ipVersion := ipPacket[0] >> 4

	// Get the source address of the decrypted frame.
	var srcAddr netip.Addr
	switch ipVersion {
	case header.IPv4Version:
		// SourceAddressSlice indexes up to IPv4MinimumSize; a decrypted packet
		// shorter than that (a peer with valid keys can send one) would panic.
		// Mirrors PhyToVirt.
		if len(ipPacket) < header.IPv4MinimumSize {
			slog.Warn("Truncated IPv4 packet after decryption")
			vnet.Stats.RXInvalidSrc.Add(1)
			return dropWindowOffset, 0
		}
		var ok bool
		ipHdr := header.IPv4(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 address in frame")
			vnet.Stats.RXInvalidSrc.Add(1)
			return dropWindowOffset, 0
		}
	case header.IPv6Version:
		if len(ipPacket) < header.IPv6MinimumSize {
			slog.Warn("Truncated IPv6 packet after decryption")
			vnet.Stats.RXInvalidSrc.Add(1)
			return dropWindowOffset, 0
		}
		var ok bool
		ipHdr := header.IPv6(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 address in frame")
			vnet.Stats.RXInvalidSrc.Add(1)
			return dropWindowOffset, 0
		}
	default:
		slog.Warn("Unsupported IP version", slog.Int("version", int(ipVersion)))
		vnet.Stats.RXInvalidSrc.Add(1)
		return dropWindowOffset, 0
	}

	// Confirm that the source address is valid for the virtual network.
	// From our perspective, the source address must be within one of the
	// allowed destination prefixes for this vnet.
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
		return dropWindowOffset, 0
	}

	// Success: count bytes/packets and timestamp
	vnet.Stats.RXPackets.Add(1)
	vnet.Stats.RXBytes.Add(uint64(len(ipPacket)))
	vnet.Stats.LastRXUnixNano.Store(h.clock.Now().UnixNano())

	if h.opts.layer3 {
		// The virtual frame is the raw IP packet, written in place over the
		// ciphertext: it begins at ctStart.
		return ctStart, len(ipPacket)
	}

	// Layer 2: prepend an Ethernet header into the headroom immediately before
	// the plaintext (over the now-consumed outer/Geneve header region). There
	// is always >= 14 bytes of headroom there: the consumed outer headers are
	// 42 (IPv4) / 62 (IPv6) bytes plus the 32-byte Geneve header, far exceeding
	// the 14-byte Ethernet header.
	ethStart := ctStart - header.EthernetMinimumSize
	eth := header.Ethernet(buf[ethStart : ethStart+header.EthernetMinimumSize])
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

	return ethStart, header.EthernetMinimumSize + len(ipPacket)
}

// VirtToPhyInPlace performs encapsulation IN PLACE within buf.
//
// On entry, buf[off:off+length] holds the virtual frame:
//   - layer3: a raw inner IP packet.
//   - layer2: an Ethernet frame; the 14-byte Ethernet header is stripped before
//     encryption. ARP requests and IPv6 Neighbor Solicitations are answered
//     locally via the proxy helpers (which write into the headroom in front of
//     the inner IP packet) and returned with handled=true.
//
// The buffer MUST provide headroom in front of the inner IP packet for the
// outer headers (PayloadOffset = 42 for an IPv4 underlay / 62 for IPv6) plus
// the 32-byte Geneve header, and at least 16 bytes of tailroom after the inner
// IP packet for the GCM tag. The forwarder's UMEM frame (FrameSize 2048) and
// the test corpus both satisfy this.
//
// On success it returns the (offset, length) window of the resulting physical
// frame within buf and handled=false. ARP/ND immediate replies return
// (window, true). Drops return a zero-length window (length 0) with
// handled=false, matching every early-return in VirtToPhy. Crypto/validation
// logic is identical to VirtToPhy; only src aliasing differs.
func (h *Handler) VirtToPhyInPlace(buf []byte, off, length int) (int, int, bool) {
	virtFrame := buf[off : off+length]
	ipPacket := virtFrame
	// ipStart is the absolute offset of the inner IP packet within buf.
	ipStart := off

	if !h.opts.layer3 {
		// A virtual frame shorter than an Ethernet header cannot be parsed;
		// eth.Type() would index past the slice and panic. Drop it (the datapath
		// must never panic on a malformed frame). Mirrors VirtToPhy.
		if length < header.EthernetMinimumSize {
			slog.Debug("Dropping runt virtual frame", slog.Int("frameSize", length))
			return dropWindowOffset, 0, false
		}

		eth := header.Ethernet(virtFrame)
		ethType := eth.Type()

		// Handle ARP requests with an immediate local reply. proxyARP.Reply
		// writes the reply into the headroom before the virtual frame, matching
		// the two-buffer call shape (Reply(virtFrame, phyFrame)).
		if ethType == header.ARPProtocolNumber {
			phyOff, phyLen, handled := h.replyInHeadroom(buf, off, length, replyKindARP)
			if handled {
				return phyOff, phyLen, true
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
						phyOff, phyLen, handled := h.replyInHeadroom(buf, off, length, replyKindND)
						if handled {
							return phyOff, phyLen, true
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
			return dropWindowOffset, 0, false
		}

		// Strip off the ethernet header
		ipPacket = virtFrame[header.EthernetMinimumSize:]
		ipStart = off + header.EthernetMinimumSize
	}

	// An empty IP packet (e.g. a frame that is exactly an Ethernet header, or a
	// zero-length layer3 frame) has no version nibble to read; ipPacket[0] would
	// panic. Drop it. Mirrors VirtToPhy.
	if len(ipPacket) == 0 {
		slog.Debug("Dropping empty virtual frame")
		return dropWindowOffset, 0, false
	}

	ipVersion := ipPacket[0] >> 4

	// Get the tunnel destination address for the IP packet.
	var srcAddr, dstAddr netip.Addr
	switch ipVersion {
	case header.IPv4Version:
		// The src/dst accessors index up to IPv4MinimumSize; a shorter packet
		// (the version nibble says IPv4 but the header is truncated) would panic.
		// Mirrors VirtToPhy.
		if len(ipPacket) < header.IPv4MinimumSize {
			slog.Debug("Dropping truncated IPv4 frame", slog.Int("frameSize", len(ipPacket)))
			return dropWindowOffset, 0, false
		}
		var ok bool
		ipHdr := header.IPv4(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 source address in frame")
			return dropWindowOffset, 0, false
		}
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 destination address in frame")
			return dropWindowOffset, 0, false
		}
	case header.IPv6Version:
		// Likewise the IPv6 accessors index up to IPv6MinimumSize.
		if len(ipPacket) < header.IPv6MinimumSize {
			slog.Debug("Dropping truncated IPv6 frame", slog.Int("frameSize", len(ipPacket)))
			return dropWindowOffset, 0, false
		}
		var ok bool
		ipHdr := header.IPv6(ipPacket)
		srcAddr, ok = netip.AddrFromSlice(ipHdr.SourceAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 source address in frame")
			return dropWindowOffset, 0, false
		}
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 destination address in frame")
			return dropWindowOffset, 0, false
		}
	}

	// Find the virtual network by the destination and source addresses.
	h.networksByAddressMu.RLock()
	value := h.networksByAddress.Find(dstAddr)
	h.networksByAddressMu.RUnlock()
	if value == nil {
		slog.Debug("Dropping frame with unknown destination address", slog.String("dstAddr", dstAddr.String()))
		return dropWindowOffset, 0, false
	}
	srcTrie := value.(*iptrie.Trie)

	value = srcTrie.Find(srcAddr)
	if value == nil {
		slog.Debug("Dropping frame with unknown source address", slog.String("srcAddr", srcAddr.String()))
		return dropWindowOffset, 0, false
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
		return dropWindowOffset, 0, false
	}

	binary.BigEndian.PutUint32(hdr.Options[0].Value[:4], txCipher.epoch)

	if txCipher.counter.Load() >= replay.RekeyAfterMessages {
		slog.Warn("TX counter overflow, you must rotate the key")
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0, false
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
		return dropWindowOffset, 0, false
	}

	// Determine the outer-header payload offset for the underlay address family.
	var payloadOffset int
	if vnet.RemoteAddr.Addr.Len() == net.IPv4len {
		payloadOffset = udp.PayloadOffsetIPv4
	} else {
		payloadOffset = udp.PayloadOffsetIPv6
	}

	// The Geneve header (hdrLen bytes) is marshalled into the headroom
	// immediately before the inner IP packet, and the outer Eth/IP/UDP headers
	// (payloadOffset bytes) go before that. So the physical frame begins at:
	//
	//	phyStart = ipStart - hdrLen - payloadOffset
	//
	// We do not know hdrLen until after MarshalBinary, but the handler's frames
	// always use the fixed 2-option header (8 base + 8 epoch + 16 txcounter =
	// 32 bytes). To stay agnostic, marshal into a scratch window at the right
	// place and read back the actual length.
	//
	// Geneve header sits at [geneveStart, geneveStart+hdrLen) == buf region
	// immediately before ipStart. Marshal it there; the AAD for Seal is exactly
	// that region.
	const geneveHdrLen = 32 // fixed for the handler's 2-option (epoch+txcounter) header
	geneveStart := ipStart - geneveHdrLen
	phyStart := geneveStart - payloadOffset
	if phyStart < 0 {
		slog.Warn("Insufficient headroom for in-place encap")
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0, false
	}

	hdrLen, err := hdr.MarshalBinary(buf[geneveStart : geneveStart+geneveHdrLen])
	if err != nil {
		slog.Warn("Failed to marshal Geneve header", slog.Any("error", err))
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0, false
	}
	if hdrLen != geneveHdrLen {
		// Defensive: the handler's header must marshal to exactly 32 bytes; if
		// not, our headroom math would be off, which would corrupt the frame.
		slog.Warn("Unexpected Geneve header length", slog.Int("hdrLen", hdrLen))
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0, false
	}

	// In-place encap: Seal the inner IP packet onto itself at the SAME start
	// (exact overlap). The ciphertext is written over the plaintext at ipStart
	// and the 16-byte tag lands in the tailroom immediately after. The AAD is
	// the Geneve header we just marshalled directly in front.
	ptLen := len(ipPacket)
	aad := buf[geneveStart : geneveStart+hdrLen]
	encryptedFrameLen := len(txCipher.Seal(buf[ipStart:ipStart], nonce, buf[ipStart:ipStart+ptLen], aad))

	// Underlay source selection.
	best := h.opts.localAddrs.Select(vnet.RemoteAddr)
	if best == nil {
		slog.Warn("No local underlay addresses configured")
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0, false
	}

	localAddr := *best
	if h.opts.sourcePortHashing {
		localAddr.Port = flowhash.MapToEphemeralPort(flowhash.Hash(buf[ipStart : ipStart+ptLen]))
	}

	// Write the outer Eth/IP/UDP headers into the headroom at phyStart. The
	// Geneve header + ciphertext + tag already sit at phyStart+payloadOffset.
	phyFrame := buf[phyStart:]
	frameLen, err := udp.Encode(phyFrame, &localAddr, vnet.RemoteAddr, hdrLen+encryptedFrameLen, false)
	if err != nil {
		slog.Warn("Failed to encode UDP frame", slog.Any("error", err))
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0, false
	}

	// Success: count bytes/packets and timestamp
	vnet.Stats.TXPackets.Add(1)
	vnet.Stats.TXBytes.Add(uint64(ptLen))
	vnet.Stats.LastTXUnixNano.Store(h.clock.Now().UnixNano())

	return phyStart, frameLen, false
}

// replyKind selects the local-reply proxy used by replyInHeadroom.
type replyKind int

const (
	replyKindARP replyKind = iota
	replyKindND
)

// replyInHeadroom produces an ARP or ND immediate reply for the virtual frame
// at buf[off:off+length], writing the reply into the SAME buffer's headroom in
// front of the request and returning the (offset, length) window of the reply
// physical frame.
//
// The proxy helpers (proxyARP.Reply / ndProxy.Reply) take (src, dst) buffers
// and build the reply from scratch into dst, reading only from src. We give
// them a src view (the virtual frame) and a dst view (the headroom + frame
// region) that do not start at the same address, so they behave exactly as in
// the two-buffer VirtToPhy path. The reply is small (an ARP reply or an NA), so
// the standard 74/94-byte headroom is more than sufficient.
func (h *Handler) replyInHeadroom(buf []byte, off, length int, kind replyKind) (int, int, bool) {
	src := buf[off : off+length]

	// Reserve the maximum headroom we use elsewhere so the reply never overlaps
	// the request bytes the proxy is still reading. PayloadOffsetIPv6 (62) +
	// the 32-byte Geneve header == 94 bytes, the largest in-place prepend.
	const maxHeadroom = 94
	if off < maxHeadroom {
		// Not enough headroom to build the reply without aliasing the request;
		// fall through to normal handling (drop / encap) like the original.
		return dropWindowOffset, 0, false
	}
	dstStart := off - maxHeadroom
	dst := buf[dstStart:]

	var frameLen int
	var err error
	switch kind {
	case replyKindARP:
		frameLen, err = h.proxyARP.Reply(src, dst)
		if err != nil {
			slog.Warn("Failed to handle ARP request", slog.Any("error", err))
			return dropWindowOffset, 0, false
		}
	case replyKindND:
		frameLen, err = h.ndProxy.Reply(src, dst)
		if err != nil {
			slog.Warn("Failed to handle ND request", slog.Any("error", err))
			return dropWindowOffset, 0, false
		}
	}

	return dstStart, frameLen, true
}

// ToPhyInPlace performs the keep-alive encapsulation IN PLACE within buf.
//
// Unlike VirtToPhyInPlace there is no inner payload: the AEAD is computed over
// an empty plaintext, so the ciphertext is just the 16-byte tag. The caller
// provides a buffer with at least PayloadOffset + 32 (Geneve) + 16 (tag) bytes
// available starting at off. The keep-alive frame is built starting at off and
// the returned window is (off, frameLen).
//
// It returns a zero length when there is nothing due to send or on any error,
// matching ToPhy. This is the in-place analogue of ToPhy.
func (h *Handler) ToPhyInPlace(buf []byte, off int) (int, int) {
	if h.opts.keepAliveInterval == nil || *h.opts.keepAliveInterval <= 0 {
		return dropWindowOffset, 0
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
		return dropWindowOffset, 0
	}

	txCipher := vnet.txCipher.Load()
	if txCipher == nil {
		// No key yet, not really an error for keep-alives.
		return dropWindowOffset, 0
	}

	if txCipher.counter.Load() >= replay.RekeyAfterMessages {
		slog.Warn("TX counter overflow, rotate the key")
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0
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
	var payloadOffset int
	if vnet.RemoteAddr.Addr.Len() == net.IPv4len {
		payloadOffset = udp.PayloadOffsetIPv4
	} else {
		payloadOffset = udp.PayloadOffsetIPv6
	}

	phyFrame := buf[off:]
	payload := phyFrame[payloadOffset:]

	// Marshal Geneve header.
	hdrLen, err := hdr.MarshalBinary(payload)
	if err != nil {
		slog.Warn("Marshal Geneve header failed", slog.Any("error", err))
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0
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
		return dropWindowOffset, 0
	}
	localAddr := *best

	// Finish outer UDP/IP/Ethernet
	totalGeneveLen := hdrLen + encLen
	frameLen, err := udp.Encode(phyFrame, &localAddr, vnet.RemoteAddr, totalGeneveLen, false)
	if err != nil {
		slog.Warn("UDP encode failed", slog.Any("error", err))
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0
	}

	// Stats: treat as a (zero-byte) virtual packet send.
	vnet.Stats.TXPackets.Add(1)
	vnet.Stats.LastTXUnixNano.Store(now.UnixNano())
	vnet.Stats.LastKeepAliveUnixNano.Store(now.UnixNano())

	return off, frameLen
}
