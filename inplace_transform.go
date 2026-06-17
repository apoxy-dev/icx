package icx

import (
	"encoding/binary"
	"log/slog"
	"net"
	"net/netip"
	"time"

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

// geneveHdrLen is the fixed marshalled size of the handler's 2-option Geneve
// header (8 base + 8 epoch option + 16 txcounter option = 32 bytes). The
// in-place encap reserves exactly this much headroom before the inner IP packet
// (geneveStart = ipStart - geneveHdrLen) BEFORE it marshals the header, then
// verifies the real marshal length matches at runtime in VirtToPhyInPlace.
// TestGeneveHdrLenMatchesConstant pins it against the geneve package so a change
// to the option encoding fails the build instead of silently dropping frames.
const geneveHdrLen = 32

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

	// Drop frames whose outer underlay source does not match the configured peer
	// before any crypto/replay work (APO-650). Only the IP is compared (the UDP
	// source port is rewritten per packet by source-port hashing). A nil
	// RemoteAddr under an enabled check fails closed. Mirrors PhyToVirt.
	if h.opts.validateOuterSrc && (vnet.RemoteAddr == nil || outerSrc.Addr != vnet.RemoteAddr.Addr) {
		slog.Debug("Dropping frame: outer source does not match configured peer",
			slog.String("outerSrc", outerSrc.Addr.String()))
		vnet.Stats.RXDropsBadPeer.Add(1)
		return dropWindowOffset, 0
	}

	var nonce []byte
	var epoch uint32
	for i := 0; i < hdr.NumOptions; i++ {
		opt := hdr.Options[i]
		if opt.Class == geneve.ClassExperimental {
			switch opt.Type {
			case geneve.OptionTypeTxCounter:
				// Require the declared 12-byte (Length=3) value so nonce[:4] (the
				// SPI) and the counter are provably sender-written, not stale pooled
				// bytes from a short/malformed option — keeps the SPI-mismatch drop
				// attribution honest. A wrong length leaves nonce nil → the
				// "Expected TX counter" drop below. Mirrors PhyToVirt exactly.
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

	// Verify the SPI bound into the nonce matches the epoch that selected this
	// SA (nonce = SPI‖counter). A conformant sender always sets nonce[:4] to the
	// key epoch; a mismatch is a malformed or tampered frame. GCM would also
	// reject it at Open (the nonce and the header both feed the tag), but the
	// explicit check makes the binding auditable and gives a precise drop reason.
	// (APO-644). Mirrors PhyToVirt exactly to preserve byte-equivalence.
	if spi := binary.BigEndian.Uint32(nonce[:4]); spi != epoch {
		slog.Debug("Dropping frame: nonce SPI does not match key epoch",
			slog.Uint64("epoch", uint64(epoch)), slog.Uint64("nonceSPI", uint64(spi)))
		vnet.Stats.RXDropsSPIMismatch.Add(1)
		return dropWindowOffset, 0
	}

	// Rate-limit the costly AES-GCM Open per network (APO-655). Placed after the
	// cheap VNI/key/SPI checks so only frames that would otherwise be authenticated
	// consume budget, and before Open so a flood cannot burn crypto CPU. Mirrors
	// PhyToVirt.
	if vnet.rxLimiter != nil && !vnet.rxLimiter.allow(h.clock.Now().UnixNano()) {
		slog.Debug("Dropping frame: RX rate limit exceeded", slog.Uint64("vni", uint64(hdr.VNI)))
		vnet.Stats.RXRateLimitDrops.Add(1)
		return dropWindowOffset, 0
	}

	txCounter := binary.BigEndian.Uint64(nonce[4:])

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

	// Anti-replay AFTER authentication (APO-645/S2): ValidateCounter both checks
	// and advances the sliding window, so it must run only on a packet whose tag
	// has verified. Running it before Open let an attacker who can spoof the
	// outer 4-tuple advance the window with a forged high counter and wedge the
	// real peer (whose in-window counters are then rejected as "behind window").
	if !rxCipher.replayFilter.ValidateCounter(txCounter, replay.RejectAfterMessages) {
		// Delayed packets can cause some unnecessary noise here.
		slog.Debug("Replay filter rejected frame", slog.Uint64("txCounter", txCounter))
		vnet.Stats.RXReplayDrops.Add(1)
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

	// A non-OOB frame whose authenticated payload is empty has no version nibble;
	// ipPacket[0] would panic. An authenticated peer can craft one. (APO-647/S4)
	if len(ipPacket) == 0 {
		slog.Warn("Dropping empty decrypted payload")
		vnet.Stats.RXInvalidSrc.Add(1)
		return dropWindowOffset, 0
	}

	ipVersion := ipPacket[0] >> 4

	// Get the source and destination addresses of the decrypted frame. Both feed
	// the cryptokey-routing check below: the inner source against the allowed
	// route.Dst prefixes (remote side) and the inner destination against the
	// allowed route.Src prefixes (local side). Mirrors PhyToVirt.
	var srcAddr, dstAddr netip.Addr
	switch ipVersion {
	case header.IPv4Version:
		// The src/dst accessors index up to IPv4MinimumSize; a decrypted packet
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
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv4 destination address in frame")
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
		dstAddr, ok = netip.AddrFromSlice(ipHdr.DestinationAddressSlice())
		if !ok {
			slog.Warn("Invalid IPv6 destination address in frame")
			vnet.Stats.RXInvalidSrc.Add(1)
			return dropWindowOffset, 0
		}
	default:
		slog.Warn("Unsupported IP version", slog.Int("version", int(ipVersion)))
		vnet.Stats.RXInvalidSrc.Add(1)
		return dropWindowOffset, 0
	}

	// Confirm the inner addresses are authorized for this virtual network in a
	// single pass: the source must fall within an allowed route.Dst prefix (the
	// remote side) and the destination within an allowed route.Src prefix (the
	// local side). The destination half is the cryptokey-routing check RX
	// previously omitted (APO-649), confining a peer to the local subnets it is
	// permitted to deliver to. Mirrors PhyToVirt.
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
		slog.Debug("Dropping frame with invalid tunnel source address", slog.String("srcAddr", srcAddr.String()))
		vnet.Stats.RXInvalidSrc.Add(1)
		return dropWindowOffset, 0
	}
	if !validDst {
		slog.Debug("Dropping frame with invalid tunnel destination address", slog.String("dstAddr", dstAddr.String()))
		vnet.Stats.RXInvalidDst.Add(1)
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
	if ethStart < 0 {
		// Defensive: mirrors the encap path's phyStart < 0 guard. The consumed
		// outer + Geneve headers (>= 42 + 32 bytes) always exceed the 14-byte
		// Ethernet header, so for a well-formed frame this is unreachable — but
		// guard rather than index out of bounds on a malformed one.
		slog.Warn("Insufficient headroom for in-place L2 prepend")
		vnet.Stats.RXInvalidSrc.Add(1)
		return dropWindowOffset, 0
	}
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

	// Find the virtual network by the destination then source address (both LPM)
	// via a single lock-free load of the copy-on-write routing snapshot (P12/APO-675).
	// The published table is immutable — writers swap in a freshly built one — so the
	// two-tier lookup is race-free with no per-packet RLock, removing the shared
	// RWMutex readerCount cache-line bounce that serialized the TX path across all
	// NIC-queue goroutines.
	rt := h.routes.Load()
	value := rt.byDst.Find(dstAddr)
	if value == nil {
		slog.Debug("Dropping frame with unknown destination address", slog.String("dstAddr", dstAddr.String()))
		return dropWindowOffset, 0, false
	}
	srcValue := value.(*roDstEntry).srcTrie.Find(srcAddr)
	if srcValue == nil {
		slog.Debug("Dropping frame with unknown source address", slog.String("srcAddr", srcAddr.String()))
		return dropWindowOffset, 0, false
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
		return dropWindowOffset, 0, false
	}

	// Fail closed once the transmit SA expires (APO-656): see txKeyExpired. Mirrors
	// VirtToPhy.
	if h.txKeyExpired(vnet, txCipher, h.clock.Now()) {
		return dropWindowOffset, 0, false
	}

	binary.BigEndian.PutUint32(hdr.Options[0].Value[:4], txCipher.epoch)

	if txCipher.counter.Load() >= replay.RekeyAfterMessages {
		slog.Warn("TX counter overflow, you must rotate the key")
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0, false
	}

	// nonce = epoch‖counter: bind the 32-bit SPI (key epoch) into the high 4
	// bytes. Under the shared-epoch model this prefix is identical for both
	// directions, so it does not separate them (the distinct rx/tx keys do); its
	// value here is letting RX reject a tampered/mismatched SPI and forward-compat
	// with per-direction SPIs. The low 8 bytes are the per-SA monotonic counter.
	// Must match the cross-buffer VirtToPhy/ToPhy nonce layout exactly.
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

	// Bound the inner packet so the ciphertext + AEAD tag cannot be sealed past
	// the end of buf. Seal writes ptLen+Overhead() bytes starting at ipStart; an
	// oversized inner packet would otherwise overflow into the adjacent UMEM
	// frame (when the caller's buf capacity spans it) or force Seal to silently
	// reallocate onto the heap — leaving plaintext in the frame the descriptor
	// still points at. Drop instead (APO-667).
	if ipStart+ptLen+txCipher.Overhead() > len(buf) {
		slog.Debug("Dropping oversized inner packet for in-place encap",
			slog.Int("innerLen", ptLen),
			slog.Int("ipStart", ipStart),
			slog.Int("bufLen", len(buf)))
		vnet.Stats.TXErrors.Add(1)
		return dropWindowOffset, 0, false
	}

	// Hash the inner flow over the PLAINTEXT inner packet BEFORE the in-place Seal
	// below overwrites buf[ipStart:ipStart+ptLen] with ciphertext. The cross-buffer
	// VirtToPhy hashes its untouched plaintext input (its Seal targets a disjoint
	// region), so the in-place twin must capture the plaintext hash here — hashing
	// after Seal would feed the hash ciphertext that changes every packet, diverging
	// from the twin and making the source port an unstable per-packet value instead of
	// a stable function of the inner 5-tuple.
	var srcPortHash uint16
	if h.opts.sourcePortHashing {
		srcPortHash = flowhash.Hash(h.flowHashKey, buf[ipStart:ipStart+ptLen])
	}

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
		localAddr.Port = flowhash.MapToEphemeralPort(srcPortHash)
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

	// Fail closed once the transmit SA expires (APO-656): no point keeping a NAT
	// mapping warm under a key the peer would reject. Mark the network serviced so an
	// expired key does not leave it perpetually "due" — re-selected, re-logged and
	// re-counted on every poll. Mirrors ToPhy.
	if h.txKeyExpired(vnet, txCipher, now) {
		vnet.Stats.LastKeepAliveUnixNano.Store(now.UnixNano())
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
	// nonce = epoch‖counter: bind the 32-bit SPI (key epoch) into the high 4
	// bytes. Under the shared-epoch model this prefix is identical for both
	// directions, so it does not separate them (the distinct rx/tx keys do); its
	// value here is letting RX reject a tampered/mismatched SPI and forward-compat
	// with per-direction SPIs. The low 8 bytes are the per-SA monotonic counter.
	// Must match the cross-buffer VirtToPhy/ToPhy nonce layout exactly.
	nonce := hdr.Options[1].Value[:12]
	binary.BigEndian.PutUint32(nonce[:4], txCipher.epoch)
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
