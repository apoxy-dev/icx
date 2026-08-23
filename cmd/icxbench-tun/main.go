//go:build linux

// Command icxbench-tun runs the ICX engine over the USERSPACE vtep/tun datapath
// (a kernel /dev/net/tun device + a plain UDP underlay socket), as opposed to the
// zero-copy AF_XDP datapath that cmd/icxbench drives. Same static-keyed handler,
// same Geneve/AES-GCM wire format (L3-IP-in-Geneve), so it interoperates on the
// wire with an icxbench AF_XDP peer. It is a real-hardware benchmark harness for
// A/B-ing the userspace datapath against AF_XDP — not part of the production plane.
//
// Role decap: bind the UDP underlay on :6081, decrypt arriving Geneve frames and
// write the plaintext inner IP packets to the TUN device (counts as icx0 RX).
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/psp"
	"github.com/apoxy-dev/icx/vtep/tun"
)

func main() {
	tunName := flag.String("tun", "icx0", "TUN device name to create")
	localIP := flag.String("local-ip", "", "outer underlay local IP (this box, what arrives after NAT)")
	remoteIP := flag.String("remote-ip", "", "outer underlay remote/peer IP")
	underlayPort := flag.Int("underlay-port", 6081, "local UDP port the underlay socket binds")
	overlay := flag.String("overlay-addr", "10.0.0.2/8", "overlay address assigned to the TUN device")
	innerMTU := flag.Int("inner-mtu", 1400, "TUN device / inner MTU clamp")
	swapKeys := flag.Bool("swap-keys", false, "swap rx/tx keys (decap side, to match the encap peer)")
	srcPortHash := flag.Bool("source-port-hash", false, "vary outer UDP source port per inner flow (encap side)")
	index := flag.Int("index", 0, "tunnel index (0..15): selects VNI 0x1000+index and a distinct per-tunnel key, so multiple userspace VTEPs on one host fan in to a single AF_XDP peer without VNI/nonce collisions")
	flag.Parse()

	if *localIP == "" || *remoteIP == "" {
		log.Fatal("--local-ip and --remote-ip are required")
	}

	local := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.ParseIP(*localIP).To4()),
		Port: uint16(*underlayPort),
	}
	opts := []icx.HandlerOption{
		icx.WithLocalAddr(local),
		icx.WithLayer3VirtFrames(), // userspace tun datapath is L3 (raw IP, no Ethernet)
	}
	if *srcPortHash {
		opts = append(opts, icx.WithSourcePortHashing())
	}
	h, err := icx.NewHandler(opts...)
	if err != nil {
		log.Fatalf("NewHandler: %v", err)
	}

	prefix := netip.MustParsePrefix("10.0.0.0/8")
	routes := []icx.Route{{Src: prefix, Dst: prefix}}
	remote := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4Slice(net.ParseIP(*remoteIP).To4()),
		Port: uint16(*underlayPort),
	}
	if *index < 0 || *index > 15 {
		log.Fatalf("--index must be 0..15 (got %d)", *index)
	}
	// Per-tunnel deterministic master secret: distinct last byte ('A'+index) keeps
	// every VTEP's derivation space (and thus every (key,nonce) pair, given each
	// VTEP counts from 0) unique even though all share epoch 1 — required when N
	// VTEPs fan into one AF_XDP peer. The handler derives the per-direction keys
	// from (master, SPI); --swap-keys selects the mirrored role on the decap side.
	var master [32]byte
	copy(master[:], []byte("icxbench-master-secret-000000000"))
	master[31] = byte('A' + *index)
	role := psp.Initiator
	if *swapKeys {
		role = psp.Responder
	}
	rxSPI, txSPI, err := psp.EpochSPIs(role, 1)
	if err != nil {
		log.Fatalf("EpochSPIs: %v", err)
	}
	vni := uint(0x1000 + *index)
	if err := h.AddVirtualNetwork(vni, remote, routes); err != nil {
		log.Fatalf("AddVirtualNetwork: %v", err)
	}
	if err := h.UpdateVirtualNetworkSecret(vni, master, rxSPI, txSPI, time.Now().Add(24*time.Hour)); err != nil {
		log.Fatalf("UpdateVirtualNetworkSecret: %v", err)
	}

	dp, err := tun.Open(tun.OpenConfig{
		Engine:       h,
		Name:         *tunName,
		OverlayAddrs: []netip.Prefix{netip.MustParsePrefix(*overlay)},
		InnerMTU:     *innerMTU,
		UnderlayBind: netip.AddrPortFrom(netip.IPv4Unspecified(), uint16(*underlayPort)),
	})
	if err != nil {
		log.Fatalf("tun.Open: %v", err)
	}
	defer func() { _ = dp.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("icxbench-tun: USERSPACE datapath tun=%s underlay=:%d local=%s remote=%s swap=%v pid=%d",
		*tunName, *underlayPort, *localIP, *remoteIP, *swapKeys, os.Getpid())
	if err := dp.Run(ctx); err != nil {
		log.Fatalf("datapath.Run: %v", err)
	}
	log.Print("icxbench-tun: stopped")
}
