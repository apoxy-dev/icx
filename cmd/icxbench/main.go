//go:build linux

// Command icxbench runs the AF_XDP forwarder over a real NIC with a STATIC-keyed
// handler (bypassing the QUIC control plane) so a single box can drive the
// datapath under load. It is a real-hardware benchmark harness — used to measure
// APO-670 (CPU pinning), APO-679 (keep-alive drain), and multi-tunnel fan-out
// (--tunnels: one forwarder serving N peer VTEPs) — not part of the production
// control/data plane.
//
// Encap-load direction: inject plaintext inner IP frames into --virt (a veth),
// the forwarder Seals each (AES-GCM) and transmits out --phy (the real NIC).
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
	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/forwarder"
	"github.com/apoxy-dev/icx/psp"
)

func main() {
	phy := flag.String("phy", "", "physical interface (real NIC) the forwarder binds for TX")
	virt := flag.String("virt", "", "virtual interface (veth) the forwarder binds for RX of inner frames")
	pin := flag.Bool("pin", true, "pin each per-queue goroutine to a distinct CPU (APO-670)")
	keepalive := flag.Duration("keepalive", 0, "keep-alive interval per VNI; 0 disables (APO-679)")
	localIP := flag.String("local-ip", "10.255.0.1", "outer underlay source IP")
	remoteIP := flag.String("remote-ip", "10.255.0.2", "outer underlay destination IP")
	localMAC := flag.String("local-mac", "", "outer Ethernet source MAC (own phy NIC); empty = synthetic")
	remoteMAC := flag.String("remote-mac", "", "outer Ethernet dest MAC (peer phy NIC); empty = synthetic")
	swapKeys := flag.Bool("swap-keys", false, "swap rx/tx keys (use on the peer/decap box so its rx matches our tx)")
	nQueues := flag.Int("queues", 0, "override per-queue socket count (0 = auto from NIC channels; cap for SR-IOV VFs)")
	srcPortHash := flag.Bool("source-port-hash", true, "vary outer UDP source port per inner flow so the peer's RSS spreads frames across all RX queues (required for a multi-queue pinning A/B)")
	busyPoll := flag.Int("busy-poll", 0, "AF_XDP socket busy-poll timeout in microseconds; >0 drives NAPI inline on the datapath core (DPDK-poll-mode style), 0 disables (APO-670 IRQ-collision fix)")
	busyPollBudget := flag.Int("busy-poll-budget", 64, "packets per busy-poll NAPI pass (SO_BUSY_POLL_BUDGET); only used when --busy-poll>0")
	layer3 := flag.Bool("layer3", false, "run the virt side as raw L3 IP (WithLayer3VirtFrames) to interop with a userspace vtep/tun peer (icxbench-tun); default is L2/Ethernet for AF_XDP<->AF_XDP")
	tunnels := flag.Int("tunnels", 1, "fan out to N independent peer VTEPs (1..16): tunnel i = VNI 0x1000+i, outer dst port 6081+i, inner /24 10.(i+1).0.0/24, distinct key. The XDP filter binds all N ports so one forwarder de/encaps for N userspace VTEPs sharing the peer host.")
	flag.Parse()

	if *phy == "" || *virt == "" {
		log.Fatal("--phy and --virt are required")
	}

	virtIf, err := net.InterfaceByName(*virt)
	if err != nil {
		log.Fatalf("virt interface %s: %v", *virt, err)
	}
	virtMAC := tcpip.LinkAddress(virtIf.HardwareAddr)

	// Outer Ethernet MACs. The handler writes remote.LinkAddr as the outer dst MAC
	// and local.LinkAddr as the outer src MAC (see ToPhyInPlace -> udp.Encode). For a
	// real two-box test set local=own phy MAC and remote=peer phy MAC (or, over an
	// L3-routed underlay, remote=next-hop/gateway MAC). Default to synthetic MACs.
	localLink := parseMACOr("local-mac", *localMAC, "\x02\x00\x00\x00\xff\x01")
	remoteLink := parseMACOr("remote-mac", *remoteMAC, "\x02\x00\x00\x00\xff\x02")

	local := &tcpip.FullAddress{
		Addr:     parseIPv4(*localIP),
		Port:     6081,
		LinkAddr: localLink,
	}

	hopts := []icx.HandlerOption{
		icx.WithLocalAddr(local),
	}
	if *layer3 {
		// Match a userspace vtep/tun peer: inner payload is a raw L3 IP packet, no
		// inner Ethernet. WithVirtMAC is meaningless here (no inner L2 to rewrite).
		hopts = append(hopts, icx.WithLayer3VirtFrames())
	} else {
		hopts = append(hopts, icx.WithVirtMAC(virtMAC))
	}
	if *srcPortHash {
		hopts = append(hopts, icx.WithSourcePortHashing())
	}
	if *keepalive > 0 {
		hopts = append(hopts, icx.WithKeepAliveInterval(*keepalive))
	}
	h, err := icx.NewHandler(hopts...)
	if err != nil {
		log.Fatalf("NewHandler: %v", err)
	}

	// Fan out to N independent peer VTEPs. Tunnel i: VNI 0x1000+i, outer dst port
	// 6081+i (so encapped return frames reach VTEP i's bound port), inner subnet
	// 10.(i+1).0.0/24 (so inner-dst routing demuxes the encap path back to tunnel
	// i), and a distinct per-tunnel key (last byte 'A'+i) — keeping every
	// (key, nonce) pair unique across tunnels even though all share epoch 1 and
	// count from 0. The server overlay answers each client at 10.(i+1).0.1.
	if *tunnels < 1 || *tunnels > 16 {
		log.Fatalf("--tunnels must be 1..16 (got %d)", *tunnels)
	}
	srcPrefix := netip.MustParsePrefix("10.0.0.0/8")
	expires := time.Now().Add(24 * time.Hour)
	binds := make([]net.Addr, 0, 2*(*tunnels))
	for i := 0; i < *tunnels; i++ {
		port := 6081 + i
		remote := &tcpip.FullAddress{
			Addr:     parseIPv4(*remoteIP),
			Port:     uint16(port),
			LinkAddr: remoteLink,
		}
		dstPrefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i + 1), 0, 0}), 24)
		routes := []icx.Route{{Src: srcPrefix, Dst: dstPrefix}}
		// Per-tunnel deterministic master secret: distinct last byte ('A'+i) keeps
		// every tunnel's derivation space unique even though all share epoch 1 —
		// required when N tunnels fan into one AF_XDP peer. The handler derives the
		// per-direction keys from (master, SPI); the peer/decap VTEP runs with
		// --swap-keys so its role mirrors ours and its rx SPI equals our tx SPI.
		var master [32]byte
		copy(master[:], []byte("icxbench-master-secret-000000000"))
		master[31] = byte('A' + i)
		role := psp.Initiator
		if *swapKeys {
			role = psp.Responder
		}
		rxSPI, txSPI, err := psp.EpochSPIs(role, 1)
		if err != nil {
			log.Fatalf("EpochSPIs: %v", err)
		}
		vni := uint(0x1000 + i)
		if err := h.AddVirtualNetwork(vni, remote, routes); err != nil {
			log.Fatalf("AddVirtualNetwork %d: %v", vni, err)
		}
		if err := h.UpdateVirtualNetworkSecret(vni, master, rxSPI, txSPI, expires); err != nil {
			log.Fatalf("UpdateVirtualNetworkSecret %d: %v", vni, err)
		}
		// Bind this tunnel's port (IPv4 wildcard) so the XDP ingress filter redirects
		// Geneve on dst port 6081+i to AF_XDP (the default filter binds only 6081). The
		// underlay is IPv4-only, so one bind per tunnel — MAX_BINDS=16 in the eBPF then
		// caps this at 16 tunnels.
		binds = append(binds, &net.UDPAddr{IP: net.IPv4zero, Port: port})
	}

	phyFilter, err := filter.Geneve(binds...)
	if err != nil {
		log.Fatalf("filter.Geneve: %v", err)
	}

	fwd, err := forwarder.NewForwarder(h,
		forwarder.WithPhyName(*phy),
		forwarder.WithVirtName(*virt),
		forwarder.WithCPUPinning(*pin),
		forwarder.WithNumQueues(*nQueues),
		forwarder.WithBusyPoll(*busyPoll, *busyPollBudget),
		forwarder.WithPhyFilter(phyFilter),
	)
	if err != nil {
		log.Fatalf("NewForwarder: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("icxbench: phy=%s virt=%s pin=%v busy-poll=%dus/%d keepalive=%v tunnels=%d pid=%d",
		*phy, *virt, *pin, *busyPoll, *busyPollBudget, *keepalive, *tunnels, os.Getpid())
	if err := fwd.Start(ctx); err != nil {
		log.Fatalf("forwarder.Start: %v", err)
	}
	log.Print("icxbench: stopped")
}

// parseMACOr parses flagVal as a MAC address (for CLI flag name, used only in the
// error message) or returns fallback — a raw 6-byte synthetic address — when the
// flag is empty.
func parseMACOr(name, flagVal, fallback string) tcpip.LinkAddress {
	if flagVal == "" {
		return tcpip.LinkAddress(fallback)
	}
	hw, err := net.ParseMAC(flagVal)
	if err != nil {
		log.Fatalf("%s %q: %v", name, flagVal, err)
	}
	return tcpip.LinkAddress(hw)
}

// parseIPv4 converts a dotted-quad string into a tcpip.Address; the outer underlay
// endpoints driven by this rig are always IPv4.
func parseIPv4(s string) tcpip.Address {
	return tcpip.AddrFrom4Slice(net.ParseIP(s).To4())
}
