//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/fips140"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/urfave/cli/v2"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/control"
	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/forwarder"
	"github.com/apoxy-dev/icx/mac"
	"github.com/apoxy-dev/icx/permissions"
	"github.com/apoxy-dev/icx/queues"
	"github.com/apoxy-dev/icx/veth"
)

func main() {
	app := &cli.App{
		Name:  "icx",
		Usage: "InterCloud eXpress — an AF_XDP Geneve L3 tunnel",
		Commands: []*cli.Command{
			genkeyCommand(),
			pubkeyCommand(),
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "Set the logging level (debug, info, warn, error, fatal, panic)",
				Value:   "info",
			},
			// NOTE: --interface is intentionally NOT marked Required. urfave/cli
			// enforces required root flags before dispatching to a subcommand, which
			// would make `icx genkey`/`icx pubkey` unrunnable. It is validated inside
			// run() instead.
			&cli.StringFlag{
				Name:    "interface",
				Aliases: []string{"i"},
				Usage:   "Physical network interface to use (required for the tunnel)",
			},
			&cli.UintFlag{
				Name:    "vni",
				Aliases: []string{"v"},
				Usage:   "Virtual Network Identifier (VNI) for the tunnel (24-bit value)",
				Value:   1,
			},
			&cli.StringFlag{
				Name:  "identity-key",
				Usage: "Path to this node's identity private key (PKCS#8 PEM from `icx genkey`). Enables the control plane",
			},
			&cli.StringFlag{
				Name:  "peer-key",
				Usage: "Peer's identity public key (base64 SPKI from `icx pubkey`, or a path to a file containing it). Enables the control plane",
			},
			&cli.IntFlag{
				Name:  "control-port",
				Usage: "UDP port for the QUIC/mTLS control plane (must match on both peers)",
				Value: 6082,
			},
			&cli.IntFlag{
				Name:  "peer-control-port",
				Usage: "Peer's control-plane UDP port (defaults to --control-port)",
			},
			&cli.DurationFlag{
				Name:  "rekey-interval",
				Usage: "How often the control plane negotiates a fresh security association",
				Value: 2 * time.Minute,
			},
			&cli.BoolFlag{
				Name:  "require-fips",
				Usage: "Refuse to start unless the Go FIPS 140-3 module is active (GODEBUG=fips140=on)",
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "Port to listen on",
				Value:   6081,
			},
			&cli.StringFlag{
				Name:    "tun-device",
				Aliases: []string{"t"},
				Usage:   "Name of the tunnel interface to create",
				Value:   "icx0",
			},
			&cli.IntFlag{
				Name:    "tun-mtu",
				Aliases: []string{"m"},
				Usage:   "MTU to use for the tunnel interface",
				Value:   icx.MTU(1500),
			},
			&cli.BoolFlag{
				Name:  "source-port-hash",
				Usage: "Source port hashing (you will need to disable this if you are behind a NAT)",
				Value: true,
			},
			&cli.StringFlag{
				Name:  "cpu-profile",
				Usage: "Path to write optional CPU profiling output",
			},
			&cli.StringFlag{
				Name:  "mem-profile",
				Usage: "Path to write optional memory profiling output",
			},
			&cli.StringFlag{
				Name:  "pcap-file",
				Usage: "Path to write optional packet capture output",
			},
		},
		ArgsUsage: "<peer-ip:port>",
		Action:    run,
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("Error running app", slog.Any("error", err))
		os.Exit(1)
	}
}

// genkeyCommand generates a fresh ECDSA P-256 identity private key.
func genkeyCommand() *cli.Command {
	return &cli.Command{
		Name:  "genkey",
		Usage: "Generate a new ECDSA P-256 identity private key (PKCS#8 PEM)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "identity-key",
				Aliases: []string{"o"},
				Usage:   "Path to write the private key (default: stdout)",
			},
			&cli.BoolFlag{
				Name:  "force",
				Usage: "Overwrite an existing key file",
			},
		},
		Action: func(c *cli.Context) error {
			id, err := control.GenerateIdentity()
			if err != nil {
				return err
			}
			pemBytes, err := id.MarshalPrivatePEM()
			if err != nil {
				return err
			}

			path := c.String("identity-key")
			if path == "" {
				_, err = os.Stdout.Write(pemBytes)
				return err
			}

			// Refuse to clobber an existing private key unless explicitly forced.
			flags := os.O_CREATE | os.O_EXCL | os.O_WRONLY
			if c.Bool("force") {
				flags = os.O_CREATE | os.O_TRUNC | os.O_WRONLY
			}
			f, err := os.OpenFile(path, flags, 0o600)
			if err != nil {
				return fmt.Errorf("create identity key %q (use --force to overwrite): %w", path, err)
			}
			defer func() { _ = f.Close() }()
			if _, err := f.Write(pemBytes); err != nil {
				return err
			}
			pub, err := id.PublicKeyString()
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote identity key to %s\npublic key (share as the peer's --peer-key):\n%s\n", path, pub)
			return nil
		},
	}
}

// pubkeyCommand derives the base64(SPKI) public key from an identity private key.
func pubkeyCommand() *cli.Command {
	return &cli.Command{
		Name:  "pubkey",
		Usage: "Print the public key (base64 SPKI) for an identity private key (from --identity-key or stdin)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "identity-key",
				Aliases: []string{"i"},
				Usage:   "Path to the identity private key (default: read PEM from stdin)",
			},
		},
		Action: func(c *cli.Context) error {
			var (
				data []byte
				err  error
			)
			if path := c.String("identity-key"); path != "" {
				data, err = os.ReadFile(path)
			} else {
				data, err = io.ReadAll(os.Stdin)
			}
			if err != nil {
				return err
			}
			id, err := control.LoadIdentityPEM(data)
			if err != nil {
				return err
			}
			pub, err := id.PublicKeyString()
			if err != nil {
				return err
			}
			fmt.Println(pub)
			return nil
		},
	}
}

func run(c *cli.Context) error {
	if c.NArg() != 1 {
		return errors.New("peer address is required")
	}

	logLevel := c.String("log-level")
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToLower(logLevel))); err != nil {
		return fmt.Errorf("invalid log level %q: %w", logLevel, err)
	}
	slog.SetLogLoggerLevel(level)

	// The control plane is the only keying mode: require both halves of the pinned
	// identity pair up front, fail-closed. There is deliberately no static/INI fallback.
	if c.String("identity-key") == "" || c.String("peer-key") == "" {
		return errors.New("control-plane keying requires both --identity-key and --peer-key (generate them with `icx genkey` / `icx pubkey`)")
	}

	if c.String("interface") == "" {
		return errors.New("--interface is required")
	}
	if c.Bool("require-fips") && !fips140.Enabled() {
		return errors.New("--require-fips set but the Go FIPS 140-3 module is not active; build and run with GODEBUG=fips140=on")
	}

	if cpuProfilePath := c.String("cpu-profile"); cpuProfilePath != "" {
		f, err := os.Create(cpuProfilePath)
		if err != nil {
			return fmt.Errorf("failed to create CPU profile file: %w", err)
		}
		defer func() { _ = f.Close() }()

		if err := pprof.StartCPUProfile(f); err != nil {
			return fmt.Errorf("failed to start CPU profiling: %w", err)
		}
		defer pprof.StopCPUProfile()
	}

	if memProfilePath := c.String("mem-profile"); memProfilePath != "" {
		f, err := os.Create(memProfilePath)
		if err != nil {
			return fmt.Errorf("failed to create memory profile file: %w", err)
		}
		defer func() {
			if err := pprof.WriteHeapProfile(f); err != nil {
				slog.Error("failed to write memory profile", slog.Any("error", err))
			}
			_ = f.Close()
		}()
	}

	var pcapWriter *pcapgo.Writer
	if pcapPath := c.String("pcap-file"); pcapPath != "" {
		f, err := os.Create(pcapPath)
		if err != nil {
			return fmt.Errorf("failed to create pcap file: %w", err)
		}
		defer func() { _ = f.Close() }()

		pcapWriter = pcapgo.NewWriter(f)
		if err := pcapWriter.WriteFileHeader(uint32(math.MaxUint16), layers.LinkTypeEthernet); err != nil {
			return fmt.Errorf("failed to write PCAP header: %w", err)
		}
	}

	// SIGINT for interactive use, SIGTERM for systemd/container stop. (os.Kill /
	// SIGKILL cannot be caught, so registering it would be a no-op.)
	ctx, cancel := signal.NotifyContext(c.Context, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	isNetAdmin, err := permissions.IsNetAdmin()
	if err != nil {
		return fmt.Errorf("failed to check NET_ADMIN capability: %w", err)
	}
	if !isNetAdmin {
		return errors.New("this command requires the NET_ADMIN capability")
	}

	phyName := c.String("interface")
	link, err := netlink.LinkByName(phyName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", phyName, err)
	}

	numQueues, err := queues.NumQueues(link)
	if err != nil {
		return fmt.Errorf("failed to get number of TX queues for interface %s: %w", phyName, err)
	}

	peerUDPAddr, err := net.ResolveUDPAddr("udp", c.Args().Get(0))
	if err != nil {
		return fmt.Errorf("failed to resolve peer address: %w", err)
	}

	peerAddr := &tcpip.FullAddress{Port: uint16(peerUDPAddr.Port)}
	if ip := peerUDPAddr.IP.To4(); ip != nil {
		peerAddr.Addr = tcpip.AddrFrom4Slice(ip)
	} else if ip := peerUDPAddr.IP.To16(); ip != nil {
		peerAddr.Addr = tcpip.AddrFrom16Slice(ip)
	}

	localAddr, err := selectSourceAddr(link, peerAddr)
	if err != nil {
		return fmt.Errorf("failed to select source address: %w", err)
	}

	peerAddr.LinkAddr, err = mac.Resolve(ctx, link, localAddr, peerAddr.Addr)
	if err != nil {
		return fmt.Errorf("failed to resolve peer MAC address: %w", err)
	}

	port := c.Int("port")
	ingressFilter, err := filter.Geneve(&net.UDPAddr{
		IP:   net.IPv4zero,
		Port: port,
	},
		&net.UDPAddr{
			IP:   net.IPv6zero,
			Port: port,
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create ingress filter: %w", err)
	}

	virtName := c.String("tun-device")
	virtMTU := c.Int("tun-mtu")

	vethDev, err := veth.Create(virtName, numQueues, virtMTU)
	if err != nil {
		return fmt.Errorf("failed to create veth device: %w", err)
	}
	defer func() {
		if err := vethDev.Close(); err != nil {
			slog.Error("Failed to close veth device", slog.Any("error", err))
		}
	}()

	virtMAC := tcpip.LinkAddress(vethDev.Link.Attrs().HardwareAddr)

	opts := []icx.HandlerOption{
		icx.WithLocalAddr(localAddr),
		icx.WithVirtMAC(virtMAC),
		icx.WithKeepAliveInterval(25 * time.Second),
	}
	if c.Bool("source-port-hash") {
		opts = append(opts, icx.WithSourcePortHashing())
	}

	h, err := icx.NewHandler(opts...)
	if err != nil {
		return fmt.Errorf("failed to create handler: %w", err)
	}

	allRoutes := []icx.Route{
		{Src: netip.MustParsePrefix("0.0.0.0/0"), Dst: netip.MustParsePrefix("0.0.0.0/0")},
		{Src: netip.MustParsePrefix("::/0"), Dst: netip.MustParsePrefix("::/0")},
	}

	vni := c.Uint("vni")
	if err := h.AddVirtualNetwork(vni, peerAddr, allRoutes); err != nil {
		return fmt.Errorf("failed to add virtual network: %w", err)
	}

	// Establish the QUIC/mTLS control plane: install the initial SAs and drive ongoing
	// rekeys. This is the only keying path.
	tun, ctrlConn, err := startControlPlane(ctx, c, h, vni, peerUDPAddr)
	if err != nil {
		return err
	}
	defer func() { _ = tun.Close() }()
	// The Tunnel only borrows the control socket; own its lifetime here.
	defer func() { _ = ctrlConn.Close() }()

	fwd, err := forwarder.NewForwarder(
		h,
		forwarder.WithPhyName(phyName),
		forwarder.WithVirtName(vethDev.Peer.Attrs().Name),
		forwarder.WithPhyFilter(ingressFilter),
		forwarder.WithPcapWriter(pcapWriter),
	)
	if err != nil {
		return fmt.Errorf("failed to create forwarder: %w", err)
	}

	// Run the rekey loop and the forwarder under one errgroup sharing a cancel: a signal
	// (ctx) or a forwarder error stops both. The control plane reconnects indefinitely on
	// its own (Tunnel.Run does not return on CP failures), so it does not abort the
	// forwarder; if it cannot re-establish, the data plane fails closed when the installed
	// keys expire (see key lifetime below).
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return tun.Run(gctx) })
	g.Go(func() error {
		if err := fwd.Start(gctx); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("forwarder: %w", err)
		}
		return nil
	})
	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// startControlPlane builds the QUIC/mTLS control-plane tunnel and performs the
// initial, fail-closed SA negotiation and install. The returned Tunnel's Run drives
// ongoing rekeys; the caller is responsible for running it and closing the Tunnel.
func startControlPlane(ctx context.Context, c *cli.Context, h *icx.Handler, vni uint, peerUDPAddr *net.UDPAddr) (*control.Tunnel, *net.UDPConn, error) {
	controlPort := c.Int("control-port")
	if controlPort == c.Int("port") {
		return nil, nil, errors.New("--control-port must differ from the Geneve data port (--port); the XDP filter redirects the data port to AF_XDP and would blackhole the control plane")
	}

	ident, err := loadIdentity(c.String("identity-key"))
	if err != nil {
		return nil, nil, err
	}
	peerPub, err := readPeerKey(c.String("peer-key"))
	if err != nil {
		return nil, nil, err
	}

	ctrlNet := "udp4"
	if peerUDPAddr.IP.To4() == nil {
		ctrlNet = "udp6"
	}
	pconn, err := net.ListenUDP(ctrlNet, &net.UDPAddr{Port: controlPort})
	if err != nil {
		return nil, nil, fmt.Errorf("bind control socket on port %d: %w", controlPort, err)
	}

	peerControlPort := c.Int("peer-control-port")
	if peerControlPort == 0 {
		peerControlPort = controlPort
	}
	peerControlAddr := &net.UDPAddr{IP: peerUDPAddr.IP, Port: peerControlPort}

	rekeyIvl := c.Duration("rekey-interval")
	// Bound the installed-key lifetime: long enough that a few missed rekeys do not
	// drop traffic, short enough to fail closed if rotation stops, capped at the
	// handler's recommended 24h rekey ceiling.
	keyLifetime := 4 * rekeyIvl
	if keyLifetime < time.Hour {
		keyLifetime = time.Hour
	}
	if keyLifetime > 24*time.Hour {
		keyLifetime = 24 * time.Hour
	}

	installer := func(rxSPI, txSPI uint32, rxKey, txKey [16]byte) error {
		return h.UpdateVirtualNetworkSAs(vni, rxSPI, txSPI, rxKey, txKey, time.Now().Add(keyLifetime))
	}

	tun, err := control.NewTunnel(control.TunnelConfig{
		Local:         ident,
		PeerPub:       peerPub,
		Conn:          pconn,
		PeerAddr:      peerControlAddr,
		RekeyInterval: rekeyIvl,
	}, installer)
	if err != nil {
		_ = pconn.Close()
		return nil, nil, err
	}

	slog.Info("establishing control plane",
		slog.String("peer-control", peerControlAddr.String()),
		slog.Bool("initiator", tun.Initiator()),
		slog.Duration("rekey-interval", rekeyIvl),
	)
	if err := tun.Bringup(ctx); err != nil {
		_ = tun.Close()
		_ = pconn.Close()
		return nil, nil, fmt.Errorf("control plane bring-up failed: %w", err)
	}
	return tun, pconn, nil
}

// loadIdentity reads and parses this node's identity private key from a PEM file.
func loadIdentity(path string) (*control.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity key %q: %w", path, err)
	}
	return control.LoadIdentityPEM(data)
}

// readPeerKey resolves a --peer-key value, which may be the base64(SPKI) string
// directly or a path to a file containing it.
func readPeerKey(val string) (*ecdsa.PublicKey, error) {
	s := strings.TrimSpace(val)
	if data, err := os.ReadFile(val); err == nil {
		s = strings.TrimSpace(string(data))
	}
	return control.ParsePublicKey(s)
}

func selectSourceAddr(link netlink.Link, dstAddr *tcpip.FullAddress) (*tcpip.FullAddress, error) {
	var network string
	ip := net.IP(dstAddr.Addr.AsSlice())

	if ip.To4() != nil {
		network = "udp4"
	} else {
		network = "udp6"
	}

	conn, err := net.DialUDP(network, nil, &net.UDPAddr{
		IP:   ip,
		Port: int(dstAddr.Port),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to determine best source address for %s: %w", ip.String(), err)
	}
	defer func() { _ = conn.Close() }()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return &tcpip.FullAddress{
		Addr:     tcpip.AddrFromSlice(localAddr.IP),
		Port:     uint16(localAddr.Port),
		LinkAddr: tcpip.LinkAddress(link.Attrs().HardwareAddr),
	}, nil
}
