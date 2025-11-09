//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/urfave/cli/v2"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"
	"github.com/apoxy-dev/icx/filter"
	"github.com/apoxy-dev/icx/mac"
	"github.com/apoxy-dev/icx/permissions"
	"github.com/apoxy-dev/icx/tunnel"
	"github.com/apoxy-dev/icx/veth"

	ini "gopkg.in/ini.v1"
)

func main() {
	app := &cli.App{
		Name: "icx",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Usage:   "Set the logging level (debug, info, warn, error, fatal, panic)",
				Value:   "info",
			},
			&cli.StringFlag{
				Name:     "interface",
				Aliases:  []string{"i"},
				Usage:    "Physical network interface to use",
				Required: true,
			},
			&cli.UintFlag{
				Name:    "vni",
				Aliases: []string{"v"},
				Usage:   "Virtual Network Identifier (VNI) for the tunnel (24-bit value)",
				Value:   1,
			},
			&cli.StringFlag{
				Name:     "key-file",
				Usage:    "Path to INI file containing keys (rx, tx, optional expires)",
				Required: true,
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

	ctx, cancel := signal.NotifyContext(c.Context, os.Interrupt, os.Kill)
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

	numQueues, err := tunnel.NumQueues(link)
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

	allRoutes := []icx.AllowedRoute{
		{Src: netip.MustParsePrefix("0.0.0.0/0"), Dst: netip.MustParsePrefix("0.0.0.0/0")},
		{Src: netip.MustParsePrefix("::/0"), Dst: netip.MustParsePrefix("::/0")},
	}

	if err := h.AddVirtualNetwork(c.Uint("vni"), peerAddr, allRoutes); err != nil {
		return fmt.Errorf("failed to add virtual network: %w", err)
	}

	var (
		epoch        uint32 = 1 // initial epoch
		rxKey, txKey [16]byte
		expiresAt    time.Time
	)

	keyFile := c.String("key-file")
	rxKey, txKey, expiresAt, err = loadKeysFromINI(keyFile)
	if err != nil {
		return err
	}

	if err := h.UpdateVirtualNetworkKeys(c.Uint("vni"), epoch, rxKey, txKey, expiresAt); err != nil {
		return fmt.Errorf("failed to update virtual network key: %w", err)
	}

	var keyMu sync.Mutex
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	// SIGHUP reload handler.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				newRX, newTX, newExpires, loadErr := loadKeysFromINI(keyFile)
				if loadErr != nil {
					slog.Error("Key reload failed", slog.Any("error", loadErr))
					continue
				}

				keyMu.Lock()
				// Refuse reload if keys are identical to current ones.
				if rxKey == newRX && txKey == newTX {
					slog.Warn("Refusing key reload: rx/tx unchanged; keeping current epoch",
						slog.Uint64("epoch", uint64(epoch)),
					)
					keyMu.Unlock()
					continue
				}

				// Keys changed: commit and bump epoch.
				rxKey = newRX
				txKey = newTX
				expiresAt = newExpires
				epoch++

				if err := h.UpdateVirtualNetworkKeys(c.Uint("vni"), epoch, rxKey, txKey, expiresAt); err != nil {
					slog.Error("Failed to apply reloaded keys", slog.Any("error", err))
				} else {
					slog.Info("Reloaded keys",
						slog.Uint64("epoch", uint64(epoch)),
						slog.Time("expiresAt", expiresAt),
					)
				}
				keyMu.Unlock()
			}
		}
	}()

	tun, err := tunnel.NewTunnel(
		h,
		tunnel.WithPhyName(phyName),
		tunnel.WithVirtName(vethDev.Peer.Attrs().Name),
		tunnel.WithPhyFilter(ingressFilter),
		tunnel.WithPcapWriter(pcapWriter),
	)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}

	if err := tun.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("failed to start tunnel: %w", err)
	}

	return nil
}

// loadKeysFromINI loads rx/tx (hex, 16-byte each) and optional expires from an INI file.
//
// Required layout:
//
//	[keys]
//	rx=0123... (32 hex chars -> 16 bytes)
//	tx=abcd... (32 hex chars -> 16 bytes)
//	expires=24h            // OR RFC3339 like 2025-10-16T12:34:56Z
//
// "expires" may be either a Go duration (e.g., "24h", "90m") or RFC3339 timestamp.
// If omitted, a default of 24h from now is applied.
func loadKeysFromINI(path string) (rxKey, txKey [16]byte, expiresAt time.Time, err error) {
	cfg, err := ini.Load(path)
	if err != nil {
		return rxKey, txKey, time.Time{}, fmt.Errorf("open INI: %w", err)
	}

	sec, err := cfg.GetSection("keys")
	if err != nil {
		return rxKey, txKey, time.Time{}, errors.New("INI must contain a [keys] section")
	}

	get := func(k string) string { return strings.TrimSpace(sec.Key(k).String()) }

	rxHex := get("rx")
	txHex := get("tx")
	expStr := get("expires")

	if rxHex == "" || txHex == "" {
		return rxKey, txKey, time.Time{}, errors.New("INI [keys] missing required keys: rx and tx")
	}
	if len(rxHex) != 32 || len(txHex) != 32 {
		return rxKey, txKey, time.Time{}, errors.New("INI [keys] rx/tx must be 32 hex characters (16 bytes)")
	}

	rxBytes, err := hex.DecodeString(rxHex)
	if err != nil {
		return rxKey, txKey, time.Time{}, fmt.Errorf("decode INI [keys].rx: %w", err)
	}
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return rxKey, txKey, time.Time{}, fmt.Errorf("decode INI [keys].tx: %w", err)
	}
	copy(rxKey[:], rxBytes)
	copy(txKey[:], txBytes)

	// Expiry handling: optional; default to 24h if absent.
	if expStr != "" {
		// Prefer duration, fall back to RFC3339.
		if d, derr := time.ParseDuration(expStr); derr == nil {
			expiresAt = time.Now().Add(d)
		} else if t, terr := time.Parse(time.RFC3339, expStr); terr == nil {
			expiresAt = t
		} else {
			return rxKey, txKey, time.Time{}, fmt.Errorf("expires must be duration (e.g. 24h) or RFC3339 timestamp: %q", expStr)
		}
	} else {
		expiresAt = time.Now().Add(24 * time.Hour)
	}

	return rxKey, txKey, expiresAt, nil
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
