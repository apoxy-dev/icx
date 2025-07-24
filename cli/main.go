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
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"

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
				Value:   0x1,
			},
			&cli.StringFlag{
				Name:     "rx-key",
				Usage:    "Ephemeral AES key for receiving (16-byte hex, DO NOT REUSE)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "tx-key",
				Usage:    "Ephemeral AES key for transmitting (16-byte hex, DO NOT REUSE)",
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
				// MTU - 40 (IPv6) - 8 (UDP) - 32 (Geneve+opts) - 16 (AES-GCM Tag)
				// Round down to the nearest AES block (16 bytes)
				// For IPv4 you can bump this up to 1424
				Value: 1404,
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
		defer func() {
			_ = f.Close()
		}()

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
		defer func() {
			_ = f.Close()
		}()

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

	addrs, err := addrsForInterface(link, c.Int("port"))
	if err != nil {
		return fmt.Errorf("failed to get addresses for interface %s: %w", phyName, err)
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

	ingressFilter, err := filter.Bind(addrs...)
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

	var rxKey, txKey [16]byte
	// Hex decode the keys provided by the user
	if len(c.String("rx-key")) != 32 || len(c.String("tx-key")) != 32 {
		return errors.New("keys must be 32 hexadecimal characters (16 bytes)")
	}
	if _, err := hex.Decode(rxKey[:], []byte(c.String("rx-key"))); err != nil {
		return fmt.Errorf("failed to decode rx-key: %w", err)
	}
	if _, err := hex.Decode(txKey[:], []byte(c.String("tx-key"))); err != nil {
		return fmt.Errorf("failed to decode tx-key: %w", err)
	}

	h, err := icx.NewHandler(localAddr, peerAddr, virtMAC, c.Uint("vni"), rxKey, txKey, c.Bool("source-port-hash"))
	if err != nil {
		return fmt.Errorf("failed to create handler: %w", err)
	}

	tun, err := tunnel.NewTunnel(phyName, vethDev.Peer.Attrs().Name, ingressFilter, h, pcapWriter)
	if err != nil {
		return fmt.Errorf("failed to create tunnel: %w", err)
	}

	if err := tun.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("failed to start tunnel: %w", err)
	}

	return nil
}

func addrsForInterface(link netlink.Link, port int) ([]net.Addr, error) {
	nlAddrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface: %w", err)
	}

	var addrs []net.Addr
	for _, addr := range nlAddrs {
		if addr.IP == nil {
			continue
		}
		addrs = append(addrs, &net.UDPAddr{
			IP:   addr.IP,
			Port: port,
		})
	}

	return addrs, nil
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
	defer func() {
		_ = conn.Close()
	}()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return &tcpip.FullAddress{
		Addr:     tcpip.AddrFromSlice(localAddr.IP),
		Port:     uint16(localAddr.Port),
		LinkAddr: tcpip.LinkAddress(link.Attrs().HardwareAddr),
	}, nil
}
