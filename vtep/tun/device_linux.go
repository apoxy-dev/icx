//go:build linux

package tun

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/apoxy-dev/icx/vtep"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// tunDeviceOffset is the read/write headroom the wireguard TUN device requires.
// CreateTUN opens the device with IFF_VNET_HDR, so Write must leave at least
// virtioNetHdrLen (10) bytes before the packet for the device to prepend the
// virtio-net header in place. 16 (matching wireguard/device.MessageTransportHeaderSize)
// is the conventional value and keeps the packet word-aligned.
const tunDeviceOffset = 16

// OpenConfig configures Open. Engine, Name and UnderlayBind are required.
type OpenConfig struct {
	// Engine is the ICX engine; it must be configured in layer3 mode.
	Engine vtep.EngineXfrm
	// Name is the TUN interface name to create (e.g. "icx0"). An empty name lets
	// the kernel pick one.
	Name string
	// OverlayAddrs are the L3 addresses assigned to the TUN device (the overlay
	// CIDRs the consumer's stack owns).
	OverlayAddrs []netip.Prefix
	// Routes are the overlay prefixes routed out the TUN device (link-scoped).
	Routes []netip.Prefix
	// InnerMTU is the device MTU / inner-MTU clamp; 0 uses defaultInnerMTU (1280).
	InnerMTU int
	// UnderlayBind is the local UDP address the underlay socket binds to.
	UnderlayBind netip.AddrPort
	// FlushInterval overrides the keep-alive flush cadence; 0 uses the default.
	FlushInterval time.Duration
}

// Open creates a /dev/net/tun overlay device and a UDP underlay socket, wires
// them to the engine, configures the device's MTU/addresses/routes, and returns
// a ready-to-Run Datapath that OWNS both (Close tears them down). It requires
// NET_ADMIN and access to /dev/net/tun.
func Open(cfg OpenConfig) (*Datapath, error) {
	if cfg.Engine == nil {
		return nil, fmt.Errorf("tun datapath: engine is required")
	}
	mtu := cfg.InnerMTU
	if mtu <= 0 {
		mtu = defaultInnerMTU
	}

	dev, err := wgtun.CreateTUN(cfg.Name, mtu)
	if err != nil {
		return nil, fmt.Errorf("tun datapath: create TUN %q: %w", cfg.Name, err)
	}

	// Disable kernel GSO/GRO offload on the device so each Read returns a single
	// <= MTU packet (no virtio super-frames the read buffers would have to be
	// sized for) and each single-packet Write emits a plain GSO_NONE frame. The
	// device keeps IFF_VNET_HDR, so the fixed tunDeviceOffset headroom is still
	// required on Read/Write.
	f := dev.File()
	if f == nil {
		// Without the fd we cannot disable offload, and proceeding with GSO/GRO
		// enabled risks the kernel handing back super-frames the read buffers are
		// not sized for (black-holing traffic). Fail loudly instead.
		_ = dev.Close()
		return nil, fmt.Errorf("tun datapath: device exposes no file descriptor; cannot disable offload")
	}
	if err := unix.IoctlSetInt(int(f.Fd()), unix.TUNSETOFFLOAD, 0); err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("tun datapath: disable offload: %w", err)
	}

	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("tun datapath: device name: %w", err)
	}

	if err := configureLink(name, mtu, cfg.OverlayAddrs, cfg.Routes); err != nil {
		_ = dev.Close()
		return nil, err
	}

	uc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(cfg.UnderlayBind))
	if err != nil {
		_ = dev.Close()
		return nil, fmt.Errorf("tun datapath: bind underlay %s: %w", cfg.UnderlayBind, err)
	}
	uu, err := newUDPUnderlay(uc)
	if err != nil {
		_ = uc.Close()
		_ = dev.Close()
		return nil, err
	}

	dp, err := New(Config{
		Engine:        cfg.Engine,
		Device:        dev,
		Underlay:      uu,
		DeviceOffset:  tunDeviceOffset,
		InnerMTU:      mtu,
		FlushInterval: cfg.FlushInterval,
	})
	if err != nil {
		_ = uu.Close()
		_ = dev.Close()
		return nil, err
	}
	return dp, nil
}

// configureLink assigns the MTU, addresses and link-scoped routes to the TUN
// device and brings it up. Mirrors the apoxy-cli NetlinkRouter setup.
func configureLink(name string, mtu int, addrs, routes []netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("tun datapath: link %q: %w", name, err)
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("tun datapath: set MTU on %q: %w", name, err)
	}
	for _, p := range addrs {
		// An interface address keeps its host bits (e.g. 10.0.0.5/24), so use the
		// address as given, not the masked network.
		ipnet := &net.IPNet{
			IP:   net.IP(p.Addr().AsSlice()),
			Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
		}
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
			return fmt.Errorf("tun datapath: add addr %s to %q: %w", p, name, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("tun datapath: bring up %q: %w", name, err)
	}
	for _, p := range routes {
		// A route destination is a network, so mask off any host bits.
		m := p.Masked()
		dst := &net.IPNet{
			IP:   net.IP(m.Addr().AsSlice()),
			Mask: net.CIDRMask(m.Bits(), m.Addr().BitLen()),
		}
		r := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Scope:     netlink.SCOPE_LINK,
		}
		// RouteReplace (not RouteAdd) for idempotency: assigning an OverlayAddr
		// already auto-installs the connected route for its prefix, and a reconciler
		// may re-run Open, so RouteAdd's EEXIST on an already-present route would
		// spuriously fail. Replace ensures the prefix points at our TUN either way.
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("tun datapath: add route %s via %q: %w", p, name, err)
		}
	}
	return nil
}
