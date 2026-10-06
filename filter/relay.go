//go:build linux

package filter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// MaxRelayBurst is the largest meter burst in bytes. The program keeps the
// tokens of a meter in byte-ns, and a refill can add one more burst.
const MaxRelayBurst = math.MaxUint64 / uint64(time.Second) / 2

// RelayConfig sets the port, the link and the meters of a relay program.
type RelayConfig struct {
	// Port is the UDP port of the relay.
	Port uint16
	// MaxLen is the largest IP length of a PSP datagram. A longer datagram
	// passes to the kernel.
	MaxLen uint32
	// LaneRate meters each row and TunnelRate meters each tunnel, in bytes
	// per second. Zero turns the meter off. The bursts are in bytes.
	LaneRate, LaneBurst uint64
	// Each CPU takes the tokens of a tunnel in groups. A tunnel can thus pass
	// 1/4096 of TunnelBurst and one packet above the limit for each CPU.
	TunnelRate, TunnelBurst uint64
	// NextHopCache is the time that a row keeps the next hop of a route
	// lookup, so a route or neighbor change takes effect after this time at
	// most. Zero does a lookup for each packet.
	NextHopCache time.Duration
	// Redirect sends with a redirect to the same link and not with XDP_TX.
	// A driver that flushes each XDP_TX packet (ena) is faster with it.
	Redirect bool
}

// Relay is the XDP program of a PSP relay. It sends a PSP packet that
// matches a row (sender address and port, SPI) to the next hop of the row
// with XDP_TX, or with a redirect to the same link. It gives other packets to
// the kernel (XDP_PASS). Each row has a lane with its meter and counters,
// which a change to the row keeps.
type Relay struct {
	objs relayObjects
	link link.Link
	// laneMeter is true when the rows have a meter.
	laneMeter bool
	// laneFull and tunnelFull are the tokens of a full bucket, in byte-ns.
	laneFull, tunnelFull uint64

	mu    sync.Mutex
	free  []uint32 // Lanes of deleted rows, oldest first.
	lanes uint32   // Lanes given out so far.
	gen   uint32   // The gen of the last row with a new next hop.
}

// RelayRow is the next hop of a row and its limits.
type RelayRow struct {
	Next netip.AddrPort
	// Tunnel is the tunnel meter of the row, or 0 for none.
	Tunnel uint32
	// Expires is the CLOCK_MONOTONIC time after which the row passes its
	// packets to the kernel.
	Expires time.Duration
}

// RelayCounters are the counters of a row.
type RelayCounters struct {
	Packets, Bytes, Drops uint64
	// Used is the CLOCK_MONOTONIC time of the last forward, or 0.
	Used time.Duration
}

// RelayStats are the counters of all CPUs. Bytes count UDP payload bytes.
type RelayStats struct {
	Packets, Bytes         uint64 // Forwarded.
	LaneDrops, TunnelDrops uint64 // Dropped by a meter.
	// Given to the kernel.
	NoRow, Expired, NoRoute, Malformed, TooLong uint64
}

// NewRelay loads a relay program. It does not attach it. The program forwards
// only after SetAddrs.
func NewRelay(cfg RelayConfig) (*Relay, error) {
	if cfg.MaxLen == 0 {
		return nil, errors.New("max len is 0")
	}
	spec, err := loadRelay()
	if err != nil {
		return nil, fmt.Errorf("failed to load relay program spec: %w", err)
	}
	laneFill, err := fill(cfg.LaneRate, cfg.LaneBurst)
	if err != nil {
		return nil, fmt.Errorf("lane meter: %w", err)
	}
	tunnelFill, err := fill(cfg.TunnelRate, cfg.TunnelBurst)
	if err != nil {
		return nil, fmt.Errorf("tunnel meter: %w", err)
	}
	var redirect uint32
	if cfg.Redirect {
		redirect = 1
	}
	vars := map[string]any{
		"relay_port":   be16(cfg.Port),
		"max_len":      cfg.MaxLen,
		"lane_rate":    cfg.LaneRate,
		"lane_burst":   cfg.LaneBurst,
		"lane_fill":    laneFill,
		"tunnel_rate":  cfg.TunnelRate,
		"tunnel_burst": cfg.TunnelBurst,
		"tunnel_fill":  tunnelFill,
		"hop_time":     uint64(max(cfg.NextHopCache, 0)),
		"redirect":     redirect,
	}
	for name, v := range vars {
		vs, ok := spec.Variables[name]
		if !ok {
			return nil, fmt.Errorf("relay program has no variable %s", name)
		}
		if err := vs.Set(v); err != nil {
			return nil, fmt.Errorf("failed to set %s: %w", name, err)
		}
	}
	r := &Relay{laneMeter: cfg.LaneRate > 0}
	// A new bucket must be full. With zero tokens the program fills it for
	// the time since the host started, which is short on a new host.
	if cfg.LaneRate > 0 {
		r.laneFull = cfg.LaneBurst * uint64(time.Second)
	}
	if cfg.TunnelRate > 0 {
		r.tunnelFull = cfg.TunnelBurst * uint64(time.Second)
	}
	if !r.laneMeter {
		// The program does not read the lane meters.
		spec.Maps["relay_meters"].MaxEntries = 1
	}
	if err := spec.LoadAndAssign(&r.objs, nil); err != nil {
		return nil, fmt.Errorf("failed to load relay program: %w", err)
	}
	return r, nil
}

// fill returns the time in ns that fills an empty bucket.
func fill(rate, burst uint64) (uint64, error) {
	if rate == 0 {
		return 0, nil
	}
	if burst == 0 || burst > MaxRelayBurst {
		return 0, fmt.Errorf("burst %d is not from 1 to %d", burst, MaxRelayBurst)
	}
	return uint64(math.Ceil(float64(burst) * float64(time.Second) / float64(rate))), nil
}

// Program returns the XDP program, for Program.Chain.
func (r *Relay) Program() *ebpf.Program { return r.objs.RelayForward }

// Attach attaches the program to the interface ifindex in mode, which is
// link.XDPDriverMode or link.XDPGenericMode. The program detaches when r
// closes or the process exits.
func (r *Relay) Attach(ifindex int, mode link.XDPAttachFlags) error {
	if r.link != nil {
		return errors.New("relay program is already attached")
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: r.objs.RelayForward, Interface: ifindex, Flags: mode})
	if err != nil {
		return err
	}
	r.link = l
	return nil
}

// Close detaches the program and frees it and its maps.
func (r *Relay) Close() error {
	var errs []error
	if r.link != nil {
		errs = append(errs, r.link.Close())
		r.link = nil
	}
	errs = append(errs, r.objs.Close())
	return errors.Join(errs...)
}

// SetAddrs sets the addresses of the relay on the link. The program forwards
// only packets to one of them, as the relay socket gets only those.
func (r *Relay) SetAddrs(addrs []netip.Addr) error {
	n := r.objs.RelayAddrs.MaxEntries()
	if len(addrs) > int(n) {
		return fmt.Errorf("%d addresses is more than %d", len(addrs), n)
	}
	for i := range n {
		var v relayRelayAddr
		if int(i) < len(addrs) {
			v.Addr = addrs[i].As16()
		}
		if err := r.objs.RelayAddrs.Put(i, v); err != nil {
			return err
		}
	}
	return nil
}

// PutRow adds or changes the row of sender and spi. A change keeps the
// meter and the counters of the row.
func (r *Relay) PutRow(sender netip.AddrPort, spi uint32, row RelayRow) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := rowKey(sender, spi)
	var v relayRelayRow
	err := r.objs.RelayRows.Lookup(&k, &v)
	added := errors.Is(err, ebpf.ErrKeyNotExist)
	if err != nil && !added {
		return err
	}
	if added {
		if v.Lane, err = r.newLane(); err != nil {
			return err
		}
	}
	next, port := row.Next.Addr().As16(), be16(row.Next.Port())
	if added || v.Next != next || v.NextPort != port {
		// A lane keeps a next hop only for the gen of its lookup.
		r.gen++
		v.Gen = r.gen
	}
	v.Tunnel = row.Tunnel
	v.Next, v.NextPort = next, port
	v.Expires = uint64(max(row.Expires, 0))
	if err := r.objs.RelayRows.Update(&k, &v, ebpf.UpdateAny); err != nil {
		if added {
			r.free = append(r.free, v.Lane)
		}
		return err
	}
	return nil
}

// newLane returns a lane with a full meter and zero counters. The caller
// holds r.mu.
func (r *Relay) newLane() (uint32, error) {
	var lane uint32
	switch {
	case len(r.free) > 0:
		lane, r.free = r.free[0], r.free[1:]
	case r.lanes < r.objs.RelayLanes.MaxEntries():
		lane, r.lanes = r.lanes, r.lanes+1
	default:
		return 0, errors.New("all lanes are in use")
	}
	err := r.objs.RelayLanes.Update(lane, relayRelayLane{}, ebpf.UpdateAny)
	if err == nil && r.laneMeter {
		err = r.objs.RelayMeters.Update(lane, relayRelayMeter{Tokens: r.laneFull}, ebpf.UpdateLock)
	}
	if err != nil {
		r.free = append(r.free, lane)
		return 0, err
	}
	return lane, nil
}

// DeleteRow removes the row of sender and spi and returns its counters.
func (r *Relay) DeleteRow(sender netip.AddrPort, spi uint32) (RelayCounters, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := rowKey(sender, spi)
	var v relayRelayRow
	if err := r.objs.RelayRows.Lookup(&k, &v); err != nil {
		return RelayCounters{}, err
	}
	if err := r.objs.RelayRows.Delete(&k); err != nil {
		return RelayCounters{}, err
	}
	c, err := r.lane(v.Lane)
	r.free = append(r.free, v.Lane)
	return c, err
}

// Counters returns the counters of the row of sender and spi.
func (r *Relay) Counters(sender netip.AddrPort, spi uint32) (RelayCounters, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := rowKey(sender, spi)
	var v relayRelayRow
	if err := r.objs.RelayRows.Lookup(&k, &v); err != nil {
		return RelayCounters{}, err
	}
	return r.lane(v.Lane)
}

// lane returns the counters of a lane.
func (r *Relay) lane(lane uint32) (RelayCounters, error) {
	var v relayRelayLane
	if err := r.objs.RelayLanes.Lookup(lane, &v); err != nil {
		return RelayCounters{}, err
	}
	c := RelayCounters{Packets: v.Packets, Bytes: v.Bytes, Used: time.Duration(v.Used)}
	if r.laneMeter {
		var m relayRelayMeter
		if err := r.objs.RelayMeters.LookupWithFlags(lane, &m, ebpf.LookupLock); err != nil {
			return RelayCounters{}, err
		}
		c.Drops = m.Drops
	}
	return c, nil
}

// PutTunnel adds the tunnel meter id with a full bucket.
func (r *Relay) PutTunnel(id uint32) error {
	if err := r.objs.RelayTunnels.Update(id, relayRelayMeter{Tokens: r.tunnelFull}, ebpf.UpdateAny); err != nil {
		return err
	}
	// The program finds a tunnel by its shares, so the bucket comes first.
	// An empty slice gives each CPU a zero share.
	if err := r.objs.RelayShares.Update(id, []relayRelayShare{}, ebpf.UpdateAny); err != nil {
		_ = r.objs.RelayTunnels.Delete(id)
		return err
	}
	return nil
}

// DeleteTunnel removes the tunnel meter id and returns its drops.
func (r *Relay) DeleteTunnel(id uint32) (uint64, error) {
	drops, err := r.TunnelDrops(id)
	if err != nil {
		return 0, err
	}
	if err := r.objs.RelayShares.Delete(id); err != nil {
		return 0, err
	}
	return drops, r.objs.RelayTunnels.Delete(id)
}

// TunnelDrops returns the drops of the tunnel meter id on all CPUs.
func (r *Relay) TunnelDrops(id uint32) (uint64, error) {
	var shares []relayRelayShare
	if err := r.objs.RelayShares.Lookup(id, &shares); err != nil {
		return 0, err
	}
	var drops uint64
	for _, s := range shares {
		drops += s.Drops
	}
	return drops, nil
}

// Stats returns the sum of the counters of all CPUs.
func (r *Relay) Stats() (RelayStats, error) {
	var cpus []relayRelayStats
	if err := r.objs.RelayCpuStats.Lookup(uint32(0), &cpus); err != nil {
		return RelayStats{}, err
	}
	var s RelayStats
	for _, c := range cpus {
		s.Packets += c.Packets
		s.Bytes += c.Bytes
		s.LaneDrops += c.LaneDrops
		s.TunnelDrops += c.TunnelDrops
		s.NoRow += c.NoRow
		s.Expired += c.Expired
		s.NoRoute += c.NoRoute
		s.Malformed += c.Malformed
		s.TooLong += c.TooLong
	}
	return s, nil
}

// Monotonic returns the CLOCK_MONOTONIC time, the clock of the program.
func Monotonic() time.Duration {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return time.Duration(ts.Nano())
}

func rowKey(sender netip.AddrPort, spi uint32) relayRelayKey {
	return relayRelayKey{Addr: sender.Addr().As16(), Port: be16(sender.Port()), Spi: be32(spi)}
}

// be16 and be32 return v with its bytes in network order in memory.
func be16(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func be32(v uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return binary.NativeEndian.Uint32(b[:])
}
