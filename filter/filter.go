//go:build linux

package filter

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/slavc/xdp"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go all ebpf/all.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bind ebpf/bind.c

// All creates an eBPF program that intercepts all incoming packets
// and redirects them to the XDP socket.
func All() (*xdp.Program, error) {
	spec, err := loadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF program: %w", err)
	}

	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	return &xdp.Program{
		Program: col.Programs["xdp_sock_prog"],
		Queues:  col.Maps["qidconf_map"],
		Sockets: col.Maps["xsks_map"],
	}, nil
}

// Bind creates an eBPF program that binds to the specified addresses.
// It supports both TCP and UDP addresses, including IPv4 and IPv6.
func Bind(addrs ...net.Addr) (*xdp.Program, error) {
	spec, err := loadBind()
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF program: %w", err)
	}

	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	bindMap := col.Maps["bind_map"]

	for _, addr := range addrs {
		var bk bindBindKey
		switch addr := addr.(type) {
		case *net.TCPAddr:
			bk.Proto = unix.IPPROTO_TCP
			if addr.IP.To4() != nil {
				bk.Family = unix.AF_INET
				bk.Addr[0] = binary.BigEndian.Uint32(addr.IP.To4())
			} else {
				bk.Family = unix.AF_INET6
				ip := addr.IP.To16()
				for i := 0; i < 4; i++ {
					bk.Addr[i] = binary.BigEndian.Uint32(ip[i*4 : (i+1)*4])
				}
			}
			bk.Port = uint16(addr.Port)
		case *net.UDPAddr:
			bk.Proto = unix.IPPROTO_UDP
			if addr.IP.To4() != nil {
				bk.Family = unix.AF_INET
				bk.Addr[0] = binary.BigEndian.Uint32(addr.IP.To4())
			} else {
				bk.Family = unix.AF_INET6
				ip := addr.IP.To16()
				for i := 0; i < 4; i++ {
					bk.Addr[i] = binary.BigEndian.Uint32(ip[i*4 : (i+1)*4])
				}
			}
			bk.Port = uint16(addr.Port)
		default:
			return nil, fmt.Errorf("unsupported address type: %T", addr)
		}

		if err := bindMap.Update(bk, uint32(1), ebpf.UpdateAny); err != nil {
			col.Close()
			return nil, fmt.Errorf("failed to update bind map: %w", err)
		}
	}

	return &xdp.Program{
		Program: col.Programs["xdp_sock_prog"],
		Queues:  col.Maps["qidconf_map"],
		Sockets: col.Maps["xsks_map"],
	}, nil
}
