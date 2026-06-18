//go:build linux

package xsk

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// AF_XDP/XSK syscall + mmap + bind wiring, validated on a real Linux kernel by
// the integration tests in afxdp_linux_test.go (run via `dagger call test`,
// which runs the suite in a privileged container on a real kernel — and in CI on
// both amd64 and arm64, the latter being the weak-memory arch the old slavc/xdp
// failed on).
//
// Model (libbpf, confirmed empirically): the UMEM is registered on an AF_XDP fd
// (regFD). The FIRST Socket reuses regFD and binds normally; every later Socket
// gets its own fd and binds XDP_SHARED_UMEM + sxdp_shared_umem_fd = regFD. The
// kernel rejects a shared bind against an fd that is not itself already bound
// (EBADF) — which is why a dedicated never-bound UMEM fd does NOT work, and the
// registration fd must become the first real socket. Each Socket has its own
// FILL/COMP/RX/TX rings (required when sharing a UMEM across netdevs/queues), so
// the rings live on Socket and stay lock-free (single goroutine per socket).
//
// CRITICAL ORDERING (else bind() == EINVAL): on each socket fd, all four ring
// SIZE setsockopts (FILL, COMPLETION, RX, TX) must precede
// getsockopt(XDP_MMAP_OFFSETS) and every ring mmap, which precede bind.

func setsockoptUmemReg(fd int, r *unix.XDPUmemReg) error {
	if _, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(unix.SOL_XDP), uintptr(unix.XDP_UMEM_REG),
		uintptr(unsafe.Pointer(r)), unsafe.Sizeof(*r), 0); e != 0 {
		return fmt.Errorf("xsk: setsockopt XDP_UMEM_REG: %w", e)
	}
	return nil
}

func getOffsets(fd int) (unix.XDPMmapOffsets, error) {
	var off unix.XDPMmapOffsets
	vallen := uint32(unsafe.Sizeof(off))
	if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(unix.SOL_XDP), uintptr(unix.XDP_MMAP_OFFSETS),
		uintptr(unsafe.Pointer(&off)), uintptr(unsafe.Pointer(&vallen)), 0); e != 0 {
		return off, fmt.Errorf("xsk: getsockopt XDP_MMAP_OFFSETS: %w", e)
	}
	return off, nil
}

// wireRing builds a ring over an mmap'd region using the kernel-supplied
// offsets. Producer/consumer/flags are pointers into kernel-shared memory and
// are only ever touched through sync/atomic in ring.go.
func wireRing(base []byte, off unix.XDPRingOffset, nDescs uint32, wantFlags bool) ring {
	p := unsafe.Pointer(&base[0])
	r := ring{
		producer: (*uint32)(unsafe.Add(p, off.Producer)),
		consumer: (*uint32)(unsafe.Add(p, off.Consumer)),
		desc:     unsafe.Add(p, off.Desc),
		mask:     nDescs - 1,
		size:     nDescs,
	}
	if wantFlags {
		r.flags = (*uint32)(unsafe.Add(p, off.Flags))
	}
	r.cachedProducer = atomic.LoadUint32(r.producer)
	r.cachedConsumer = atomic.LoadUint32(r.consumer)
	return r
}

// mmapRing maps one ring at the given page offset and wires it. elemSize is 8
// for FILL/COMPLETION (uint64 addrs) and sizeof(Desc) for RX/TX.
func mmapRing(fd int, pgoff int64, off unix.XDPRingOffset, nDescs uint32, elemSize uintptr, wantFlags bool) ([]byte, ring, error) {
	length := int(off.Desc + uint64(nDescs)*uint64(elemSize))
	b, err := unix.Mmap(fd, pgoff, length,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return nil, ring{}, err
	}
	return b, wireRing(b, off, nDescs, wantFlags), nil
}

// NewUMEM allocates the shared frame area and registers it on an AF_XDP fd
// (regFD), also setting that fd's FILL/COMPLETION ring sizes (libbpf order: REG,
// then FILL, then COMP). regFD is NOT bound here — the first NewSocket on this
// UMEM reuses it and binds it (see NewSocket), so its FILL/COMPLETION rings are
// the ones whose sizes are set here. Sockets created with NewSocket(umem, ...)
// share this frame pool; Close the UMEM only after all its sockets are closed.
func NewUMEM(opts Options) (*UMEM, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("xsk: socket(AF_XDP) for UMEM: %w", err)
	}
	u := &UMEM{frameSize: uint64(opts.FrameSize), numFrames: uint32(opts.NumFrames), regFD: fd}
	ok := false
	defer func() {
		if !ok {
			_ = u.Close()
		}
	}()

	u.mem, err = unix.Mmap(-1, 0, opts.NumFrames*opts.FrameSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("xsk: mmap UMEM frame area: %w", err)
	}

	reg := unix.XDPUmemReg{
		Addr: uint64(uintptr(unsafe.Pointer(&u.mem[0]))),
		Len:  uint64(len(u.mem)),
		Size: uint32(opts.FrameSize),
	}
	if err = setsockoptUmemReg(fd, &reg); err != nil {
		return nil, err
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, opts.FillRingNumDescs); err != nil {
		return nil, fmt.Errorf("xsk: setsockopt XDP_UMEM_FILL_RING (umem fd): %w", err)
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, opts.CompletionRingNumDescs); err != nil {
		return nil, fmt.Errorf("xsk: setsockopt XDP_UMEM_COMPLETION_RING (umem fd): %w", err)
	}

	u.free = make([]uint32, opts.NumFrames)
	for i := range u.free {
		u.free[i] = uint32(i)
	}

	ok = true
	return u, nil
}

// NewSocket binds a socket on (ifindex, queueID) sharing umem's frame pool and
// returns it. The returned Socket does not own the UMEM; Close it before
// umem.Close().
//
// Shared-UMEM model (libbpf): the FIRST socket on a UMEM reuses the UMEM
// registration fd and binds NORMALLY; every later socket gets its own fd and
// binds XDP_SHARED_UMEM referencing the registration fd. The kernel rejects a
// shared bind whose referenced fd is not itself already bound (EBADF), so the
// registration fd must become a real bound socket — the first one. Each socket
// (first or later) has its OWN FILL/COMPLETION/RX/TX rings, which is required
// when sharing a UMEM across different netdevs/queues (the forwarder's case).
//
// For zero-copy forwarding, create one UMEM and bind both the phy and virt
// sockets to it: a frame received on one can be transmitted on the other with no
// copy.
func NewSocket(umem *UMEM, ifindex, queueID int, opts Options) (*Socket, error) {
	if umem == nil {
		return nil, fmt.Errorf("xsk: NewSocket requires a non-nil UMEM")
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}

	// The first socket reuses the UMEM registration fd (already carrying
	// XDP_UMEM_REG + the FILL/COMPLETION ring sizes from NewUMEM) and binds
	// normally; later sockets get their own fd and bind shared against regFD.
	first := umem.claimFirst()
	var fd int
	var err error
	if first {
		fd = umem.regFD
	} else {
		fd, err = unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
		if err != nil {
			umem.unclaimFirst() // never consumed regFD; let a retry reuse it
			return nil, fmt.Errorf("xsk: socket(AF_XDP): %w", err)
		}
	}
	s := &Socket{fd: fd, ifindex: ifindex, queueID: queueID, umem: umem, opts: opts, sharesUMEMFD: first}
	ok := false
	defer func() {
		if !ok {
			_ = s.Close() // munmaps rings; closes fd only when !sharesUMEMFD
			if first {
				umem.unclaimFirst()
			}
		}
	}()

	// All four ring sizes must be set BEFORE XDP_MMAP_OFFSETS/mmap/bind on this
	// fd (else bind == EINVAL). The first socket's FILL/COMPLETION sizes were
	// already set on regFD by NewUMEM; later sockets set their own here. Each
	// socket has its own FILL/COMPLETION rings (required across netdevs/queues).
	if !first {
		if err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, opts.FillRingNumDescs); err != nil {
			return nil, fmt.Errorf("xsk: setsockopt XDP_UMEM_FILL_RING: %w", err)
		}
		if err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, opts.CompletionRingNumDescs); err != nil {
			return nil, fmt.Errorf("xsk: setsockopt XDP_UMEM_COMPLETION_RING: %w", err)
		}
	}
	if opts.RxRingNumDescs > 0 {
		if err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_RX_RING, opts.RxRingNumDescs); err != nil {
			return nil, fmt.Errorf("xsk: setsockopt XDP_RX_RING: %w", err)
		}
	}
	if opts.TxRingNumDescs > 0 {
		if err = unix.SetsockoptInt(fd, unix.SOL_XDP, unix.XDP_TX_RING, opts.TxRingNumDescs); err != nil {
			return nil, fmt.Errorf("xsk: setsockopt XDP_TX_RING: %w", err)
		}
	}

	off, err := getOffsets(fd)
	if err != nil {
		return nil, err
	}
	wantFlags := opts.UseNeedWakeup
	descSize := unsafe.Sizeof(Desc{})

	s.fillMmap, s.fillRing, err = mmapRing(fd, unix.XDP_UMEM_PGOFF_FILL_RING,
		off.Fr, uint32(opts.FillRingNumDescs), 8, wantFlags)
	if err != nil {
		return nil, fmt.Errorf("xsk: mmap FILL ring: %w", err)
	}
	s.compMmap, s.compRing, err = mmapRing(fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		off.Cr, uint32(opts.CompletionRingNumDescs), 8, wantFlags)
	if err != nil {
		return nil, fmt.Errorf("xsk: mmap COMPLETION ring: %w", err)
	}
	if opts.RxRingNumDescs > 0 {
		s.rxMmap, s.rxRing, err = mmapRing(fd, unix.XDP_PGOFF_RX_RING,
			off.Rx, uint32(opts.RxRingNumDescs), descSize, wantFlags)
		if err != nil {
			return nil, fmt.Errorf("xsk: mmap RX ring: %w", err)
		}
	}
	if opts.TxRingNumDescs > 0 {
		s.txMmap, s.txRing, err = mmapRing(fd, unix.XDP_PGOFF_TX_RING,
			off.Tx, uint32(opts.TxRingNumDescs), descSize, wantFlags)
		if err != nil {
			return nil, fmt.Errorf("xsk: mmap TX ring: %w", err)
		}
	}

	sa := &unix.SockaddrXDP{
		Flags:   bindFlags(opts),
		Ifindex: uint32(ifindex),
		QueueID: uint32(queueID),
	}
	if !first {
		// Reference the already-bound registration fd (the first socket bound
		// it). The kernel requires the referenced fd to be bound, else EBADF.
		sa.Flags |= unix.XDP_SHARED_UMEM
		sa.SharedUmemFD = uint32(umem.regFD)
	}
	if err = unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("xsk: bind ifindex=%d queue=%d shared=%v: %w", ifindex, queueID, !first, err)
	}

	if err = applyBusyPoll(fd, opts); err != nil {
		return nil, err
	}

	ok = true
	return s, nil
}

// applyBusyPoll enables socket busy polling on fd when opts.BusyPoll > 0. With
// busy poll, a poll()/recvmsg() on this socket drives the bound netdev's NAPI
// inline on the calling core (the AF_XDP analogue of a DPDK poll-mode driver)
// instead of waiting for the NIC IRQ's RX softirq to run on its own core, which
// removes the IRQ-core contention a pinned datapath thread otherwise hits
// (APO-670). It is a no-op when busy poll is disabled, so the default datapath is
// untouched.
//
// Requires Linux >= 5.11: SO_PREFER_BUSY_POLL/SO_BUSY_POLL_BUDGET do not exist on
// older kernels and the setsockopt fails ENOPROTOOPT — which fails NewSocket,
// because the caller explicitly asked for a feature the kernel lacks rather than
// silently getting a non-busy-polled socket. The per-netdev
// napi_defer_hard_irqs/gro_flush_timeout knobs that make the hard-IRQ deferral
// actually engage are the caller's responsibility (the forwarder sets them).
func applyBusyPoll(fd int, opts Options) error {
	if opts.BusyPoll <= 0 {
		return nil
	}
	// Order per the kernel's Documentation/networking/af_xdp.rst busy-poll
	// example: prefer-busy-poll first, then the busy-poll timeout, then the
	// per-pass budget.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PREFER_BUSY_POLL, 1); err != nil {
		return fmt.Errorf("xsk: setsockopt SO_PREFER_BUSY_POLL (busy poll needs kernel >= 5.11): %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BUSY_POLL, opts.BusyPoll); err != nil {
		return fmt.Errorf("xsk: setsockopt SO_BUSY_POLL=%d: %w", opts.BusyPoll, err)
	}
	budget := opts.BusyPollBudget
	if budget <= 0 {
		budget = DefaultBusyPollBudget
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BUSY_POLL_BUDGET, budget); err != nil {
		return fmt.Errorf("xsk: setsockopt SO_BUSY_POLL_BUDGET=%d: %w", budget, err)
	}
	return nil
}

func bindFlags(opts Options) uint16 {
	// Default to letting the kernel choose the driver mode (like libbpf). Forcing
	// XDP_COPY unconditionally makes bind return EINVAL on some setups (veth).
	// XDP_ZEROCOPY is the driver-level DMA-to-UMEM mode (needs NIC support) and
	// is independent of the shared-UMEM userspace zero-copy this package gives.
	var f uint16
	if opts.UseNeedWakeup {
		f |= unix.XDP_USE_NEED_WAKEUP
	}
	if opts.ZeroCopy {
		f |= unix.XDP_ZEROCOPY
	}
	if opts.ForceCopy {
		f |= unix.XDP_COPY
	}
	return f
}
