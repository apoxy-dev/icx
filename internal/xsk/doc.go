//go:build linux

// Package xsk is an in-repo AF_XDP (XSK) socket implementation, written to
// replace github.com/slavc/xdp v0.3.4. It exists because the upstream binding
// has structural correctness defects that cannot be patched without a redesign,
// and because icx wants shared-UMEM zero-copy forwarding, which the upstream
// UMEM-per-socket model does not support.
//
// # Why a rewrite (vs forking slavc/xdp)
//
// icx uses only a thin slice of the upstream API: the Socket datapath
// (GetDescs/GetFrame/Fill/Receive/Transmit/Complete/Num*) from the forwarder,
// and xdp.Program purely as a struct of {*ebpf.Program, qidconf map, xsks map}
// with Attach/Detach/Register glue (filter.go builds it by hand from a cilium
// collection). The upstream NewProgram eBPF-asm program is unused. The defects
// that matter are all structural:
//
//   - ring producer/consumer indices accessed via plain (non-atomic) *uint32
//     dereferences of kernel-shared mmap memory, with every memory fence
//     commented out -> works by luck on x86-64 TSO, data corruption on ARM64,
//     and a compiler hoist/cache hazard on every architecture;
//   - UMEM owned per-socket + an RX/TX "half partition" freelist, which forces
//     a full per-frame copy between the phy and virt UMEMs and blocks zero-copy;
//   - Transmit panics the process on an unexpected sendto errno;
//   - Close never munmaps the four ring mappings (leak);
//   - GetFrame returns a slice whose cap runs to the end of the whole UMEM.
//
// Fixing the memory ordering and the UMEM model is a redesign of the exact
// pieces a fork would carry, so we rewrite.
//
// # Memory-ordering contract (the whole point)
//
// Each ring is single-producer/single-consumer with the KERNEL as the
// counterparty on the other end, running on a different CPU. The Go race
// detector cannot observe the kernel, so these accesses MUST be explicitly
// ordered. This package follows the libbpf xsk.h discipline exactly, using
// sync/atomic (which on Go gives acquire/release and also defeats compiler
// caching/hoisting, unlike re-enabling an arch-specific asm fence):
//
//   - producer reserve: load-ACQUIRE the consumer index to compute free space;
//   - producer submit:  write descriptors, THEN store-RELEASE the producer index;
//   - consumer peek:    load-ACQUIRE the producer index, THEN read descriptors;
//   - consumer release: read descriptors, THEN store-RELEASE the consumer index.
//
// See ring.go; this is the foundation everything else is built on.
//
// # Zero-copy model (shared UMEM)
//
// The forwarder splices frames between a physical and a virtual interface. With
// slavc/xdp each socket had its own UMEM, so every forwarded frame was copied
// between the two. Here a single UMEM (NewUMEM) is shared by both sockets
// (NewSocket(umem, ...)): a frame received on one socket's RX ring is placed
// directly onto the other socket's TX ring by handing over its descriptor — same
// UMEM addr, no copy — and reclaimed via that socket's COMPLETION ring back into
// the one shared free-frame pool. An in-place transform (e.g. Geneve decap)
// rewrites the frame within its own chunk and adjusts the descriptor.
//
// Cross-netdev XDP_SHARED_UMEM was validated empirically against the kernel: the
// UMEM is registered on an fd (regFD); the first socket reuses regFD and binds
// normally, and each later socket has its OWN FILL/COMPLETION/RX/TX rings and
// binds XDP_SHARED_UMEM + sxdp_shared_umem_fd = regFD, even on a different
// netdev/queue. (A dedicated never-bound UMEM fd does NOT work — the kernel
// requires the referenced fd to be already bound, returning EBADF otherwise.)
// So the rings live on Socket and the UMEM is shared memory + allocator + regFD.
//
// Note: this gives USERSPACE zero-copy (no memcpy between two UMEMs). The
// driver-level XDP_ZEROCOPY flag (NIC DMA straight to/from UMEM, no kernel copy)
// is independent, needs driver support, and is opt-in via Options.ZeroCopy; on
// veth (tests) it is unavailable and the kernel uses copy mode, which still
// benefits from the shared UMEM.
//
// # Status
//
// Linux-only. The ring atomics (ring.go), the allocator (umem.go), and the
// setup/bind wiring (setup_linux.go) are validated on a real aarch64 kernel by
// afxdp_linux_test.go (run via `dagger call test`): NewUMEM/NewSocket, the
// shared cross-device bind, Fill, and Transmit->Complete all pass. The RX path
// (an XDP redirect program — xsks_map — steering packets into a socket) is wired
// via the filter package and exercised end-to-end by the forwarder over veth
// (forwarder RX-headroom and crypto round-trip tests), which now runs entirely
// on this package.
package xsk
