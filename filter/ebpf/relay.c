/* SPDX-License-Identifier: GPL-2.0 */

/* relay_forward sends PSP packets on to the next hop of their row, with
 * XDP_TX or a redirect. A row is keyed on the sender address, the sender port
 * and the SPI. Packets that it cannot forward go to the kernel (XDP_PASS). */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define AF_INET6 10
#define NSEC 1000000000ULL
/* The TTL and hop limit of a forward. It is the Linux default, which the
 * relay socket also sends with. */
#define FWD_TTL 64
/* The most addresses of the relay on the link. */
#define RELAY_ADDRS 32

/* PSP v0 and v1 tunnel mode with a VC in clear, as the Go relay reads it. */
#define PSP_OVERHEAD 40
#define PSP_NEXT_V4 4
#define PSP_NEXT_V6 41
#define PSP_EXT_LEN 2
#define PSP_CRYPT_OFF 2

/* A CPU takes the tokens of a tunnel in groups of 1/4096 of the burst, or of
 * one packet if that is more. */
#define SHARE_SHIFT 12

/* The loader sets these. The port is in network byte order. max_len is the
 * largest IP length of a PSP datagram. A rate is in bytes per second, a burst
 * is in bytes, and a fill is the time in ns that fills an empty bucket. A zero
 * rate turns the meter off. */
volatile const __be16 relay_port = 0;
volatile const __u32 max_len = 0;
volatile const __u64 lane_rate = 0;
volatile const __u64 lane_burst = 0;
volatile const __u64 lane_fill = 0;
volatile const __u64 tunnel_rate = 0;
volatile const __u64 tunnel_burst = 0;
volatile const __u64 tunnel_fill = 0;
/* hop_time is the time in ns that a lane keeps its next hop; zero does a
 * lookup for each packet. redirect sends with a redirect to the same link. */
volatile const __u64 hop_time = 0;
volatile const __u32 redirect = 0;

struct relay_key {
	__u8 addr[16]; /* IPv4 is ::ffff:a.b.c.d. */
	__be16 port;
	__u16 pad;
	__be32 spi;
};

/* The next hop of a row. Only the loader writes it. */
struct relay_row {
	__u32 tunnel; /* Key in relay_tunnels, or 0 for no tunnel limit. */
	__u32 lane;   /* Key in relay_lanes and relay_meters. */
	__u8 next[16];
	__be16 next_port;
	__u16 pad;
	__u32 gen;     /* The loader changes it with each new next hop. */
	__u64 expires; /* CLOCK_MONOTONIC ns. */
};

/* The counters and the next hop of a row. Only the program writes them. A
 * lane is one cache line. */
struct relay_lane {
	__u64 used;
	__u64 packets;
	__u64 bytes;
	__u64 hop_until; /* The next hop is good before this time. */
	__u8 hop_mac[2 * ETH_ALEN]; /* The destination, then the source. */
	__u32 hop_gen;   /* The gen of the row at the lookup. */
	__be32 hop_flow; /* The TOS or the flow info of the lookup. */
	__u32 hop_link;  /* The link of the lookup. */
	__u16 hop_mtu;
	__u8 hop_slot;   /* The relay address of the lookup. */
	__u8 pad[5];
};

/* A token bucket. Only the program writes it. */
struct relay_meter {
	struct bpf_spin_lock lock;
	__u32 pad;
	__u64 tokens; /* In byte-ns. */
	__u64 last;
	__u64 drops; /* Of a lane meter. A tunnel counts its drops in its shares. */
};

/* The tokens that one CPU took from the bucket of a tunnel and did not use,
 * and the drops of the tunnel on that CPU. */
struct relay_share {
	__u64 tokens; /* In bytes. */
	__u64 drops;
};

/* An address of the relay. IPv4 is ::ffff:a.b.c.d. */
struct relay_addr {
	__u8 addr[16];
} __attribute__((aligned(8)));

struct relay_stats {
	__u64 packets;
	__u64 bytes;
	__u64 lane_drops;
	__u64 tunnel_drops;
	__u64 no_row;
	__u64 expired;
	__u64 no_route;
	__u64 malformed;
	__u64 too_long;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct relay_key);
	__type(value, struct relay_row);
} relay_rows SEC(".maps");

/* The lanes of the rows. The loader gives each row a lane. The map can be
 * mapped, so its values start on a page and each lane is one cache line. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_MMAPABLE);
	__type(key, __u32);
	__type(value, struct relay_lane);
} relay_lanes SEC(".maps");

/* The lane meters, by lane. The loader makes the map small when the lane
 * meter is off. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct relay_meter);
} relay_meters SEC(".maps");

/* The buckets of the tunnel limits, by tunnel. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct relay_meter);
} relay_tunnels SEC(".maps");

/* The share of each CPU in a tunnel limit, by tunnel. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct relay_share);
} relay_shares SEC(".maps");

/* The addresses of the relay on the link. An all-zero entry ends the list. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, RELAY_ADDRS);
	__type(key, __u32);
	__type(value, struct relay_addr);
} relay_addrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct relay_stats);
} relay_cpu_stats SEC(".maps");

/* What lookup finds for a packet that the program can forward. */
struct relay_fwd {
	struct relay_row *row;
	struct relay_lane *lane;
	struct relay_stats *st;
	__u64 now;  /* The CLOCK_MONOTONIC time. */
	__u64 size; /* UDP payload bytes. */
	__u32 slot; /* The place of the destination in relay_addrs. */
	__u32 link; /* The link of the packet. */
	__u32 tot;  /* The IP length. */
};

/* meter_fill returns the tokens of a bucket at the time now. The tokens are
 * in byte-ns, so a refill needs no division. */
static __always_inline __u64 meter_fill(__u64 tokens, __u64 last, __u64 now,
					__u64 rate, __u64 full, __u64 fill)
{
	__u64 elapsed = now > last ? now - last : 0;

	if (elapsed >= fill)
		return full;
	tokens += elapsed * rate;
	return tokens > full ? full : tokens;
}

static __always_inline __u16 csum_fold(__u32 s)
{
	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return (__u16)s;
}

/* csum_replace returns the checksum check after the n 16-bit words old
 * change to new. */
static __always_inline __u16 csum_replace(__u16 check, const __u16 *old,
					  const __u16 *new, int n)
{
	__u32 s = (__u16)~check;

#pragma unroll
	for (int i = 0; i < n; i++) {
		s += (__u16)~old[i];
		s += new[i];
	}
	return ~csum_fold(s);
}

/* psp_spi returns the SPI of a PSP packet that the Go relay accepts, in
 * network byte order, or 0. */
static __always_inline __be32 psp_spi(const __u8 *p)
{
	__u8 ver = (p[3] >> 2) & 0x0f;
	__be32 spi = *(const __be32 *)(p + 4);

	if (p[0] != PSP_NEXT_V4 && p[0] != PSP_NEXT_V6)
		return 0;
	if (p[1] != PSP_EXT_LEN || (p[2] & 0x3f) != PSP_CRYPT_OFF)
		return 0;
	if ((p[3] & 0x03) != 0x03 || (p[3] & 0x40) || ver > 1)
		return 0;
	if (!(spi & bpf_htonl(0x7fffffff)))
		return 0;
	return spi;
}

/* relay_slot returns the place of dst in relay_addrs, or -1 if dst is not an
 * address of the relay. */
static __always_inline int relay_slot(const struct relay_addr *dst)
{
	const __u64 *d = (const __u64 *)dst->addr;

#pragma unroll
	for (int i = 0; i < RELAY_ADDRS; i++) {
		__u32 slot = i;
		struct relay_addr *a = bpf_map_lookup_elem(&relay_addrs, &slot);
		const __u64 *w;

		if (!a)
			return -1;
		w = (const __u64 *)a->addr;
		if (w[0] == d[0] && w[1] == d[1])
			return i;
		if (!w[0] && !w[1])
			return -1;
	}
	return -1;
}

/* meter takes size bytes from a token bucket. It returns 0 when the bucket
 * does not have them. */
static __always_inline int meter(struct relay_meter *m, __u64 size, __u64 rate,
				 __u64 burst, __u64 fill)
{
	__u64 now = bpf_ktime_get_ns(), full = burst * NSEC;
	__u64 last = m->last, t = m->tokens;
	int ok;

	size *= NSEC;
	/* A bucket that is empty drops with no lock, so the CPUs do not wait
	 * for each other in a flood. Only a CPU with the lock passes. */
	if (meter_fill(t, last, now, rate, full, fill) < size)
		return 0;
	bpf_spin_lock(&m->lock);
	t = meter_fill(m->tokens, m->last, now, rate, full, fill);
	/* A CPU that waited for the lock has an old time. The time must not go
	 * back, or the bucket gets the tokens of that time again. */
	if (now > m->last)
		m->last = now;
	ok = t >= size;
	if (ok)
		t -= size;
	m->tokens = t;
	bpf_spin_unlock(&m->lock);
	return ok;
}

/* share_take takes size bytes from the share of this CPU in the tunnel id.
 * An empty share takes a group of tokens from the bucket of the tunnel, so
 * the CPUs do not write to the bucket for each packet. */
static __always_inline int share_take(struct relay_share *s, __u32 id, __u64 size)
{
	__u64 group = tunnel_burst >> SHARE_SHIFT;
	struct relay_meter *m;

	if (s->tokens >= size) {
		s->tokens -= size;
		return 1;
	}
	m = bpf_map_lookup_elem(&relay_tunnels, &id);
	/* The loader removes the shares before the bucket. */
	if (!m)
		return 1;
	if (group < size)
		group = size;
	if (!meter(m, group, tunnel_rate, tunnel_burst, tunnel_fill))
		return 0;
	s->tokens += group - size;
	return 1;
}

/* meters runs the lane meter of the row and the tunnel limit of its tunnel.
 * It returns 0 when a meter drops the packet. */
static __always_inline int meters(const struct relay_fwd *f)
{
	if (lane_rate) {
		__u32 id = f->row->lane;
		struct relay_meter *m = bpf_map_lookup_elem(&relay_meters, &id);

		if (m && !meter(m, f->size, lane_rate, lane_burst, lane_fill)) {
			__sync_fetch_and_add(&m->drops, 1);
			f->st->lane_drops++;
			return 0;
		}
	}
	if (tunnel_rate && f->row->tunnel) {
		__u32 id = f->row->tunnel;
		struct relay_share *s = bpf_map_lookup_elem(&relay_shares, &id);

		if (s && !share_take(s, id, f->size)) {
			s->drops++;
			f->st->tunnel_drops++;
			return 0;
		}
	}
	return 1;
}

/* send counts the forward and returns the action that sends the packet. */
static __always_inline int send(const struct relay_fwd *f)
{
	__sync_fetch_and_add(&f->lane->packets, 1);
	__sync_fetch_and_add(&f->lane->bytes, f->size);
	f->lane->used = f->now;
	f->st->packets++;
	f->st->bytes += f->size;
	if (redirect)
		return bpf_redirect(f->link, 0);
	return XDP_TX;
}

/* hop_ok reports whether the lane has the next hop of the packet. flow is
 * the flow word of the packet. */
static __always_inline int hop_ok(const struct relay_fwd *f, __be32 flow)
{
	const struct relay_lane *lane = f->lane;

	return f->now < lane->hop_until && lane->hop_gen == f->row->gen &&
	       lane->hop_slot == f->slot && lane->hop_link == f->link &&
	       lane->hop_flow == flow && f->tot <= lane->hop_mtu;
}

/* hop_save keeps the next hop of a lookup in the lane. An old kernel gives
 * the length of the packet for the MTU, so a longer packet gets a lookup. */
static __always_inline void hop_save(const struct relay_fwd *f, __be32 flow,
				     const struct bpf_fib_lookup *fib)
{
	struct relay_lane *lane = f->lane;

	lane->hop_until = 0;
	__builtin_memcpy(lane->hop_mac, fib->dmac, ETH_ALEN);
	__builtin_memcpy(lane->hop_mac + ETH_ALEN, fib->smac, ETH_ALEN);
	lane->hop_gen = f->row->gen;
	lane->hop_flow = flow;
	lane->hop_link = f->link;
	lane->hop_slot = f->slot;
	lane->hop_mtu = fib->mtu_result;
	lane->hop_until = f->now + hop_time;
}

/* set_macs writes the MAC addresses of a packet: of the lane when the lane
 * keeps the next hop, and of the lookup when it does not. */
static __always_inline void set_macs(struct ethhdr *eth, const struct relay_fwd *f,
				     const struct bpf_fib_lookup *fib)
{
	if (hop_time) {
		const __u32 *m = (const __u32 *)f->lane->hop_mac;
		__u32 *e = (__u32 *)eth;

		e[0] = m[0];
		e[1] = m[1];
		e[2] = m[2];
		return;
	}
	__builtin_memcpy(eth->h_dest, fib->dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib->smac, ETH_ALEN);
}

static __always_inline int forward4(struct xdp_md *ctx, struct ethhdr *eth,
				    struct iphdr *iph, struct udphdr *udp,
				    struct relay_fwd *f)
{
	struct relay_row *row = f->row;
	struct bpf_fib_lookup fib;
	__be32 next = *(__be32 *)&row->next[12];
	/* Routing does not read the ECN bits. */
	__be32 flow = iph->tos & 0xfc;
	__u16 old[3], new[3];

	if (*(__u32 *)&row->next[8] != bpf_htonl(0xffff)) {
		f->st->no_route++;
		return XDP_PASS;
	}
	if (!hop_time || !hop_ok(f, flow)) {
		__builtin_memset(&fib, 0, sizeof(fib));
		fib.family = AF_INET;
		fib.tos = iph->tos;
		fib.l4_protocol = IPPROTO_UDP;
		fib.sport = relay_port;
		fib.dport = row->next_port;
		fib.tot_len = f->tot;
		fib.ifindex = f->link;
		fib.ipv4_src = iph->daddr;
		fib.ipv4_dst = next;
		if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS ||
		    fib.ifindex != f->link) {
			f->st->no_route++;
			return XDP_PASS;
		}
		if (hop_time)
			hop_save(f, flow, &fib);
	}
	if (!meters(f))
		return XDP_DROP;

	/* The source moves to the old destination, so only the old source
	 * leaves the sums. */
	__builtin_memcpy(old, &iph->saddr, 4);
	__builtin_memcpy(new, &next, 4);
	old[2] = *(__u16 *)&iph->ttl;
	iph->ttl = FWD_TTL;
	new[2] = *(__u16 *)&iph->ttl;
	iph->check = csum_replace(iph->check, old, new, 3);
	if (udp->check) {
		old[2] = udp->source;
		new[2] = row->next_port;
		udp->check = csum_replace(udp->check, old, new, 3) ?: 0xffff;
	}
	iph->saddr = iph->daddr;
	iph->daddr = next;
	udp->source = udp->dest;
	udp->dest = row->next_port;
	set_macs(eth, f, &fib);
	return send(f);
}

static __always_inline int forward6(struct xdp_md *ctx, struct ethhdr *eth,
				    struct ipv6hdr *ip6, struct udphdr *udp,
				    struct relay_fwd *f)
{
	struct relay_row *row = f->row;
	__be32 flow = *(__be32 *)ip6 & bpf_htonl(0x0fffffff);
	struct bpf_fib_lookup fib;
	__u16 old[9], new[9];

	/* IPv6 does not allow UDP without a checksum. */
	if (!udp->check) {
		f->st->malformed++;
		return XDP_PASS;
	}
	if (*(__u32 *)&row->next[8] == bpf_htonl(0xffff) &&
	    !*(__u64 *)&row->next[0]) {
		f->st->no_route++;
		return XDP_PASS;
	}
	if (!hop_time || !hop_ok(f, flow)) {
		__builtin_memset(&fib, 0, sizeof(fib));
		fib.family = AF_INET6;
		fib.flowinfo = flow;
		fib.l4_protocol = IPPROTO_UDP;
		fib.sport = relay_port;
		fib.dport = row->next_port;
		fib.tot_len = f->tot;
		fib.ifindex = f->link;
		__builtin_memcpy(fib.ipv6_src, &ip6->daddr, 16);
		__builtin_memcpy(fib.ipv6_dst, row->next, 16);
		if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS ||
		    fib.ifindex != f->link) {
			f->st->no_route++;
			return XDP_PASS;
		}
		if (hop_time)
			hop_save(f, flow, &fib);
	}
	if (!meters(f))
		return XDP_DROP;

	__builtin_memcpy(old, &ip6->saddr, 16);
	__builtin_memcpy(new, row->next, 16);
	old[8] = udp->source;
	new[8] = row->next_port;
	udp->check = csum_replace(udp->check, old, new, 9) ?: 0xffff;
	__builtin_memcpy(&ip6->saddr, &ip6->daddr, 16);
	__builtin_memcpy(&ip6->daddr, row->next, 16);
	ip6->hop_limit = FWD_TTL;
	udp->source = udp->dest;
	udp->dest = row->next_port;
	set_macs(eth, f, &fib);
	return send(f);
}

/* lookup checks the UDP and PSP headers and finds the row and the lane of
 * the packet. tot is the IP length and hlen the IP header length. It returns
 * 0 for XDP_PASS. */
static __always_inline int lookup(struct xdp_md *ctx, struct udphdr *udp,
				  void *data_end, __u32 tot, __u32 hlen,
				  const struct relay_addr *dst,
				  struct relay_key *key, struct relay_fwd *f)
{
	__u8 *psp = (void *)(udp + 1);
	__u32 zero = 0;
	__u32 ulen, lane_id;
	int slot;

	if ((void *)(psp + 8) > data_end || udp->dest != relay_port)
		return 0;
	ulen = bpf_ntohs(udp->len);
	/* An old kernel knows no bounds of a byte swap, and the sum of a packet
	 * pointer and ulen needs them. The compiler must keep the mask. */
	barrier_var(ulen);
	ulen &= 0xffff;
	if (ulen < sizeof(*udp) + PSP_OVERHEAD || ulen != tot - hlen ||
	    (void *)udp + ulen > data_end)
		return 0;
	key->spi = psp_spi(psp);
	if (!key->spi)
		return 0;
	f->st = bpf_map_lookup_elem(&relay_cpu_stats, &zero);
	if (!f->st)
		return 0;
	/* In generic mode the kernel can join UDP packets before the program
	 * runs. This catches only a join above max_len. The loader checks that
	 * the link does not join packets. */
	if (tot > max_len) {
		f->st->too_long++;
		return 0;
	}
	slot = relay_slot(dst);
	if (slot < 0)
		return 0;
	f->slot = slot;
	key->port = udp->source;
	f->row = bpf_map_lookup_elem(&relay_rows, key);
	if (!f->row) {
		f->st->no_row++;
		return 0;
	}
	/* The coarse clock costs less than the exact clock, and is one timer
	 * tick behind at most. A meter reads the exact clock when it needs it. */
	f->now = bpf_ktime_get_coarse_ns();
	if (f->now > f->row->expires) {
		f->st->expired++;
		return 0;
	}
	lane_id = f->row->lane;
	f->lane = bpf_map_lookup_elem(&relay_lanes, &lane_id);
	if (!f->lane)
		return 0;
	f->size = ulen - sizeof(*udp);
	f->link = ctx->ingress_ifindex;
	f->tot = tot;
	return 1;
}

SEC("xdp")
int relay_forward(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct relay_key key = {};
	struct relay_addr dst = {};
	struct relay_fwd f;
	struct udphdr *udp;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = (void *)(eth + 1);

		if ((void *)(iph + 1) > data_end || iph->ihl != 5 ||
		    iph->protocol != IPPROTO_UDP ||
		    (iph->frag_off & bpf_htons(0x3fff)))
			return XDP_PASS;
		udp = (void *)(iph + 1);
		key.addr[10] = 0xff;
		key.addr[11] = 0xff;
		__builtin_memcpy(&key.addr[12], &iph->saddr, 4);
		dst.addr[10] = 0xff;
		dst.addr[11] = 0xff;
		__builtin_memcpy(&dst.addr[12], &iph->daddr, 4);
		if (!lookup(ctx, udp, data_end, bpf_ntohs(iph->tot_len),
			    sizeof(*iph), &dst, &key, &f))
			return XDP_PASS;
		return forward4(ctx, eth, iph, udp, &f);
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);

		if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_UDP)
			return XDP_PASS;
		udp = (void *)(ip6 + 1);
		__builtin_memcpy(key.addr, &ip6->saddr, 16);
		__builtin_memcpy(dst.addr, &ip6->daddr, 16);
		if (!lookup(ctx, udp, data_end,
			    (__u32)bpf_ntohs(ip6->payload_len) + sizeof(*ip6),
			    sizeof(*ip6), &dst, &key, &f))
			return XDP_PASS;
		return forward6(ctx, eth, ip6, udp, &f);
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
