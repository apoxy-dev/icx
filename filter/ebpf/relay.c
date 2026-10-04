/* SPDX-License-Identifier: GPL-2.0 */

/* relay_forward sends PSP packets on to the next hop of their row and
 * returns XDP_TX. A row is keyed on the sender address, the sender port and
 * the SPI. Packets that it cannot forward go to the kernel (XDP_PASS). */

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

struct relay_key {
	__u8 addr[16]; /* IPv4 is ::ffff:a.b.c.d. */
	__be16 port;
	__u16 pad;
	__be32 spi;
};

/* The next hop of a row. Only the loader writes it. */
struct relay_row {
	__u32 tunnel; /* Key in relay_tunnels, or 0 for no tunnel limit. */
	__u32 lane;   /* Key in relay_lanes. */
	__u8 next[16];
	__be16 next_port;
	__u16 pad[3];
	__u64 expires; /* CLOCK_MONOTONIC ns. */
};

/* The meter and the counters of a row. Only the program writes them. */
struct relay_lane {
	struct bpf_spin_lock lock;
	__u32 pad;
	__u64 tokens; /* Lane meter, in byte-ns. */
	__u64 last;
	__u64 used;
	__u64 packets;
	__u64 bytes;
	__u64 drops;
};

struct relay_tunnel {
	struct bpf_spin_lock lock;
	__u32 pad;
	__u64 tokens;
	__u64 last;
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

/* The lanes of the rows. The loader gives each row a lane. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct relay_lane);
} relay_lanes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct relay_tunnel);
} relay_tunnels SEC(".maps");

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

/* meter_take takes size bytes from a token bucket. The tokens are in
 * byte-ns, so a refill needs no division. The caller holds the lock. */
static __always_inline int meter_take(__u64 *tokens, __u64 *last, __u64 now,
				      __u64 size, __u64 rate, __u64 burst,
				      __u64 fill)
{
	__u64 t = *tokens, full = burst * NSEC;
	__u64 elapsed = now > *last ? now - *last : 0;

	if (elapsed >= fill)
		t = full;
	else
		t += elapsed * rate;
	if (t > full)
		t = full;
	*last = now;
	size *= NSEC;
	if (t < size) {
		*tokens = t;
		return 0;
	}
	*tokens = t - size;
	return 1;
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

/* is_relay_addr reports whether dst is an address of the relay. */
static __always_inline int is_relay_addr(const struct relay_addr *dst)
{
	const __u64 *d = (const __u64 *)dst->addr;

#pragma unroll
	for (int i = 0; i < RELAY_ADDRS; i++) {
		__u32 slot = i;
		struct relay_addr *a = bpf_map_lookup_elem(&relay_addrs, &slot);
		const __u64 *w;

		if (!a)
			return 0;
		w = (const __u64 *)a->addr;
		if (w[0] == d[0] && w[1] == d[1])
			return 1;
		if (!w[0] && !w[1])
			return 0;
	}
	return 0;
}

/* meters runs the lane meter of the row and the tunnel limit of its tunnel.
 * It returns 0 when a meter drops the packet. */
static __always_inline int meters(struct relay_row *row,
				  struct relay_lane *lane,
				  struct relay_stats *st, __u64 now,
				  __u64 size)
{
	int ok;

	if (lane_rate) {
		bpf_spin_lock(&lane->lock);
		ok = meter_take(&lane->tokens, &lane->last, now, size,
				lane_rate, lane_burst, lane_fill);
		if (!ok)
			lane->drops++;
		bpf_spin_unlock(&lane->lock);
		if (!ok) {
			st->lane_drops++;
			return 0;
		}
	}
	if (tunnel_rate && row->tunnel) {
		__u32 id = row->tunnel;
		struct relay_tunnel *t = bpf_map_lookup_elem(&relay_tunnels, &id);

		if (t) {
			bpf_spin_lock(&t->lock);
			ok = meter_take(&t->tokens, &t->last, now, size,
					tunnel_rate, tunnel_burst, tunnel_fill);
			if (!ok)
				t->drops++;
			bpf_spin_unlock(&t->lock);
			if (!ok) {
				st->tunnel_drops++;
				return 0;
			}
		}
	}
	return 1;
}

static __always_inline void count(struct relay_lane *lane,
				  struct relay_stats *st, __u64 now,
				  __u64 size)
{
	__sync_fetch_and_add(&lane->packets, 1);
	__sync_fetch_and_add(&lane->bytes, size);
	lane->used = now;
	st->packets++;
	st->bytes += size;
}

static __always_inline int forward4(struct xdp_md *ctx, struct ethhdr *eth,
				    struct iphdr *iph, struct udphdr *udp,
				    struct relay_row *row,
				    struct relay_lane *lane,
				    struct relay_stats *st, __u64 now,
				    __u64 size)
{
	struct bpf_fib_lookup fib = {};
	__be32 next = *(__be32 *)&row->next[12];
	__u16 old[3], new[3];

	if (*(__u32 *)&row->next[8] != bpf_htonl(0xffff)) {
		st->no_route++;
		return XDP_PASS;
	}
	fib.family = AF_INET;
	fib.tos = iph->tos;
	fib.l4_protocol = IPPROTO_UDP;
	fib.sport = relay_port;
	fib.dport = row->next_port;
	fib.tot_len = bpf_ntohs(iph->tot_len);
	fib.ifindex = ctx->ingress_ifindex;
	fib.ipv4_src = iph->daddr;
	fib.ipv4_dst = next;
	if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS ||
	    fib.ifindex != ctx->ingress_ifindex) {
		st->no_route++;
		return XDP_PASS;
	}
	if (!meters(row, lane, st, now, size))
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
	__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
	count(lane, st, now, size);
	return XDP_TX;
}

static __always_inline int forward6(struct xdp_md *ctx, struct ethhdr *eth,
				    struct ipv6hdr *ip6, struct udphdr *udp,
				    struct relay_row *row,
				    struct relay_lane *lane,
				    struct relay_stats *st, __u64 now,
				    __u64 size)
{
	struct bpf_fib_lookup fib = {};
	__u16 old[9], new[9];

	/* IPv6 does not allow UDP without a checksum. */
	if (!udp->check) {
		st->malformed++;
		return XDP_PASS;
	}
	if (*(__u32 *)&row->next[8] == bpf_htonl(0xffff) &&
	    !*(__u64 *)&row->next[0]) {
		st->no_route++;
		return XDP_PASS;
	}
	fib.family = AF_INET6;
	fib.flowinfo = *(__be32 *)ip6 & bpf_htonl(0x0fffffff);
	fib.l4_protocol = IPPROTO_UDP;
	fib.sport = relay_port;
	fib.dport = row->next_port;
	fib.tot_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
	fib.ifindex = ctx->ingress_ifindex;
	__builtin_memcpy(fib.ipv6_src, &ip6->daddr, 16);
	__builtin_memcpy(fib.ipv6_dst, row->next, 16);
	if (bpf_fib_lookup(ctx, &fib, sizeof(fib), 0) != BPF_FIB_LKUP_RET_SUCCESS ||
	    fib.ifindex != ctx->ingress_ifindex) {
		st->no_route++;
		return XDP_PASS;
	}
	if (!meters(row, lane, st, now, size))
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
	__builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);
	count(lane, st, now, size);
	return XDP_TX;
}

/* lookup checks the UDP and PSP headers and finds the row and the lane of
 * the packet. tot is the IP length and hlen the IP header length. It returns
 * NULL for XDP_PASS. */
static __always_inline struct relay_row *
lookup(struct udphdr *udp, void *data_end, __u32 tot, __u32 hlen,
       const struct relay_addr *dst, struct relay_key *key,
       struct relay_lane **lane, struct relay_stats **st, __u64 *now,
       __u64 *size)
{
	__u8 *psp = (void *)(udp + 1);
	struct relay_row *row;
	__u32 zero = 0;
	__u32 ulen, lane_id;

	if ((void *)(psp + 8) > data_end || udp->dest != relay_port)
		return NULL;
	ulen = bpf_ntohs(udp->len);
	if (ulen < sizeof(*udp) + PSP_OVERHEAD || ulen != tot - hlen ||
	    (void *)udp + ulen > data_end)
		return NULL;
	key->spi = psp_spi(psp);
	if (!key->spi)
		return NULL;
	*st = bpf_map_lookup_elem(&relay_cpu_stats, &zero);
	if (!*st)
		return NULL;
	/* In generic mode the kernel can join UDP packets before the program
	 * runs. This catches only a join above max_len. The loader checks that
	 * the link does not join packets. */
	if (tot > max_len) {
		(*st)->too_long++;
		return NULL;
	}
	if (!is_relay_addr(dst))
		return NULL;
	key->port = udp->source;
	row = bpf_map_lookup_elem(&relay_rows, key);
	if (!row) {
		(*st)->no_row++;
		return NULL;
	}
	*now = bpf_ktime_get_ns();
	if (*now > row->expires) {
		(*st)->expired++;
		return NULL;
	}
	lane_id = row->lane;
	*lane = bpf_map_lookup_elem(&relay_lanes, &lane_id);
	if (!*lane)
		return NULL;
	*size = ulen - sizeof(*udp);
	return row;
}

SEC("xdp")
int relay_forward(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct relay_key key = {};
	struct relay_addr dst = {};
	struct relay_stats *st;
	struct relay_lane *lane;
	struct relay_row *row;
	struct udphdr *udp;
	__u64 now, size;

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
		row = lookup(udp, data_end, bpf_ntohs(iph->tot_len), sizeof(*iph),
			     &dst, &key, &lane, &st, &now, &size);
		if (!row)
			return XDP_PASS;
		return forward4(ctx, eth, iph, udp, row, lane, st, now, size);
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);

		if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_UDP)
			return XDP_PASS;
		udp = (void *)(ip6 + 1);
		__builtin_memcpy(key.addr, &ip6->saddr, 16);
		__builtin_memcpy(dst.addr, &ip6->daddr, 16);
		row = lookup(udp, data_end,
			     (__u32)bpf_ntohs(ip6->payload_len) + sizeof(*ip6),
			     sizeof(*ip6), &dst, &key, &lane, &st, &now, &size);
		if (!row)
			return XDP_PASS;
		return forward6(ctx, eth, ip6, udp, row, lane, st, now, size);
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
