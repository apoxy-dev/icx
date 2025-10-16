/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "parsing_helpers.h"

#define IPPROTO_UDP 17

struct genevehdr {
	__u8 ver_opt_len;
	__u8 flags;
	__be16 proto_type;
	__u8 vni[3];
	__u8 reserved;
};

static __always_inline int
parse_genevehdr(struct hdr_cursor *nh, void *data_end, struct genevehdr **ghdr)
{
	struct genevehdr *gh = nh->pos;

	if ((void *)(gh + 1) > data_end)
		return -1;

	if ((gh->ver_opt_len >> 6) != 0) // Only version 0 supported
		return -1;

	// Check that the protocol type is valid (IPv4 or IPv6 or Unknown (out-of-band messages))
	__u16 ptype = bpf_ntohs(gh->proto_type);
	if (ptype != ETH_P_IP && ptype != ETH_P_IPV6 && ptype != 0)
		return -1;

	*ghdr = gh;
	nh->pos = gh + 1; // Advance cursor past Geneve header
	return 0;
}

#define MAX_QUEUES 256

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_QUEUES);
	__type(key, int);
	__type(value, int);
} qidconf_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, MAX_QUEUES);
	__type(key, int);
	__type(value, int);
} xsks_map SEC(".maps");

#define MAX_BINDS 16

struct bind_key {
	__u8 family; // AF_INET or AF_INET6
	__u32 addr[4]; // IPv4 uses only dst_ip[0], IPv6 uses all 4.
	__u16 port; // Destination port
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_BINDS);
	__type(key, struct bind_key);
	__type(value, int);
} bind_map SEC(".maps");

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int *qidconf, index = ctx->rx_queue_index;
	int nh_type, ip_proto;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct bind_key key = { 0 };
	struct genevehdr *geneve;

	qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf)
		return XDP_PASS;

	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		ip_proto = parse_ip6hdr(&nh, data_end, &ip6h);
		if (ip_proto != IPPROTO_UDP)
			return XDP_PASS;

		key.family = AF_INET6;
		for (int i = 0; i < 4; i++)
			key.addr[i] = bpf_ntohl(ip6h->daddr.s6_addr32[i]);
	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		ip_proto = parse_iphdr(&nh, data_end, &iph);
		if (ip_proto != IPPROTO_UDP)
			return XDP_PASS;

		key.family = AF_INET;
		key.addr[0] = bpf_ntohl(iph->daddr);
	} else {
		return XDP_PASS;
	}

	if (parse_udphdr(&nh, data_end, &udph) < 0)
		return XDP_PASS;

	key.port = bpf_ntohs(udph->dest);

	// First try exact match; if none, try a wildcard bind.
	if (!bpf_map_lookup_elem(&bind_map, &key)) {
		struct bind_key any_key = key;
		any_key.addr[0] = 0;
		any_key.addr[1] = 0;
		any_key.addr[2] = 0;
		any_key.addr[3] = 0;

		if (!bpf_map_lookup_elem(&bind_map, &any_key)) {
			return XDP_PASS;
		}
	}

	// Now make sure it's Geneve traffic.
	if (parse_genevehdr(&nh, data_end, &geneve) < 0)
		return XDP_PASS;

	return bpf_redirect_map(&xsks_map, index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";