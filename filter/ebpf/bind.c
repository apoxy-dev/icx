/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This eBPF/XDP program implements a selective socket redirection mechanism
 * based on source IP and destination port/protocol.
 */

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "parsing_helpers.h"

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

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
	__u8 proto; // IPPROTO_UDP, IPPROTO_TCP
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

	qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf)
		return XDP_PASS;

	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		ip_proto = parse_ip6hdr(&nh, data_end, &ip6h);
		if (ip_proto < 0)
			return XDP_PASS;

		key.family = AF_INET6;
		for (int i = 0; i < 4; i++)
			key.addr[i] = bpf_ntohl(ip6h->daddr.s6_addr32[i]);
	} else {
		ip_proto = parse_iphdr(&nh, data_end, &iph);
		if (ip_proto < 0)
			return XDP_PASS;

		key.family = AF_INET;
		key.addr[0] = bpf_ntohl(iph->daddr);
	}
	key.proto = (__u8)ip_proto;

	if (ip_proto == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcph) < 0)
			return XDP_PASS;
		key.port = bpf_ntohs(tcph->dest);
	} else if (ip_proto == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udph) < 0)
			return XDP_PASS;
		key.port = bpf_ntohs(udph->dest);
	} else {
		return XDP_PASS;
	}

	if (!bpf_map_lookup_elem(&bind_map, &key))
		return XDP_PASS;

	return bpf_redirect_map(&xsks_map, index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";