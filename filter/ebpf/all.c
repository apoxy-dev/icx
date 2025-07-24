/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

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

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	int *qidconf, index = ctx->rx_queue_index;

	qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
	if (!qidconf)
		return XDP_PASS;

	return bpf_redirect_map(&xsks_map, index, XDP_PASS);
}

char _license[] SEC("license") = "GPL";