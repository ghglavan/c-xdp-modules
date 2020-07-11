/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "parsing_helpers.h"

SEC("xdp_block_sni")
int xdp_block_sni_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = {.pos = data};

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0)
	{
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP))
	{
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6))
	{
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	}
	else
	{
		goto out;
	}

	if (ip_type == IPPROTO_UDP)
		goto out;
	else if (ip_type == IPPROTO_TCP)
	{
		int len = parse_tcphdr(&nh, data_end, &tcphdr);
		if (len < 0)
		{
			action = XDP_ABORTED;
			goto out;
		}

		struct tls_hdr h;

		if (parse_tls(&nh, data_end, &h) > 0)
			printk("got sni: %s\n", h.sni);
	}

out:
	return action;
}

char _license[] SEC("license") = "GPL";
