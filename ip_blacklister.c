#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "parsing_helpers.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define MAX_IP_ENTRIES 1
#define WHITELIST 1
#define BLACKLIST 0

struct bpf_map_def SEC("maps") xdp_progs_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};

struct bpf_map_def SEC("maps") ips_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_IP_ENTRIES,
};

struct bpf_map_def SEC("maps") ips_masks = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__be32),
    .max_entries = MAX_IP_ENTRIES,
};

SEC("xdp_ip_blacklist")
int xdp_ip_blacklist_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh;
    struct ethhdr *eth;
    struct iphdr *iph;
    int eth_type, ip_proto;
    int action = XDP_PASS;

    // char msg[] = "in xdp_ip_blacklist\n";
    // bpf_trace_printk(msg, sizeof(msg));

    nh.pos = data;

    /* Parse Ethernet and IP/IPv6 headers */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type == -1)
    {

        char msg2[] = "got ethtype -1\n\0";
        bpf_trace_printk(msg2, sizeof(msg2));
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP))
    {
        char msg2[] = "got ipv4 header\n\0";
        bpf_trace_printk(msg2, sizeof(msg2));
        ip_proto = parse_iphdr(&nh, data_end, &iph);

        if (ip_proto >= 0)
        {
            char msg2[] = "got ip_proto %d %d %d\n\0";
            bpf_trace_printk(msg2, sizeof(msg2), ip_proto, iph->saddr, iph->daddr);

            for (unsigned i = 0; i < MAX_IP_ENTRIES; i++)
            {
                // We need this because using the actual i in the map_lookup will invalidate
                // i since it is passed as a pointer and the checker will fail
                unsigned fake_i = i;

                __be32 *mask = bpf_map_lookup_elem(&ips_masks, &fake_i);
                if (mask != NULL && mask)
                {
                    __be32 src_root = iph->saddr & *mask;
                    __be32 dst_root = iph->daddr & *mask;
                    __u8 *src_verdict = bpf_map_lookup_elem(&ips_map, &src_root);
                    __u8 *dst_verdict = bpf_map_lookup_elem(&ips_map, &dst_root);

                    if ((src_verdict != NULL && *src_verdict == BLACKLIST) ||
                        (dst_verdict != NULL && *dst_verdict == BLACKLIST))
                    {
                        char msg[] = "got verdict drop\n\0";
                        bpf_trace_printk(msg, sizeof(msg));
                        action = XDP_DROP;
                        break;
                    }
                }
            }
        }
        else
        {

            char msg2[] = "got no ip proto\n\0";
            bpf_trace_printk(msg2, sizeof(msg2));
        }
    }
    else
    {

        char msg2[] = "got eth_type %d, expected %d\n\0";
        bpf_trace_printk(msg2, sizeof(msg2), eth_type, bpf_htons(ETH_P_IP));
    }

    if (action == XDP_PASS)
    {
        bpf_tail_call(ctx, &xdp_progs_map, 0);
    }

out:
    return action;
}

char _license[] SEC("license") = "GPL";