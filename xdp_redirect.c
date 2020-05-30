#include <linux/bpf.h>
#include <linux/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "parsing_helpers.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct bpf_map_def SEC("maps") tx_port = {
    .type = BPF_MAP_TYPE_DEVMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 256,
};

struct bpf_map_def SEC("maps") redirect_params = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = ETH_ALEN,
    .value_size = ETH_ALEN,
    .max_entries = 2,
};

struct bpf_map_def SEC("maps") xdp_progs_map = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 10,
};

SEC("xdp_redirect_map")
int xdp_redirect_map_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh;
    struct ethhdr *eth;
    int eth_type;
    int action = XDP_PASS;
    unsigned char *dst;

    char msg[] = "in xdp_redirect_map";
    bpf_trace_printk(msg, sizeof(msg));

    /* These keep track of the next header type and iterator pointer */
    nh.pos = data;

    /* Parse Ethernet and IP/IPv6 headers */
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type == -1)
        goto out;

    /* Do we know where to redirect this packet? */
    dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
    if (!dst)
        goto out;

    char msg2[] = "redirecting";
    bpf_trace_printk(msg2, sizeof(msg2));

    /* Set a proper destination address */
    memcpy(eth->h_dest, dst, ETH_ALEN);
    action = bpf_redirect_map(&tx_port, 0, 0);

out:
    return action;
}