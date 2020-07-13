/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/*
 * This file contains parsing functions that are used in the packetXX XDP
 * programs. The functions are marked as __always_inline, and fully defined in
 * this header file to be included in the BPF program.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 *
 * The versions of the functions included here are slightly expanded versions of
 * the functions in the packet01 lesson. For instance, the Ethernet header
 * parsing has support for parsing VLAN tags.
 */

#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/* Header cursor to keep track of current parsing position */
struct hdr_cursor
{
    void *pos;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/*
 * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
 * structures.
 */
struct icmphdr_common
{
    __u8 type;
    __u8 code;
    __sum16 cksum;
};

#define TLS_CONTENT_TYPE_HS 0x16
#define TLS_MAJ 0x03 // acutally SLL 3.0
#define TLS_VERSION_1_0 0x01
#define TLS_VERSION_1_1 0x02
#define TLS_VERSION_1_2 0x03
#define TLS_RECORD_LEN_OFFSET 3
#define SNI_LEN 30

struct tls_hdr
{
    __u16 tls_version;
    __u16 sni_len;
    __u16 sni_type;
    char sni[SNI_LEN];
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

static __always_inline int proto_is_vlan(__u16 h_proto)
{
    return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
              h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
                                        struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);
    struct vlan_hdr *vlh;
    __u16 h_proto;
    int i;

    /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *ethhdr = eth;
    vlh = nh->pos;
    h_proto = eth->h_proto;

/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
#pragma unroll
    for (i = 0; i < VLAN_MAX_DEPTH; i++)
    {
        if (!proto_is_vlan(h_proto))
            break;

        if (vlh + 1 > data_end)
            break;

        h_proto = vlh->h_vlan_encapsulated_proto;
        vlh++;
    }

    nh->pos = vlh;
    return h_proto; /* network-byte-order */
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;

    /* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
    if (ip6h + 1 > data_end)
        return -1;

    nh->pos = ip6h + 1;
    *ip6hdr = ip6h;

    return ip6h->nexthdr;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
                                          void *data_end,
                                          struct icmp6hdr **icmp6hdr)
{
    struct icmp6hdr *icmp6h = nh->pos;

    if (icmp6h + 1 > data_end)
        return -1;

    nh->pos = icmp6h + 1;
    *icmp6hdr = icmp6h;

    return icmp6h->icmp6_type;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct icmphdr **icmphdr)
{
    struct icmphdr *icmph = nh->pos;

    if (icmph + 1 > data_end)
        return -1;

    nh->pos = icmph + 1;
    *icmphdr = icmph;

    return icmph->type;
}

static __always_inline int parse_icmphdr_common(struct hdr_cursor *nh,
                                                void *data_end,
                                                struct icmphdr_common **icmphdr)
{
    struct icmphdr_common *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    nh->pos = h + 1;
    *icmphdr = h;

    return h->type;
}

/*
 * parse_tcphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct udphdr **udphdr)
{
    int len;
    struct udphdr *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    nh->pos = h + 1;
    *udphdr = h;

    len = bpf_ntohs(h->len) - sizeof(struct udphdr);
    if (len < 0)
        return -1;

    return len;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct tcphdr **tcphdr)
{
    int len;
    struct tcphdr *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    len = h->doff * 4;
    if ((void *)h + len > data_end)
        return -1;

    *tcphdr = h;
    nh->pos += len;

    return len;
}

static __always_inline int __get_u8(void *data, void *data_end, __u8 *u)
{
    __u8 *p = (__u8 *)data;
    if (p + 1 > data_end)
        return -1;
    *u = *p;
    return 1;
}

static __always_inline int __get_u16(void *data, void *data_end, __u16 *u)
{
    __u16 *p = (__u16 *)data;
    if (p + 1 > data_end)
        return -1;
    *u = bpf_ntohs(*p);
    return 1;
}

#define GET_U8(data, data_end, u)           \
    __u8 u;                                 \
    if (__get_u8(data, data_end, &u) == -1) \
        return -1;                          \
    data += 1;
#define GET_U16(data, data_end, u)           \
    __u16 u;                                 \
    if (__get_u16(data, data_end, &u) == -1) \
        return -1;                           \
    data += 2;

#define printk(fmt, ...)                                   \
    do                                                     \
    {                                                      \
        char msg[] = fmt;                                  \
        bpf_trace_printk(msg, sizeof(msg), ##__VA_ARGS__); \
    } while (0)

static __always_inline int is_tls_version(__u16 ver)
{
    __u8 *data = (__u8 *)&ver;
    __u8 maj = *data;
    data++;
    __u8 min = *data;

    if (maj == TLS_MAJ && (min == TLS_VERSION_1_0 || min == TLS_VERSION_1_1 ||
                           min == TLS_VERSION_1_2))
        return 1;

    return -1;
}

static __always_inline int is_tls_hs(void *data, void *data_end)
{
    if (data_end - data < TLS_RECORD_LEN_OFFSET)
        return -1;

    GET_U8(data, data_end, content_type);
    GET_U16(data, data_end, ver);
    if (content_type == TLS_CONTENT_TYPE_HS && is_tls_version(ver))
        return 1;

    return -1;
}

static __always_inline int parse_tls(struct hdr_cursor *nh, void *data_end, struct tls_hdr *h)
{
    void *data = nh->pos;

    if (is_tls_hs(data, data_end) == -1)
        return -1;

    if (data_end - data < TLS_RECORD_LEN_OFFSET)
        return -1;

    data += TLS_RECORD_LEN_OFFSET;

    GET_U16(data, data_end, record_len);
    if (data_end - data < record_len)
        return -1;

    GET_U8(data, data_end, hs_type);
    if (hs_type != 1)
        return -1;

    GET_U8(data, data_end, z);
    if (z != 0)
        return -1;

    GET_U16(data, data_end, ch_len);
    if (data_end - data < ch_len)
        return -1;

    GET_U16(data, data_end, tls_ver);

    if (is_tls_version(tls_ver) == -1)
        return -1;

    if (data_end - data < 32)
        return -1;

    data += 32;

    GET_U8(data, data_end, ssn_len);
    data += ssn_len;

    GET_U16(data, data_end, cs_len);

    // for some reason the verifier forgets the boundary for the cs_len var
    // so we have to remind him here. 10000 is a better value than 65535
    // a cipher suite bigger than 10000 is something malformed
    if (cs_len > 10000)
        return -1;

    data += cs_len;

    GET_U8(data, data_end, cm_len);
    data += cm_len;

    GET_U16(data, data_end, exts_len);

    // same as the above
    if (exts_len > 10000)
        return -1;

    GET_U16(data, data_end, ext_type);

    if (ext_type != 0) // not a server name ext
        return -1;

    GET_U16(data, data_end, ext_len);

    if (ext_len + 4 > exts_len)
        return -1;

    GET_U16(data, data_end, snl_len);
    GET_U8(data, data_end, sn_type);

    // this is an overkill
    if (sn_type != 0) // not a host name
        return -1;

    GET_U16(data, data_end, sn_len);

    if (sn_len + 5 > ext_len)
        return -1;

    h->tls_version = tls_ver;
    h->sni_len = sn_len;
    h->sni_type = sn_type;

    int j = 0;
#pragma clang loop unroll(full)
    for (int i = 0; i < SNI_LEN - 1; i++)
    {
        j = i;
        if (i >= sn_len)
            break;

        GET_U8(data, data_end, c);
        h->sni[i] = (char)c;
    }
    h->sni[j] = '\0';

    return 1;
}

#endif /* __PARSING_HELPERS_H */
