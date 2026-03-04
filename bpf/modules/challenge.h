#ifndef __CHALLENGE_H
#define __CHALLENGE_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "../include/maps.h"

static __always_inline __u32 generate_cookie(__u32 ip, __u16 port, __u64 ts) {
    return bpf_get_prandom_u32() ^ ip ^ port ^ (__u32)ts;
}

static __always_inline int handle_challenge(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp, __u64 now) {
    void *data_end = (void *)(long)ctx->data_end;
    void *payload = (void *)(udp + 1);
    __u32 src_ip = ip->saddr;

    __u32 cookie = generate_cookie(src_ip, udp->source, now);
    struct challenge new_ch = {};
    __builtin_memset(&new_ch, 0, sizeof(new_ch));
    new_ch.timestamp = now;
    new_ch.cookie = cookie;
    bpf_map_update_elem(&challenge_sent, &src_ip, &new_ch, BPF_ANY);

    // Swap MAC
    unsigned char tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);

    // Swap IP
    __u32 tmp_ip = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp_ip;
    ip->ttl = 64;

    // Swap Port
    __u16 tmp_port = udp->dest;
    udp->dest = udp->source;
    udp->source = tmp_port;
    udp->len = bpf_htons(sizeof(struct udphdr) + 4);

    if ((void *)(payload + 4) <= data_end) {
        *(__u32 *)payload = cookie;
        int shift = (int)(data_end - (payload + 4));
        if (bpf_xdp_adjust_tail(ctx, -shift) == 0) {
            return XDP_TX;
        }
    }
    return XDP_DROP;
}

#endif
