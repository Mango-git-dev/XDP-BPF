#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/in.h>

#include "include/common.h"
#include "include/maps.h"
#include "modules/dpi.h"
#include "modules/ratelimit.h"
#include "modules/challenge.h"
#include "stages/stage0.h"
#include "stages/stage1.h"
#include "stages/stage2.h"
#include "stages/stage3.h"

SEC("xdp")
int xdp_anti_ddos_core(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 key = 0;
    struct global_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    struct stats_data *st = bpf_map_lookup_elem(&stats_map, &key);
    
    if (st) __sync_fetch_and_add(&st->total_req, 1);

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    // whitelist check
    __u64 *wl_ts = bpf_map_lookup_elem(&whitelist, &src_ip);
    if (wl_ts) {
        if (now - *wl_ts < WHITELIST_TIMEOUT_NS) {
            if (st) __sync_fetch_and_add(&st->passed_req, 1);
            return XDP_PASS;
        }
        bpf_map_delete_elem(&whitelist, &src_ip);
    }

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        
        // logic stage
        __u32 stage = cfg ? cfg->stage : 0;

        // s1: ratelimit
        if (stage >= 1) {
            if (process_stage1(src_ip, now) == XDP_DROP) goto drop;
        }

        // s2: dpi
        if (stage >= 2) {
            if (process_stage2(udp, data_end) == XDP_DROP) goto drop;
        }

        // check cookie challenge
        void *payload = (void *)(udp + 1);
        if (data_end - payload >= 4) {
             __u32 *returned_cookie = payload;
             struct challenge *ch = bpf_map_lookup_elem(&challenge_sent, &src_ip);
             if (ch && ch->cookie == *returned_cookie) {
                 if (now - ch->timestamp < CHALLENGE_TIMEOUT_NS) {
                     bpf_map_update_elem(&whitelist, &src_ip, &now, BPF_ANY);
                     bpf_map_delete_elem(&challenge_sent, &src_ip);
                     if (st) __sync_fetch_and_add(&st->passed_req, 1);
                     return XDP_PASS;
                 }
             }
        }

        // s3: max defense (face challenge)
        if (stage == 3) {
            int res = process_stage3(ctx, eth, ip, udp, now);
            if (res == XDP_TX) return XDP_TX;
            goto drop;
        }
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        if (tcp->syn && !tcp->ack) {
            if (st) __sync_fetch_and_add(&st->passed_req, 1);
            return XDP_PASS;
        }
    }

    if (st) __sync_fetch_and_add(&st->passed_req, 1);
    return XDP_PASS;

drop:
    if (st) __sync_fetch_and_add(&st->blocked_req, 1);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
