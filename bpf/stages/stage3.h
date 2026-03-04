#ifndef __STAGE3_H
#define __STAGE3_H

#include "../modules/challenge.h"

static __always_inline int process_stage3(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *ip, struct udphdr *udp, __u64 now) {
    return handle_challenge(ctx, eth, ip, udp, now);
}

#endif
