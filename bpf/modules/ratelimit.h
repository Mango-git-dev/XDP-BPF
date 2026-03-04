#ifndef __RATELIMIT_H
#define __RATELIMIT_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../include/maps.h"

static __always_inline int check_ratelimit(__u32 ip, __u64 now) {
    struct token_bucket *tb = bpf_map_lookup_elem(&ratelimit_map, &ip);
    if (!tb) {
        struct token_bucket init = { .tokens = A2S_TOKEN_CAPACITY, .last_ns = now };
        bpf_map_update_elem(&ratelimit_map, &ip, &init, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = now - tb->last_ns;
    if (elapsed >= REFILL_NS) {
        __u64 add = elapsed / REFILL_NS;
        tb->tokens = (tb->tokens + add > A2S_TOKEN_CAPACITY) ? A2S_TOKEN_CAPACITY : tb->tokens + add;
        tb->last_ns += add * REFILL_NS;
    }

    if (tb->tokens > 0) {
        tb->tokens--;
        return XDP_PASS;
    }

    return XDP_DROP;
}

#endif
