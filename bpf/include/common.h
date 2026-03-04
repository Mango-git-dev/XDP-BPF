#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

#define MAX_ENTRIES 1000000
#define WHITELIST_TIMEOUT_NS 360000000000ULL
#define CHALLENGE_TIMEOUT_NS 5000000000ULL
#define REFILL_NS 1000000000ULL

#define A2S_PORT 27015
#define A2S_TOKEN_CAPACITY 5
#define A2S_SIGN_LEN 23

struct stats_data {
    __u64 total_req;
    __u64 blocked_req;
    __u64 passed_req;
    __u64 last_peak_pps;
};

struct global_config {
    __u32 stage;
    __u32 threshold_pps;
};

struct challenge {
    __u64 timestamp;
    __u32 cookie;
    __u32 pad;
};

struct token_bucket {
    __u64 tokens;
    __u64 last_ns;
};

#endif
