#ifndef __STAGE1_H
#define __STAGE1_H

#include "../modules/ratelimit.h"

static __always_inline int process_stage1(__u32 ip, __u64 now) {
    return check_ratelimit(ip, now);
}

#endif
