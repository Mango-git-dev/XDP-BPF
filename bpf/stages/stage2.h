#ifndef __STAGE2_H
#define __STAGE2_H

#include "../modules/dpi.h"

static __always_inline int process_stage2(struct udphdr *udp, void *data_end) {
    if (!payload_looks_legit(udp, data_end)) return XDP_DROP;
    return XDP_PASS;
}

#endif
