#ifndef __STAGE0_H
#define __STAGE0_H

#include "../include/maps.h"

static __always_inline int process_stage0(struct xdp_md *ctx) {
    return XDP_PASS;
}

#endif
