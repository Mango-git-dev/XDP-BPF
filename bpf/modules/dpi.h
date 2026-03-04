#ifndef __DPI_H
#define __DPI_H

#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include "../include/common.h"

static __always_inline int is_a2s_query(void *data, void *data_end, struct udphdr *udp) {
    unsigned char sig[A2S_SIGN_LEN] = {
        0xff, 0xff, 0xff, 0xff,
        0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20, 0x51, 0x75, 0x65
    };
    unsigned char *payload = (unsigned char *)(udp + 1);
    if ((void*)payload + A2S_SIGN_LEN > data_end) return 0;

    #pragma unroll
    for (int i = 0; i < A2S_SIGN_LEN; i++) {
        if (payload[i] != sig[i]) return 0;
    }
    return 1;
}

static __always_inline int payload_looks_legit(struct udphdr *udp, void *data_end) {
    void *data = (void *)(udp + 1);
    __u16 dport = bpf_ntohs(udp->dest);

    if (data + 4 > data_end) return 0;

    if (dport == 53) {
        if (data + 12 > data_end) return 0;
        __u16 flags = *(__u16 *)(data + 2);
        return (bpf_ntohs(flags) & 0x8000) == 0;
    }
    
    if (dport >= 27000 && dport <= 27500) {
        return *(__u32 *)data == 0xffffffff;
    }

    if (dport >= 30000 && dport <= 32000) {
        if (data + 16 <= data_end) {
            if (*(__u32 *)data == 0xffffffff) return 1;
        }
    }

    if (dport == 51820) return *(unsigned char *)data == 1;

    return 1;
}

#endif
