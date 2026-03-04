#ifndef __ENDIAN_H
#define __ENDIAN_H

#include <linux/types.h>
#include <asm/byteorder.h>

#if defined(__be32_to_cpu)
#define bpf_ntohl(x) __be32_to_cpu(x)
#define bpf_htonl(x) __cpu_to_be32(x)
#define bpf_ntohs(x) __be16_to_cpu(x)
#define bpf_htons(x) __cpu_to_be16(x)
#else
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#endif

#endif
