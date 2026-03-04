#ifndef __MAPS_H
#define __MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct global_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_data);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); 
    __type(value, __u64);
    __uint(max_entries, MAX_ENTRIES);
} whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct challenge);
    __uint(max_entries, MAX_ENTRIES);
} challenge_sent SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct token_bucket);
    __uint(max_entries, 65536);
} ratelimit_map SEC(".maps");

#endif
