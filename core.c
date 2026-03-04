#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>



#define MAX_ENTRIES 1000000
#define WHITELIST_TIMEOUT_NS 360000000000ULL
#define CHALLENGE_TIMEOUT_NS 5000000000ULL   // 5 giây để IP phản hồi cookie
#define A2S_PORT 27015
#define A2S_TOKEN_CAPACITY 5
#define REFILL_NS 1000000000ULL               // hồi lại token mỗi 1 giây
#define SIGN_LEN 21

// cấu trúc dữ liệu
struct challenge {
    __u64 timestamp;
    __u32 cookie;
};

struct token_bucket {
    __u64 tokens;
    __u64 last_ns;
};

// maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); 
    __type(value, __u64); // IP -> Last Valid Timestamp
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


// check chữ ký steam a2s query
static __always_inline int is_a2s_query(void *data, void *data_end, struct udphdr *udph) {
    unsigned char sig[SIGN_LEN] = {
        0xff,0xff,0xff,0xff,
        0x54,0x53,0x6f,0x75,0x72,0x63,0x65,0x20,0x45,0x6e,0x67,0x69,0x6e,0x65,0x20,0x51,0x75,0x65
    };
    unsigned char *payload = (unsigned char *)(udph + 1);
    if ((void*)payload + SIGN_LEN > data_end) return 0;
    
    #pragma unroll
    for (int i = 0; i < SIGN_LEN; i++) {
        if (payload[i] != sig[i]) return 0;
    }
    return 1;
}

// list port được bảo vệ
static __always_inline int is_protected_port(__u16 dport_n) {
    __u16 dport = bpf_ntohs(dport_n);
    if (dport == 53 || dport == 1194 || dport == 27015 || dport == 28015 || dport == 51820) return 1;
    if (dport >= 7000 && dport <= 8999) return 1;   // Game servers range 1
    if (dport >= 4970 && dport <= 4980) return 1;   // Game servers range 2
    if (dport >= 30000 && dport <= 32000) return 1; // FiveM/RedM
    return 0;
}


static __always_inline int payload_looks_legit(void *data, void *data_end, __u16 dport) {
    if (data + 4 > data_end) return 0;

    // DNS 
    if (dport == 53) {
        if (data + 12 > data_end) return 0;
        __u16 flags = *(__u16 *)(data + 2);
        return (bpf_ntohs(flags) & 0x8000) == 0; // Chỉ cho phép Query
    }
    
    // Steam / Source Engine (A2S)
    if (dport >= 27000 && dport <= 27500) {
        return *(__u32 *)data == 0xffffffff;
    }

    // FiveM / RedM (getInfo)
    if (dport >= 30000 && dport <= 32000) {
        if (data + 16 <= data_end) {
            if (*(__u32 *)data == 0xffffffff) return 1;
        }
    }

    if (dport == 51820) return *(unsigned char *)data == 1;

    return 1; //mặc định gói tin đầu tiên để tạo challenge
}

// tạo Cookie bảo mật 
static __always_inline __u32 generate_secure_cookie(__u32 ip, __u16 port, __u64 ts) {
    // prandom tránh bypass
    return bpf_get_prandom_u32() ^ ip ^ port ^ (__u32)ts;
}


SEC("xdp")
int xdp_anti_ddos_core(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    __u64 *wl_ts = bpf_map_lookup_elem(&whitelist, &src_ip);
    if (wl_ts) {
        if (now - *wl_ts < WHITELIST_TIMEOUT_NS) {
            return XDP_PASS; 
        }
        bpf_map_delete_elem(&whitelist, &src_ip);
    }

    //udp
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;

        if (!is_protected_port(udp->dest)) return XDP_PASS;

        __u16 dport = bpf_ntohs(udp->dest);
        void *payload = (void *)(udp + 1);

        // ratelimit
        if (dport == A2S_PORT) {
            if (is_a2s_query(data, data_end, udp)) {
                struct token_bucket *tb = bpf_map_lookup_elem(&ratelimit_map, &src_ip);
                if (!tb) {
                    struct token_bucket init = { .tokens = A2S_TOKEN_CAPACITY, .last_ns = now };
                    bpf_map_update_elem(&ratelimit_map, &src_ip, &init, BPF_ANY);
                } else {
                    __u64 elapsed = now - tb->last_ns;
                    if (elapsed >= REFILL_NS) {
                        __u64 add = elapsed / REFILL_NS;
                        tb->tokens = (tb->tokens + add > A2S_TOKEN_CAPACITY) ? A2S_TOKEN_CAPACITY : tb->tokens + add;
                        tb->last_ns += add * REFILL_NS;
                    }
                    if (tb->tokens > 0) {
                        tb->tokens--;
                    } else {
                        return XDP_DROP; // vượt ngưỡng pps cho phép thì drop
                    }
                }
            }
        }

        // check phản hồi challenge
        if (data_end - payload >= 4) {
            __u32 *returned_cookie = payload;
            struct challenge *ch = bpf_map_lookup_elem(&challenge_sent, &src_ip);
            if (ch && ch->cookie == *returned_cookie) {
                if (now - ch->timestamp < CHALLENGE_TIMEOUT_NS) {
                    bpf_map_update_elem(&whitelist, &src_ip, &now, BPF_ANY);
                    bpf_map_delete_elem(&challenge_sent, &src_ip);
                    return XDP_PASS;
                }
            }
        }

        // gửi thử thách cho ip lạ
        if (!payload_looks_legit(payload, data_end, dport)) return XDP_DROP;

        __u32 cookie = generate_secure_cookie(src_ip, udp->source, now);
        struct challenge new_ch = { .timestamp = now, .cookie = cookie };
        bpf_map_update_elem(&challenge_sent, &src_ip, &new_ch, BPF_ANY);

        unsigned char tmp_mac[6];
        __builtin_memcpy(tmp_mac, eth->h_dest, 6);
        __builtin_memcpy(eth->h_dest, eth->h_source, 6);
        __builtin_memcpy(eth->h_source, tmp_mac, 6);

        __u32 tmp_ip = ip->daddr;
        ip->daddr = ip->saddr;
        ip->saddr = tmp_ip;
        ip->ttl = 64;

        __u16 tmp_port = udp->dest;
        udp->dest = udp->source;
        udp->source = tmp_port;
        udp->len = bpf_htons(sizeof(struct udphdr) + 4);

        if ((void *)(payload + 4) <= data_end) {
            *(__u32 *)payload = cookie;
            int shift = (int)(data_end - (payload + 4));
            if (bpf_xdp_adjust_tail(ctx, -shift) == 0) {
                return XDP_TX; 
            }
        }
        return XDP_DROP;
    }

    // tcp
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        
        if (tcp->syn && !tcp->ack) return XDP_PASS;
        
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
