#include <stdint.h>
#include <stddef.h>
#include <math.h>
#include "hyperloglog.h"
#include <arpa/inet.h>


static const char *last_error = "no error";

const char *hll_last_error(void) {
    return last_error;
}

// STORAGE HYPERLOGLOG

// WORKFLOW:
// These registers live for the whole execution.
// Each packet updates the estimate of unique source IPs.
static unsigned char registers[HLL_M];

#define HLL_HASH_BITS 32
#define HLL_REMAINING_BITS (HLL_HASH_BITS - HLL_P)

// HASH IPV4

static uint32_t mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;

    return x;
}


// WORKFLOW:
// This function is called when hll_add_ip() receives the packet source IP from the Decision Engine.
static int hash_ipv4(const char *ip, uint32_t *out_hash) {
    
    struct in_addr addr;
    uint32_t ip_value;

    if (ip == NULL || out_hash == NULL) {
        last_error = "NULL argument in hash_ipv4";
        return HLL_ERROR;
    }

    // Convert a string such as "192.168.1.10" into a binary IPv4 value.
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        last_error = "invalid IPv4 address";
        return HLL_ERROR;
    }

    // ntohl converts the value to host byte order.
    ip_value = ntohl(addr.s_addr);

    // XOR with a constant to prevent 0.0.0.0 from producing hash 0.
    *out_hash = mix32(ip_value ^ 0x9e3779b9u);

    return HLL_OK;
}


// COUNT ZEROS

#if !defined(__GNUC__)
// Count the leading zeroes in the remaining hash bits. The more leading zeroes
// we find, the more likely the observed distinct-element count is high.
static int hll_rank_slow(uint32_t value) {
    // Start from the lowest rank.
    int rank  = 1;

    // The maximum rank is reached when all remaining bits are 0.
    int max_rank = HLL_REMAINING_BITS + 1; 

    if (value == 0) {
        return max_rank;
    }

    // 0x80000000u masks the most significant bit. While that bit is 0, increase
    // the rank and shift to the next bit. Once a 1 is found, stop and return.
    while ((value & 0x80000000u) == 0 && rank < max_rank) {
        rank++;
        value <<= 1;
    }

    return rank;
}
#endif

// GCC can count leading zeroes efficiently through a builtin.

// __builtin_clz counts leading zeroes using efficient instructions.
// WARNING: it must never be called with value == 0.
static int hll_rank_fast(uint32_t value) {
    if (value == 0) {
        return HLL_REMAINING_BITS + 1;
    }

#if defined(__GNUC__)
    int rank = __builtin_clz(value) + 1;

    // Clamp the maximum rank.
    if (rank > HLL_REMAINING_BITS + 1) {
        return HLL_REMAINING_BITS + 1;
    }

    return rank;
#else
    return hll_rank_slow(value);
#endif
}


// INIT

// WORKFLOW:
// This function should be called at firewall startup,
// ideally from decision_init().
int  hll_init(void) {
    
    for (int i = 0; i < HLL_M; i++) {
        registers[i] = 0;
    }

    last_error = "no error";
    return HLL_OK;
}

// ADD IP

// WORKFLOW:
// This function is called at the beginning of decide().
// The packet has not been accepted or blocked yet: we are only updating stats.
int  hll_add_ip(const char *src_ip) {
    
    uint32_t hash;
    uint32_t index;
    uint32_t remaining_bits;
    int rank;

    if (src_ip == NULL || src_ip[0] == '\0') {
        last_error = "invalid source IP in hll_add_ip";
        return HLL_ERROR;
    }

    if (hash_ipv4(src_ip, &hash) != HLL_OK) {
        return HLL_ERROR;
    }

    // The first HLL_P bits select which register to update.
    index = hash >> (32 - HLL_P);

    // The remaining bits are used to compute the rank.
    remaining_bits = hash << HLL_P;

    // Slow version:
    // rank = hll_rank_slow(remaining_bits);

    // Optimized GCC version:
    rank = hll_rank_fast(remaining_bits);

    // Each register stores the maximum observed rank.
    if (rank > registers[index]) {
        registers[index] = rank;
    }

    last_error = "no error";
    return HLL_OK;
}

// CARDINALITY ESTIMATE

// WORKFLOW:
// This function is called by Decision Engine logging, for example every 50 packets.
// It does not directly affect ACCEPT/DROP.
// It returns the estimated cardinality.
int hll_get_cardinality(void) {
    
    double alpha;
    double sum = 0.0;
    double estimate;
    int zero_registers = 0;


    alpha = 0.7213 / (1.0 + 1.079 / HLL_M); // correction constant used by HLL to reduce estimation bias

    // Harmonic mean of register values. It gives less weight to extreme values
    // than the arithmetic mean, which would skew the estimate.
    for (int i = 0; i < HLL_M; i++) {
        sum += pow(2.0, -registers[i]); 
        
        if (registers[i] == 0) {
            zero_registers++;
        }
    }

    if (sum == 0.0) {
        last_error = "invalid HLL sum";
        return HLL_ERROR;
    }
    
    estimate = alpha * HLL_M * HLL_M / sum;  // estimation formula

    // Small-range correction. Without it, HyperLogLog tends to overestimate
    // significantly when only a few IPs have been observed.
    if (estimate <= 2.5 * HLL_M && zero_registers > 0) {
        estimate = HLL_M * log((double)HLL_M / zero_registers);
    }

    if (!isfinite(estimate)) {
        last_error = "invalid HLL estimate";
        return HLL_ERROR;
    }

    last_error = "no error";
    return (int)(estimate + 0.5);
}
