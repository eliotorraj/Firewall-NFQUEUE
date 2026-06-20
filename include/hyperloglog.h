#ifndef HYPERLOGLOG_H
#define HYPERLOGLOG_H

#include <stdint.h>

#define HLL_OK      0
#define HLL_ERROR  -1

// HYPERLOGLOG CONFIGURATION

// HLL_P defines how many bits are used to select the register.
// With P=10, we have 2^10 = 1024 registers.
#define HLL_P 10
#define HLL_M (1 << HLL_P)

// Initialize HyperLogLog registers.
int  hll_init(void);

// Add a source IP to the estimate.
int  hll_add_ip(const char *src_ip);

// Return the estimated number of unique source IPs.
int hll_get_cardinality(void);

const char *hll_last_error(void);

#endif
