#ifndef HYPERLOGLOG_H
#define HYPERLOGLOG_H

#include <stdint.h>

#define HLL_OK      0
#define HLL_ERROR  -1

// HYPERLOGLOG CONFIGURATION

// HLL_P indicates how many bits are used to choose the register.
// With P=10 we have 2^10 = 1024 registers.
#define HLL_P 10
#define HLL_M (1 << HLL_P)

// Initializes the HyperLogLog registers.
int  hll_init(void);

// Adds a source IP address to the estimate.
int  hll_add_ip(const char *src_ip);

// Returns the estimate of the number of unique source IP addresses.
int hll_get_cardinality(void);

const char *hll_last_error(void);

#endif
