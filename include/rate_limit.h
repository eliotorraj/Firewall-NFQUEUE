#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include <time.h>
#include "packet.h"

// LEAKY BUCKET CONSTANTS

// Maximum number of tracked source IPs.
#define MAX_BUCKETS 1024

// Maximum bucket threshold.
// If an IP exceeds this value, it is blocked.
#define RATE_LIMIT_MAX_TOKENS 10

// Bucket leak rate.
// Here: 1 token removed per second.
#define RATE_LIMIT_LEAK_RATE 1

#define RATE_LIMIT_OK     0
#define RATE_LIMIT_DROP   1
#define RATE_LIMIT_ERROR -1

// BUCKET STRUCTURE

// Each source IP has one bucket.
// The more packets it sends, the more tokens it accumulates.
// Tokens decrease over time.
typedef struct {
    char ip[16];             // source IP associated with this bucket
    int tokens;              // current bucket level
    time_t last_update;      // last bucket update time
    int used;                // 1 if this slot is occupied
} bucket_t;

// API

// Initialize the bucket table.
int rate_limit_init(void);

// Check whether a packet exceeds the rate limit.
// Returns 1 if it must be blocked, 0 if it can continue.
int rate_limit_check(packet_t *pkt);
const char *rate_limit_last_error(void);

#endif
