#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include <time.h>
#include "packet.h"

// LEAKY BUCKET CONSTANTS

// Maximum number of trackable source IP addresses.
#define MAX_BUCKETS 1024

// Maximum bucket threshold.
// If an IP address exceeds this value, it is blocked.
#define RATE_LIMIT_MAX_TOKENS 10

// Rate at which the bucket drains.
// Here: 1 token removed per second.
#define RATE_LIMIT_LEAK_RATE 1

#define RATE_LIMIT_OK     0
#define RATE_LIMIT_DROP   1
#define RATE_LIMIT_ERROR -1

// BUCKET STRUCTURE

// Each source IP address has a bucket.
// The more packets it sends, the more tokens it accumulates.
// Over time, tokens decrease.
typedef struct {
    char ip[16];             // source IP associated with the bucket
    int tokens;              // current bucket level
    time_t last_update;      // last time the bucket was updated
    int used;                // 1 if this slot is occupied
} bucket_t;

// API

// Initializes the bucket table.
int rate_limit_init(void);

// Checks whether a packet exceeds the rate limit.
// Returns 1 if it must be blocked, 0 if it can continue.
int rate_limit_check(packet_t *pkt);
const char *rate_limit_last_error(void);

#endif
