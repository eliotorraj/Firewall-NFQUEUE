#include <string.h>
#include <time.h>
#include "rate_limit.h"

// STORAGE BUCKET

// WORKFLOW:
// This table lives for the entire firewall execution.
// It stores recent traffic for each source IP address.
static bucket_t buckets[MAX_BUCKETS];


// Store the last error in a string, so the cause of a possible error is available.
static const char *last_error = "no error";

const char *rate_limit_last_error(void) {
    return last_error;
}

// HASH IP

// Converts an IP string into a number.
// Used to quickly choose a position in the table.
// Hash: djb2, created by Dan Bernstein.
static unsigned int hash_ip(const char *ip) {
    // 5381 is a prime number with good statistical properties for reducing initial collisions.
    unsigned int hash = 5381;

    // Using << 5 is equivalent to multiplying by 32; adding hash gives *33,
    // which spreads similar strings across distant points in the table.
    while (*ip != '\0') {
        hash = ((hash << 5) + hash) + (unsigned char)(*ip);
        ip++;
    }

    return hash;
}

// INIT

// WORKFLOW:
// This function must be called when the program starts,
// ideally inside decision_init().
int rate_limit_init(void) {

    time_t now = time(NULL);

    if (now == (time_t)-1) {
        last_error = "time() failed during rate_limit_init";
        return RATE_LIMIT_ERROR;
    }

    for (int i = 0; i < MAX_BUCKETS; i++) {
        buckets[i].ip[0] = '\0';
        buckets[i].tokens = 0;
        buckets[i].last_update = now;
        buckets[i].used = 0;
    }

    last_error = "no error";
    return RATE_LIMIT_OK;
}

// FIND OR CREATE BUCKET

// WORKFLOW:
// When a packet arrives, we need to find the bucket
// associated with its source IP address.
// If it does not exist yet, we create it.
static bucket_t *find_or_create_bucket(const char *ip) {

    unsigned int index = hash_ip(ip) % MAX_BUCKETS;
    unsigned int start = index;

    // If the position is occupied by another IP, try the next position.
    while (buckets[index].used) {

        if (strcmp(buckets[index].ip, ip) == 0) {
            return &buckets[index];
        }

        index = (index + 1) % MAX_BUCKETS;

        // If we return to the starting point, the table is full.
        if (index == start) {
            return NULL;
        }
    }

    // Create a new bucket.
    buckets[index].used = 1;
    strncpy(buckets[index].ip, ip, 15);
    buckets[index].ip[15] = '\0';
    buckets[index].tokens = 0;
    buckets[index].last_update = time(NULL);

    return &buckets[index];
}

// CORE RATE LIMITING

// WORKFLOW:
// This function is called by the Decision Engine
// after static rules have been checked.
//
// Logic:
// - each packet increases the bucket level
// - time decreases the bucket level
// - if the level exceeds the threshold, the packet is dropped
int rate_limit_check(packet_t *pkt) {

    bucket_t *bucket;
    time_t now;
    int elapsed;
    int leaked_tokens;


    if (pkt == NULL) {
        last_error = "NULL packet in rate_limit_check";
        return RATE_LIMIT_ERROR;
    }

    if (pkt->src_ip[0] == '\0') {
        last_error = "empty source IP in rate_limit_check";
        return RATE_LIMIT_ERROR;
    }

    // Find the bucket for the packet's source IP address.
    bucket = find_or_create_bucket(pkt->src_ip);

    if (bucket == NULL) {
        // If no more IP addresses can be tracked, use a conservative choice: block the packet.
        last_error = "bucket table full";
        return RATE_LIMIT_ERROR;
    }

    now = time(NULL);

    if (now == (time_t)-1) {
        last_error = "time() failed in rate_limit_check";
        return RATE_LIMIT_ERROR;
    }

    elapsed = (int)(now - bucket->last_update);
    
    if (elapsed < 0) {
        elapsed = 0;
    }

    // If time has passed since the last packet, the bucket drains.
    if (elapsed > 0) {
        
        leaked_tokens = elapsed * RATE_LIMIT_LEAK_RATE;

        bucket->tokens -= leaked_tokens;

        if (bucket->tokens < 0) {
            bucket->tokens = 0;
        }

        bucket->last_update = now;
    }

    // The current packet increases the bucket level.
    bucket->tokens++;

    // If the bucket exceeds the threshold, the IP address is sending too much traffic.
    if (bucket->tokens > RATE_LIMIT_MAX_TOKENS) {
        last_error = "rate limit exceeded";
        return RATE_LIMIT_DROP;
    }

    last_error = "no error";
    return RATE_LIMIT_OK;
}
