#ifndef NFQUEUE_CORE_H
#define NFQUEUE_CORE_H

#include <stdint.h>

// Packet marks used with iptables CONNMARK.
#define FW_MARK_NONE 0x0
#define FW_MARK_PASS 0x1
#define FW_MARK_DROP 0x2

// CALLBACK DEFINED BY THE UPPER LAYER
// Returns:
// 1 = ACCEPT
// 0 = DROP

typedef int (*packet_handler_cb)(
    unsigned char *data,
    int len
);

// Initializes NFQUEUE and registers the callback.
int nfqueue_init(packet_handler_cb cb);

// Main loop (blocking).
void nfqueue_run();

// Resource cleanup.
void nfqueue_cleanup();

#endif
