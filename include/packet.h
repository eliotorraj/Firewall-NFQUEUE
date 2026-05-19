#ifndef PACKET_H
#define PACKET_H

// Standard representation of a parsed packet.
// Used by ALL modules (parser, rules, rate limit, decision).
typedef struct {
    char src_ip[16];   // IPv4 string (e.g. "192.168.1.1")
    char dst_ip[16];
    int src_port;      // 0 if not applicable (e.g. ICMP)
    int dst_port;
    int protocol;      // TCP=6, UDP=17, ICMP=1
} packet_t;

#endif
