#ifndef RULES_H
#define RULES_H

#include <stdint.h>

// COSTANTI

#define RULE_ALLOW 1
#define RULE_DROP  2

#define MAX_RULES 100

// STRUTTURA PACCHETTO

typedef struct {
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    int protocol; // TCP=6, UDP=17, ICMP=1
} packet_t;

// STRUTTURA REGOLA

typedef struct {
    char src_ip[16];   // "ANY"
    char dst_ip[16];   // "ANY"
    int src_port;      // -1 = ANY
    int dst_port;      // -1 = ANY
    int protocol;      // -1 = ANY
    int action;        // RULE_ALLOW / RULE_DROP
} rule_t;

// RISULTATO

typedef struct {
    int matched;
    int action;
} rule_result_t;

// API

void rules_init(void);
rule_result_t check_rules(packet_t *pkt);
const char* rule_action_to_string(int action);

#endif