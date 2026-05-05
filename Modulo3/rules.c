#include <stdio.h>
#include <string.h>
#include "rules.h"

static rule_t rules[MAX_RULES];
static int rules_count = 0;

// UTILITY

static int match_ip(const char *rule_ip, const char *pkt_ip) {
    if (strcmp(rule_ip, "ANY") == 0)
        return 1;
    return strcmp(rule_ip, pkt_ip) == 0;
}

static int match_port(int rule_port, int pkt_port) {
    if (rule_port == -1)
        return 1;
    return rule_port == pkt_port;
}

static int match_protocol(int rule_proto, int pkt_proto) {
    if (rule_proto == -1)
        return 1;
    return rule_proto == pkt_proto;
}

// MATCH

static int match_rule(packet_t *pkt, rule_t *r) {

    if (!match_ip(r->src_ip, pkt->src_ip))
        return 0;

    if (!match_ip(r->dst_ip, pkt->dst_ip))
        return 0;

    if (!match_protocol(r->protocol, pkt->protocol))
        return 0;

    // ICMP non ha porte
    if (pkt->protocol != 1) {
        if (!match_port(r->src_port, pkt->src_port))
            return 0;

        if (!match_port(r->dst_port, pkt->dst_port))
            return 0;
    }

    return 1;
}

// INIT


void rules_init(void) {

    rules_count = 0;

    rules[rules_count++] = (rule_t){
        .src_ip = "ANY",
        .dst_ip = "ANY",
        .src_port = -1,
        .dst_port = 23,
        .protocol = 6,
        .action = RULE_DROP
    };

    rules[rules_count++] = (rule_t){
        .src_ip = "ANY",
        .dst_ip = "ANY",
        .src_port = -1,
        .dst_port = 80,
        .protocol = 6,
        .action = RULE_ALLOW
    };

    rules[rules_count++] = (rule_t){
        .src_ip = "ANY",
        .dst_ip = "ANY",
        .src_port = -1,
        .dst_port = -1,
        .protocol = 17,
        .action = RULE_DROP
    };

    rules[rules_count++] = (rule_t){
        .src_ip = "192.168.1.100",
        .dst_ip = "ANY",
        .src_port = -1,
        .dst_port = -1,
        .protocol = -1,
        .action = RULE_DROP
    };
}

// CORE

rule_result_t check_rules(packet_t *pkt) {

    if (pkt == NULL) {
        return (rule_result_t){0, 0};
    }

    for (int i = 0; i < rules_count; i++) {

        if (match_rule(pkt, &rules[i])) {
            return (rule_result_t){
                .matched = 1,
                .action = rules[i].action
            };
        }
    }

    return (rule_result_t){0, 0};
}

// DEBUG

const char* rule_action_to_string(int action) {
    switch (action) {
        case RULE_ALLOW: return "ALLOW";
        case RULE_DROP:  return "DROP";
        default:         return "UNKNOWN";
    }
}