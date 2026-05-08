#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rules.h"

static rule_t rules[MAX_RULES];
static int rules_count = 0;

// ============================
// UTILITY
// ============================

static int parse_action(const char *s)
{
    if (strcmp(s, "ALLOW") == 0)
        return RULE_ALLOW;

    if (strcmp(s, "DROP") == 0)
        return RULE_DROP;

    return -1;
}

static int parse_protocol(const char *s)
{
    if (strcmp(s, "ANY") == 0)
        return -1;

    if (strcmp(s, "TCP") == 0)
        return 6;

    if (strcmp(s, "UDP") == 0)
        return 17;

    if (strcmp(s, "ICMP") == 0)
        return 1;

    return -1;
}

static int parse_port(const char *s)
{
    if (strcmp(s, "ANY") == 0)
        return -1;

    return atoi(s);
}

static int match_ip(const char *rule_ip, const char *pkt_ip)
{
    if (strcmp(rule_ip, "ANY") == 0)
        return 1;

    return strcmp(rule_ip, pkt_ip) == 0;
}

static int match_port(int rule_port, int pkt_port)
{
    if (rule_port == -1)
        return 1;

    return rule_port == pkt_port;
}

static int match_protocol(int rule_proto, int pkt_proto)
{
    if (rule_proto == -1)
        return 1;

    return rule_proto == pkt_proto;
}

// ============================
// MATCH
// ============================

static int match_rule(packet_t *pkt, rule_t *r)
{
    if (!match_ip(r->src_ip, pkt->src_ip))
        return 0;

    if (!match_ip(r->dst_ip, pkt->dst_ip))
        return 0;

    if (!match_protocol(r->protocol, pkt->protocol))
        return 0;

    // ICMP non usa porte
    if (pkt->protocol != 1) {

        if (!match_port(r->src_port, pkt->src_port))
            return 0;

        if (!match_port(r->dst_port, pkt->dst_port))
            return 0;
    }

    return 1;
}

// ============================
// LOAD RULES
// ============================

int rules_init(const char *config_file)
{
    FILE *fp;

    char line[256];

    rules_count = 0;

    fp = fopen(config_file, "r");

    if (!fp) {
        perror("fopen firewall.conf");
        return RULES_ERROR;
    }

    while (fgets(line, sizeof(line), fp)) {

        // Salta commenti e righe vuote
        if (line[0] == '#' || line[0] == '\n')
            continue;

        char action[16];
        char src_ip[32];
        char dst_ip[32];
        char src_port[16];
        char dst_port[16];
        char proto[16];

        int fields = sscanf(
            line,
            "%15s %31s %31s %15s %15s %15s",
            action,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto
        );

        if (fields != 6) {
            fprintf(stderr, "Regola invalida: %s", line);
            continue;
        }

        if (rules_count >= MAX_RULES) {
            fprintf(stderr, "MAX_RULES raggiunto\n");
            break;
        }

        rule_t r;

        strncpy(r.src_ip, src_ip, sizeof(r.src_ip));
        r.src_ip[15] = '\0';

        strncpy(r.dst_ip, dst_ip, sizeof(r.dst_ip));
        r.dst_ip[15] = '\0';

        r.src_port = parse_port(src_port);
        r.dst_port = parse_port(dst_port);

        r.protocol = parse_protocol(proto);

        r.action = parse_action(action);

        rules[rules_count++] = r;
    }

    fclose(fp);

    printf("[RULES] Caricate %d regole da %s\n",
           rules_count,
           config_file);

    return RULES_OK;
}

// ============================
// CORE
// ============================

rule_result_t check_rules(packet_t *pkt)
{
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

// ============================
// DEBUG
// ============================

const char *rule_action_to_string(int action)
{
    switch (action) {

        case RULE_ALLOW:
            return "ALLOW";

        case RULE_DROP:
            return "DROP";

        default:
            return "UNKNOWN";
    }
}