#include <stdio.h>
#include <time.h>
#include "decision.h"

// ============================
// CONFIGURAZIONE
// ============================

static int default_policy = DECISION_DROP;
static FILE *log_file = NULL;

// ============================
// INIT
// ============================

void decision_init() {

    default_policy = DECISION_DROP;

    // Apri file log una sola volta (performance)
    log_file = fopen("firewall.log", "a");
}

// ============================
// LOGGING
// ============================

static void log_packet(packet_t *pkt, const char *reason, int decision) {

    if (!log_file) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    fprintf(log_file,
        "[%02d:%02d:%02d] SRC=%s DST=%s SPORT=%d DPORT=%d PROTO=%d DECISION=%s REASON=%s\n",
        t->tm_hour,
        t->tm_min,
        t->tm_sec,
        pkt->src_ip,
        pkt->dst_ip,
        pkt->src_port,
        pkt->dst_port,
        pkt->protocol,
        decision == DECISION_ACCEPT ? "ACCEPT" : "DROP",
        reason
    );

    fflush(log_file); // flush immediato (debug-friendly)
}

// ============================
// STATISTICHE (HyperLogLog)
// ============================

static void log_stats() {

    int unique_ips = hll_get_cardinality();

    fprintf(log_file,
        "[STATS] Unique source IPs ≈ %d\n",
        unique_ips
    );

    fflush(log_file);
}

// ============================
// DECISION ENGINE
// ============================

decision_result_t decide(packet_t *pkt) {

    // ============================
    // 1. TRAFFIC ANALYSIS (HLL)
    // ============================
    hll_add_ip(pkt->src_ip);

    // ============================
    // 2. FIREWALL RULES
    // ============================
    rule_result_t rr = check_rules(pkt);

    if (rr.matched) {

        if (rr.action == RULE_DROP) {
            log_packet(pkt, "RULE_DROP", DECISION_DROP);
            return (decision_result_t){DECISION_DROP, "RULE_DROP"};
        }

        if (rr.action == RULE_ALLOW) {
            log_packet(pkt, "RULE_ALLOW", DECISION_ACCEPT);
            return (decision_result_t){DECISION_ACCEPT, "RULE_ALLOW"};
        }
    }

    // ============================
    // 3. RATE LIMITING (Leaky Bucket)
    // ============================
    if (rate_limit_check(pkt)) {
        log_packet(pkt, "RATE_LIMIT", DECISION_DROP);
        return (decision_result_t){DECISION_DROP, "RATE_LIMIT"};
    }

    // ============================
    // 4. DEFAULT POLICY
    // ============================
    log_packet(pkt, "DEFAULT_POLICY", default_policy);

    // Log statistiche ogni N pacchetti (semplice versione)
    static int counter = 0;
    counter++;

    if (counter % 50 == 0) {
        log_stats();
    }

    return (decision_result_t){
        .decision = default_policy,
        .reason = "DEFAULT_POLICY"
    };
}