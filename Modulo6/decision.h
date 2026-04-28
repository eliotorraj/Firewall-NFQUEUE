#ifndef DECISION_H
#define DECISION_H

#include "rules.h"

// ============================
// COSTANTI
// ============================

#define DECISION_ACCEPT 1
#define DECISION_DROP   0

// ============================
// RISULTATO DECISIONE
// ============================

typedef struct {
    int decision;          // ACCEPT / DROP
    const char *reason;    // motivo della decisione
} decision_result_t;

// ============================
// API
// ============================

void decision_init();

// Funzione principale
decision_result_t decide(packet_t *pkt);

// ============================
// INTEGRAZIONE MODULI (HOOK)
// ============================

// Modulo 4 — Leaky Bucket
int rate_limit_check(packet_t *pkt);

// Modulo 5 — HyperLogLog
void hll_add_ip(const char *src_ip);
int hll_get_cardinality();

#endif