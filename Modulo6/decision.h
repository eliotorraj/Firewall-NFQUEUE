#ifndef DECISION_H
#define DECISION_H

#include "rules.h"
#include "rate_limit.h"
#include "hyperloglog.h"

// COSTANTI

#define DECISION_ACCEPT 1
#define DECISION_DROP   0

// RISULTATO

typedef struct {
    int decision;
    const char *reason;
} decision_result_t;

// API

void decision_init(void);
decision_result_t decide(packet_t *pkt);

int rate_limit_init(void);
int rate_limit_check(packet_t *pkt);

int hll_init(void);
int hll_add_ip(const char *src_ip);
int hll_get_cardinality(void);

#endif