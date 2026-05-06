#ifndef NFQUEUE_CORE_H
#define NFQUEUE_CORE_H

#include <stdint.h>

// CALLBACK DEFINITA DAL LIVELLO SUPERIORE
// Ritorna:
// 1 = ACCEPT
// 0 = DROP

typedef int (*packet_handler_cb)(
    unsigned char *data,
    int len
);

// Inizializza NFQUEUE e registra callback
int nfqueue_init(packet_handler_cb cb);

// Loop principale (blocking)
void nfqueue_run();

// Cleanup risorse
void nfqueue_cleanup();

#endif