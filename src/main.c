#include <stdio.h>
#include "nfqueue_core.h"

#include "parser.h"
#include "decision.h"

//CALLBACK

int handle_packet(unsigned char *data, int len)
{
    packet_t pkt;

    // Parsing
    if (parse_packet(data, len, &pkt) == 0) {
        fprintf(stderr, "Errore parsing pacchetto\n");
        return 1; // ACCEPT per sicurezza
    }

    printf("SRC=%s DST=%s PROTO=%d SPORT=%d DPORT=%d\n",
        pkt.src_ip,
        pkt.dst_ip,
        pkt.protocol,
        pkt.src_port,
        pkt.dst_port
    );

    decision_result_t res = decide(&pkt);

    return res.decision;
}

int main()
{

    decision_init();

    if (nfqueue_init(handle_packet) < 0) {
        fprintf(stderr, "Errore init NFQUEUE\n");
        decision_cleanup();
        return 1;
    }

    nfqueue_run();

    nfqueue_cleanup();
    decision_cleanup();

    return 0;
}