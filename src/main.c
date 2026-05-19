#include <stdio.h>

#include "nfqueue_core.h"
#include "parser.h"
#include "decision.h"
#include "rules.h"

// CALLBACK

int handle_packet(unsigned char *data, int len){
    
    packet_t pkt;

    if (parse_packet(data, len, &pkt) == 0) {

        fprintf(stderr, "Packet parsing error\n");

        return 1;
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

// MAIN

int main()
{
    // Load rules from file
    if (rules_init("firewall.conf") != 0) {

        fprintf(stderr, "Error loading firewall.conf\n");

        return 1;
    }

    // Initialize decision engine
    decision_init();

    // Initialize NFQUEUE
    if (nfqueue_init(handle_packet) < 0) {

        fprintf(stderr, "NFQUEUE initialization error\n");

        decision_cleanup();

        return 1;
    }

    nfqueue_run();

    nfqueue_cleanup();

    decision_cleanup();

    return 0;
}
