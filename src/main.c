#include <stdio.h>
#include "nfqueue_core.h"

#include "parser.h"
#include "decision.h"


/* ******** CALLBACK DI TEST ******** */

int handle_packet(unsigned char *data, int len)
{
    packet_t pkt;

    // Parsing
    if (parse_packet(data, len, &pkt) == 0) {
        fprintf(stderr, "Errore parsing pacchetto\n");
        return 1; // ACCEPT (per evitare drop in caso di errore)
    }
    printf("SRC=%s DST=%s PROTO=%d SPORT=%d DPORT=%d\n",
        pkt.src_ip,
        pkt.dst_ip,
        pkt.protocol,
        pkt.src_port,
        pkt.dst_port
    );

    int decision = decide(&pkt);

    return decision; // 1 = ACCEPT, 0 = DROP
}

int main()
{
    if (nfqueue_init(handle_packet) < 0) {
        fprintf(stderr, "Errore init NFQUEUE\n");
        return 1;
    }    

    nfqueue_run();

    nfqueue_cleanup();

    return 0;
}