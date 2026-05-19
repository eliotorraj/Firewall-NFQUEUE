#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include "nfqueue_core.h"

static struct nfq_handle *h = NULL;
static struct nfq_q_handle *qh = NULL;
static int fd = -1;
static volatile int running = 1;

// user callback
static packet_handler_cb user_cb = NULL;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

// INTERNAL NFQUEUE CALLBACK

static int nfqueue_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
    
    (void)nfmsg;
    (void)data;

    unsigned char *payload;
    int payload_len;

    // 1. GET HEADER (PACKET ID)
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);

    uint32_t id = 0;

    if (ph) {
        id = ntohl(ph->packet_id);
    }

    // 2. GET PAYLOAD
    payload_len = nfq_get_payload(nfa, &payload);

    if (payload_len < 0) {
        fprintf(stderr, "Error: unable to get payload\n");
        return nfq_set_verdict2(qh, id, NF_ACCEPT, FW_MARK_NONE, 0, NULL);
    }

    // 3. CALL USER CALLBACK
    int verdict = NF_ACCEPT;
    uint32_t mark = FW_MARK_NONE;

    if (user_cb) {

        int res = user_cb(payload, payload_len);

        if (res == 1) {
            verdict = NF_ACCEPT;
            mark = FW_MARK_PASS;
        } 
        else {
            // The actual DROP is applied by iptables rules after save-mark.
            verdict = NF_ACCEPT;
            mark = FW_MARK_DROP;
        }
    }

    // 4. SEND VERDICT TO THE KERNEL
    return nfq_set_verdict2(qh, id, verdict, mark, 0, NULL);
}

//INIT

int nfqueue_init(packet_handler_cb cb){
    
    user_cb = cb;

    // Open handler
    h = nfq_open();

    if (!h) {
        fprintf(stderr, "Error: nfq_open()\n");
        return -1;
    }

    // Detach any existing handler (safety)
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: nfq_unbind_pf()\n");
    }

    // Bind to IPv4
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "Error: nfq_bind_pf()\n");
        nfq_close(h);
        return -1;
    }

    // Create queue 0
    qh = nfq_create_queue(h, 0, &nfqueue_callback, NULL);

    if (!qh) {
        fprintf(stderr, "Error: nfq_create_queue()\n");
        nfq_close(h);
        return -1;
    }

    // Packet copy mode (FULL PACKET)
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "Error: nfq_set_mode()\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return -1;
    }

    fd = nfq_fd(h);

    printf("[NFQUEUE] Initialized successfully\n");

    return 0;
}

// Main loop
void nfqueue_run(){

    char buffer[4096] __attribute__ ((aligned));

    signal(SIGINT, handle_sigint);

    printf("[NFQUEUE] Listening for packets...\n");

    while (running) {

        int rv = recv(fd, buffer, sizeof(buffer), 0);

        if (rv > 0) {
            nfq_handle_packet(h, buffer, rv);
        }
        else if (rv == 0) {
            continue;
        }
        else {
            perror("recv");
            break;
        }
    }

    printf("[NFQUEUE] Stopping...\n");
}

// Cleanup
void nfqueue_cleanup(){
    
    if (qh)
        nfq_destroy_queue(qh);

    if (h) {
        nfq_unbind_pf(h, AF_INET);
        nfq_close(h);
    }

    printf("[NFQUEUE] Cleanup completed\n");
}
