#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "parser.h"

/* ******** Packet Header ******** */ 
struct ip_header {
    unsigned char ihl:4;
    unsigned char version:4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

struct tcp_header {
    unsigned short source;
    unsigned short dest;
};

struct udp_header {
    unsigned short source;
    unsigned short dest;
};

/* ******* Parser ******* */
int parse_packet(unsigned char *data, int len, packet_t *pkt)
{
    if (len < sizeof(struct ip_header)) {
        return 0;
    }

    struct ip_header *ip = (struct ip_header *)data;

    // Solo IPv4
    if (ip->version != 4) {
        return 0;
    }

    // VAalidazione IHL
    if (ip->ihl < 5) {
        return 0;
    }

    int ip_header_len = ip->ihl * 4;

    // Validazione buffer
    if (len < ip_header_len) {
        return 0;
    }

    // Controllo coerenza interna del pkt
    if (ntohs(ip->tot_len) < ip_header_len) {
        return 0;
    }

    // IP
    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

/*  check di ritorno
    if (inet_ntop(AF_INET, &src, pkt->src_ip, sizeof(pkt->src_ip)) == NULL) {
        return 0;
    }*/
   
    //rispetto alla strcpy, questa è trade-safe
    inet_ntop(AF_INET, &src, pkt->src_ip, sizeof(pkt->src_ip));
    inet_ntop(AF_INET, &dst, pkt->dst_ip, sizeof(pkt->dst_ip));
    pkt->protocol = ip->protocol;

    // Default (per ICMP o fallback)
    pkt->src_port = 0;
    pkt->dst_port = 0;

    // TCP
    if (ip->protocol == 6) { // TCP

        if (len < ip_header_len + sizeof(struct tcp_header)) {
            return 0;
        }

        struct tcp_header *tcp = (struct tcp_header *)(data + ip_header_len);

        pkt->src_port = ntohs(tcp->source);
        pkt->dst_port = ntohs(tcp->dest);
    }

    // UDP
    else if (ip->protocol == 17) { // UDP

        if (len < ip_header_len + sizeof(struct udp_header)) {
            return 0;
        }

        struct udp_header *udp = (struct udp_header *)(data + ip_header_len);

        pkt->src_port = ntohs(udp->source);
        pkt->dst_port = ntohs(udp->dest);
    }

    // ICMP
    else if (ip->protocol == 1) {
        // niente porte
        pkt->src_port = 0;
        pkt->dst_port = 0;
    }

    return 1;
}