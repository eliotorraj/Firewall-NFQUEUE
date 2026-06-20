#ifndef PARSER_H
#define PARSER_H

#include "packet.h"  // for packet_t

// Parse raw packet data into packet_t.
// return: 1 = OK, 0 = error
int parse_packet(unsigned char *data, int len, packet_t *pkt);

#endif
