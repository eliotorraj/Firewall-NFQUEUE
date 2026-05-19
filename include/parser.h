#ifndef PARSER_H
#define PARSER_H

#include "packet.h"  // for packet_t

// Parses a raw packet into packet_t.
// return: 1 = OK, 0 = error
int parse_packet(unsigned char *data, int len, packet_t *pkt);

#endif
