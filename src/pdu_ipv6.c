/* Copyright (c) 2016-2017, Rafael Almeida <rlca at dcc dot ufmg dot br>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of mtraceroute nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "protocol_numbers.h"
#include "pdu_ipv6.h"

int pdu_ipv6(struct packet *p, uint8_t traffic_class,
             uint32_t flow_label, uint16_t length,
             uint8_t next_header, uint8_t hop_limit,
             const uint8_t *src_addr, const uint8_t *dst_addr) {

    uint8_t version = 6; // IPv6

    flow_label &= IPV6_FL_MASK;

    struct ipv6_hdr hdr;
    memset(&hdr, 0, IPV6_H_SIZE);

    hdr.version_tc_fl = htonl(version << 28 | traffic_class << 20 | flow_label);
    hdr.length        = htons(length);
    hdr.next_header   = next_header;
    hdr.hop_limit     = hop_limit;

    if (src_addr != NULL) memcpy(&(hdr.src_addr), src_addr, 16);
    if (dst_addr != NULL) memcpy(&(hdr.dst_addr), dst_addr, 16);

    uint8_t tag = packet_block_append(p, PACKET_BLOCK_IPV6, &hdr,
                                      IPV6_H_SIZE);

    return tag;
}

int pdu_ipv6_length(struct packet *p, int tag) {
    struct packet_block *b = packet_block_get(p, tag);
    if (b == NULL || b->type != PACKET_BLOCK_IPV6) return -1;

    struct ipv6_hdr *hdr = (struct ipv6_hdr *)&p->buf[b->position];
    hdr->length = htons(p->length - b->position - IPV6_H_SIZE);

    return 0;
}

int pdu_ipv6_next_header(struct packet *p, int tag) {

    struct packet_block *b = packet_block_get(p, tag);
    if (b == NULL || b->type != PACKET_BLOCK_IPV6) return -1;

    struct ipv6_hdr *hdr = (struct ipv6_hdr *)&p->buf[b->position];

    // Get the next block
    struct packet_block *nextb = packet_block_next(p, tag);

    switch (nextb->type) {
        case PACKET_BLOCK_TCP: {
            hdr->next_header = PROTO_TCP;
            break;
        }
        case PACKET_BLOCK_UDP: {
            hdr->next_header = PROTO_UDP;
            break;
        }
        case PACKET_BLOCK_ICMPV6: {
            hdr->next_header = PROTO_ICMPV6;
            break;
        }
        default: {
            return -1;
        }
    }

    return 0;
}

struct ipv6_ph *pdu_ipv6_ph(const uint32_t *src_addr, const uint32_t *dst_addr,
                            uint16_t length, uint8_t next_header) {
    struct ipv6_ph *ph = malloc(sizeof(*ph));
    memset(ph, 0, sizeof(*ph));
    ph->length = length;
    ph->next_header = next_header;
    memcpy(&ph->src_addr, src_addr, 4);
    memcpy(&ph->dst_addr, dst_addr, 4);
    return ph;
}
