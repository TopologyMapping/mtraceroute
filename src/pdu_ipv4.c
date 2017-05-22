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

#include "checksum.h"
#include "pdu_ipv4.h"

int pdu_ipv4(struct packet *p, uint8_t ihl, uint8_t tos,
             uint16_t length, uint16_t id, uint16_t flags_offset,
             uint8_t ttl, uint8_t protocol, uint16_t checksum,
             const uint8_t *src_addr, const uint8_t *dst_addr) {

    uint8_t version = 4; // IPv4

    ihl &= IPV4_IHL_MASK;

    struct ipv4_hdr hdr;
    memset(&hdr, 0, IPV4_H_SIZE);

    hdr.version_ihl = (version << 4) | ihl;
    hdr.tos         = tos;
    hdr.length      = htons(length);
    hdr.id          = htons(id);
    hdr.flags_off   = htons(flags_offset);
    hdr.ttl         = ttl;
    hdr.protocol    = protocol;
    hdr.checksum    = checksum;

    if (src_addr != NULL) memcpy(&(hdr.src_addr), src_addr, 4);
    if (dst_addr != NULL) memcpy(&(hdr.dst_addr), dst_addr, 4);

    uint8_t tag = packet_block_append(p, PACKET_BLOCK_IPV4, &hdr,
                                      IPV4_H_SIZE);

    return tag;
}

int pdu_ipv4_checksum(struct packet *p, int tag) {
    struct packet_block *b = packet_block_get(p, tag);
    if (b == NULL || b->type != PACKET_BLOCK_IPV4) return -1;

    struct ipv4_hdr *hdr = (struct ipv4_hdr *)&p->buf[b->position];

    // Make sure the checksum field is 0 before calculating the checksum
    hdr->checksum = 0;
    hdr->checksum = checksum((uint16_t *)hdr, b->length);

    return 0;
}

int pdu_ipv4_length(struct packet *p, int tag) {
    struct packet_block *b = packet_block_get(p, tag);
    if (b == NULL || b->type != PACKET_BLOCK_IPV4) return -1;

    struct ipv4_hdr *hdr = (struct ipv4_hdr *)&p->buf[b->position];
    hdr->length = htons(p->length - b->position);

    return 0;
}

struct ipv4_ph *pdu_ipv4_ph(uint32_t src_addr, uint32_t dst_addr,
                            uint8_t protocol, uint16_t length) {
    struct ipv4_ph *ph = malloc(sizeof(*ph));
    memset(ph, 0, sizeof(*ph));
    ph->src_addr = src_addr;
    ph->dst_addr = dst_addr;
    ph->protocol = protocol;
    ph->length = length;
    return ph;
}
