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

#include "pdu_icmpv4.h"
#include "checksum.h"

int pdu_icmpv4(struct packet *p, uint8_t type, uint8_t code,
               uint16_t checksum, uint32_t body) {

    struct icmpv4_hdr hdr;
    memset(&hdr, 0, ICMPV4_H_SIZE);

    hdr.type     = type;
    hdr.code     = code;
    hdr.checksum = checksum;
    hdr.body     = body;

    uint8_t tag = packet_block_append(p, PACKET_BLOCK_ICMPV4, &hdr,
                                      ICMPV4_H_SIZE);

    return tag;
}

int pdu_icmpv4_echo(struct packet *p, uint16_t checksum,
                    uint16_t id, uint16_t seq_num) {

    uint32_t body = htonl((id << 16) + seq_num);
    return pdu_icmpv4(p, ICMPV4_TYPE_ECHO, ICMPV4_NO_CODE, checksum, body);
}

int pdu_icmpv4_checksum(struct packet *p, int tag) {

    struct packet_block *b = packet_block_get(p, tag);
    if (b == NULL || b->type != PACKET_BLOCK_ICMPV4) return -1;

    struct icmpv4_hdr *hdr = (struct icmpv4_hdr *)&p->buf[b->position];

    // The ICMP checksum include the data so we go from the beginning
    // of the icmpv4 header to the end of the packet
    uint32_t len = p->length - b->position;

    // Make sure the checksum field is 0 before calculating the checksum
    hdr->checksum = 0;
    hdr->checksum = checksum((uint16_t *)hdr, len);

    return 0;
}
