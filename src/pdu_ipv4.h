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

#ifndef __PDU_IPV4_H__
#define __PDU_IPV4_H__

#include <stdint.h>
#include "packet.h"

#define IPV4_H_SIZE   20
#define IPV4_IHL      5
#define IPV4_TTL      64
#define IPV4_FLAGS_DF 0x4000
#define IPV4_FLAGS_MF 0x2000
#define IPV4_IHL_MASK 0xf

// IPv4 header
struct ipv4_hdr {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t length;
    uint16_t id;
    uint16_t flags_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

#define IPV4_PH_SIZE 12

struct ipv4_ph {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zeroes;
    uint8_t protocol;
    uint16_t length;
};

int pdu_ipv4(struct packet *p, uint8_t ihl, uint8_t tos,
             uint16_t length, uint16_t id, uint16_t flags_offset,
             uint8_t ttl, uint8_t protocol, uint16_t checksum,
             const uint8_t *src_addr, const uint8_t *dst_addr);

int pdu_ipv4_checksum(struct packet *p, int tag);

int pdu_ipv4_length(struct packet *p, int tag);

struct ipv4_ph *pdu_ipv4_ph(uint32_t src_addr, uint32_t dst_addr,
                            uint8_t protocol, uint16_t length);

#endif // __PDU_IPV4_H__
