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

#ifndef __PDU_ICMPV6_H__
#define __PDU_ICMPV6_H__

#include <stdint.h>
#include "packet.h"

// ICMPv6 header
struct icmpv6_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t body;
};

#define ICMPV6_H_SIZE 8

// ICMPv6 Types
#define ICMPV6_TYPE_UNREACH   1
#define ICMPV6_TYPE_EXCEEDED  3
#define ICMPV6_TYPE_ECHO      128
#define ICMPV6_TYPE_ECHOREPLY 129
#define ICMPV6_TYPE_NEIGHSOL  135
#define ICMPV6_TYPE_NEIGHADV  136

// ICMPv6 Codes
#define ICMPV6_NO_CODE 0

int pdu_icmpv6(struct packet *p, uint8_t type, uint8_t code,
               uint16_t checksum, uint32_t body);

int pdu_icmpv6_echo(struct packet *p, uint16_t checksum,
                    uint16_t id, uint16_t seq_num);

int pdu_icmpv6_checksum(struct packet *p, int tag, int ipv6_tag);

int pdu_icmpv6_neighbor_sol(struct packet *p, const uint8_t *target,
                            const uint8_t *mac_src);

#endif // __PDU_ICMPV6_H__
