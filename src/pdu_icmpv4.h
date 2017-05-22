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

#ifndef __PDU_ICMPV4_H__
#define __PDU_ICMPV4_H__

#include <stdint.h>
#include "packet.h"

// ICMPv4 header
struct icmpv4_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t body;
};

#define ICMPV4_H_SIZE 8

// ICMPv4 Types
#define ICMPV4_TYPE_ECHOREPLY 0
#define ICMPV4_TYPE_UNREACH   3
#define ICMPV4_TYPE_ECHO      8
#define ICMPV4_TYPE_EXCEEDED  11

// ICMPv4 Codes
#define ICMPV4_NO_CODE            0
#define ICMPV4_CODE_UNREACH_NET   0
#define ICMPV4_CODE_UNREACH_HOST  1
#define ICMPV4_CODE_UNREACH_PROTO 2
#define ICMPV4_CODE_UNREACH_PORT  3

int pdu_icmpv4(struct packet *p, uint8_t type, uint8_t code,
               uint16_t checksum, uint32_t body);

int pdu_icmpv4_echo(struct packet *p, uint16_t checksum,
                    uint16_t id, uint16_t seq_num);

int pdu_icmpv4_checksum(struct packet *p, int tag);

#endif // __PDU_ICMPV4_H__
