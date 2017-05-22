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

#ifndef __PDU_TCP_H__
#define __PDU_TCP_H__

#include <stdint.h>
#include "packet.h"

#define TCP_H_SIZE      20
#define TCP_DATA_OFFSET 5 // number of 32 bits words (without options)
#define TCP_FLAGS_MASK  0x3f

// TCP flags
#define TCP_URG 0x20
#define TCP_ACK 0x10
#define TCP_PSH 0x8
#define TCP_RST 0x4
#define TCP_SYN 0x2
#define TCP_FIN 0x1

// TCP header
struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_numb;
    uint32_t ack_numb;
    uint8_t  offset;
    uint8_t  flags;
    uint16_t win_size;
    uint16_t checksum;
    uint16_t urg_ptr;
};

int pdu_tcp(struct packet *p, uint16_t src_port, uint16_t dst_port,
            uint32_t seq_numb, uint32_t ack_numb, uint8_t offset,
            uint8_t flags, uint16_t win_size, uint16_t checksum,
            uint16_t urg_ptr);

int pdu_tcp_checksum(struct packet *p, int tag, int ip_tag);

#endif // __PDU_TCP_H__
