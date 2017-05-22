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

#ifndef __PDU_ARP_H__
#define __PDU_ARP_H__

#include <stdint.h>
#include "packet.h"

#define ARP_H_SIZE 28
#define ARP_OP_REQ 1

#define ARP_HW_ADDR_SIZE 6
#define ARP_IP_ADDR_SIZE 4
#define ARP_HW_TYPE_ETH  1
#define ARP_IP_TYPE_IPV4 0x0800

struct arp_hdr {
    uint16_t hw_type;
    uint16_t ip_type;
    uint8_t  hw_len;
    uint8_t  ip_len;
    uint16_t opcode;
    uint8_t  sender_hw[ARP_HW_ADDR_SIZE];
    uint8_t  sender_ip[ARP_IP_ADDR_SIZE];
    uint8_t  target_hw[ARP_HW_ADDR_SIZE];
    uint8_t  target_ip[ARP_IP_ADDR_SIZE];
};

int pdu_arp_request(struct packet *p, const uint8_t *sender_hw,
                    const uint8_t *sender_ip, const uint8_t *target_ip);

#endif // __PDU_ARP_H__
