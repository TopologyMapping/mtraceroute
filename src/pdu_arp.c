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

#include <string.h>
#include <arpa/inet.h>

#include "pdu_arp.h"

int pdu_arp_request(struct packet *p, const uint8_t *sender_hw,
                    const uint8_t *sender_ip, const uint8_t *target_ip) {

    struct arp_hdr hdr;
    memset(&hdr, 0, ARP_H_SIZE);

    hdr.hw_type = htons(ARP_HW_TYPE_ETH);
    hdr.ip_type = htons(ARP_IP_TYPE_IPV4);
    hdr.hw_len  = ARP_HW_ADDR_SIZE;
    hdr.ip_len  = ARP_IP_ADDR_SIZE;
    hdr.opcode  = htons(ARP_OP_REQ);

    memcpy(&(hdr.sender_hw), sender_hw, ARP_HW_ADDR_SIZE);
    memcpy(&(hdr.sender_ip), sender_ip, ARP_IP_ADDR_SIZE);
    memcpy(&(hdr.target_ip), target_ip, ARP_IP_ADDR_SIZE);

    uint8_t tag = packet_block_append(p, PACKET_BLOCK_ARP, &hdr,
                                      ARP_H_SIZE);
    
    return tag;
};
