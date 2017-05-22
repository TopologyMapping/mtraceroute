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

#ifndef __PDU_ETH_H__
#define __PDU_ETH_H__

#include <stdint.h>
#include "packet.h"

#define ETH_H_SIZE   14
#define ETH_ADDR_LEN 6

// EtherTypes
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPV6 0x86dd

// Ethernet II (DIX) header
struct eth_hdr {
    uint8_t  dst_addr[ETH_ADDR_LEN];
    uint8_t  src_addr[ETH_ADDR_LEN];
    uint16_t type;
};

int pdu_eth(struct packet *p, const uint8_t *dst_addr,
            const uint8_t *src_addr, uint16_t type);

int pdu_eth_arp(struct packet *p, const uint8_t *src_addr);

int pdu_eth_ipv4(struct packet *p, const uint8_t *dst_addr,
                 const uint8_t *src_addr);

int pdu_eth_ipv6(struct packet *p, const uint8_t *dst_addr,
                 const uint8_t *src_addr);

int pdu_eth_ipv6_mcast(struct packet *p, const uint8_t *dst,
                       const uint8_t *src);

#endif // __PDU_ETH_H__
