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

#include "pdu_eth.h"

int pdu_eth(struct packet *p, const uint8_t *dst_addr,
            const uint8_t *src_addr, uint16_t type) {

    struct eth_hdr hdr;
    memset(&hdr, 0, ETH_H_SIZE);

    // Allow dst_addr and src_addr == NULL
    if (dst_addr != NULL) memcpy(hdr.dst_addr, dst_addr, ETH_ADDR_LEN);
    if (src_addr != NULL) memcpy(hdr.src_addr, src_addr, ETH_ADDR_LEN);
    
    hdr.type = htons(type);

    uint8_t tag = packet_block_append(p, PACKET_BLOCK_ETHERNET, &hdr,
                                      ETH_H_SIZE);

    return tag;
}

int pdu_eth_arp(struct packet *p, const uint8_t *src_addr) {
    uint8_t broadcast[ETH_ADDR_LEN];
    memset(broadcast, 0xff, ETH_ADDR_LEN);
    return pdu_eth(p, broadcast, src_addr, ETH_TYPE_ARP);
}

int pdu_eth_ipv4(struct packet *p, const uint8_t *dst_addr,
                    const uint8_t *src_addr) {
    return pdu_eth(p, dst_addr, src_addr, ETH_TYPE_IPV4);
}

int pdu_eth_ipv6(struct packet *p, const uint8_t *dst_addr,
                 const uint8_t *src_addr) {
    return pdu_eth(p, dst_addr, src_addr, ETH_TYPE_IPV6);
}

int pdu_eth_ipv6_mcast(struct packet *p, const uint8_t *dst,
                       const uint8_t *src) {
    uint8_t dst_addr[ETH_ADDR_LEN];
    dst_addr[0] = 0x33;
    dst_addr[1] = 0x33;

    // Copy the last four bits of the multicast IPv6 address
    memcpy(&dst_addr[2], &dst[12], 4);

    return pdu_eth(p, dst_addr, src, ETH_TYPE_IPV6);
}
