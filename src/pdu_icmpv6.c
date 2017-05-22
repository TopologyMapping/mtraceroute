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

#include "pdu_data.h"
#include "pdu_ipv6.h"
#include "pdu_icmpv6.h"
#include "checksum.h"
#include "protocol_numbers.h"

int pdu_icmpv6(struct packet *p, uint8_t type, uint8_t code,
               uint16_t checksum, uint32_t body) {

    struct icmpv6_hdr hdr;
    memset(&hdr, 0, ICMPV6_H_SIZE);

    hdr.type     = type;
    hdr.code     = code;
    hdr.checksum = checksum;
    hdr.body     = body;

    uint8_t tag = packet_block_append(p, PACKET_BLOCK_ICMPV6, &hdr,
                                      ICMPV6_H_SIZE);

    return tag;
}

int pdu_icmpv6_echo(struct packet *p, uint16_t checksum,
                    uint16_t id, uint16_t seq_num) {

    uint32_t body = htonl((id << 16) + seq_num);
    return pdu_icmpv6(p, ICMPV6_TYPE_ECHO, ICMPV6_NO_CODE, checksum, body);
}

int pdu_icmpv6_checksum(struct packet *p, int tag, int ipv6_tag) {

    struct packet_block *icmpb = packet_block_get(p, tag);
    if (icmpb == NULL || icmpb->type != PACKET_BLOCK_ICMPV6) return -1;

    struct icmpv6_hdr *hdr = (struct icmpv6_hdr *)&p->buf[icmpb->position];

    // Get the IPv6 block
    struct packet_block *ipv6b = packet_block_get(p, ipv6_tag);
    if (ipv6b == NULL || ipv6b->type != PACKET_BLOCK_IPV6) return -1;

    struct ipv6_hdr *ipv6_hdr = (struct ipv6_hdr *)&p->buf[ipv6b->position];
    
    // Length of the packet starting from the ICMPv6 header
    uint32_t len = p->length - icmpb->position;

    // The ICMPv6 checksum includes an 40 bytes IPv6 pseudo-header composed of
    // the source and destination addresses, followed by 4 bytes with the
    // ICMPv6 header + data length, followed by 3 zeroed bytes, followed
    // by one byte with PROTO_ICMPV6 (58)
    uint32_t pseudo_h_len = 40;
    uint32_t chksum_data_size = pseudo_h_len + len;
    uint8_t *chksum_data = malloc(chksum_data_size);
    if (chksum_data == NULL) return -1;

    memset(chksum_data, 0, chksum_data_size);

    uint32_t len_network = htonl(len);
    uint8_t nh = PROTO_ICMPV6;
    
    // Copy the pseudo-header information
    memcpy(chksum_data, &ipv6_hdr->src_addr, 16);
    memcpy(&chksum_data[16], &ipv6_hdr->dst_addr, 16);
    memcpy(&chksum_data[32], &len_network, 4);
    memcpy(&chksum_data[39], &nh, 1);   

    // Make sure the checksum field is 0 before calculating the checksum
    hdr->checksum = 0;

    // Copy the packet starting from the ICMPv6 header
    memcpy(&chksum_data[40], hdr, len);

    hdr->checksum = checksum((uint16_t *)chksum_data, chksum_data_size);

    free(chksum_data);

    return 0;
}

int pdu_icmpv6_neighbor_sol(struct packet *p, const uint8_t *target,
                            const uint8_t *mac_src) {
    
    uint8_t icmp_tag = pdu_icmpv6(p, ICMPV6_TYPE_NEIGHSOL,
                                     ICMPV6_NO_CODE, 0, 0);
    if (icmp_tag == -1) return -1;

    uint8_t *icmp_data = malloc(16 + 8);
    memset(icmp_data, 0, 16 + 8);

    memcpy(icmp_data, target, 16);
    icmp_data[16] = 0x01;
    icmp_data[17] = 0x01;
    memcpy(&icmp_data[18], mac_src, 6);

    pdu_data(p, icmp_data, 16 + 8);

    free(icmp_data);

    return icmp_tag;
}
