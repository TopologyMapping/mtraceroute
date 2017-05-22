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
#include <stdint.h>
#include <string.h>

#include "packet.h"
#include "pdu_eth.h"
#include "pdu_arp.h"
#include "pdu_ipv6.h"
#include "pdu_icmpv6.h"
#include "pdu_data.h"

#include "iface.h"
#include "util.h"
#include "mt_nd.h"

#include <stdio.h>

static struct packet *neighbor6_packet(const uint8_t *mac_src,
                                       const uint8_t *src_addr,
                                       const uint8_t *dst_addr) {

    // Create the solicited-node multicast address (RFC 4291)
    // It take the last 24 bits of the destination address
    struct addr *mdst = addr_create_from_str(ADDR_IPV6, "FF02::1:FF00:0");
    memcpy(&mdst->addr[13], &dst_addr[13], 3);

    struct packet *p = packet_create();

    uint8_t eth_tag = pdu_eth_ipv6_mcast(p, mdst->addr, mac_src);

    uint8_t ipv6_tag = pdu_ipv6(p, 0, 0, 0, 0, IPV6_HOP_LIMIT_ND,
                                   src_addr, mdst->addr);

    uint8_t icmp_tag = pdu_icmpv6_neighbor_sol(p, dst_addr, mac_src);

    pdu_ipv6_length(p, ipv6_tag);
    pdu_ipv6_next_header(p, ipv6_tag);
    pdu_icmpv6_checksum(p, icmp_tag, ipv6_tag);

    addr_destroy(mdst);

    return p;
}

static int neighbor4_match(const uint8_t *probe, uint32_t probe_len,
                           const uint8_t *resp, uint32_t resp_len) {

    struct eth_hdr *resp_eth_hdr = (struct eth_hdr *)resp;

    if (ntohs(resp_eth_hdr->type) == ETH_TYPE_ARP) {
        
        struct arp_hdr *p_arp = (struct arp_hdr *)(probe + ETH_H_SIZE);
        struct arp_hdr *r_arp = (struct arp_hdr *)(resp + ETH_H_SIZE);

        if (buff_cmp(p_arp->sender_ip, r_arp->target_ip, 4) == 0 &&
            buff_cmp(r_arp->sender_ip, p_arp->target_ip, 4) == 0) {
            return 1;
        }
    }

    return 0;
}

static struct addr *neighbor4(struct mt *a, const struct addr *addr,
                              int if_index) {

    struct addr *if_hw = iface_hw_addr(if_index);
    if (if_hw == NULL) return NULL;

    struct addr *if_ip = iface_ip_addr(if_index, addr->type);
    if (if_ip == NULL) {
        addr_destroy(if_hw);
        return NULL;
    }

    struct packet *p = packet_create();

    pdu_eth_arp(p, if_hw->addr);
    pdu_arp_request(p, if_hw->addr, if_ip->addr, addr->addr);

    mt_send(a, if_index, p->buf, p->length, &neighbor4_match);
    mt_wait(a, if_index);

    struct addr *resp = NULL;

    struct interface *i = mt_get_interface(a, if_index);
    while (i->probes->count > 0) {
        struct probe *probe = (struct probe *)list_pop(i->probes);
        if (probe->response_len > 0) {
            struct arp_hdr *r_arp = (struct arp_hdr *)(probe->response + ETH_H_SIZE);
            resp = addr_create(ADDR_ETHERNET, r_arp->sender_hw);
        }
        probe_destroy(probe);
    }

    addr_destroy(if_hw);
    addr_destroy(if_ip);
    packet_destroy(p);

    return resp;
}

static int neighbor6_match(const uint8_t *probe, uint32_t probe_len,
                           const uint8_t *resp, uint32_t resp_len) {

    struct eth_hdr *resp_eth_hdr = (struct eth_hdr *)resp;

    if (ntohs(resp_eth_hdr->type) == ETH_TYPE_IPV6) {

        uint32_t icmp_pos = ETH_H_SIZE + IPV6_H_SIZE;
        uint32_t tpos = icmp_pos + ICMPV6_H_SIZE;

        struct icmpv6_hdr *icmp_r = (struct icmpv6_hdr *)(resp + icmp_pos);

        uint8_t *p_targ = (uint8_t *)(probe + tpos);
        uint8_t *r_targ = (uint8_t *)(resp + tpos);

        if (icmp_r->type == ICMPV6_TYPE_NEIGHADV &&
            buff_cmp(p_targ, r_targ, 16) == 0) {
            return 1;
        }
    }

    return 0;
}

static struct addr *neighbor6(struct mt *a, const struct addr *addr,
                              int if_index) {

    struct addr *if_hw = iface_hw_addr(if_index);
    if (if_hw == NULL) return NULL;

    struct addr *if_ip = iface_ip_addr(if_index, addr->type);
    if (if_ip == NULL) {
        addr_destroy(if_hw);
        return NULL;
    }

    struct packet *p = neighbor6_packet(if_hw->addr, if_ip->addr, addr->addr);

    mt_send(a, if_index, p->buf, p->length, &neighbor6_match);
    mt_wait(a, if_index);

    struct addr *resp = NULL;

    struct interface *i = mt_get_interface(a, if_index);
    while (i->probes->count > 0) {
        struct probe *probe = (struct probe *)list_pop(i->probes);
        if (probe->response_len > 0) {

            uint32_t icmp_opt_pos = ETH_H_SIZE + IPV6_H_SIZE +
                                    ICMPV6_H_SIZE + 16;

            uint8_t *icmp_opt = (uint8_t *)(probe->response + icmp_opt_pos);

            resp = addr_create(ADDR_ETHERNET, icmp_opt+2);
        }
        probe_destroy(probe);
    }

    addr_destroy(if_hw);
    addr_destroy(if_ip);
    packet_destroy(p);

    return resp;
}

struct addr *mt_nd(struct mt *a, const struct addr *addr, int if_index) {
    if (addr->type == ADDR_IPV4) {
        return neighbor4(a, addr, if_index);
    } else if (addr->type == ADDR_IPV6) {
        return neighbor6(a, addr, if_index);
    }
    return NULL;
}
