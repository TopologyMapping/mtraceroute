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

#include "match.h"
#include "pdu_eth.h"
#include "pdu_ipv4.h"
#include "pdu_ipv6.h"
#include "pdu_icmpv4.h"
#include "pdu_icmpv6.h"
#include "pdu_udp.h"
#include "pdu_tcp.h"
#include "protocol_numbers.h"

static int get_proto6(const uint8_t *b, uint32_t blen) {
    struct eth_hdr *reth = (struct eth_hdr *)b;
    if (ntohs(reth->type) != ETH_TYPE_IPV6) return -1;
    struct ipv6_hdr *rip = (struct ipv6_hdr *)(b + ETH_H_SIZE);
    return rip->next_header;
}

static int get_proto4(const uint8_t *b, uint32_t blen) {
    struct eth_hdr *reth = (struct eth_hdr *)b;
    if (ntohs(reth->type) != ETH_TYPE_IPV4) return -1;
    struct ipv4_hdr *rip = (struct ipv4_hdr *)(b + ETH_H_SIZE);
    return rip->protocol;
}

static const uint8_t *get_transport4(const uint8_t *b, uint32_t blen) {
    return b + IPV4_H_SIZE;
}

static const uint8_t *get_transport6(const uint8_t *b, uint32_t blen) {
    return b + IPV6_H_SIZE;
}

static const uint8_t *get_inner4(const uint8_t *b, uint32_t blen) {
    return get_transport4(b + ICMPV4_H_SIZE, blen - ICMPV4_H_SIZE);
}

static const uint8_t *get_inner6(const uint8_t *b, uint32_t blen) {
    return get_transport6(b + ICMPV6_H_SIZE, blen - ICMPV6_H_SIZE);
}

/* Match for ICMPv4 probe
 *
 */
int match_icmp4(const uint8_t *p, uint32_t plen,
                const uint8_t *r, uint32_t rlen) {

    if (get_proto4(r, rlen) != PROTO_ICMPV4) return 0;

    const uint8_t *player4 = get_transport4(p + ETH_H_SIZE, plen - ETH_H_SIZE);
    const uint8_t *rlayer4 = get_transport4(r + ETH_H_SIZE, rlen - ETH_H_SIZE);
    struct icmpv4_hdr *picmp = (struct icmpv4_hdr *)player4;
    struct icmpv4_hdr *ricmp = (struct icmpv4_hdr *)rlayer4;

    if (ricmp->type == ICMPV4_TYPE_EXCEEDED || ricmp->type == ICMPV4_TYPE_UNREACH) {
        struct icmpv4_hdr *inner = (struct icmpv4_hdr *)get_inner4(rlayer4, rlen);
        if (picmp->body == inner->body) return 1;
    }

    // Match an echo reply message
    if (ricmp->type == ICMPV4_TYPE_ECHOREPLY) {
        if (picmp->body == ricmp->body) return 1;
    }

    return 0;
}

/* Match for ICMPv6 probe
 *
 */
int match_icmp6(const uint8_t *p, uint32_t plen,
                const uint8_t *r, uint32_t rlen) {

    if (get_proto6(r, rlen) != PROTO_ICMPV6) return 0;

    const uint8_t *player4 = get_transport6(p + ETH_H_SIZE, plen - ETH_H_SIZE);
    const uint8_t *rlayer4 = get_transport6(r + ETH_H_SIZE, rlen - ETH_H_SIZE);
    struct icmpv6_hdr *picmp = (struct icmpv6_hdr *)player4;
    struct icmpv6_hdr *ricmp = (struct icmpv6_hdr *)rlayer4;

    if (ricmp->type == ICMPV6_TYPE_EXCEEDED || ricmp->type == ICMPV6_TYPE_UNREACH) {
        struct icmpv6_hdr *inner = (struct icmpv6_hdr *)get_inner6(rlayer4, rlen);
        if (picmp->body == inner->body) return 1;
    }

    // Match an echo reply message
    if (ricmp->type == ICMPV6_TYPE_ECHOREPLY) {
        if (picmp->body == ricmp->body) return 1;
    }

    return 0;
}

/* Match for UDP4 probe
 *
 */
int match_udp4(const uint8_t *p, uint32_t plen,
               const uint8_t *r, uint32_t rlen) {

    if (get_proto4(r, rlen) != PROTO_ICMPV4) return 0;

    const uint8_t *player4 = get_transport4(p + ETH_H_SIZE, plen - ETH_H_SIZE);
    const uint8_t *rlayer4 = get_transport4(r + ETH_H_SIZE, rlen - ETH_H_SIZE);
    struct udp_hdr *pudp = (struct udp_hdr *)player4;
    struct icmpv4_hdr *ricmp = (struct icmpv4_hdr *)rlayer4;

    if (ricmp->type == ICMPV4_TYPE_EXCEEDED || ricmp->type == ICMPV4_TYPE_UNREACH) {
        struct udp_hdr *inner = (struct udp_hdr *)get_inner4(rlayer4, rlen);
        if (pudp->src_port == inner->src_port &&
            pudp->dst_port == inner->dst_port &&
            pudp->checksum == inner->checksum) return 1;
    }

    return 0;
}

/* Match for UDP6 probe
 *
 */
int match_udp6(const uint8_t *p, uint32_t plen,
               const uint8_t *r, uint32_t rlen) {

    if (get_proto6(r, rlen) != PROTO_ICMPV6) return 0;

    const uint8_t *player4 = get_transport6(p + ETH_H_SIZE, plen - ETH_H_SIZE);
    const uint8_t *rlayer4 = get_transport6(r + ETH_H_SIZE, rlen - ETH_H_SIZE);
    struct udp_hdr *pudp = (struct udp_hdr *)player4;
    struct icmpv6_hdr *ricmp = (struct icmpv6_hdr *)rlayer4;

    if (ricmp->type == ICMPV6_TYPE_EXCEEDED || ricmp->type == ICMPV6_TYPE_UNREACH) {
        struct udp_hdr *inner = (struct udp_hdr *)get_inner6(rlayer4, rlen);
        if (pudp->src_port == inner->src_port &&
            pudp->dst_port == inner->dst_port &&
            pudp->checksum == inner->checksum) return 1;
    }

    return 0;
}

/* Match for TCP4 probe
 *
 */
int match_tcp4(const uint8_t *p, uint32_t plen,
               const uint8_t *r, uint32_t rlen) {

    int proto = get_proto4(r, rlen);
    if (proto != PROTO_ICMPV4 && proto != PROTO_TCP) return 0;

    if (proto == PROTO_ICMPV4) {
        const uint8_t *player4 = get_transport4(p + ETH_H_SIZE, plen - ETH_H_SIZE);
        const uint8_t *rlayer4 = get_transport4(r + ETH_H_SIZE, rlen - ETH_H_SIZE);
        struct tcp_hdr *ptcp = (struct tcp_hdr *)player4;
        struct icmpv4_hdr *ricmp = (struct icmpv4_hdr *)rlayer4;

        if (ricmp->type == ICMPV4_TYPE_EXCEEDED || ricmp->type == ICMPV4_TYPE_UNREACH) {
            struct tcp_hdr *inner = (struct tcp_hdr *)get_inner4(rlayer4, rlen);
            if (ptcp->seq_numb == inner->seq_numb &&
                ptcp->src_port == inner->src_port &&
                ptcp->dst_port == inner->dst_port) return 1;
        }
    }

    return 0;
}

/* Match for TCP6 probe
 *
 */
int match_tcp6(const uint8_t *p, uint32_t plen,
               const uint8_t *r, uint32_t rlen) {

    int proto = get_proto6(r, rlen);
    if (proto != PROTO_ICMPV6 && proto != PROTO_TCP) return 0;

    if (proto == PROTO_ICMPV6) {
        const uint8_t *player4 = get_transport6(p + ETH_H_SIZE, plen - ETH_H_SIZE);
        const uint8_t *rlayer4 = get_transport6(r + ETH_H_SIZE, rlen - ETH_H_SIZE);
        struct tcp_hdr *ptcp = (struct tcp_hdr *)player4;
        struct icmpv6_hdr *ricmp = (struct icmpv6_hdr *)rlayer4;

        if (ricmp->type == ICMPV6_TYPE_EXCEEDED || ricmp->type == ICMPV6_TYPE_UNREACH) {
            struct tcp_hdr *inner = (struct tcp_hdr *)get_inner6(rlayer4, rlen);
            if (ptcp->seq_numb == inner->seq_numb &&
                ptcp->src_port == inner->src_port &&
                ptcp->dst_port == inner->dst_port) return 1;
        }
    }

    return 0;
}
