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
#include <arpa/inet.h>

#include "util.h"
#include "pdu_eth.h"
#include "pdu_ipv4.h"
#include "pdu_icmpv4.h"
#include "pdu_ipv6.h"
#include "pdu_icmpv6.h"
#include "protocol_numbers.h"
#include "buffer.h"

int get_icmp4_type(const uint8_t *b) {
    struct ipv4_hdr *rip = (struct ipv4_hdr *)(b + ETH_H_SIZE);
    if (rip->protocol != PROTO_ICMPV4) return -1;
    struct icmpv4_hdr *icmp = (struct icmpv4_hdr *)(b + ETH_H_SIZE + IPV4_H_SIZE);
    return icmp->type;
}

int get_icmp4_seqnum(const uint8_t *b) {
    struct ipv4_hdr *rip = (struct ipv4_hdr *)(b + ETH_H_SIZE);
    if (rip->protocol != PROTO_ICMPV4) return -1;
    struct icmpv4_hdr *icmp = (struct icmpv4_hdr *)(b + ETH_H_SIZE + IPV4_H_SIZE);
    return ntohl(icmp->body) & 0x0000ffff;
}

char get_ip4_ttl(const uint8_t *b) {
   struct ipv4_hdr *rip = (struct ipv4_hdr *)(b + ETH_H_SIZE);
   return rip->ttl;
}

char *get_ip4_src_addr(const uint8_t *b) {
   struct ipv4_hdr *rip = (struct ipv4_hdr *)(b + ETH_H_SIZE);
   struct sockaddr *src_ip = sockaddr_create((uint8_t *)&rip->src_addr, AF_INET);
   char *addr = sockaddr_to_str(src_ip);
   free(src_ip);
   return addr;
}

char *get_ip4_dst_addr(const uint8_t *b) {
   struct ipv4_hdr *rip = (struct ipv4_hdr *)(b + ETH_H_SIZE);
   struct sockaddr *dst_ip = sockaddr_create((uint8_t *)&rip->dst_addr, AF_INET);
   char *addr = sockaddr_to_str(dst_ip);
   free(dst_ip);
   return addr;
}

int get_icmp6_type(const uint8_t *b) {
    struct ipv6_hdr *rip = (struct ipv6_hdr *)(b + ETH_H_SIZE);
    if (rip->next_header != PROTO_ICMPV6) return -1;
    struct icmpv6_hdr *icmp = (struct icmpv6_hdr *)(b + ETH_H_SIZE + IPV6_H_SIZE);
    return icmp->type;
}

int get_icmp6_seqnum(const uint8_t *b) {
    struct ipv6_hdr *rip = (struct ipv6_hdr *)(b + ETH_H_SIZE);
    if (rip->next_header != PROTO_ICMPV6) return -1;
    struct icmpv6_hdr *icmp = (struct icmpv6_hdr *)(b + ETH_H_SIZE + IPV6_H_SIZE);
    return ntohl(icmp->body) & 0x0000ffff;
}

char get_ip6_ttl(const uint8_t *b) {
   struct ipv6_hdr *rip = (struct ipv6_hdr *)(b + ETH_H_SIZE);
   return rip->hop_limit;
}

char *get_ip6_src_addr(const uint8_t *b) {
   struct ipv6_hdr *rip = (struct ipv6_hdr *)(b + ETH_H_SIZE);
   struct sockaddr *src_ip = sockaddr_create((uint8_t *)&rip->src_addr, AF_INET6);
   char *addr = sockaddr_to_str(src_ip);
   free(src_ip);
   return addr;
}

char *get_ip6_dst_addr(const uint8_t *b) {
   struct ipv6_hdr *rip = (struct ipv6_hdr *)(b + ETH_H_SIZE);
   struct sockaddr *dst_ip = sockaddr_create((uint8_t *)&rip->dst_addr, AF_INET6);
   char *addr = sockaddr_to_str(dst_ip);
   free(dst_ip);
   return addr;
}
