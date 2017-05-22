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

#include "pdu_data.h"
#include "pdu_eth.h"
#include "pdu_ipv4.h"
#include "pdu_ipv6.h"
#include "pdu_icmpv4.h"
#include "pdu_icmpv6.h"
#include "pdu_udp.h"
#include "pdu_tcp.h"

#include "util.h"
#include "protocol_numbers.h"
#include "packet_helper.h"

struct packet *packet_helper_echo4(const uint8_t *eth_dst, const uint8_t *eth_src,
                                   const uint8_t *ip_src, const uint8_t *ip_dst,
                                   uint8_t ttl, uint16_t ip_id, uint16_t icmp_id,
                                   uint16_t seq_num, uint16_t checksum) {

    struct packet *p = packet_create();

    uint8_t eth_tag = pdu_eth_ipv4(p, eth_dst, eth_src);

    uint8_t ip_tag = pdu_ipv4(p, IPV4_IHL, 0, 0, ip_id, 0, ttl,
                              PROTO_ICMPV4, 0, ip_src, ip_dst);
    
    uint8_t icmp_tag = pdu_icmpv4_echo(p, 0, icmp_id, seq_num);

    // Add 2 bytes data so to exchange it with
    // the checksum to keep the flow id fixed
    uint16_t data = htons(checksum);
    uint8_t data_tag = pdu_data(p, (uint8_t *)&data, 2);

    // Finalize the packet
    pdu_ipv4_length(p, ip_tag);
    pdu_ipv4_checksum(p, ip_tag);
    pdu_icmpv4_checksum(p, icmp_tag);

    // Exchange the 2 bytes data with the checksum
    uint8_t *data_buf = (uint8_t *)packet_buf_get_by_tag(p, data_tag);
    struct icmpv4_hdr *icmp_buf = (struct icmpv4_hdr *)
                                  packet_buf_get_by_tag(p, icmp_tag);
    buff_swap(data_buf, (uint8_t *)&icmp_buf->checksum, 2);

    return p;        
}

struct packet *packet_helper_echo6(const uint8_t *eth_dst, const uint8_t *eth_src,
                                   const uint8_t *ip_src, const uint8_t *ip_dst,
                                   uint8_t traffic_class, uint32_t flow_label,
                                   uint8_t hop_limit, uint16_t icmp_id, uint16_t seq_num,
                                   uint16_t checksum) {

    struct packet *p = packet_create();

    uint8_t eth_tag = pdu_eth_ipv6(p, eth_dst, eth_src);

    uint8_t ip_tag = pdu_ipv6(p, traffic_class, flow_label, 0, 0, hop_limit, ip_src, ip_dst);

    uint8_t icmp_tag = pdu_icmpv6_echo(p, 0, icmp_id, seq_num);

    // Add 2 bytes data so to exchange it with
    // the checksum to keep the flow id fixed
    uint16_t data = htons(checksum);
    uint8_t data_tag = pdu_data(p, (uint8_t *)&data, 2);

    // Finalize the packet
    pdu_ipv6_length(p, ip_tag);
    pdu_ipv6_next_header(p, ip_tag);
    pdu_icmpv6_checksum(p, icmp_tag, ip_tag);

    // Exchange the 2 bytes data with the checksum
    uint8_t *data_buf = (uint8_t *)packet_buf_get_by_tag(p, data_tag);
    struct icmpv6_hdr *icmp_buf = (struct icmpv6_hdr *)
                                  packet_buf_get_by_tag(p, icmp_tag);
    buff_swap(data_buf, (uint8_t *)&icmp_buf->checksum, 2);

    return p;        
}

struct packet *packet_helper_udp4(const uint8_t *eth_dst, const uint8_t *eth_src,
                                  const uint8_t *ip_src, const uint8_t *ip_dst,
                                  uint8_t ttl, uint16_t ip_id, uint16_t src_port,
                                  uint16_t dst_port, uint16_t checksum) {

    struct packet *p = packet_create();

    uint8_t eth_tag = pdu_eth_ipv4(p, eth_dst, eth_src);

    uint8_t ip_tag = pdu_ipv4(p, IPV4_IHL, 0, 0, ip_id, 0, ttl,
                                PROTO_UDP, 0, ip_src, ip_dst);

    uint8_t udp_tag = pdu_udp(p, src_port, dst_port, 0, 0);

    uint8_t data_tag = 0;
    if (checksum != 0) {
        // Add 2 bytes data so to exchange it with the checksum
        uint16_t data = htons(checksum);
        data_tag = pdu_data(p, (uint8_t *)&data, 2);
    }

    pdu_ipv4_length(p, ip_tag);
    pdu_ipv4_checksum(p, ip_tag);
    pdu_udp_length(p, udp_tag);
    pdu_udp_checksum(p, udp_tag, ip_tag);

    if (checksum != 0) {
        // Exchange the 2 bytes data with the checksum
        uint8_t *data_buf = (uint8_t *)packet_buf_get_by_tag(p, data_tag);
        struct udp_hdr *udp_buf = (struct udp_hdr *)
                                   packet_buf_get_by_tag(p, udp_tag);
        buff_swap(data_buf, (uint8_t *)&udp_buf->checksum, 2);
    }

    return p;
}

struct packet *packet_helper_udp6(const uint8_t *eth_dst, const uint8_t *eth_src,
                                  const uint8_t *ip_src, const uint8_t *ip_dst,
                                  uint8_t traffic_class, uint32_t flow_label,
                                  uint8_t hop_limit, uint16_t src_port,
                                  uint16_t dst_port, uint16_t checksum) {

    struct packet *p = packet_create();

    uint8_t eth_tag = pdu_eth_ipv6(p, eth_dst, eth_src);

    uint8_t ip_tag = pdu_ipv6(p, traffic_class, flow_label, 0, 0, hop_limit, ip_src, ip_dst);

    uint8_t udp_tag = pdu_udp(p, src_port, dst_port, 0, 0);

    uint8_t data_tag = 0;
    if (checksum != 0) {
        // Add 2 bytes data so to exchange it with the checksum
        uint16_t data = htons(checksum);
        data_tag = pdu_data(p, (uint8_t *)&data, 2);
    }

    pdu_ipv6_length(p, ip_tag);
    pdu_ipv6_next_header(p, ip_tag);
    pdu_udp_length(p, udp_tag);
    pdu_udp_checksum(p, udp_tag, ip_tag);

    if (checksum != 0) {
        // Exchange the 2 bytes data with the checksum
        uint8_t *data_buf = (uint8_t *)packet_buf_get_by_tag(p, data_tag);
        struct udp_hdr *udp_buf = (struct udp_hdr *)
                                   packet_buf_get_by_tag(p, udp_tag);
        buff_swap(data_buf, (uint8_t *)&udp_buf->checksum, 2);
    }

    return p;
}

struct packet *packet_helper_tcp4(const uint8_t *eth_dst, const uint8_t *eth_src,
                                  const uint8_t *ip_src, const uint8_t *ip_dst,
                                  uint8_t ttl, uint16_t ip_id, uint16_t src_port,
                                  uint16_t dst_port, uint32_t seq_numb) {

    struct packet *p = packet_create();

    uint8_t eth_tag = pdu_eth_ipv4(p, eth_dst, eth_src);

    uint8_t ip_tag = pdu_ipv4(p, IPV4_IHL, 0, 0, ip_id, 0, ttl,
                              PROTO_TCP, 0, ip_src, ip_dst);

    uint8_t tcp_tag = pdu_tcp(p, src_port, dst_port, seq_numb, 0, TCP_DATA_OFFSET, TCP_SYN, 0, 0, 0);

    pdu_ipv4_length(p, ip_tag);
    pdu_ipv4_checksum(p, ip_tag);
    pdu_tcp_checksum(p, tcp_tag, ip_tag);

    return p;
}

struct packet *packet_helper_tcp6(const uint8_t *eth_dst, const uint8_t *eth_src,
                                  const uint8_t *ip_src, const uint8_t *ip_dst,
                                  uint8_t traffic_class, uint32_t flow_label,
                                  uint8_t hop_limit, uint16_t src_port,
                                  uint16_t dst_port, uint32_t seq_numb) {

    struct packet *p = packet_create();

    uint8_t eth_tag = pdu_eth_ipv6(p, eth_dst, eth_src);

    uint8_t ip_tag = pdu_ipv6(p, traffic_class, flow_label, 0, 0, hop_limit, ip_src, ip_dst);

    uint8_t tcp_tag = pdu_tcp(p, src_port, dst_port, seq_numb, 0, TCP_DATA_OFFSET, TCP_SYN, 0, 0, 0);

    pdu_ipv6_length(p, ip_tag);
    pdu_ipv6_next_header(p, ip_tag);
    pdu_tcp_checksum(p, tcp_tag, ip_tag);

    return p;
}
