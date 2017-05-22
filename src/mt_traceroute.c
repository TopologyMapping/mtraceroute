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
#include <stdio.h>
#include <arpa/inet.h>

#include "args.h"
#include "packet.h"
#include "pdu_eth.h"
#include "pdu_ipv4.h"
#include "pdu_icmpv4.h"
#include "pdu_ipv6.h"
#include "pdu_icmpv6.h"
#include "pdu_udp.h"
#include "pdu_tcp.h"
#include "protocol_numbers.h"
#include "packet_helper.h"
#include "iface.h"
#include "probe.h"
#include "util.h"
#include "match.h"
#include "buffer.h"
#include "mt_traceroute.h"

#define IP_ID     54321
#define CHECKSUM  54321
#define ICMP_ID   54321
#define DPORT     33435
#define SPORT     43435
#define TCP_DPORT 80

static void traceroute4_print(const struct probe *p) {
    if (p->response_len == 0) {
        printf("*\n");
        return;
    }

    char *addr = get_ip4_src_addr(p->response);
    char *time = timeval_diff_to_str(&p->response_time, &p->sent_time);
    int ttl = get_ip4_ttl(p->probe);
    printf("%2d  %s  %s ms\n", ttl, addr, time);
    free(addr);
    free(time);
}

static void traceroute6_print(const struct probe *p) {
    if (p->response_len == 0) {
        printf("*\n");
        return;
    }

    char *addr = get_ip6_src_addr(p->response);
    char *time = timeval_diff_to_str(&p->response_time, &p->sent_time);
    int ttl = get_ip6_ttl(p->probe);
    printf("%2d  %s  %s ms\n", ttl, addr, time);
    free(addr);
    free(time);
}

static int traceroute(struct mt *a, const struct dst *dst, int probe_type,
                      int max_ttl, int at_once) {
    int ttl = 1;

    while (ttl <= max_ttl) {
        int pn = 0;
        for (pn = 0; pn < at_once && ttl <= max_ttl; pn++, ttl++) {

            struct packet *p = NULL;

            if (dst->ip_dst->type == ADDR_IPV4) {
                if (probe_type == METHOD_ICMP) {
                    p = packet_helper_echo4(dst->mac_dst->addr, dst->mac_src->addr,
                                        dst->ip_src->addr, dst->ip_dst->addr, ttl,
                                        IP_ID + ttl, ICMP_ID, ttl, CHECKSUM);
                    mt_send(a, dst->if_index, p->buf, p->length, &match_icmp4);
                } else if (probe_type == METHOD_UDP) {
                    p = packet_helper_udp4(dst->mac_dst->addr, dst->mac_src->addr,
                                       dst->ip_src->addr, dst->ip_dst->addr, ttl,
                                       IP_ID + ttl, SPORT, DPORT, ttl);
                    mt_send(a, dst->if_index, p->buf, p->length, &match_udp4);
                } else if (probe_type == METHOD_TCP) {
                    p = packet_helper_tcp4(dst->mac_dst->addr, dst->mac_src->addr,
                                       dst->ip_src->addr, dst->ip_dst->addr, ttl,
                                       IP_ID + ttl, SPORT, TCP_DPORT, ttl);
                    mt_send(a, dst->if_index, p->buf, p->length, &match_tcp4);
                }
            } else if (dst->ip_dst->type == ADDR_IPV6) {
                if (probe_type == METHOD_ICMP) {
                    p = packet_helper_echo6(dst->mac_dst->addr, dst->mac_src->addr,
                                            dst->ip_src->addr, dst->ip_dst->addr,
                                            0, 0, ttl, ICMP_ID, ttl, CHECKSUM);
                    mt_send(a, dst->if_index, p->buf, p->length, &match_icmp6);
                } else if (probe_type == METHOD_UDP) {
                    p = packet_helper_udp6(dst->mac_dst->addr, dst->mac_src->addr,
                                           dst->ip_src->addr, dst->ip_dst->addr, 0, 0, ttl,
                                           SPORT, DPORT, ttl);
                    mt_send(a, dst->if_index, p->buf, p->length, &match_udp6);
                } else if (probe_type == METHOD_TCP) {
                    p = packet_helper_tcp6(dst->mac_dst->addr, dst->mac_src->addr,
                                           dst->ip_src->addr, dst->ip_dst->addr, 0, 0, ttl,
                                           SPORT, TCP_DPORT, ttl);
                    mt_send(a, dst->if_index, p->buf, p->length, &match_tcp6);                    
                }
            }

            packet_destroy(p);
        }

        mt_wait(a, dst->if_index);

        struct interface *i = mt_get_interface(a, dst->if_index);
        int finished = 0;
        struct list *it = i->probes;
        while (i->probes->count > 0) {
            struct probe *probe = (struct probe *)list_pop(i->probes);

            if (finished == 0) {
                if (dst->ip_dst->type == ADDR_IPV4) {
                    traceroute4_print(probe);

                    if (probe->response_len > 0) {
                        char *raddr = get_ip4_src_addr(probe->response);
                        char *dst_addr = get_ip4_dst_addr(probe->probe);
                        if (get_icmp4_type(probe->response) == ICMPV4_TYPE_UNREACH ||
                            strcmp(raddr, dst_addr) == 0) {
                            finished = 1;
                        }
                        free(raddr);
                        free(dst_addr);
                    }
                } else if (dst->ip_dst->type == ADDR_IPV6) {
                    traceroute6_print(probe);

                    if (probe->response_len > 0) {
                        char *raddr = get_ip6_src_addr(probe->response);
                        char *dst_addr = get_ip6_dst_addr(probe->probe);
                        if (get_icmp6_type(probe->response) == ICMPV6_TYPE_UNREACH ||
                            strcmp(raddr, dst_addr) == 0) {
                            finished = 1;
                        }
                        free(raddr);
                        free(dst_addr);
                    }
                }
            }

            probe_destroy(probe);
            
        }
        if (finished) break;
    }
}

int mt_traceroute(struct mt *a, const struct dst *dst, int probe_type,
                  int max_ttl, int at_once) {
    if (dst->ip_dst->type != ADDR_IPV4 &&
        dst->ip_dst->type != ADDR_IPV6) return -1;

    return traceroute(a, dst, probe_type, max_ttl, at_once);
}
