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

#ifndef __MT_H__
#define __MT_H__

#include <time.h>
#include <net/if.h>
#include <pcap.h>

#include "list.h"
#include "probe.h"
#include "route.h"

#define MT_PCAP_SNAPLEN 1518
#define MT_PCAP_PROMISC 0
#define MT_PCAP_MS      20

struct mt {
    struct list *interfaces;
    struct list *neighbors;
    struct list *routes;

    int retries;
    int probe_timeout;
    struct timespec send_wait;

    // Statistics
    int probes_count;
    struct timespec init_time;
    struct timespec first_probe_time;
    struct timespec last_probe_time;
};

struct interface {
    int if_index;
    char if_name[IF_NAMESIZE];
    struct addr *hw_addr;
    struct link *link;
    struct list *probes;
    pcap_t *pcap_handle;
};

struct neighbor {
    int if_index;
    struct addr *ip_addr;
    struct addr *hw_addr;
};

struct probe *mt_send(struct mt *a, int if_index, const uint8_t *buf, uint32_t len, match_fn fn);
void mt_wait(struct mt *a, int if_index);
struct route *mt_get_route(struct mt *a, const struct addr *dst);
struct interface *mt_get_interface(struct mt *a, int if_index);
struct neighbor *mt_get_neighbor(struct mt *a, const struct addr *dst, int if_index);

#endif // __MT_H__
