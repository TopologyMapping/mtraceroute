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
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

#include "dst.h"
#include "iface.h"
#include "util.h"
#include "link.h"
#include "args.h"
#include "mt.h"
#include "mt_nd.h"
#include "mt_mda.h"
#include "mt_ping.h"
#include "mt_traceroute.h"

#define MT_MDA        1
#define MT_PING       2
#define MT_TRACEROUTE 3

struct probe *mt_send(struct mt *a, int if_index, const uint8_t *buf,
                      uint32_t len, match_fn fn) {
    struct interface *i = mt_get_interface(a, if_index);
    struct probe *p = probe_create(buf, len, fn);
    link_write(i->link, p->probe, p->probe_len, &(p->sent_time));
    list_insert(i->probes, p);

    if (a->probes_count > 0) {
        struct timespec elapsed = timespec_diff_now(&a->last_probe_time);
        if (timespec_cmp(&elapsed, &a->send_wait) == -1) {
            struct timespec remaining = timespec_diff(&a->send_wait, &elapsed);
            usleep(timespec_to_ms(&remaining) * 1000);
        }
    }

    if (a->probes_count == 0) {
        clock_gettime(CLOCK_REALTIME, &a->first_probe_time);
    }
    a->probes_count++;
    clock_gettime(CLOCK_REALTIME, &a->last_probe_time);
    return p;
}

static void mt_retry(struct mt *a, struct interface *i, struct probe *p) {
    link_write(i->link, p->probe, p->probe_len, &(p->sent_time));
    p->retries++;
}

static void mt_receive(struct interface *i, const uint8_t *buf,
                       uint32_t len, struct timespec ts) {
    struct list_item *it;
    for (it = i->probes->first; it != NULL; it = it->next) {
        struct probe *p = (struct probe *)it->data;
        if (p->sent_time.tv_sec > 0 && p->response_len == 0) {
            probe_match(p, buf, len, &ts);
        }
    }
}

static int mt_unanswered_probes(struct mt *a, struct interface *i) {
    struct list_item *it;
    int count = 0;
    for (it = i->probes->first; it != NULL; it = it->next) {
        struct probe *p = (struct probe *)it->data;
        if (p->fn == NULL) continue;
        if (p->response_len > 0) continue;
        if (probe_timeout(p, a->probe_timeout) == 0) {
            count++;
            continue;
        }
        if (p->retries == a->retries) continue;        
        mt_retry(a, i, p);
        count++;
    }
    return count;
}

void mt_wait(struct mt *a, int if_index) {
    struct interface *i = mt_get_interface(a, if_index);
    while (mt_unanswered_probes(a, i) > 0) {
        struct pcap_pkthdr *header;
        const u_char *pkt_data;
        if (pcap_next_ex(i->pcap_handle, &header, &pkt_data) > 0) {
            struct timespec ts;
            ts.tv_sec = header->ts.tv_sec;
            ts.tv_nsec = header->ts.tv_usec * 1000;
            mt_receive(i, (uint8_t *)pkt_data, header->caplen, ts);
        }
    }
}

struct route *mt_get_route(struct mt *a, const struct addr *dst) {
    struct list_item *i = NULL;
    for (i = a->routes->first; i != NULL; i = i->next) {
        struct route *r = (struct route *)i->data;
        int dst_size = (dst->type == ADDR_IPV4) ? ADDR_IPV4_SIZE : ADDR_IPV6_SIZE;
        if (buff_cmp(dst->addr, r->dst->addr, dst_size) == 0) return r;
    }
    struct route *r = route_create(dst);
    if (r == NULL) return NULL;
    list_insert(a->routes, r);
    return r;
}

static int interface_pcap_open(struct interface *i) {
    char pcap_error[PCAP_ERRBUF_SIZE];
    i->pcap_handle = pcap_open_live(i->if_name, MT_PCAP_SNAPLEN,
                                    MT_PCAP_PROMISC, MT_PCAP_MS,
                                    pcap_error);

    if (i->pcap_handle == NULL) goto fail;
    if (pcap_datalink(i->pcap_handle) != DLT_EN10MB) goto fail;
    if (pcap_setdirection(i->pcap_handle, PCAP_D_IN) != 0) goto fail;
    return 0;

fail:
    pcap_close(i->pcap_handle);
    return -1;
}

struct interface *mt_get_interface(struct mt *a, int if_index) {
    struct list_item *it = NULL;
    for (it = a->interfaces->first; it != NULL; it = it->next) {
        struct interface *interface = (struct interface *)it->data;
        if (interface->if_index == if_index) return interface;
    }

    struct interface *i = malloc(sizeof(*i));
    if (i == NULL) return NULL;
    memset(i, 0, sizeof(*i));
    i->if_index = if_index;
    if_indextoname(if_index, i->if_name);
    i->hw_addr = iface_hw_addr(if_index);
    i->link = link_open(if_index);
    i->probes = list_create();
    if (i->probes == NULL) return NULL;
    interface_pcap_open(i);

    list_insert(a->interfaces, i);
    return i;
}

static void mt_interface_destroy(struct interface *i) {
    while (i->probes->count > 0) {
        struct probe *p = (struct probe *)list_pop(i->probes);
        probe_destroy(p);
    }
    list_destroy(i->probes);
    link_close(i->link);
    pcap_close(i->pcap_handle);
    addr_destroy(i->hw_addr);
    free(i);
}

struct neighbor *mt_get_neighbor(struct mt *a, const struct addr *dst,
                                   int if_index) {

    struct list_item *i = NULL;
    for (i = a->neighbors->first; i != NULL; i = i->next) {
        struct neighbor *n = (struct neighbor *)i->data;
        int dst_size = (dst->type == ADDR_IPV4) ? ADDR_IPV4_SIZE : ADDR_IPV6_SIZE;
        if (buff_cmp(dst->addr, n->ip_addr->addr, dst_size) == 0) return n;
    }

    struct addr *gw = mt_nd(a, dst, if_index);
    if (gw != NULL) {
        struct neighbor *n = malloc(sizeof(*n));
        if (n == NULL) {
            addr_destroy(gw);
            return NULL;
        }
        memset(n, 0, sizeof(*n));

        n->ip_addr  = addr_copy(dst);
        n->hw_addr  = gw;
        n->if_index = if_index;

        list_insert(a->neighbors, n);
        return n;
    }

    return NULL;
}

void neighbor_destroy(struct neighbor *n) {
    addr_destroy(n->ip_addr);
    addr_destroy(n->hw_addr);
    free(n);
}

static struct mt *mt_create(int wait, int send_wait, int retries) {
    struct mt *a = malloc(sizeof(*a));
    if (a == NULL) return NULL;
    memset(a, 0, sizeof(*a));

    a->interfaces = list_create();
    a->neighbors = list_create();
    a->routes = list_create();
    a->retries = retries;
    a->probe_timeout = wait;
    a->send_wait = timespec_from_ms(send_wait);
    a->probes_count = 0;

    clock_gettime(CLOCK_REALTIME, &a->init_time);
    memset(&a->first_probe_time, 0, sizeof(a->first_probe_time));
    memset(&a->last_probe_time, 0, sizeof(a->last_probe_time));

    return a;
}

static void mt_destroy(struct mt *a) {
    while (a->interfaces->count > 0) {
        struct interface *i = (struct interface *)list_pop(a->interfaces);
        mt_interface_destroy(i);
    }

    while (a->routes->count > 0) {
        struct route *r = (struct route *)list_pop(a->routes);
        route_destroy(r);
    }

    while (a->neighbors->count > 0) {
        struct neighbor *n = (struct neighbor *)list_pop(a->neighbors);
        neighbor_destroy(n);
    }

    list_destroy(a->routes);
    list_destroy(a->neighbors);
    list_destroy(a->interfaces);
    free(a);
}

int check_permissions(void) {
    if(getuid() != 0) {
        printf("you must be root to run this program.\n");
        return 0;
    }
    return 1;
}

int main(int argc, char *argv[]) {
    if(!check_permissions()) return 1;

    struct args *args = get_args(argc, argv);
    if (args == NULL) return 1;

    struct mt *a = mt_create(args->w, args->z, args->r);

    struct dst *d = dst_create_from_str(a, args->dst);

    if (d == NULL) {
        printf("Wrong address.\n");
        mt_destroy(a);
        return 1;
    }

    if (args->c == CMD_PING) {
        mt_ping(a, d, args->n);
    } else if (args->c == CMD_MDA) {
        mt_mda(a, d, args->a, args->f, args->t);
    } else if (args->c == CMD_TRACEROUTE) {
        mt_traceroute(a, d, args->m, args->t, args->p);
    }

    dst_destroy(d);
    mt_destroy(a);
    free(args);

    return 0;
}
