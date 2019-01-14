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

#include "iface.h"
#include "dst.h"

struct dst *dst_create(struct mt *a, struct addr *ip_dst) {

    struct dst *d = malloc(sizeof(*d));
    if (d == NULL) return NULL;
    memset(d, 0, sizeof(*d));

    struct route *r = mt_get_route(a, ip_dst);

    if (r == NULL) {
        free(d);
        return NULL;
    }

    struct neighbor *n = mt_get_neighbor(a, r->gateway, r->if_index);

    if (n == NULL) {
        printf("mt_get_neighbor failed\n");
        free(d);
        return NULL;
    }

    struct interface *i = mt_get_interface(a, r->if_index);

    if (i == NULL) {
        printf("mt_get_interface failed\n");
        free(d);
        return NULL;
    }

    struct addr *if_ip = NULL;
    if (ip_dst->type == ADDR_IPV4) {
        if_ip  = iface_ip_addr(r->if_index, ADDR_IPV4);
    } else if (ip_dst->type == ADDR_IPV6) {
        if_ip  = iface_ip_addr(r->if_index, ADDR_IPV6);
    }

    d->ip_dst   = ip_dst;
    d->ip_src   = if_ip;
    d->mac_dst  = n->hw_addr;
    d->mac_src  = i->hw_addr;
    d->if_index = r->if_index;

    return d;
}

struct dst *dst_create_from_str(struct mt *a, const char *addr_str) {
    // try to guess the type of the addr
    int type = addr_guess_type(addr_str);
    if (type != ADDR_IPV4 && type != ADDR_IPV6) return NULL;

    struct addr *addr = addr_create_from_str(type, addr_str);

    struct dst *dst = dst_create(a, addr);
    if (dst == NULL) {
        addr_destroy(addr);
    }

    return dst;
}

void dst_destroy(struct dst *d) {
    addr_destroy(d->ip_dst);
    addr_destroy(d->ip_src);
    free(d);
}
