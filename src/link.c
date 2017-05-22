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
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>

#include "link.h"

struct link *link_open(int if_index) {
    struct link *l = malloc(sizeof(*l));
    if (l == NULL) return NULL;
    memset(l, 0, sizeof(*l));

    l->if_index = if_index;
    l->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (l->fd == -1) {
        free(l);
        return NULL;
    }

    return l;
}

void link_close(struct link *l) {
    if (l == NULL) return;
    close(l->fd);
    free(l);
}

int link_write(struct link *l, uint8_t *buf, uint32_t len, struct timeval *t) {
    if (l == NULL) return -1;
    
    // To correct an annoying error in Valgrind
    // Looks like it is because of alignment of sockaddr_ll
    struct sockaddr_storage addr;
    struct sockaddr_ll *addr_ll = (struct sockaddr_ll *)&addr;

    memset(addr_ll, 0, sizeof(addr));

    addr_ll->sll_family   = AF_PACKET;
    addr_ll->sll_ifindex  = l->if_index;
    addr_ll->sll_protocol = htons(ETH_P_ALL);

    if (t != NULL) gettimeofday(t, NULL);

    int sent = sendto(l->fd, buf, len, 0, (struct sockaddr *)addr_ll,
                      sizeof(struct sockaddr_ll));

    if (sent > 0) {
        l->write_count++;
        l->write_bytes += sent;
    }

    return sent;
}
