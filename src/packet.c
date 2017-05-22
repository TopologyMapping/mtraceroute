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
#include "packet.h"

struct packet *packet_create() {
    struct packet *p = malloc(sizeof(*p));
    if (p == NULL) return NULL;

    p->blocks_list = list_create();
    if (p->blocks_list == NULL) {
        free(p);
        return NULL;
    }

    p->next_tag = 1;
    p->length   = 0;
    p->alloc    = PACKET_ALLOC_EXTRA;
    p->buf      = malloc(p->alloc);

    if (p->buf == NULL) {
        free(p);
        list_destroy(p->blocks_list);
        return NULL;
    }

    memset(p->buf, 0, p->alloc);
    return p;
}

void packet_destroy(struct packet *p) {
	while (p->blocks_list->count) {
		void *d = list_pop(p->blocks_list);
		free(d);
	}
	list_destroy(p->blocks_list);
	free(p->buf);
	free(p);
}

int packet_block_append(struct packet *p, uint8_t type, const void *buf,
                         uint32_t len) {

    struct packet_block *b = malloc(sizeof(*b));
    if (b == NULL) return -1;

    b->type     = type;
    b->tag      = p->next_tag;
    b->length   = len;
    b->position = p->length;

    // Check if we have enough memory
    if ((p->alloc - p->length) < len) {
        uint32_t new_size = p->length + len + PACKET_ALLOC_EXTRA;

        uint8_t *new_buf = malloc(new_size);
        if (new_buf == NULL) {
            free(b);
            return -1;
        }

        memset(new_buf, 0, new_size);
        memcpy(new_buf, p->buf, p->length);
        free(p->buf);

        p->buf   = new_buf;
        p->alloc = new_size;
    }

    memcpy(&(p->buf[p->length]), buf, len);

    list_insert(p->blocks_list, b);

    p->next_tag++;
    p->length += len;

    return b->tag;
}

static int packet_block_get_cmp(const void *a, const void *b) {
    int *tag = (int *)a;
    struct packet_block *block = (struct packet_block *)b;
    if ((*tag) == block->tag) return 0;
    return -1;
}

struct packet_block *packet_block_get(struct packet *p, int tag) {
    struct list_item *i = list_find(p->blocks_list, &tag,
                                    &packet_block_get_cmp);
    if (i == NULL) return NULL;
    return (struct packet_block *)i->data;
}

struct packet_block *packet_block_next(struct packet *p, int tag) {
    struct list_item *i = list_find(p->blocks_list, &tag,
                                    &packet_block_get_cmp);
    if (i == NULL) return NULL;
    if (i->next == NULL) return NULL;
    return (struct packet_block *)i->next->data;
}

void *packet_buf_get_by_tag(struct packet *p, int tag) {
    struct packet_block *b = packet_block_get(p, tag);
    if (b == NULL) return NULL;
    return &p->buf[b->position];
}
