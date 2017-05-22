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

#ifndef __PACKET_H__
#define __PACKET_H__

#include <stdint.h>
#include "list.h"

struct packet_block { 
    uint8_t type;
    uint8_t tag;
    uint32_t length;
    uint32_t position;
};

#define PACKET_ALLOC_EXTRA    128 // bytes

// Block types
#define PACKET_BLOCK_DATA     1
#define PACKET_BLOCK_ETHERNET 2
#define PACKET_BLOCK_IPV4     3
#define PACKET_BLOCK_IPV6     4
#define PACKET_BLOCK_ARP      5
#define PACKET_BLOCK_ICMPV4   6
#define PACKET_BLOCK_ICMPV6   7
#define PACKET_BLOCK_TCP      8
#define PACKET_BLOCK_UDP      9

struct packet {
    struct list *blocks_list;
    uint8_t next_tag;
    uint8_t *buf;
    uint32_t length;
    uint32_t alloc;
};

struct packet *packet_create();

void packet_destroy(struct packet *p);

int packet_block_append(struct packet *p, uint8_t type, const void *buf,
                         uint32_t len);

struct packet_block *packet_block_get(struct packet *p, int tag);

struct packet_block *packet_block_next(struct packet *p, int tag);

void *packet_buf_get_by_tag(struct packet *p, int tag);

#endif // __PACKET_H__
