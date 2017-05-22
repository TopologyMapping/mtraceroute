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

#include "util.h"
#include "addr.h"

static int addr_size(int type) {
    if (type == ADDR_IPV4) {
        return ADDR_IPV4_SIZE;
    } else if (type == ADDR_IPV6) {
        return ADDR_IPV6_SIZE;
    } else if (type == ADDR_ETHERNET) {
        return ADDR_ETH_SIZE;
    }
    return -1;
}

static struct addr *addr_create_no_copy(int type, uint8_t *addr) {
    struct addr *a = malloc(sizeof(*a));
    if (a == NULL) return NULL;
    memset(a, 0, sizeof(*a));
    a->type = type;
    a->addr = addr;
    return a;
}

struct addr *addr_create(int type, const uint8_t *addr) {
    int addr_s = addr_size(type);
    
    // Copy addr to buf
    uint8_t *buf = malloc(addr_s);
    if (buf == NULL) return NULL;
    memcpy(buf, addr, addr_s);

    struct addr *a = addr_create_no_copy(type, buf);
    if (a == NULL) {
        free(buf);
        return NULL;
    }

    return a;
}

struct addr *addr_create_from_str(int type, const char *addr) {
    if (type != ADDR_IPV4 && type != ADDR_IPV6) return NULL;

    int addr_s = addr_size(type);

    uint8_t *buf = malloc(addr_s);
    if (buf == NULL) return NULL;

    if (type == ADDR_IPV4) {
        if (inet_pton(AF_INET, addr, buf) != 1) {
            free(buf);
            return NULL;
        }
    } else if (type == ADDR_IPV6) {
        if (inet_pton(AF_INET6, addr, buf) != 1) {
            free(buf);
            return NULL;
        }
    }

    struct addr *a = addr_create_no_copy(type, buf);
    if (a == NULL) {
        free(buf);
        return NULL;
    }

    return a;
}

struct addr *addr_create_from_sockaddr(const struct sockaddr *sa) {
    void *addr_data = sockaddr_addr(sa);
    if (sa->sa_family == AF_INET) {
        return addr_create(ADDR_IPV4, addr_data);
    } else if (sa->sa_family == AF_INET6) {
        return addr_create(ADDR_IPV6, addr_data);
    }
    return NULL;
}

struct addr *addr_copy(const struct addr *a) {
    return addr_create(a->type, a->addr);
}

char *addr_to_str(const struct addr *a) {
    int family = 0;
    int str_len = 0;
    if (a->type == ADDR_IPV4) {
        family = AF_INET;
        str_len = INET_ADDRSTRLEN;
    } else if (a->type == ADDR_IPV6) {
        family = AF_INET6;
        str_len = INET6_ADDRSTRLEN;
    } else {
        return NULL;
    }

    char *addr = malloc(str_len);
    if (addr == NULL) return NULL;
    memset(addr, 0, str_len);
    
    inet_ntop(family, a->addr, addr, str_len);
    return addr;
}

char *addr_bytes_to_str(int type, const uint8_t *addr) {
    struct addr *a = addr_create(type, addr);
    char *s = addr_to_str(a);
    addr_destroy(a);
    return s;
}

int addr_cmp(const void *a, const void *b) {
    if (a == NULL || b == NULL) return -1;

    struct addr *a_addr = (struct addr *)a;
    struct addr *b_addr = (struct addr *)b;    
    int s = addr_size(a_addr->type);
    if (s < 0) return -1;
    return buff_cmp(a_addr->addr, b_addr->addr, s);
}

int addr_guess_type(const char *addr_str) {
    uint8_t buf[16];
    if (inet_pton(AF_INET, addr_str, buf)) {
        return ADDR_IPV4;
    } else if (inet_pton(AF_INET6, addr_str, buf)) {
        return ADDR_IPV6;
    }
    return -1;
}

void addr_destroy(struct addr *addr) {
    free(addr->addr);
    free(addr);
}
