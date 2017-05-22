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
#include <stdio.h>
#include <sys/time.h>

#include "util.h"

void print_hex(const uint8_t *buf, uint32_t len) {
    uint32_t i = 0;
    while (i < len) {
        printf("%02x", buf[i]);
        if (((i + 1) % 16) == 0) {
            printf("\n");
        } else if (((i + 1) % 8) == 0) {
            printf("  ");
        } else {
            printf(" ");
        }
        i++;
    }
    if ((len % 32) != 0) printf("\n");
    return;
}

int buff_cmp(const uint8_t *a, const uint8_t *b, uint32_t len) {
    uint32_t i = 0;
    for (i = 0; i < len; i++) {
        if (a[i] != b[i]) return -1;
    }
    return 0;
}

int buff_swap(uint8_t *a, uint8_t *b, uint32_t len) {
    uint8_t *tmp = malloc(len);
    if (tmp == NULL) return -1;
    memcpy(tmp, a, len);
    memcpy(a, b, len);
    memcpy(b, tmp, len);
    free(tmp);
    return 0;
}

int strcmp_void(const void *a, const void *b) {
    return strcmp((char *)a, (char *)b);
}

void *sockaddr_addr(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &((struct sockaddr_in *)sa)->sin_addr;
    } else if (sa->sa_family == AF_INET6) {
        return &((struct sockaddr_in6 *)sa)->sin6_addr;
    }
    return NULL;
}

char *sockaddr_to_str(const struct sockaddr *sa) {
    int str_len = 0;
    if (sa->sa_family == AF_INET) {
        str_len = INET_ADDRSTRLEN;
    } else if (sa->sa_family == AF_INET6) {
        str_len = INET6_ADDRSTRLEN;
    } else {
        return NULL;
    }

    char *addr = malloc(str_len);
    if (addr == NULL) return NULL;
    memset(addr, 0, str_len);

    void *src = sockaddr_addr(sa);
    inet_ntop(sa->sa_family, src, addr, str_len);

    return addr;
}

struct sockaddr *sockaddr_copy(const struct sockaddr *sa) {
    size_t sa_size = 0;
    if (sa->sa_family == AF_INET) {
        sa_size = sizeof(struct sockaddr_in);
    } else if (sa->sa_family == AF_INET6) {
        sa_size = sizeof(struct sockaddr_in6);
    } else {
        return NULL;
    }

    struct sockaddr *sa_copy = malloc(sa_size);
    if (sa_copy == NULL) return NULL;
    memcpy(sa_copy, sa, sa_size);

    return sa_copy;
}

struct sockaddr *sockaddr_create(const uint8_t *addr, int family) {
    size_t sa_size = 0;
    size_t addr_size = 0;

    if (family == AF_INET) {
        sa_size = sizeof(struct sockaddr_in);
        addr_size = 4;
    } else if (family == AF_INET6) {
        sa_size = sizeof(struct sockaddr_in6);
        addr_size = 16;
    } else {
        return NULL;
    }

    struct sockaddr *sa = malloc(sa_size);
    if (sa == NULL) return NULL;

    memset(sa, 0, sa_size);
    sa->sa_family = family;
    memcpy(sockaddr_addr(sa), addr, addr_size);

    return sa;
}

struct sockaddr *sockaddr_from_str(const char *addr, int family) {
    if (family != AF_INET && family != AF_INET6) return NULL;

    size_t addr_size = (family == AF_INET) ? 4 : 16;
    uint8_t *buf = malloc(addr_size);
    if (buf == NULL) return NULL;
    memset(buf, 0, addr_size);

    if (inet_pton(family, addr, buf) != 1) {
        free(buf);
        return NULL;
    }

    struct sockaddr *sa = sockaddr_create(buf, family);

    free(buf);
    return sa;
}

struct timeval timeval_diff(const struct timeval *a, const struct timeval *b) {
    struct timeval c;
    c.tv_sec = a->tv_sec - b->tv_sec;
    c.tv_usec = a->tv_usec - b->tv_usec;
    if (c.tv_usec < 0) {
        c.tv_sec--;
        c.tv_usec += 1000000;
    }
    return c;
}

struct timeval timeval_diff_now(const struct timeval *t) {
    struct timeval a;
    gettimeofday(&a, NULL);
    return timeval_diff(&a, t);
}

struct timeval timeval_divide(const struct timeval *t, int d) {
    struct timeval r;
    r.tv_sec = ((t->tv_sec * 1000000 + t->tv_usec) / d) / 1000000;
    r.tv_usec = ((t->tv_sec * 1000000 + t->tv_usec) / d) % 1000000;
    return r;
}

struct timeval timeval_from_ms(int ms) {
    struct timeval r;
    r.tv_sec = ms / 1000;
    r.tv_usec = (ms % 1000) * 1000;
    return r;
}

int timeval_to_ms(const struct timeval *t) {
    return t->tv_sec * 1000 + (t->tv_usec + 500) / 1000;
}

int timeval_cmp(const struct timeval *a, const struct timeval *b) {
    if (a->tv_sec > b->tv_sec) return 1;
    if (a->tv_sec < b->tv_sec) return -1;
    if (a->tv_usec > b->tv_usec) return 1;
    if (a->tv_usec < b->tv_usec) return -1;
    return 0; // equal
}

char *timeval_to_str(const struct timeval *t) {
    uint32_t strlen = 64;
    char *str = malloc(strlen);
    memset(str, 0, strlen);
    uint32_t usec = (t->tv_sec * 1000000) + t->tv_usec;
    snprintf(str, strlen, "%d.%03d", usec / 1000, usec % 1000);
    return str;
}

char *timeval_diff_to_str(const struct timeval *a, const struct timeval *b) {
    struct timeval c = timeval_diff(a, b);
    return timeval_to_str(&c);
}

char *timeval_diff_now_to_str(const struct timeval *t) {
    struct timeval r = timeval_diff_now(t);
    return timeval_to_str(&r);
}
