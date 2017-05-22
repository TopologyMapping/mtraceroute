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

#ifndef __ADDR_H__
#define __ADDR_H__

#include <stdint.h>
#include <arpa/inet.h>

// types
#define ADDR_IPV4      1
#define ADDR_IPV6      2
#define ADDR_ETHERNET  3

// sizes
#define ADDR_IPV4_SIZE 4
#define ADDR_IPV6_SIZE 16
#define ADDR_ETH_SIZE  6

struct addr {
    int type;
    uint8_t *addr;
};

struct addr *addr_create(int type, const uint8_t *addr);
struct addr *addr_create_from_str(int type, const char *addr);
struct addr *addr_create_from_sockaddr(const struct sockaddr *sa);
struct addr *addr_copy(const struct addr *a);
char *addr_to_str(const struct addr *a);
char *addr_bytes_to_str(int type, const uint8_t *addr);
int addr_cmp(const void *a, const void *b);
int addr_guess_type(const char *addr_str);
void addr_destroy(struct addr *addr);

#endif // __ADDR_H__
