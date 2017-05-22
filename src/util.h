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

#ifndef __UTIL_H__
#define __UTIL_H__

#include <arpa/inet.h>

void print_hex(const uint8_t *buf, uint32_t len);
int buff_cmp(const uint8_t *a, const uint8_t *b, uint32_t len);
int buff_swap(uint8_t *a, uint8_t *b, uint32_t len);
int strcmp_void(const void *a, const void *b);

void *sockaddr_addr(const struct sockaddr *sa);
char *sockaddr_to_str(const struct sockaddr *sa);
struct sockaddr *sockaddr_copy(const struct sockaddr *sa);
struct sockaddr *sockaddr_create(const uint8_t *addr, int family);
struct sockaddr *sockaddr_from_str(const char *addr, int family);

struct timeval timeval_diff(const struct timeval *a, const struct timeval *b);
struct timeval timeval_diff_now(const struct timeval *t);
struct timeval timeval_divide(const struct timeval *t, int d);
struct timeval timeval_from_ms(int ms);
int timeval_to_ms(const struct timeval *t);
int timeval_cmp(const struct timeval *a, const struct timeval *b);
char *timeval_to_str(const struct timeval *t);
char *timeval_diff_to_str(const struct timeval *a, const struct timeval *b);
char *timeval_diff_now_to_str(const struct timeval *t);

#endif // __UTIL_H__
