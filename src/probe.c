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
#include "probe.h"

struct probe *probe_create(const uint8_t *probe, uint32_t probe_len,
                           match_fn fn) {
    struct probe *p = malloc(sizeof(*p));
    if (p == NULL) return p;
    memset(p, 0, sizeof(*p));

    uint8_t *buf = malloc(probe_len);
    if (buf == NULL) {
        free(p);
        return NULL;
    }
    memcpy(buf, probe, probe_len);
    
    p->fn        = fn;
    p->probe     = buf;
    p->probe_len = probe_len;

    return p;
}

void probe_destroy(struct probe *p) {
    if (p->probe) free(p->probe);
    if (p->response) free(p->response);
    free(p);
}

int probe_timeout(const struct probe *p, int timeout) {
    struct timeval now;
    gettimeofday(&now, NULL);
    if ((now.tv_sec - p->sent_time.tv_sec) >= timeout) return 1;
    return 0;
}

int probe_match(struct probe *p, const uint8_t *buf, uint32_t len,
                const struct timeval *ts) {
    if (p->fn == NULL) return -1;

    if (p->fn(p->probe, p->probe_len, buf, len)) {
        p->response = malloc(len);
        if (p->response == NULL) return -1;
        p->response_len  = len;
        p->response_time = *ts;
        memcpy(p->response, buf, len);
        return 1;
    }

    return 0;
}
