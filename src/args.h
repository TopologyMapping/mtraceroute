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

#include <getopt.h>

#define CMD_TRACEROUTE 1
#define CMD_PING       2
#define CMD_MDA        3

#define METHOD_ICMP    1
#define METHOD_UDP     2
#define METHOD_TCP     3

#define FLOW_ICMP_CHK  1  // icmp-chk
#define FLOW_ICMP_DST  2  // icmp-dst
#define FLOW_ICMP_FL   3  // icmp-fl
#define FLOW_ICMP_TC   4  // icmp-tc
#define FLOW_UDP_SPORT 5  // udp-sport
#define FLOW_UDP_DST   6  // udp-dst
#define FLOW_UDP_FL    7  // udp-fl
#define FLOW_UDP_TC    8  // udp-tc
#define FLOW_TCP_SPORT 9  // tcp-sport
#define FLOW_TCP_DST   10 // tcp-dst
#define FLOW_TCP_FL    11 // tcp-fl
#define FLOW_TCP_TC    12 // tcp-tc

struct args {
    char dst[128];
    int a; // confidence
    int c; // command
    int f; // flow-id
    int t; // max-ttl
    int m; // method
    int n; // send-probes
    int p; // probes-at-once
    int r; // retries
    int w; // wait
    int z; // send-wait
};

struct args *get_args(int argc, char **argv);
