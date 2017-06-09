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
#include "mt.h"
#include "args.h"

typedef int (*parse_fn)(char *, int *);

struct xoption {
    struct option o;
    parse_fn fn;
    void *d;
};

struct xoption *get_xoption(struct xoption *opts, char n) {
    int t = 0;
    while (opts[t].o.name != NULL) {
        if (opts[t].o.val == n) return &opts[t];
        t++;
    }
    return NULL;
}

int parse_cmd(char *s, int *r) {
    if (strcmp(s, "traceroute") == 0) *r = CMD_TRACEROUTE;
    else if (strcmp(s, "ping") == 0)  *r = CMD_PING;
    else if (strcmp(s, "mda") == 0)   *r = CMD_MDA;
    else return -1;
    return 0;
}

int parse_method(char *s, int *r) {
    if (strcmp(s, "icmp") == 0)     *r = METHOD_ICMP;
    else if (strcmp(s, "udp") == 0) *r = METHOD_UDP;
    else if (strcmp(s, "tcp") == 0) *r = METHOD_TCP;
    else return -1;
    return 0;
}

int parse_flow_id(char *s, int *r) {
    if (strcmp(s, "icmp-chk") == 0)       *r = FLOW_ICMP_CHK;
    else if (strcmp(s, "icmp-dst") == 0)  *r = FLOW_ICMP_DST;
    else if (strcmp(s, "icmp-fl") == 0)   *r = FLOW_ICMP_FL;
    else if (strcmp(s, "icmp-tc") == 0)   *r = FLOW_ICMP_TC;
    else if (strcmp(s, "udp-sport") == 0) *r = FLOW_UDP_SPORT;
    else if (strcmp(s, "udp-dst") == 0)   *r = FLOW_UDP_DST;
    else if (strcmp(s, "udp-fl") == 0)    *r = FLOW_UDP_FL;
    else if (strcmp(s, "udp-tc") == 0)    *r = FLOW_UDP_TC;
    else if (strcmp(s, "tcp-sport") == 0) *r = FLOW_TCP_SPORT;
    else if (strcmp(s, "tcp-dst") == 0)   *r = FLOW_TCP_DST;
    else if (strcmp(s, "tcp-fl") == 0)    *r = FLOW_TCP_FL;
    else if (strcmp(s, "tcp-tc") == 0)    *r = FLOW_TCP_TC;
    else return -1;
    return 0;
}

int parse_conf(char *s, int *r) {
    *r = atoi(s);
    if (*r == 90 || *r == 95 || *r == 99) return 0;
    return -1;
}

int parse_int(char *s, int *r) {
    *r = atoi(s);
    return 0;
}

int parse_args(int argc, char **argv, struct args *args, struct xoption *opts) {

    // Count the number of options
    int t = 0;
    while (opts[t].o.name != NULL) t++;
    t++;

    // Create struct option
    struct option *long_opts = malloc(t * sizeof(*long_opts));
    int i = 0;
    for (i = 0; i < t; i++) {
        long_opts[i] = opts[i].o;
    }

    // Create short_opts string
    char short_opts[256];
    memset(short_opts, 0, 256);
    int str_pos = 0;
    for (i = 0; i < t; i++) {
        short_opts[str_pos] = opts[i].o.val;
        str_pos++;
        if (opts[i].o.has_arg == required_argument) {
            short_opts[str_pos] = ':';
            str_pos++;
        }
        else if (opts[i].o.has_arg == optional_argument) {
            short_opts[str_pos] = ':';
            short_opts[str_pos+1] = ':';
            str_pos += 2;
        }
    }
 
    while (1) {
        int next = getopt_long(argc, argv, short_opts, long_opts, NULL);
        if (next == -1 || next == '?') break;
        struct xoption *o = get_xoption(opts, next);
        if (o != NULL) {
            if (o->o.has_arg == no_argument) {
                if (o->fn(NULL, NULL) == -1) {
                    free(long_opts);
                    return 1;
                }
            } else if (o->o.has_arg == required_argument) {
                if (o->fn(optarg, o->d) == -1) {
                    printf("Wrong value for argument '%c'\n", next);
                    free(long_opts);
                    return 1;
                }
            }
        }
    }

    free(long_opts);

    if (optind == (argc-1)) {
        strcpy(args->dst, argv[optind]);
    } else {
        printf("No destination address specified.\n");
        return 1;
    }

    return 0;
}

int show_usage() {
    printf(
"mtraceroute ADDRESS [-c command] [-w wait] [-z send-wait]\n"
"\n"
"  -c command: traceroute|ping|mda, default: traceroute\n"
"  -w seconds to wait for answer: default: 1\n"
"  -z milliseconds to wait between sends: default: 20\n"
"\n"
"  MDA: -c mda [-a confidence] [-f flow-id] [-h max-ttl]\n"
"\n"
"    -a confidence level in %%: 90|95|99, default: 95\n"
"    -f what flow identifier to use, some values depends on\n"
"       the type of the address\n"
"       IPv4: icmp-chk, icmp-dst, udp-sport, udp-dst, tcp-sport, tcp-dst\n"
"             Default: udp-sport\n"
"       IPv6: icmp-chk, icmp-dst, icmp-fl, icmp-tc, udp-sport, udp-dst,\n"
"             udp-fl, udp-tc, tcp-sport, tcp-dst, tcp-fl, tcp-tc\n"
"             Default: udp-sport\n"
"    -h max number of hops to probe: default: 30\n"
"\n"
"  TRACEROUTE: -c traceroute [-h max-ttl] [-m method] [-p probes-at-once]\n"
"\n"
"    -h max number of hops to probe: default: 30\n"
"    -m method of probing: icmp|udp|tcp, default: icmp\n"
"    -p number of probes to send at once: default: 3\n"
"\n"
"  PING: -c ping [-n send-probes]\n"
"\n"
"    -n number of probes to send: default: 5\n");

    return -1;
}

struct args *get_args(int argc, char **argv) {
    struct args *args = malloc(sizeof(*args));
    memset(args, 0, sizeof(*args));

    args->a = 95;
    args->c = CMD_TRACEROUTE;
    args->f = FLOW_UDP_SPORT;
    args->h = 30;
    args->m = METHOD_ICMP;
    args->n = 5;
    args->p = 3;
    args->r = 2;
    args->w = 5;
    args->z = 20;

    struct xoption opts[] = {
        {{"help",           no_argument,       NULL, 'h'}, show_usage,    NULL},
        {{"confidence",     required_argument, NULL, 'a'}, parse_conf,    &args->a},
        {{"command",        required_argument, NULL, 'c'}, parse_cmd,     &args->c},
        {{"flow-id",        required_argument, NULL, 'f'}, parse_flow_id, &args->f},
        {{"max-ttl",        required_argument, NULL, 'h'}, parse_int,     &args->h},
        {{"method",         required_argument, NULL, 'm'}, parse_method,  &args->m},
        {{"send-probes",    required_argument, NULL, 'n'}, parse_int,     &args->n},
        {{"probes-at-once", required_argument, NULL, 'p'}, parse_int,     &args->p},
        {{"retries",        required_argument, NULL, 'r'}, parse_int,     &args->r},
        {{"wait",           required_argument, NULL, 'w'}, parse_int,     &args->w},
        {{"send-wait",      required_argument, NULL, 'z'}, parse_int,     &args->z},
        {{NULL,             no_argument,       NULL,  0 }, NULL,          NULL}
    };

    if (parse_args(argc, argv, args, opts) == 1) {
        free(args);
        return NULL;
    }

    return args;
}
