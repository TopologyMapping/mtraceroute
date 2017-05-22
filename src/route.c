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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#include "route.h"

#define MSGBUF 1024

static int route_lookup(const struct addr *dst, int *if_index,
                        struct addr **gateway) {
    int len = (dst->type == ADDR_IPV4) ? 4 : 16;
    uint32_t pid = getpid();

    // Construct the RTM_GETROUTE request and send it
    uint8_t msg_buf[MSGBUF];
    memset(msg_buf, 0, MSGBUF);

    struct nlmsghdr *msg = (struct nlmsghdr *)msg_buf;
    msg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg)) + RTA_LENGTH(len);
    msg->nlmsg_type  = RTM_GETROUTE;
    msg->nlmsg_flags = NLM_F_REQUEST;
    msg->nlmsg_seq   = 1;
    msg->nlmsg_pid   = pid;

    struct rtmsg *rmsg = NLMSG_DATA(msg);
    rmsg->rtm_family   = (dst->type == ADDR_IPV4) ? AF_INET : AF_INET6;
    rmsg->rtm_dst_len  = len * 8;

    struct rtattr *rta = RTM_RTA(rmsg);
    rta->rta_type      = RTA_DST;
    rta->rta_len       = RTA_LENGTH(len);

    memcpy(RTA_DATA(rta), dst->addr, len);

    int fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd == -1) return -1;

    int send_len = send(fd, msg_buf, msg->nlmsg_len, 0);
    if (send_len == -1) goto fail;
    
    // Receive and parse the response
    uint8_t recv_buf[MSGBUF];
    memset(recv_buf, 0, MSGBUF);

    int recv_len = recv(fd, recv_buf, sizeof(recv_buf), 0);
    if (recv_len == -1) goto fail;

    struct nlmsghdr *resp = (struct nlmsghdr *)recv_buf;

    if (resp->nlmsg_pid != pid || resp->nlmsg_type != RTM_NEWROUTE) goto fail;

    struct rtmsg *rtmsg = NLMSG_DATA(resp);
    int rlen = resp->nlmsg_len - NLMSG_LENGTH(sizeof(*rtmsg));

    for (rta = RTM_RTA(rtmsg); RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
        if (rta->rta_type == RTA_OIF) {
            *if_index = *((int *)RTA_DATA(rta));
        } else if (rta->rta_type == RTA_GATEWAY) {
            *gateway = addr_create(dst->type, RTA_DATA(rta));
        }
    }

    close(fd);
    return 0;

fail:
    close(fd);
    return -1;
}

struct route *route_create(const struct addr *dst) {
    struct route *r = malloc(sizeof(*r));
    if (r == NULL) return NULL;
    memset(r, 0, sizeof(*r));

    if (route_lookup(dst, &r->if_index, &r->gateway) == -1) {
        free(r);
        return NULL;
    }
    r->dst = addr_copy(dst);
    return r;
}

void route_destroy(struct route *r) {
    addr_destroy(r->gateway);
    addr_destroy(r->dst);
    free(r);
}
