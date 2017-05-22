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
#include <unistd.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "iface.h"

struct addr *iface_hw_addr(int if_index) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return NULL;

    char if_name[IF_NAMESIZE];
    if (if_indextoname(if_index, if_name) == NULL) goto exit;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IF_NAMESIZE-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) goto exit;
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) goto exit;

    struct addr *addr = addr_create(ADDR_ETHERNET, ifr.ifr_hwaddr.sa_data);

    close(fd);
    return addr;

exit:
    close(fd);
    return NULL;
}

struct addr *iface_ip_addr(int if_index, int type) {
    int family = (type == ADDR_IPV4) ? AF_INET : AF_INET6;

    char if_name[IF_NAMESIZE];
    if (if_indextoname(if_index, if_name) == NULL) return NULL;

    struct ifaddrs *if_addrs;
    if (getifaddrs(&if_addrs) == -1) return NULL;

    struct addr *addr = NULL;

    struct ifaddrs *ifa;
    for (ifa = if_addrs; ifa != NULL; ifa = ifa->ifa_next) {
        if (strcmp(ifa->ifa_name, if_name) != 0) continue;

        if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == family) {
            addr = addr_create_from_sockaddr(ifa->ifa_addr);
            break;
        }
    }

    freeifaddrs(if_addrs);
    return addr;
}
