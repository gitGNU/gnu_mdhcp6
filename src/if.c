/*
 * Copyright: 2005 Axis Communications AB
 *
 * This file is part of Mini DHCP6.
 *
 * mdhcp6 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * mdhcp6 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with mdhcp6.  If not, see <http://www.gnu.org/licenses/>.
 *
 * 
 * network interface config
 * 
 * Authors:          Edgar E. Iglesias <edgar@axis.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_STDINT_H
#include <stdint.h>
#endif
#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>

#ifdef HAVE_NETLINK
#include <linux/rtnetlink.h>
#include "netlink.h"
#endif

#if HAVE_GETIFADDRS
#include <ifaddrs.h>
#endif

#if HAVE_SOCKADDR_DL
#include <net/if_dl.h>
#endif

#define D(x)

#if HAVE_SIOCGIFHWADDR
ssize_t if_hwaddress(int s, unsigned char *buf, size_t buflen,
		     char *ifname, uint16_t *type)
{
	ssize_t len = 6;
	struct ifreq if_hwaddr;
	
	strcpy(if_hwaddr.ifr_name, ifname);
	
	if (ioctl(s, SIOCGIFHWADDR, &if_hwaddr) < 0)
		return -1;

	switch (if_hwaddr.ifr_hwaddr.sa_family) {
	case ARPHRD_ETHER:
	case ARPHRD_IEEE802:
		*type = ARPHRD_ETHER;
		break;
	default:
		*type = if_hwaddr.ifr_hwaddr.sa_family;
                break;
	}
	
        if (len > buflen)
                len = buflen;
        
	memcpy(buf, if_hwaddr.ifr_hwaddr.sa_data, len);
        return len;
}
#elif defined(HAVE_GETIFADDRS) && defined(HAVE_SOCKADDR_DL) && defined(AF_LINK)
ssize_t if_hwaddress(int s, unsigned char *buf, size_t buflen,
		     char *ifname, uint16_t *type)
{	
	struct ifaddrs *ifalist, *ifa;
	ssize_t len;
	int ifindex;
	int r;
	
	r = getifaddrs(&ifalist);
	if (r) {
		perror("getifaddrs");
		return 0;
	}

	ifindex = if_nametoindex(ifname);
	for (ifa = ifalist; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr
		    && ifa->ifa_addr->sa_family == AF_LINK) {
			struct sockaddr_dl *sa;
			
			sa = (struct sockaddr_dl *) ifa->ifa_addr;
			if (sa->sdl_index != ifindex)
				continue;
			
			/* found it */
			len = sa->sdl_alen;
			if (len > buflen)
				len = buflen;

			*type = sa->sdl_type;
			memcpy(buf, LLADDR(sa), len);
			return len;
		}		
	}
	return 0;
}
#else
#error "I dont know howto get the dl address from an interface"
#endif

#ifdef HAVE_NETLINK
int if_get_raflags(char *interface)
{
	int ifindex;
	int seq;
	int s;
	int flags = 0;
	
	seq = time(NULL);
	s = netlink_open();
	if (s < 0)
		return 0;

	if (netlink_send_rtgenmsg(s, RTM_GETLINK, NLM_F_ROOT, seq) < 0)
		goto err;
	ifindex = if_nametoindex(interface);
	flags = netlink_recv_if_raflags(s, seq, ifindex);

  err:
	close(s);
	return flags;
}
#else
int if_get_raflags(char *interface)
{
	return 0;
}
#endif
