/*
 * Copyright: 2007 Axis Communications AB
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
 * net api through bsd-sockets.
 *
 * Authors:	     Edgar E. Iglesias <edgar@axis.com>
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
#define __GNU_SOURCE
#define __USE_GNU
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#include "msgbuf.h"
#include "if.h"

/* Predefined addresses */
#define DH6ADDR_ALLAGENT	"ff02::1:2"
#define DH6ADDR_ALLSERVER	"ff05::1:3"
#define DH6PORT_DOWNSTREAM	"546"
#define DH6PORT_UPSTREAM	"547"

int
dh6_create_and_bind_mc_socket(char *interface) {
	int s;
	s = socket(PF_INET6, SOCK_DGRAM, 0);
	if (s >= 0)
	{
		struct sockaddr_in6 sin6;
		
		if (if_mc_bindsocket(s, interface) < 0) {
			perror(interface);
			goto err;
		}
		
		memset(&sin6, 0, sizeof sin6);
		sin6.sin6_family = AF_INET6;
		sin6.sin6_flowinfo = 0;
		sin6.sin6_port = htons(546);
		sin6.sin6_addr = in6addr_any;  /* structure assignment */
		if (bind(s, (struct sockaddr *) &sin6, sizeof(sin6)) == -1)
			goto err;
	}	
	return s;
  err:
	close(s);
	return -1;
}

ssize_t
dh6_recv_msg(int s,
	     void *buf, size_t buflen, time_t timeout,
	     struct sockaddr *from, socklen_t *fromlen)
{
	fd_set rfds;
	struct timeval tv;
	int r;
	
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(s, &rfds);
	
	r = select(s + 1, &rfds, NULL, NULL, &tv);
	if (r == -1 || r == 0)
		return r;
	
	/* FD_ISSET(0, &rfds) will be true. */
	return recvfrom(s, buf, buflen, 0, from, fromlen);
}

void
dh6_send_msg(int s, struct msgbuf_t **msg,
	     struct sockaddr *to, socklen_t tolen)
{
	static struct sockaddr_in6 sa6_allagents = {0};
	struct addrinfo hints, *res;
	
	/* if to == NULL send to all agents multicast addr */
	if (to == NULL) {
		to = (struct sockaddr *)&sa6_allagents;
		tolen = sizeof sa6_allagents;

		/* cache the binary conversion */
		if (sa6_allagents.sin6_family == 0) {
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = PF_INET6;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;
			if (getaddrinfo(DH6ADDR_ALLAGENT,
					DH6PORT_UPSTREAM, &hints, &res))
				return;
			
			memcpy(&sa6_allagents, res->ai_addr, res->ai_addrlen);
			freeaddrinfo(res);
		}
	}
	
	if (sendto(s, (*msg)->buf, (*msg)->pos, MSG_DONTROUTE, to, tolen) < 0)
		perror("sendto");
}
