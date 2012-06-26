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
 * DHCPv6 net interface through unix-sockets. Used to simplify tests.
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

#include "msgbuf.h"

static int sock_refcount = 0;
static int dh6_pending_socket = -1;

int
dh6_create_and_bind_mc_socket(char *interface) {
	int sv[2];
	int err;

	if (dh6_pending_socket != -1) {
		sock_refcount++;
		return dh6_pending_socket;
	}
	
	err = socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
	if (err) {
		sv[0] = -1;
		perror("socketpair");
	}
	dh6_pending_socket = sv[1];
	return sv[0];
}

int dh6_close(int s) {
	sock_refcount--;
	return 0;
}

ssize_t
dh6_recv_msg(int s,
	     void *buf, size_t buflen, time_t timeout,
	     struct sockaddr *from, socklen_t *fromlen)
{
	fd_set rfds;
	struct timeval tv;
	int r;
	
	FD_ZERO(&rfds);
	FD_SET(s, &rfds);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	
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
	if (sendto(s, (*msg)->buf, (*msg)->pos, MSG_DONTROUTE, NULL, 0) < 0)
		perror("sendto");
}
