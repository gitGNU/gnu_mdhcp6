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
 * API to somewhat abstract network/sockets.
 *
 * TODO: Improve this api, it sucks.
 *
 * Authors:	     Edgar E. Iglesias <edgar@axis.com>
 */

int dh6_create_and_bind_mc_socket(char *interface);
ssize_t dh6_recv_msg(int s,
		     void *buf, size_t buflen, time_t timeout,
		     struct sockaddr *from, socklen_t *fromlen);
void dh6_send_msg(int s, struct msgbuf_t **msg,
		  struct sockaddr *to, socklen_t tolen);

#ifdef OVERRIDE_DH6_CLOSE
extern int dh6_close(int s);
#else
static inline int dh6_close(int s) {
	return close(s);
}
#endif
