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
 * Notifies the distribution about new DHCPv6 options.
 *
 * Authors:	     Edgar E. Iglesias <edgar@axis.com>
 */

#define __GNU_SOURCE
#define __USE_GNU

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
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "msgbuf.h"
#include "optionmap.h"
#include "lease.h"
#include "net.h"

#undef D
#define D(x)

/* notify via a script or program */
void notify_exec_script(char *script, struct lease_t *lease) {
	extern char **environ;	
	D(printf("%s %s\n", __func__, script));
	
	lease_create_environ(lease);

	/*
	 * Send over the dh6_ environemnt to the tester. One string per
	 * dgram. The tester will validate this for us.
	 */
	{
		ssize_t err;
		int len;
		int i = 0;
		int s;

		s = dh6_create_and_bind_mc_socket("c0");
		while (environ[i]) {
			static const char dh6_prefix[] = "dh6_";
			
			len = strlen(environ[i]);
			if (memcmp(environ[i],
				   dh6_prefix, sizeof dh6_prefix - 1) == 0) {
				
				D(printf("%s\n", environ[i]));
				if ((err = sendto(s, environ[i], len,
						  MSG_DONTROUTE,
						  NULL, 0)) != len) {
					perror("send");
				}
			}
			i++;
		}
		dh6_close(s);
	}
	lease_update_oldvalues(lease);
}
