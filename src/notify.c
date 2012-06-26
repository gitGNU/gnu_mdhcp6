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

#include "optionmap.h"
#include "lease.h"

#undef D
#define D(x)

/* notify via a script or program */
void notify_exec_script(char *script, struct lease_t *lease) {
	pid_t kid;
	int status;
	extern char **environ;

	assert(lease);

	if (!script)
		return;
	
	D(printf("%s %s\n", __func__, script));
	
	kid = fork();
	if (!kid) {
		char *a[2];
		a[0] = script;
		a[1] = NULL;
		
		lease_create_environ(lease);
		
		execve(script, a, environ);
		perror(script);
	}
	else {
		waitpid(kid, &status, 0);
		lease_update_oldvalues(lease);
	}
}
