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
 * dhcpv6 lease handling.
 * 
 * Authors:	     Edgar E. Iglesias <edgar@axis.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "msgbuf.h"
#include "dhcpv6.h"
#include "optionmap.h"
#include "lease.h"

#undef D
#define D(x)

static inline FILE *lease_open_file(char *filename) {
	FILE *fp;

	if (!filename)
		return NULL;
	if ((fp = fopen(filename, "rb+")) == NULL) {
		if ((fp = fopen(filename, "wb+")) == NULL) {
			perror(filename);
			return NULL;
		}
	}

	return fp;
}

void lease_set_server(struct lease_t *lz,
		       struct dhcpv6_nodeid_t *server) {
	dhcpv6_free_nodeid(lz->server);
	lz->server = server;
}

void lease_set_ia(struct lease_t *lz,
		   struct dhcpv6_option_ia_t *ia) {
	dhcpv6_free_ia(lz->ia);
	lz->ia = ia;
}

/* returns non-zero if any options where dropped. This is useful for the caller
   to know if it needs to let notify config changes.  */
int lease_drop(struct lease_t *lease) {
	int r = 0;
	char *p;
	char *end;

	lease_set_ia(lease, NULL);
	lease_set_server(lease, NULL);

	/* Clear and count addr.  */
	p = (char *) &lease->addr;
	end = p + sizeof lease->addr;

	while (p < end) {
		if (*p)
			r = 1;
		*p = 0;
		p++;
	}
	r |= optionmap_drop(lease->omap,
			   sizeof lease->omap
			   / sizeof lease->omap[0]);
	lease->aquired = 0;
	memset(&lease->addr, 0, sizeof lease->addr);
	return r;
}

void lease_cleanup(struct lease_t *lease) {
	lease_set_ia(lease, NULL);
	lease_set_server(lease, NULL);
	memset(&lease->addr, 0, sizeof lease->addr);
	memset(&lease->oldaddr, 0, sizeof lease->oldaddr);
	optionmap_cleanup(lease->omap,
			  sizeof lease->omap
			  / sizeof lease->omap[0]);
}

/*
 * read lease info from file
 */
void lease_readfile(char *filename, struct lease_t *lease) {
	char addrstr[INET6_ADDRSTRLEN];
	size_t r;
	FILE *fp;

	assert(lease);
	
	if ((fp = lease_open_file(filename)) == NULL)
		return;
	
	/* sync from file */
	if (fgets(addrstr, sizeof addrstr, fp)) {
		unsigned char duidbuf[128];
		size_t len = strlen(addrstr);
		
		addrstr[len - 1] = 0; /* chop the newline */
		
		r = inet_pton(AF_INET6, addrstr, &lease->addr);
		if (r != -1) {
			inet_ntop(AF_INET6, &lease->addr,
				  addrstr, INET6_ADDRSTRLEN);
			D(printf("synccore %s\n", addrstr));
		}
		
		r = fread(duidbuf, 1, sizeof duidbuf, fp);
		if (r > 0)
			lease->server = dhcpv6_parse_nodeid(duidbuf, r);
		lease->needsreconfig = 1;
	}	
	memcpy(&lease->syncedaddr, &lease->addr, sizeof lease->addr);
	fclose(fp);
}

/*
 * synchronize the current lease with the one on the leasefile
 */
void lease_sync(char *filename, struct lease_t *lease) {	
	char addrstr[INET6_ADDRSTRLEN];
	int insync;
	FILE *fp;

	if (!lease->ia || !lease->server)
		return;
	
	insync = !memcmp(&lease->syncedaddr, &lease->addr, sizeof lease->addr);

	inet_ntop(AF_INET6, &lease->addr,
		  addrstr, INET6_ADDRSTRLEN);
	if (!insync) {
		struct msgbuf_t *msg;

		if ((fp = lease_open_file(filename)) == NULL) {
			D(printf("%s: no leasefile\n", __func__));
			return;
		}

		/* update file */	
		D(printf("syncfile - %s\n", addrstr));
		rewind(fp);
		fprintf(fp, "%s\n", addrstr);
		
		msg = msgbuf_new(lease->server->duidlen);
		dhcpv6_append_node_id_opt(&msg, DH6OPT_SERVERID,
					  lease->server);
		fwrite(msg->buf + 4, 1, msg->pos - 4, fp);
		msgbuf_free(msg);
		fflush(fp);
		
		lease->needsreconfig = 1;
		/* synced */
		memcpy(&lease->syncedaddr, &lease->addr, sizeof lease->addr);
		fclose(fp);
	}
}

int lease_test_and_clear_reconfig(struct lease_t *lease) {
	int needsreconfig = lease->needsreconfig;	
	lease->needsreconfig = 0;	
	needsreconfig |=optionmap_test_and_clear_reconfig(lease->omap,
							  sizeof lease->omap /
							  sizeof *lease->omap);
	return needsreconfig;
}

void lease_update_oldvalues(struct lease_t *lease) {
	if (lease->aquired)
		memcpy(&lease->oldaddr, &lease->addr, sizeof lease->addr);
	else
		memset(&lease->oldaddr, 0, sizeof lease->oldaddr);
	memset(&lease->addr, 0, sizeof lease->addr);
	optionmap_update_oldvalues(lease->omap,
				   sizeof lease->omap
				   / sizeof lease->omap[0]);
}


/*
 * fabricate an environment for the configuration scripts process.
 * Tipically called from a separate process.
 */
#undef ADDRENVNAME
#define ADDRENVNAME "dh6_addr="
#undef OLDADDRENVNAME
#define OLDADDRENVNAME "dh6_addr_old="
void lease_create_environ(struct lease_t *lease) {
	/*
	 * this mess makes it possible for the compiler to optimze the strlen..
	 */
	static char addrstr[INET6_ADDRSTRLEN + 20] = ADDRENVNAME;
	static char oldaddrstr[INET6_ADDRSTRLEN + 20] = OLDADDRENVNAME;
	char *str = addrstr + strlen(ADDRENVNAME);
	char *oldstr = oldaddrstr + strlen(OLDADDRENVNAME);
	
	assert((strlen(OLDADDRENVNAME) + INET6_ADDRSTRLEN + 1)
	       < sizeof(oldaddrstr));
	assert((strlen(ADDRENVNAME) + INET6_ADDRSTRLEN+1) < sizeof(addrstr));
	
	inet_ntop(AF_INET6, &lease->addr, str, INET6_ADDRSTRLEN);

	inet_ntop(AF_INET6, &lease->oldaddr, oldstr, INET6_ADDRSTRLEN);

	D(printf("%s str=%s oldstr=%s ia=%x server=%x\n",
		 __func__, str, oldstr, lease->ia, lease->server));
	
	if (lease->ia
	    && lease->server
	    && (memcmp(&in6addr_any, &lease->addr, sizeof lease->addr) != 0))
		putenv(addrstr);
	if (memcmp(&in6addr_any, &lease->oldaddr, sizeof lease->addr) != 0)
		putenv(oldaddrstr);

	{
		static char raflags[32];
		static char state[32];

		snprintf(raflags, sizeof raflags, 
			 "dh6_raflags=%x", lease->raflags);
		putenv(raflags);
		snprintf(state, sizeof state, 
			 "dh6_state=%x", lease->state);
		putenv(state);
	}	
	optionmap_create_environ(lease->omap,
				 sizeof lease->omap
				 / sizeof lease->omap[0]);
}
