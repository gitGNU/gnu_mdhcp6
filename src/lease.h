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
 * Authors:          Edgar E. Iglesias <edgar@axis.com>
 */

struct lease_t {
	time_t aquired;
	int needsreconfig;
	unsigned int raflags;
	unsigned int state;
	struct dhcpv6_option_ia_t *ia;
	struct dhcpv6_nodeid_t *server;
	struct in6_addr addr;
	struct in6_addr oldaddr;
	struct in6_addr syncedaddr;
	struct optionmap_t omap[256];
};

static inline void lease_init(struct lease_t *lease)
{
	memset(lease, 0, sizeof *lease);
}

extern void lease_readfile(char *filename, struct lease_t *lease);
extern void lease_sync(char *filename, struct lease_t *lease);
extern int lease_drop(struct lease_t *lease);
extern void lease_cleanup(struct lease_t *lease);
extern int lease_test_and_clear_reconfig(struct lease_t *lease);
extern void lease_update_oldvalues(struct lease_t *lease);
extern void lease_create_environ(struct lease_t *lease);
extern void lease_set_server(struct lease_t *lz,
                             struct dhcpv6_nodeid_t *server);
extern void lease_set_ia(struct lease_t *lz, struct dhcpv6_option_ia_t *ia);
