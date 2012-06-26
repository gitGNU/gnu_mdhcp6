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
 * Authors:          Edgar E. Iglesias <edgar@axis.com>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <check.h>

#include <netinet/in.h>

#include "optionmap.h"
#include "lease.h"

#include "msgbuf.h"
#include "dhcpv6.h"

START_TEST(check_lease_create)
{
	struct lease_t lease;
	int i;

	for (i = 0; i < 0x1fff; i++) {
		lease_init(&lease);
		lease_cleanup(&lease);
	}
}
END_TEST

START_TEST(check_lease_drop_nul)
{
	struct lease_t lease;
	int r;
	int i;

	for (i = 0; i < 0x1fff; i++) {
		lease_init(&lease);
		r = lease_drop(&lease);
		fail_unless(r == 0);
		lease_cleanup(&lease);
	}
}
END_TEST

START_TEST(check_lease_aquire)
{
	struct in6_addr nul6, bcast6;
	struct lease_t lease;

	memset(&nul6, 0, sizeof nul6);
	memset(&bcast6, 0xff, sizeof nul6);

	lease_init(&lease);

	/* Get a lease.  */
	lease.aquired = 0;
	memcpy(&lease.addr, &nul6, sizeof lease.addr);
	memcpy(&lease.oldaddr, &nul6, sizeof lease.addr);

	/* The notifier would call this.  */
	lease_update_oldvalues(&lease);

	/* Now aquire a lease.  */
	lease.aquired = 1;
	memcpy(&lease.addr, &bcast6, sizeof lease.addr);
	memcpy(&lease.oldaddr, &nul6, sizeof lease.addr);

	fail_unless(lease.aquired == 1);
	fail_unless(memcmp(&lease.addr, &bcast6, sizeof bcast6) == 0);
	fail_unless(memcmp(&lease.oldaddr, &nul6, sizeof nul6) == 0);

	lease_cleanup(&lease);
}
END_TEST

START_TEST(check_lease_drop_aquired)
{
	struct in6_addr nul6, bcast6;
	struct lease_t lease;

	memset(&nul6, 0, sizeof nul6);
	memset(&bcast6, 0xff, sizeof nul6);	

	lease_init(&lease);

	/* Get a lease.  */
	lease.aquired = 1;
	memcpy(&lease.addr, &bcast6, sizeof lease.addr);
	memcpy(&lease.oldaddr, &nul6, sizeof lease.addr);

	/* The notifier would call this.  */
	lease_update_oldvalues(&lease);

	/* Now drop it.  */
	lease_drop(&lease);
	fail_unless(lease.aquired == 0);
	fail_unless(memcmp(&lease.addr, &nul6, sizeof bcast6) == 0);
	fail_unless(memcmp(&lease.oldaddr, &bcast6, sizeof nul6) == 0);

	lease_cleanup(&lease);
}
END_TEST

START_TEST(check_lease_shift_oldaddr)
{
	struct in6_addr nul6, bcast6;
	struct lease_t lease = {0};

	memset(&lease, 0, sizeof lease);
	memset(&nul6, 0, sizeof nul6);
	memset(&bcast6, 0xff, sizeof nul6);

	lease.aquired = 1;
	memcpy(&lease.addr, &bcast6, sizeof lease.addr);
	memcpy(&lease.oldaddr, &nul6, sizeof lease.addr);

	lease_update_oldvalues(&lease);
	fail_unless(memcmp(&lease.addr, &nul6, sizeof bcast6) == 0);
	fail_unless(memcmp(&lease.oldaddr, &bcast6, sizeof nul6) == 0);

	lease.aquired = 1;
	memcpy(&lease.addr, &bcast6, sizeof lease.addr);
	memcpy(&lease.oldaddr, &bcast6, sizeof lease.addr);

	lease_update_oldvalues(&lease);
	fail_unless(memcmp(&lease.addr, &nul6, sizeof bcast6) == 0);
	fail_unless(memcmp(&lease.oldaddr, &bcast6, sizeof nul6) == 0);

	lease.aquired = 0;
	memcpy(&lease.addr, &bcast6, sizeof lease.addr);
	memcpy(&lease.oldaddr, &bcast6, sizeof lease.addr);

	lease_update_oldvalues(&lease);
	fail_unless(memcmp(&lease.addr, &nul6, sizeof bcast6) == 0);
	fail_unless(memcmp(&lease.oldaddr, &nul6, sizeof nul6) == 0);
}
END_TEST

/* It would be good to extend this test to handle the full contents of the
 * leasefile. I.e. more than only the IP adress */
START_TEST(check_lease_readfile)
{
	struct lease_t lease = {0};
	struct lease_t lease_reference = {0};
	char *leasefile = "unittest.lease";
	char filecontent[] = "5555:5555:5555:5555:5555:5555:5555:5555\n\0";
	FILE *filehandle;

	/* Make sure reading non-existing leasefile is a noop.  */
	lease_readfile(NULL, &lease);
	lease_readfile(leasefile, &lease);
	fail_unless(memcmp(&lease, &lease_reference, sizeof lease) == 0);

	/* Generate a known lease file */
	fail_unless((filehandle = fopen(leasefile, "w+")) != NULL);
	fail_unless(fwrite(filecontent,
				sizeof(filecontent), 1, filehandle) == 1);
	fclose(filehandle);

	/* Create a known reference */
	lease_init(&lease_reference);
	memset(&lease_reference.addr, 0x55, sizeof lease_reference.addr);
	memset(&lease_reference.syncedaddr, 0x55,
					sizeof (lease_reference.syncedaddr));
	lease_reference.needsreconfig = 1;

	/* read file and compare lease with reference */
	lease_readfile(leasefile, &lease);
	fail_unless(memcmp(&lease, &lease_reference, sizeof lease) == 0);
	remove(leasefile);
}
END_TEST

/* It would be good to extend this test to handle the full contents of the
 * leasefile. I.e. more than only the IP adress */
START_TEST(check_lease_sync)
{
	struct in6_addr nul6, bcast6;
	struct lease_t lease = {0};
	char *leasefile = "unittest.lease";
	FILE *filehandle;
	char content_reference[] =
				 "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa\n\0";
	char file_content[42];
	struct dhcpv6_nodeid_t *server;
	char dummy_byte;

	/* fill lease */
	memset(&lease.ia, 1, sizeof lease.ia);
	server = malloc(sizeof(struct dhcpv6_nodeid_t));
	memset(server, 0x00, sizeof (*server));
	server->duid = malloc(0);
	server->duidlen = 0;
	server->duid->type = 0;
	lease.server = server;
	lease.aquired = 1;
	memset(&lease.addr, 0xaa, sizeof lease.addr);
	memcpy(&lease.oldaddr, &nul6, sizeof lease.addr);

	/* sync lease */
	lease_sync(leasefile, &lease);

	/* read file and compare lease with reference */
	fail_unless((filehandle = fopen(leasefile, "r")) != NULL);
	fail_unless(fread(file_content, sizeof(content_reference), 1,
							filehandle) == 1);
	fail_if(fread(&dummy_byte, 1, 1, filehandle) != 0); /* check for eof */
	fclose(filehandle);

	fail_unless(memcmp(&content_reference, &file_content,
						sizeof (file_content)) == 0);

	remove(leasefile);
	free(server);
}
END_TEST

static Suite *lease_suite(void)
{
	Suite *s = suite_create("lease");
	TCase *tc = tcase_create("core");
	
	tcase_add_test(tc, check_lease_create);
	tcase_add_test(tc, check_lease_drop_nul);
	tcase_add_test(tc, check_lease_aquire);
	tcase_add_test(tc, check_lease_drop_aquired);
	tcase_add_test(tc, check_lease_shift_oldaddr);
	tcase_add_test(tc, check_lease_readfile);
	tcase_add_test(tc, check_lease_sync);

	suite_add_tcase(s, tc);
	return s;
}

int main(int argc, char **argv)
{
	int nf;
	Suite *s = lease_suite();
	SRunner *sr = srunner_create(s);
	srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr, CK_VERBOSE);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (nf == 0) ? 0 : 1;
}
