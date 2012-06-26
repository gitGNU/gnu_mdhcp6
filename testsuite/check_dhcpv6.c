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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "msgbuf.h"
#include "dhcpv6.h"
#include "random.h"

extern int
x_dhcpv6_parse_msg(struct dhcpv6_message_t *reply,
		 unsigned char *buf, size_t buflen,
		 uint32_t expected_id,
		 uint8_t expected_type);

/* testcases */
#include "check_dhcpv6_dhcp6s.c"
#include "check_dhcpv6_dibbler.c"

START_TEST(check_dhcpv6_parse_duid1)
{
	struct dhcpv6_message_t reply;
	struct dhcpv6_option_t *opts;
	struct msgbuf_t *msg;
	uint32_t transaction_id;
	int ret;
	uint8_t myaddr[] = { 0x00, 0x40, 0x8c, 0x12, 0x34, 0x56 };
	int ok = 0;
	
	printf("%s\n", __func__);
	random_fill(&transaction_id, sizeof transaction_id);
	transaction_id &=  0xffffff;

	msg = msgbuf_new(3);
	
	msgbuf_append_u8(&msg, DH6_REPLY);
	msgbuf_append_u24no(&msg, transaction_id);

	msgbuf_append_u16no(&msg, DH6OPT_CLIENTID);
	msgbuf_append_u16no(&msg, 14); /* length */
	msgbuf_append_u16no(&msg, 1);  /* type */
	msgbuf_append_u16no(&msg, 1);  /* hwtype 1 == ethernet */
	msgbuf_append_u32no(&msg, 0x12345678);	/* time */
	msgbuf_append(&msg, myaddr, sizeof myaddr);

	ret = x_dhcpv6_parse_msg(&reply,
			       msg->buf,
			       msg->pos,
			       transaction_id,
			       DH6_REPLY);
	
	fail_unless(ret == EXIT_SUCCESS);
	
	opts = reply.options;
	while (ret == EXIT_SUCCESS && opts) {
		switch(opts->code) {
		case DH6OPT_CLIENTID:
		{
			struct dhcpv6_nodeid_t *node;
			struct duid_t *duid;
			
			fail_unless(opts->interp != NULL);
			node = opts->interp;			
			fail_unless(node->duid != NULL);
			duid = node->duid;
			
			fail_unless(node->duidlen == 14);
			fail_unless(duid->type == 1);
			fail_unless(duid->dt.t1.hwtype == 1);
			fail_unless(duid->dt.t1.time == 0x12345678);
			ok = !memcmp(duid->dt.t1.addr, myaddr, sizeof myaddr);
		}
		break;
		default:
			break;
		}
		opts = opts->next;
	}	
	fail_unless(ok);
	dhcpv6_free_options(reply.options);
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_dhcpv6_parse_duid2)
{
	struct dhcpv6_message_t reply;
	struct dhcpv6_option_t *opts;
	struct msgbuf_t *msg;
	uint32_t transaction_id;
	int ret;
	uint8_t myedata[] = { 0x00, 0x40, 0x8c, 0x12, 0x34, 0x56, 0x78, 0x90 };
	int ok = 0;
	
	printf("%s\n", __func__);
	random_fill(&transaction_id, sizeof transaction_id);
	transaction_id &=  0xffffff;

	msg = msgbuf_new(3);
	
	msgbuf_append_u8(&msg, DH6_REPLY);
	msgbuf_append_u24no(&msg, transaction_id);

	msgbuf_append_u16no(&msg, DH6OPT_CLIENTID);
	msgbuf_append_u16no(&msg, 6 + sizeof myedata); /* length */
	msgbuf_append_u16no(&msg, 2);  /* type */
	msgbuf_append_u32no(&msg, 9);  /* enterprise number */
	msgbuf_append(&msg, myedata, sizeof myedata);

	ret = x_dhcpv6_parse_msg(&reply,
				msg->buf,
				msg->pos,
				transaction_id,
				DH6_REPLY);

	fail_unless(ret == EXIT_SUCCESS);
	
	opts = reply.options;
	while (ret == EXIT_SUCCESS && opts) {
		switch(opts->code) {
		case DH6OPT_CLIENTID:
		{
			struct dhcpv6_nodeid_t *node;
			struct duid_t *duid;
			
			fail_unless(opts->interp != NULL);
			node = opts->interp;			
			fail_unless(node->duid != NULL);
			duid = node->duid;
			
			fail_unless(node->duidlen == 14);
			fail_unless(duid->type == 2);
			fail_unless(duid->dt.t2.enterprise_nr == 9);
			ok = !memcmp(duid->dt.t2.addr,
				     myedata, sizeof myedata);
		}
		break;
		default:
			break;
		}
		opts = opts->next;
	}	
	fail_unless(ok);
	dhcpv6_free_options(reply.options);
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_dhcpv6_parse_duid3)
{
	struct dhcpv6_message_t reply;
	struct dhcpv6_option_t *opts;
	struct msgbuf_t *msg;
	uint32_t transaction_id;
	int ret;
	uint8_t myaddr[] = { 0x00, 0x40, 0x8c, 0x12, 0x34, 0x56 };
	int ok = 0;
	
	printf("%s\n", __func__);
	random_fill(&transaction_id, sizeof transaction_id);
	transaction_id &=  0xffffff;

	msg = msgbuf_new(3);
	
	msgbuf_append_u8(&msg, DH6_REPLY);
	msgbuf_append_u24no(&msg, transaction_id);

	msgbuf_append_u16no(&msg, DH6OPT_CLIENTID);
	msgbuf_append_u16no(&msg, 10); /* length */
	msgbuf_append_u16no(&msg, 3);  /* type */
	msgbuf_append_u16no(&msg, 1);  /* hwtype 1 == ethernet */
	msgbuf_append(&msg, myaddr, sizeof myaddr);

	ret = x_dhcpv6_parse_msg(&reply,
			       msg->buf,
			       msg->pos,
			       transaction_id,
			       DH6_REPLY);

	fail_unless(ret == EXIT_SUCCESS);
	
	opts = reply.options;
	while (ret == EXIT_SUCCESS && opts) {
		switch(opts->code) {
		case DH6OPT_CLIENTID:
		{
			struct dhcpv6_nodeid_t *node;
			struct duid_t *duid;
			
			fail_unless(opts->interp != NULL);
			node = opts->interp;			
			fail_unless(node->duid != NULL);
			duid = node->duid;
			
			fail_unless(node->duidlen == 10);
			fail_unless(duid->type == 3);
			fail_unless(duid->dt.t3.hwtype == 1);
			ok = !memcmp(duid->dt.t3.addr, myaddr, sizeof myaddr);
		}
		break;
		default:
			break;
		}
		opts = opts->next;
	}	
	fail_unless(ok);
	dhcpv6_free_options(reply.options);
	msgbuf_free(msg);
}
END_TEST


static size_t cr_packet_gen(int constraint_lvl, unsigned char *buf,
			    unsigned int buflen,
			    uint32_t *fakeid, uint8_t *faketype)
{
	unsigned int pos = 0;
	unsigned int option_code, option_len;
	size_t fakelen;

	assert(buflen > 12);
	assert(fakeid);
	assert(faketype);

	random_fill(fakeid, sizeof *fakeid);
	random_fill(faketype, sizeof *faketype);
	*fakeid &= 0xffffff;

	random_fill(buf, buflen);
	random_fill(&fakelen, sizeof fakelen);

	if (fakelen > buflen)
		fakelen = buflen;

	if (!constraint_lvl)
		return fakelen;

	/* fakely place our transaction id */
	buf[0] = *faketype;
	buf[1] = *fakeid >> 16;
	buf[2] = *fakeid >> 8;
	buf[3] = *fakeid;

	if (constraint_lvl == 1)
		return fakelen;

	/* We now have a randomized packet. Constrain it further by
	   applying fixups.  */
	if (fakelen < 12)
		fakelen += 12;

	if (constraint_lvl == 2)
		return fakelen;

	pos = 4;
	while (pos < fakelen) {
		/* Load.  */
		option_code = buf[pos++] << 8;
		option_code += buf[pos++] << 8;
		option_len = buf[pos++] << 8;
		option_len += buf[pos++] << 8;

		/* Fixup.  */

		/* We don't support option codes above 41.  */
		option_code &= 63;
		if (option_code > 41) {
			option_code -= 41;
		}

		if (option_len > (fakelen - pos)) {
			/* Out of bounds, constrain, some of the time.  */
			option_len = fakelen - pos -
					(option_len & 0x1f);
			if (option_len > (fakelen - pos))
				option_len = fakelen - pos;
		}

		/* Writeback.  */
		buf[pos - 4] = option_code >> 8;
		buf[pos - 3] = option_code & 0xff;
		buf[pos - 2] = option_len >> 8;
		buf[pos - 1] = option_len & 0xff;
	}
	return fakelen;
}


START_TEST(check_dhcpv6_torture)
{
	unsigned char buf[512];
	int i;
	int ret;
	uint32_t fakeid;
	uint8_t faketype;
	unsigned int clvl = 0;

	
	printf("\ntorture the dhcpv6 "); fflush(stdout);
	for (i = 0; i < 50000; i++) {
		size_t fakelen;
		struct dhcpv6_message_t reply = {0};		
		if (i % 1000 == 0) {
			printf("."); fflush(stdout);
		}

		fakelen = cr_packet_gen(clvl + 1, buf, sizeof buf,
					&fakeid, &faketype);
		clvl++;
		clvl &= 15;

		ret = x_dhcpv6_parse_msg(&reply, buf,
				       fakelen, fakeid, faketype);
		if (ret == EXIT_SUCCESS) {
			if (i % 16  == 0)
				printf("+");fflush(stdout);
			dhcpv6_free_options(reply.options);
		}
	}
	printf("\n");
}
END_TEST

START_TEST(check_dhcpv6_torture_unconstrained)
{
	unsigned char buf[512];
	int i;
	int ret;
	uint32_t fakeid;
	uint8_t faketype;
	unsigned int clvl = 0;

	
	printf("\ntorture dhcpv6 unconstrained"); fflush(stdout);
	for (i = 0; i < 50000; i++) {
		size_t fakelen;
		struct dhcpv6_message_t reply = {0};		
		if (i % 1000 == 0) {
			printf("."); fflush(stdout);
		}

		fakelen = cr_packet_gen(clvl, buf, sizeof buf,
					&fakeid, &faketype);
		clvl++;
		clvl &= 7;
		ret = x_dhcpv6_parse_msg(&reply, buf,
				       fakelen, fakeid, faketype);
		if (ret == EXIT_SUCCESS) {
			if ((i % 8) == 0)
				printf("+");fflush(stdout);
			dhcpv6_free_options(reply.options);
		}
	}
	printf("\n");
}
END_TEST

static Suite *dhcpv6_suite(void)
{
	Suite *s = suite_create("dhcpv6");
	TCase *tc = tcase_create("core");

	tcase_add_test(tc, check_dhcpv6__dibbler_R0_6_0RC1_reply_to_renew);
	tcase_add_test(tc, check_dhcpv6_parse_duid1);
	tcase_add_test(tc, check_dhcpv6_parse_duid2);
	tcase_add_test(tc, check_dhcpv6_parse_duid3);
	tcase_add_test(tc, check_dhcpv6__dhcp6s_R0_8_reply_to_solicit);
	tcase_add_test(tc, check_dhcpv6__dhcp6s_R0_8_reply_to_request);
	tcase_add_test(tc, check_dhcpv6__dhcp6s_R0_10_reply_to_renew__nobind);

	tcase_add_test(tc, check_dhcpv6__dibbler_R0_4_1_reply_to_solicit);
	tcase_add_test(tc, check_dhcpv6__dibbler_R0_4_1_reply_to_request);
	tcase_add_test(tc, check_dhcpv6__dibbler_R0_4_1_reply_to_infrequest);

	tcase_add_test(tc, check_dhcpv6_torture_unconstrained);
	tcase_add_test(tc, check_dhcpv6_torture);
	
	suite_add_tcase(s, tc);
	return s;
}

int main(int argc, char **argv)
{
	int nf;
	Suite *s = dhcpv6_suite();
	SRunner *sr = srunner_create(s);
	srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr, CK_VERBOSE);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (nf == 0) ? 0 : 1;
}
