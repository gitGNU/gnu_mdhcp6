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

#include "msgbuf.h"

START_TEST(check_msgbuf_append_u8)
{
	struct msgbuf_t *msg;
	int i;
	
	printf("%s\n", __func__);
	
	msg = msgbuf_new(2);
	for (i = 0; i < 10000; i++) {
		msgbuf_append_u8(&msg, 0x10);
		msgbuf_append_u8(&msg, (unsigned char) i);
	}
	for (i = 0; i < 10000; i++) {
		fail_unless(msg->buf[i*2] == 0x10);
		fail_unless(msg->buf[i*2 + 1] == (unsigned char) i);
	}
	msgbuf_free(msg);		
}
END_TEST

START_TEST(check_msgbuf_append16no)
{
	struct msgbuf_t *msg;
	int i;

	printf("%s\n", __func__);
	
	msg = msgbuf_new(2);
	i  = 0x1234;
	msgbuf_append_u16no(&msg, i);
	fail_unless(msg->buf[0] == 0x12);
	fail_unless(msg->buf[1] == 0x34);
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_msgbuf_append24no)
{
	struct msgbuf_t *msg;
	int i;

	printf("%s\n", __func__);
	
	msg = msgbuf_new(3);
	i  = 0x00123456;
	msgbuf_append_u24no(&msg, i);
	fail_unless(msg->buf[0] == 0x12);
	fail_unless(msg->buf[1] == 0x34);
	fail_unless(msg->buf[2] == 0x56);
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_msgbuf_append32no)
{
	struct msgbuf_t *msg;
	int i;
	
	printf("%s\n", __func__);
	
	msg = msgbuf_new(4);
	i  = 0x12000000;
	i += 0x00340000;
	i += 0x00005600;
	i += 0x00000078;
	msgbuf_append_u32no(&msg, i);
	fail_unless(msg->buf[0] == 0x12);
	fail_unless(msg->buf[1] == 0x34);
	fail_unless(msg->buf[2] == 0x56);
	fail_unless(msg->buf[3] == 0x78);
	/* this only works cause we know buf is correctly aligned atm
	 * otherwise it might SIGBUS*/
	fail_unless(htonl(0x12345678) == *(u_int32_t *)msg->buf);
	
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_msgbuf_resize)
{
#undef NUM_ROUNDS
#define NUM_ROUNDS 100000
	struct msgbuf_t *msg;
	char data[] = "foo";
	char *next;
	int i;
	
	printf("%s\n", __func__);
	msg = msgbuf_new(1);
	
	for (i = 0; i < NUM_ROUNDS; i++)
		msgbuf_append(&msg, data, strlen(data));

	/* nul terminate */
	msgbuf_append_u8(&msg, 0);
	
	i = 0;
	do {		
		next = strstr((char *) msg->buf + i, "foo");
		i += strlen(data);
	}
	while (next);

	/* NUM_ROUNDS + 1 to compensate for early increase of i */
	fail_unless(i == strlen(data) * (NUM_ROUNDS + 1));	
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_msgbuf_resize__default_initial_size)
{
#undef NUM_ROUNDS
#define NUM_ROUNDS 100000
	struct msgbuf_t *msg;
	char data[] = "foo";
	char *next;
	int i;
	
	printf("%s\n", __func__);
	msg = msgbuf_new(0);
	
	for (i = 0; i < NUM_ROUNDS; i++)
		msgbuf_append(&msg, data, strlen(data));

	/* nul terminate */
	msgbuf_append_u8(&msg, 0);
	
	i = 0;
	do {		
		next = strstr((char *) msg->buf + i, "foo");
		i += strlen(data);
	}
	while (next);

	/* NUM_ROUNDS + 1 to compensate for early increase of i */
	fail_unless(i == strlen(data) * (NUM_ROUNDS + 1));	
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_msgbuf_save_restore)
{
	struct msgbuf_t *msg;
	ssize_t savedpos;
	
	printf("%s\n", __func__);
	
	msg = msgbuf_new(2);
	msgbuf_append_u8(&msg, 0x01);
	msgbuf_append_u8(&msg, 0x02);
	msgbuf_append_u8(&msg, 0x03);
	msgbuf_append_u8(&msg, 0x04);
	savedpos = msgbuf_save(&msg);

	msgbuf_append_u8(&msg, 0x05);
	msgbuf_append_u8(&msg, 0x06);
	msgbuf_append_u8(&msg, 0x07);
	msgbuf_append_u8(&msg, 0x08);
	msgbuf_restore(&msg, savedpos);

	fail_unless(msg->buf[msg->pos - 4] == 0x01);
	fail_unless(msg->buf[msg->pos - 3] == 0x02);
	fail_unless(msg->buf[msg->pos - 2] == 0x03);
	fail_unless(msg->buf[msg->pos - 1] == 0x04);
	fail_unless(msg->buf[msg->pos] == 0x05);
	fail_unless(msg->buf[msg->pos + 1] == 0x06);
	fail_unless(msg->buf[msg->pos + 2] == 0x07);
	fail_unless(msg->buf[msg->pos + 3] == 0x08);
	
	msgbuf_free(msg);		
}
END_TEST

START_TEST(check_msgbuf_reset)
{
	struct msgbuf_t *msg;
	
	printf("%s\n", __func__);
	
	msg = msgbuf_new(2);
	msgbuf_append_u8(&msg, 0x01);
	msgbuf_append_u8(&msg, 0x02);
	msgbuf_append_u8(&msg, 0x03);
	msgbuf_append_u8(&msg, 0x04);
	msgbuf_append_u8(&msg, 0x05);
	msgbuf_append_u8(&msg, 0x06);
	msgbuf_append_u8(&msg, 0x07);
	msgbuf_append_u8(&msg, 0x08);
	
	msgbuf_reset(&msg);

	fail_unless(msg->pos == 0);
	fail_unless(msg->buf[msg->pos] == 0x01);
	fail_unless(msg->buf[msg->pos + 1] == 0x02);
	fail_unless(msg->buf[msg->pos + 2] == 0x03);
	fail_unless(msg->buf[msg->pos + 3] == 0x04);
	fail_unless(msg->buf[msg->pos + 4] == 0x05);
	fail_unless(msg->buf[msg->pos + 5] == 0x06);
	fail_unless(msg->buf[msg->pos + 6] == 0x07);
	fail_unless(msg->buf[msg->pos + 7] == 0x08);
	
	msgbuf_free(msg);		
}
END_TEST

static Suite *msgbuf_suite(void)
{
	Suite *s = suite_create("msgbuf");
	TCase *tc = tcase_create("core");
	
	tcase_add_test(tc, check_msgbuf_append_u8);
	tcase_add_test(tc, check_msgbuf_append16no);
	tcase_add_test(tc, check_msgbuf_append24no);
	tcase_add_test(tc, check_msgbuf_append32no);
	tcase_add_test(tc, check_msgbuf_resize);
	tcase_add_test(tc, check_msgbuf_resize__default_initial_size);
	tcase_add_test(tc, check_msgbuf_save_restore);
	tcase_add_test(tc, check_msgbuf_reset);
       
	suite_add_tcase(s, tc);
	return s;
}

int main(int argc, char **argv)
{
	int nf;
	Suite *s = msgbuf_suite();
	SRunner *sr = srunner_create(s);
	srunner_set_fork_status(sr, CK_NOFORK);
	srunner_run_all(sr, CK_VERBOSE);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (nf == 0) ? 0 : 1;
}
