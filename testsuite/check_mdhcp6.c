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
#include <unistd.h>
#include <signal.h>

#include <check.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "msgbuf.h"
#include "mdhcp6.h"
#include "net.h"
#include "dhcpv6.h"
#include "random.h"
#include "if.h"

static int stdpipes[2];

extern int x_dhcpv6_parse_msg(struct dhcpv6_message_t *reply,
			    unsigned char *buf, size_t buflen,
			    uint32_t expected_id,
			    int expected_type);

/* registered callback to kill DUT */
static pid_t pidtokill = 0;
static void teardown(void) {
	if(pidtokill)
		kill(pidtokill, SIGKILL);
}

/* start the mdhcp6 client */
static pid_t do_mdhcp6(int argc, char *argv[]) {
	pid_t kid;
	
	kid = fork();
	if (!kid) {
		_exit(run_mdhcp6(argc, argv));
		fprintf(stderr, "kid returned!!\n");
	}

	/* register callback to kill it */
	pidtokill = kid;
	atexit(teardown);
	return kid;
}

/* parse a dhcpv6 message */
static int parse_msg(struct dhcpv6_message_t *msg,
		     unsigned char *buf, size_t len) {
	uint32_t transaction_id;
	transaction_id = buf[1] << 16;
	transaction_id += buf[2] << 8;
	transaction_id += buf[3];
	return x_dhcpv6_parse_msg(msg, buf, len, transaction_id, DH6_UNSPEC);
}

/* validate environment variables */
static int validate_env(char *var, char *val) {
	char *env;

	env = getenv(var);
	
	/* ok if both var and val are NULL */
	if (!env)
		return val ? EXIT_FAILURE : EXIT_SUCCESS;

	/* ok if identical */
	return strcmp(env, val) ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void check_stateful_wide_dhcpv6_server(int argc, char *argv[]) {
	int err;
	pid_t dhcp;
	int sock;
	ssize_t len = 0;
	struct dhcpv6_message_t dh6_msg;
	struct msgbuf_t *msg;
	static uint8_t buf[2 * 1024];
	int tmp;
	
	/* wide-dhcpv6-server 20070507-4 */
	uint8_t dhcpv6s_reply_to_solicit[] = {
		0x02, 0x22,
		0x0b, 0x79, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
		0x00, 0x01, 0x00, 0x40, 0x8c, 0x94, 0x09, 0x96,
		0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
		0x11, 0x2e, 0x95, 0x3b, 0x00, 0x1c, 0xc0, 0x31,
		0x7a, 0xd0, 0x00, 0x17, 0x00, 0x10, 0xfd, 0x00,
		0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18,
		0x00, 0x15, 0x03, 0x69, 0x70, 0x36, 0x06, 0x69,
		0x6f, 0x6e, 0x75, 0x74, 0x7a, 0x04, 0x61, 0x78,
		0x69, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
		0x1f, 0x00, 0x10, 0xfd, 0x00, 0x12, 0x34, 0x56,
		0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01
	};
	uint8_t dhcpv6s_reply_to_request[] = {
		0x07, 0x1f,
		0xf1, 0x5f, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
		0x00, 0x01, 0x00, 0x40, 0x8c, 0x94, 0x09, 0x96,
		0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
		0x11, 0x2e, 0x95, 0x3b, 0x00, 0x1c, 0xc0, 0x31,
		0x7a, 0xd0, 0x00, 0x03, 0x00, 0x28, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00,
		0x00, 0x18, 0x00, 0x05, 0x00, 0x18, 0xfd, 0x00,
		0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00,
		0x00, 0x1e, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x17,
		0x00, 0x10, 0xfd, 0x00, 0x12, 0x34, 0x56, 0x78,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x18, 0x00, 0x15, 0x03, 0x69,
		0x70, 0x36, 0x06, 0x69, 0x6f, 0x6e, 0x75, 0x74,
		0x7a, 0x04, 0x61, 0x78, 0x69, 0x73, 0x03, 0x63,
		0x6f, 0x6d, 0x00, 0x00, 0x1f, 0x00, 0x10, 0xfd,
		0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
	};

	instr_if_hwaddress[0] = 0x00;
	instr_if_hwaddress[1] = 0x40;
	instr_if_hwaddress[2] = 0x8c;
	instr_if_hwaddress[3] = 0x94;
	instr_if_hwaddress[4] = 0x09;
	instr_if_hwaddress[5] = 0x96;
	
	/* Create the link (simulated through unix sockets) */
	sock = dh6_create_and_bind_mc_socket("c0");

	/* run the mdhcp6 program */
	dhcp = do_mdhcp6(argc, argv);

	/* We are ready to interact with the daemon */

	/* wait for incomming requests */
	tmp = 0; /* Let him resend once.  */
	while (len < 4 || tmp < 8) {
		len = dh6_recv_msg(sock, buf, sizeof buf, 0, NULL, NULL);
		if (!len)
			usleep(1);
		if (len)
			tmp++;
	}
	fail_unless(len > 5);
	err = parse_msg(&dh6_msg, buf, len);

	/*
	 * We are expecting a valid SOLICIT from the DUT.
	 */
	fail_unless(err == EXIT_SUCCESS);
	fail_unless(dh6_msg.msgtype == DH6_SOLICIT);

	dhcpv6_free_options(dh6_msg.options);

	/* fake an answer, letting him know we excist. */
	msg = msgbuf_new(3);
	dhcpv6s_reply_to_solicit[1] = (dh6_msg.transaction_id >> 16) & 0xff;
	dhcpv6s_reply_to_solicit[2] = (dh6_msg.transaction_id >> 8) & 0xff;
	dhcpv6s_reply_to_solicit[3] = (dh6_msg.transaction_id) & 0xff;
	msgbuf_append(&msg, dhcpv6s_reply_to_solicit,
		      sizeof dhcpv6s_reply_to_solicit);
	dh6_send_msg(sock, &msg, NULL, 0);
	msgbuf_free(msg);

	/* wait for incomming requests */
	len = 0;
	dh6_msg.msgtype = DH6_SOLICIT;
	while (len < 4 || dh6_msg.msgtype == DH6_SOLICIT) {
		len = dh6_recv_msg(sock, buf, sizeof buf, 0, NULL, NULL);
		if (len == 0)
			usleep(1);
		else
			err = parse_msg(&dh6_msg, buf, len);
	}
	fail_unless(len > 5);

	/*
	 * We are expecting a valid lease REQUEST.
	 */
	fail_unless(err == EXIT_SUCCESS);
	fail_unless(dh6_msg.msgtype == DH6_REQUEST);

	dhcpv6_free_options(dh6_msg.options);

	/* fake an answer */
	msg = msgbuf_new(3);
	dhcpv6s_reply_to_request[1] = (dh6_msg.transaction_id >> 16) & 0xff;
	dhcpv6s_reply_to_request[2] = (dh6_msg.transaction_id >> 8) & 0xff;
	dhcpv6s_reply_to_request[3] = (dh6_msg.transaction_id) & 0xff;
	msgbuf_append(&msg, dhcpv6s_reply_to_request,
		      sizeof dhcpv6s_reply_to_request);
	dh6_send_msg(sock, &msg, NULL, 0);
	msgbuf_free(msg);
	
	/* wait for incomming environment strings */
	len = 0;
	tmp = 0;
	while (tmp++ < 100) {
		usleep(100);
		len = dh6_recv_msg(sock, buf, sizeof buf, 0, NULL, NULL);
		if (len > 0) {
			char *str;
			
			str = malloc(len + 1);
			memcpy(str, buf, len);
			str[len] = 0;
			putenv(str);
		}
	}
	
	/*
	 * validate the environment based on the fake reply we sent to the DUT
	 */
	fail_unless(!validate_env("dh6_addr", "fd00:1234:5678::110"));
	fail_unless(!validate_env("dh6_iface", "c0"));
	fail_unless(!validate_env("dh6_dnssrv", "fd00:1234:5678::1"));
	fail_unless(!validate_env("dh6_dnslist", "ip6.ionutz.axis.com"));
	fail_unless(!validate_env("dh6_ntpsrv", "fd00:1234:5678::1"));
	
	kill(dhcp, SIGKILL);
	if (waitpid(dhcp, &err, 0) == pidtokill) {
		fprintf(stderr, "killed %d\n", pidtokill);
		pidtokill = 0;
	}
	fail_unless(WEXITSTATUS(err) == EXIT_SUCCESS);	
	close(sock);
}

static void check_stateful_dibbler041(int argc, char *argv[]) {
	int err;
	pid_t dhcp;
	int sock;
	ssize_t len = 0;
	struct dhcpv6_message_t dh6_msg;
	struct msgbuf_t *msg;
	static uint8_t buf[2 * 1024];
	int tmp;
	
	/* dibbler 0.4.1 */
	uint8_t dibbler_reply_to_solicit[] = {
		0x02, 0x1e,
		0xb8, 0x80, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
		0x00, 0x01, 0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9,
		0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x00,
		0x43, 0xb1, 0x34, 0xd8, 0x00, 0x13, 0x20, 0x11,
		0xd2, 0xee, 0x00, 0x07, 0x00, 0x01, 0x00
	};
	uint8_t dibbler_reply_to_request[] = {
		0x07, 0x64,
		0x7f, 0xac, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
		0x00, 0x01, 0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9,
		0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x00,
		0x43, 0xb1, 0x34, 0xd8, 0x00, 0x13, 0x20, 0x11,
		0xd2, 0xee, 0x00, 0x03, 0x00, 0x6c, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
		0x00, 0x0a, 0x00, 0x05, 0x00, 0x18, 0x20, 0x01,
		0x05, 0xc0, 0x84, 0xd9, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x4b, 0x00, 0x00,
		0x07, 0x08, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x0d,
		0x00, 0x40, 0x00, 0x00, 0x31, 0x20, 0x61, 0x64,
		0x64, 0x72, 0x20, 0x67, 0x72, 0x61, 0x6e, 0x74,
		0x65, 0x64, 0x2e, 0x20, 0x4e, 0x65, 0x78, 0x74,
		0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x69, 0x6e,
		0x63, 0x6c, 0x75, 0x64, 0x65, 0x20, 0x49, 0x41,
		0x41, 0x44, 0x44, 0x52, 0x20, 0x69, 0x6e, 0x20,
		0x49, 0x41, 0x20, 0x6f, 0x70, 0x74, 0x69, 0x6f,
		0x6e, 0x2c, 0x20, 0x70, 0x6c, 0x65, 0x61, 0x73,
		0x65, 0x2e, 0x00, 0x17, 0x00, 0x20, 0x20, 0x01,
		0x05, 0xc0, 0x84, 0xd9, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01,
		0x05, 0xc0, 0x84, 0xd9, 0x00, 0x05, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18,
		0x00, 0x26, 0x0b, 0x75, 0x6e, 0x64, 0x65, 0x72,
		0x67, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x02, 0x73,
		0x65, 0x04, 0x61, 0x78, 0x69, 0x73, 0x03, 0x63,
		0x6f, 0x6d, 0x00, 0x02, 0x73, 0x65, 0x04, 0x61,
		0x78, 0x69, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x28, 0x00, 0x10, 0x20, 0x01, 0x05, 0xc0,
		0x84, 0xd9, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x29, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x16, 0x00, 0x10, 0x20, 0x01,
		0x05, 0xc0, 0x84, 0xd9, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x2a,
		0x00, 0x04, 0x00, 0x00, 0x01, 0xf4
	};

	instr_if_hwaddress[0] = 0x00;
	instr_if_hwaddress[1] = 0x40;
	instr_if_hwaddress[2] = 0x8c;
	instr_if_hwaddress[3] = 0x6b;
	instr_if_hwaddress[4] = 0x3c;
	instr_if_hwaddress[5] = 0xb9;
	
	/* Create the link (simulated through unix sockets) */
	sock = dh6_create_and_bind_mc_socket("c0");

	/* run the mdhcp6 program */
	dhcp = do_mdhcp6(argc, argv);

	/* We are ready to interact with the daemon */

	/* wait for incomming requests */
	while (len < 4) {
		len = dh6_recv_msg(sock, buf, sizeof buf, 0, NULL, NULL);
		if (!len)
			usleep(1);
	}
	fail_unless(len > 5);
	err = parse_msg(&dh6_msg, buf, len);

	/*
	 * We are expecting a valid SOLICIT from the DUT.
	 */
	fail_unless(err == EXIT_SUCCESS);
	fail_unless(dh6_msg.msgtype == DH6_SOLICIT);

	dhcpv6_free_options(dh6_msg.options);

	/* fake an answer, letting him know we excist. */
	msg = msgbuf_new(3);
	dibbler_reply_to_solicit[1] = (dh6_msg.transaction_id >> 16) & 0xff;
	dibbler_reply_to_solicit[2] = (dh6_msg.transaction_id >> 8) & 0xff;
	dibbler_reply_to_solicit[3] = (dh6_msg.transaction_id) & 0xff;
	msgbuf_append(&msg, dibbler_reply_to_solicit,
		      sizeof dibbler_reply_to_solicit);
	dh6_send_msg(sock, &msg, NULL, 0);
	msgbuf_free(msg);

	/* wait for incomming requests */
	len = 0;
	dh6_msg.msgtype = DH6_SOLICIT;
	while (len < 4 || dh6_msg.msgtype == DH6_SOLICIT) {
		len = dh6_recv_msg(sock, buf, sizeof buf, 0, NULL, NULL);
		if (len == 0)
			usleep(1);
		else
			err = parse_msg(&dh6_msg, buf, len);
	}
	fail_unless(len > 5);

	/*
	 * We are expecting a valid lease REQUEST.
	 */
	fail_unless(err == EXIT_SUCCESS);
	fail_unless(dh6_msg.msgtype == DH6_REQUEST);

	dhcpv6_free_options(dh6_msg.options);

	/* fake an answer */
	msg = msgbuf_new(3);
	dibbler_reply_to_request[1] = (dh6_msg.transaction_id >> 16) & 0xff;
	dibbler_reply_to_request[2] = (dh6_msg.transaction_id >> 8) & 0xff;
	dibbler_reply_to_request[3] = (dh6_msg.transaction_id) & 0xff;
	msgbuf_append(&msg, dibbler_reply_to_request,
		      sizeof dibbler_reply_to_request);
	dh6_send_msg(sock, &msg, NULL, 0);
	msgbuf_free(msg);
	
	/* wait for incomming environment strings */
	len = 0;
	tmp = 0;
	while (tmp++ < 100) {
		usleep(100);
		len = dh6_recv_msg(sock, buf, sizeof buf, 0, NULL, NULL);
		if (len > 0) {
			char *str;
			
			str = malloc(len + 1);
			memcpy(str, buf, len);
			str[len] = 0;
			putenv(str);
		}
	}
	
	/*
	 * validate the environment based on the fake reply we sent to the DUT
	 */
	fail_unless(!validate_env("dh6_iface", "c0"));
	fail_unless(!validate_env("dh6_sipsrv", "2001:5c0:84d9:2::1"));
	fail_unless(!validate_env("dh6_dnssrv",
		    "2001:5c0:84d9:2::1 "
		    "2001:5c0:84d9:5::1"));
	fail_unless(!validate_env("dh6_dnslist",
		    "underground.se.axis.com "
		    "se.axis.com"));
/*	fail_unless(!validate_env("dh6_ntpsrv", "2001:5c0:84d9:2::1")); */
	
	kill(dhcp, SIGKILL);
	if (waitpid(dhcp, &err, 0) == pidtokill) {
		fprintf(stderr, "killed %d\n", pidtokill);
		pidtokill = 0;
	}
	fail_unless(WEXITSTATUS(err) == EXIT_SUCCESS);	
	close(sock);
}

static void check_stateless_dibbler041(int argc, char *argv[]) {
	int err;
	pid_t dhcp;
	int sock;
	ssize_t len = 0;
	struct dhcpv6_message_t dh6_msg;
	struct msgbuf_t *msg;
	static uint8_t buf[2 * 1024];
	int tmp;
	
	/* dibbler 0.4.1 */
	uint8_t dibbler_reply_to_infrequest[] = {
		0x07, 0xb5,
		0xe9, 0x7e, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
		0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9,
		0x00, 0x17, 0x00, 0x20, 0x20, 0x01, 0x05, 0xc0, 0x84, 0xd9,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x05, 0xc0, 0x84, 0xd9,
		0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x26, 0x0b, 0x75,
		0x6e, 0x64, 0x65, 0x72, 0x67, 0x72,
		0x6f, 0x75, 0x6e, 0x64, 0x02, 0x73, 0x65, 0x04, 0x61, 0x78,
		0x69, 0x73, 0x03, 0x63, 0x6f, 0x6d,
		0x00, 0x02, 0x73, 0x65, 0x04, 0x61, 0x78, 0x69, 0x73, 0x03,
		0x63, 0x6f, 0x6d, 0x00, 0x00, 0x28,
		0x00, 0x10, 0x20, 0x01, 0x05, 0xc0, 0x84, 0xd9, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x29, 0x00, 0x02, 0x00, 0x00, 0x00, 0x16,
		0x00, 0x10, 0x20, 0x01, 0x05, 0xc0,
		0x84, 0xd9, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x2a, 0x00, 0x04,
		0x00, 0x00, 0x01, 0xf4, 0x00, 0x02, 0x00, 0x0e, 0x00, 0x01,
		0x00, 0x00, 0x43, 0xb1, 0x34, 0xd8,
		0x00, 0x13, 0x20, 0x11, 0xd2, 0xee
	};
	
	/* Create the link (simulated through unix sockets) */
	sock = dh6_create_and_bind_mc_socket("c0");

	/* run the mdhcp6 program */
	dhcp = do_mdhcp6(argc, argv);

	/* We are ready to interact with the daemon */

	/* wait for incomming requests */
	while (len < 4) {
		len = dh6_recv_msg(sock, buf, sizeof buf, 0, NULL, NULL);
		usleep(1);
	}
	fail_unless(len > 5);
	err = parse_msg(&dh6_msg, buf, len);

	/*
	 * We are expecting a valid INFORMATION-REQUEST from the DUT. As
	 * instructed from the fake RA.
	 */
	fail_unless(err == EXIT_SUCCESS);
	fail_unless(dh6_msg.msgtype == DH6_INFORM_REQ);

	dhcpv6_free_options(dh6_msg.options);

	/* fake an answer */
	msg = msgbuf_new(3);
	dibbler_reply_to_infrequest[1] = (dh6_msg.transaction_id >> 16) & 0xff;
	dibbler_reply_to_infrequest[2] = (dh6_msg.transaction_id >> 8) & 0xff;
	dibbler_reply_to_infrequest[3] = (dh6_msg.transaction_id) & 0xff;
	msgbuf_append(&msg, dibbler_reply_to_infrequest,
		      sizeof dibbler_reply_to_infrequest);	
	dh6_send_msg(sock, &msg, NULL, 0);
	msgbuf_free(msg);

	/* wait for incomming environment strings */
	len = 0;
	tmp = 0;
	while (tmp++ < 100) {
		usleep(1000);		
		len = dh6_recv_msg(sock, buf, sizeof buf, 0, NULL, NULL);
		if (len > 0) {
			char *str;
			
			str = malloc(len + 1);
			memcpy(str, buf, len);
			str[len] = 0;
			putenv(str);
		}
	}
	
	/*
	 * validate the environment based on the fake reply we sent to the DUT
	 */
	fail_unless(!validate_env("dh6_iface", "c0"));
	fail_unless(!validate_env("dh6_sipsrv", "2001:5c0:84d9:2::1"));
	fail_unless(!validate_env("dh6_dnssrv",
		    "2001:5c0:84d9:2::1 "
		    "2001:5c0:84d9:5::1"));
	fail_unless(!validate_env("dh6_dnslist",
		    "underground.se.axis.com "
		    "se.axis.com"));
/*	fail_unless(!validate_env("dh6_ntpsrv", "2001:5c0:84d9:2::1")); */
	
	kill(dhcp, SIGKILL);
	if (waitpid(dhcp, &err, 0) == pidtokill) {
		fprintf(stderr, "killed %d\n", pidtokill);
		pidtokill = 0;
	}
	fail_unless(WEXITSTATUS(err) == EXIT_SUCCESS);	
	close(sock);
}

START_TEST(check_mdhcp6_auto_stateful)
{	
	char *argv[] = { "mdhcp6", "-n", "-i", "c0"};
	
	printf("\n%s\n", __func__);
	
	/*
	 * Instrumentation to make mdhcp6 beleive we have received an RA on
	 * the iface. The RA says we should do stateful dhcpv6.
	 */
	instr_if_raflags = IF_RA_RCVD | IF_RA_MANAGED;
	check_stateful_dibbler041(sizeof argv / sizeof *argv, argv);
}
END_TEST

START_TEST(check_mdhcp6_auto_stateful_no_success_option)
{	
	/* 
	 * The major difference between this test and the one above
	 * is that this one doesn't send a success status in the REPLY.
	 * The main purpose is to check that the statefull address is
	 * set when there is no status returned (aka, the status is implied
	 * to be successfull).
	 */
	char *argv[] = { "mdhcp6", "-n", "-i", "c0"};
	
	printf("\n%s\n", __func__);
	
	/*
	 * Instrumentation to make mdhcp6 beleive we have received an RA on
	 * the iface. The RA says we should do stateful dhcpv6.
	 */
	instr_if_raflags = IF_RA_RCVD | IF_RA_MANAGED;
	check_stateful_wide_dhcpv6_server(sizeof argv / sizeof *argv, argv);
}
END_TEST

START_TEST(check_mdhcp6_force_stateful_sl_ra)
{	
	char *argv[] = { "mdhcp6", "-n", "-i", "c0", "-fs"};
	
	printf("\n%s\n", __func__);
	
	/*
	 * Instrumentation to make mdhcp6 beleive we have received an RA on
	 * the iface. The RA says we should do stateless dhcpv6.
	 */
	instr_if_raflags = IF_RA_RCVD | IF_RA_OTHERCONF;
	check_stateful_dibbler041(sizeof argv / sizeof *argv, argv);
}
END_TEST

START_TEST(check_mdhcp6_force_stateful_no_ra)
{	
	char *argv[] = { "mdhcp6", "-n", "-i", "c0", "-fs"};
	
	printf("\n%s\n", __func__);
	
	/*
	 * Instrumentation to make mdhcp6 beleive we have not received any
	 * RA.
	 */
	instr_if_raflags = 0;
	check_stateful_dibbler041(sizeof argv / sizeof *argv, argv);
}
END_TEST

START_TEST(check_mdhcp6_force_stateful_managed_ra)
{	
	char *argv[] = { "mdhcp6", "-n", "-i", "c0", "-fs"};
	
	printf("\n%s\n", __func__);
	
	/*
	 * Instrumentation to make mdhcp6 beleive we have received an RA on
	 * the iface. The RA says we should do stateful dhcpv6.
	 */
	instr_if_raflags = IF_RA_RCVD | IF_RA_MANAGED;
	check_stateful_dibbler041(sizeof argv / sizeof *argv, argv);
}
END_TEST

START_TEST(check_mdhcp6_auto_stateless)
{	
	char *argv[] = { "mdhcp6", "-n", "-i", "c0"};
	
	printf("\n%s\n", __func__);
	
	/*
	 * Instrumentation to make mdhcp6 beleive we have received an RA on
	 * the iface. The RA says we should do stateless dhcpv6.
	 */
	instr_if_raflags = IF_RA_RCVD | IF_RA_OTHERCONF;
	check_stateless_dibbler041(sizeof argv / sizeof *argv, argv);
}
END_TEST

START_TEST(check_mdhcp6_force_stateless_sl_ra)
{	
	char *argv[] = { "mdhcp6", "-n", "-i", "c0", "-fo"};
	
	printf("\n%s\n", __func__);
	
	/*
	 * Instrumentation to make mdhcp6 beleive we have received an RA on
	 * the iface. The RA says we should do stateless dhcpv6.
	 */
	instr_if_raflags = IF_RA_RCVD | IF_RA_OTHERCONF;
	check_stateless_dibbler041(sizeof argv / sizeof *argv, argv);
}
END_TEST

START_TEST(check_mdhcp6_force_stateless_no_ra)
{	
	char *argv[] = { "mdhcp6", "-n", "-i", "c0", "-fo"};
	
	printf("\n%s\n", __func__);
	
	/*
	 * Instrumentation to make mdhcp6 beleive we have not received
	 * an RA.
	 */
	instr_if_raflags = 0;
	check_stateless_dibbler041(sizeof argv / sizeof *argv, argv);
}
END_TEST

START_TEST(check_mdhcp6_force_stateless_managed_ra)
{	
	char *argv[] = { "mdhcp6", "-n", "-i", "c0", "-fo"};
	
	printf("\n%s\n", __func__);
	
	/*
	 * Instrumentation to make mdhcp6 beleive we have received an RA on
	 * the iface. The RA says we should do stateful dhcpv6.
	 */
	instr_if_raflags = IF_RA_RCVD | IF_RA_MANAGED;
	check_stateless_dibbler041(sizeof argv / sizeof *argv, argv);
}
END_TEST

START_TEST(check_mdhcp6_usage)
{
	char *argv[] = { "mdhcp6"};
	int err;
	int buflen;
	char *buf;
	int i;
	extern const char *mdhcp6_usagestr;
	
	printf("\n%s\n", __func__);
	
	buflen = strlen(mdhcp6_usagestr) + 1; /* +1 for trailing new line */
	/* redirect stdout to our pipe */
	close(fileno(stdout));
	if (dup2(stdpipes[1], fileno(stdout)) != 1) {
		fprintf(stderr, "unable to redirect stdout!\n");
	}

	buf = malloc(buflen);
	for (i = 0; i < 1000; i++) {
		err = run_mdhcp6(sizeof argv / sizeof *argv, argv);
		fail_unless(err == EXIT_FAILURE);
		fail_unless(buf != NULL);
		err = read(stdpipes[0], buf, buflen);
		fail_unless(err == buflen);
		fail_unless(memcmp(buf, mdhcp6_usagestr, err - 1) == 0);
		fail_unless(buf[err - 1] == '\n'); /* trailing newline */
	}
	fprintf(stderr, "%s\n", buf);
	free(buf);
}
END_TEST

static Suite *mdhcp6_suite(void)
{
	Suite *s = suite_create("mdhcp6");
	TCase *tc = tcase_create("core");

	/* These test-cases end up doing lot's of forks. The linux
	   scheduler will punish us badly on loaded systems.
	   Just be patient.  */
	tcase_set_timeout(tc, 90);

	/* stateful dhcp tests */
	tcase_add_test(tc, check_mdhcp6_auto_stateful);
	tcase_add_test(tc, check_mdhcp6_force_stateful_sl_ra);
	tcase_add_test(tc, check_mdhcp6_force_stateful_no_ra);
	tcase_add_test(tc, check_mdhcp6_force_stateful_managed_ra);
	tcase_add_test(tc, check_mdhcp6_auto_stateful_no_success_option);

	/* stateless dhcp tests */
	tcase_add_test(tc, check_mdhcp6_auto_stateless);
	tcase_add_test(tc, check_mdhcp6_force_stateless_sl_ra);
	tcase_add_test(tc, check_mdhcp6_force_stateless_no_ra);
	tcase_add_test(tc, check_mdhcp6_force_stateless_managed_ra);

	/* Temporarily remove this test until we have a version that
	   does not close stdout.  */
	/* tcase_add_test(tc, check_mdhcp6_usage); */

	suite_add_tcase(s, tc);
	return s;
}

int main(int argc, char **argv)
{
	int nf;
	Suite *s = mdhcp6_suite();
	SRunner *sr = srunner_create(s);

	if (pipe(stdpipes) == -1) {
		perror("pipe");
		return EXIT_FAILURE;
	}
	srunner_set_fork_status(sr, CK_FORK);
	srunner_run_all(sr, CK_VERBOSE);
	nf = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (nf == 0) ? 0 : 1;
}
