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

START_TEST(check_dhcpv6__dhcp6s_R0_8_reply_to_request)
{
	uint8_t clientaddr[] = { 0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9 };
	uint8_t servaddr[] = { 0x00, 0x13, 0x20, 0x11, 0xd2, 0xee };
	/* dhcp6s captured by ethereal */
	uint8_t dhcp6s_reply_to_request[] = {
		0x07, 0x28,
		0x28, 0x5e, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
		0x00, 0x01, 0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9,
		0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
		0x0b, 0x8f, 0x35, 0xb0, 0x00, 0x13, 0x20, 0x11,
		0xd2, 0xee, 0x00, 0x03, 0x00, 0x2e, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
		0x00, 0x0a, 0x00, 0x05, 0x00, 0x1e, 0x20, 0x01,
		0x05, 0xc0, 0x84, 0xd9, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00,
		0x00, 0x82, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x0d,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x01,
		0xff, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x00, 0x00,
		0x19, 0x00, 0x10, 0x20, 0x01, 0x05, 0xc0, 0x84,
		0xd9, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x1a, 0x00, 0x19, 0x0b,
		0x75, 0x6e, 0x64, 0x65, 0x72, 0x67, 0x72, 0x6f,
		0x75, 0x6e, 0x64, 0x02, 0x73, 0x65, 0x04, 0x61,
		0x78, 0x69, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00
	};

	struct dhcpv6_message_t reply;
	struct dhcpv6_option_t *opts;
	struct msgbuf_t *msg;
	uint32_t transaction_id;
	int ret;
	int ok = 0;
	int foundclientid = 0;
	int foundserverid = 0;
	int foundiana = 0;

	printf("%s\n", __func__);
	/* from the trace */
	transaction_id = 0x0028285e; 

	msg = msgbuf_new(3);	   
	msgbuf_append(&msg, dhcp6s_reply_to_request,
		      sizeof dhcp6s_reply_to_request);

	ret = x_dhcpv6_parse_msg(&reply,
			       msg->buf,
			       msg->pos,
			       transaction_id,
			       DH6_REPLY);

	fail_unless(ret == EXIT_SUCCESS);
	
	if (ret != EXIT_SUCCESS)
		goto err;
	
	opts = reply.options;
	while (opts) {
		switch(opts->code) {
		case DH6OPT_CLIENTID:
		{
			struct dhcpv6_nodeid_t *node;
			struct duid_t *duid;
			
			fail_unless(opts->interp != NULL);
			node = opts->interp;			
			fail_unless(node->duid != NULL);
			duid = node->duid;
			
			/* from the trace */
			fail_unless(node->duidlen == 10);
			fail_unless(duid->type == 3);
			fail_unless(duid->dt.t3.hwtype == 1);
			ok = !memcmp(duid->dt.t3.addr,
				     clientaddr, sizeof clientaddr);
			fail_unless(ok);
			foundclientid++;
		}
		break;		
		case DH6OPT_SERVERID:
		{
			struct dhcpv6_nodeid_t *node;
			struct duid_t *duid;
			
			fail_unless(opts->interp != NULL);
			node = opts->interp;			
			fail_unless(node->duid != NULL);
			duid = node->duid;
			
			/* from the trace */
			fail_unless(node->duidlen == 14);
			fail_unless(duid->type == 1);
			fail_unless(duid->dt.t1.hwtype == 1);
			fail_unless(duid->dt.t1.time == 0x0b8f35b0);
			ok = !memcmp(duid->dt.t1.addr,
				     servaddr, sizeof servaddr);
			fail_unless(ok);
			foundserverid++;
		}
		break;
		case DH6OPT_IA_NA:
		{
			struct dhcpv6_option_ia_t *na;			
			struct in6_addr a6;
			
			fail_unless(opts->interp != NULL);
			na = opts->interp;

			fail_unless(na->iaid == 2);
			fail_unless(na->t1 == 5);
			fail_unless(na->t2 == 10);
			fail_unless(na->iaddr.prefered_lft == 130);
			fail_unless(na->iaddr.valid_lft == 200);
			fail_unless(na->status->code == DH6OPT_STCODE_SUCCESS);

			inet_pton(AF_INET6, "2001:5c0:84d9:2::103", &a6);
			fail_unless(!memcmp(&na->iaddr.addr, &a6, sizeof a6));
			foundiana++;
		}
		break;
		default:
			break;
		}
		opts = opts->next;
	}
	dhcpv6_free_options(reply.options);
	fail_unless(foundserverid == 1);
	fail_unless(foundclientid == 1);
	fail_unless(foundiana == 1);
err:
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_dhcpv6__dhcp6s_R0_8_reply_to_solicit)
{
	uint8_t clientaddr[] = { 0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9 };
	uint8_t servaddr[] = { 0x00, 0x13, 0x20, 0x11, 0xd2, 0xee };
	/* dhcp6s captured by ethereal */
	uint8_t dhcp6s_reply_to_solicit[] = {
		0x07, 0xc5,
		0x7c, 0xee, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01,
		0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9,
		0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x0b, 0x8f,
		0x35, 0xb0, 0x00, 0x13, 0x20, 0x11,
		0xd2, 0xee, 0x00, 0x07, 0x00, 0x01, 0xff, 0x00, 0x0d, 0x00,
		0x02, 0x00, 0x00
	};	
	struct dhcpv6_message_t reply;
	struct dhcpv6_option_t *opts;
	struct msgbuf_t *msg;
	uint32_t transaction_id;
	int ret;
	int ok = 0;
	int foundclientid = 0;
	int foundserverid = 0;

	printf("%s\n", __func__);
	/* from the trace */
	transaction_id = 0x00c57cee; 

	msg = msgbuf_new(3);	   
	msgbuf_append(&msg, dhcp6s_reply_to_solicit,
		      sizeof dhcp6s_reply_to_solicit);

	ret = x_dhcpv6_parse_msg(&reply,
			       msg->buf,
			       msg->pos,
			       transaction_id,
			       DH6_UNSPEC);

	fail_unless(ret == EXIT_SUCCESS);
	
	opts = reply.options;
	if (ret != EXIT_SUCCESS)
		goto err;
	while (opts) {
		switch(opts->code) {
		case DH6OPT_CLIENTID:
		{
			struct dhcpv6_nodeid_t *node;
			struct duid_t *duid;
				
			fail_unless(opts->interp != NULL);
			node = opts->interp;			
			fail_unless(node->duid != NULL);
			duid = node->duid;
				
			/* from the trace */
			fail_unless(node->duidlen == 10);
			fail_unless(duid->type == 3);
			fail_unless(duid->dt.t3.hwtype == 1);
			ok = memcmp(duid->dt.t3.addr,
				     clientaddr, sizeof clientaddr);
			fail_unless(ok == 0);
			foundclientid++;
		}
		break;
		
		case DH6OPT_SERVERID:
		{
			struct dhcpv6_nodeid_t *node;
			struct duid_t *duid;
			
			fail_unless(opts->interp != NULL);
			node = opts->interp;			
			fail_unless(node->duid != NULL);
			duid = node->duid;
			
			/* from the trace */
			fail_unless(node->duidlen == 14);
			fail_unless(duid->type == 1);
			fail_unless(duid->dt.t1.hwtype == 1);
			fail_unless(duid->dt.t1.time == 0x0b8f35b0);
			ok = !memcmp(duid->dt.t1.addr,
				     servaddr, sizeof servaddr);
			fail_unless(ok);
			foundserverid++;
		}
		break;
		default:
			break;
		}
		opts = opts->next;
	}	
	dhcpv6_free_options(reply.options);
	fail_unless(foundserverid == 1);
	fail_unless(foundclientid == 1);
  err:
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_dhcpv6__dhcp6s_R0_10_reply_to_renew__nobind)
{
	uint8_t clientaddr[] = { 0x00, 0x40, 0x8c, 0x6b, 0x2e, 0xce };
	uint8_t servaddr[] = { 0x00, 0x11, 0x09, 0xef, 0xf0, 0xbe };
	/* dhcp6s captured by ethereal */
	uint8_t dhcp6s_reply_to_renew[] = {
		0x07, 0x5e,
		0xd5, 0x02, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
		0x00, 0x01, 0x00, 0x40, 0x8c, 0x6b, 0x2e, 0xce,
		0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01,
		0x0b, 0x8d, 0xa6, 0x33, 0x00, 0x11, 0x09, 0xef,
		0xf0, 0xbe, 0x00, 0x03, 0x00, 0x0c, 0x00, 0x00,
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x07, 0x00, 0x01, 0xff, 0x00,
		0x0d, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0d, 0x00,		
		0x02, 0x00, 0x02
	};

	struct dhcpv6_message_t reply;
	struct dhcpv6_option_t *opts;
	struct msgbuf_t *msg;
	uint32_t transaction_id;
	int ret;
	int ok = 0;
	int foundclientid = 0;
	int foundserverid = 0;
	int foundiana = 0;

	printf("%s\n", __func__);
	/* from the trace */
	transaction_id = 0x005ed502; 

	msg = msgbuf_new(3);	   
	msgbuf_append(&msg, dhcp6s_reply_to_renew,
		      sizeof dhcp6s_reply_to_renew);

	ret = x_dhcpv6_parse_msg(&reply,
			       msg->buf,
			       msg->pos,
			       transaction_id,
			       DH6_REPLY);

	fail_unless(ret == EXIT_SUCCESS);
	
	if (ret != EXIT_SUCCESS)
		goto err;
	
	opts = reply.options;
	while (opts) {
		switch(opts->code) {
		case DH6OPT_CLIENTID:
		{
			struct dhcpv6_nodeid_t *node;
			struct duid_t *duid;
			
			fail_unless(opts->interp != NULL);
			node = opts->interp;			
			fail_unless(node->duid != NULL);
			duid = node->duid;
			
			/* from the trace */
			fail_unless(node->duidlen == 10);
			fail_unless(duid->type == 3);
			fail_unless(duid->dt.t3.hwtype == 1);
			ok = !memcmp(duid->dt.t3.addr,
				     clientaddr, sizeof clientaddr);
			fail_unless(ok);
			foundclientid++;
		}
		break;		
		case DH6OPT_SERVERID:
		{
			struct dhcpv6_nodeid_t *node;
			struct duid_t *duid;
			
			fail_unless(opts->interp != NULL);
			node = opts->interp;			
			fail_unless(node->duid != NULL);
			duid = node->duid;
			
			/* from the trace */
			fail_unless(node->duidlen == 14);
			fail_unless(duid->type == 1);
			fail_unless(duid->dt.t1.hwtype == 1);
			fail_unless(duid->dt.t1.time == 0x0b8da633);
			ok = !memcmp(duid->dt.t1.addr,
				     servaddr, sizeof servaddr);
			fail_unless(ok);
			foundserverid++;
		}
		break;
		case DH6OPT_IA_NA:
		{
			struct dhcpv6_option_ia_t *na;			
			
			fail_unless(opts->interp != NULL);
			na = opts->interp;

			fail_unless(na->iaid == 2);
			fail_unless(na->t1 == 0);
			fail_unless(na->t2 == 0);
			fail_unless(na->iaddr.valid_lft == 0);
			fail_unless(!na->status);
			foundiana++;
		}
		break;
		default:
			break;
		}
		opts = opts->next;
	}
	dhcpv6_free_options(reply.options);
	fail_unless(foundserverid == 1);
	fail_unless(foundclientid == 1);
	fail_unless(foundiana == 1);
err:
	msgbuf_free(msg);
}
END_TEST
