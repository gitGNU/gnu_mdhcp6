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

START_TEST(check_dhcpv6__dibbler_R0_6_0RC1_reply_to_renew)
{
	uint8_t clientaddr[] = { 0x00, 0x40, 0x8c, 0x1c, 0x00, 0x60 };
	uint8_t servaddr[] = { 0x00, 0x13, 0x20, 0x11, 0xd2, 0xee };
	/* dibbler captured by ethereal */
	uint8_t dibbler_reply_to_renew[] = {
		0x07, 0x82,
		0x6e, 0x64, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
		0x00, 0x01, 0x00, 0x40, 0x8c, 0x1c, 0x00, 0x60,
		0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x00,
		0x43, 0xb1, 0x34, 0xd8, 0x00, 0x13, 0x20, 0x11,
		0xd2, 0xee, 0x00, 0x03, 0x00, 0x49, 0x00, 0x00,
		0x00, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0x00, 0x05, 0x00, 0x18, 0x20, 0x01,
		0x05, 0xc0, 0x84, 0xd9, 0x00, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x49, 0x00, 0x01,
		0x51, 0x80, 0x00, 0x02, 0xa3, 0x00, 0x00, 0x0d,
		0x00, 0x1d, 0x00, 0x00, 0x47, 0x72, 0x65, 0x65,
		0x74, 0x69, 0x6e, 0x67, 0x73, 0x20, 0x66, 0x72,
		0x6f, 0x6d, 0x20, 0x70, 0x6c, 0x61, 0x6e, 0x65,
		0x74, 0x20, 0x45, 0x61, 0x72, 0x74, 0x68, 0x00,
		0x17, 0x00, 0x20, 0x20, 0x01, 0x05, 0xc0, 0x84,
		0xd9, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x20, 0x01, 0x05, 0xc0, 0x84,
		0xd9, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x26, 0x0b,
		0x75, 0x6e, 0x64, 0x65, 0x72, 0x67, 0x72, 0x6f,
		0x75, 0x6e, 0x64, 0x02, 0x73, 0x65, 0x04, 0x61,
		0x78, 0x69, 0x73, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x02, 0x73, 0x65, 0x04, 0x61, 0x78, 0x69, 0x73,
		0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x16, 0x00,
		0x10, 0x20, 0x01, 0x05, 0xc0, 0x84, 0xd9, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x20, 0x00, 0x04, 0x00, 0x00, 0x00, 0xc8,
	};

	struct dhcpv6_message_t reply;
	struct dhcpv6_option_t *opts;
	struct msgbuf_t *msg;
	uint32_t transaction_id;
	int ret;
	int ok = 0;
	int foundclientid = 0;
	int foundserverid = 0;
	int foundntpsrv = 0;
	int founddnssrv = 0;
	int foundsipsrv = 0;
	int founddomainlist = 0;
	int foundiana = 0;

	printf("%s\n", __func__);
	/* from the trace */
	transaction_id = 0x00826e64; 

	msg = msgbuf_new(3);
	msgbuf_append(&msg, dibbler_reply_to_renew,
		      sizeof dibbler_reply_to_renew);

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
				fail_unless(duid->dt.t1.hwtype == 0);
				fail_unless(duid->dt.t1.time == 0x043b134d8);
				ok = !memcmp(duid->dt.t1.addr,
					     servaddr, sizeof servaddr);
				fail_unless(ok);
				foundserverid++;
			}
			break;
			case DH6OPT_NTP_SERVERS:
			{
				struct dhcpv6_option_addrlist_t *lopt = opts->interp;
				char ntpsrv[] = "2001:5c0:84d9:2::1";
				struct in6_addr a6;

				inet_pton(AF_INET6, ntpsrv, &a6);
				fail_unless(!memcmp(&(lopt->addr),
						    &a6, sizeof a6));
				foundntpsrv++;
			}
			break;
			case DH6OPT_DNS_SERVERS:
			{
				struct dhcpv6_option_addrlist_t *lopt = opts->interp;
				char dnssrv[] = "2001:5c0:84d9:3::1";
				char dnssrv2[] = "2001:5c0:84d9:2::1";
				struct in6_addr a6;

				fail_unless(lopt->nr_addr == 2);
			
				inet_pton(AF_INET6, dnssrv, &a6);
				fail_unless(!memcmp(&(lopt->addr[0]),
						    &a6, sizeof a6));
				inet_pton(AF_INET6, dnssrv2, &a6);
				fail_unless(!memcmp(&(lopt->addr[1]),
						    &a6, sizeof a6));
				founddnssrv++;
			}
			break;
			case DH6OPT_SIP_SERVERS:
			{
				struct dhcpv6_option_addrlist_t *lopt = opts->interp;
				char sipsrv[] = "2001:5c0:84d9:2::1";
				struct in6_addr a6;

				fail_unless(lopt->nr_addr == 1);
			
				inet_pton(AF_INET6, sipsrv, &a6);
				fail_unless(!memcmp(&(lopt->addr[0]),
						    &a6, sizeof a6));
				foundsipsrv++;
			}
			break;
			case DH6OPT_DOMAIN_LIST:
			{
				char domainlist[] = "underground.se.axis.com";
				fail_unless(!strncmp(opts->interp,
						     domainlist,
						     sizeof domainlist - 1));
				founddomainlist++;
			}
			break;
			case DH6OPT_IA_NA:
			{
				struct dhcpv6_option_ia_t *na;
				struct in6_addr a6;
				
				fail_unless(opts->interp != NULL);
				na = opts->interp;
				
				fail_unless(na->iaid == 2);
				fail_unless(na->t1 == 0xffffffff);
				fail_unless(na->t2 == 0xffffffff);
				fail_unless(na->iaddr.prefered_lft == 86400);
				fail_unless(na->iaddr.valid_lft == 172800);
				fail_unless(na->status->code 
					    == DH6OPT_STCODE_SUCCESS);
				
				inet_pton(AF_INET6, "2001:5c0:84d9:2::149",
					  &a6);
				fail_unless(!memcmp(&na->iaddr.addr, 
						    &a6, sizeof a6));
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
/*	fail_unless(foundntpsrv == 1); */
	fail_unless(founddnssrv == 1);
	fail_unless(foundsipsrv == 1);
	fail_unless(founddomainlist == 1);
	fail_unless(foundiana == 1);
  err:
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_dhcpv6__dibbler_R0_4_1_reply_to_solicit)
{
	uint8_t clientaddr[] = { 0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9 };
	uint8_t servaddr[] = { 0x00, 0x13, 0x20, 0x11, 0xd2, 0xee };
	/* dibbler captured by ethereal */
	uint8_t dibbler_reply_to_solicit[] = {
		0x02, 0x1e,
		0xb8, 0x80, 0x00, 0x01, 0x00, 0x0a, 0x00, 0x03,
		0x00, 0x01, 0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9,
		0x00, 0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x00,
		0x43, 0xb1, 0x34, 0xd8, 0x00, 0x13, 0x20, 0x11,
		0xd2, 0xee, 0x00, 0x07, 0x00, 0x01, 0x00
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
	transaction_id = 0x001eb880; 

	msg = msgbuf_new(3);	   
	msgbuf_append(&msg, dibbler_reply_to_solicit,
		      sizeof dibbler_reply_to_solicit);

	ret = x_dhcpv6_parse_msg(&reply,
			       msg->buf,
			       msg->pos,
			       transaction_id,
			       DH6_UNSPEC);

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
			fail_unless(duid->dt.t1.hwtype == 0);
			fail_unless(duid->dt.t1.time == 0x043b134d8);
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

START_TEST(check_dhcpv6__dibbler_R0_4_1_reply_to_infrequest)
{
	uint8_t clientaddr[] = { 0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9 };
	uint8_t servaddr[] = { 0x00, 0x13, 0x20, 0x11, 0xd2, 0xee };
	/* dibbler captured by ethereal */
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

	struct dhcpv6_message_t reply;
	struct dhcpv6_option_t *opts;
	struct msgbuf_t *msg;
	uint32_t transaction_id;
	int ret;
	int ok = 0;
	int foundclientid = 0;
	int foundserverid = 0;
	int foundntpsrv = 0;
	int founddnssrv = 0;
	int foundsipsrv = 0;
	int founddomainlist = 0;

	printf("%s\n", __func__);
	/* from the trace */
	transaction_id = 0x00b5e97e; 

	msg = msgbuf_new(3);	   
	msgbuf_append(&msg, dibbler_reply_to_infrequest,
		      sizeof dibbler_reply_to_infrequest);

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
			fail_unless(duid->dt.t1.hwtype == 0);
			fail_unless(duid->dt.t1.time == 0x043b134d8);
			ok = !memcmp(duid->dt.t1.addr,
				     servaddr, sizeof servaddr);
			fail_unless(ok);
			foundserverid++;
		}
		break;
		case DH6OPT_NTP_SERVERS:
		{
			struct dhcpv6_option_addrlist_t *lopt = opts->interp;
			char ntpsrv[] = "2001:5c0:84d9:2::1";
			struct in6_addr a6;

			inet_pton(AF_INET6, ntpsrv, &a6);
			fail_unless(!memcmp(&(lopt->addr),
					    &a6, sizeof a6));
			foundntpsrv++;
		}
		break;
		case DH6OPT_DNS_SERVERS:
		{
			struct dhcpv6_option_addrlist_t *lopt = opts->interp;
			char dnssrv[] = "2001:5c0:84d9:2::1";
			char dnssrv2[] = "2001:5c0:84d9:5::1";
			struct in6_addr a6;

			fail_unless(lopt->nr_addr == 2);
			
			inet_pton(AF_INET6, dnssrv, &a6);
			fail_unless(!memcmp(&(lopt->addr[0]),
					    &a6, sizeof a6));
			inet_pton(AF_INET6, dnssrv2, &a6);
			fail_unless(!memcmp(&(lopt->addr[1]),
					    &a6, sizeof a6));
			founddnssrv++;
		}
		break;
		case DH6OPT_SIP_SERVERS:
		{
			struct dhcpv6_option_addrlist_t *lopt = opts->interp;
			char sipsrv[] = "2001:5c0:84d9:2::1";
			struct in6_addr a6;

			fail_unless(lopt->nr_addr == 1);
			
			inet_pton(AF_INET6, sipsrv, &a6);
			fail_unless(!memcmp(&(lopt->addr[0]),
					    &a6, sizeof a6));
			foundsipsrv++;
		}
		break;
		case DH6OPT_DOMAIN_LIST:
		{
			char domainlist[] = "underground.se.axis.com";
			fail_unless(!strncmp(opts->interp,
					     domainlist,
					     sizeof domainlist - 1));
			founddomainlist++;
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
/*	fail_unless(foundntpsrv == 1); */
	fail_unless(founddnssrv == 1);
	fail_unless(foundsipsrv == 1);
	fail_unless(founddomainlist == 1);
err:
	msgbuf_free(msg);
}
END_TEST

START_TEST(check_dhcpv6__dibbler_R0_4_1_reply_to_request)
{
	uint8_t clientaddr[] = { 0x00, 0x40, 0x8c, 0x6b, 0x3c, 0xb9 };
	uint8_t servaddr[] = { 0x00, 0x13, 0x20, 0x11, 0xd2, 0xee };
	/* dibbler captured by ethereal */
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

	struct dhcpv6_message_t reply;
	struct dhcpv6_option_t *opts;
	struct msgbuf_t *msg;
	uint32_t transaction_id;
	int ret;
	int ok = 0;
	int foundclientid = 0;
	int foundserverid = 0;
	int foundntpsrv = 0;
	int founddnssrv = 0;
	int foundsipsrv = 0;
	int founddomainlist = 0;
	int foundiana = 0;

	printf("%s\n", __func__);
	/* from the trace */
	transaction_id = 0x00647fac; 

	msg = msgbuf_new(3);	   
	msgbuf_append(&msg, dibbler_reply_to_request,
		      sizeof dibbler_reply_to_request);

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
			fail_unless(duid->dt.t1.hwtype == 0);
			fail_unless(duid->dt.t1.time == 0x043b134d8);
			ok = !memcmp(duid->dt.t1.addr,
				     servaddr, sizeof servaddr);
			fail_unless(ok);
			foundserverid++;
		}
		break;
		case DH6OPT_NTP_SERVERS:
		{
			struct dhcpv6_option_addrlist_t *lopt = opts->interp;
			char ntpsrv[] = "2001:5c0:84d9:2::1";
			struct in6_addr a6;

			inet_pton(AF_INET6, ntpsrv, &a6);
			fail_unless(!memcmp(&(lopt->addr),
					    &a6, sizeof a6));
			foundntpsrv++;
		}
		break;
		case DH6OPT_DNS_SERVERS:
		{
			struct dhcpv6_option_addrlist_t *lopt = opts->interp;
			char dnssrv[] = "2001:5c0:84d9:2::1";
			char dnssrv2[] = "2001:5c0:84d9:5::1";
			struct in6_addr a6;

			fail_unless(lopt->nr_addr == 2);
			
			inet_pton(AF_INET6, dnssrv, &a6);
			fail_unless(!memcmp(&(lopt->addr[0]),
					    &a6, sizeof a6));
			inet_pton(AF_INET6, dnssrv2, &a6);
			fail_unless(!memcmp(&(lopt->addr[1]),
					    &a6, sizeof a6));
			founddnssrv++;
		}
		break;
		case DH6OPT_SIP_SERVERS:
		{
			struct dhcpv6_option_addrlist_t *lopt = opts->interp;
			char sipsrv[] = "2001:5c0:84d9:2::1";
			struct in6_addr a6;

			fail_unless(lopt->nr_addr == 1);
			
			inet_pton(AF_INET6, sipsrv, &a6);
			fail_unless(!memcmp(&(lopt->addr[0]),
					    &a6, sizeof a6));
			foundsipsrv++;
		}
		break;
		case DH6OPT_DOMAIN_LIST:
		{
			char domainlist[] = "underground.se.axis.com";
			fail_unless(!strncmp(opts->interp,
					     domainlist,
					     sizeof domainlist - 1));
			founddomainlist++;
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
			fail_unless(na->iaddr.prefered_lft == 1800);
			fail_unless(na->iaddr.valid_lft == 3600);
			fail_unless(na->status->code == DH6OPT_STCODE_SUCCESS);

			inet_pton(AF_INET6, "2001:5c0:84d9:2::14b", &a6);
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
/*	fail_unless(foundntpsrv == 1); */
	fail_unless(founddnssrv == 1);
	fail_unless(foundsipsrv == 1);
	fail_unless(founddomainlist == 1);
	fail_unless(foundiana == 1);
err:
	msgbuf_free(msg);
}
END_TEST
