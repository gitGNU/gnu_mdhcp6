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
 * Implements the DHCPv6 protocol, building up and parsing headers, option
 * requests etc.
 *
 * TODO: go through the option parser and use ntohx for correctly aligned
 * fields. This should result in less and more efficient code. Specially for
 * big-endian platforms.
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
#include <time.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>

#include "msgbuf.h"
#include "dhcpv6.h"
#include "random.h"
#include "if.h"
#include "ptime.h"
#include "net.h"

#define SECD(x) x
#define D(x)

#ifndef DHCP6_TIMESCALE
#define DHCP6_TIMESCALE 1
#endif

/* our max datagram size */
#define DEFAULT_RECV_BUFSIZ 1280

#define INF_MAX_DELAY	1
#define INF_TIMEOUT	1
#define INF_MAX_RT	120

#define SOL_MAX_DELAY	1
#define SOL_TIMEOUT	1
#define SOL_MAX_RT	120

#define REQ_TIMEOUT	1
#define REQ_MAX_RT	30
#define REQ_MAX_RC	10

#define REN_TIMEOUT	10
#define REN_MAX_RT	600

/* Predefined addresses */
#define DH6ADDR_ALLAGENT	"ff02::1:2"
#define DH6ADDR_ALLSERVER	"ff05::1:3"
#define DH6PORT_DOWNSTREAM	"546"
#define DH6PORT_UPSTREAM	"547"

static void
dh6_append_time_elapsed_opt(struct msgbuf_t **msg, time_t elapsed) {
	msgbuf_append_u16no(msg, DH6OPT_ELAPSED_TIME);
	msgbuf_append_u16no(msg, 2);
	msgbuf_append_u16no(msg, elapsed);
}

static void
dh6_append_reqoptions_opt(struct msgbuf_t **msg, int *opts, size_t nr_opts) {
	int i;

	assert(nr_opts && opts);

	msgbuf_append_u16no(msg, DH6OPT_ORO);
	msgbuf_append_u16no(msg, nr_opts * 2);
	for (i = 0; i < nr_opts; i++)
		msgbuf_append_u16no(msg, opts[i]);		
}

static void dh6_append_ia_na_opt(struct msgbuf_t **msg,
				 struct dhcpv6_option_ia_t *ia) {
	assert(ia);

	msgbuf_append_u16no(msg, DH6OPT_IA_NA);
	if (ia->iaddr.valid_lft)
		msgbuf_append_u16no(msg, 40);
	else
		msgbuf_append_u16no(msg, 12);
	msgbuf_append_u32no(msg, ia->iaid);
	msgbuf_append_u32no(msg, ia->t1);
	msgbuf_append_u32no(msg, ia->t2);

	if (ia->iaddr.valid_lft) {
		msgbuf_append_u16no(msg, DH6OPT_IADDR);
		msgbuf_append_u16no(msg, 24);
		
		msgbuf_append(msg, &ia->iaddr.addr, 16);
		msgbuf_append_u32no(msg, ia->iaddr.prefered_lft);
		msgbuf_append_u32no(msg, ia->iaddr.valid_lft);
	}		
}

static void
dh6_append_vendorclass_opt(struct msgbuf_t **msg,
			   struct dhcpv6_option_vendorclass_t *vc) {
	size_t end_pos;
	size_t optlen_pos;
	int i;
	
	if (!vc)
		return;
	
	msgbuf_append_u16no(msg, DH6OPT_VENDOR_CLASS);
	/* remember this position, later we will update with real len */
	optlen_pos = msgbuf_save(msg);
	msgbuf_append_u16no(msg, 0); /* zerolen */

	msgbuf_append_u32no(msg, vc->enterprise_nr);	
	for(i = 0; i < vc->nr_vcdata; i++) {
		msgbuf_append_u16no(msg, vc->vcdata[i].len);
		msgbuf_append(msg, vc->vcdata[i].data, vc->vcdata[i].len);
	}
	
	end_pos = msgbuf_save(msg);	
	/*
	 *  rewind the msgbuf and update the length field
	 */
	msgbuf_restore(msg, optlen_pos);
	msgbuf_append_u16no(msg, end_pos - optlen_pos - 2);
	msgbuf_restore(msg, end_pos);
}

static size_t dhcpv6_create_duid3(int s, char *ifname,
				  struct duid_t *duid, size_t size) {
	assert(size >= sizeof (*duid));
	duid->type = 3;
	
	return if_hwaddress(s, duid->dt.t3.addr, size - sizeof (*duid),
			    ifname, &(duid->dt.t3.hwtype)) + 4;
}

static time_t
dh6_compute_new_rto(time_t prev_rto, time_t max_rto) {
	time_t rnd;

	/* not strictly compliant, but close */
	random_fill(&rnd, sizeof rnd);
	rnd &= 0x1f;
	rnd -= 0xf;

	if (max_rto && (prev_rto < max_rto))
		return 2 * prev_rto + ((rnd*prev_rto) / 256);	    
	else		
		return max_rto + ((rnd*max_rto) / 256);
}

/*
 * Parses the options field within an IA option
 */
static void dhcpv6_parse_ia_opts(struct dhcpv6_option_ia_t *na,
				 unsigned char *buf, size_t buflen) {
	size_t pos = 0;
	int option_code, option_len;
	
	while(pos + 4 < buflen) {
		int mypos;
		
		option_code = buf[pos++] << 8;
		option_code += buf[pos++];
		option_len = buf[pos++] << 8;
		option_len += buf[pos++];
		
		/*
		 * dont let lengths pointing further away than the
		 * data we got slip through.
		 */
		if (option_len > (buflen - pos))
			return;

		mypos = pos;
		
		D(printf("%s: option_code=%d buflen=%d pos=%d option_len=%d\n",
			 __func__, option_code, buflen, pos, option_len));
		/* options specific parsing */
		switch (option_code)
		{
		case DH6OPT_IADDR:
		{
			memcpy(&na->iaddr.addr, buf + mypos, 16);
			mypos += 16;
			
			na->iaddr.prefered_lft	= buf[mypos++] << 24;
			na->iaddr.prefered_lft += buf[mypos++] << 16;
			na->iaddr.prefered_lft += buf[mypos++] << 8;
			na->iaddr.prefered_lft += buf[mypos++];
			
			na->iaddr.valid_lft	= buf[mypos++] << 24;
			na->iaddr.valid_lft    += buf[mypos++] << 16;
			na->iaddr.valid_lft    += buf[mypos++] << 8;
			na->iaddr.valid_lft    += buf[mypos++];

			/*
			 * flatten out inner options by simply folding the
			 * header length.
			 */
			option_len = mypos - pos;
		}
		break;
		
		case DH6OPT_STATUS_CODE:
		{
			na->status = malloc(sizeof *na->status + option_len);
			if (na->status) {
				na->status->code  = buf[mypos++] << 8;
				na->status->code += buf[mypos++];
				memcpy(na->status->str,
				       buf + mypos,
				       option_len - 2);
				na->status->str[option_len - 2] = 0;
			}
		}
		
		default:
			/* silently ignore */
			break;
		}
		pos += option_len;
	}
}

/*
 * Parses DHCPv6 messages.
 */
static int
dhcpv6_parse_msg(struct dhcpv6_message_t *reply,
		 unsigned char *buf, size_t buflen,
		 uint32_t expected_id,
		 int expected_type) {
	size_t pos = 0;
	struct dhcpv6_option_t *opts = NULL;

	/* header + 1 option is minimum */
	if (buflen < 8) {
		D(printf("short reply %s:%d\n", __func__, __LINE__));
		return EXIT_FAILURE;
	}
	
	reply->msgtype = buf[pos++];
	reply->transaction_id = buf[pos++] << 16;
	reply->transaction_id += buf[pos++] << 8;
	reply->transaction_id += buf[pos++];

	if ((expected_type != DH6_UNSPEC &&
	     reply->msgtype != expected_type)
	    || expected_id != reply->transaction_id) {
		D(printf("%s:%d: %s\n", __func__, __LINE__,
			 (expected_type != DH6_UNSPEC &&
			  reply->msgtype != expected_type)
			 ? "unexpected type" :
			 expected_id != reply->transaction_id ?
			 "unexpected transaction id" :
			 "short reply"));
		return EXIT_FAILURE;
	}
	
	while(pos < buflen - 4) {
		int option_code, option_len;
		int mypos;

		option_code = buf[pos++] << 8;
		option_code += buf[pos++];
		option_len = buf[pos++] << 8;
		option_len += buf[pos++];

		/*
		 * dont let lengths pointing further away than the
		 * data we got slip through.
		 */
		if (option_len > (buflen - pos)) {
			D(printf("options out of bounds %d %d\n", option_len, buflen - pos));
			goto err;
		}
		
		if (opts == NULL) {
			reply->options = malloc(sizeof(*opts) + option_len);
			opts = reply->options;
		}
		else {
			opts->next = malloc(sizeof(*opts) + option_len);
			opts = opts->next;		  
		}

		if (!opts)
			goto err;
		
		opts->code = option_code;
		opts->len = option_len;
		
		/*
		 * not needed as long as we calloc
		 */
		opts->next = NULL;
		opts->interp = NULL;
		opts->interp_delete = NULL;
		
		mypos = pos;
		
		/* options specific parsing */
		switch (opts->code)
		{
			case DH6OPT_IA_NA:
			{
				struct dhcpv6_option_ia_t *na;

				if (option_len < 12)
					goto err;

				na = malloc(sizeof *na + (option_len - 12));
				if (!na)
					goto err;

				na->iaid  = buf[mypos++] << 24;
				na->iaid += buf[mypos++] << 16;
				na->iaid += buf[mypos++] << 8;
				na->iaid += buf[mypos++];

				na->t1	= buf[mypos++] << 24;
				na->t1 += buf[mypos++] << 16;
				na->t1 += buf[mypos++] << 8;
				na->t1 += buf[mypos++];

				na->t2	= buf[mypos++] << 24;
				na->t2 += buf[mypos++] << 16;
				na->t2 += buf[mypos++] << 8;
				na->t2 += buf[mypos++];

				/* mark it as invalid */
				na->iaddr.valid_lft    = 0;
				na->status = 0;
				dhcpv6_parse_ia_opts(na, buf + mypos,
						     option_len
						     - (mypos - pos));
			
				opts->interp = na;
				opts->interp_delete =
					(void (*)(void*))dhcpv6_free_ia;
			}
			break;
		
			/*
			 * simple opaque nlv
			 */
			case DH6OPT_TIME_ZONE:
				opts->interp = opts->rawdata;
				break;

			case DH6OPT_SERVERID:
			case DH6OPT_CLIENTID:
			{			
				opts->interp = dhcpv6_parse_nodeid(buf + pos,
								   option_len);
				opts->interp_delete =
					(void (*)(void*))dhcpv6_free_nodeid;
			}
			break;
			/*
			 * list of binary represented ipv6 addresses
			 */
			case DH6OPT_SIP_SERVERS:
			case DH6OPT_DNS_SERVERS:
			case DH6OPT_NTP_SERVERS:
			{
				struct dhcpv6_option_addrlist_t *lopt;
				unsigned int nr_addr;

				nr_addr = option_len / 16;
				nr_addr %= 32; /* truncate */

				lopt = malloc(sizeof *lopt +
					      (sizeof(lopt->addr[0]) * nr_addr));
				if (!lopt)
					goto err;			
				lopt->nr_addr = nr_addr;
				memcpy(lopt->addr, buf + pos, nr_addr * 16);
				opts->interp = lopt;
				opts->interp_delete = free;
			}
			break;

			/*
			 * list of length,label
			 */
			case DH6OPT_SIP_DOMAINS:
			case DH6OPT_DOMAIN_LIST:
			{
				char *str;
				unsigned int nlen = 0;
				mypos = 0;

				if (option_len == 0)
					goto err;

				opts->interp = str = malloc(option_len + 1);
				if (!opts->interp)
					goto err;
			
				opts->interp_delete = free;
				str--;

				/* FIXME: Rewrite this loop.  */
				nlen = buf[pos + mypos++];
				while (mypos + nlen < option_len) {
					while (nlen
					       && mypos + nlen < option_len) {
						memcpy(str + 1,
						       buf + pos + mypos,
						       nlen);
						str += nlen + 1;
						*str = '.';
						mypos += nlen;
						nlen = buf[pos + mypos++];
					}
					*str = ' ';
					nlen = buf[pos + mypos++];
				}
				*str = 0; /* nul terminate */
			}
			break;
			default:
				/* silently ignore */
				break;
		}
		memcpy(opts->rawdata, buf + pos, option_len);
		pos += option_len;
	}

	assert(pos <= buflen);
	return EXIT_SUCCESS;
  err:
	D(printf("%s FAILED\n", __func__));
	dhcpv6_free_options(reply->options);
	return EXIT_FAILURE;
}

/*
 * Do a dhcpv6 transaction, send a message and wait for a reply.
 * Handles retransmision and validation/parsing of replies.
 */
static int dh6_do_transaction(int s, struct msgbuf_t **msg,
			      struct dhcpv6_message_t *reply,
			      int code,
			      time_t timeout,
			      time_t max_rt,
			      time_t max_delay)
{
	static unsigned char rbuf[DEFAULT_RECV_BUFSIZ];
	time_t start, begin, now;
	time_t rto = timeout;
	uint32_t transaction_id;
	ssize_t rlen;
	ssize_t savedpos;
	int ret = EXIT_FAILURE;

	assert((*msg)->size > 4);

	/*
	 * Insert the random transaction id in the message.
	 */
	random_fill((*msg)->buf + 1, 3);

	/* Remember the value of it in host byte order.  */
	transaction_id  = (*msg)->buf[1] << 16;
	transaction_id += (*msg)->buf[2] << 8;
	transaction_id += (*msg)->buf[3];

	/* Save the msgbuf position just before the time elapsed option.  */
	savedpos = msgbuf_save(msg);

	start = ptime();
	while (rto) {
		begin = ptime();

		msgbuf_restore(msg, savedpos);
		dh6_append_time_elapsed_opt(msg,
					    (begin - start) * 100);

		dh6_send_msg(s, msg, NULL, 0);
		do {
			rlen = dh6_recv_msg(s, rbuf, sizeof rbuf,
					    rto / DHCP6_TIMESCALE,
					    NULL, 0);
			if (rlen > 0) {
				ret = dhcpv6_parse_msg(reply,
						       rbuf,
						       rlen,
						       transaction_id,
						       code);
				if (ret == EXIT_SUCCESS)
					goto done;
				else {
					SECD(printf("bogus reply\n"));
				}
			}
			if (rlen == -1 && errno == EINTR)
				return ret;			
			now = ptime();
		} while((now - begin) < (rto / DHCP6_TIMESCALE));

		/* global timeout ? */
		if (max_delay && (now > start + max_delay))
			return ret;

		/* recompute rto, retransmit and try again */
		rto = dh6_compute_new_rto(rto, max_rt);
	}
  done:
	return ret;
}

/*
 * Does a stateless autoconfig. INFO-REQUEST / REPLY.
 */
int dhcpv6_do_stateless(struct dhcpv6_message_t *reply,
			struct dhcpv6_option_vendorclass_t *vclass,
			char *interface,
			int *options,
			size_t nr_options)
{
	struct dhcpv6_nodeid_t client;
	struct msgbuf_t *msg;
	int s = 0;
	int ret = EXIT_FAILURE;

	D(printf("%s\n", __func__));

	assert(interface);

	if ((s = dh6_create_and_bind_mc_socket(interface)) < 0)
		goto err;

	client.duid = alloca(sizeof *client.duid + 16);
	client.duidlen = dhcpv6_create_duid3(s, interface,
					     client.duid,
					     sizeof *client.duid + 16);
		
	if (!(msg = msgbuf_new(48)))
		goto err;
	msgbuf_append_u8(&msg, DH6_INFORM_REQ);
	msg->pos += 3; /* gap for tr-id */
	dhcpv6_append_node_id_opt(&msg, DH6OPT_CLIENTID, &client);
	dh6_append_vendorclass_opt(&msg, vclass);
	dh6_append_reqoptions_opt(&msg, options, nr_options);

	ret = dh6_do_transaction(s, &msg, reply,
				 DH6_REPLY,
				 INF_TIMEOUT,
				 INF_MAX_RT,
				 0);
  err:	
	msgbuf_free(msg);
	dh6_close(s);
	return ret;
}

/*
 * DHCPv6 server solicitation. Finds a neighbor server for later autoconfig.
 */
static void dh6_do_solicit(int s,
			   struct dhcpv6_nodeid_t *client,		    
			   struct dhcpv6_nodeid_t **server,
			   struct dhcpv6_option_vendorclass_t *vclass)
{
	struct dhcpv6_message_t reply;
	struct msgbuf_t *msg;
	struct dhcpv6_option_t *opt;
	
	msg = msgbuf_new(48);
	if (!msg)
		return;
	
	msgbuf_append_u8(&msg, DH6_SOLICIT);
	msg->pos += 3; /* gap for tr-id */
	dhcpv6_append_node_id_opt(&msg, DH6OPT_CLIENTID, client);
	dh6_append_vendorclass_opt(&msg, vclass);
	
	if (dh6_do_transaction(s, &msg, &reply,
			       DH6_UNSPEC,
			       SOL_TIMEOUT,
			       SOL_MAX_RT,
			       0) != EXIT_SUCCESS)
		goto done;
	
	opt = reply.options;
	while (opt) {
		if (opt->code == DH6OPT_SERVERID) {
			/* found one, save him from destruction */
			*server = opt->interp;
			opt->interp_delete = NULL;
		}
		opt = opt->next;
	}
	dhcpv6_free_options(reply.options);
  done:
	msgbuf_free(msg);
}

/*
 * Does a REQUEST for configuration options. The request is IPv6 multicasted
 * to a specific server duid.
 */
static int dh6_do_request(int s,
			  struct dhcpv6_nodeid_t *client,
			  struct dhcpv6_nodeid_t *server,		     
			  struct dhcpv6_option_ia_t *ia,
			  struct dhcpv6_option_vendorclass_t *vclass,
			  int *options,
			  size_t nr_options,
			  struct dhcpv6_message_t *reply)
{
	struct msgbuf_t *msg;
	int ret;
	
	msg = msgbuf_new(48);
	if (!msg)
		return EXIT_FAILURE;
	
	msgbuf_append_u8(&msg, DH6_REQUEST);
	msg->pos += 3; /* gap for tr-id */
	dhcpv6_append_node_id_opt(&msg, DH6OPT_CLIENTID, client);
	dh6_append_vendorclass_opt(&msg, vclass);
	dhcpv6_append_node_id_opt(&msg, DH6OPT_SERVERID, server);
	dh6_append_ia_na_opt(&msg, ia);
	dh6_append_reqoptions_opt(&msg, options, nr_options);
	ret = dh6_do_transaction(s, &msg, reply,
				 DH6_REPLY,
				 REQ_TIMEOUT,
				 REQ_MAX_RT,
				 REQ_TIMEOUT * REQ_MAX_RC);
	msgbuf_free(msg);
	return ret;
}

/*
 * Does the entire statefull autoconfiguration. Solicit and requests.
 */
int dhcpv6_do_statefull(struct dhcpv6_message_t *reply,
			struct dhcpv6_nodeid_t **rserver,
			struct dhcpv6_option_ia_t *ia,
			struct dhcpv6_option_vendorclass_t *vclass,
			char *interface,
			int *options,
			size_t nr_options)
{
	struct dhcpv6_nodeid_t *server = NULL;
	struct dhcpv6_nodeid_t client;
	struct dhcpv6_option_ia_t lia;
	int s = 0;
	int ret = EXIT_FAILURE;
	
	if ((s = dh6_create_and_bind_mc_socket(interface)) < 0)
		goto err;

	client.duid = alloca(sizeof *client.duid + 16);
	client.duidlen = dhcpv6_create_duid3(s, interface,
					     client.duid,
					     sizeof *client.duid + 16);
	
	/* TODO: support multiple server responses */
	dh6_do_solicit(s, &client, &server, vclass);

	if (!server)
		goto err;

	
	/*
	 * The caller may provide an ia with an indication of a wanted ip
	 * address.
	 */
	if (!ia) {
		ia = &lia;		
		ia->iaid = if_nametoindex(interface);
		ia->t1 = 0;
		ia->t2 = 0;
		ia->iaddr.valid_lft = 0; /* invalidate */
	}
	
	ret = dh6_do_request(s, &client, server,
			     ia, vclass,
			     options, nr_options,
			     reply);

	if (ret != EXIT_SUCCESS) {
		free(server);
		server = NULL;
	}
  err:
	*rserver = server;
	dh6_close(s);
	return ret;
}

/*
 * Try to reclaim a previously held IA.
 */
int dhcpv6_do_reclaim(int cmd,
		      struct dhcpv6_message_t *reply,
		      struct dhcpv6_nodeid_t **rserver,
		      struct dhcpv6_option_ia_t *ia,
		      struct dhcpv6_option_vendorclass_t *vclass,
		      char *interface,
		      int *options,
		      size_t nr_options,
		      time_t timeout)
{
	struct dhcpv6_nodeid_t *server = *rserver;
	struct dhcpv6_nodeid_t client;
	int s = -1;
	int ret = EXIT_FAILURE;
	struct msgbuf_t *msg;

	if (!server)
		goto err;
	
	if ((s = dh6_create_and_bind_mc_socket(interface)) < 0)
		goto err;

	client.duid = alloca(sizeof *client.duid + 16);
	client.duidlen = dhcpv6_create_duid3(s, interface,
					     client.duid,
					     sizeof *client.duid + 16);
	
	msg = msgbuf_new(48);
	if (!msg)
		goto err;
	
	msgbuf_append_u8(&msg, cmd);
	msg->pos += 3; /* gap for tr-id */	
	dhcpv6_append_node_id_opt(&msg, DH6OPT_CLIENTID, &client);
	dh6_append_vendorclass_opt(&msg, vclass);
	dhcpv6_append_node_id_opt(&msg, DH6OPT_SERVERID, server);
	
	dh6_append_ia_na_opt(&msg, ia);
	dh6_append_reqoptions_opt(&msg, options, nr_options);
	ret = dh6_do_transaction(s, &msg, reply,
				 DH6_REPLY,
				 REN_TIMEOUT,
				 REN_MAX_RT,
				 timeout);

	msgbuf_free(msg);
  err:
	if (s >= 0)
		dh6_close(s);
	return ret;
}

void dhcpv6_append_node_id_opt(struct msgbuf_t **msg, int type,
			       struct dhcpv6_nodeid_t *node) {
	struct duid_t *duid = node->duid;
	size_t start;
	size_t duidlen = node->duidlen;
	
	msgbuf_append_u16no(msg, type);
	msgbuf_append_u16no(msg, duidlen);
	start = msgbuf_save(msg);
	msgbuf_append_u16no(msg, duid->type);
	switch (duid->type)
	{
	case 1:
		msgbuf_append_u16no(msg, duid->dt.t1.hwtype);
		msgbuf_append_u32no(msg, duid->dt.t1.time);
		msgbuf_append(msg, duid->dt.t1.addr,
			      duidlen - ((*msg)->pos - start));
		break;
	case 2:
		msgbuf_append_u32no(msg, duid->dt.t2.enterprise_nr);
		msgbuf_append(msg, duid->dt.t2.addr,
			      duidlen - ((*msg)->pos - start));
		break;
	case 3:
		msgbuf_append_u16no(msg, duid->dt.t3.hwtype);
		msgbuf_append(msg, duid->dt.t3.addr,
			      duidlen - ((*msg)->pos - start));
		break;
	}
}

/*
 * parses DHCPv6 options
 */
struct dhcpv6_nodeid_t *
dhcpv6_parse_nodeid(unsigned char *buf, size_t buflen) {
	
	struct dhcpv6_nodeid_t *node;
	struct duid_t *duid;
	int mypos = 0;
	
	int duidtype;

	if (buflen < 4)
		return NULL;
	
	node = malloc(sizeof *node);
	if (!node)
		return NULL;
	node->duid = NULL;
	
	duidtype  = buf[mypos++] << 8;
	duidtype += buf[mypos++];
			
	/* link-layer address plus time */
	duid = malloc(buflen);
	if (!duid)
		goto err;	
	node->duid = duid;
	
	switch (duidtype) {
	case 1:
	{					
		if (buflen < 6)
			goto err;
		
		duid->type	    = 1;
		duid->dt.t1.hwtype  = buf[mypos++] << 8;
		duid->dt.t1.hwtype += buf[mypos++];
		duid->dt.t1.time    = buf[mypos++] << 24;
		duid->dt.t1.time   += buf[mypos++] << 16;
		duid->dt.t1.time   += buf[mypos++] << 8;
		duid->dt.t1.time   += buf[mypos++];
		memcpy(duid->dt.t1.addr,
		       buf + mypos,
		       buflen - mypos);
	}
	break;
	case 2:
	{	
		duid->type		  = 2;
		duid->dt.t2.enterprise_nr = buf[mypos++] << 24;
		duid->dt.t2.enterprise_nr+= buf[mypos++] << 16;
		duid->dt.t2.enterprise_nr+= buf[mypos++] << 8;
		duid->dt.t2.enterprise_nr+= buf[mypos++];
				
		memcpy(duid->dt.t2.addr,
		       buf + mypos, buflen - mypos);
	}
	break;
	case 3:
	{				
		duid->type	    = 3;
		duid->dt.t3.hwtype  = buf[mypos++] << 8;
		duid->dt.t3.hwtype += buf[mypos++];
		memcpy(duid->dt.t3.addr,
		       buf + mypos,
		       buflen - mypos);
	}
	break;
				
	case 0:
	default:
		/* unsupported ignore */
		break;
	}			
	node->duidlen = buflen;	
	return node;
  err:
	if (node)
		free(node->duid);
	free(node);
	return NULL;
}
					     
void dhcpv6_free_nodeid(struct dhcpv6_nodeid_t *node) {
	if (node)
		free(node->duid);
	free(node);
}

void dhcpv6_free_ia(struct dhcpv6_option_ia_t *ia) {
	if (ia)
		free(ia->status);
	free(ia);
}

void dhcpv6_free_options(struct dhcpv6_option_t *opts) {
	while(opts) {
		void *tmp;
		tmp = opts;
		if (opts->interp && opts->interp_delete) {
			opts->interp_delete(opts->interp);
		}
		opts = opts->next;
		free(tmp);
	}
}
