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
 * get raflags via netlink
 * 
 * Authors:          Edgar E. Iglesias <edgar@axis.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_NETLINK

#if HAVE_STDINT_H
#include <stdint.h>
#endif
#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "if.h"

/* turn this on when bug-hunting */
#define D(x)

int netlink_open(void)
{
	struct sockaddr_nl nl_addr;
	int s;
	
	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s <= 0)
		return -1;
	
	memset(&nl_addr, 0, sizeof(nl_addr));
	nl_addr.nl_family = AF_NETLINK;
	if (bind(s, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) < 0) {
		D(printf("netlink bind error"));
		close(s);
		return -1;
	}
	return s;
}

static void get_if_raflags(struct nlmsghdr *nlm, int nlm_len,
		    int ifindex, int *raflags) 
{
	struct ifinfomsg *ifim = (struct ifinfomsg *)NLMSG_DATA(nlm);
	struct rtattr *rta;
	size_t rtasize, rtapayload;
	void *rtadata;
	
	if (ifim->ifi_family != AF_INET6 || nlm->nlmsg_type != RTM_NEWLINK)
		return;
	if (ifim->ifi_index != ifindex)
		return;
	
	rtasize = NLMSG_PAYLOAD(nlm, nlm_len) - NLMSG_ALIGN(sizeof(*ifim));
	for (rta = (struct rtattr *) (((char *) NLMSG_DATA(nlm)) +
				      NLMSG_ALIGN(sizeof(*ifim)));
	     RTA_OK(rta, rtasize);
	     rta = RTA_NEXT(rta, rtasize)) {
		rtadata = RTA_DATA(rta);
		rtapayload = RTA_PAYLOAD(rta);
		
		switch(rta->rta_type) {
		case IFLA_IFNAME:
			break;
#ifdef IFLA_PROTINFO
		case IFLA_PROTINFO:
		{
			struct rtattr *rta1;
			size_t rtasize1;
			
			rtasize1 = rta->rta_len;
			for (rta1 = (struct rtattr *)rtadata;
			     RTA_OK(rta1, rtasize1);
			     rta1 = RTA_NEXT(rta1, rtasize1)) {
				void *rtadata1 = RTA_DATA(rta1);
				switch(rta1->rta_type) {
				case IFLA_INET6_FLAGS:
					/* flags for
					 * IF_RA_MANAGED/IF_RA_OTHERCONF
					 */
					if (raflags)
						*raflags = *((u_int32_t *)rtadata1);
					if (*((u_int32_t *)rtadata1) & IF_RA_MANAGED)
						D(printf( 
							  "interface managed flags set"));
					if (*((u_int32_t *)rtadata1) & IF_RA_OTHERCONF)
						D(printf(
							  "interface otherconf flags set"));
					D(printf("raflags=%x\n", *raflags));
					break;
				default:
					break;
				}
			}
		}
		break;
#endif
		default:
			break;
		}
	}
	return;
}

int netlink_send_rtgenmsg(int sd, int request, int flags, int seq)
{
	struct sockaddr_nl nl_addr;
	struct nlmsghdr *nlm_hdr;
	struct rtgenmsg *rt_genmsg;
	char buf[NLMSG_ALIGN (sizeof (struct nlmsghdr)) +
		 NLMSG_ALIGN (sizeof (struct rtgenmsg))];

	memset(&buf, 0, sizeof(buf));

	nlm_hdr = (struct nlmsghdr *)buf;
	nlm_hdr->nlmsg_len = NLMSG_LENGTH (sizeof (*rt_genmsg));
	nlm_hdr->nlmsg_type = request;
	nlm_hdr->nlmsg_flags = flags | NLM_F_REQUEST;
	nlm_hdr->nlmsg_pid = getpid();
	nlm_hdr->nlmsg_seq = seq;

	memset(&nl_addr, 0, sizeof(nl_addr));
	nl_addr.nl_family = AF_NETLINK;

	rt_genmsg = (struct rtgenmsg*)NLMSG_DATA(nlm_hdr);
	rt_genmsg->rtgen_family = AF_INET6;
	return sendto(sd, (void *)nlm_hdr, nlm_hdr->nlmsg_len, 0,
		      (struct sockaddr *)&nl_addr, sizeof(nl_addr)); 
}

int netlink_recv_if_raflags(int sd, int seq, int ifindex)
{
	struct nlmsghdr *nlm;
	struct msghdr msgh;
	struct sockaddr_nl nl_addr;
	char *buf = NULL;
	size_t newsize = 65536, size = 0;
	int msglen;
	int if_raflags = 0;

	while (1) {
		void *newbuf = realloc(buf, newsize);
		if (newbuf == NULL) {
			break;
		}
		buf = newbuf;
		do { 
			struct iovec iov;
			iov.iov_base = buf;
			iov.iov_len = newsize;
			
			memset(&msgh, 0, sizeof(msgh));
			msgh.msg_name = (void *)&nl_addr;
			msgh.msg_namelen = sizeof(nl_addr);
			msgh.msg_iov = &iov;
			msgh.msg_iovlen = 1;
			msglen = recvmsg(sd, &msgh, 0);
		} while (msglen < 0 && errno == EINTR);
		
		if (msglen < 0 || msgh.msg_flags & MSG_TRUNC) {
			size = newsize;
			newsize *= 2;
			continue;
		} else if (msglen == 0) 
			break;
		/* buf might have some data not for this request */
		for (nlm = (struct nlmsghdr *)buf; NLMSG_OK(nlm, msglen);
		     nlm = (struct nlmsghdr *)NLMSG_NEXT(nlm, msglen)) {
			if (nlm->nlmsg_type == NLMSG_DONE ||
			    nlm->nlmsg_type == NLMSG_ERROR) {
				goto out;
			}
			if (nlm->nlmsg_pid != getpid() ||
			    nlm->nlmsg_seq != seq)
				continue;
			
			get_if_raflags(nlm,
				       msglen,
				       ifindex, &if_raflags);
			
		}
		free(buf);
		buf = NULL;
	}
  out:
	free(buf);
	return if_raflags;
}
#endif
