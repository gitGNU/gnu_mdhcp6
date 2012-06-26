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
 * mdhcp6 - a thin dhcpv6 client for embedded unix-like systems.
 *
 * Authors:	     Edgar E. Iglesias <edgar@axis.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "msgbuf.h"
#include "dhcpv6.h"
#include "optionmap.h"
#include "lease.h"
#include "notify.h"
#include "if.h"
#include "ptime.h"

#define D(x)

/* maximum number of request options */
#define MAX_REQ_DHCP_OPTS 32

#define IRT_DEFAULT 86400
#define IRT_MINIMUM 600
#define IRT_MDHCP6_DEFAULT (2*60*60) /* stateless refresh every 2 hours */

struct arguments
{
	char *interface;
	char *execute;
	char *pidfile;
	char *leasefile;
	int   force;
	int   force_statefull;
	int   updateresolv;
	int   no_daemon;
	int   roptions[MAX_REQ_DHCP_OPTS];
	int   nr_roptions;

	/* Only one enterprise number */
	uint32_t             vclass_enterprise_nr;

	const unsigned char *vclass_data[MAX_VC_DATA];
	int		     vclass_data_count;
};

static struct arguments args =
{
	NULL,
	NULL,
	NULL,
	NULL,
	0,
	0,
	0,
	0,

	/*
	 * Default list of options to request
	 */
	{
		DH6OPT_SIP_DOMAINS,
		DH6OPT_SIP_SERVERS,
		DH6OPT_DNS_SERVERS,
		DH6OPT_DOMAIN_LIST,
		DH6OPT_NTP_SERVERS,
		DH6OPT_TIME_ZONE
	},
	6,
	/* Vclass options */
	0,
	{ 0 },
	0
};

enum dhcpv6_policy_t {
	DHCPV6_DO_NADA,
	DHCPV6_DO_RACHECK,
	DHCPV6_DO_MANAGED,
	DHCPV6_DO_OTHER,
	DHCPV6_DO_RENEW,
	DHCPV6_DO_REBIND
};

static struct lease_t lease;
static sig_atomic_t running = 1;
static const char mdhcp6_usagestr[] = \
"mdhcp6 " PACKAGE_VERSION "\n"
"-e   exec-script\n"
"-fs  force statefull dhcp transaction\n"
"-fo  force stateless dhcp transaction\n"
"-l   leasefile\n"
"-p   pidfile\n"
"-r   comma separated list of options to request\n"
"-i   iface\n"
"-n   no-daemon\n"
"-E   enterprise number\n"
"-V   vendor-class-data string";

static void usage(void) {
	puts(mdhcp6_usagestr);
}

/*
 * parses the string of cli provided DHCP options to request for.
 * The string is a comma separated list of numbers.
 */
static int parse_dhcp_options(char *s, int *opts, size_t maxlen)
{
	char *next = s;
	int i = 0;
	while (i < maxlen && next) {
		opts[i++] = strtoul(s, &next, 0);
		if (next == s)
			break;
		else
			s = next + 1;
	}
	return --i;
}

static void parse_arguments(int argc, char **argv)
{
	int c;

	while (1) {
		c = getopt(argc, argv, "E:e:f:hi:l:np:r:V:v");
		if (c == -1)
			break;

		switch (c) {
		case 'e':
			args.execute = optarg;
			break;
		case 'E':
			args.vclass_enterprise_nr
				= strtoul(optarg, (char **)NULL, 0);
			break;
		case 'f':
			args.force = 1;
			if (optarg && *optarg == 's')
				args.force_statefull = 1;
			break;
		case 'i':
			args.interface = optarg;
			break;
		case 'l':
			args.leasefile = optarg;
			break;
		case 'p':
			args.pidfile = optarg;
			break;
		case 'r':
			args.nr_roptions =
				parse_dhcp_options(optarg,
						   args.roptions,
						   sizeof args.roptions
						   /
						   sizeof args.roptions[0]);
			break;
		case 'n':
			args.no_daemon = 1;
			break;
		case 'V':
			args.vclass_data[args.vclass_data_count++] = (const unsigned char *) optarg;
			break;
		case 'v':
		case 'h':
		default:
			usage();
			exit(EXIT_FAILURE);
			break;
		}
	}
}

/*
 * Decide what to do based on the interfaces ra flags
 */
static enum dhcpv6_policy_t dhcpv6_policy(int flags) {
	int received;
	enum dhcpv6_policy_t p = DHCPV6_DO_NADA;

	received = flags & IF_RA_RCVD;

	if (args.force) {
		if (args.force_statefull)
			p = DHCPV6_DO_MANAGED;
		else
			p = DHCPV6_DO_OTHER;
	} else {
		if (received) {
			if (received && (flags & (IF_RA_OTHERCONF)))
				p = DHCPV6_DO_OTHER;
			if (received && (flags & (IF_RA_MANAGED)))
				p = DHCPV6_DO_MANAGED;
		}
		else
			p = DHCPV6_DO_MANAGED;
	}

	/* If we already got a lease and we continue with managed, try
	   to renew it.  */
	if (p == DHCPV6_DO_MANAGED && lease.ia && lease.server)
		p = DHCPV6_DO_RENEW;

	return p;
}

static void create_pidfile(char *file) {
	FILE *fp;
	fp = fopen(file, "w+");
	if (fp == NULL)
		return;
	fprintf(fp, "%d", getpid());
	fclose(fp);
}

/*
 * fabricate an ia to put on our initial request, we aim for infinte lifetimes.
 */
static struct dhcpv6_option_ia_t *
fabricate_initial_ia(struct in6_addr *addr, char *interface) {
	struct dhcpv6_option_ia_t *ia;

	ia = calloc(sizeof *ia, 1);
	if (ia) {
		memcpy(&ia->iaddr.addr, addr, sizeof *addr);
		ia->iaddr.prefered_lft = 0xffffffff;
		ia->iaddr.valid_lft = 0xffffffff;
		ia->iaid = if_nametoindex(interface);
	}

	return ia;
}

/*
 * Callback registered with the optionmap to update a string option value.
 * Only update if the value differs from the one we hold.
 */
static void update_string(struct optionmap_t *om, void *newvalue) {
	char *str = newvalue;
	size_t len;

	/* empty new value ? */
	if (!str || (len = strlen(str)) == 0) {
		om->needsreconfig = 1;
		free(om->value);
		om->value = NULL;
		return;
	}

	if (!om->value || memcmp(om->value, newvalue, len) != 0) {
		free(om->value);
		om->value = malloc(len + 1);
		if (om->value) {
			memcpy(om->value, newvalue, len + 1);
		}
		om->needsreconfig = 1;
	}
}

/*
 * Callback registered with the optionmap to update an array of ipv6 addresses.
 * Only update if the value differs from the one we hold.
 */
static void update_addrlist(struct optionmap_t *om, void *newvalue) {
	struct dhcpv6_option_addrlist_t *opt = newvalue;
	char *nvalue, *str;
	int a;
	size_t size;

	assert(opt);

	/*
	 * space for a space separated list with traling nul
	 * character.
	 */
	size = (INET6_ADDRSTRLEN * opt->nr_addr) + opt->nr_addr + 1;
	str = nvalue = malloc(size);
	if (!str)
		return;

	for (a = 0; a < opt->nr_addr; a++) {
		inet_ntop(AF_INET6, opt->addr + a,
			  str,
			  INET6_ADDRSTRLEN);
		str += strlen(str);
		*str++ = ' ';
	}
	*(str - 1) = 0;

	if (!om->value || memcmp(om->value, nvalue, str - nvalue) != 0) {
		free(om->value);
		om->value = nvalue;
		om->needsreconfig = 1;
	}
	else
		free(nvalue);
}

/*
 * Dont forget to cleanup after us before we leave. On most unix systmes
 * this doesnt matter (the kernel will clean up after us) but it is useful
 * in the verification process while running valgrind and seeing zero leaks.
 */
static int graceful_exit(void) {
	lease_cleanup(&lease);

	lease_set_ia(&lease, NULL);
	memset(&lease.addr, 0, 16);
	notify_exec_script(args.execute, &lease);

	return EXIT_SUCCESS;
}

static void sigint(int signum) {
	running = 0;
	lease_cleanup(&lease);
	exit(EXIT_SUCCESS);
}

static void sigterm(int signum) {
	running = 0;
}

/* Wrapper around sleep to handle integer overflows and avoid negative
 * interpretations by sleep(). We continously poll for RA reconfig.
 * TODO: Find a nice way to let netlink notify us when there are new netif
 *       flags to be read.
 */
static inline void dh_sleep(uint32_t timeout, int raflags)
{
	time_t start, now, diff;
	int64_t tleft;
	int new_raflags = raflags;
	int max_sleep;

	/* If we already got an RA we poll for net reconfig of the managed
	   and other flags through RA. A 120s poll interval should be ok.
	   If we haven't got an RA yet, we might have incorrectly setup DHCP
	   addresses so we poll more agressively.
	   If the user has forced a specific mode, we saturate the sleep to
	   avoid integer overflows.
	*/
	if (args.force)
		max_sleep = 60 * 60 * 24 * 7; /* avoid overflow.  */
	else if (raflags & IF_RA_RCVD)
		max_sleep = 60;               /* poll for RA reconfig.  */
	else
		max_sleep = 16;               /* Waiting for RA.  */

	D(printf("%s(%d, %x)\n", __func__, timeout, raflags));
	tleft = timeout;
	start = ptime();
	do
	{
		unsigned int sleep_time;

		/*
		 * Staturate sleep time to avoid negative interpretations by
		 * sleep().
		 */
		sleep_time = tleft; /* Avoid 64bit cmp.  */
		if (sleep_time > max_sleep)
			sleep_time = max_sleep;
		sleep(sleep_time);

		/* Now, compute the actual time slept and decrease timeout.  */
		now = ptime();
		diff = now - start; /* signed arithmetics.  */
		start = now;
		tleft -= diff;

		if (!args.force)
			new_raflags = if_get_raflags(args.interface);
	} while (running && tleft > 0 && new_raflags == raflags);
}

int run_mdhcp6(int argc, char **argv)
{
	unsigned int force_notify = 1;
	uint32_t timeout;
	enum dhcpv6_policy_t action = DHCPV6_DO_RACHECK;
	int ifindex, if_raflags = 0;
	int r = EXIT_FAILURE;
	int leaseisvalid;
	int statuscode;
	int needsreconfig;
	struct dhcpv6_option_t *opt;
	struct sigaction saction;
	struct dhcpv6_message_t reply = {0};
	struct dhcpv6_option_vendorclass_t *vclass = NULL;
	int i;

	lease_init(&lease);
	memset(&saction, 0, sizeof saction);

	sigfillset (&saction.sa_mask);
	saction.sa_handler = sigint;
	saction.sa_flags = 0;
	sigaction(SIGINT, &saction, NULL);

	sigfillset (&saction.sa_mask);
	saction.sa_handler = sigterm;
	saction.sa_flags = 0;
	sigaction(SIGTERM, &saction, NULL);

	parse_arguments(argc, argv);

	if (args.interface == NULL) {
		usage();
		return EXIT_FAILURE;
	}

	ifindex = if_nametoindex(args.interface);

	if (!args.no_daemon) {
		if (daemon(0, 0) == -1) {
			perror("daemon\n");
			return EXIT_FAILURE;
		}
	}

	openlog("mdhcp6", LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "mdhcp6 starting\n");

	optionmap_add(lease.omap,
		      DH6OPT_DNS_SERVERS, "dh6_dnssrv", update_addrlist);
	optionmap_add(lease.omap,
		      DH6OPT_NTP_SERVERS, "dh6_ntpsrv", update_addrlist);
	optionmap_add(lease.omap,
		      DH6OPT_SIP_SERVERS, "dh6_sipsrv", update_addrlist);

	optionmap_add(lease.omap,
		      DH6OPT_SIP_DOMAINS, "dh6_sipdomains", update_string);
	optionmap_add(lease.omap,
		      DH6OPT_DOMAIN_LIST, "dh6_dnslist", update_string);
	optionmap_add(lease.omap,
		      DH6OPT_TIME_ZONE, "dh6_timezone", update_string);

	setenv("dh6_iface", args.interface, 1);

	if (args.pidfile)
		create_pidfile(args.pidfile);

	lease_readfile(args.leasefile, &lease);

	if (args.vclass_enterprise_nr) {
		vclass = calloc(1, sizeof *vclass);
		if (vclass) {
			vclass->enterprise_nr = args.vclass_enterprise_nr;
			if (args.vclass_data_count > 0) {
				vclass->nr_vcdata = args.vclass_data_count;

				for (i = 0; i < vclass->nr_vcdata; i++) {
				  vclass->vcdata[i].len
				    = strlen((char*) args.vclass_data[i]);
				  vclass->vcdata[i].data = args.vclass_data[i];
				}
			}
		}
	}

	/* fabricate the initial ia if we have an old lease */
	if (memcmp(&in6addr_any, &lease.addr, sizeof lease.addr) != 0)
		lease.ia = fabricate_initial_ia(&lease.addr, args.interface);

	/* Decide what to start with ?  */
	action = dhcpv6_policy(if_raflags);

	/*
	 * the main loop
	 */
	do
	{
		int new_if_raflags;
		r = EXIT_FAILURE;
		timeout = 60;

		new_if_raflags = if_get_raflags(args.interface);
		if (new_if_raflags != if_raflags) {
			D(printf ("ra change! Update policy! %x %x\n",
				  new_if_raflags, if_raflags));
			if_raflags = new_if_raflags;
			lease.raflags = if_raflags;
			action = dhcpv6_policy(if_raflags);
		}
		D(printf("action=%d\n", action));
		lease.state = action;
		switch (action)
		{
		case DHCPV6_DO_RACHECK:
		{
			r = EXIT_SUCCESS;
			action = dhcpv6_policy(if_raflags);
			continue;
		}
		break;
		case DHCPV6_DO_MANAGED:
			if (lease.ia && lease.ia->iaddr.valid_lft)
				action = DHCPV6_DO_REBIND;

			lease_set_server(&lease, NULL);
			/* do_statefull will overwrite the server */
			r = dhcpv6_do_statefull(&reply,
						&lease.server,
						lease.ia,
						vclass,
						args.interface,
						args.roptions,
						args.nr_roptions);
			break;
		case DHCPV6_DO_OTHER:
			/* invalidate ia and server */
			lease_set_ia(&lease, NULL);
			lease_set_server(&lease, NULL);
			r = dhcpv6_do_stateless(&reply,
						vclass,
						args.interface,
						args.roptions,
						args.nr_roptions);
			timeout = IRT_MDHCP6_DEFAULT;
			break;
		case DHCPV6_DO_NADA:
			/* RA says we shoudnt do DHCP. If we've got any
			   previous leases we drop them here.  */
			if (lease_drop(&lease)) {
				D(printf("NO DHCP, Cleanup leases.\n"));
				notify_exec_script(args.execute, &lease);
			}
			timeout = 60 * 60 * 24;
			r = EXIT_SUCCESS;
			break;
		case DHCPV6_DO_RENEW:
			/* renew will read the server */
			r = dhcpv6_do_reclaim(DH6_RENEW,
					      &reply,
					      &lease.server,
					      lease.ia,
					      vclass,
					      args.interface,
					      args.roptions,
					      args.nr_roptions,
					      lease.aquired ? 60 : 5);
			break;
		case DHCPV6_DO_REBIND:
			/* renew will read the server */
			r = dhcpv6_do_reclaim(DH6_REBIND,
					      &reply,
					      &lease.server,
					      lease.ia,
					      vclass,
					      args.interface,
					      args.roptions,
					      args.nr_roptions,
					      60);
			break;
		default:
			assert(0);
			break;
		}

		if (r == EXIT_FAILURE)
			action = DHCPV6_DO_RACHECK; /* back to init */

		statuscode = -1;
		leaseisvalid = 0;
		opt = reply.options;
		while (opt) {
			switch (opt->code) {

			case DH6OPT_NTP_SERVERS:
			case DH6OPT_DNS_SERVERS:
			case DH6OPT_SIP_SERVERS:
			case DH6OPT_SIP_DOMAINS:
			case DH6OPT_DOMAIN_LIST:
			case DH6OPT_TIME_ZONE:
				optionmap_up(lease.omap,
					     opt->code, opt->interp);
				break;
			case DH6OPT_IA_NA:
			{
				struct dhcpv6_option_ia_t *na = opt->interp;
				int iaddrisvalid = 0;

				/*
				 * did we get a valid IADDR?
				 */
				if (na->iaddr.valid_lft != 0) {
					D(printf("IA-NA: got lease\n"));
					/* record the relevant timing */
					lease.aquired = ptime();
					timeout = na->t1;

					/* save it from destruction */
					lease_set_ia(&lease, NULL);
					lease.ia = na;
					opt->interp_delete = NULL;
					memcpy(&lease.addr,
					       &na->iaddr.addr, 16);

					/* sync the lease file */
					lease_sync(args.leasefile, &lease);

					action = DHCPV6_DO_RENEW;
					iaddrisvalid = 1;
				}
				else {
					D(printf("IA-NA: invalid lifetime\n"));
				}

				if (!na->status) {
					if(iaddrisvalid != 0) {
						/* no status means success */
						statuscode = 0;
						leaseisvalid = 1;
					}
					break;
				}

				statuscode = na->status->code;
				if(na->status->code != 0) {
					D(printf("IA-NA: error %d\n",
						 na->status->code));
					/*
					 * Something is wrong, go back
					 * to initial state.
					 */
					lease_set_server(&lease, NULL);

					if (action == DHCPV6_DO_RENEW) {
						/*
						 * keep lease address, we might
						 * be able to get the same
						 * after a complete solicit,
						 * request and reply sequence.
						 */
						action = DHCPV6_DO_RACHECK;
						/* fast-retry */
						timeout = 1;
					}
					else
						lease_set_ia(&lease, NULL);
				}
				else
					leaseisvalid = 1;

				D(printf("status: %s\n",
					 na->status->str));
			}
			break;
			default:
				/* unsupported, silent ignore */
				break;
			}
			opt = opt->next;
		}

		if (!leaseisvalid)
			lease_set_server(&lease, NULL);

		dhcpv6_free_options(reply.options);
		reply.options = NULL;

		/*
		 * dont configure anything until we give the solicit/request
		 * a chance to get the same address. This is to avoid multiple
		 * reconfigurations (once without address and once with).
		 */
		if (statuscode == DH6OPT_STCODE_NOBINDING)
			continue;


		needsreconfig = (leaseisvalid || statuscode == -1)
			&& lease_test_and_clear_reconfig(&lease);

		if (needsreconfig) {
			notify_exec_script(args.execute, &lease);
		} else if (force_notify && leaseisvalid && !statuscode) {
			force_notify = 0;
			notify_exec_script(args.execute, &lease);
		}

		dh_sleep(timeout, if_raflags);
	} while(running);

	free(vclass);
	return graceful_exit();
}
