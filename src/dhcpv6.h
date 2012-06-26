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
 * Authors:	     Edgar E. Iglesias <edgar@axis.com>
 */


/*
 * some of this stuff should live in dhcpv6.c but to make life easier for the
 * unit tests, they live here.
 */

/* Message type */
#define DH6_UNSPEC	0
#define DH6_SOLICIT	1
#define DH6_ADVERTISE	2
#define DH6_REQUEST	3
#define DH6_CONFIRM	4
#define DH6_RENEW	5
#define DH6_REBIND	6
#define DH6_REPLY	7
#define DH6_RELEASE	8
#define DH6_DECLINE	9
#define DH6_RECONFIGURE 10
#define DH6_INFORM_REQ	11
#define DH6_RELAY_FORW	12
#define DH6_RELAY_REPL	13

/* options */
#define DH6OPT_CLIENTID 1
#define DH6OPT_SERVERID 2
#define DH6OPT_IA_NA 3
#define DH6OPT_IA_TA 4
#define DH6OPT_IADDR 5
#define DH6OPT_ORO 6
#define DH6OPT_PREFERENCE 7
#  define DH6OPT_PREF_UNDEF 0
#  define DH6OPT_PREF_MAX 255
#define DH6OPT_ELAPSED_TIME 8
#define DH6OPT_RELAY_MSG 9

#define DH6OPT_AUTH 11
#define DH6OPT_UNICAST 12
#define DH6OPT_STATUS_CODE 13


#  define DH6OPT_STCODE_SUCCESS 0
#  define DH6OPT_STCODE_UNSPECFAIL 1
#  define DH6OPT_STCODE_NOADDRAVAIL 2
#  define DH6OPT_STCODE_NOBINDING 3
#  define DH6OPT_STCODE_NOTONLINK 4
#  define DH6OPT_STCODE_USEMULTICAST 5

#  define DH6OPT_STCODE_AUTHFAILED 6
#  define DH6OPT_STCODE_ADDRUNAVAIL 7
#  define DH6OPT_STCODE_CONFNOMATCH 8

#  define DH6OPT_STCODE_NOPREFIXAVAIL 10

#  define DH6OPT_STCODE_UNDEFINE 0xffff

#define DH6OPT_RAPID_COMMIT 14
#define DH6OPT_USER_CLASS 15
#define DH6OPT_VENDOR_CLASS 16
#define DH6OPT_VENDOR_OPTS 17
#define DH6OPT_INTERFACE_ID 18
#define DH6OPT_RECONF_MSG 19

#define DEFAULT_VALID_LIFE_TIME 720000
#define DEFAULT_PREFERRED_LIFE_TIME 360000

#define DH6OPT_SIP_DOMAINS 21
#define DH6OPT_SIP_SERVERS 22

#define DH6OPT_DNS_SERVERS 23
#define DH6OPT_DOMAIN_LIST 24

#define DH6OPT_IA_PD 25
#define DH6OPT_IAPREFIX 26

#define DH6OPT_NTP_SERVERS  31
#define DH6OPT_TIME_ZONE    41

#define MAX_VC_DATA 32 /* number of vclass data entries supported */

struct dhcpv6_option_addrlist_t {
	size_t nr_addr;
	__extension__ struct in6_addr addr[0]; /* null terminated list */
};

struct dhcpv6_option_dns_searchlist_t {
	char **addr;
};

struct dhcpv6_option_status_t {
	int code;
	char str[1];
};

struct dhcpv6_option_iaddr_t {
	unsigned int prefered_lft;
	unsigned int valid_lft;	     /* if zero, the while iaddr is invalid */
	struct in6_addr addr;
};

struct dhcpv6_option_ia_t {
	int status_code;
	int iaid;
	uint32_t t1;
	uint32_t t2;
	struct dhcpv6_option_iaddr_t iaddr;
	struct dhcpv6_option_status_t *status;
};

struct dhcpv6_option_vendorclass_data_t {
	uint32_t len;
	const unsigned char *data;
};

struct dhcpv6_option_vendorclass_t {
	uint32_t enterprise_nr;
	int nr_vcdata;
	struct dhcpv6_option_vendorclass_data_t vcdata[MAX_VC_DATA];
};

/*
 * dhcpv6 options after beeing parsed.
 * interpreted strucutre depends on the specific option.
 */
struct dhcpv6_option_t {
	struct dhcpv6_option_t *next;
	void *interp; /* interpreted structure */
	void (*interp_delete)(void *p);
	int code;
	int len;
	unsigned char rawdata[1];
};

struct dhcpv6_message_t {
	uint8_t msgtype;
	uint32_t transaction_id;
	struct dhcpv6_option_t *options;
};

struct duid_t {
	uint16_t type;
	union {
		struct {
			uint16_t hwtype;
			uint32_t time;
			__extension__ uint8_t addr[0];
		} __attribute__ ((__packed__)) t1;
		
		struct {
			uint32_t enterprise_nr;
			__extension__ uint8_t addr[0];
		} __attribute__ ((__packed__)) t2;
		
		struct {
			uint16_t hwtype;
			__extension__ uint8_t addr[0];
		} __attribute__ ((__packed__)) t3;
	} dt;
}__attribute__ ((__packed__)) ;

enum dhcpv6_node_t {
	CLIENT,
	SERVER,
	RELAY
};

struct dhcpv6_nodeid_t {
	enum dhcpv6_node_t kind;
	struct duid_t *duid;
	size_t	       duidlen;
	
	void	   *lladdr;  /* link-local address for unicast requests */
	size_t	    lladdrlen;
};


extern int dhcpv6_do_stateless(struct dhcpv6_message_t *reply,
			       struct dhcpv6_option_vendorclass_t *vclass,
			       char *interface,
			       int *options,
			       size_t nr_options);
extern int dhcpv6_do_statefull(struct dhcpv6_message_t *reply,
			       struct dhcpv6_nodeid_t **server,
			       struct dhcpv6_option_ia_t *ia,
			       struct dhcpv6_option_vendorclass_t *vclass,
			       char *interface,
			       int *options,
			       size_t nr_options);
extern int dhcpv6_do_reclaim(int cmd,
			     struct dhcpv6_message_t *reply,
			     struct dhcpv6_nodeid_t **rserver,
			     struct dhcpv6_option_ia_t *ia,
			     struct dhcpv6_option_vendorclass_t *vclass,
			     char *interface,
			     int *options,
			     size_t nr_options,
			     time_t timeout);

extern struct dhcpv6_nodeid_t *dhcpv6_parse_nodeid(unsigned char *buf,
						   size_t buflen);
extern void dhcpv6_append_node_id_opt(struct msgbuf_t **msg, int type,
				      struct dhcpv6_nodeid_t *node);
extern void dhcpv6_free_nodeid(struct dhcpv6_nodeid_t *node);
extern void dhcpv6_free_ia(struct dhcpv6_option_ia_t *ia);
extern void dhcpv6_free_options(struct dhcpv6_option_t *opts);
