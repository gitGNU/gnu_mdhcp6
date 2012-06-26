/*
 * Copyright: 2007 Axis Communications AB
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
 * network interface manipulation, with instrumentation.
 * 
 * Authors:	     Edgar E. Iglesias <edgar@axis.com>
 */

#include <net/if.h>

#ifndef IF_RA_MANAGED
#define IF_RA_OTHERCONF   0x80
#define IF_RA_MANAGED     0x40
#define IF_RA_RCVD	  0x20
#endif

extern uint8_t instr_if_hwaddress[6];
extern ssize_t if_hwaddress(int s, unsigned char *buf, size_t buflen,
			    char *ifname, uint16_t *type);

extern int if_mc_bindsocket(int s, char *interface);

extern int instr_if_raflags;
extern int if_get_raflags(char *interface);
