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
 * netdev utils, with instrumentation.
 * 
 * Authors:	  Edgar E. Iglesias <edgar@axis.com>
 */

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
#include <time.h>
#include <assert.h>

uint8_t instr_if_hwaddress[] = {0x00, 0x40, 0x8C, 0x1C, 0x00, 0x68};
ssize_t if_hwaddress(int s, unsigned char *buf, size_t buflen,
		     char *ifname, uint16_t *type)
{
	int len = sizeof instr_if_hwaddress;

	if (len > buflen)
		len = buflen;
	
	memcpy(buf, instr_if_hwaddress, len);
	return len;
}

int if_mc_bindsocket(int s, char *interface)
{
	return 0;
}

unsigned int ra_seq[128];
unsigned int ra_seqlen = 0;

int instr_if_raflags = 0;
int if_get_raflags(char *interface)
{
	static int cnt = 0;
	static int f = 0;
	unsigned int raflags;

	if (!ra_seqlen)
		return instr_if_raflags;

	if (cnt >= 0 && cnt < ra_seqlen)
		raflags = ra_seq[cnt];
	else
		raflags = f;

	f = raflags;
	cnt++;
	return raflags;
}
