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

#define DHCP6_TIMESCALE 32
#include "dhcpv6.c"

/* Wrapper call to test internal calls.  */
int x_dhcpv6_parse_msg(struct dhcpv6_message_t *reply,
                     unsigned char *buf, size_t buflen,
                     uint32_t expected_id,
                     int expected_type)
{
	return dhcpv6_parse_msg(reply, buf, buflen, expected_id, expected_type);
}
