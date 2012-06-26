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
 * time
 * 
 * Authors:          Edgar E. Iglesias <edgar@axis.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <time.h>

#ifdef HAVE_SYSINFO
#include <sys/sysinfo.h>
#else
#include <unistd.h>
#include <sys/times.h>
#endif

/*
 * This function returns the number of seconds that have elapsed since an
 * arbitrary point in the past. Dont rely on its initial value beeing any
 * specific number.
 */
time_t ptime(void) {
#ifdef HAVE_SYSINFO
	struct sysinfo si;
	sysinfo(&si);
	return si.uptime;
#else
	/* if the systems time is modified, the caller will get confused */
	return time(NULL);
#endif
}
