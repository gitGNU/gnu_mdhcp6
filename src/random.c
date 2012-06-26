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
 * Code to supply random data
 * 
 * Authors:	     Edgar E. Iglesias <edgar@axis.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

static const char randfile[] = "/dev/urandom";
static FILE *randfp = NULL;

static void random_close(void) {
	if (randfp)
		fclose(randfp);
}

void random_fill(void *buf, size_t len) {
	if (!randfp) {
		randfp = fopen(randfile, "r");
		if (!randfp) {
			perror(randfile);
			exit(EXIT_FAILURE);
		}
		atexit(random_close);
	}	
	fread(buf, 1, len, randfp);
}
