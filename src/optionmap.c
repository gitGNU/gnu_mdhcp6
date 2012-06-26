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
 * implements a map of options.
 *
 * Authors:	     Edgar E. Iglesias <edgar@axis.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "optionmap.h"

#undef D
#define D(x)

void optionmap_cleanup(struct optionmap_t *o, size_t optionlen) {
	size_t i;
	for(i = 0; i < optionlen; i++) {
		free(o[i].value);
		free(o[i].oldvalue);
		o[i].value = NULL;
		o[i].oldvalue = NULL;
	}
}

int optionmap_test_and_clear_reconfig(struct optionmap_t *o,
				      size_t optionlen) {
	size_t i;
	int needsreconfig = 0;
	for(i = 0; i < optionlen; i++) {
		needsreconfig |= o[i].needsreconfig;
		o[i].needsreconfig = 0;
	}
	return needsreconfig;
}

/*
 * Fabricate an environment for a configuration script process.
 * Tipically called from a separate process.
 */
void optionmap_create_environ(struct optionmap_t *o, size_t optionlen) {
	size_t i;
	for(i = 0; i < optionlen; i++) {
		if (o[i].env) {
			size_t envname_len;
			size_t oldvalue_len;
			
			envname_len = strlen(o[i].env);
			
			if (o[i].oldvalue) {
#undef POSTFIX
#define POSTFIX "_old="
				static const char postfix[] = POSTFIX;
				char *old;
				size_t postfix_len = strlen(POSTFIX);

				/* grab the nul char from this one */
				oldvalue_len = strlen(o[i].oldvalue) + 1;

				old = malloc(envname_len
					     + postfix_len + oldvalue_len);
				if (old) {
					char *str = old;
					memcpy(str, o[i].env, envname_len);
					str += envname_len;
					memcpy(str, postfix, postfix_len);
					str += postfix_len;
					memcpy(str,
					       o[i].oldvalue, oldvalue_len);
					putenv(old);
				}
			}
			if (o[i].value)
				setenv(o[i].env, o[i].value, 1);
		}
	}
}

/*
 * Drop active options by making them obsolete. We do this simply by moving
 * every option to the old state. Let the caller know how many options got
 * dropped.
 */
int optionmap_drop(struct optionmap_t *o, size_t optionlen) {
	size_t i;
	int nr_options = 0;

	for(i = 0; i < optionlen; i++) {
		if (o[i].env) {
			if (o[i].value)
				nr_options++;
			o[i].oldvalue = o[i].value;
			o[i].value = NULL;
		}
	}
	return nr_options;
}

/*
 * update the oldvalues in the lease object. This is done when a configuration
 * update is made so that we can provide previously configured values every
 * time.
 */
void optionmap_update_oldvalues(struct optionmap_t *o, size_t optionlen) {
	size_t i;
	for(i = 0; i < optionlen; i++) {
		if (o[i].env) {
			free(o[i].oldvalue);
			if (o[i].value)
				o[i].oldvalue = strdup(o[i].value);
			else
				o[i].oldvalue = NULL;
		}
	}
}
