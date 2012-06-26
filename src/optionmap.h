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
 * Authors:          Edgar E. Iglesias <edgar@axis.com>
 */

struct optionmap_t {
	const char *env;
	void  (*update)(struct optionmap_t *o, void *newvalue);
	char       *value;
	char       *oldvalue;
	int         needsreconfig;
};

extern int optionmap_drop(struct optionmap_t *o, size_t optionlen);
extern void optionmap_cleanup(struct optionmap_t *o, size_t optionlen);
extern int optionmap_test_and_clear_reconfig(struct optionmap_t *o,
					     size_t optionlen);
extern void optionmap_create_environ(struct optionmap_t *o, size_t optionlen);
extern void optionmap_update_oldvalues(struct optionmap_t *o,
				       size_t optionlen);

static inline void
optionmap_add(struct optionmap_t *o, int code, char *env,
	      void (*update)(struct optionmap_t *o, void *nv)) {
	o[code].env = env;
	o[code].update = update;
}

static inline
void optionmap_up(struct optionmap_t *o, int code, void *newvalue) {
	if (o[code].update)
		o[code].update(&o[code], newvalue);
}
