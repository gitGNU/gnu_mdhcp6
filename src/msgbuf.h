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
 * message buffers, keep this small.
 *
 * Authors:          Edgar E. Iglesias <edgar@axis.com>
 */
#include <assert.h>

struct msgbuf_t {
        size_t pos;
        size_t size;
        unsigned char buf[1];
};

extern struct msgbuf_t * msgbuf_new(size_t size)
__attribute__ ((__warn_unused_result__));

static inline void msgbuf_free(struct msgbuf_t *msg) {
	free(msg);
}

static inline void msgbuf_reset(struct msgbuf_t **msg) {
	assert(msg && *msg);
	(*msg)->pos = 0;
}

static inline size_t msgbuf_save(struct msgbuf_t **msg) {
	assert(msg && *msg);
	return (*msg)->pos;
}

static inline void msgbuf_restore(struct msgbuf_t **msg, size_t savedpos) {
	assert(msg && *msg);
	(*msg)->pos = savedpos;
}

extern size_t msgbuf_save(struct msgbuf_t **msg)
__attribute__ ((__const__))
__attribute__ ((__warn_unused_result__));

extern void msgbuf_append(struct msgbuf_t **msg, const void *buf, size_t len);
extern void msgbuf_append_u8(struct msgbuf_t **msg, uint8_t value);
extern void msgbuf_append_u16no(struct msgbuf_t **msg, uint16_t value);
extern void msgbuf_append_u24no(struct msgbuf_t **msg, uint32_t value);
extern void msgbuf_append_u32no(struct msgbuf_t **msg, uint32_t value);
