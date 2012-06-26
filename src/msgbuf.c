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
#include <assert.h>

#include "msgbuf.h"

#define D(x)

#define DEFAULTSIZE 64

struct msgbuf_t *
msgbuf_new(size_t size) {
        struct msgbuf_t *msg;

	if (!size)
                size = (DEFAULTSIZE - sizeof(*msg));
	
        msg = malloc(sizeof(*msg) + size);
        msg->size = size;
	msg->pos = 0;
        return msg;
}

static void
msgbuf_resize(struct msgbuf_t **msg, size_t addedsize) {
	struct msgbuf_t *tmp;

	/* create the msg before resizeing it! */
	assert(msg && *msg);

	/* will be new buffer size */
	addedsize += (*msg)->size;

	/*
	 * allocate space for buffer and structure in one malloc
	 */
	tmp = realloc(*msg, addedsize + sizeof **msg);
	if (tmp) {
		*msg = tmp;
		(*msg)->size = addedsize;
	}
	else {
		D(printf("%s: internal-error msg=%p\n",
			 __FUNCTION__, (void *)*msg));
		assert(0);
		exit(EXIT_FAILURE);
	}
}

static void
msgbuf_resize_if_needed(struct msgbuf_t **msg, size_t addedsize) {
	assert(msg && *msg);

	if (((*msg)->pos + addedsize) > (*msg)->size)
		msgbuf_resize(msg, addedsize);
}

/* append a chunk of opaque data */
void
msgbuf_append(struct msgbuf_t **msg, const void *buf, size_t len) {
	int pos;
	unsigned char *dst;

        msgbuf_resize_if_needed(msg, len);

	pos = (*msg)->pos;
	dst = (*msg)->buf + pos;
	(*msg)->pos += len;
        memcpy(dst, buf, len);
}

/* append a single byte */
void 
msgbuf_append_u8(struct msgbuf_t **msg, uint8_t value) {
        msgbuf_resize_if_needed(msg, sizeof(value));
        (*msg)->buf[(*msg)->pos++] = value;
}

/*
 * Append data in network byte-order.
 */
void
msgbuf_append_u16no(struct msgbuf_t **msg, uint16_t value) {
	uint8_t *d;
        msgbuf_resize_if_needed(msg, 2);
	
	(*msg)->pos += 2;
	d = (*msg)->buf + (*msg)->pos;
	*--d = (value);
	*--d = (value >>= 8);
}

void
msgbuf_append_u24no(struct msgbuf_t **msg, uint32_t value) {
	uint8_t *d;
        msgbuf_resize_if_needed(msg, 3);
	
	(*msg)->pos += 3;
	d = (*msg)->buf + (*msg)->pos;
	*--d = (value);
	*--d = (value >>= 8);
	*--d = (value >>= 8);
}

void
msgbuf_append_u32no(struct msgbuf_t **msg, uint32_t value) {
	uint8_t *d;
        msgbuf_resize_if_needed(msg, 4);
	
	(*msg)->pos += 4;
	d = (*msg)->buf + (*msg)->pos;
	*--d = (value);
	*--d = (value >>= 8);
	*--d = (value >>= 8);
	*--d = (value >>= 8);
}
