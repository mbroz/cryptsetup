/*
 * Reed-Solomon codecs, based on libfec
 *
 * Copyright (C) 2004 Phil Karn, KA9Q
 * libcryptsetup modifications
 *   Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LIBFEC_RS_H
#define _LIBFEC_RS_H

/* Special reserved value encoding zero in index form. */
#define A0 (rs->nn)

#define RS_MIN(a, b) ((a) < (b) ? (a) : (b))

typedef unsigned char data_t;

/* Reed-Solomon codec control block */
struct rs {
	int mm;          /* Bits per symbol */
	int nn;          /* Symbols per block (= (1<<mm)-1) */
	data_t *alpha_to;/* log lookup table */
	data_t *index_of;/* Antilog lookup table */
	data_t *genpoly; /* Generator polynomial */
	int nroots;      /* Number of generator roots = number of parity symbols */
	int fcr;         /* First consecutive root, index form */
	int prim;        /* Primitive element, index form */
	int iprim;       /* prim-th root of 1, index form */
	int pad;         /* Padding bytes in shortened block */
};

static inline int modnn(struct rs *rs, int x)
{
	while (x >= rs->nn) {
		x -= rs->nn;
		x = (x >> rs->mm) + (x & rs->nn);
	}
	return x;
}

struct rs *init_rs_char(int symsize, int gfpoly, int fcr, int prim, int nroots, int pad);
void free_rs_char(struct rs *rs);

/* General purpose RS codec, 8-bit symbols */
void encode_rs_char(struct rs *rs, data_t *data, data_t *parity);
int decode_rs_char(struct rs *rs, data_t *data);

#endif
