// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Reed-Solomon codecs, based on libfec
 *
 * Copyright (C) 2004 Phil Karn, KA9Q
 * libcryptsetup modifications
 *   Copyright (C) 2017-2025 Red Hat, Inc. All rights reserved.
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
