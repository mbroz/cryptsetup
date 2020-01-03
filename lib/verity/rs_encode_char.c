/*
 * Reed-Solomon encoder, based on libfec
 *
 * Copyright (C) 2002, Phil Karn, KA9Q
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

#include <string.h>
#include <stdlib.h>

#include "rs.h"

/* Initialize a Reed-Solomon codec
 * symsize = symbol size, bits
 * gfpoly = Field generator polynomial coefficients
 * fcr = first root of RS code generator polynomial, index form
 * prim = primitive element to generate polynomial roots
 * nroots = RS code generator polynomial degree (number of roots)
 * pad = padding bytes at front of shortened block
 */
struct rs *init_rs_char(int symsize, int gfpoly, int fcr, int prim, int nroots, int pad)
{
	struct rs *rs;
	int i, j, sr, root, iprim;

	/* Check parameter ranges */
	if (symsize < 0 || symsize > 8 * (int)sizeof(data_t))
		return NULL;
	if (fcr < 0 || fcr >= (1<<symsize))
		return NULL;
	if (prim <= 0 || prim >= (1<<symsize))
		return NULL;
	if (nroots < 0 || nroots >= (1<<symsize))
		return NULL; /* Can't have more roots than symbol values! */

	if (pad < 0 || pad >= ((1<<symsize) - 1 - nroots))
		return NULL; /* Too much padding */

	rs = calloc(1, sizeof(struct rs));
	if (rs == NULL)
		return NULL;

	rs->mm = symsize;
	rs->nn = (1<<symsize) - 1;
	rs->pad = pad;

	rs->alpha_to = malloc(sizeof(data_t) * (rs->nn + 1));
	if (rs->alpha_to == NULL) {
		free(rs);
		return NULL;
	}
	rs->index_of = malloc(sizeof(data_t) * (rs->nn + 1));
	if (rs->index_of == NULL) {
		free(rs->alpha_to);
		free(rs);
		return NULL;
	}
	memset(rs->index_of, 0, sizeof(data_t) * (rs->nn + 1));

	/* Generate Galois field lookup tables */
	rs->index_of[0] = A0; /* log(zero) = -inf */
	rs->alpha_to[A0] = 0; /* alpha**-inf = 0 */
	sr = 1;
	for (i = 0; i < rs->nn; i++) {
		rs->index_of[sr] = i;
		rs->alpha_to[i] = sr;
		sr <<= 1;
		if(sr & (1<<symsize))
			sr ^= gfpoly;
		sr &= rs->nn;
	}
	if (sr != 1) {
		/* field generator polynomial is not primitive! */
		free(rs->alpha_to);
		free(rs->index_of);
		free(rs);
		return NULL;
	}

	/* Form RS code generator polynomial from its roots */
	rs->genpoly = malloc(sizeof(data_t) * (nroots + 1));
	if (rs->genpoly == NULL) {
		free(rs->alpha_to);
		free(rs->index_of);
		free(rs);
		return NULL;
	}

	rs->fcr = fcr;
	rs->prim = prim;
	rs->nroots = nroots;

	/* Find prim-th root of 1, used in decoding */
	for (iprim = 1; (iprim % prim) != 0; iprim += rs->nn)
		;
	rs->iprim = iprim / prim;

	rs->genpoly[0] = 1;
	for (i = 0, root = fcr * prim; i < nroots; i++, root += prim) {
		rs->genpoly[i + 1] = 1;

		/* Multiply rs->genpoly[] by  @**(root + x) */
		for (j = i; j > 0; j--){
			if (rs->genpoly[j] != 0)
				rs->genpoly[j] = rs->genpoly[j - 1] ^ rs->alpha_to[modnn(rs, rs->index_of[rs->genpoly[j]] + root)];
			else
				rs->genpoly[j] = rs->genpoly[j - 1];
		}
		/* rs->genpoly[0] can never be zero */
		rs->genpoly[0] = rs->alpha_to[modnn(rs, rs->index_of[rs->genpoly[0]] + root)];
	}
	/* convert rs->genpoly[] to index form for quicker encoding */
	for (i = 0; i <= nroots; i++)
		rs->genpoly[i] = rs->index_of[rs->genpoly[i]];

	return rs;
}

void free_rs_char(struct rs *rs)
{
	if (!rs)
		return;

	free(rs->alpha_to);
	free(rs->index_of);
	free(rs->genpoly);
	free(rs);
}

void encode_rs_char(struct rs *rs, data_t *data, data_t *parity)
{
	int i, j;
	data_t feedback;

	memset(parity, 0, rs->nroots * sizeof(data_t));

	for (i = 0; i < rs->nn - rs->nroots - rs->pad; i++) {
		feedback = rs->index_of[data[i] ^ parity[0]];
		if (feedback != A0) {
			/* feedback term is non-zero */
#ifdef UNNORMALIZED
			/* This line is unnecessary when GENPOLY[NROOTS] is unity, as it must
			 * always be for the polynomials constructed by init_rs() */
			feedback = modnn(rs, rs->nn - rs->genpoly[rs->nroots] + feedback);
#endif
			for (j = 1; j < rs->nroots; j++)
				parity[j] ^= rs->alpha_to[modnn(rs, feedback + rs->genpoly[rs->nroots - j])];
		}

		/* Shift */
		memmove(&parity[0], &parity[1], sizeof(data_t) * (rs->nroots - 1));

		if (feedback != A0)
			parity[rs->nroots - 1] = rs->alpha_to[modnn(rs, feedback + rs->genpoly[0])];
		else
			parity[rs->nroots - 1] = 0;
	}
}
