/*
 * Reed-Solomon decoder, based on libfec
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

int decode_rs_char(struct rs* rs, data_t* data)
{
	int deg_lambda, el, deg_omega, syn_error, count;
	int i, j, r, k;
	data_t q, tmp, num1, num2, den, discr_r;
	/* FIXME: remove VLAs here */
	data_t lambda[rs->nroots + 1], s[rs->nroots]; /* Err+Eras Locator poly and syndrome poly */
	data_t b[rs->nroots + 1], t[rs->nroots + 1], omega[rs->nroots + 1];
	data_t root[rs->nroots], reg[rs->nroots + 1], loc[rs->nroots];

	memset(s, 0, rs->nroots * sizeof(data_t));
	memset(b, 0, (rs->nroots + 1) * sizeof(data_t));

	/* form the syndromes; i.e., evaluate data(x) at roots of g(x) */
	for (i = 0; i < rs->nroots; i++)
		s[i] = data[0];

	for (j = 1; j < rs->nn - rs->pad; j++) {
		for (i = 0; i < rs->nroots; i++) {
			if (s[i] == 0) {
				s[i] = data[j];
			} else {
				s[i] = data[j] ^ rs->alpha_to[modnn(rs, rs->index_of[s[i]] + (rs->fcr + i) * rs->prim)];
			}
		}
	}

	/* Convert syndromes to index form, checking for nonzero condition */
	syn_error = 0;
	for (i = 0; i < rs->nroots; i++) {
		syn_error |= s[i];
		s[i] = rs->index_of[s[i]];
	}

	/*
	 * if syndrome is zero, data[] is a codeword and there are no
	 * errors to correct. So return data[] unmodified
	 */
	if (!syn_error)
		return 0;

	memset(&lambda[1], 0, rs->nroots * sizeof(lambda[0]));
	lambda[0] = 1;

	for (i   = 0; i < rs->nroots + 1; i++)
		b[i] = rs->index_of[lambda[i]];

	/*
	 * Begin Berlekamp-Massey algorithm to determine error+erasure
	 * locator polynomial
	 */
	r  = 0;
	el = 0;
	while (++r <= rs->nroots) { /* r is the step number */
		/* Compute discrepancy at the r-th step in poly-form */
		discr_r = 0;
		for (i = 0; i < r; i++) {
			if ((lambda[i] != 0) && (s[r - i - 1] != A0)) {
				discr_r ^= rs->alpha_to[modnn(rs, rs->index_of[lambda[i]] + s[r - i - 1])];
			}
		}
		discr_r = rs->index_of[discr_r]; /* Index form */
		if (discr_r == A0) {
			/* 2 lines below: B(x) <-- x*B(x) */
			memmove(&b[1], b, rs->nroots * sizeof(b[0]));
			b[0] = A0;
		} else {
			/* 7 lines below: T(x) <-- lambda(x) - discr_r*x*b(x) */
			t[0] = lambda[0];
			for (i = 0; i < rs->nroots; i++) {
				if (b[i] != A0)
					t[i + 1] = lambda[i + 1] ^ rs->alpha_to[modnn(rs, discr_r + b[i])];
				else
					t[i + 1] = lambda[i + 1];
			}
			if (2 * el <= r - 1) {
				el = r - el;
				/*
				 * 2 lines below: B(x) <-- inv(discr_r) *
				 * lambda(x)
				 */
				for (i   = 0; i <= rs->nroots; i++)
					b[i] = (lambda[i] == 0) ? A0 : modnn(rs, rs->index_of[lambda[i]] - discr_r + rs->nn);
			} else {
				/* 2 lines below: B(x) <-- x*B(x) */
				memmove(&b[1], b, rs->nroots * sizeof(b[0]));
				b[0] = A0;
			}
			memcpy(lambda, t, (rs->nroots + 1) * sizeof(t[0]));
		}
	}

	/* Convert lambda to index form and compute deg(lambda(x)) */
	deg_lambda = 0;
	for (i = 0; i < rs->nroots + 1; i++) {
		lambda[i] = rs->index_of[lambda[i]];
		if (lambda[i] != A0)
			deg_lambda = i;
	}
	/* Find roots of the error+erasure locator polynomial by Chien search */
	memcpy(&reg[1], &lambda[1], rs->nroots * sizeof(reg[0]));
	count = 0; /* Number of roots of lambda(x) */
	for (i = 1, k = rs->iprim - 1; i <= rs->nn; i++, k = modnn(rs, k + rs->iprim)) {
		q = 1; /* lambda[0] is always 0 */
		for (j = deg_lambda; j > 0; j--) {
			if (reg[j] != A0) {
				reg[j] = modnn(rs, reg[j] + j);
				q ^= rs->alpha_to[reg[j]];
			}
		}
		if (q != 0)
			continue; /* Not a root */

		/* store root (index-form) and error location number */
		root[count] = i;
		loc[count]  = k;
		/* If we've already found max possible roots, abort the search to save time */
		if (++count == deg_lambda)
			break;
	}

	/*
	 * deg(lambda) unequal to number of roots => uncorrectable
	 * error detected
	 */
	if (deg_lambda != count)
		return -1;

	/*
	 * Compute err+eras evaluator poly omega(x) = s(x)*lambda(x) (modulo
	 * x**rs->nroots). in index form. Also find deg(omega).
	 */
	deg_omega = deg_lambda - 1;
	for (i = 0; i <= deg_omega; i++) {
		tmp = 0;
		for (j = i; j >= 0; j--) {
			if ((s[i - j] != A0) && (lambda[j] != A0))
				tmp ^= rs->alpha_to[modnn(rs, s[i - j] + lambda[j])];
		}
		omega[i] = rs->index_of[tmp];
	}

	/*
	 * Compute error values in poly-form. num1 = omega(inv(X(l))), num2 =
	 * inv(X(l))**(rs->fcr-1) and den = lambda_pr(inv(X(l))) all in poly-form
	 */
	for (j = count - 1; j >= 0; j--) {
		num1 = 0;
		for (i = deg_omega; i >= 0; i--) {
			if (omega[i] != A0)
				num1 ^= rs->alpha_to[modnn(rs, omega[i] + i * root[j])];
		}
		num2 = rs->alpha_to[modnn(rs, root[j] * (rs->fcr - 1) + rs->nn)];
		den  = 0;

		/* lambda[i+1] for i even is the formal derivative lambda_pr of lambda[i] */
		for (i = RS_MIN(deg_lambda, rs->nroots - 1) & ~1; i >= 0; i -= 2) {
			if (lambda[i + 1] != A0)
				den ^= rs->alpha_to[modnn(rs, lambda[i + 1] + i * root[j])];
		}

		/* Apply error to data */
		if (num1 != 0 && loc[j] >= rs->pad) {
			data[loc[j] - rs->pad] ^= rs->alpha_to[modnn(rs, rs->index_of[num1] +
						  rs->index_of[num2] + rs->nn - rs->index_of[den])];
		}
	}

	return count;
}
