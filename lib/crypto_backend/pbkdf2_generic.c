/*
 * Implementation of Password-Based Cryptography as per PKCS#5
 * Copyright (C) 2002,2003 Simon Josefsson
 * Copyright (C) 2004 Free Software Foundation
 *
 * cryptsetup related changes
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2020 Milan Broz
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
 *
 */

#include <errno.h>
#include <alloca.h>
#include "crypto_backend_internal.h"

static int hash_buf(const char *src, size_t src_len,
		    char *dst, size_t dst_len,
		    const char *hash_name)
{
	struct crypt_hash *hd = NULL;
	int r;

	if (crypt_hash_init(&hd, hash_name))
		return -EINVAL;

	r = crypt_hash_write(hd, src, src_len);

	if (!r)
		r = crypt_hash_final(hd, dst, dst_len);

	crypt_hash_destroy(hd);
	return r;
}

/*
 * 5.2 PBKDF2
 *
 *  PBKDF2 applies a pseudorandom function (see Appendix B.1 for an
 *  example) to derive keys. The length of the derived key is essentially
 *  unbounded. (However, the maximum effective search space for the
 *  derived key may be limited by the structure of the underlying
 *  pseudorandom function. See Appendix B.1 for further discussion.)
 *  PBKDF2 is recommended for new applications.
 *
 *  PBKDF2 (P, S, c, dkLen)
 *
 *  Options:        PRF        underlying pseudorandom function (hLen
 *                             denotes the length in octets of the
 *                             pseudorandom function output)
 *
 *  Input:          P          password, an octet string (ASCII or UTF-8)
 *                  S          salt, an octet string
 *                  c          iteration count, a positive integer
 *                  dkLen      intended length in octets of the derived
 *                             key, a positive integer, at most
 *                             (2^32 - 1) * hLen
 *
 *  Output:         DK         derived key, a dkLen-octet string
 */

/*
 * if hash_block_size is not zero, the HMAC key is pre-hashed
 * inside this function.
 * This prevents situation when crypto backend doesn't support
 * long HMAC keys or it tries hash long key in every iteration
 * (because of crypt_final() cannot do simple key reset.
 */

#define MAX_PRF_BLOCK_LEN 80

int pkcs5_pbkdf2(const char *hash,
			const char *P, size_t Plen,
			const char *S, size_t Slen,
			unsigned int c, unsigned int dkLen,
			char *DK, unsigned int hash_block_size)
{
	struct crypt_hmac *hmac;
	char U[MAX_PRF_BLOCK_LEN];
	char T[MAX_PRF_BLOCK_LEN];
	char P_hash[MAX_PRF_BLOCK_LEN];
	int i, k, rc = -EINVAL;
	unsigned int u, hLen, l, r;
	size_t tmplen = Slen + 4;
	char *tmp;

	tmp = alloca(tmplen);
	if (tmp == NULL)
		return -ENOMEM;

	hLen = crypt_hmac_size(hash);
	if (hLen == 0 || hLen > MAX_PRF_BLOCK_LEN)
		return -EINVAL;

	if (c == 0)
		return -EINVAL;

	if (dkLen == 0)
		return -EINVAL;

	/*
	 *
	 *  Steps:
	 *
	 *     1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
	 *        stop.
	 */

	if (dkLen > 4294967295U)
		return -EINVAL;

	/*
	 *     2. Let l be the number of hLen-octet blocks in the derived key,
	 *        rounding up, and let r be the number of octets in the last
	 *        block:
	 *
	 *                  l = CEIL (dkLen / hLen) ,
	 *                  r = dkLen - (l - 1) * hLen .
	 *
	 *        Here, CEIL (x) is the "ceiling" function, i.e. the smallest
	 *        integer greater than, or equal to, x.
	 */

	l = dkLen / hLen;
	if (dkLen % hLen)
		l++;
	r = dkLen - (l - 1) * hLen;

	/*
	 *     3. For each block of the derived key apply the function F defined
	 *        below to the password P, the salt S, the iteration count c, and
	 *        the block index to compute the block:
	 *
	 *                  T_1 = F (P, S, c, 1) ,
	 *                  T_2 = F (P, S, c, 2) ,
	 *                  ...
	 *                  T_l = F (P, S, c, l) ,
	 *
	 *        where the function F is defined as the exclusive-or sum of the
	 *        first c iterates of the underlying pseudorandom function PRF
	 *        applied to the password P and the concatenation of the salt S
	 *        and the block index i:
	 *
	 *                  F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
	 *
	 *        where
	 *
	 *                  U_1 = PRF (P, S || INT (i)) ,
	 *                  U_2 = PRF (P, U_1) ,
	 *                  ...
	 *                  U_c = PRF (P, U_{c-1}) .
	 *
	 *        Here, INT (i) is a four-octet encoding of the integer i, most
	 *        significant octet first.
	 *
	 *     4. Concatenate the blocks and extract the first dkLen octets to
	 *        produce a derived key DK:
	 *
	 *                  DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
	 *
	 *     5. Output the derived key DK.
	 *
	 *  Note. The construction of the function F follows a "belt-and-
	 *  suspenders" approach. The iterates U_i are computed recursively to
	 *  remove a degree of parallelism from an opponent; they are exclusive-
	 *  ored together to reduce concerns about the recursion degenerating
	 *  into a small set of values.
	 *
	 */

	/* If hash_block_size is provided, hash password in advance. */
	if (hash_block_size > 0 && Plen > hash_block_size) {
		if (hash_buf(P, Plen, P_hash, hLen, hash))
			return -EINVAL;

		if (crypt_hmac_init(&hmac, hash, P_hash, hLen))
			return -EINVAL;
		crypt_backend_memzero(P_hash, sizeof(P_hash));
	} else {
		if (crypt_hmac_init(&hmac, hash, P, Plen))
			return -EINVAL;
	}

	for (i = 1; (unsigned int) i <= l; i++) {
		memset(T, 0, hLen);

		for (u = 1; u <= c ; u++) {
			if (u == 1) {
				memcpy(tmp, S, Slen);
				tmp[Slen + 0] = (i & 0xff000000) >> 24;
				tmp[Slen + 1] = (i & 0x00ff0000) >> 16;
				tmp[Slen + 2] = (i & 0x0000ff00) >> 8;
				tmp[Slen + 3] = (i & 0x000000ff) >> 0;

				if (crypt_hmac_write(hmac, tmp, tmplen))
					goto out;
			} else {
				if (crypt_hmac_write(hmac, U, hLen))
					goto out;
			}

			if (crypt_hmac_final(hmac, U, hLen))
				goto out;

			for (k = 0; (unsigned int) k < hLen; k++)
				T[k] ^= U[k];
		}

		memcpy(DK + (i - 1) * hLen, T, (unsigned int) i == l ? r : hLen);
	}
	rc = 0;
out:
	crypt_hmac_destroy(hmac);
	crypt_backend_memzero(U, sizeof(U));
	crypt_backend_memzero(T, sizeof(T));
	crypt_backend_memzero(tmp, tmplen);

	return rc;
}
