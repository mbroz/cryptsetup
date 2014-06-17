/*
 * Implementation of Password-Based Cryptography as per PKCS#5
 * Copyright (C) 2002,2003 Simon Josefsson
 * Copyright (C) 2004 Free Software Foundation
 *
 * cryptsetup related changes
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2014, Milan Broz
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
#include "crypto_backend.h"

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
		memset(P_hash, 0, sizeof(P_hash));
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
	memset(U, 0, sizeof(U));
	memset(T, 0, sizeof(T));
	memset(tmp, 0, tmplen);

	return rc;
}

#if 0
#include <stdio.h>

struct test_vector {
	const char *hash;
	unsigned int hash_block_length;
	unsigned int iterations;
	const char *password;
	unsigned int password_length;
	const char *salt;
	unsigned int salt_length;
	const char *output;
	unsigned int output_length;
};

struct test_vector test_vectors[] = {
	/* RFC 3962 */
	{
		"sha1", 64, 1,
		"password", 8,
		"ATHENA.MIT.EDUraeburn", 21,
		"\xcd\xed\xb5\x28\x1b\xb2\xf8\x01"
		"\x56\x5a\x11\x22\xb2\x56\x35\x15"
		"\x0a\xd1\xf7\xa0\x4b\xb9\xf3\xa3"
		"\x33\xec\xc0\xe2\xe1\xf7\x08\x37", 32
	}, {
		"sha1", 64, 2,
		"password", 8,
		"ATHENA.MIT.EDUraeburn", 21,
		"\x01\xdb\xee\x7f\x4a\x9e\x24\x3e"
		"\x98\x8b\x62\xc7\x3c\xda\x93\x5d"
		"\xa0\x53\x78\xb9\x32\x44\xec\x8f"
		"\x48\xa9\x9e\x61\xad\x79\x9d\x86", 32
	}, {
		"sha1", 64, 1200,
		"password", 8,
		"ATHENA.MIT.EDUraeburn", 21,
		"\x5c\x08\xeb\x61\xfd\xf7\x1e\x4e"
		"\x4e\xc3\xcf\x6b\xa1\xf5\x51\x2b"
		"\xa7\xe5\x2d\xdb\xc5\xe5\x14\x2f"
		"\x70\x8a\x31\xe2\xe6\x2b\x1e\x13", 32
	}, {
		"sha1", 64, 5,
		"password", 8,
		"\0224VxxV4\022", 8, // "\x1234567878563412
		"\xd1\xda\xa7\x86\x15\xf2\x87\xe6"
		"\xa1\xc8\xb1\x20\xd7\x06\x2a\x49"
		"\x3f\x98\xd2\x03\xe6\xbe\x49\xa6"
		"\xad\xf4\xfa\x57\x4b\x6e\x64\xee", 32
	}, {
		"sha1", 64, 1200,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 64,
		"pass phrase equals block size", 29,
		"\x13\x9c\x30\xc0\x96\x6b\xc3\x2b"
		"\xa5\x5f\xdb\xf2\x12\x53\x0a\xc9"
		"\xc5\xec\x59\xf1\xa4\x52\xf5\xcc"
		"\x9a\xd9\x40\xfe\xa0\x59\x8e\xd1", 32
	}, {
		"sha1", 64, 1200,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 65,
		"pass phrase exceeds block size", 30,
		"\x9c\xca\xd6\xd4\x68\x77\x0c\xd5"
		"\x1b\x10\xe6\xa6\x87\x21\xbe\x61"
		"\x1a\x8b\x4d\x28\x26\x01\xdb\x3b"
		"\x36\xbe\x92\x46\x91\x5e\xc8\x2a", 32
	}, {
		"sha1", 64, 50,
		"\360\235\204\236", 4, // g-clef ("\xf09d849e)
		"EXAMPLE.COMpianist", 18,
		"\x6b\x9c\xf2\x6d\x45\x45\x5a\x43"
		"\xa5\xb8\xbb\x27\x6a\x40\x3b\x39"
		"\xe7\xfe\x37\xa0\xc4\x1e\x02\xc2"
		"\x81\xff\x30\x69\xe1\xe9\x4f\x52", 32
	}, {
	/* RFC-6070 */
		"sha1", 64, 1,
		"password", 8,
		"salt", 4,
		"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9"
		"\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6", 20
	}, {
		"sha1", 64, 2,
		"password", 8,
		"salt", 4,
		"\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e"
		"\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57", 20
	}, {
		"sha1", 64, 4096,
		"password", 8,
		"salt", 4,
		"\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad"
		"\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1", 20
	}, {
		"sha1", 64, 16777216,
		"password", 8,
		"salt", 4,
		"\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94"
		"\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84", 20
	}, {
		"sha1", 64, 4096,
		"passwordPASSWORDpassword", 24,
		"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
		"\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8"
		"\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96"
		"\x4c\xf2\xf0\x70\x38", 25
	}, {
		"sha1", 64, 4096,
		"pass\0word", 9,
		"sa\0lt", 5,
		"\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37"
		"\xd7\xf0\x34\x25\xe0\xc3", 16
	}, {
	/* empty password test */
		"sha1", 64, 2,
		"", 0,
		"salt", 4,
		"\x13\x3a\x4c\xe8\x37\xb4\xd2\x52\x1e\xe2"
		"\xbf\x03\xe1\x1c\x71\xca\x79\x4e\x07\x97", 20
	}, {
	/* Password exceeds block size test */
		"sha256", 64, 1200,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 65,
		"pass phrase exceeds block size", 30,
		"\x22\x34\x4b\xc4\xb6\xe3\x26\x75"
		"\xa8\x09\x0f\x3e\xa8\x0b\xe0\x1d"
		"\x5f\x95\x12\x6a\x2c\xdd\xc3\xfa"
		"\xcc\x4a\x5e\x6d\xca\x04\xec\x58", 32
	}, {
		"sha512", 128, 1200,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 129,
		"pass phrase exceeds block size", 30,
		"\x0f\xb2\xed\x2c\x0e\x6e\xfb\x7d"
		"\x7d\x8e\xdd\x58\x01\xb4\x59\x72"
		"\x99\x92\x16\x30\x5e\xa4\x36\x8d"
		"\x76\x14\x80\xf3\xe3\x7a\x22\xb9", 32
	}, {
		"whirlpool", 64, 1200,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 65,
		"pass phrase exceeds block size", 30,
		"\x9c\x1c\x74\xf5\x88\x26\xe7\x6a"
		"\x53\x58\xf4\x0c\x39\xe7\x80\x89"
		"\x07\xc0\x31\x19\x9a\x50\xa2\x48"
		"\xf1\xd9\xfe\x78\x64\xe5\x84\x50", 32
	}
};

static void printhex(const char *s, const char *buf, size_t len)
{
	size_t i;

	printf("%s: ", s);
	for (i = 0; i < len; i++)
		printf("\\x%02x", (unsigned char)buf[i]);
	printf("\n");
	fflush(stdout);
}

static int pkcs5_pbkdf2_test_vectors(void)
{
	char result[64];
	unsigned int i, j;
	struct test_vector *vec;

	for (i = 0; i < (sizeof(test_vectors) / sizeof(*test_vectors)); i++) {
		vec = &test_vectors[i];
		for (j = 1; j <= vec->output_length; j++) {
			if (pkcs5_pbkdf2(vec->hash,
			    vec->password, vec->password_length,
			    vec->salt, vec->salt_length,
			    vec->iterations,
			    j, result, vec->hash_block_length)) {
				printf("pbkdf2 failed, vector %d\n", i);
				return -EINVAL;
			}
			if (memcmp(result, vec->output, j) != 0) {
				printf("vector %u\n", i);
				printhex(" got", result, j);
				printhex("want", vec->output, j);
				return -EINVAL;
			}
			memset(result, 0, sizeof(result));
		}
	}
	return 0;
}
#endif
