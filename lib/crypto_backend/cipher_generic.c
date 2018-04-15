/*
 * Linux kernel cipher generic utilities
 *
 * Copyright (C) 2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018, Milan Broz
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
#include <stdbool.h>
#include <errno.h>
#include "crypto_backend.h"

struct cipher_alg {
	const char *name;
	int blocksize;
	bool wrapped_key;
};

/* FIXME: Getting block size should be dynamic from cipher backend. */
static const struct cipher_alg cipher_algs[] = {
	{ "cipher_null", 16, false },
	{ "aes",         16, false },
	{ "serpent",     16, false },
	{ "twofish",     16, false },
	{ "anubis",      16, false },
	{ "blowfish",     8, false },
	{ "camellia",    16, false },
	{ "cast5",        8, false },
	{ "cast6",       16, false },
	{ "des",          8, false },
	{ "des3_ede",     8, false },
	{ "khazad",       8, false },
	{ "seed",        16, false },
	{ "tea",          8, false },
	{ "xtea",         8, false },
	{ "paes",        16,  true }, /* protected AES, s390 wrapped key scheme */
	{ NULL,           0, false }
};

static const struct cipher_alg *_get_alg(const char *name)
{
	int i = 0;

	while (name && cipher_algs[i].name) {
		if (!strcasecmp(name, cipher_algs[i].name))
			return &cipher_algs[i];
		i++;
	}
	return NULL;
}

int crypt_cipher_blocksize(const char *name)
{
	const struct cipher_alg *ca = _get_alg(name);

	return ca ? ca->blocksize : -EINVAL;
}

int crypt_cipher_wrapped_key(const char *name)
{
	const struct cipher_alg *ca = _get_alg(name);

	return ca ? (int)ca->wrapped_key : 0;
}
