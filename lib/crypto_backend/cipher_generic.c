/*
 * Linux kernel cipher generic utilities
 *
 * Copyright (C) 2018-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2020 Milan Broz
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
	const char *mode;
	int blocksize;
	bool wrapped_key;
};

/* FIXME: Getting block size should be dynamic from cipher backend. */
static const struct cipher_alg cipher_algs[] = {
	{ "cipher_null", NULL, 16, false },
	{ "aes",         NULL, 16, false },
	{ "serpent",     NULL, 16, false },
	{ "twofish",     NULL, 16, false },
	{ "anubis",      NULL, 16, false },
	{ "blowfish",    NULL,  8, false },
	{ "camellia",    NULL, 16, false },
	{ "cast5",       NULL,  8, false },
	{ "cast6",       NULL, 16, false },
	{ "des",         NULL,  8, false },
	{ "des3_ede",    NULL,  8, false },
	{ "khazad",      NULL,  8, false },
	{ "seed",        NULL, 16, false },
	{ "tea",         NULL,  8, false },
	{ "xtea",        NULL,  8, false },
	{ "paes",        NULL, 16,  true }, /* protected AES, s390 wrapped key scheme */
	{ "xchacha12,aes", "adiantum", 32, false },
	{ "xchacha20,aes", "adiantum", 32, false },
	{ "sm4",         NULL, 16, false },
	{ NULL,          NULL,  0, false }
};

static const struct cipher_alg *_get_alg(const char *name, const char *mode)
{
	int i = 0;

	while (name && cipher_algs[i].name) {
		if (!strcasecmp(name, cipher_algs[i].name))
			if (!mode || !cipher_algs[i].mode ||
			    !strncasecmp(mode, cipher_algs[i].mode, strlen(cipher_algs[i].mode)))
				return &cipher_algs[i];
		i++;
	}
	return NULL;
}

int crypt_cipher_ivsize(const char *name, const char *mode)
{
	const struct cipher_alg *ca = _get_alg(name, mode);

	if (!ca)
		return -EINVAL;

	if (mode && !strcasecmp(mode, "ecb"))
		return 0;

	return ca->blocksize;
}

int crypt_cipher_wrapped_key(const char *name, const char *mode)
{
	const struct cipher_alg *ca = _get_alg(name, mode);

	return ca ? (int)ca->wrapped_key : 0;
}
