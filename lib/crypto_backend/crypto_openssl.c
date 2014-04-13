/*
 * OPENSSL crypto backend implementation
 *
 * Copyright (C) 2010-2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2010-2014, Milan Broz
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
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU Lesser General Public License in all respects
 * for all of the code used other than OpenSSL.
 */

#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "crypto_backend.h"

static int crypto_backend_initialised = 0;

struct crypt_hash {
	EVP_MD_CTX md;
	const EVP_MD *hash_id;
	int hash_len;
};

struct crypt_hmac {
	HMAC_CTX md;
	const EVP_MD *hash_id;
	int hash_len;
};

int crypt_backend_init(struct crypt_device *ctx)
{
	if (crypto_backend_initialised)
		return 0;

	OpenSSL_add_all_algorithms();

	crypto_backend_initialised = 1;
	return 0;
}

uint32_t crypt_backend_flags(void)
{
	return 0;
}

const char *crypt_backend_version(void)
{
	return SSLeay_version(SSLEAY_VERSION);
}

/* HASH */
int crypt_hash_size(const char *name)
{
	const EVP_MD *hash_id = EVP_get_digestbyname(name);

	if (!hash_id)
		return -EINVAL;

	return EVP_MD_size(hash_id);
}

int crypt_hash_init(struct crypt_hash **ctx, const char *name)
{
	struct crypt_hash *h;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->hash_id = EVP_get_digestbyname(name);
	if (!h->hash_id) {
		free(h);
		return -EINVAL;
	}

	if (EVP_DigestInit(&h->md, h->hash_id) != 1) {
		free(h);
		return -EINVAL;
	}

	h->hash_len = EVP_MD_size(h->hash_id);
	*ctx = h;
	return 0;
}

static int crypt_hash_restart(struct crypt_hash *ctx)
{
	if (EVP_DigestInit(&ctx->md, ctx->hash_id) != 1)
		return -EINVAL;

	return 0;
}

int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length)
{
	if (EVP_DigestUpdate(&ctx->md, buffer, length) != 1)
		return -EINVAL;

	return 0;
}

int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length)
{
	unsigned char tmp[EVP_MAX_MD_SIZE];
	unsigned int tmp_len = 0;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	if (EVP_DigestFinal_ex(&ctx->md, tmp, &tmp_len) != 1)
		return -EINVAL;

	memcpy(buffer, tmp, length);
	memset(tmp, 0, sizeof(tmp));

	if (tmp_len < length)
		return -EINVAL;

	if (crypt_hash_restart(ctx))
		return -EINVAL;

	return 0;
}

int crypt_hash_destroy(struct crypt_hash *ctx)
{
	EVP_MD_CTX_cleanup(&ctx->md);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
	return 0;
}

/* HMAC */
int crypt_hmac_size(const char *name)
{
	return crypt_hash_size(name);
}

int crypt_hmac_init(struct crypt_hmac **ctx, const char *name,
		    const void *buffer, size_t length)
{
	struct crypt_hmac *h;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->hash_id = EVP_get_digestbyname(name);
	if (!h->hash_id) {
		free(h);
		return -EINVAL;
	}

	HMAC_CTX_init(&h->md);
	HMAC_Init_ex(&h->md, buffer, length, h->hash_id, NULL);

	h->hash_len = EVP_MD_size(h->hash_id);
	*ctx = h;
	return 0;
}

static void crypt_hmac_restart(struct crypt_hmac *ctx)
{
	HMAC_Init_ex(&ctx->md, NULL, 0, ctx->hash_id, NULL);
}

int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length)
{
	HMAC_Update(&ctx->md, (const unsigned char *)buffer, length);
	return 0;
}

int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length)
{
	unsigned char tmp[EVP_MAX_MD_SIZE];
	unsigned int tmp_len = 0;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	HMAC_Final(&ctx->md, tmp, &tmp_len);

	memcpy(buffer, tmp, length);
	memset(tmp, 0, sizeof(tmp));

	if (tmp_len < length)
		return -EINVAL;

	crypt_hmac_restart(ctx);

	return 0;
}

int crypt_hmac_destroy(struct crypt_hmac *ctx)
{
	HMAC_CTX_cleanup(&ctx->md);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
	return 0;
}

/* RNG */
int crypt_backend_rng(char *buffer, size_t length, int quality, int fips)
{
	if (fips)
		return -EINVAL;

	if (RAND_bytes((unsigned char *)buffer, length) != 1)
		return -EINVAL;

	return 0;
}

/* PBKDF */
int crypt_pbkdf(const char *kdf, const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		unsigned int iterations)
{
	const EVP_MD *hash_id;

	if (!kdf || strncmp(kdf, "pbkdf2", 6))
		return -EINVAL;

	hash_id = EVP_get_digestbyname(hash);
	if (!hash_id)
		return -EINVAL;

	if (!PKCS5_PBKDF2_HMAC(password, (int)password_length,
	    (unsigned char *)salt, (int)salt_length,
            (int)iterations, hash_id, (int)key_length, (unsigned char *)key))
		return -EINVAL;

	return 0;
}
