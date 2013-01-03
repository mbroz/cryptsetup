/*
 * GCRYPT crypto backend implementation
 *
 * Copyright (C) 2010-2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2010-2012, Milan Broz
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
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <gcrypt.h>
#include "crypto_backend.h"

static int crypto_backend_initialised = 0;
static int crypto_backend_secmem = 1;
static char version[64];

struct crypt_hash {
	gcry_md_hd_t hd;
	int hash_id;
	int hash_len;
};

struct crypt_hmac {
	gcry_md_hd_t hd;
	int hash_id;
	int hash_len;
};

int crypt_backend_init(struct crypt_device *ctx)
{
	if (crypto_backend_initialised)
		return 0;

	if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
		if (!gcry_check_version (GCRYPT_REQ_VERSION)) {
			return -ENOSYS;
		}

/* FIXME: If gcrypt compiled to support POSIX 1003.1e capabilities,
 * it drops all privileges during secure memory initialisation.
 * For now, the only workaround is to disable secure memory in gcrypt.
 * cryptsetup always need at least cap_sys_admin privilege for dm-ioctl
 * and it locks its memory space anyway.
 */
#if 0
		gcry_control (GCRYCTL_DISABLE_SECMEM);
		crypto_backend_secmem = 0;
#else

		gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
		gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
		gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
#endif
		gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	}

	snprintf(version, 64, "gcrypt %s%s",
		 gcry_check_version(NULL),
		 crypto_backend_secmem ? "" : ", secmem disabled");
	crypto_backend_initialised = 1;
	return 0;
}

const char *crypt_backend_version(void)
{
	return crypto_backend_initialised ? version : "";
}

uint32_t crypt_backend_flags(void)
{
	return 0;
}

/* HASH */
int crypt_hash_size(const char *name)
{
	int hash_id;

	assert(crypto_backend_initialised);

	hash_id = gcry_md_map_name(name);
	if (!hash_id)
		return -EINVAL;

	return gcry_md_get_algo_dlen(hash_id);
}

int crypt_hash_init(struct crypt_hash **ctx, const char *name)
{
	struct crypt_hash *h;

	assert(crypto_backend_initialised);

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->hash_id = gcry_md_map_name(name);
	if (!h->hash_id) {
		free(h);
		return -EINVAL;
	}

	if (gcry_md_open(&h->hd, h->hash_id, 0)) {
		free(h);
		return -EINVAL;
	}

	h->hash_len = gcry_md_get_algo_dlen(h->hash_id);
	*ctx = h;
	return 0;
}

static void crypt_hash_restart(struct crypt_hash *ctx)
{
	gcry_md_reset(ctx->hd);
}

int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length)
{
	gcry_md_write(ctx->hd, buffer, length);
	return 0;
}

int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length)
{
	unsigned char *hash;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	hash = gcry_md_read(ctx->hd, ctx->hash_id);
	if (!hash)
		return -EINVAL;

	memcpy(buffer, hash, length);
	crypt_hash_restart(ctx);

	return 0;
}

int crypt_hash_destroy(struct crypt_hash *ctx)
{
	gcry_md_close(ctx->hd);
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

	assert(crypto_backend_initialised);

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->hash_id = gcry_md_map_name(name);
	if (!h->hash_id) {
		free(h);
		return -EINVAL;
	}

	if (gcry_md_open(&h->hd, h->hash_id, GCRY_MD_FLAG_HMAC)) {
		free(h);
		return -EINVAL;
	}

	if (gcry_md_setkey(h->hd, buffer, length)) {
		gcry_md_close(h->hd);
		free(h);
		return -EINVAL;
	}

	h->hash_len = gcry_md_get_algo_dlen(h->hash_id);
	*ctx = h;
	return 0;
}

static void crypt_hmac_restart(struct crypt_hmac *ctx)
{
	gcry_md_reset(ctx->hd);
}

int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length)
{
	gcry_md_write(ctx->hd, buffer, length);
	return 0;
}

int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length)
{
	unsigned char *hash;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	hash = gcry_md_read(ctx->hd, ctx->hash_id);
	if (!hash)
		return -EINVAL;

	memcpy(buffer, hash, length);
	crypt_hmac_restart(ctx);

	return 0;
}

int crypt_hmac_destroy(struct crypt_hmac *ctx)
{
	gcry_md_close(ctx->hd);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
	return 0;
}

/* RNG */
int crypt_backend_rng(char *buffer, size_t length, int quality, int fips)
{
	switch(quality) {
	case CRYPT_RND_NORMAL:
		gcry_randomize(buffer, length, GCRY_STRONG_RANDOM);
		break;
	case CRYPT_RND_SALT:
	case CRYPT_RND_KEY:
	default:
		gcry_randomize(buffer, length, GCRY_VERY_STRONG_RANDOM);
		break;
	}
	return 0;
}

/* PBKDF */
int crypt_pbkdf(const char *kdf, const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		unsigned int iterations)
{
#if USE_INTERNAL_PBKDF2
	if (!kdf || strncmp(kdf, "pbkdf2", 6))
		return -EINVAL;

	return pkcs5_pbkdf2(hash, password, password_length, salt, salt_length,
			    iterations, key_length, key);

#else /* USE_INTERNAL_PBKDF2 */
	int hash_id = gcry_md_map_name(hash);
	int kdf_id;

	if (!hash_id)
		return -EINVAL;

	if (kdf && !strncmp(kdf, "pbkdf2", 6))
		kdf_id = GCRY_KDF_PBKDF2;
	else
		return -EINVAL;

	if (gcry_kdf_derive(password, password_length, kdf_id, hash_id,
	    salt, salt_length, iterations, key_length, key))
		return -EINVAL;

	return 0;
#endif /* USE_INTERNAL_PBKDF2 */
}
