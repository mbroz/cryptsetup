/*
 * Generic wrapper for storage encryption modes and Initial Vectors
 * (reimplementation of some functions from Linux dm-crypt kernel)
 *
 * Copyright (C) 2014-2020 Milan Broz
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

#include <stdlib.h>
#include <errno.h>
#include "bitops.h"
#include "crypto_backend.h"

#define SECTOR_SHIFT	9

/*
 * Internal IV helper
 * IV documentation: https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt
 */
struct crypt_sector_iv {
	enum { IV_NONE, IV_NULL, IV_PLAIN, IV_PLAIN64, IV_ESSIV, IV_BENBI, IV_PLAIN64BE, IV_EBOIV } type;
	int iv_size;
	char *iv;
	struct crypt_cipher *cipher;
	int shift;
};

/* Block encryption storage context */
struct crypt_storage {
	unsigned sector_shift;
	unsigned iv_shift;
	struct crypt_cipher *cipher;
	struct crypt_sector_iv cipher_iv;
};

static int int_log2(unsigned int x)
{
	int r = 0;
	for (x >>= 1; x > 0; x >>= 1)
		r++;
	return r;
}

static int crypt_sector_iv_init(struct crypt_sector_iv *ctx,
			 const char *cipher_name, const char *mode_name,
			 const char *iv_name, const void *key, size_t key_length, size_t sector_size)
{
	int r;

	memset(ctx, 0, sizeof(*ctx));

	ctx->iv_size = crypt_cipher_ivsize(cipher_name, mode_name);
	if (ctx->iv_size < 8)
		return -ENOENT;

	if (!strcmp(cipher_name, "cipher_null") ||
	    !strcmp(mode_name, "ecb")) {
		if (iv_name)
			return -EINVAL;
		ctx->type = IV_NONE;
		ctx->iv_size = 0;
		return 0;
	} else if (!iv_name) {
		return -EINVAL;
	} else if (!strcasecmp(iv_name, "null")) {
		ctx->type = IV_NULL;
	} else if (!strcasecmp(iv_name, "plain64")) {
		ctx->type = IV_PLAIN64;
	} else if (!strcasecmp(iv_name, "plain64be")) {
		ctx->type = IV_PLAIN64BE;
	} else if (!strcasecmp(iv_name, "plain")) {
		ctx->type = IV_PLAIN;
	} else if (!strncasecmp(iv_name, "essiv:", 6)) {
		struct crypt_hash *h = NULL;
		char *hash_name = strchr(iv_name, ':');
		int hash_size;
		char tmp[256];

		if (!hash_name)
			return -EINVAL;

		hash_size = crypt_hash_size(++hash_name);
		if (hash_size < 0)
			return -ENOENT;

		if ((unsigned)hash_size > sizeof(tmp))
			return -EINVAL;

		if (crypt_hash_init(&h, hash_name))
			return -EINVAL;

		r = crypt_hash_write(h, key, key_length);
		if (r) {
			crypt_hash_destroy(h);
			return r;
		}

		r = crypt_hash_final(h, tmp, hash_size);
		crypt_hash_destroy(h);
		if (r) {
			crypt_backend_memzero(tmp, sizeof(tmp));
			return r;
		}

		r = crypt_cipher_init(&ctx->cipher, cipher_name, "ecb",
				      tmp, hash_size);
		crypt_backend_memzero(tmp, sizeof(tmp));
		if (r)
			return r;

		ctx->type = IV_ESSIV;
	} else if (!strncasecmp(iv_name, "benbi", 5)) {
		int log = int_log2(ctx->iv_size);
		if (log > SECTOR_SHIFT)
			return -EINVAL;

		ctx->type = IV_BENBI;
		ctx->shift = SECTOR_SHIFT - log;
	} else if (!strncasecmp(iv_name, "eboiv", 5)) {
		r = crypt_cipher_init(&ctx->cipher, cipher_name, "ecb",
				      key, key_length);
		if (r)
			return r;

		ctx->type = IV_EBOIV;
		ctx->shift = int_log2(sector_size);
	} else
		return -ENOENT;

	ctx->iv = malloc(ctx->iv_size);
	if (!ctx->iv)
		return -ENOMEM;

	return 0;
}

static int crypt_sector_iv_generate(struct crypt_sector_iv *ctx, uint64_t sector)
{
	uint64_t val;

	switch (ctx->type) {
	case IV_NONE:
		break;
	case IV_NULL:
		memset(ctx->iv, 0, ctx->iv_size);
		break;
	case IV_PLAIN:
		memset(ctx->iv, 0, ctx->iv_size);
		*(uint32_t *)ctx->iv = cpu_to_le32(sector & 0xffffffff);
		break;
	case IV_PLAIN64:
		memset(ctx->iv, 0, ctx->iv_size);
		*(uint64_t *)ctx->iv = cpu_to_le64(sector);
		break;
	case IV_PLAIN64BE:
		memset(ctx->iv, 0, ctx->iv_size);
		*(uint64_t *)&ctx->iv[ctx->iv_size - sizeof(uint64_t)] = cpu_to_be64(sector);
		break;
	case IV_ESSIV:
		memset(ctx->iv, 0, ctx->iv_size);
		*(uint64_t *)ctx->iv = cpu_to_le64(sector);
		return crypt_cipher_encrypt(ctx->cipher,
			ctx->iv, ctx->iv, ctx->iv_size, NULL, 0);
		break;
	case IV_BENBI:
		memset(ctx->iv, 0, ctx->iv_size);
		val = cpu_to_be64((sector << ctx->shift) + 1);
		memcpy(ctx->iv + ctx->iv_size - sizeof(val), &val, sizeof(val));
		break;
	case IV_EBOIV:
		memset(ctx->iv, 0, ctx->iv_size);
		*(uint64_t *)ctx->iv = cpu_to_le64(sector << ctx->shift);
		return crypt_cipher_encrypt(ctx->cipher,
			ctx->iv, ctx->iv, ctx->iv_size, NULL, 0);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void crypt_sector_iv_destroy(struct crypt_sector_iv *ctx)
{
	if (ctx->type == IV_ESSIV || ctx->type == IV_EBOIV)
		crypt_cipher_destroy(ctx->cipher);

	if (ctx->iv) {
		memset(ctx->iv, 0, ctx->iv_size);
		free(ctx->iv);
	}

	memset(ctx, 0, sizeof(*ctx));
}

/* Block encryption storage wrappers */

int crypt_storage_init(struct crypt_storage **ctx,
		       size_t sector_size,
		       const char *cipher,
		       const char *cipher_mode,
		       const void *key, size_t key_length)
{
	struct crypt_storage *s;
	char mode_name[64];
	char *cipher_iv = NULL;
	int r = -EIO;

	if (sector_size < (1 << SECTOR_SHIFT) ||
	    sector_size > (1 << (SECTOR_SHIFT + 3)) ||
	    sector_size & (sector_size - 1))
		return -EINVAL;

	s = malloc(sizeof(*s));
	if (!s)
		return -ENOMEM;
	memset(s, 0, sizeof(*s));

	/* Remove IV if present */
	strncpy(mode_name, cipher_mode, sizeof(mode_name));
	mode_name[sizeof(mode_name) - 1] = 0;
	cipher_iv = strchr(mode_name, '-');
	if (cipher_iv) {
		*cipher_iv = '\0';
		cipher_iv++;
	}

	r = crypt_cipher_init(&s->cipher, cipher, mode_name, key, key_length);
	if (r) {
		crypt_storage_destroy(s);
		return r;
	}

	r = crypt_sector_iv_init(&s->cipher_iv, cipher, mode_name, cipher_iv, key, key_length, sector_size);
	if (r) {
		crypt_storage_destroy(s);
		return r;
	}

	s->sector_shift = int_log2(sector_size);
	s->iv_shift = s->sector_shift - SECTOR_SHIFT;

	*ctx = s;
	return 0;
}

int crypt_storage_decrypt(struct crypt_storage *ctx,
		       uint64_t iv_offset,
		       uint64_t length, char *buffer)
{
	uint64_t i;
	int r = 0;

	if (length & ((1 << ctx->sector_shift) - 1))
		return -EINVAL;

	length >>= ctx->sector_shift;

	for (i = 0; i < length; i++) {
		r = crypt_sector_iv_generate(&ctx->cipher_iv, iv_offset + (uint64_t)(i << ctx->iv_shift));
		if (r)
			break;
		r = crypt_cipher_decrypt(ctx->cipher,
					 &buffer[i << ctx->sector_shift],
					 &buffer[i << ctx->sector_shift],
					 1 << ctx->sector_shift,
					 ctx->cipher_iv.iv,
					 ctx->cipher_iv.iv_size);
		if (r)
			break;
	}

	return r;
}

int crypt_storage_encrypt(struct crypt_storage *ctx,
		       uint64_t iv_offset,
		       uint64_t length, char *buffer)
{
	uint64_t i;
	int r = 0;

	if (length & ((1 << ctx->sector_shift) - 1))
		return -EINVAL;

	length >>= ctx->sector_shift;

	for (i = 0; i < length; i++) {
		r = crypt_sector_iv_generate(&ctx->cipher_iv, iv_offset + (i << ctx->iv_shift));
		if (r)
			break;
		r = crypt_cipher_encrypt(ctx->cipher,
					 &buffer[i << ctx->sector_shift],
					 &buffer[i << ctx->sector_shift],
					 1 << ctx->sector_shift,
					 ctx->cipher_iv.iv,
					 ctx->cipher_iv.iv_size);
		if (r)
			break;
	}

	return r;
}

void crypt_storage_destroy(struct crypt_storage *ctx)
{
	if (!ctx)
		return;

	crypt_sector_iv_destroy(&ctx->cipher_iv);

	if (ctx->cipher)
		crypt_cipher_destroy(ctx->cipher);

	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
}

bool crypt_storage_kernel_only(struct crypt_storage *ctx)
{
	return crypt_cipher_kernel_only(ctx->cipher);
}
