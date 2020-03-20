/*
 * Nettle crypto backend implementation
 *
 * Copyright (C) 2011-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2011-2020 Milan Broz
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
#include <string.h>
#include <errno.h>
#include <nettle/sha.h>
#include <nettle/sha3.h>
#include <nettle/hmac.h>
#include <nettle/pbkdf2.h>
#include "crypto_backend_internal.h"

#if HAVE_NETTLE_VERSION_H
#include <nettle/version.h>
#define VSTR(s) STR(s)
#define STR(s) #s
static const char *version = "Nettle "VSTR(NETTLE_VERSION_MAJOR)"."VSTR(NETTLE_VERSION_MINOR);
#else
static const char *version = "Nettle";
#endif

typedef void (*init_func) (void *);
typedef void (*update_func) (void *, size_t, const uint8_t *);
typedef void (*digest_func) (void *, size_t, uint8_t *);
typedef void (*set_key_func) (void *, size_t, const uint8_t *);

struct hash_alg {
	const char *name;
	int length;
	init_func init;
	update_func update;
	digest_func digest;
	update_func hmac_update;
	digest_func hmac_digest;
	set_key_func hmac_set_key;
};

/* Missing HMAC wrappers in Nettle */
#define HMAC_FCE(xxx) \
struct xhmac_##xxx##_ctx HMAC_CTX(struct xxx##_ctx); \
static void xhmac_##xxx##_set_key(struct xhmac_##xxx##_ctx *ctx, \
size_t key_length, const uint8_t *key) \
{HMAC_SET_KEY(ctx, &nettle_##xxx, key_length, key);} \
static void xhmac_##xxx##_update(struct xhmac_##xxx##_ctx *ctx, \
size_t length, const uint8_t *data) \
{xxx##_update(&ctx->state, length, data);} \
static void xhmac_##xxx##_digest(struct xhmac_##xxx##_ctx *ctx, \
size_t length, uint8_t *digest) \
{HMAC_DIGEST(ctx, &nettle_##xxx, length, digest);}

HMAC_FCE(sha3_224);
HMAC_FCE(sha3_256);
HMAC_FCE(sha3_384);
HMAC_FCE(sha3_512);

static struct hash_alg hash_algs[] = {
	{ "sha1", SHA1_DIGEST_SIZE,
		(init_func) sha1_init,
		(update_func) sha1_update,
		(digest_func) sha1_digest,
		(update_func) hmac_sha1_update,
		(digest_func) hmac_sha1_digest,
		(set_key_func) hmac_sha1_set_key,
	},
	{ "sha224", SHA224_DIGEST_SIZE,
		(init_func) sha224_init,
		(update_func) sha224_update,
		(digest_func) sha224_digest,
		(update_func) hmac_sha224_update,
		(digest_func) hmac_sha224_digest,
		(set_key_func) hmac_sha224_set_key,
	},
	{ "sha256", SHA256_DIGEST_SIZE,
		(init_func) sha256_init,
		(update_func) sha256_update,
		(digest_func) sha256_digest,
		(update_func) hmac_sha256_update,
		(digest_func) hmac_sha256_digest,
		(set_key_func) hmac_sha256_set_key,
	},
	{ "sha384", SHA384_DIGEST_SIZE,
		(init_func) sha384_init,
		(update_func) sha384_update,
		(digest_func) sha384_digest,
		(update_func) hmac_sha384_update,
		(digest_func) hmac_sha384_digest,
		(set_key_func) hmac_sha384_set_key,
	},
	{ "sha512", SHA512_DIGEST_SIZE,
		(init_func) sha512_init,
		(update_func) sha512_update,
		(digest_func) sha512_digest,
		(update_func) hmac_sha512_update,
		(digest_func) hmac_sha512_digest,
		(set_key_func) hmac_sha512_set_key,
	},
	{ "ripemd160", RIPEMD160_DIGEST_SIZE,
		(init_func) ripemd160_init,
		(update_func) ripemd160_update,
		(digest_func) ripemd160_digest,
		(update_func) hmac_ripemd160_update,
		(digest_func) hmac_ripemd160_digest,
		(set_key_func) hmac_ripemd160_set_key,
	},
/* Nettle prior to version 3.2 has incompatible SHA3 implementation */
#if NETTLE_SHA3_FIPS202
	{ "sha3-224", SHA3_224_DIGEST_SIZE,
		(init_func) sha3_224_init,
		(update_func) sha3_224_update,
		(digest_func) sha3_224_digest,
		(update_func) xhmac_sha3_224_update,
		(digest_func) xhmac_sha3_224_digest,
		(set_key_func) xhmac_sha3_224_set_key,
	},
	{ "sha3-256", SHA3_256_DIGEST_SIZE,
		(init_func) sha3_256_init,
		(update_func) sha3_256_update,
		(digest_func) sha3_256_digest,
		(update_func) xhmac_sha3_256_update,
		(digest_func) xhmac_sha3_256_digest,
		(set_key_func) xhmac_sha3_256_set_key,
	},
	{ "sha3-384", SHA3_384_DIGEST_SIZE,
		(init_func) sha3_384_init,
		(update_func) sha3_384_update,
		(digest_func) sha3_384_digest,
		(update_func) xhmac_sha3_384_update,
		(digest_func) xhmac_sha3_384_digest,
		(set_key_func) xhmac_sha3_384_set_key,
	},
	{ "sha3-512", SHA3_512_DIGEST_SIZE,
		(init_func) sha3_512_init,
		(update_func) sha3_512_update,
		(digest_func) sha3_512_digest,
		(update_func) xhmac_sha3_512_update,
		(digest_func) xhmac_sha3_512_digest,
		(set_key_func) xhmac_sha3_512_set_key,
	},
#endif
	{ NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, }
};

struct crypt_hash {
	const struct hash_alg *hash;
	union {
		struct sha1_ctx sha1;
		struct sha224_ctx sha224;
		struct sha256_ctx sha256;
		struct sha384_ctx sha384;
		struct sha512_ctx sha512;
		struct ripemd160_ctx ripemd160;
		struct sha3_224_ctx sha3_224;
		struct sha3_256_ctx sha3_256;
		struct sha3_384_ctx sha3_384;
		struct sha3_512_ctx sha3_512;
	} nettle_ctx;
};

struct crypt_hmac {
	const struct hash_alg *hash;
	union {
		struct hmac_sha1_ctx sha1;
		struct hmac_sha224_ctx sha224;
		struct hmac_sha256_ctx sha256;
		struct hmac_sha384_ctx sha384;
		struct hmac_sha512_ctx sha512;
		struct hmac_ripemd160_ctx ripemd160;
		struct xhmac_sha3_224_ctx sha3_224;
		struct xhmac_sha3_256_ctx sha3_256;
		struct xhmac_sha3_384_ctx sha3_384;
		struct xhmac_sha3_512_ctx sha3_512;
	} nettle_ctx;
	size_t key_length;
	uint8_t *key;
};

struct crypt_cipher {
	struct crypt_cipher_kernel ck;
};

uint32_t crypt_backend_flags(void)
{
	return 0;
}

static struct hash_alg *_get_alg(const char *name)
{
	int i = 0;

	while (name && hash_algs[i].name) {
		if (!strcmp(name, hash_algs[i].name))
			return &hash_algs[i];
		i++;
	}
	return NULL;
}

int crypt_backend_init(void)
{
	return 0;
}

void crypt_backend_destroy(void)
{
	return;
}

const char *crypt_backend_version(void)
{
	return version;
}

/* HASH */
int crypt_hash_size(const char *name)
{
	struct hash_alg *ha = _get_alg(name);

	return ha ? ha->length : -EINVAL;
}

int crypt_hash_init(struct crypt_hash **ctx, const char *name)
{
	struct crypt_hash *h;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->hash = _get_alg(name);
	if (!h->hash) {
		free(h);
		return -EINVAL;
	}

	h->hash->init(&h->nettle_ctx);

	*ctx = h;
	return 0;
}

static void crypt_hash_restart(struct crypt_hash *ctx)
{
	ctx->hash->init(&ctx->nettle_ctx);
}

int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length)
{
	ctx->hash->update(&ctx->nettle_ctx, length, (const uint8_t*)buffer);
	return 0;
}

int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length)
{
	if (length > (size_t)ctx->hash->length)
		return -EINVAL;

	ctx->hash->digest(&ctx->nettle_ctx, length, (uint8_t *)buffer);
	crypt_hash_restart(ctx);
	return 0;
}

void crypt_hash_destroy(struct crypt_hash *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
}

/* HMAC */
int crypt_hmac_size(const char *name)
{
	return crypt_hash_size(name);
}

int crypt_hmac_init(struct crypt_hmac **ctx, const char *name,
		    const void *key, size_t key_length)
{
	struct crypt_hmac *h;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;
	memset(ctx, 0, sizeof(*ctx));


	h->hash = _get_alg(name);
	if (!h->hash)
		goto bad;

	h->key = malloc(key_length);
	if (!h->key)
		goto bad;

	memcpy(h->key, key, key_length);
	h->key_length = key_length;

	h->hash->init(&h->nettle_ctx);
	h->hash->hmac_set_key(&h->nettle_ctx, h->key_length, h->key);

	*ctx = h;
	return 0;
bad:
	free(h);
	return -EINVAL;
}

static void crypt_hmac_restart(struct crypt_hmac *ctx)
{
	ctx->hash->hmac_set_key(&ctx->nettle_ctx, ctx->key_length, ctx->key);
}

int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length)
{
	ctx->hash->hmac_update(&ctx->nettle_ctx, length, (const uint8_t *)buffer);
	return 0;
}

int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length)
{
	if (length > (size_t)ctx->hash->length)
		return -EINVAL;

	ctx->hash->hmac_digest(&ctx->nettle_ctx, length, (uint8_t *)buffer);
	crypt_hmac_restart(ctx);
	return 0;
}

void crypt_hmac_destroy(struct crypt_hmac *ctx)
{
	memset(ctx->key, 0, ctx->key_length);
	free(ctx->key);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
}

/* RNG - N/A */
int crypt_backend_rng(char *buffer, size_t length, int quality, int fips)
{
	return -EINVAL;
}

/* PBKDF */
int crypt_pbkdf(const char *kdf, const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		uint32_t iterations, uint32_t memory, uint32_t parallel)
{
	struct crypt_hmac *h;
	int r;

	if (!kdf)
		return -EINVAL;

	if (!strcmp(kdf, "pbkdf2")) {
		r = crypt_hmac_init(&h, hash, password, password_length);
		if (r < 0)
			return r;

		nettle_pbkdf2(&h->nettle_ctx, h->hash->hmac_update,
			      h->hash->hmac_digest, h->hash->length, iterations,
			      salt_length, (const uint8_t *)salt, key_length,
			      (uint8_t *)key);
		crypt_hmac_destroy(h);
		return 0;
	} else if (!strncmp(kdf, "argon2", 6)) {
		return argon2(kdf, password, password_length, salt, salt_length,
			      key, key_length, iterations, memory, parallel);
	}

	return -EINVAL;
}

/* Block ciphers */
int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *key, size_t key_length)
{
	struct crypt_cipher *h;
	int r;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	r = crypt_cipher_init_kernel(&h->ck, name, mode, key, key_length);
	if (r < 0) {
		free(h);
		return r;
	}

	*ctx = h;
	return 0;
}

void crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	crypt_cipher_destroy_kernel(&ctx->ck);
	free(ctx);
}

int crypt_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return crypt_cipher_encrypt_kernel(&ctx->ck, in, out, length, iv, iv_length);
}

int crypt_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return crypt_cipher_decrypt_kernel(&ctx->ck, in, out, length, iv, iv_length);
}

bool crypt_cipher_kernel_only(struct crypt_cipher *ctx)
{
	return true;
}

int crypt_bitlk_decrypt_key(const void *key, size_t key_length,
			    const char *in, char *out, size_t length,
			    const char *iv, size_t iv_length,
			    const char *tag, size_t tag_length)
{
	return crypt_bitlk_decrypt_key_kernel(key, key_length, in, out, length,
					      iv, iv_length, tag, tag_length);
}
