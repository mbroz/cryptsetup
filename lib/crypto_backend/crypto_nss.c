// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * NSS crypto backend implementation
 *
 * Copyright (C) 2010-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2010-2025 Milan Broz
 */

#include <stdio.h>
#include <errno.h>
#include <nss.h>
#include <pk11pub.h>
#include "crypto_backend_internal.h"

#define CONST_CAST(x) (x)(uintptr_t)

static int crypto_backend_initialised = 0;
static char version[64];

struct hash_alg {
	const char *name;
	SECOidTag oid;
	CK_MECHANISM_TYPE ck_type;
	int length;
	unsigned int block_length;
};

static struct hash_alg hash_algs[] = {
	{ "sha1",   SEC_OID_SHA1,   CKM_SHA_1_HMAC,  20,  64 },
	{ "sha256", SEC_OID_SHA256, CKM_SHA256_HMAC, 32,  64 },
	{ "sha384", SEC_OID_SHA384, CKM_SHA384_HMAC, 48, 128 },
	{ "sha512", SEC_OID_SHA512, CKM_SHA512_HMAC, 64, 128 },
//	{ "ripemd160", SEC_OID_RIPEMD160, CKM_RIPEMD160_HMAC, 20, 64 },
	{ NULL, 0, 0, 0 }
};

struct crypt_hash {
	PK11Context *md;
	const struct hash_alg *hash;
};

struct crypt_hmac {
	PK11Context *md;
	PK11SymKey *key;
	PK11SlotInfo *slot;
	const struct hash_alg *hash;
};

struct crypt_cipher {
	struct crypt_cipher_kernel ck;
};

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

int crypt_backend_init(bool fips __attribute__((unused)))
{
	int r;

	if (crypto_backend_initialised)
		return 0;

	if (NSS_NoDB_Init(".") != SECSuccess)
		return -EINVAL;

#if HAVE_DECL_NSS_GETVERSION
	r = snprintf(version, sizeof(version), "NSS %s", NSS_GetVersion());
#else
	r = snprintf(version, sizeof(version), "NSS");
#endif
	if (r < 0 || (size_t)r >= sizeof(version))
		return -EINVAL;

	crypto_backend_initialised = 1;
	return 0;
}

void crypt_backend_destroy(void)
{
	crypto_backend_initialised = 0;
}

uint32_t crypt_backend_flags(void)
{
	return 0;
}

const char *crypt_backend_version(void)
{
	return crypto_backend_initialised ? version : "";
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

	h->md = PK11_CreateDigestContext(h->hash->oid);
	if (!h->md) {
		free(h);
		return -EINVAL;
	}

	if (PK11_DigestBegin(h->md) != SECSuccess) {
		PK11_DestroyContext(h->md, PR_TRUE);
		free(h);
		return -EINVAL;
	}

	*ctx = h;
	return 0;
}

static int crypt_hash_restart(struct crypt_hash *ctx)
{
	if (PK11_DigestBegin(ctx->md) != SECSuccess)
		return -EINVAL;

	return 0;
}

int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length)
{
	if (PK11_DigestOp(ctx->md, CONST_CAST(unsigned char *)buffer, length) != SECSuccess)
		return -EINVAL;

	return 0;
}

int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length)
{
	unsigned char tmp[64];
	unsigned int tmp_len;

	if (length > (size_t)ctx->hash->length)
		return -EINVAL;

	if (PK11_DigestFinal(ctx->md, tmp, &tmp_len, length) != SECSuccess)
		return -EINVAL;

	crypt_backend_memcpy(buffer, tmp, length);
	crypt_backend_memzero(tmp, sizeof(tmp));

	if (tmp_len < length)
		return -EINVAL;

	if (crypt_hash_restart(ctx))
		return -EINVAL;

	return 0;
}

void crypt_hash_destroy(struct crypt_hash *ctx)
{
	PK11_DestroyContext(ctx->md, PR_TRUE);
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
	SECItem keyItem;
	SECItem noParams;

	keyItem.type = siBuffer;
	keyItem.data = CONST_CAST(unsigned char *)key;
	keyItem.len = (int)key_length;

	noParams.type = siBuffer;
	noParams.data = 0;
	noParams.len = 0;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;
	memset(h, 0, sizeof(*h));

	h->hash = _get_alg(name);
	if (!h->hash)
		goto err;

	h->slot = PK11_GetInternalKeySlot();
	if (!h->slot)
		goto err;

	h->key = PK11_ImportSymKey(h->slot, h->hash->ck_type, PK11_OriginUnwrap,
				   CKA_SIGN,  &keyItem, NULL);
	if (!h->key)
		goto err;

	h->md = PK11_CreateContextBySymKey(h->hash->ck_type, CKA_SIGN, h->key,
					   &noParams);
	if (!h->md)
		goto err;

	if (PK11_DigestBegin(h->md) != SECSuccess)
		goto err;

	*ctx = h;
	return 0;
err:
	crypt_hmac_destroy(h);
	return -EINVAL;
}

static int crypt_hmac_restart(struct crypt_hmac *ctx)
{
	if (PK11_DigestBegin(ctx->md) != SECSuccess)
		return -EINVAL;

	return 0;
}

int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length)
{
	if (PK11_DigestOp(ctx->md, CONST_CAST(unsigned char *)buffer, length) != SECSuccess)
		return -EINVAL;

	return 0;
}

int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length)
{
	unsigned char tmp[64];
	unsigned int tmp_len;

	if (length > (size_t)ctx->hash->length)
		return -EINVAL;

	if (PK11_DigestFinal(ctx->md, tmp, &tmp_len, length) != SECSuccess)
		return -EINVAL;

	crypt_backend_memcpy(buffer, tmp, length);
	crypt_backend_memzero(tmp, sizeof(tmp));

	if (tmp_len < length)
		return -EINVAL;

	if (crypt_hmac_restart(ctx))
		return -EINVAL;

	return 0;
}

void crypt_hmac_destroy(struct crypt_hmac *ctx)
{
	if (ctx->key)
		PK11_FreeSymKey(ctx->key);
	if (ctx->slot)
		PK11_FreeSlot(ctx->slot);
	if (ctx->md)
		PK11_DestroyContext(ctx->md, PR_TRUE);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
}

/* RNG */
int crypt_backend_rng(char *buffer, size_t length, int quality __attribute__((unused)), int fips)
{
	if (fips)
		return -EINVAL;

	if (PK11_GenerateRandom((unsigned char *)buffer, length) != SECSuccess)
		return -EINVAL;

	return 0;
}

/* PBKDF */
int crypt_pbkdf(const char *kdf, const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		uint32_t iterations, uint32_t memory, uint32_t parallel)
{
	struct hash_alg *ha;

	if (!kdf)
		return -EINVAL;

	if (!strcmp(kdf, "pbkdf2")) {
		ha = _get_alg(hash);
		if (!ha)
			return -EINVAL;

		return pkcs5_pbkdf2(hash, password, password_length, salt, salt_length,
				    iterations, key_length, key, ha->block_length);
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

bool crypt_cipher_kernel_only(struct crypt_cipher *ctx __attribute__((unused)))
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

int crypt_backend_memeq(const void *m1, const void *m2, size_t n)
{
	return NSS_SecureMemcmp(m1, m2, n);
}

bool crypt_fips_mode(void)
{
	return false;
}
