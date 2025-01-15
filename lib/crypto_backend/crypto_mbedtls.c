// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Mbed TLS crypto backend implementation
 *
 * Copyright (C) 2024-2025 Yiyuan Zhong
 */

#include "crypto_backend.h"

#include <errno.h>
#include <stdlib.h>

#include <mbedtls/ccm.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/version.h>

#include "crypto_backend_internal.h"

struct crypt_hash {
	const mbedtls_md_info_t *info;
	mbedtls_md_context_t md;
};

struct crypt_hmac {
	const mbedtls_md_info_t *info;
	mbedtls_md_context_t md;
};

struct crypt_cipher {
	const mbedtls_cipher_info_t *info;
	mbedtls_cipher_context_t enc;
	mbedtls_cipher_context_t dec;
	int ecb;
};

static bool g_initialized = false;
static char g_backend_version[32];
static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;

static const mbedtls_md_info_t *crypt_get_hash(const char *name)
{
	static const struct hash_alg {
		const char *name;
		mbedtls_md_type_t type;
	} kHash[] = {
		{"sha1",      MBEDTLS_MD_SHA1     },
		{"sha224",    MBEDTLS_MD_SHA224   },
		{"sha256",    MBEDTLS_MD_SHA256   },
		{"sha384",    MBEDTLS_MD_SHA384   },
		{"sha512",    MBEDTLS_MD_SHA512   },
		{"ripemd160", MBEDTLS_MD_RIPEMD160},
		{NULL,        0,                  }
	};

	size_t i = 0;

	while (name && kHash[i].name) {
		if (strcmp(kHash[i].name, name) == 0)
			return mbedtls_md_info_from_type(kHash[i].type);
		i++;
	}

	return NULL;
}

int crypt_backend_init(bool fips)
{
	int ret;

	if (g_initialized)
		return 0;

	if (fips)
		return -ENOTSUP;

	mbedtls_version_get_string_full(g_backend_version);

	mbedtls_entropy_init(&g_entropy);
	mbedtls_ctr_drbg_init(&g_ctr_drbg);

	ret = mbedtls_ctr_drbg_seed(
		&g_ctr_drbg, mbedtls_entropy_func,
		&g_entropy, NULL, MBEDTLS_CTR_DRBG_ENTROPY_LEN);

	if (ret)
		return -EINVAL;

	g_initialized = true;
	return 0;
}

void crypt_backend_destroy(void)
{
	if (!g_initialized)
		return;

	mbedtls_ctr_drbg_free(&g_ctr_drbg);
	mbedtls_entropy_free(&g_entropy);
	g_initialized = false;
}

uint32_t crypt_backend_flags(void)
{
	return 0;
}

const char *crypt_backend_version(void)
{
	return g_backend_version;
}

bool crypt_fips_mode(void)
{
	return false;
}

int crypt_backend_memeq(const void *m1, const void *m2, size_t n)
{
	return mbedtls_ct_memcmp(m1, m2, n);
}

/* HASH */
int crypt_hash_size(const char *name)
{
	const mbedtls_md_info_t *info;
	info = crypt_get_hash(name);
	return info ? mbedtls_md_get_size(info) : -ENOENT;
}

int crypt_hash_init(struct crypt_hash **ctx, const char *name)
{
	struct crypt_hash *h;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->info = crypt_get_hash(name);
	if (!h->info) {
		free(h);
		return -ENOENT;
	}

	mbedtls_md_init(&h->md);

	if (mbedtls_md_setup(&h->md, h->info, 0)) {
		mbedtls_md_free(&h->md);
		free(h);
		return -EINVAL;
	}

	if (mbedtls_md_starts(&h->md)) {
		mbedtls_md_free(&h->md);
		free(h);
		return -EINVAL;
	}

	*ctx = h;
	return 0;
}

int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length)
{
	if (mbedtls_md_update(&ctx->md, (const unsigned char *)buffer, length))
		return -EINVAL;

	return 0;
}

int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length)
{
	unsigned char tmp[MBEDTLS_MD_MAX_SIZE];

	if (length > mbedtls_md_get_size(ctx->info))
		return -EINVAL;

	if (mbedtls_md_finish(&ctx->md, tmp))
		return -EINVAL;

	crypt_backend_memcpy(buffer, tmp, length);
	crypt_backend_memzero(tmp, sizeof(tmp));

	if (mbedtls_md_starts(&ctx->md))
		return -EINVAL;

	return 0;
}

void crypt_hash_destroy(struct crypt_hash *ctx)
{
	mbedtls_md_free(&ctx->md);
	crypt_backend_memzero(ctx, sizeof(*ctx));
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

	h->info = crypt_get_hash(name);
	if (!h->info) {
		free(h);
		return -ENOENT;
	}

	mbedtls_md_init(&h->md);

	if (mbedtls_md_setup(&h->md, h->info, 1)) {
		mbedtls_md_free(&h->md);
		free(h);
		return -EINVAL;
	}

	if (mbedtls_md_hmac_starts(&h->md, key, key_length)) {
		mbedtls_md_free(&h->md);
		free(h);
		return -EINVAL;
	}

	*ctx = h;
	return 0;
}

int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length)
{
	if (mbedtls_md_hmac_update(&ctx->md, (const unsigned char *)buffer, length))
		return -EINVAL;

	return 0;
}

int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length)
{
	unsigned char tmp[MBEDTLS_MD_MAX_SIZE];

	if (length > mbedtls_md_get_size(ctx->info))
		return -EINVAL;

	if (mbedtls_md_hmac_finish(&ctx->md, tmp))
		return -EINVAL;

	crypt_backend_memcpy(buffer, tmp, length);
	crypt_backend_memzero(tmp, sizeof(tmp));

	if (mbedtls_md_hmac_reset(&ctx->md))
		return -EINVAL;

	return 0;
}

void crypt_hmac_destroy(struct crypt_hmac *ctx)
{
	mbedtls_md_free(&ctx->md);
	crypt_backend_memzero(ctx, sizeof(*ctx));
	free(ctx);
}

/* RNG */
int crypt_backend_rng(char *buffer, size_t length, int quality, int fips)
{
	if (fips)
		return -ENOTSUP;

	/* Allow skipping reseeding for non-cryptographic strong random numbers */
	if (quality == CRYPT_RND_NORMAL || quality == CRYPT_RND_SALT)
		mbedtls_ctr_drbg_set_prediction_resistance(&g_ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF);
	else
		mbedtls_ctr_drbg_set_prediction_resistance(&g_ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

	if (mbedtls_ctr_drbg_random(&g_ctr_drbg, (unsigned char *)buffer, length))
		return -EINVAL;

	return 0;
}

/* CIPHER */
int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		      const char *mode, const void *key, size_t key_length)
{
	static const struct {
		const char *name;
		mbedtls_cipher_id_t id;
	} kCipher[] = {
		{ "aes",      MBEDTLS_CIPHER_ID_AES      },
		{ "aria",     MBEDTLS_CIPHER_ID_ARIA     },
		{ "camellia", MBEDTLS_CIPHER_ID_CAMELLIA },
		{ NULL,       0                          }
	};

	static const struct {
		const char *name;
		mbedtls_cipher_mode_t mode;
	} kMode[] = {
		{ "ecb", MBEDTLS_MODE_ECB },
		{ "cbc", MBEDTLS_MODE_CBC },
		{ "cfb", MBEDTLS_MODE_CFB },
		{ "ofb", MBEDTLS_MODE_OFB },
		{ "ctr", MBEDTLS_MODE_CTR },
		{ "xts", MBEDTLS_MODE_XTS },
		{ NULL,  0                }
	};

	mbedtls_cipher_id_t cid = MBEDTLS_CIPHER_ID_NONE;
	mbedtls_cipher_mode_t cmode = MBEDTLS_MODE_NONE;
	struct crypt_cipher *h;
	size_t i;
	int bits;

	for (i = 0; kCipher[i].name; i++) {
		if (strcmp(kCipher[i].name, name) == 0) {
			cid = kCipher[i].id;
			break;
		}
	}

	for (i = 0; kMode[i].name; i++) {
		if (strcmp(kMode[i].name, mode) == 0) {
			cmode = kMode[i].mode;
			break;
		}
	}

	if (cid == MBEDTLS_CIPHER_ID_NONE || cmode == MBEDTLS_MODE_NONE)
		return -ENOENT;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	bits = key_length * 8;
	h->info = mbedtls_cipher_info_from_values(cid, bits, cmode);
	if (!h->info) {
		free(h);
		return -ENOENT;
	}

	mbedtls_cipher_init(&h->enc);
	mbedtls_cipher_init(&h->dec);
	if (mbedtls_cipher_setup(&h->enc, h->info)                     ||
	    mbedtls_cipher_setup(&h->dec, h->info)                     ||
	    mbedtls_cipher_setkey(&h->enc, key, bits, MBEDTLS_ENCRYPT) ||
	    mbedtls_cipher_setkey(&h->dec, key, bits, MBEDTLS_DECRYPT)) {

		mbedtls_cipher_free(&h->dec);
		mbedtls_cipher_free(&h->enc);
		free(h);
		return -EINVAL;
	}

	if (cmode == MBEDTLS_MODE_CBC) {
		if (mbedtls_cipher_set_padding_mode(&h->enc, MBEDTLS_PADDING_NONE) ||
		    mbedtls_cipher_set_padding_mode(&h->dec, MBEDTLS_PADDING_NONE)) {

			mbedtls_cipher_free(&h->dec);
			mbedtls_cipher_free(&h->enc);
			free(h);
			return -EINVAL;
		}
	}

	h->ecb = cmode == MBEDTLS_MODE_ECB;
	*ctx = h;
	return 0;
}

void crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	mbedtls_cipher_free(&ctx->dec);
	mbedtls_cipher_free(&ctx->enc);
	free(ctx);
}

static int crypt_cipher_crypt(
	mbedtls_cipher_context_t *ctx,
	const char *in, char *out, size_t length,
	const char *iv, size_t iv_length,
	int ecb)
{
	const unsigned char *input;
	unsigned char *output;
	size_t outlen;
	size_t block;
	size_t len;

	if (ecb) /* ECB requires exactly block length input */
		block = mbedtls_cipher_get_block_size(ctx);
	else
		block = length;

	input = (const unsigned char *)in;
	output = (unsigned char *)out;

	if (mbedtls_cipher_set_iv(ctx, (const unsigned char *)iv, iv_length))
		return -EINVAL;

	if (mbedtls_cipher_reset(ctx))
		return -EINVAL;

	while (length) {
		len = length < block ? length : block;
		if (mbedtls_cipher_update(ctx, input, len, output, &outlen))
			return -EINVAL;

		output += outlen;
		length -= len;
		input += len;
	}

	if (mbedtls_cipher_finish(ctx, output, &outlen))
		return -EINVAL;

	return 0;
}

int crypt_cipher_encrypt(struct crypt_cipher *ctx,
                         const char *in, char *out, size_t length,
                         const char *iv, size_t iv_length)
{
	return crypt_cipher_crypt(&ctx->enc, in, out, length, iv, iv_length, ctx->ecb);
}

int crypt_cipher_decrypt(struct crypt_cipher *ctx,
                         const char *in, char *out, size_t length,
                         const char *iv, size_t iv_length)
{
	return crypt_cipher_crypt(&ctx->dec, in, out, length, iv, iv_length, ctx->ecb);
}

bool crypt_cipher_kernel_only(struct crypt_cipher *ctx __attribute__((unused)))
{
	return false;
}

int crypt_pbkdf(const char *kdf, const char *hash,
                const char *password, size_t password_length,
                const char *salt, size_t salt_length,
                char *key, size_t key_length,
                uint32_t iterations, uint32_t memory, uint32_t parallel)
{
	const mbedtls_md_info_t *info;
#if !HAVE_MBEDTLS_PKCS5_PBKDF2_HMAC_EXT
	mbedtls_md_context_t md;
#endif

	if (!kdf)
		return -EINVAL;

	if (strcmp(kdf, "pbkdf2") == 0) {
		info = crypt_get_hash(hash);
		if (!info)
			return -EINVAL;

#if HAVE_MBEDTLS_PKCS5_PBKDF2_HMAC_EXT
		if (mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_get_type(info),
						  (const unsigned char *)password, password_length,
						  (const unsigned char *)salt, salt_length,
						  iterations, key_length, (unsigned char *)key)) {

			return -EINVAL;
		}
#else
		mbedtls_md_init(&md);
		if (mbedtls_md_setup(&md, info, 1))
			return -EINVAL;

		if (mbedtls_pkcs5_pbkdf2_hmac(&md,
					      (const unsigned char *)password, password_length,
					      (const unsigned char *)salt, salt_length,
					      iterations, key_length, (unsigned char *)key)) {

			mbedtls_md_free(&md);
			return -EINVAL;
		}

		mbedtls_md_free(&md);
#endif
		return 0;

	} else if (strncmp(kdf, "argon2", 6) == 0) {
		return argon2(kdf, password, password_length, salt, salt_length,
			      key, key_length, iterations, memory, parallel);
	}

	return -EINVAL;
}

int crypt_bitlk_decrypt_key(const void *key, size_t key_length,
                            const char *in, char *out, size_t length,
                            const char *iv, size_t iv_length,
                            const char *tag, size_t tag_length)
{
	const unsigned char *tagptr;
	const unsigned char *input;
	const unsigned char *ivptr;
	mbedtls_ccm_context ctx;
	unsigned char *output;

	tagptr = (const unsigned char *)tag;
	ivptr = (const unsigned char *)iv;
	input = (const unsigned char *)in;
	output = (unsigned char *)out;
	mbedtls_ccm_init(&ctx);

	if (mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, key_length * 8)) {
		mbedtls_ccm_free(&ctx);
		return -EINVAL;
	}

	if (mbedtls_ccm_auth_decrypt(&ctx, length, ivptr, iv_length, NULL, 0,
				     input, output, tagptr, tag_length)) {

		mbedtls_ccm_free(&ctx);
		return -EINVAL;
	}

	mbedtls_ccm_free(&ctx);
	return 0;
}
