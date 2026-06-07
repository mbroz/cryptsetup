// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Mbed TLS crypto backend implementation
 *
 * Copyright (C) 2024-2026 Yiyuan Zhong
 */

#include "crypto_backend.h"

#include <errno.h>
#include <stdlib.h>

#include <psa/crypto.h>

#include <mbedtls/constant_time.h>
#include <mbedtls/version.h>

#if MBEDTLS_VERSION_MAJOR < 4
#include <mbedtls/pkcs5.h>
#include <mbedtls/psa_util.h>
#endif

#include "crypto_backend_internal.h"

struct crypt_hash {
	psa_algorithm_t alg;
	psa_hash_operation_t md;
};

struct crypt_hmac {
	psa_key_id_t ki;
	psa_algorithm_t alg;
	psa_mac_operation_t md;
};

struct crypt_cipher {
	psa_algorithm_t alg;
	psa_key_id_t eki;
	psa_key_id_t dki;
};

static bool g_initialized = false;

static psa_algorithm_t crypt_get_hash(const char *name)
{
	static const struct hash_alg {
		const char *name;
		psa_algorithm_t type;
	} kHash[] = {
		{"sha1",      PSA_ALG_SHA_1    },
		{"sha224",    PSA_ALG_SHA_224  },
		{"sha256",    PSA_ALG_SHA_256  },
		{"sha384",    PSA_ALG_SHA_384  },
		{"sha512",    PSA_ALG_SHA_512  },
		{"ripemd160", PSA_ALG_RIPEMD160},
		{NULL,        PSA_ALG_NONE,    }
	};

	size_t i = 0;

	while (name && kHash[i].name) {
		if (strcmp(kHash[i].name, name) == 0)
			return kHash[i].type;
		i++;
	}

	return PSA_ALG_NONE;
}

int crypt_backend_init(void)
{
	if (g_initialized)
		return 0;

	if (psa_crypto_init())
		return -EINVAL;

	g_initialized = true;
	return 0;
}

void crypt_backend_destroy(void)
{
	if (!g_initialized)
		return;

	mbedtls_psa_crypto_free();
	g_initialized = false;
}

uint32_t crypt_backend_flags(void)
{
	return 0;
}

const char *crypt_backend_version(void)
{
	return MBEDTLS_VERSION_STRING_FULL;
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
	psa_algorithm_t alg;
	alg = crypt_get_hash(name);
	return alg ? PSA_HASH_LENGTH(alg) : -ENOENT;
}

int crypt_hash_init(struct crypt_hash **ctx, const char *name)
{
	struct crypt_hash *h;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->alg = crypt_get_hash(name);
	if (!h->alg) {
		free(h);
		return -ENOENT;
	}

	h->md = psa_hash_operation_init();

	if (psa_hash_setup(&h->md, h->alg)) {
		free(h);
		return -EINVAL;
	}

	*ctx = h;
	return 0;
}

int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length)
{
	if (psa_hash_update(&ctx->md, (const unsigned char *)buffer, length))
		return -EINVAL;

	return 0;
}

int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length)
{
	unsigned char tmp[PSA_HASH_MAX_SIZE];
	size_t hashlen;

	if (length > PSA_HASH_LENGTH(ctx->alg))
		return -EINVAL;

	if (psa_hash_finish(&ctx->md, tmp, sizeof(tmp), &hashlen))
		return -EINVAL;

	crypt_backend_memcpy(buffer, tmp, length);
	crypt_backend_memzero(tmp, sizeof(tmp));

	if (psa_hash_setup(&ctx->md, ctx->alg))
		return -EINVAL;

	return 0;
}

void crypt_hash_destroy(struct crypt_hash *ctx)
{
	psa_hash_abort(&ctx->md);
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
	psa_key_attributes_t a;
	struct crypt_hmac *h;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->alg = crypt_get_hash(name);
	if (!h->alg) {
		free(h);
		return -ENOENT;
	}

	a = psa_key_attributes_init();
	psa_set_key_type(&a, PSA_KEY_TYPE_HMAC);
	psa_set_key_algorithm(&a, PSA_ALG_HMAC(h->alg));
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE);

	if (psa_import_key(&a, key, key_length, &h->ki)) {
		free(h);
		return -EINVAL;
	}

	h->md = psa_mac_operation_init();
	if (psa_mac_sign_setup(&h->md, h->ki, PSA_ALG_HMAC(h->alg))) {
		psa_destroy_key(h->ki);
		free(h);
		return -EINVAL;
	}

	*ctx = h;
	return 0;
}

int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length)
{
	if (psa_mac_update(&ctx->md, (const unsigned char *)buffer, length))
		return -EINVAL;

	return 0;
}

int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length)
{
	unsigned char tmp[PSA_HASH_MAX_SIZE];
	size_t hashlen;

	if (length > PSA_HASH_LENGTH(ctx->alg))
		return -EINVAL;

	if (psa_mac_sign_finish(&ctx->md, tmp, sizeof(tmp), &hashlen))
		return -EINVAL;

	crypt_backend_memcpy(buffer, tmp, length);
	crypt_backend_memzero(tmp, sizeof(tmp));

	if (psa_mac_sign_setup(&ctx->md, ctx->ki, PSA_ALG_HMAC(ctx->alg)))
		return -EINVAL;

	return 0;
}

void crypt_hmac_destroy(struct crypt_hmac *ctx)
{
	psa_mac_abort(&ctx->md);
	psa_destroy_key(ctx->ki);
	crypt_backend_memzero(ctx, sizeof(*ctx));
	free(ctx);
}

/* RNG */
int crypt_backend_rng(char *buffer, size_t length, int quality, int fips)
{
	if (fips)
		return -ENOTSUP;

	if (psa_generate_random((uint8_t *)buffer, length))
		return -EINVAL;

	return 0;
}

/* CIPHER */
int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		      const char *mode, const void *key, size_t key_length)
{
	static const struct {
		const char *name;
		psa_key_type_t type;
	} kType[] = {
		{ "aes",      PSA_KEY_TYPE_AES      },
		{ "aria",     PSA_KEY_TYPE_ARIA     },
		{ "camellia", PSA_KEY_TYPE_CAMELLIA },
		{ NULL,       PSA_KEY_TYPE_NONE     }
	};

	static const struct {
		const char *name;
		psa_algorithm_t alg;
	} kMode[] = {
		{ "ecb", PSA_ALG_ECB_NO_PADDING },
		{ "cbc", PSA_ALG_CBC_NO_PADDING },
		{ "cfb", PSA_ALG_CFB            },
		{ "ofb", PSA_ALG_OFB            },
		{ "ctr", PSA_ALG_CTR            },
		{ NULL,  PSA_ALG_NONE           }
	};

	psa_key_attributes_t a;
	struct crypt_cipher *h;
	psa_algorithm_t alg;
	psa_key_type_t type;
	size_t i;

	type = PSA_KEY_TYPE_NONE;
	alg = PSA_ALG_NONE;

	a = psa_key_attributes_init();
	psa_set_key_bits(&a, key_length * 8);

	for (i = 0; kType[i].name; i++) {
		if (strcmp(kType[i].name, name) == 0) {
			type = kType[i].type;
			break;
		}
	}

	if (type == PSA_KEY_TYPE_NONE)
		return -ENOENT;

	for (i = 0; kMode[i].name; i++) {
		if (strcmp(kMode[i].name, mode) == 0) {
			alg = kMode[i].alg;
			break;
		}
	}

	if (alg == PSA_ALG_NONE)
		return -ENOENT;

	psa_set_key_algorithm(&a, alg);
	psa_set_key_type(&a, type);
	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT);
	if (psa_import_key(&a, key, key_length, &h->eki)) {
		free(h);
		return -EINVAL;
	}

	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DECRYPT);
	if (psa_import_key(&a, key, key_length, &h->dki)) {
		psa_destroy_key(h->eki);
		free(h);
		return -EINVAL;
	}

	h->alg = alg;
	*ctx = h;
	return 0;
}

void crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	psa_destroy_key(ctx->eki);
	psa_destroy_key(ctx->dki);
	free(ctx);
}

static int crypt_cipher_crypt(
	struct crypt_cipher *ctx, int encrypt,
	const char *in, char *out, size_t length,
	const char *iv, size_t iv_length)
{
	const unsigned char *input;
	psa_cipher_operation_t c;
	unsigned char *output;
	size_t ulen;

	input = (const unsigned char *)in;
	output = (unsigned char *)out;

	c = psa_cipher_operation_init();
	if (encrypt) {
		if (psa_cipher_encrypt_setup(&c, ctx->eki, ctx->alg))
			return -EINVAL;
	} else {
		if (psa_cipher_decrypt_setup(&c, ctx->dki, ctx->alg))
			return -EINVAL;
	}

	if (iv_length && psa_cipher_set_iv(&c, (const unsigned char *)iv, iv_length))
		return -EINVAL;

	if (psa_cipher_update(&c, input, length, output, length, &ulen))
		return -EINVAL;

	psa_cipher_abort(&c);
	return 0;
}

int crypt_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return crypt_cipher_crypt(ctx, 1, in, out, length, iv, iv_length);
}

int crypt_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return crypt_cipher_crypt(ctx, 0, in, out, length, iv, iv_length);
}

bool crypt_cipher_kernel_only(struct crypt_cipher *ctx __attribute__((unused)))
{
	return false;
}

#if MBEDTLS_VERSION_MAJOR >= 4

static int crypt_pbkdf2_impl(
		const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		uint32_t iterations)
{
	static const char kZero = 0;

	psa_key_derivation_operation_t op;
	psa_key_attributes_t a;
	psa_algorithm_t alg;
	psa_key_id_t ki;

	alg = crypt_get_hash(hash);
	if (!alg)
		return -EINVAL;

	op = psa_key_derivation_operation_init();
	if (psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(alg)))
		return -EINVAL;

	if (psa_key_derivation_input_integer(&op,
			PSA_KEY_DERIVATION_INPUT_COST, iterations)) {

		psa_key_derivation_abort(&op);
		return -EINVAL;
	}

	if (psa_key_derivation_input_bytes(&op,
			PSA_KEY_DERIVATION_INPUT_SALT,
			(const unsigned char *)salt, salt_length)) {

		psa_key_derivation_abort(&op);
		return -EINVAL;
	}

	a = psa_key_attributes_init();
	psa_set_key_type(&a, PSA_KEY_TYPE_PASSWORD);
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&a, PSA_ALG_PBKDF2_HMAC(alg));

	if (!password_length) {    /* Empty password not allowed     */
		password = &kZero; /* Provide a single zero password */
		password_length = 1;
	}

	if (psa_import_key(&a, (const unsigned char *)password,
			password_length, &ki)) {

		psa_key_derivation_abort(&op);
		return -EINVAL;
	}

	if (psa_key_derivation_input_key(&op,
			PSA_KEY_DERIVATION_INPUT_PASSWORD, ki)) {

		psa_destroy_key(ki);
		psa_key_derivation_abort(&op);
		return -EINVAL;
	}

	psa_destroy_key(ki);

	if (psa_key_derivation_output_bytes(&op,
			(unsigned char *)key, key_length)) {

		psa_key_derivation_abort(&op);
		return -EINVAL;
	}

	psa_key_derivation_abort(&op);
	return 0;
}

#else /* MBEDTLS_VERSION_MAJOR >= 4 */

static int crypt_pbkdf2_impl( /* Legacy implementation (2.x/3.x) */
		const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		uint32_t iterations)
{
	psa_algorithm_t alg;
	mbedtls_md_type_t type;
#if !HAVE_MBEDTLS_PKCS5_PBKDF2_HMAC_EXT
	mbedtls_md_context_t md;
#endif

	alg = crypt_get_hash(hash);
	if (!alg)
			return -EINVAL;

#if HAVE_MBEDTLS_PKCS5_PBKDF2_HMAC_EXT
	type = mbedtls_md_type_from_psa_alg(alg);
	if (mbedtls_pkcs5_pbkdf2_hmac_ext(type,
			(const unsigned char *)password, password_length,
			(const unsigned char *)salt, salt_length,
			iterations, key_length, (unsigned char *)key)) {

			return -EINVAL;
	}
#else
	switch (alg) {
	case PSA_ALG_SHA_1:     type = MBEDTLS_MD_SHA1;      break;
	case PSA_ALG_SHA_224:   type = MBEDTLS_MD_SHA224;    break;
	case PSA_ALG_SHA_256:   type = MBEDTLS_MD_SHA256;    break;
	case PSA_ALG_SHA_384:   type = MBEDTLS_MD_SHA384;    break;
	case PSA_ALG_SHA_512:   type = MBEDTLS_MD_SHA512;    break;
	case PSA_ALG_RIPEMD160: type = MBEDTLS_MD_RIPEMD160; break;
	default: return -EINVAL;
	}

	mbedtls_md_init(&md);
	if (mbedtls_md_setup(&md, mbedtls_md_info_from_type(type), 1))
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
}

#endif /* MBEDTLS_VERSION_MAJOR >= 4 */

int crypt_pbkdf(const char *kdf, const char *hash,
	        const char *password, size_t password_length,
	        const char *salt, size_t salt_length,
	        char *key, size_t key_length,
	        uint32_t iterations, uint32_t memory, uint32_t parallel)
{
	if (!kdf)
		return -EINVAL;

	if (strcmp(kdf, "pbkdf2") == 0) {
		return crypt_pbkdf2_impl(hash, password, password_length,
				salt, salt_length, key, key_length, iterations);

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
	unsigned char *output;

	psa_key_attributes_t a;
	psa_algorithm_t alg;
	psa_key_id_t ki;
	size_t outlen;

	tagptr = (const unsigned char *)tag;
	ivptr = (const unsigned char *)iv;
	input = (const unsigned char *)in;
	output = (unsigned char *)out;

	alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_length);

	a = psa_key_attributes_init();
	psa_set_key_type(&a, PSA_KEY_TYPE_AES);
	psa_set_key_algorithm(&a, alg);
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DECRYPT);
	psa_set_key_bits(&a, key_length * 8);

	if (psa_import_key(&a, key, key_length, &ki))
		return -EINVAL;

	if (psa_aead_decrypt(ki, alg, ivptr, iv_length, tagptr, tag_length,
			input, length, output, length, &outlen)) {

		psa_destroy_key(ki);
		return -EINVAL;
	}

	psa_destroy_key(ki);
	if (outlen != length)
		return -EINVAL;

	return 0;
}
