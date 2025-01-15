// SPDX-License-Identifier: LGPL-2.1-or-later WITH cryptsetup-OpenSSL-exception
/*
 * OPENSSL crypto backend implementation
 *
 * Copyright (C) 2010-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2010-2025 Milan Broz
 */

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <strings.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "crypto_backend_internal.h"
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/provider.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
static OSSL_PROVIDER *ossl_legacy = NULL;
static OSSL_PROVIDER *ossl_default = NULL;
static OSSL_LIB_CTX  *ossl_ctx = NULL;
static char backend_version[256] = "OpenSSL";

#define MAX_THREADS 8
#if !HAVE_DECL_OSSL_GET_MAX_THREADS
static int OSSL_set_max_threads(OSSL_LIB_CTX *ctx __attribute__((unused)),
				uint64_t max_threads __attribute__((unused))) { return 0; }
static uint64_t OSSL_get_max_threads(OSSL_LIB_CTX *ctx __attribute__((unused))) { return 0; }
#else
#include <openssl/thread.h>
#endif

#endif

#define CONST_CAST(x) (x)(uintptr_t)
#define UNUSED(x) (void)(x)

static int crypto_backend_initialised = 0;

struct crypt_hash {
	EVP_MD_CTX *md;
	const EVP_MD *hash_id;
	int hash_len;
};

struct crypt_hmac {
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_MAC *mac;
	EVP_MAC_CTX *md;
	EVP_MAC_CTX *md_org;
#else
	HMAC_CTX *md;
	const EVP_MD *hash_id;
#endif
	int hash_len;
};

struct crypt_cipher {
	bool use_kernel;
	union {
	struct crypt_cipher_kernel kernel;
	struct {
		EVP_CIPHER_CTX *hd_enc;
		EVP_CIPHER_CTX *hd_dec;
		const EVP_CIPHER *cipher_type;
		size_t iv_length;
	} lib;
	} u;
};

struct hash_alg {
	const char *name;
	const char *openssl_name;
};

/*
 * Compatible wrappers for OpenSSL < 1.1.0 and LibreSSL < 2.7.0
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)

static int openssl_backend_init(bool fips __attribute__((unused)))
{
	OpenSSL_add_all_algorithms();
	return 0;
}

static void openssl_backend_exit(void)
{
}

static const char *openssl_backend_version(void)
{
	return SSLeay_version(SSLEAY_VERSION);
}

static EVP_MD_CTX *EVP_MD_CTX_new(void)
{
	EVP_MD_CTX *md = malloc(sizeof(*md));

	if (md)
		EVP_MD_CTX_init(md);

	return md;
}

static void EVP_MD_CTX_free(EVP_MD_CTX *md)
{
	EVP_MD_CTX_cleanup(md);
	free(md);
}

static HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *md = malloc(sizeof(*md));

	if (md)
		HMAC_CTX_init(md);

	return md;
}

static void HMAC_CTX_free(HMAC_CTX *md)
{
	HMAC_CTX_cleanup(md);
	free(md);
}
#else
static void openssl_backend_exit(void)
{
#if OPENSSL_VERSION_MAJOR >= 3
	if (ossl_legacy)
		OSSL_PROVIDER_unload(ossl_legacy);
	if (ossl_default)
		OSSL_PROVIDER_unload(ossl_default);
	if (ossl_ctx)
		OSSL_LIB_CTX_free(ossl_ctx);

	ossl_legacy = NULL;
	ossl_default = NULL;
	ossl_ctx = NULL;
#endif
}

static int openssl_backend_init(bool fips)
{
/*
 * OpenSSL >= 3.0.0 provides some algorithms in legacy provider
 */
#if OPENSSL_VERSION_MAJOR >= 3
	int r;
	bool ossl_threads = false;

	/*
	 * In FIPS mode we keep default OpenSSL context & global config
	 */
	if (!fips) {
		ossl_ctx = OSSL_LIB_CTX_new();
		if (!ossl_ctx)
			return -EINVAL;

		ossl_default = OSSL_PROVIDER_try_load(ossl_ctx, "default", 0);
		if (!ossl_default) {
			OSSL_LIB_CTX_free(ossl_ctx);
			return -EINVAL;
		}

		/* Optional */
		ossl_legacy = OSSL_PROVIDER_try_load(ossl_ctx, "legacy", 0);
	}

	if (OSSL_set_max_threads(ossl_ctx, MAX_THREADS) == 1 &&
	    OSSL_get_max_threads(ossl_ctx) == MAX_THREADS)
		ossl_threads = true;

	r = snprintf(backend_version, sizeof(backend_version), "%s %s%s%s%s%s",
		OpenSSL_version(OPENSSL_VERSION),
		ossl_default ? "[default]" : "",
		ossl_legacy  ? "[legacy]" : "",
		fips  ? "[fips]" : "",
		ossl_threads ? "[threads]" : "",
		crypt_backend_flags() & CRYPT_BACKEND_ARGON2 ? "[argon2]" : "");

	if (r < 0 || (size_t)r >= sizeof(backend_version)) {
		openssl_backend_exit();
		return -EINVAL;
	}
#else
	UNUSED(fips);
#endif
	return 0;
}

static const char *openssl_backend_version(void)
{
#if OPENSSL_VERSION_MAJOR >= 3
	return backend_version;
#else
	return OpenSSL_version(OPENSSL_VERSION);
#endif
}
#endif

int crypt_backend_init(bool fips)
{
	if (crypto_backend_initialised)
		return 0;

	if (openssl_backend_init(fips))
		return -EINVAL;

	crypto_backend_initialised = 1;
	return 0;
}

void crypt_backend_destroy(void)
{
	/*
	 * If Destructor was already called, we must not call it again
	 */
	if (!crypto_backend_initialised)
		return;

	crypto_backend_initialised = 0;

	openssl_backend_exit();
}

uint32_t crypt_backend_flags(void)
{
	uint32_t flags = 0;
#if OPENSSL_VERSION_MAJOR < 3
	flags |= CRYPT_BACKEND_PBKDF2_INT;
#endif
#if HAVE_DECL_OSSL_KDF_PARAM_ARGON2_VERSION
	flags |= CRYPT_BACKEND_ARGON2;
#endif
	return flags;
}

const char *crypt_backend_version(void)
{
	return openssl_backend_version();
}

static const char *crypt_hash_compat_name(const char *name)
{
	const char *hash_name = name;
	int i;
	static struct hash_alg hash_algs[] = {
	{ "blake2b-512", "blake2b512" },
	{ "blake2s-256", "blake2s256" },
	{ NULL,          NULL,         }};

	if (!name)
		return NULL;

	i = 0;
	while (hash_algs[i].name) {
		if (!strcasecmp(name, hash_algs[i].name)) {
			hash_name =  hash_algs[i].openssl_name;
			break;
		}
		i++;
	}

	return hash_name;
}

static const EVP_MD *hash_id_get(const char *name)
{
#if OPENSSL_VERSION_MAJOR >= 3
	return EVP_MD_fetch(ossl_ctx, crypt_hash_compat_name(name), NULL);
#else
	return EVP_get_digestbyname(crypt_hash_compat_name(name));
#endif
}

static void hash_id_free(const EVP_MD *hash_id)
{
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_MD_free(CONST_CAST(EVP_MD*)hash_id);
#else
	UNUSED(hash_id);
#endif
}

static const EVP_CIPHER *cipher_type_get(const char *name)
{
#if OPENSSL_VERSION_MAJOR >= 3
	return EVP_CIPHER_fetch(ossl_ctx, name, NULL);
#else
	return EVP_get_cipherbyname(name);
#endif
}

static void cipher_type_free(const EVP_CIPHER *cipher_type)
{
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_CIPHER_free(CONST_CAST(EVP_CIPHER*)cipher_type);
#else
	UNUSED(cipher_type);
#endif
}

/* HASH */
int crypt_hash_size(const char *name)
{
	int size;
	const EVP_MD *hash_id;

	hash_id = hash_id_get(name);
	if (!hash_id)
		return -EINVAL;

	size = EVP_MD_size(hash_id);
	hash_id_free(hash_id);
	return size;
}

int crypt_hash_init(struct crypt_hash **ctx, const char *name)
{
	struct crypt_hash *h;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->md = EVP_MD_CTX_new();
	if (!h->md) {
		free(h);
		return -ENOMEM;
	}

	h->hash_id = hash_id_get(name);
	if (!h->hash_id) {
		EVP_MD_CTX_free(h->md);
		free(h);
		return -EINVAL;
	}

	if (EVP_DigestInit_ex(h->md, h->hash_id, NULL) != 1) {
		hash_id_free(h->hash_id);
		EVP_MD_CTX_free(h->md);
		free(h);
		return -EINVAL;
	}

	h->hash_len = EVP_MD_size(h->hash_id);
	*ctx = h;
	return 0;
}

static int crypt_hash_restart(struct crypt_hash *ctx)
{
	if (EVP_DigestInit_ex(ctx->md, ctx->hash_id, NULL) != 1)
		return -EINVAL;

	return 0;
}

int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length)
{
	if (EVP_DigestUpdate(ctx->md, buffer, length) != 1)
		return -EINVAL;

	return 0;
}

int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length)
{
	unsigned char tmp[EVP_MAX_MD_SIZE];
	unsigned int tmp_len = 0;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	if (EVP_DigestFinal_ex(ctx->md, tmp, &tmp_len) != 1)
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
	hash_id_free(ctx->hash_id);
	EVP_MD_CTX_free(ctx->md);
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
#if OPENSSL_VERSION_MAJOR >= 3
	OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, CONST_CAST(void*)name, 0),
		OSSL_PARAM_END
	};

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->mac = EVP_MAC_fetch(ossl_ctx, OSSL_MAC_NAME_HMAC, NULL);
	if (!h->mac) {
		free(h);
		return -EINVAL;
	}

	h->md = EVP_MAC_CTX_new(h->mac);
	if (!h->md) {
		EVP_MAC_free(h->mac);
		free(h);
		return -ENOMEM;
	}

	if (EVP_MAC_init(h->md, key, key_length, params) != 1) {
		EVP_MAC_CTX_free(h->md);
		EVP_MAC_free(h->mac);
		free(h);
		return -EINVAL;
	}

	h->hash_len = EVP_MAC_CTX_get_mac_size(h->md);
	h->md_org = EVP_MAC_CTX_dup(h->md);
#else
	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->md = HMAC_CTX_new();
	if (!h->md) {
		free(h);
		return -ENOMEM;
	}

	h->hash_id = hash_id_get(name);
	if (!h->hash_id) {
		HMAC_CTX_free(h->md);
		free(h);
		return -EINVAL;
	}

	HMAC_Init_ex(h->md, key, key_length, h->hash_id, NULL);

	h->hash_len = EVP_MD_size(h->hash_id);
#endif
	*ctx = h;
	return 0;
}

static int crypt_hmac_restart(struct crypt_hmac *ctx)
{
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_MAC_CTX_free(ctx->md);
	ctx->md = EVP_MAC_CTX_dup(ctx->md_org);
	if (!ctx->md)
		return -EINVAL;
#else
	HMAC_Init_ex(ctx->md, NULL, 0, ctx->hash_id, NULL);
#endif
	return 0;
}

int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length)
{
#if OPENSSL_VERSION_MAJOR >= 3
	return EVP_MAC_update(ctx->md, (const unsigned char *)buffer, length) == 1 ? 0 : -EINVAL;
#else
	HMAC_Update(ctx->md, (const unsigned char *)buffer, length);
	return 0;
#endif
}

int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length)
{
	unsigned char tmp[EVP_MAX_MD_SIZE];
#if OPENSSL_VERSION_MAJOR >= 3
	size_t tmp_len = 0;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	if (EVP_MAC_final(ctx->md, tmp,  &tmp_len, sizeof(tmp)) != 1)
		return -EINVAL;
#else
	unsigned int tmp_len = 0;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	HMAC_Final(ctx->md, tmp, &tmp_len);
#endif
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
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_MAC_CTX_free(ctx->md);
	EVP_MAC_CTX_free(ctx->md_org);
	EVP_MAC_free(ctx->mac);
#else
	hash_id_free(ctx->hash_id);
	HMAC_CTX_free(ctx->md);
#endif
	free(ctx);
}

/* RNG */
int crypt_backend_rng(char *buffer, size_t length,
	int quality __attribute__((unused)), int fips __attribute__((unused)))
{
	if (RAND_bytes((unsigned char *)buffer, length) != 1)
		return -EINVAL;

	return 0;
}

static int openssl_pbkdf2(const char *password, size_t password_length,
	const char *salt, size_t salt_length, uint32_t iterations,
	const char *hash, char *key, size_t key_length)
{
	int r;
#if OPENSSL_VERSION_MAJOR >= 3
	EVP_KDF_CTX *ctx;
	EVP_KDF *pbkdf2;
	OSSL_PARAM params[] = {
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD,
			CONST_CAST(void*)password, password_length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT,
			CONST_CAST(void*)salt, salt_length),
		OSSL_PARAM_uint32(OSSL_KDF_PARAM_ITER, &iterations),
		OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST,
			CONST_CAST(void*)hash, 0),
		OSSL_PARAM_END
	};

	pbkdf2 = EVP_KDF_fetch(ossl_ctx, "pbkdf2", NULL);
	if (!pbkdf2)
		return -EINVAL;

	ctx = EVP_KDF_CTX_new(pbkdf2);
	if (!ctx) {
		EVP_KDF_free(pbkdf2);
		return -EINVAL;
	}

	r = EVP_KDF_derive(ctx, (unsigned char*)key, key_length, params);

	EVP_KDF_CTX_free(ctx);
	EVP_KDF_free(pbkdf2);
#else
	const EVP_MD *hash_id = EVP_get_digestbyname(crypt_hash_compat_name(hash));
	if (!hash_id)
		return -EINVAL;

	/* OpenSSL2 has iteration as signed int, avoid overflow */
	if (iterations > INT_MAX)
		return -EINVAL;

	r = PKCS5_PBKDF2_HMAC(password, (int)password_length, (const unsigned char *)salt,
		(int)salt_length, iterations, hash_id, (int)key_length, (unsigned char*) key);
#endif
	return r == 1 ? 0 : -EINVAL;
}

static int openssl_argon2(const char *type, const char *password, size_t password_length,
	const char *salt, size_t salt_length, char *key, size_t key_length,
	uint32_t iterations, uint32_t memory, uint32_t parallel)
{
#if HAVE_DECL_OSSL_KDF_PARAM_ARGON2_VERSION
	EVP_KDF_CTX *ctx;
	EVP_KDF *argon2;
	unsigned int threads = parallel;
	int r;
	OSSL_PARAM params[] = {
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_PASSWORD,
			CONST_CAST(void*)password, password_length),
		OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT,
			CONST_CAST(void*)salt, salt_length),
		OSSL_PARAM_uint32(OSSL_KDF_PARAM_ITER, &iterations),
		OSSL_PARAM_uint(OSSL_KDF_PARAM_THREADS, &threads),
		OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &parallel),
		OSSL_PARAM_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory),
		OSSL_PARAM_END
	};

	if (OSSL_get_max_threads(ossl_ctx) == 0)
		threads = 1;

	argon2 = EVP_KDF_fetch(ossl_ctx, type, NULL);
	if (!argon2)
		return -EINVAL;

	ctx = EVP_KDF_CTX_new(argon2);
	if (!ctx) {
		EVP_KDF_free(argon2);
		return -EINVAL;
	}

	if (EVP_KDF_CTX_set_params(ctx, params) != 1) {
		EVP_KDF_CTX_free(ctx);
		EVP_KDF_free(argon2);
		return -EINVAL;
	}

	r = EVP_KDF_derive(ctx, (unsigned char*)key, key_length, NULL /*params*/);

	EVP_KDF_CTX_free(ctx);
	EVP_KDF_free(argon2);

	/* Memory allocation is common issue with memory-hard Argon2 */
	if (r == 0 && ERR_GET_REASON(ERR_get_error()) == ERR_R_MALLOC_FAILURE)
		return -ENOMEM;

	/* _derive() returns 0 or negative value on error, 1 on success */
	return r == 1 ? 0 : -EINVAL;
#else
	return argon2(type, password, password_length, salt, salt_length,
		      key, key_length, iterations, memory, parallel);
#endif
}

/* PBKDF */
int crypt_pbkdf(const char *kdf, const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		uint32_t iterations, uint32_t memory, uint32_t parallel)
{
	if (!kdf)
		return -EINVAL;

	if (!strcmp(kdf, "pbkdf2"))
		return openssl_pbkdf2(password, password_length, salt, salt_length,
				      iterations, hash, key, key_length);
	if (!strncmp(kdf, "argon2", 6))
		return openssl_argon2(kdf, password, password_length, salt, salt_length,
				      key, key_length, iterations, memory, parallel);
	return -EINVAL;
}

/* Block ciphers */
static void _cipher_destroy(EVP_CIPHER_CTX **hd_enc, EVP_CIPHER_CTX **hd_dec, const EVP_CIPHER **cipher_type)
{
	EVP_CIPHER_CTX_free(*hd_enc);
	*hd_enc = NULL;

	EVP_CIPHER_CTX_free(*hd_dec);
	*hd_dec = NULL;

	cipher_type_free(*cipher_type);
	*cipher_type = NULL;
}

static int _cipher_init(EVP_CIPHER_CTX **hd_enc, EVP_CIPHER_CTX **hd_dec, const EVP_CIPHER **cipher_type, const char *name,
			const char *mode, const void *key, size_t key_length, size_t *iv_length)
{
	char cipher_name[256];
	const EVP_CIPHER *type;
	int r, key_bits;

	key_bits = key_length * 8;
	if (!strcmp(mode, "xts"))
		key_bits /= 2;

	r = snprintf(cipher_name, sizeof(cipher_name), "%s-%d-%s", name, key_bits, mode);
	if (r < 0 || (size_t)r >= sizeof(cipher_name))
		return -EINVAL;

	type = cipher_type_get(cipher_name);
	if (!type)
		return -ENOENT;

	if (EVP_CIPHER_key_length(type) != (int)key_length) {
		cipher_type_free(type);
		return -EINVAL;
	}

	*hd_enc = EVP_CIPHER_CTX_new();
	*hd_dec = EVP_CIPHER_CTX_new();
	*iv_length = EVP_CIPHER_iv_length(type);

	if (!*hd_enc || !*hd_dec) {
		cipher_type_free(type);
		return -EINVAL;
	}

	if (EVP_EncryptInit_ex(*hd_enc, type, NULL, key, NULL) != 1 ||
	    EVP_DecryptInit_ex(*hd_dec, type, NULL, key, NULL) != 1) {
		_cipher_destroy(hd_enc, hd_dec, &type);
		return -EINVAL;
	}

	if (EVP_CIPHER_CTX_set_padding(*hd_enc, 0) != 1 ||
	    EVP_CIPHER_CTX_set_padding(*hd_dec, 0) != 1) {
		_cipher_destroy(hd_enc, hd_dec, &type);
		return -EINVAL;
	}

	*cipher_type = type;

	return 0;
}

int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *key, size_t key_length)
{
	struct crypt_cipher *h;
	int r;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	if (!_cipher_init(&h->u.lib.hd_enc, &h->u.lib.hd_dec, &h->u.lib.cipher_type, name, mode, key,
			  key_length, &h->u.lib.iv_length)) {
		h->use_kernel = false;
		*ctx = h;
		return 0;
	}

	r = crypt_cipher_init_kernel(&h->u.kernel, name, mode, key, key_length);
	if (r < 0) {
		free(h);
		return r;
	}

	h->use_kernel = true;
	*ctx = h;
	return 0;
}

void crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	if (ctx->use_kernel)
		crypt_cipher_destroy_kernel(&ctx->u.kernel);
	else
		_cipher_destroy(&ctx->u.lib.hd_enc, &ctx->u.lib.hd_dec, &ctx->u.lib.cipher_type);
	free(ctx);
}

static int _cipher_encrypt(struct crypt_cipher *ctx, const unsigned char *in, unsigned char *out,
			   int length, const unsigned char *iv, size_t iv_length)
{
	int len;

	if (ctx->u.lib.iv_length != iv_length)
		return -EINVAL;

	if (EVP_EncryptInit_ex(ctx->u.lib.hd_enc, NULL, NULL, NULL, iv) != 1)
		return -EINVAL;

	if (EVP_EncryptUpdate(ctx->u.lib.hd_enc, out, &len, in, length) != 1)
		return -EINVAL;

	if (EVP_EncryptFinal(ctx->u.lib.hd_enc, out + len, &len) != 1)
		return -EINVAL;

	return 0;
}

static int _cipher_decrypt(struct crypt_cipher *ctx, const unsigned char *in, unsigned char *out,
			   int length, const unsigned char *iv, size_t iv_length)
{
	int len;

	if (ctx->u.lib.iv_length != iv_length)
		return -EINVAL;

	if (EVP_DecryptInit_ex(ctx->u.lib.hd_dec, NULL, NULL, NULL, iv) != 1)
		return -EINVAL;

	if (EVP_DecryptUpdate(ctx->u.lib.hd_dec, out, &len, in, length) != 1)
		return -EINVAL;

	if (EVP_DecryptFinal(ctx->u.lib.hd_dec, out + len, &len) != 1)
		return -EINVAL;

	return 0;
}

int crypt_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	if (ctx->use_kernel)
		return crypt_cipher_encrypt_kernel(&ctx->u.kernel, in, out, length, iv, iv_length);

	return _cipher_encrypt(ctx, (const unsigned char*)in,
			       (unsigned char *)out, length, (const unsigned char*)iv, iv_length);
}

int crypt_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	if (ctx->use_kernel)
		return crypt_cipher_decrypt_kernel(&ctx->u.kernel, in, out, length, iv, iv_length);

	return _cipher_decrypt(ctx, (const unsigned char*)in,
			       (unsigned char *)out, length, (const unsigned char*)iv, iv_length);
}

bool crypt_cipher_kernel_only(struct crypt_cipher *ctx)
{
	return ctx->use_kernel;
}

int crypt_bitlk_decrypt_key(const void *key, size_t key_length __attribute__((unused)),
			    const char *in, char *out, size_t length,
			    const char *iv, size_t iv_length,
			    const char *tag, size_t tag_length)
{
#ifdef EVP_CTRL_CCM_SET_IVLEN
	EVP_CIPHER_CTX *ctx;
	int len = 0, r = -EINVAL;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -EINVAL;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL) != 1)
		goto out;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_length, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_length, CONST_CAST(void*)tag) != 1)
		goto out;

	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, (const unsigned char*)iv) != 1)
		goto out;

	if (EVP_DecryptUpdate(ctx, (unsigned char*)out, &len, (const unsigned char*)in, length) == 1)
		r = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	return r;
#else
	return -ENOTSUP;
#endif
}

int crypt_backend_memeq(const void *m1, const void *m2, size_t n)
{
	return CRYPTO_memcmp(m1, m2, n);
}

#if !ENABLE_FIPS
bool crypt_fips_mode(void) { return false; }
#else
static bool openssl_fips_mode(void)
{
#if OPENSSL_VERSION_MAJOR >= 3
	return EVP_default_properties_is_fips_enabled(NULL);
#else
	return FIPS_mode();
#endif
}

bool crypt_fips_mode(void)
{
	static bool fips_mode = false, fips_checked = false;

	if (fips_checked)
		return fips_mode;

	fips_mode = openssl_fips_mode();
	fips_checked = true;

	return fips_mode;
}
#endif /* ENABLE FIPS */
