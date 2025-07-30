// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * crypto backend implementation
 *
 * Copyright (C) 2010-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2010-2025 Milan Broz
 */

#ifndef _CRYPTO_BACKEND_H
#define _CRYPTO_BACKEND_H

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#if HAVE_UCHAR_H
#include <uchar.h>
#else
#define char32_t uint32_t
#define char16_t uint16_t
#endif

# ifdef __cplusplus
extern "C" {
# endif

struct crypt_hash;
struct crypt_hmac;
struct crypt_cipher;
struct crypt_storage;

int crypt_backend_init(bool fips);
void crypt_backend_destroy(void);

#define CRYPT_BACKEND_KERNEL     (1 << 0) /* Crypto uses kernel part, for benchmark */
#define CRYPT_BACKEND_PBKDF2_INT (1 << 1) /* Iteration in PBKDF2 is signed int and can overflow */
#define CRYPT_BACKEND_ARGON2     (1 << 2) /* Backend provides native Argon2 implementation */

uint32_t crypt_backend_flags(void);
const char *crypt_backend_version(void);
const char *crypt_argon2_version(void);

/* HASH */
int crypt_hash_size(const char *name);
int crypt_hash_init(struct crypt_hash **ctx, const char *name);
int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length);
int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length);
void crypt_hash_destroy(struct crypt_hash *ctx);

/* HMAC */
int crypt_hmac_size(const char *name);
int crypt_hmac_init(struct crypt_hmac **ctx, const char *name,
		    const void *key, size_t key_length);
int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length);
int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length);
void crypt_hmac_destroy(struct crypt_hmac *ctx);

/* RNG (if fips parameter set, must provide FIPS compliance) */
enum { CRYPT_RND_NORMAL = 0, CRYPT_RND_KEY = 1, CRYPT_RND_SALT = 2 };
int crypt_backend_rng(char *buffer, size_t length, int quality, int fips);


/* PBKDF*/
struct crypt_pbkdf_limits {
	uint32_t min_iterations, max_iterations;
	uint32_t min_memory, max_memory, min_bench_memory;
	uint32_t min_parallel, max_parallel;
};

int crypt_pbkdf_get_limits(const char *kdf, struct crypt_pbkdf_limits *l);
int crypt_pbkdf(const char *kdf, const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		uint32_t iterations, uint32_t memory, uint32_t parallel);
int crypt_pbkdf_perf(const char *kdf, const char *hash,
		const char *password, size_t password_size,
		const char *salt, size_t salt_size,
		size_t volume_key_size, uint32_t time_ms,
		uint32_t max_memory_kb, uint32_t parallel_threads,
		uint32_t *iterations_out, uint32_t *memory_out,
		int (*progress)(uint32_t time_ms, void *usrptr), void *usrptr);

/* CRC32 */
uint32_t crypt_crc32(uint32_t seed, const unsigned char *buf, size_t len);
uint32_t crypt_crc32c(uint32_t seed, const unsigned char *buf, size_t len);

/* Base64 */
int crypt_base64_encode(char **out, size_t *out_length, const char *in, size_t in_length);
int crypt_base64_decode(char **out, size_t *out_length, const char *in, size_t in_length);

/* UTF8/16 */
int crypt_utf16_to_utf8(char **out, const char16_t *s, size_t length /* bytes! */);
int crypt_utf8_to_utf16(char16_t **out, const char *s, size_t length);
size_t crypt_char16_strlen(const char16_t *s);

/* Block ciphers */
int crypt_cipher_ivsize(const char *name, const char *mode);
int crypt_cipher_wrapped_key(const char *name, const char *mode);
int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *key, size_t key_length);
void crypt_cipher_destroy(struct crypt_cipher *ctx);
int crypt_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length);
int crypt_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length);
bool crypt_cipher_kernel_only(struct crypt_cipher *ctx);

/* Benchmark of kernel cipher performance */
int crypt_cipher_perf_kernel(const char *name, const char *mode, char *buffer, size_t buffer_size,
			     const char *key, size_t key_size, const char *iv, size_t iv_size,
			     double *encryption_mbs, double *decryption_mbs);

/* Check availability of a cipher (in kernel only) */
int crypt_cipher_check_kernel(const char *name, const char *mode,
			      const char *integrity, size_t key_length);

/* Storage encryption wrappers */
int crypt_storage_init(struct crypt_storage **ctx, size_t sector_size,
		       const char *cipher, const char *cipher_mode,
		       const void *key, size_t key_length, bool large_iv);
void crypt_storage_destroy(struct crypt_storage *ctx);
int crypt_storage_decrypt(struct crypt_storage *ctx, uint64_t iv_offset,
			  uint64_t length, char *buffer);
int crypt_storage_encrypt(struct crypt_storage *ctx, uint64_t iv_offset,
			  uint64_t length, char *buffer);

bool crypt_storage_kernel_only(struct crypt_storage *ctx);

/* Temporary Bitlk helper */
int crypt_bitlk_decrypt_key(const void *key, size_t key_length,
			    const char *in, char *out, size_t length,
			    const char *iv, size_t iv_length,
			    const char *tag, size_t tag_length);

/* Memzero helper (memset on stack can be optimized out) */
void crypt_backend_memzero(void *s, size_t n);

/* Memcpy helper to avoid spilling sensitive data through additional registers */
void *crypt_backend_memcpy(void *dst, const void *src, size_t n);

/* Memcmp helper (memcmp in constant time) */
int crypt_backend_memeq(const void *m1, const void *m2, size_t n);

/* crypto backend running in FIPS mode */
bool crypt_fips_mode(void);

# ifdef __cplusplus
}
# endif

#endif /* _CRYPTO_BACKEND_H */
