/*
 * crypto backend implementation
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
 */
#ifndef _CRYPTO_BACKEND_H
#define _CRYPTO_BACKEND_H

#include <stdint.h>
#include <string.h>

struct crypt_device;
struct crypt_hash;
struct crypt_hmac;
struct crypt_cipher;
struct crypt_storage;

int crypt_backend_init(struct crypt_device *ctx);

#define CRYPT_BACKEND_KERNEL (1 << 0)	/* Crypto uses kernel part, for benchmark */

uint32_t crypt_backend_flags(void);
const char *crypt_backend_version(void);

/* HASH */
int crypt_hash_size(const char *name);
int crypt_hash_init(struct crypt_hash **ctx, const char *name);
int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length);
int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length);
int crypt_hash_destroy(struct crypt_hash *ctx);

/* HMAC */
int crypt_hmac_size(const char *name);
int crypt_hmac_init(struct crypt_hmac **ctx, const char *name,
		    const void *buffer, size_t length);
int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length);
int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length);
int crypt_hmac_destroy(struct crypt_hmac *ctx);

/* RNG (if fips paramater set, must provide FIPS compliance) */
enum { CRYPT_RND_NORMAL = 0, CRYPT_RND_KEY = 1, CRYPT_RND_SALT = 2 };
int crypt_backend_rng(char *buffer, size_t length, int quality, int fips);

/* PBKDF*/
int crypt_pbkdf_check(const char *kdf, const char *hash,
		      const char *password, size_t password_size,
		      const char *salt, size_t salt_size,
		      uint64_t *iter_secs);
int crypt_pbkdf(const char *kdf, const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		unsigned int iterations);

#if USE_INTERNAL_PBKDF2
/* internal PBKDF2 implementation */
int pkcs5_pbkdf2(const char *hash,
		 const char *P, size_t Plen,
		 const char *S, size_t Slen,
		 unsigned int c,
		 unsigned int dkLen, char *DK,
		 unsigned int hash_block_size);
#endif

/* CRC32 */
uint32_t crypt_crc32(uint32_t seed, const unsigned char *buf, size_t len);

/* ciphers */
int crypt_cipher_blocksize(const char *name);
int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *buffer, size_t length);
int crypt_cipher_destroy(struct crypt_cipher *ctx);
int crypt_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length);
int crypt_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length);

/* storage encryption wrappers */
int crypt_storage_init(struct crypt_storage **ctx, uint64_t sector_start,
		       const char *cipher, const char *cipher_mode,
		       char *key, size_t key_length);
int crypt_storage_destroy(struct crypt_storage *ctx);
int crypt_storage_decrypt(struct crypt_storage *ctx, uint64_t sector,
			  size_t count, char *buffer);
int crypt_storage_encrypt(struct crypt_storage *ctx, uint64_t sector,
			  size_t count, char *buffer);

#endif /* _CRYPTO_BACKEND_H */
