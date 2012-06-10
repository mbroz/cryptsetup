/*
 * crypto backend implementation
 *
 * Copyright (C) 2010-2012, Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef _CRYPTO_BACKEND_H
#define _CRYPTO_BACKEND_H

#include <stdint.h>
#include "config.h"

struct crypt_device;
struct crypt_hash;
struct crypt_hmac;

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

#endif /* _CRYPTO_BACKEND_H */
