/*
 * Linux kernel userspace API crypto backend implementation
 *
 * Copyright (C) 2010-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2010-2020 Milan Broz
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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <linux/if_alg.h>
#include "crypto_backend_internal.h"

/* FIXME: remove later */
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

static int crypto_backend_initialised = 0;
static char version[256];

struct hash_alg {
	const char *name;
	const char *kernel_name;
	int length;
	unsigned int block_length;
};

static struct hash_alg hash_algs[] = {
	{ "sha1",      "sha1",        20,  64 },
	{ "sha224",    "sha224",      28,  64 },
	{ "sha256",    "sha256",      32,  64 },
	{ "sha384",    "sha384",      48, 128 },
	{ "sha512",    "sha512",      64, 128 },
	{ "ripemd160", "rmd160",      20,  64 },
	{ "whirlpool", "wp512",       64,  64 },
	{ "sha3-224",  "sha3-224",    28, 144 },
	{ "sha3-256",  "sha3-256",    32, 136 },
	{ "sha3-384",  "sha3-384",    48, 104 },
	{ "sha3-512",  "sha3-512",    64,  72 },
	{ "stribog256","streebog256", 32,  64 },
	{ "stribog512","streebog512", 64,  64 },
	{ "sm3",       "sm3",         32,  64 },
	{ NULL,        NULL,           0,   0 }
};

struct crypt_hash {
	int tfmfd;
	int opfd;
	int hash_len;
};

struct crypt_hmac {
	int tfmfd;
	int opfd;
	int hash_len;
};

struct crypt_cipher {
	struct crypt_cipher_kernel ck;
};

static int crypt_kernel_socket_init(struct sockaddr_alg *sa, int *tfmfd, int *opfd,
				    const void *key, size_t key_length)
{
	*tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (*tfmfd < 0)
		return -ENOTSUP;

	if (bind(*tfmfd, (struct sockaddr *)sa, sizeof(*sa)) < 0) {
		close(*tfmfd);
		*tfmfd = -1;
		return -ENOENT;
	}

	if (key && setsockopt(*tfmfd, SOL_ALG, ALG_SET_KEY, key, key_length) < 0) {
		close(*tfmfd);
		*tfmfd = -1;
		return -EINVAL;
	}

	*opfd = accept(*tfmfd, NULL, 0);
	if (*opfd < 0) {
		close(*tfmfd);
		*tfmfd = -1;
		return -EINVAL;
	}

	return 0;
}

int crypt_backend_init(void)
{
	struct utsname uts;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
		.salg_name = "sha256",
	};
	int tfmfd = -1, opfd = -1;

	if (crypto_backend_initialised)
		return 0;

	if (uname(&uts) == -1 || strcmp(uts.sysname, "Linux"))
		return -EINVAL;

	if (crypt_kernel_socket_init(&sa, &tfmfd, &opfd, NULL, 0) < 0)
		return -EINVAL;

	close(tfmfd);
	close(opfd);

	snprintf(version, sizeof(version), "%s %s kernel cryptoAPI",
		 uts.sysname, uts.release);

	crypto_backend_initialised = 1;
	return 0;
}

void crypt_backend_destroy(void)
{
	crypto_backend_initialised = 0;
}

uint32_t crypt_backend_flags(void)
{
	return CRYPT_BACKEND_KERNEL;
}

const char *crypt_backend_version(void)
{
	return crypto_backend_initialised ? version : "";
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

/* HASH */
int crypt_hash_size(const char *name)
{
	struct hash_alg *ha = _get_alg(name);

	return ha ? ha->length : -EINVAL;
}

int crypt_hash_init(struct crypt_hash **ctx, const char *name)
{
	struct crypt_hash *h;
	struct hash_alg *ha;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	ha = _get_alg(name);
	if (!ha) {
		free(h);
		return -EINVAL;
	}
	h->hash_len = ha->length;

	strncpy((char *)sa.salg_name, ha->kernel_name, sizeof(sa.salg_name)-1);

	if (crypt_kernel_socket_init(&sa, &h->tfmfd, &h->opfd, NULL, 0) < 0) {
		free(h);
		return -EINVAL;
	}

	*ctx = h;
	return 0;
}

int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length)
{
	ssize_t r;

	r = send(ctx->opfd, buffer, length, MSG_MORE);
	if (r < 0 || (size_t)r < length)
		return -EIO;

	return 0;
}

int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length)
{
	ssize_t r;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	r = read(ctx->opfd, buffer, length);
	if (r < 0)
		return -EIO;

	return 0;
}

void crypt_hash_destroy(struct crypt_hash *ctx)
{
	if (ctx->tfmfd >= 0)
		close(ctx->tfmfd);
	if (ctx->opfd >= 0)
		close(ctx->opfd);
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
	struct hash_alg *ha;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "hash",
	};

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	ha = _get_alg(name);
	if (!ha) {
		free(h);
		return -EINVAL;
	}
	h->hash_len = ha->length;

	snprintf((char *)sa.salg_name, sizeof(sa.salg_name),
		 "hmac(%s)", ha->kernel_name);

	if (crypt_kernel_socket_init(&sa, &h->tfmfd, &h->opfd, key, key_length) < 0) {
		free(h);
		return -EINVAL;
	}

	*ctx = h;
	return 0;
}

int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length)
{
	ssize_t r;

	r = send(ctx->opfd, buffer, length, MSG_MORE);
	if (r < 0 || (size_t)r < length)
		return -EIO;

	return 0;
}

int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length)
{
	ssize_t r;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	r = read(ctx->opfd, buffer, length);
	if (r < 0)
		return -EIO;

	return 0;
}

void crypt_hmac_destroy(struct crypt_hmac *ctx)
{
	if (ctx->tfmfd >= 0)
		close(ctx->tfmfd);
	if (ctx->opfd >= 0)
		close(ctx->opfd);
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
