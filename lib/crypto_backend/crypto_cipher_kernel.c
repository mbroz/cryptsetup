/*
 * Linux kernel userspace API crypto backend implementation (skcipher)
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2014, Milan Broz
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
#include <sys/stat.h>
#include "crypto_backend.h"

#ifdef ENABLE_AF_ALG

#include <linux/if_alg.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

struct crypt_cipher {
	int tfmfd;
	int opfd;
};

struct cipher_alg {
	const char *name;
	int blocksize;
};

/* FIXME: Getting block size should be dynamic from cipher backend. */
static struct cipher_alg cipher_algs[] = {
	{ "cipher_null", 16 },
	{ "aes",         16 },
	{ "serpent",     16 },
	{ "twofish",     16 },
	{ "anubis",      16 },
	{ "blowfish",     8 },
	{ "camellia",    16 },
	{ "cast5",        8 },
	{ "cast6",       16 },
	{ "des",          8 },
	{ "des3_ede",     8 },
	{ "khazad",       8 },
	{ "seed",        16 },
	{ "tea",          8 },
	{ "xtea",         8 },
	{ NULL,           0 }
};

static struct cipher_alg *_get_alg(const char *name)
{
	int i = 0;

	while (name && cipher_algs[i].name) {
		if (!strcasecmp(name, cipher_algs[i].name))
			return &cipher_algs[i];
		i++;
	}
	return NULL;
}

int crypt_cipher_blocksize(const char *name)
{
	struct cipher_alg *ca = _get_alg(name);

	return ca ? ca->blocksize : -EINVAL;
}

/* Shared with hash kernel backend */
int crypt_kernel_socket_init(struct sockaddr_alg *sa, int *tfmfd, int *opfd);

int crypt_kernel_socket_init(struct sockaddr_alg *sa, int *tfmfd, int *opfd)
{
	*tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (*tfmfd == -1)
		return -ENOTSUP;

	if (bind(*tfmfd, (struct sockaddr *)sa, sizeof(*sa)) == -1) {
		close(*tfmfd);
		*tfmfd = -1;
		return -ENOENT;
	}

	*opfd = accept(*tfmfd, NULL, 0);
	if (*opfd == -1) {
		close(*tfmfd);
		*tfmfd = -1;
		return -EINVAL;
	}

	return 0;
}

/*
 *ciphers
 *
 * ENOENT - algorithm not available
 * ENOTSUP - AF_ALG family not available
 * (but cannot check specificaly for skcipher API)
 */
int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *buffer, size_t length)
{
	struct crypt_cipher *h;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
	};
	int r;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	snprintf((char *)sa.salg_name, sizeof(sa.salg_name),
		 "%s(%s)", mode, name);

	r = crypt_kernel_socket_init(&sa, &h->tfmfd, &h->opfd);
	if (r < 0) {
		free(h);
		return r;
	}

	if (length && strcmp(name, "cipher_null") &&
	    setsockopt(h->tfmfd, SOL_ALG, ALG_SET_KEY, buffer, length) == -1) {
		crypt_cipher_destroy(h);
		return -EINVAL;
	}

	*ctx = h;
	return 0;
}

/* The in/out should be aligned to page boundary */
static int crypt_cipher_crypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length,
			 uint32_t direction)
{
	int r = 0;
	ssize_t len;
	struct af_alg_iv *alg_iv;
	struct cmsghdr *header;
	uint32_t *type;
	struct iovec iov = {
		.iov_base = (void*)(uintptr_t)in,
		.iov_len = length,
	};
	int iv_msg_size = iv ? CMSG_SPACE(sizeof(*alg_iv) + iv_length) : 0;
	char buffer[CMSG_SPACE(sizeof(*type)) + iv_msg_size];
	struct msghdr msg = {
		.msg_control = buffer,
		.msg_controllen = sizeof(buffer),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	if (!in || !out || !length)
		return -EINVAL;

	if ((!iv && iv_length) || (iv && !iv_length))
		return -EINVAL;

	memset(buffer, 0, sizeof(buffer));

	/* Set encrypt/decrypt operation */
	header = CMSG_FIRSTHDR(&msg);
	if (!header)
		return -EINVAL;

	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_OP;
	header->cmsg_len = CMSG_LEN(sizeof(*type));
	type = (void*)CMSG_DATA(header);
	*type = direction;

	/* Set IV */
	if (iv) {
		header = CMSG_NXTHDR(&msg, header);
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_IV;
		header->cmsg_len = iv_msg_size;
		alg_iv = (void*)CMSG_DATA(header);
		alg_iv->ivlen = iv_length;
		memcpy(alg_iv->iv, iv, iv_length);
	}

	len = sendmsg(ctx->opfd, &msg, 0);
	if (len != (ssize_t)length) {
		r = -EIO;
		goto bad;
	}

	len = read(ctx->opfd, out, length);
	if (len != (ssize_t)length)
		r = -EIO;
bad:
	memset(buffer, 0, sizeof(buffer));
	return r;
}

int crypt_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return crypt_cipher_crypt(ctx, in, out, length,
				  iv, iv_length, ALG_OP_ENCRYPT);
}

int crypt_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return crypt_cipher_crypt(ctx, in, out, length,
				  iv, iv_length, ALG_OP_DECRYPT);
}

int crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	if (ctx->tfmfd != -1)
		close(ctx->tfmfd);
	if (ctx->opfd != -1)
		close(ctx->opfd);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
	return 0;
}

#else /* ENABLE_AF_ALG */

int crypt_cipher_blocksize(const char *name)
{
	return -EINVAL;
}

int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *buffer, size_t length)
{
	return -ENOTSUP;
}

int crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	return 0;
}

int crypt_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return -EINVAL;
}
int crypt_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	return -EINVAL;
}
#endif
