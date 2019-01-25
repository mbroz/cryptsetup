/*
 * Linux kernel userspace API crypto backend implementation (skcipher)
 *
 * Copyright (C) 2012-2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2019 Milan Broz
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
#include <stdbool.h>
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

/*
 * ciphers
 *
 * ENOENT - algorithm not available
 * ENOTSUP - AF_ALG family not available
 * (but cannot check specifically for skcipher API)
 */
static int _crypt_cipher_init(struct crypt_cipher **ctx,
			      const void *key, size_t key_length,
			      struct sockaddr_alg *sa)
{
	struct crypt_cipher *h;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->opfd = -1;
	h->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (h->tfmfd < 0) {
		crypt_cipher_destroy(h);
		return -ENOTSUP;
	}

	if (bind(h->tfmfd, (struct sockaddr *)sa, sizeof(*sa)) < 0) {
		crypt_cipher_destroy(h);
		return -ENOENT;
	}

	if (setsockopt(h->tfmfd, SOL_ALG, ALG_SET_KEY, key, key_length) < 0) {
		crypt_cipher_destroy(h);
		return -EINVAL;
	}

	h->opfd = accept(h->tfmfd, NULL, 0);
	if (h->opfd < 0) {
		crypt_cipher_destroy(h);
		return -EINVAL;
	}

	*ctx = h;
	return 0;
}

int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		      const char *mode, const void *key, size_t key_length)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
	};

	if (!strcmp(name, "cipher_null"))
		key_length = 0;

	snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "%s(%s)", mode, name);

	return _crypt_cipher_init(ctx, key, key_length, &sa);
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
	crypt_backend_memzero(buffer, sizeof(buffer));
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

void crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	if (ctx->tfmfd >= 0)
		close(ctx->tfmfd);
	if (ctx->opfd >= 0)
		close(ctx->opfd);
	memset(ctx, 0, sizeof(*ctx));
	free(ctx);
}

int crypt_cipher_check(const char *name, const char *mode,
		       const char *integrity, size_t key_length)
{
	struct crypt_cipher *c = NULL;
	char mode_name[64], tmp_salg_name[180], *real_mode = NULL, *cipher_iv = NULL, *key;
	const char *salg_type;
	bool aead;
	int r;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
	};

	aead = integrity && strcmp(integrity, "none");

	/* Remove IV if present */
	if (mode) {
		strncpy(mode_name, mode, sizeof(mode_name));
		mode_name[sizeof(mode_name) - 1] = 0;
		cipher_iv = strchr(mode_name, '-');
		if (cipher_iv) {
			*cipher_iv = '\0';
			real_mode = mode_name;
		}
	}

	salg_type = aead ? "aead" : "skcipher";
	snprintf((char *)sa.salg_type, sizeof(sa.salg_type), "%s", salg_type);
	memset(tmp_salg_name, 0, sizeof(tmp_salg_name));

	/* FIXME: this is duplicating a part of devmapper backend */
	if (aead && !strcmp(integrity, "poly1305"))
		r = snprintf(tmp_salg_name, sizeof(tmp_salg_name), "rfc7539(%s,%s)", name, integrity);
	else if (!real_mode)
		r = snprintf(tmp_salg_name, sizeof(tmp_salg_name), "%s", name);
	else if (aead && !strcmp(real_mode, "ccm"))
		r = snprintf(tmp_salg_name, sizeof(tmp_salg_name), "rfc4309(%s(%s))", real_mode, name);
	else
		r = snprintf(tmp_salg_name, sizeof(tmp_salg_name), "%s(%s)", real_mode, name);

	if (r <= 0 || r > (int)(sizeof(sa.salg_name) - 1))
		return -EINVAL;

	memcpy(sa.salg_name, tmp_salg_name, sizeof(sa.salg_name));

	key = malloc(key_length);
	if (!key)
		return -ENOMEM;

	/* We cannot use RNG yet, any key works here, tweak the first part if it is split key (XTS). */
	memset(key, 0xab, key_length);
	*key = 0xef;

	r = _crypt_cipher_init(&c, key, key_length, &sa);
	if (c)
		crypt_cipher_destroy(c);
	free(key);

	return r;
}

#else /* ENABLE_AF_ALG */
int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *buffer, size_t length)
{
	return -ENOTSUP;
}

void crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	return;
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
int crypt_cipher_check(const char *name, const char *mode,
		       const char *integrity, size_t key_length)
{
	return 0;
}
#endif
