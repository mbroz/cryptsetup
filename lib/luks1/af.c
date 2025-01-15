// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AFsplitter - Anti forensic information splitter
 *
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 *
 * AFsplitter diffuses information over a large stripe of data,
 * therefore supporting secure data destruction.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "internal.h"
#include "af.h"

static void XORblock(const char *src1, const char *src2, char *dst, size_t n)
{
	size_t j;

	for (j = 0; j < n; j++)
		dst[j] = src1[j] ^ src2[j];
}

static int hash_buf(const char *src, char *dst, uint32_t iv,
		    size_t len, const char *hash_name)
{
	struct crypt_hash *hd = NULL;
	char *iv_char = (char *)&iv;
	int r;

	iv = be32_to_cpu(iv);
	if (crypt_hash_init(&hd, hash_name))
		return -EINVAL;

	if ((r = crypt_hash_write(hd, iv_char, sizeof(uint32_t))))
		goto out;

	if ((r = crypt_hash_write(hd, src, len)))
		goto out;

	r = crypt_hash_final(hd, dst, len);
out:
	crypt_hash_destroy(hd);
	return r;
}

/*
 * diffuse: Information spreading over the whole dataset with
 * the help of hash function.
 */
static int diffuse(char *src, char *dst, size_t size, const char *hash_name)
{
	int r, hash_size = crypt_hash_size(hash_name);
	unsigned int digest_size;
	unsigned int i, blocks, padding;

	if (hash_size <= 0)
		return -EINVAL;
	digest_size = hash_size;

	blocks = size / digest_size;
	padding = size % digest_size;

	for (i = 0; i < blocks; i++) {
		r = hash_buf(src + digest_size * i,
			    dst + digest_size * i,
			    i, (size_t)digest_size, hash_name);
		if (r < 0)
			return r;
	}

	if (padding) {
		r = hash_buf(src + digest_size * i,
			    dst + digest_size * i,
			    i, (size_t)padding, hash_name);
		if (r < 0)
			return r;
	}

	return 0;
}

/*
 * Information splitting. The amount of data is multiplied by
 * blocknumbers. The same blocksize and blocknumbers values
 * must be supplied to AF_merge to recover information.
 */
int AF_split(struct crypt_device *ctx, const char *src, char *dst,
	     size_t blocksize, unsigned int blocknumbers, const char *hash)
{
	unsigned int i;
	char *bufblock;
	int r;

	bufblock = crypt_safe_alloc(blocksize);
	if (!bufblock)
		return -ENOMEM;

	/* process everything except the last block */
	for (i = 0; i < blocknumbers - 1; i++) {
		r = crypt_random_get(ctx, dst + blocksize * i, blocksize, CRYPT_RND_NORMAL);
		if (r < 0)
			goto out;

		XORblock(dst + blocksize * i, bufblock, bufblock, blocksize);
		r = diffuse(bufblock, bufblock, blocksize, hash);
		if (r < 0)
			goto out;
	}
	/* the last block is computed */
	XORblock(src, bufblock, dst + blocksize * i, blocksize);
	r = 0;
out:
	crypt_safe_free(bufblock);
	return r;
}

int AF_merge(const char *src, char *dst,
	     size_t blocksize, unsigned int blocknumbers, const char *hash)
{
	unsigned int i;
	char *bufblock;
	int r;

	bufblock = crypt_safe_alloc(blocksize);
	if (!bufblock)
		return -ENOMEM;

	for (i = 0; i < blocknumbers - 1; i++) {
		XORblock(src + blocksize * i, bufblock, bufblock, blocksize);
		r = diffuse(bufblock, bufblock, blocksize, hash);
		if (r < 0)
			goto out;
	}
	XORblock(src + blocksize * i, bufblock, dst, blocksize);
	r = 0;
out:
	crypt_safe_free(bufblock);
	return r;
}

/* Size of final split data including sector alignment */
size_t AF_split_sectors(size_t blocksize, unsigned int blocknumbers)
{
	size_t af_size;

	/* data material * stripes */
	af_size = blocksize * blocknumbers;

	/* round up to sector */
	af_size = (af_size + (SECTOR_SIZE - 1)) / SECTOR_SIZE;

	return af_size;
}
