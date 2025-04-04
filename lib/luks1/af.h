// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AFsplitter - Anti forensic information splitter
 *
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 */

#ifndef INCLUDED_CRYPTSETUP_LUKS_AF_H
#define INCLUDED_CRYPTSETUP_LUKS_AF_H

#include <stddef.h>

struct crypt_device;
struct volume_key;

/*
 * AF_split operates on src and produces information split data in
 * dst. src is assumed to be of the length blocksize. The data stripe
 * dst points to must be capable of storing blocksize*blocknumbers.
 * blocknumbers is the data multiplication factor.
 *
 * AF_merge does just the opposite: reproduces the information stored in
 * src of the length blocksize*blocknumbers into dst of the length
 * blocksize.
 *
 * On error, both functions return -1, 0 otherwise.
 */

int AF_split(struct crypt_device *ctx, const char *src, char *dst,
	     size_t blocksize, unsigned int blocknumbers, const char *hash);
int AF_merge(const char *src, char *dst, size_t blocksize,
	     unsigned int blocknumbers, const char *hash);
size_t AF_split_sectors(size_t blocksize, unsigned int blocknumbers);

int LUKS_encrypt_to_storage(
	char *src, size_t srcLength,
	const char *cipher,
	const char *cipher_mode,
	struct volume_key *vk,
	unsigned int sector,
	struct crypt_device *ctx);

int LUKS_decrypt_from_storage(
	char *dst, size_t dstLength,
	const char *cipher,
	const char *cipher_mode,
	struct volume_key *vk,
	unsigned int sector,
	struct crypt_device *ctx);

#endif
