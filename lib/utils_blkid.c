// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * blkid probe utilities
 *
 * Copyright (C) 2018-2025 Red Hat, Inc. All rights reserved.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils_blkid.h"
#include "utils_io.h"

#if HAVE_BLKID

#include <blkid/blkid.h>
/* make bad checksums flag optional */
#ifndef BLKID_SUBLKS_BADCSUM
#define BLKID_SUBLKS_BADCSUM 0
#endif
struct blkid_handle {
	int fd;
	blkid_probe pr;
};
#if !HAVE_BLKID_WIPE
static size_t crypt_getpagesize(void)
{
	long r = sysconf(_SC_PAGESIZE);
	return r <= 0 ? 4096 : (size_t)r;
}
#endif

void blk_set_chains_for_wipes(struct blkid_handle *h)
{
	blkid_probe_enable_partitions(h->pr, 1);
	blkid_probe_set_partitions_flags(h->pr, 0
#if HAVE_BLKID_WIPE
	| BLKID_PARTS_MAGIC
#endif
	);

	blkid_probe_enable_superblocks(h->pr, 1);
	blkid_probe_set_superblocks_flags(h->pr, BLKID_SUBLKS_LABEL   |
						 BLKID_SUBLKS_UUID    |
						 BLKID_SUBLKS_TYPE    |
						 BLKID_SUBLKS_USAGE   |
						 BLKID_SUBLKS_VERSION |
						 BLKID_SUBLKS_MAGIC   |
						 BLKID_SUBLKS_BADCSUM);
}

void blk_set_chains_for_full_print(struct blkid_handle *h)
{
	blk_set_chains_for_wipes(h);
}

void blk_set_chains_for_superblocks(struct blkid_handle *h)
{
	blkid_probe_enable_superblocks(h->pr, 1);
	blkid_probe_set_superblocks_flags(h->pr, BLKID_SUBLKS_TYPE);
}

void blk_set_chains_for_fast_detection(struct blkid_handle *h)
{
	blkid_probe_enable_partitions(h->pr, 1);
	blkid_probe_set_partitions_flags(h->pr, 0);
	blk_set_chains_for_superblocks(h);
}

int blk_init_by_path(struct blkid_handle **h, const char *path)
{
	struct blkid_handle *tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	tmp->fd = -1;

	tmp->pr = blkid_new_probe_from_filename(path);
	if (!tmp->pr) {
		free(tmp);
		return -EINVAL;
	}

	*h = tmp;
	return 0;
}

int blk_init_by_fd(struct blkid_handle **h, int fd)
{
	struct blkid_handle *tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	tmp->pr = blkid_new_probe();
	if (!tmp->pr) {
		free(tmp);
		return -EINVAL;
	}

	if (blkid_probe_set_device(tmp->pr, fd, 0, 0)) {
		blkid_free_probe(tmp->pr);
		free(tmp);
		return -EINVAL;
	}

	tmp->fd = fd;

	*h = tmp;
	return 0;
}

static int blk_superblocks_luks(struct blkid_handle *h, bool enable)
{
	char luks[] = "crypto_LUKS";
	char *luks_filter[] = {
		luks,
		NULL
	};
	return blkid_probe_filter_superblocks_type(h->pr,
			enable ? BLKID_FLTR_ONLYIN : BLKID_FLTR_NOTIN,
			luks_filter);
}

int blk_superblocks_filter_luks(struct blkid_handle *h)
{
	return blk_superblocks_luks(h, false);
}

int blk_superblocks_only_luks(struct blkid_handle *h)
{
	return blk_superblocks_luks(h, true);
}

blk_probe_status blk_probe(struct blkid_handle *h)
{
	blk_probe_status pr = PRB_FAIL;

	int r = blkid_do_probe(h->pr);

	if (r == 0)
		pr = PRB_OK;
	else if (r == 1)
		pr = PRB_EMPTY;

	return pr;
}

blk_probe_status blk_safeprobe(struct blkid_handle *h)
{
	switch (blkid_do_safeprobe(h->pr)) {
	case -2:
		return PRB_AMBIGUOUS;
	case 1:
		return PRB_EMPTY;
	case 0:
		return PRB_OK;
	default:
		return PRB_FAIL;
	}
}

int blk_is_partition(struct blkid_handle *h)
{
	return blkid_probe_has_value(h->pr, "PTTYPE");
}

int blk_is_superblock(struct blkid_handle *h)
{
	return blkid_probe_has_value(h->pr, "TYPE");
}

const char *blk_get_partition_type(struct blkid_handle *h)
{
	const char *value = NULL;
	(void) blkid_probe_lookup_value(h->pr, "PTTYPE", &value, NULL);
	return value;
}

const char *blk_get_superblock_type(struct blkid_handle *h)
{
	const char *value = NULL;
	(void) blkid_probe_lookup_value(h->pr, "TYPE", &value, NULL);
	return value;
}

void blk_free(struct blkid_handle *h)
{
	if (!h)
		return;

	if (h->pr)
		blkid_free_probe(h->pr);

	free(h);
}

#if !HAVE_BLKID_WIPE
static int blk_step_back(struct blkid_handle *h)
{
#if HAVE_BLKID_STEP_BACK
	return blkid_probe_step_back(h->pr);
#else
	blkid_reset_probe(h->pr);
	blkid_probe_set_device(h->pr, h->fd, 0, 0);
	return 0;
#endif
}
#endif /* not HAVE_BLKID_WIPE */

int blk_do_wipe(struct blkid_handle *h)
{
#if HAVE_BLKID_WIPE
	return blkid_do_wipe(h->pr, 0);
#else
	const char *offset;
	off_t offset_val;
	void *buf;
	ssize_t ret;
	size_t alignment, len, bsize = blkid_probe_get_sectorsize(h->pr);

	if (h->fd < 0 || !bsize)
		return -EINVAL;

	if (blk_is_partition(h)) {
		if (blkid_probe_lookup_value(h->pr, "PTMAGIC_OFFSET", &offset, NULL))
			return -EINVAL;
		if (blkid_probe_lookup_value(h->pr, "PTMAGIC", NULL, &len))
			return -EINVAL;
	} else if (blk_is_superblock(h)) {
		if (blkid_probe_lookup_value(h->pr, "SBMAGIC_OFFSET", &offset, NULL))
			return -EINVAL;
		if (blkid_probe_lookup_value(h->pr, "SBMAGIC", NULL, &len))
			return -EINVAL;
	} else
		return 0;

	alignment = crypt_getpagesize();

	if (posix_memalign(&buf, alignment, len))
		return -EINVAL;
	memset(buf, 0, len);

	offset_val = strtoll(offset, NULL, 10);

	/* TODO: missing crypt_wipe_fd() */
	ret = write_lseek_blockwise(h->fd, bsize, alignment, buf, len, offset_val);
	free(buf);
	if (ret < 0)
		return -EIO;

	if ((size_t)ret == len) {
		blk_step_back(h);
		return 0;
	}

	return -EIO;
#endif
}

int blk_supported(void)
{
	return 1;
}

unsigned blk_get_block_size(struct blkid_handle *h)
{
	unsigned block_size = 0;
	const char *data;
	if (!blk_is_superblock(h) || !blkid_probe_has_value(h->pr, "BLOCK_SIZE") ||
	    blkid_probe_lookup_value(h->pr, "BLOCK_SIZE", &data, NULL) ||
	    sscanf(data, "%u", &block_size) != 1)
		block_size = 0;

	return block_size;
}

#else /* HAVE_BLKID */
#pragma GCC diagnostic ignored "-Wunused-parameter"

void blk_set_chains_for_wipes(struct blkid_handle *h)
{
}

void blk_set_chains_for_full_print(struct blkid_handle *h)
{
}

void blk_set_chains_for_superblocks(struct blkid_handle *h)
{
}

void blk_set_chains_for_fast_detection(struct blkid_handle *h)
{
}

int blk_init_by_path(struct blkid_handle **h, const char *path)
{
	return -ENOTSUP;
}

int blk_init_by_fd(struct blkid_handle **h, int fd)
{
	return -ENOTSUP;
}

int blk_superblocks_filter_luks(struct blkid_handle *h)
{
	return -ENOTSUP;
}

int blk_superblocks_only_luks(struct blkid_handle *h)
{
	return -ENOTSUP;
}

blk_probe_status blk_probe(struct blkid_handle *h)
{
	return PRB_FAIL;
}

blk_probe_status blk_safeprobe(struct blkid_handle *h)
{
	return PRB_FAIL;
}

int blk_is_partition(struct blkid_handle *h)
{
	return 0;
}

int blk_is_superblock(struct blkid_handle *h)
{
	return 0;
}

const char *blk_get_partition_type(struct blkid_handle *h)
{
	return NULL;
}

const char *blk_get_superblock_type(struct blkid_handle *h)
{
	return NULL;
}

void blk_free(struct blkid_handle *h)
{
}

int blk_do_wipe(struct blkid_handle *h)
{
	return -ENOTSUP;
}

int blk_supported(void)
{
	return 0;
}

unsigned blk_get_block_size(struct blkid_handle *h)
{
	return 0;
}
#endif
