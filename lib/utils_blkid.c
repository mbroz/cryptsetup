/*
 * blkid probe utilities
 *
 * Copyright (C) 2018-2020 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils_blkid.h"
#include "utils_io.h"

#ifdef HAVE_BLKID
#include <blkid/blkid.h>
/* make bad checksums flag optional */
#ifndef BLKID_SUBLKS_BADCSUM
#define BLKID_SUBLKS_BADCSUM 0
#endif
struct blkid_handle {
	int fd;
	blkid_probe pr;
};
#ifndef HAVE_BLKID_WIPE
static size_t crypt_getpagesize(void)
{
	long r = sysconf(_SC_PAGESIZE);
	return r <= 0 ? 4096 : (size_t)r;
}
#endif
#endif

void blk_set_chains_for_wipes(struct blkid_handle *h)
{
#ifdef HAVE_BLKID
	blkid_probe_enable_partitions(h->pr, 1);
	blkid_probe_set_partitions_flags(h->pr, 0
#ifdef HAVE_BLKID_WIPE
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
#endif
}

void blk_set_chains_for_full_print(struct blkid_handle *h)
{
	blk_set_chains_for_wipes(h);
}

void blk_set_chains_for_fast_detection(struct blkid_handle *h)
{
#ifdef HAVE_BLKID
	blkid_probe_enable_partitions(h->pr, 1);
	blkid_probe_set_partitions_flags(h->pr, 0);

	blkid_probe_enable_superblocks(h->pr, 1);
	blkid_probe_set_superblocks_flags(h->pr, BLKID_SUBLKS_TYPE);
#endif
}

int blk_init_by_path(struct blkid_handle **h, const char *path)
{
	int r = -ENOTSUP;
#ifdef HAVE_BLKID
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

	r = 0;
#endif
	return r;
}

int blk_init_by_fd(struct blkid_handle **h, int fd)
{
	int r = -ENOTSUP;
#ifdef HAVE_BLKID
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

	r = 0;
#endif
	return r;
}

int blk_superblocks_filter_luks(struct blkid_handle *h)
{
	int r = -ENOTSUP;
#ifdef HAVE_BLKID
	char luks[] = "crypto_LUKS";
	char *luks_filter[] = {
		luks,
		NULL
	};
	r = blkid_probe_filter_superblocks_type(h->pr, BLKID_FLTR_NOTIN, luks_filter);
#endif
	return r;
}

blk_probe_status blk_probe(struct blkid_handle *h)
{
	blk_probe_status pr = PRB_FAIL;
#ifdef HAVE_BLKID
	int r = blkid_do_probe(h->pr);

	if (r == 0)
		pr = PRB_OK;
	else if (r == 1)
		pr = PRB_EMPTY;
#endif
	return pr;
}

blk_probe_status blk_safeprobe(struct blkid_handle *h)
{
	int r = -1;
#ifdef HAVE_BLKID
	r = blkid_do_safeprobe(h->pr);
#endif
	switch (r) {
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
	int r = 0;
#ifdef HAVE_BLKID
	r = blkid_probe_has_value(h->pr, "PTTYPE");
#endif
	return r;
}

int blk_is_superblock(struct blkid_handle *h)
{
	int r = 0;
#ifdef HAVE_BLKID
	r = blkid_probe_has_value(h->pr, "TYPE");
#endif
	return r;
}

const char *blk_get_partition_type(struct blkid_handle *h)
{
	const char *value = NULL;
#ifdef HAVE_BLKID
	(void) blkid_probe_lookup_value(h->pr, "PTTYPE", &value, NULL);
#endif
	return value;
}

const char *blk_get_superblock_type(struct blkid_handle *h)
{
	const char *value = NULL;
#ifdef HAVE_BLKID
	(void) blkid_probe_lookup_value(h->pr, "TYPE", &value, NULL);
#endif
	return value;
}

void blk_free(struct blkid_handle *h)
{
#ifdef HAVE_BLKID
	if (!h)
		return;

	if (h->pr)
		blkid_free_probe(h->pr);

	free(h);
#endif
}

#ifdef HAVE_BLKID
#ifndef HAVE_BLKID_WIPE
static int blk_step_back(struct blkid_handle *h)
{
#ifdef HAVE_BLKID_STEP_BACK
	return blkid_probe_step_back(h->pr);
#else
	blkid_reset_probe(h->pr);
	blkid_probe_set_device(h->pr, h->fd, 0, 0);
	return 0;
#endif
}
#endif /* not HAVE_BLKID_WIPE */
#endif /* HAVE_BLKID */

int blk_do_wipe(struct blkid_handle *h)
{
#ifdef HAVE_BLKID
#ifdef HAVE_BLKID_WIPE
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
#else /* HAVE_BLKID */
	return -ENOTSUP;
#endif
}

int blk_supported(void)
{
	int r = 0;
#ifdef HAVE_BLKID
	r = 1;
#endif
	return r;
}

off_t blk_get_offset(struct blkid_handle *h)
{
	off_t offset_value = -1;
#ifdef HAVE_BLKID
	const char *offset;
	if (blk_is_superblock(h)) {
		if (!blkid_probe_lookup_value(h->pr, "SBMAGIC_OFFSET", &offset, NULL))
			offset_value = strtoll(offset, NULL, 10);
	} else if (blk_is_partition(h) && !blkid_probe_lookup_value(h->pr, "PTMAGIC_OFFSET", &offset, NULL))
		offset_value = strtoll(offset, NULL, 10);
#endif
	return offset_value;
}
