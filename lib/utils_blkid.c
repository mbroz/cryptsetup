/*
 * blkid probe utilities
 *
 * Copyright (C) 2018, Red Hat, Inc. All rights reserved.
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

#ifdef HAVE_BLKID
#include <blkid/blkid.h>
struct blkid_handle {
	int fd;
	blkid_probe pr;
};
#endif

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
	struct blkid_handle *tmp = malloc(sizeof(*h));
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

int blk_superblocks_filter_luks(struct blkid_handle *h)
{
	int r = -ENOTSUP;
#ifdef HAVE_BLKID
	char *luks_filter[] = {
		"crypto_LUKS",
		NULL
	};
	r = blkid_probe_filter_superblocks_type(h->pr, BLKID_FLTR_NOTIN, luks_filter);
#endif
	return r;
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

int blk_supported(void)
{
	int r = 0;
#ifdef HAVE_BLKID
	r = 1;
#endif
	return r;
}
