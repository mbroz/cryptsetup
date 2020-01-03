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

#ifndef _UTILS_BLKID_H
#define _UTILS_BLKID_H

struct blkid_handle;

typedef enum { PRB_OK = 0, PRB_EMPTY, PRB_AMBIGUOUS, PRB_FAIL } blk_probe_status;

int blk_init_by_path(struct blkid_handle **h, const char *path);

void blk_free(struct blkid_handle *h);

/*
 * WARNING: This will reset file description offset as if
 * 	    lseek(devfd, 0, SEEK_SET) was called!
 */
int blk_init_by_fd(struct blkid_handle **h, int fd);

void blk_set_chains_for_wipes(struct blkid_handle *h);

void blk_set_chains_for_full_print(struct blkid_handle *h);

void blk_set_chains_for_fast_detection(struct blkid_handle *h);

int blk_superblocks_filter_luks(struct blkid_handle *h);

blk_probe_status blk_safeprobe(struct blkid_handle *h);

blk_probe_status blk_probe(struct blkid_handle *h);

int blk_is_partition(struct blkid_handle *h);

int blk_is_superblock(struct blkid_handle *h);

const char *blk_get_partition_type(struct blkid_handle *h);

const char *blk_get_superblock_type(struct blkid_handle *h);

int blk_do_wipe(struct blkid_handle *h);

int blk_supported(void);

off_t blk_get_offset(struct blkid_handle *h);

#endif
