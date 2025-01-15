// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * blkid probe utilities
 *
 * Copyright (C) 2018-2025 Red Hat, Inc. All rights reserved.
 */

#ifndef _UTILS_BLKID_H
#define _UTILS_BLKID_H

#include <sys/types.h>

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

void blk_set_chains_for_superblocks(struct blkid_handle *h);

void blk_set_chains_for_fast_detection(struct blkid_handle *h);

int blk_superblocks_filter_luks(struct blkid_handle *h);
int blk_superblocks_only_luks(struct blkid_handle *h);

blk_probe_status blk_safeprobe(struct blkid_handle *h);

blk_probe_status blk_probe(struct blkid_handle *h);

int blk_is_partition(struct blkid_handle *h);

int blk_is_superblock(struct blkid_handle *h);

const char *blk_get_partition_type(struct blkid_handle *h);

const char *blk_get_superblock_type(struct blkid_handle *h);

int blk_do_wipe(struct blkid_handle *h);

int blk_supported(void);

unsigned blk_get_block_size(struct blkid_handle *h);

#endif
