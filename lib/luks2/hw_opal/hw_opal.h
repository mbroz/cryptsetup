/*
 * OPAL utilities
 *
 * Copyright (C) 2022-2023 Luca Boccassi <bluca@debian.org>
 *               2023 Ondrej Kozina <okozina@redhat.com>
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

#ifndef _UTILS_OPAL
#define _UTILS_OPAL

#include "internal.h"

int opal_setup_ranges(struct crypt_device *cd,
		      struct device *dev,
		      const struct volume_key *vk,
		      uint64_t range_start,
		      uint64_t range_length,
		      uint32_t segment_number,
		      const void *admin_key,
		      size_t admin_key_len);
int opal_lock(struct crypt_device *cd, struct device *dev, uint32_t segment_number);
int opal_unlock(struct crypt_device *cd,
		struct device *dev,
		uint32_t segment_number,
		const struct volume_key *vk);
int opal_supported(struct crypt_device *cd, struct device *dev);
int opal_factory_reset(struct crypt_device *cd,
		       struct device *dev,
		       const char *password,
		       size_t password_len);
int opal_reset_segment(struct crypt_device *cd,
		       struct device *dev,
		       uint32_t segment_number,
		       const char *password,
		       size_t password_len);
int opal_geometry(struct crypt_device *cd,
		  struct device *dev,
		  bool *ret_align,
		  uint32_t *ret_block_size,
		  uint64_t *ret_alignment_granularity_blocks,
		  uint64_t *ret_lowest_lba_blocks);
int opal_range_check_attributes(struct crypt_device *cd,
				struct device *dev,
				uint32_t segment_number,
				const struct volume_key *vk,
				const uint64_t *check_offset_sectors,
				const uint64_t *check_length_sectors,
				bool *check_read_locked,
				bool *check_write_locked);

#endif
