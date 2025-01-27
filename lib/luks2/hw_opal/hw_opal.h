// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * OPAL utilities
 *
 * Copyright (C) 2022-2023 Luca Boccassi <bluca@debian.org>
 * Copyright (C) 2023-2025 Ondrej Kozina <okozina@redhat.com>
 * Copyright (C) 2024-2025 Milan Broz
 */

#ifndef _UTILS_OPAL
#define _UTILS_OPAL

#include "internal.h"

struct crypt_lock_handle;

int opal_setup_ranges(struct crypt_device *cd,
		      struct device *dev,
		      const struct volume_key *vk,
		      uint64_t range_start_blocks,
		      uint64_t range_length_blocks,
		      uint32_t opal_block_bytes,
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
int opal_range_check_attributes_and_get_lock_state(struct crypt_device *cd,
				struct device *dev,
				uint32_t segment_number,
				const struct volume_key *vk,
				const uint64_t *check_offset_sectors,
				const uint64_t *check_length_sectors,
				bool *ret_read_locked,
				bool *ret_write_locked);
int opal_exclusive_lock(struct crypt_device *cd,
			struct device *opal_device,
			struct crypt_lock_handle **opal_lock);
void opal_exclusive_unlock(struct crypt_device *cd, struct crypt_lock_handle *opal_lock);

#endif
