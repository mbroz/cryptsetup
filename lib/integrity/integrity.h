// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Integrity header definition
 *
 * Copyright (C) 2016-2025 Milan Broz
 */

#ifndef _CRYPTSETUP_INTEGRITY_H
#define _CRYPTSETUP_INTEGRITY_H

#include <stdint.h>
#include <stdbool.h>

struct crypt_device;
struct device;
struct crypt_params_integrity;
struct volume_key;
struct crypt_dm_active_device;

/* dm-integrity helper */
#define SB_MAGIC	"integrt"
#define SB_VERSION_1	1
#define SB_VERSION_2	2
#define SB_VERSION_3	3
#define SB_VERSION_4	4
#define SB_VERSION_5	5
#define SB_VERSION_6	6

#define SB_FLAG_HAVE_JOURNAL_MAC	(1 << 0)
#define SB_FLAG_RECALCULATING		(1 << 1) /* V2 only */
#define SB_FLAG_DIRTY_BITMAP		(1 << 2) /* V3 only */
#define SB_FLAG_FIXED_PADDING		(1 << 3) /* V4 only */
#define SB_FLAG_FIXED_HMAC		(1 << 4) /* V5 only */
#define SB_FLAG_INLINE			(1 << 5) /* V6 only */

struct superblock {
	uint8_t magic[8];
	uint8_t version;
	int8_t log2_interleave_sectors;
	uint16_t integrity_tag_size;
	uint32_t journal_sections;
	uint64_t provided_data_sectors;
	uint32_t flags;
	uint8_t log2_sectors_per_block;
	uint8_t log2_blocks_per_bitmap_bit; /* V3 only */
	uint8_t pad[2]; /* (padding) */
	uint64_t recalc_sector; /* V2 only */
	uint8_t pad2[8]; /* (padding) */
	uint8_t salt[16]; /* for fixed hmac, V5 only */
} __attribute__ ((packed));

int INTEGRITY_read_sb(struct crypt_device *cd,
		      struct crypt_params_integrity *params,
		      uint32_t *flags);

int INTEGRITY_dump(struct crypt_device *cd, struct device *device, uint64_t offset);

int INTEGRITY_data_sectors(struct crypt_device *cd,
			   struct device *device, uint64_t offset,
			   uint64_t *data_sectors);
int INTEGRITY_key_size(const char *integrity, int required_key_size);
int INTEGRITY_tag_size(const char *integrity,
		       const char *cipher,
		       const char *cipher_mode);
int INTEGRITY_hash_tag_size(const char *integrity);

int INTEGRITY_format(struct crypt_device *cd,
		     const struct crypt_params_integrity *params,
		     struct volume_key *integrity_key,
		     struct volume_key *journal_crypt_key,
		     struct volume_key *journal_mac_key,
		     uint64_t backing_device_sectors,
		     uint32_t *sb_flags,
		     bool integrity_inline);

int INTEGRITY_activate(struct crypt_device *cd,
		       const char *name,
		       const struct crypt_params_integrity *params,
		       struct volume_key *vk,
		       struct volume_key *journal_crypt_key,
		       struct volume_key *journal_mac_key,
		       uint32_t flags, uint32_t sb_flags);

int INTEGRITY_create_dmd_device(struct crypt_device *cd,
		       const struct crypt_params_integrity *params,
		       struct volume_key *vk,
		       struct volume_key *journal_crypt_key,
		       struct volume_key *journal_mac_key,
		       struct crypt_dm_active_device *dmd,
		       uint32_t flags, uint32_t sb_flags);

int INTEGRITY_activate_dmd_device(struct crypt_device *cd,
		       const char *name,
		       const char *type,
		       struct crypt_dm_active_device *dmd,
		       uint32_t sb_flags);
#endif
