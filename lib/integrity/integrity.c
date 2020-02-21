/*
 * Integrity volume handling
 *
 * Copyright (C) 2016-2020 Milan Broz
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#include "integrity.h"
#include "internal.h"

static int INTEGRITY_read_superblock(struct crypt_device *cd,
				     struct device *device,
				     uint64_t offset, struct superblock *sb)
{
	int devfd, r;

	devfd = device_open(cd, device, O_RDONLY);
	if(devfd < 0)
		return -EINVAL;

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
		device_alignment(device), sb, sizeof(*sb), offset) != sizeof(*sb) ||
	    memcmp(sb->magic, SB_MAGIC, sizeof(sb->magic)) ||
	    sb->version < SB_VERSION_1 || sb->version > SB_VERSION_4) {
		log_std(cd, "No integrity superblock detected on %s.\n",
			device_path(device));
		r = -EINVAL;
	} else {
		sb->integrity_tag_size = le16toh(sb->integrity_tag_size);
		sb->journal_sections = le32toh(sb->journal_sections);
		sb->provided_data_sectors = le64toh(sb->provided_data_sectors);
		sb->recalc_sector = le64toh(sb->recalc_sector);
		sb->flags = le32toh(sb->flags);
		r = 0;
	}

	return r;
}

int INTEGRITY_read_sb(struct crypt_device *cd,
		      struct crypt_params_integrity *params,
		      uint32_t *flags)
{
	struct superblock sb;
	int r;

	r = INTEGRITY_read_superblock(cd, crypt_metadata_device(cd), 0, &sb);
	if (r)
		return r;

	params->sector_size = SECTOR_SIZE << sb.log2_sectors_per_block;
	params->tag_size = sb.integrity_tag_size;

	if (flags)
		*flags = sb.flags;

	return 0;
}

int INTEGRITY_dump(struct crypt_device *cd, struct device *device, uint64_t offset)
{
	struct superblock sb;
	int r;

	r = INTEGRITY_read_superblock(cd, device, offset, &sb);
	if (r)
		return r;

	log_std(cd, "Info for integrity device %s.\n", device_path(device));
	log_std(cd, "superblock_version %d\n", (unsigned)sb.version);
	log_std(cd, "log2_interleave_sectors %d\n", sb.log2_interleave_sectors);
	log_std(cd, "integrity_tag_size %u\n", sb.integrity_tag_size);
	log_std(cd, "journal_sections %u\n", sb.journal_sections);
	log_std(cd, "provided_data_sectors %" PRIu64 "\n", sb.provided_data_sectors);
	log_std(cd, "sector_size %u\n", SECTOR_SIZE << sb.log2_sectors_per_block);
	if (sb.version == SB_VERSION_2 && (sb.flags & SB_FLAG_RECALCULATING))
		log_std(cd, "recalc_sector %" PRIu64 "\n", sb.recalc_sector);
	log_std(cd, "log2_blocks_per_bitmap %u\n", sb.log2_blocks_per_bitmap_bit);
	log_std(cd, "flags %s%s%s%s\n",
		sb.flags & SB_FLAG_HAVE_JOURNAL_MAC ? "have_journal_mac " : "",
		sb.flags & SB_FLAG_RECALCULATING ? "recalculating " : "",
		sb.flags & SB_FLAG_DIRTY_BITMAP ? "dirty_bitmap " : "",
		sb.flags & SB_FLAG_FIXED_PADDING ? "fix_padding " : "");

	return 0;
}

int INTEGRITY_data_sectors(struct crypt_device *cd,
			   struct device *device, uint64_t offset,
			   uint64_t *data_sectors)
{
	struct superblock sb;
	int r;

	r = INTEGRITY_read_superblock(cd, device, offset, &sb);
	if (r)
		return r;

	*data_sectors = sb.provided_data_sectors;
	return 0;
}

int INTEGRITY_key_size(struct crypt_device *cd, const char *integrity)
{
	if (!integrity)
		return 0;

	//FIXME: use crypto backend hash size
	if (!strcmp(integrity, "aead"))
		return 0;
	else if (!strcmp(integrity, "hmac(sha1)"))
		return 20;
	else if (!strcmp(integrity, "hmac(sha256)"))
		return 32;
	else if (!strcmp(integrity, "hmac(sha512)"))
		return 64;
	else if (!strcmp(integrity, "poly1305"))
		return 0;
	else if (!strcmp(integrity, "none"))
		return 0;

	return -EINVAL;
}

/* Return hash or hmac(hash) size, if known */
int INTEGRITY_hash_tag_size(const char *integrity)
{
	char hash[MAX_CIPHER_LEN];
	int r;

	if (!integrity)
		return 0;

	if (!strcmp(integrity, "crc32") || !strcmp(integrity, "crc32c"))
		return 4;

	r = sscanf(integrity, "hmac(%" MAX_CIPHER_LEN_STR "[^)]s", hash);
	if (r == 1)
		r = crypt_hash_size(hash);
	else
		r = crypt_hash_size(integrity);

	return r < 0 ? 0 : r;
}

int INTEGRITY_tag_size(struct crypt_device *cd,
		       const char *integrity,
		       const char *cipher,
		       const char *cipher_mode)
{
	int iv_tag_size = 0, auth_tag_size = 0;

	if (!cipher_mode)
		iv_tag_size = 0;
	else if (!strcmp(cipher_mode, "xts-random"))
		iv_tag_size = 16;
	else if (!strcmp(cipher_mode, "gcm-random"))
		iv_tag_size = 12;
	else if (!strcmp(cipher_mode, "ccm-random"))
		iv_tag_size = 8;
	else if (!strcmp(cipher_mode, "ctr-random"))
		iv_tag_size = 16;
	else if (!strcmp(cipher, "aegis256") && !strcmp(cipher_mode, "random"))
		iv_tag_size = 32;
	else if (!strcmp(cipher_mode, "random"))
		iv_tag_size = 16;

	//FIXME: use crypto backend hash size
	if (!integrity || !strcmp(integrity, "none"))
		auth_tag_size = 0;
	else if (!strcmp(integrity, "aead"))
		auth_tag_size = 16; //FIXME gcm- mode only
	else if (!strcmp(integrity, "cmac(aes)"))
		auth_tag_size = 16;
	else if (!strcmp(integrity, "hmac(sha1)"))
		auth_tag_size = 20;
	else if (!strcmp(integrity, "hmac(sha256)"))
		auth_tag_size = 32;
	else if (!strcmp(integrity, "hmac(sha512)"))
		auth_tag_size = 64;
	else if (!strcmp(integrity, "poly1305")) {
		if (iv_tag_size)
			iv_tag_size = 12;
		auth_tag_size = 16;
	}

	return iv_tag_size + auth_tag_size;
}

int INTEGRITY_create_dmd_device(struct crypt_device *cd,
		       const struct crypt_params_integrity *params,
		       struct volume_key *vk,
		       struct volume_key *journal_crypt_key,
		       struct volume_key *journal_mac_key,
		       struct crypt_dm_active_device *dmd,
		       uint32_t flags, uint32_t sb_flags)
{
	int r;

	if (!dmd)
		return -EINVAL;

	*dmd = (struct crypt_dm_active_device) {
		.flags = flags,
	};

	/* Workaround for kernel dm-integrity table bug */
	if (sb_flags & SB_FLAG_RECALCULATING)
		dmd->flags |= CRYPT_ACTIVATE_RECALCULATE;

	r = INTEGRITY_data_sectors(cd, crypt_metadata_device(cd),
				   crypt_get_data_offset(cd) * SECTOR_SIZE, &dmd->size);
	if (r < 0)
		return r;

	return dm_integrity_target_set(cd, &dmd->segment, 0, dmd->size,
			crypt_metadata_device(cd), crypt_data_device(cd),
			crypt_get_integrity_tag_size(cd), crypt_get_data_offset(cd),
			crypt_get_sector_size(cd), vk, journal_crypt_key,
			journal_mac_key, params);
}

int INTEGRITY_activate_dmd_device(struct crypt_device *cd,
		       const char *name,
		       const char *type,
		       struct crypt_dm_active_device *dmd,
		       uint32_t sb_flags)
{
	int r;
	uint32_t dmi_flags;
	struct dm_target *tgt = &dmd->segment;

	if (!single_segment(dmd) || tgt->type != DM_INTEGRITY)
		return -EINVAL;

	log_dbg(cd, "Trying to activate INTEGRITY device on top of %s, using name %s, tag size %d, provided sectors %" PRIu64".",
		device_path(tgt->data_device), name, tgt->u.integrity.tag_size, dmd->size);

	r = device_block_adjust(cd, tgt->data_device, DEV_EXCL,
				tgt->u.integrity.offset, NULL, &dmd->flags);
	if (r)
		return r;

	if (tgt->u.integrity.meta_device) {
		r = device_block_adjust(cd, tgt->u.integrity.meta_device, DEV_EXCL, 0, NULL, NULL);
		if (r)
			return r;
	}

	r = dm_create_device(cd, name, type, dmd);
	if (r < 0 && (dm_flags(cd, DM_INTEGRITY, &dmi_flags) || !(dmi_flags & DM_INTEGRITY_SUPPORTED))) {
		log_err(cd, _("Kernel does not support dm-integrity mapping."));
		return -ENOTSUP;
	}

	if (r < 0 && (sb_flags & SB_FLAG_FIXED_PADDING) && !dm_flags(cd, DM_INTEGRITY, &dmi_flags) &&
	    !(dmi_flags & DM_INTEGRITY_FIX_PADDING_SUPPORTED)) {
		log_err(cd, _("Kernel does not support dm-integrity fixed metadata alignment."));
		return -ENOTSUP;
	}

	return r;
}

int INTEGRITY_activate(struct crypt_device *cd,
		       const char *name,
		       const struct crypt_params_integrity *params,
		       struct volume_key *vk,
		       struct volume_key *journal_crypt_key,
		       struct volume_key *journal_mac_key,
		       uint32_t flags, uint32_t sb_flags)
{
	struct crypt_dm_active_device dmd = {};
	int r = INTEGRITY_create_dmd_device(cd, params, vk, journal_crypt_key,
					    journal_mac_key, &dmd, flags, sb_flags);

	if (r < 0)
		return r;

	r = INTEGRITY_activate_dmd_device(cd, name, CRYPT_INTEGRITY, &dmd, sb_flags);
	dm_targets_free(cd, &dmd);
	return r;
}

int INTEGRITY_format(struct crypt_device *cd,
		     const struct crypt_params_integrity *params,
		     struct volume_key *journal_crypt_key,
		     struct volume_key *journal_mac_key)
{
	uint32_t dmi_flags;
	char tmp_name[64], tmp_uuid[40];
	struct crypt_dm_active_device dmdi = {
		.size = 8,
		.flags = CRYPT_ACTIVATE_PRIVATE, /* We always create journal but it can be unused later */
	};
	struct dm_target *tgt = &dmdi.segment;
	int r;
	uuid_t tmp_uuid_bin;
	struct volume_key *vk = NULL;

	uuid_generate(tmp_uuid_bin);
	uuid_unparse(tmp_uuid_bin, tmp_uuid);

	snprintf(tmp_name, sizeof(tmp_name), "temporary-cryptsetup-%s", tmp_uuid);

	/* There is no data area, we can actually use fake zeroed key */
	if (params && params->integrity_key_size)
		vk = crypt_alloc_volume_key(params->integrity_key_size, NULL);

	r = dm_integrity_target_set(cd, tgt, 0, dmdi.size, crypt_metadata_device(cd),
			crypt_data_device(cd), crypt_get_integrity_tag_size(cd),
			crypt_get_data_offset(cd), crypt_get_sector_size(cd), vk,
			journal_crypt_key, journal_mac_key, params);
	if (r < 0) {
		crypt_free_volume_key(vk);
		return r;
	}

	log_dbg(cd, "Trying to format INTEGRITY device on top of %s, tmp name %s, tag size %d.",
		device_path(tgt->data_device), tmp_name, tgt->u.integrity.tag_size);

	r = device_block_adjust(cd, tgt->data_device, DEV_EXCL, tgt->u.integrity.offset, NULL, NULL);
	if (r < 0 && (dm_flags(cd, DM_INTEGRITY, &dmi_flags) || !(dmi_flags & DM_INTEGRITY_SUPPORTED))) {
		log_err(cd, _("Kernel does not support dm-integrity mapping."));
		r = -ENOTSUP;
	}
	if (r) {
		dm_targets_free(cd, &dmdi);
		return r;
	}

	if (tgt->u.integrity.meta_device) {
		r = device_block_adjust(cd, tgt->u.integrity.meta_device, DEV_EXCL, 0, NULL, NULL);
		if (r) {
			dm_targets_free(cd, &dmdi);
			return r;
		}
	}

	r = dm_create_device(cd, tmp_name, CRYPT_INTEGRITY, &dmdi);
	crypt_free_volume_key(vk);
	dm_targets_free(cd, &dmdi);
	if (r)
		return r;

	return dm_remove_device(cd, tmp_name, CRYPT_DEACTIVATE_FORCE);
}
