// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Integrity volume handling
 *
 * Copyright (C) 2016-2025 Milan Broz
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#include "integrity.h"
#include "internal.h"

/* For LUKS2, integrity metadata are on DATA device even for detached header! */
static struct device *INTEGRITY_metadata_device(struct crypt_device *cd)
{
	const char *type = crypt_get_type(cd);

	if (type && !strcmp(type, CRYPT_LUKS2))
		return crypt_data_device(cd);

	return crypt_metadata_device(cd);
}

static int INTEGRITY_read_superblock(struct crypt_device *cd,
				     struct device *device,
				     uint64_t offset, struct superblock *sb)
{
	int devfd, r;

	log_dbg(cd, "Reading kernel dm-integrity metadata on %s.", device_path(device));

	devfd = device_open(cd, device, O_RDONLY);
	if(devfd < 0)
		return -EINVAL;

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
	    device_alignment(device), sb, sizeof(*sb), offset) != sizeof(*sb)) {
		log_dbg(cd, "Cannot read kernel dm-integrity metadata on %s.", device_path(device));
		return -EINVAL;
	}

	if (memcmp(sb->magic, SB_MAGIC, sizeof(sb->magic))) {
		log_dbg(cd, "No kernel dm-integrity metadata detected on %s.", device_path(device));
		r = -EINVAL;
	} else if (sb->version < SB_VERSION_1 || sb->version > SB_VERSION_6) {
		log_err(cd, _("Incompatible kernel dm-integrity metadata (version %u) detected on %s."),
			sb->version, device_path(device));
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

	r = INTEGRITY_read_superblock(cd, INTEGRITY_metadata_device(cd), 0, &sb);
	if (r)
		return r;

	if (params) {
		params->sector_size = SECTOR_SIZE << sb.log2_sectors_per_block;
		params->tag_size = sb.integrity_tag_size;
	}

	if (flags)
		*flags = sb.flags;

	return 0;
}

int INTEGRITY_dump(struct crypt_device *cd, struct device *device, uint64_t offset)
{
	struct superblock sb;
	uint64_t sector_size;
	int r;

	r = INTEGRITY_read_superblock(cd, device, offset, &sb);
	if (r)
		return r;

	sector_size = (uint64_t)SECTOR_SIZE << sb.log2_sectors_per_block;
	log_std(cd, "INTEGRITY header information for %s.\n", device_path(device));
	log_std(cd, "version: %d\n", (unsigned)sb.version);
	log_std(cd, "tag size: %u [bytes]\n", sb.integrity_tag_size);
	log_std(cd, "sector size: %" PRIu64 " [bytes]\n", sector_size);
	log_std(cd, "data size: %" PRIu64 " [512-byte units] (%" PRIu64 " [bytes])\n",
		sb.provided_data_sectors, sb.provided_data_sectors * SECTOR_SIZE);
	if (sb.version >= SB_VERSION_2 && (sb.flags & SB_FLAG_RECALCULATING))
		log_std(cd, "recalculate sector: %" PRIu64 "\n", sb.recalc_sector);
	log_std(cd, "journal sections: %u\n", sb.journal_sections);
	log_std(cd, "log2 interleave sectors: %d\n", sb.log2_interleave_sectors);
	log_std(cd, "log2 blocks per bitmap: %u\n", sb.log2_blocks_per_bitmap_bit);
	log_std(cd, "flags: %s%s%s%s%s%s\n",
		sb.flags & SB_FLAG_HAVE_JOURNAL_MAC ? "have_journal_mac " : "",
		sb.flags & SB_FLAG_RECALCULATING ? "recalculating " : "",
		sb.flags & SB_FLAG_DIRTY_BITMAP ? "dirty_bitmap " : "",
		sb.flags & SB_FLAG_FIXED_PADDING ? "fix_padding " : "",
		sb.flags & SB_FLAG_FIXED_HMAC ? "fix_hmac " : "",
		sb.flags & SB_FLAG_INLINE ? "inline " : "");

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

int INTEGRITY_key_size(const char *integrity, int required_key_size)
{
	int ks = 0;

	if (!integrity && required_key_size)
		return -EINVAL;

	if (!integrity)
		return 0;

	//FIXME: use crypto backend hash size
	if (!strcmp(integrity, "aead"))
		ks = 0;
	else if (!strcmp(integrity, "hmac(sha1)"))
		ks = required_key_size ?: 20;
	else if (!strcmp(integrity, "hmac(sha256)"))
		ks = required_key_size ?: 32;
	else if (!strcmp(integrity, "hmac(sha512)"))
		ks = required_key_size ?: 64;
	else if (!strcmp(integrity, "poly1305"))
		ks = 0;
	else if (!strcmp(integrity, "none"))
		ks = 0;
	else
		return -EINVAL;

	if (required_key_size && ks != required_key_size)
		return -EINVAL;

	return ks;
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

	if (!strcmp(integrity, "xxhash64"))
		return 8;

	r = sscanf(integrity, "hmac(%" MAX_CIPHER_LEN_STR "[^)]s", hash);
	if (r == 1)
		r = crypt_hash_size(hash);
	else
		r = crypt_hash_size(integrity);

	return r < 0 ? 0 : r;
}

int INTEGRITY_tag_size(const char *integrity,
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
		auth_tag_size = 16; /* gcm- mode only */
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

	if (sb_flags & SB_FLAG_INLINE)
		dmd->flags |= (CRYPT_ACTIVATE_NO_JOURNAL | CRYPT_ACTIVATE_INLINE_MODE);

	r = INTEGRITY_data_sectors(cd, INTEGRITY_metadata_device(cd),
				   crypt_get_data_offset(cd) * SECTOR_SIZE, &dmd->size);
	if (r < 0)
		return r;

	return dm_integrity_target_set(cd, &dmd->segment, 0, dmd->size,
			INTEGRITY_metadata_device(cd), crypt_data_device(cd),
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
	uint64_t dmi_flags;
	struct dm_target *tgt = &dmd->segment;

	if (!single_segment(dmd) || tgt->type != DM_INTEGRITY)
		return -EINVAL;

	log_dbg(cd, "Trying to activate INTEGRITY device on top of %s, using name %s, tag size %d%s, provided sectors %" PRIu64".",
		device_path(tgt->data_device), name, tgt->u.integrity.tag_size,
		(sb_flags & SB_FLAG_INLINE) ? " (inline)" :"", dmd->size);

	r = create_or_reload_device(cd, name, type, dmd);

	if (r < 0 && (dm_flags(cd, DM_INTEGRITY, &dmi_flags) || !(dmi_flags & DM_INTEGRITY_SUPPORTED))) {
		log_err(cd, _("Kernel does not support dm-integrity mapping."));
		return -ENOTSUP;
	}

	if (r < 0 && (sb_flags & SB_FLAG_FIXED_PADDING) && !dm_flags(cd, DM_INTEGRITY, &dmi_flags) &&
	    !(dmi_flags & DM_INTEGRITY_FIX_PADDING_SUPPORTED)) {
		log_err(cd, _("Kernel does not support dm-integrity fixed metadata alignment."));
		return -ENOTSUP;
	}

	if (r < 0 && (dmd->flags & CRYPT_ACTIVATE_RECALCULATE) &&
	    !(crypt_get_compatibility(cd) & CRYPT_COMPAT_LEGACY_INTEGRITY_RECALC) &&
	    ((sb_flags & SB_FLAG_FIXED_HMAC) ?
	    (tgt->u.integrity.vk && !tgt->u.integrity.journal_integrity_key) :
	    (tgt->u.integrity.vk || tgt->u.integrity.journal_integrity_key))) {
		log_err(cd, _("Kernel refuses to activate insecure recalculate option (see legacy activation options to override)."));
		return -ENOTSUP;
	}

	if (r < 0 && (sb_flags & SB_FLAG_INLINE) && !dm_flags(cd, DM_INTEGRITY, &dmi_flags) &&
	    !(dmi_flags & DM_INTEGRITY_INLINE_MODE_SUPPORTED)) {
		log_err(cd, _("Kernel does not support dm-integrity inline mode."));
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
	struct crypt_dm_active_device dmdq = {}, dmd = {};
	int r;

	if (flags & CRYPT_ACTIVATE_REFRESH) {
		r = dm_query_device(cd, name, DM_ACTIVE_CRYPT_KEYSIZE |
					      DM_ACTIVE_CRYPT_KEY |
					      DM_ACTIVE_INTEGRITY_PARAMS |
					      DM_ACTIVE_JOURNAL_CRYPT_KEY |
					      DM_ACTIVE_JOURNAL_MAC_KEY, &dmdq);
		if (r < 0)
			return r;

		r = INTEGRITY_create_dmd_device(cd, params, vk ?: dmdq.segment.u.integrity.vk,
						journal_crypt_key ?: dmdq.segment.u.integrity.journal_crypt_key,
						journal_mac_key ?: dmdq.segment.u.integrity.journal_integrity_key,
						&dmd, flags, sb_flags);

		if (!r)
			dmd.size = dmdq.size;
	} else
		r = INTEGRITY_create_dmd_device(cd, params, vk, journal_crypt_key,
						journal_mac_key, &dmd, flags, sb_flags);

	if (!r)
		r = INTEGRITY_activate_dmd_device(cd, name, CRYPT_INTEGRITY, &dmd, sb_flags);

	dm_targets_free(cd, &dmdq);
	dm_targets_free(cd, &dmd);
	return r;
}

static int _create_reduced_device(struct crypt_device *cd,
				  const char *name,
				  uint64_t device_size_sectors,
				  struct device **ret_device)
{
	int r;
	char path[PATH_MAX];
	struct device *dev;

	struct crypt_dm_active_device dmd = {
		.size = device_size_sectors,
		.flags = CRYPT_ACTIVATE_PRIVATE,
	};

	assert(cd);
	assert(name);
	assert(device_size_sectors);
	assert(ret_device);

	r = snprintf(path, sizeof(path), "%s/%s", dm_get_dir(), name);
	if (r < 0 || (size_t)r >= sizeof(path))
		return -EINVAL;

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				crypt_get_data_offset(cd), &device_size_sectors, &dmd.flags);
	if (r)
		return r;

	log_dbg(cd, "Activating reduced helper device %s.", name);

	r = dm_linear_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd), crypt_get_data_offset(cd));
	if (!r)
		r = dm_create_device(cd, name, CRYPT_SUBDEV, &dmd);
	dm_targets_free(cd, &dmd);
	if (r < 0)
		return r;

	r = device_alloc(cd, &dev, path);
	if (!r) {
		*ret_device = dev;
		return 0;
	}

	dm_remove_device(cd, name, CRYPT_DEACTIVATE_FORCE);

	return r;
}

int INTEGRITY_format(struct crypt_device *cd,
		     const struct crypt_params_integrity *params,
		     struct volume_key *integrity_key,
		     struct volume_key *journal_crypt_key,
		     struct volume_key *journal_mac_key,
		     uint64_t backing_device_sectors,
		     uint32_t *sb_flags,
		     bool integrity_inline)
{
	uint64_t dmi_flags;
	char reduced_device_name[70], tmp_name[64], tmp_uuid[40];
	struct crypt_dm_active_device dmdi = {
		.size = 8,
		.flags = CRYPT_ACTIVATE_PRIVATE, /* We always create journal but it can be unused later */
	};
	struct dm_target *tgt = &dmdi.segment;
	int r;
	uuid_t tmp_uuid_bin;
	uint64_t data_offset_sectors;
	struct device *p_metadata_device, *p_data_device, *reduced_device = NULL;

	uuid_generate(tmp_uuid_bin);
	uuid_unparse(tmp_uuid_bin, tmp_uuid);

	r = snprintf(tmp_name, sizeof(tmp_name), "temporary-cryptsetup-%s", tmp_uuid);
	if (r < 0 || (size_t)r >= sizeof(tmp_name))
		return -EINVAL;

	p_metadata_device = INTEGRITY_metadata_device(cd);

	if (backing_device_sectors) {
		r = snprintf(reduced_device_name, sizeof(reduced_device_name),
			     "temporary-cryptsetup-reduced-%s", tmp_uuid);
		if (r < 0 || (size_t)r >= sizeof(reduced_device_name))
			return -EINVAL;

		/*
		 * Creates reduced dm-linear mapping over data device starting at
		 * crypt_data_offset(cd) and backing_device_sectors in size.
		 */
		r = _create_reduced_device(cd, reduced_device_name,
					   backing_device_sectors, &reduced_device);
		if (r < 0)
			return r;

		data_offset_sectors = 0;
		p_data_device = reduced_device;
		if (p_metadata_device == crypt_data_device(cd))
			p_metadata_device = reduced_device;
	} else {
		data_offset_sectors = crypt_get_data_offset(cd);
		p_data_device = crypt_data_device(cd);
	}

	if (integrity_inline)
		dmdi.flags |= (CRYPT_ACTIVATE_NO_JOURNAL | CRYPT_ACTIVATE_INLINE_MODE);

	r = dm_integrity_target_set(cd, tgt, 0, dmdi.size, p_metadata_device,
			p_data_device, crypt_get_integrity_tag_size(cd),
			data_offset_sectors, crypt_get_sector_size(cd), integrity_key,
			journal_crypt_key, journal_mac_key, params);
	if (r < 0)
		goto err;

	log_dbg(cd, "Trying to format INTEGRITY device on top of %s, tmp name %s, tag size %d%s.",
		device_path(tgt->data_device), tmp_name, tgt->u.integrity.tag_size, integrity_inline ? " (inline)" : "");

	r = device_block_adjust(cd, tgt->data_device, DEV_EXCL, tgt->u.integrity.offset, NULL, NULL);
	if (r < 0 && (dm_flags(cd, DM_INTEGRITY, &dmi_flags) || !(dmi_flags & DM_INTEGRITY_SUPPORTED))) {
		log_err(cd, _("Kernel does not support dm-integrity mapping."));
		r = -ENOTSUP;
	}
	if (r)
		goto err;

	if (tgt->u.integrity.meta_device) {
		r = device_block_adjust(cd, tgt->u.integrity.meta_device, DEV_EXCL, 0, NULL, NULL);
		if (r)
			goto err;
	}

	r = dm_create_device(cd, tmp_name, CRYPT_INTEGRITY, &dmdi);
	if (r)
		goto err;

	r = dm_remove_device(cd, tmp_name, CRYPT_DEACTIVATE_FORCE);
	if (r)
		goto err;

	/* reload sb_flags from superblock (important for SB_FLAG_INLINE) */
	if (sb_flags)
		r = INTEGRITY_read_sb(cd, NULL, sb_flags);
err:
	dm_targets_free(cd, &dmdi);
	if (reduced_device) {
		dm_remove_device(cd, reduced_device_name, CRYPT_DEACTIVATE_FORCE);
		device_free(cd, reduced_device);
	}
	return r;
}
