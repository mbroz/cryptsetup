// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2, reencryption keyslot handler
 *
 * Copyright (C) 2016-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2025 Ondrej Kozina
 */

#include "luks2_internal.h"

static int reenc_keyslot_open(struct crypt_device *cd __attribute__((unused)),
	int keyslot __attribute__((unused)),
	const char *password __attribute__((unused)),
	size_t password_len __attribute__((unused)),
	char *volume_key __attribute__((unused)),
	size_t volume_key_len __attribute__((unused)))
{
	return -ENOENT;
}

static json_object *reencrypt_keyslot_area_jobj(struct crypt_device *cd,
		const struct crypt_params_reencrypt *params,
		size_t alignment,
		uint64_t area_offset,
		uint64_t area_length)
{
	json_object *jobj_area = json_object_new_object();

	if (!jobj_area || !params || !params->resilience)
		return NULL;

	json_object_object_add(jobj_area, "offset", crypt_jobj_new_uint64(area_offset));
	json_object_object_add(jobj_area, "size", crypt_jobj_new_uint64(area_length));
	json_object_object_add(jobj_area, "type", json_object_new_string(params->resilience));

	if (!strcmp(params->resilience, "checksum")) {
		log_dbg(cd, "Setting reencrypt keyslot for checksum protection.");
		json_object_object_add(jobj_area, "hash", json_object_new_string(params->hash));
		json_object_object_add(jobj_area, "sector_size", json_object_new_int64(alignment));
	} else if (!strcmp(params->resilience, "journal")) {
		log_dbg(cd, "Setting reencrypt keyslot for journal protection.");
	} else if (!strcmp(params->resilience, "none")) {
		log_dbg(cd, "Setting reencrypt keyslot for none protection.");
	} else if (!strcmp(params->resilience, "datashift")) {
		log_dbg(cd, "Setting reencrypt keyslot for datashift protection.");
		json_object_object_add(jobj_area, "shift_size",
				       crypt_jobj_new_uint64(params->data_shift << SECTOR_SHIFT));
	} else if (!strcmp(params->resilience, "datashift-checksum")) {
		log_dbg(cd, "Setting reencrypt keyslot for datashift and checksum protection.");
		json_object_object_add(jobj_area, "hash", json_object_new_string(params->hash));
		json_object_object_add(jobj_area, "sector_size", json_object_new_int64(alignment));
		json_object_object_add(jobj_area, "shift_size",
				       crypt_jobj_new_uint64(params->data_shift << SECTOR_SHIFT));
	} else if (!strcmp(params->resilience, "datashift-journal")) {
		log_dbg(cd, "Setting reencrypt keyslot for datashift and journal protection.");
		json_object_object_add(jobj_area, "shift_size",
				       crypt_jobj_new_uint64(params->data_shift << SECTOR_SHIFT));
	} else {
		json_object_put(jobj_area);
		return NULL;
	}

	return jobj_area;
}

static json_object *reencrypt_keyslot_area_jobj_update_block_size(struct crypt_device *cd,
		json_object *jobj_area, size_t alignment)
{
	json_object *jobj_type, *jobj_area_new = NULL;

	if (!jobj_area ||
	    !json_object_object_get_ex(jobj_area, "type", &jobj_type) ||
	    (strcmp(json_object_get_string(jobj_type), "checksum") &&
	     strcmp(json_object_get_string(jobj_type), "datashift-checksum")))
		return NULL;

	if (json_object_copy(jobj_area, &jobj_area_new))
		return NULL;

	log_dbg(cd, "Updating reencrypt resilience checksum block size.");

	json_object_object_add(jobj_area_new, "sector_size", json_object_new_int64(alignment));

	return jobj_area_new;
}

static int reenc_keyslot_alloc(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const struct crypt_params_reencrypt *params,
	size_t alignment)
{
	int r;
	json_object *jobj_keyslots, *jobj_keyslot, *jobj_area;
	uint64_t area_offset, area_length;

	log_dbg(cd, "Allocating reencrypt keyslot %d.", keyslot);

	if (!params || !params->resilience || params->direction > CRYPT_REENCRYPT_BACKWARD)
		return -EINVAL;

	if (keyslot < 0 || keyslot >= LUKS2_KEYSLOTS_MAX)
		return -ENOMEM;

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	/* only plain datashift resilience mode does not require additional storage */
	if (!strcmp(params->resilience, "datashift"))
		r = LUKS2_find_area_gap(cd, hdr, 1, &area_offset, &area_length);
	else
		r = LUKS2_find_area_max_gap(cd, hdr, &area_offset, &area_length);
	if (r < 0)
		return r;

	jobj_area = reencrypt_keyslot_area_jobj(cd, params, alignment, area_offset, area_length);
	if (!jobj_area)
		return -EINVAL;

	jobj_keyslot = json_object_new_object();
	if (!jobj_keyslot) {
		json_object_put(jobj_area);
		return -ENOMEM;
	}
	json_object_object_add(jobj_keyslot, "area", jobj_area);

	json_object_object_add(jobj_keyslot, "type", json_object_new_string("reencrypt"));
	json_object_object_add(jobj_keyslot, "key_size", json_object_new_int(1)); /* useless but mandatory */
	json_object_object_add(jobj_keyslot, "mode", json_object_new_string(crypt_reencrypt_mode_to_str(params->mode)));
	if (params->direction == CRYPT_REENCRYPT_FORWARD)
		json_object_object_add(jobj_keyslot, "direction", json_object_new_string("forward"));
	else
		json_object_object_add(jobj_keyslot, "direction", json_object_new_string("backward"));

	r = json_object_object_add_by_uint(jobj_keyslots, keyslot, jobj_keyslot);
	if (r) {
		json_object_put(jobj_keyslot);
		return r;
	}

	if (LUKS2_check_json_size(cd, hdr)) {
		log_dbg(cd, "New keyslot too large to fit in free metadata space.");
		json_object_object_del_by_uint(jobj_keyslots, keyslot);
		return -ENOSPC;
	}

	JSON_DBG(cd, hdr->jobj, "JSON:");

	return 0;
}

static int reenc_keyslot_store_data(struct crypt_device *cd,
	json_object *jobj_keyslot,
	const void *buffer, size_t buffer_len)
{
	int devfd, r;
	json_object *jobj_area, *jobj_offset, *jobj_length;
	uint64_t area_offset, area_length;
	struct device *device = crypt_metadata_device(cd);

	if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area) ||
	    !json_object_object_get_ex(jobj_area, "offset", &jobj_offset) ||
	    !json_object_object_get_ex(jobj_area, "size", &jobj_length))
		return -EINVAL;

	area_offset = crypt_jobj_get_uint64(jobj_offset);
	area_length = crypt_jobj_get_uint64(jobj_length);

	if (!area_offset || !area_length || ((uint64_t)buffer_len > area_length))
		return -EINVAL;

	devfd = device_open_locked(cd, device, O_RDWR);
	if (devfd >= 0) {
		if (write_lseek_blockwise(devfd, device_block_size(cd, device),
					  device_alignment(device), CONST_CAST(void *)buffer,
					  buffer_len, area_offset) < 0)
			r = -EIO;
		else
			r = 0;
	} else
		r = -EINVAL;

	if (r)
		log_err(cd, _("IO error while encrypting keyslot."));

	return r;
}

static int reenc_keyslot_store(struct crypt_device *cd,
	int keyslot,
	const char *password __attribute__((unused)),
	size_t password_len __attribute__((unused)),
	const char *buffer,
	size_t buffer_len)
{
	struct luks2_hdr *hdr;
	json_object *jobj_keyslot;
	int r = 0;

	if (!cd || !buffer || !buffer_len)
		return -EINVAL;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	log_dbg(cd, "Reencrypt keyslot %d store.", keyslot);

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	r = LUKS2_device_write_lock(cd, hdr, crypt_metadata_device(cd));
	if (r)
		return r;

	r = reenc_keyslot_store_data(cd, jobj_keyslot, buffer, buffer_len);
	if (r < 0) {
		device_write_unlock(cd, crypt_metadata_device(cd));
		return r;
	}

	r = LUKS2_hdr_write(cd, hdr);

	device_write_unlock(cd, crypt_metadata_device(cd));

	return r < 0 ? r : keyslot;
}

static int reenc_keyslot_wipe(struct crypt_device *cd,
	int keyslot)
{
	struct luks2_hdr *hdr;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	/* remove reencryption verification data */
	LUKS2_digest_assign(cd, hdr, keyslot, CRYPT_ANY_DIGEST, 0, 0);

	return 0;
}

static int reenc_keyslot_dump(struct crypt_device *cd, int keyslot)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_direction, *jobj_mode, *jobj_resilience,
		    *jobj1;

	jobj_keyslot = LUKS2_get_keyslot_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_keyslot, "direction", &jobj_direction) ||
	    !json_object_object_get_ex(jobj_keyslot, "mode", &jobj_mode) ||
	    !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area) ||
	    !json_object_object_get_ex(jobj_area, "type", &jobj_resilience))
		return -EINVAL;

	log_std(cd, "\t%-12s%s\n", "Mode:", json_object_get_string(jobj_mode));
	log_std(cd, "\t%-12s%s\n", "Direction:", json_object_get_string(jobj_direction));
	log_std(cd, "\t%-12s%s\n", "Resilience:", json_object_get_string(jobj_resilience));

	if (!strcmp(json_object_get_string(jobj_resilience), "checksum")) {
		json_object_object_get_ex(jobj_area, "hash", &jobj1);
		log_std(cd, "\t%-12s%s\n", "Hash:", json_object_get_string(jobj1));
		json_object_object_get_ex(jobj_area, "sector_size", &jobj1);
		log_std(cd, "\t%-12s%d [bytes]\n", "Hash data:", json_object_get_int(jobj1));
	} else if (!strcmp(json_object_get_string(jobj_resilience), "datashift")) {
		json_object_object_get_ex(jobj_area, "shift_size", &jobj1);
		log_std(cd, "\t%-12s%" PRIu64 "[bytes]\n", "Shift size:", crypt_jobj_get_uint64(jobj1));
	}

	json_object_object_get_ex(jobj_area, "offset", &jobj1);
	log_std(cd, "\tArea offset:%" PRIu64 " [bytes]\n", crypt_jobj_get_uint64(jobj1));

	json_object_object_get_ex(jobj_area, "size", &jobj1);
	log_std(cd, "\tArea length:%" PRIu64 " [bytes]\n", crypt_jobj_get_uint64(jobj1));

	return 0;
}

static int reenc_keyslot_validate(struct crypt_device *cd, json_object *jobj_keyslot)
{
	json_object *jobj_mode, *jobj_area, *jobj_type, *jobj_shift_size, *jobj_hash,
		    *jobj_sector_size, *jobj_direction, *jobj_key_size;
	const char *mode, *type, *direction;
	uint32_t sector_size;
	uint64_t shift_size;

	/* mode (string: encrypt,reencrypt,decrypt)
	 * direction (string:)
	 * area {
	 *   type: (string: datashift, journal, checksum, none, datashift-journal, datashift-checksum)
	 *   	hash: (string: checksum and datashift-checksum types)
	 *   	sector_size (uint32:  checksum and datashift-checksum types)
	 *   	shift_size (uint64: all datashift based types)
	 * }
	 */

	/* area and area type are validated in general validation code */
	if (!jobj_keyslot || !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area) ||
	    !json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return -EINVAL;

	jobj_key_size = json_contains(cd, jobj_keyslot, "", "reencrypt keyslot", "key_size", json_type_int);
	jobj_mode = json_contains_string(cd, jobj_keyslot, "", "reencrypt keyslot", "mode");
	jobj_direction = json_contains_string(cd, jobj_keyslot, "", "reencrypt keyslot", "direction");

	if (!jobj_mode || !jobj_direction || !jobj_key_size)
		return -EINVAL;

	if (!validate_json_uint32(jobj_key_size) || crypt_jobj_get_uint32(jobj_key_size) != 1) {
		log_dbg(cd, "Illegal reencrypt key size.");
		return -EINVAL;
	}

	mode = json_object_get_string(jobj_mode);
	type = json_object_get_string(jobj_type);
	direction = json_object_get_string(jobj_direction);

	if (strcmp(mode, "reencrypt") && strcmp(mode, "encrypt") &&
	    strcmp(mode, "decrypt")) {
		log_dbg(cd, "Illegal reencrypt mode %s.", mode);
		return -EINVAL;
	}

	if (strcmp(direction, "forward") && strcmp(direction, "backward")) {
		log_dbg(cd, "Illegal reencrypt direction %s.", direction);
		return -EINVAL;
	}

	if (!strcmp(type, "checksum") || !strcmp(type, "datashift-checksum")) {
		jobj_hash = json_contains_string(cd, jobj_area, "type:checksum",
					  "Keyslot area", "hash");
		jobj_sector_size = json_contains(cd, jobj_area, "type:checksum",
						 "Keyslot area", "sector_size", json_type_int);
		if (!jobj_hash || !jobj_sector_size)
			return -EINVAL;
		if (!validate_json_uint32(jobj_sector_size))
			return -EINVAL;
		sector_size = crypt_jobj_get_uint32(jobj_sector_size);
		if (sector_size < SECTOR_SIZE || NOTPOW2(sector_size)) {
			log_dbg(cd, "Invalid sector_size (%" PRIu32 ") for checksum resilience mode.",
				sector_size);
			return -EINVAL;
		}
	} else if (!strcmp(type, "datashift") ||
		   !strcmp(type, "datashift-checksum") ||
		   !strcmp(type, "datashift-journal")) {
		if (!(jobj_shift_size = json_contains_string(cd, jobj_area, "type:datashift",
						      "Keyslot area", "shift_size")))
			return -EINVAL;

		shift_size = crypt_jobj_get_uint64(jobj_shift_size);
		if (!shift_size)
			return -EINVAL;

		if (MISALIGNED_512(shift_size)) {
			log_dbg(cd, "Shift size field has to be aligned to 512 bytes.");
			return -EINVAL;
		}
	}

	return 0;
}

static int reenc_keyslot_update_needed(json_object *jobj_keyslot,
	const struct crypt_params_reencrypt *params,
	size_t alignment)
{
	const char *type;
	json_object *jobj_area, *jobj_type, *jobj;

	if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area) ||
	    !json_object_object_get_ex(jobj_area, "type", &jobj_type) ||
	    !(type = json_object_get_string(jobj_type)))
		return -EINVAL;

	/*
	 * If no resilience mode change is requested and effective
	 * resilience mode is 'checksum' then check alignment matches
	 * stored checksum block size.
	 */
	if (!params || !params->resilience) {
		if (!strcmp(json_object_get_string(jobj_type), "checksum") ||
		    !strcmp(json_object_get_string(jobj_type), "datashift-checksum"))
			return (json_object_object_get_ex(jobj_area, "sector_size", &jobj) ||
				alignment != crypt_jobj_get_uint32(jobj));
		return 0;
	}

	if (strcmp(params->resilience, type))
		return 1;

	if (!strcmp(type, "checksum") ||
	    !strcmp(type, "datashift-checksum")) {
		if (!params->hash)
			return -EINVAL;
		if (!json_object_object_get_ex(jobj_area, "hash", &jobj) ||
			strcmp(json_object_get_string(jobj), params->hash) ||
			!json_object_object_get_ex(jobj_area, "sector_size", &jobj) ||
			crypt_jobj_get_uint32(jobj) != alignment)
			return 1;
	}

	if (!strncmp(type, "datashift", 9)) {
		if (!json_object_object_get_ex(jobj_area, "shift_size", &jobj))
			return -EINVAL;
		if ((params->data_shift << SECTOR_SHIFT) != crypt_jobj_get_uint64(jobj))
			return 1;
	}

	/* nothing to compare with 'none' and 'journal' */
	return 0;
}

static int load_checksum_protection(struct crypt_device *cd,
	json_object *jobj_area,
	uint64_t area_length,
	struct reenc_protection *rp)
{
	int r;
	json_object *jobj_hash, *jobj_block_size;

	if (!jobj_area || !rp ||
	    !json_object_object_get_ex(jobj_area, "hash", &jobj_hash) ||
	    !json_object_object_get_ex(jobj_area, "sector_size", &jobj_block_size))
		return -EINVAL;

	r = snprintf(rp->p.csum.hash, sizeof(rp->p.csum.hash), "%s", json_object_get_string(jobj_hash));
	if (r < 0 || (size_t)r >= sizeof(rp->p.csum.hash))
		return -EINVAL;

	if (crypt_hash_init(&rp->p.csum.ch, rp->p.csum.hash)) {
		log_err(cd, _("Hash algorithm %s is not available."), rp->p.csum.hash);
		return -EINVAL;
	}

	r = crypt_hash_size(rp->p.csum.hash);
	if (r <= 0) {
		crypt_hash_destroy(rp->p.csum.ch);
		rp->p.csum.ch = NULL;
		log_dbg(cd, "Invalid hash size");
		return -EINVAL;
	}

	rp->p.csum.hash_size = r;
	rp->p.csum.block_size = crypt_jobj_get_uint32(jobj_block_size);
	rp->p.csum.checksums_len = area_length;

	rp->type = REENC_PROTECTION_CHECKSUM;
	return 0;
}

static int reenc_keyslot_load_resilience_primary(struct crypt_device *cd,
	const char *type,
	json_object *jobj_area,
	uint64_t area_length,
	struct reenc_protection *rp)
{
	json_object *jobj;

	if (!strcmp(type, "checksum")) {
		log_dbg(cd, "Initializing checksum resilience mode.");
		return load_checksum_protection(cd, jobj_area, area_length, rp);
	} else if (!strcmp(type, "journal")) {
		log_dbg(cd, "Initializing journal resilience mode.");
		rp->type = REENC_PROTECTION_JOURNAL;
	} else if (!strcmp(type, "none")) {
		log_dbg(cd, "Initializing none resilience mode.");
		rp->type = REENC_PROTECTION_NONE;
	} else if (!strcmp(type, "datashift") ||
		   !strcmp(type, "datashift-checksum") ||
		   !strcmp(type, "datashift-journal")) {
		log_dbg(cd, "Initializing datashift resilience mode.");
		if (!json_object_object_get_ex(jobj_area, "shift_size", &jobj))
			return -EINVAL;
		rp->type = REENC_PROTECTION_DATASHIFT;
		rp->p.ds.data_shift = crypt_jobj_get_uint64(jobj);
	} else
		return -EINVAL;

	return 0;
}

static int reenc_keyslot_load_resilience_secondary(struct crypt_device *cd,
	const char *type,
	json_object *jobj_area,
	uint64_t area_length,
	struct reenc_protection *rp)
{
	if (!strcmp(type, "datashift-checksum")) {
		log_dbg(cd, "Initializing checksum resilience mode.");
		return load_checksum_protection(cd, jobj_area, area_length, rp);
	} else if (!strcmp(type, "datashift-journal")) {
		log_dbg(cd, "Initializing journal resilience mode.");
		rp->type = REENC_PROTECTION_JOURNAL;
	} else
		rp->type = REENC_PROTECTION_NOT_SET;

	return 0;
}

static int reenc_keyslot_load_resilience(struct crypt_device *cd,
	json_object *jobj_keyslot,
	struct reenc_protection *rp,
	bool primary)
{
	const char *type;
	int r;
	json_object *jobj_area, *jobj_type;
	uint64_t dummy, area_length;

	if (!rp || !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area) ||
	    !json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return -EINVAL;

	r = LUKS2_keyslot_jobj_area(jobj_keyslot, &dummy, &area_length);
	if (r < 0)
		return r;

	type = json_object_get_string(jobj_type);
	if (!type)
		return -EINVAL;

	if (primary)
		return reenc_keyslot_load_resilience_primary(cd, type, jobj_area, area_length, rp);
	else
		return reenc_keyslot_load_resilience_secondary(cd, type, jobj_area, area_length, rp);
}

static bool reenc_keyslot_update_is_valid(json_object *jobj_area,
	const struct crypt_params_reencrypt *params)
{
	const char *type;
	json_object *jobj_type, *jobj;

	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type) ||
	    !(type = json_object_get_string(jobj_type)))
		return false;

	/* do not allow switch to/away from datashift resilience type */
	if ((strcmp(params->resilience, "datashift") && !strcmp(type, "datashift")) ||
	    (!strcmp(params->resilience, "datashift") && strcmp(type, "datashift")))
		return false;

	/* do not allow switch to/away from datashift- resilience subvariants */
	if ((strncmp(params->resilience, "datashift-", 10) &&
	     !strncmp(type, "datashift-", 10)) ||
	    (!strncmp(params->resilience, "datashift-", 10) &&
	     strncmp(type, "datashift-", 10)))
		return false;

	/* datashift value is also immutable */
	if (!strncmp(type, "datashift", 9)) {
		if (!json_object_object_get_ex(jobj_area, "shift_size", &jobj))
			return false;
		return (params->data_shift << SECTOR_SHIFT) == crypt_jobj_get_uint64(jobj);
	}

	return true;
}

static int reenc_keyslot_update(struct crypt_device *cd,
	json_object *jobj_keyslot,
	const struct crypt_params_reencrypt *params,
	size_t alignment)
{
	int r;
	json_object *jobj_area, *jobj_area_new;
	uint64_t area_offset, area_length;

	if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	r = LUKS2_keyslot_jobj_area(jobj_keyslot, &area_offset, &area_length);
	if (r < 0)
		return r;

	if (!params || !params->resilience)
		jobj_area_new = reencrypt_keyslot_area_jobj_update_block_size(cd, jobj_area, alignment);
	else {
		if (!reenc_keyslot_update_is_valid(jobj_area, params)) {
			log_err(cd, _("Invalid reencryption resilience mode change requested."));
			return -EINVAL;
		}

		jobj_area_new = reencrypt_keyslot_area_jobj(cd, params, alignment,
							    area_offset, area_length);
	}

	if (!jobj_area_new)
		return -EINVAL;

	/* increase refcount for validation purposes */
	json_object_get(jobj_area);

	json_object_object_add(jobj_keyslot, "area", jobj_area_new);

	r = reenc_keyslot_validate(cd, jobj_keyslot);
	if (r) {
		/* replace invalid object with previous valid one */
		json_object_object_add(jobj_keyslot, "area", jobj_area);
		return -EINVAL;
	}

	/* previous area object is no longer needed */
	json_object_put(jobj_area);

	return 0;
}

int LUKS2_keyslot_reencrypt_allocate(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const struct crypt_params_reencrypt *params,
	size_t alignment)
{
	int r;

	if (keyslot == CRYPT_ANY_SLOT)
		return -EINVAL;

	r = reenc_keyslot_alloc(cd, hdr, keyslot, params, alignment);
	if (r < 0)
		return r;

	r = LUKS2_keyslot_priority_set(cd, hdr, keyslot, CRYPT_SLOT_PRIORITY_IGNORE, 0);
	if (r < 0)
		return r;

	r = reenc_keyslot_validate(cd, LUKS2_get_keyslot_jobj(hdr, keyslot));
	if (r) {
		log_dbg(cd, "Keyslot validation failed.");
		return r;
	}

	return 0;
}

int LUKS2_keyslot_reencrypt_update_needed(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const struct crypt_params_reencrypt *params,
	size_t alignment)
{
	int r;
	json_object *jobj_type, *jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);

	if (!jobj_keyslot ||
	    !json_object_object_get_ex(jobj_keyslot, "type", &jobj_type) ||
	    strcmp(json_object_get_string(jobj_type), "reencrypt"))
		return -EINVAL;

	r = reenc_keyslot_update_needed(jobj_keyslot, params, alignment);
	if (!r)
		log_dbg(cd, "No update of reencrypt keyslot needed.");

	return r;
}

int LUKS2_keyslot_reencrypt_update(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const struct crypt_params_reencrypt *params,
	size_t alignment,
	struct volume_key *vks)
{
	int r;
	uint8_t version;
	uint64_t max_size, moved_segment_size;
	json_object *jobj_type, *jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	struct reenc_protection check_rp = {};

	if (!jobj_keyslot ||
	    !json_object_object_get_ex(jobj_keyslot, "type", &jobj_type) ||
	    strcmp(json_object_get_string(jobj_type), "reencrypt"))
		return -EINVAL;

	if (LUKS2_config_get_reencrypt_version(hdr, &version))
		return -EINVAL;

	/* verify existing reencryption metadata before updating */
	r = LUKS2_reencrypt_digest_verify(cd, hdr, vks);
	if (r < 0)
		return r;

	r = reenc_keyslot_update(cd, jobj_keyslot, params, alignment);
	if (r < 0)
		return r;

	r = reenc_keyslot_load_resilience(cd, jobj_keyslot, &check_rp, false);
	if (r < 0)
		return r;

	if (check_rp.type != REENC_PROTECTION_NOT_SET) {
		r = LUKS2_reencrypt_max_hotzone_size(cd, hdr, &check_rp, keyslot, &max_size);
		LUKS2_reencrypt_protection_erase(&check_rp);
		if (r < 0)
			return r;
		moved_segment_size = json_segment_get_size(LUKS2_get_segment_by_flag(hdr, "backup-moved-segment"), 0);
		if (!moved_segment_size)
			return -EINVAL;
		if (moved_segment_size > max_size) {
			log_err(cd, _("Can not update resilience type. "
				      "New type only provides %" PRIu64 " bytes, "
				      "required space is: %" PRIu64 " bytes."),
				max_size, moved_segment_size);
			return -EINVAL;
		}
	}

	r = LUKS2_keyslot_reencrypt_digest_create(cd, hdr, version, vks);
	if (r < 0)
		log_err(cd, _("Failed to refresh reencryption verification digest."));

	return r ?: LUKS2_hdr_write(cd, hdr);
}

int LUKS2_keyslot_reencrypt_load(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	struct reenc_protection *rp,
	bool primary)
{
	json_object *jobj_type, *jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);

	if (!jobj_keyslot ||
	    !json_object_object_get_ex(jobj_keyslot, "type", &jobj_type) ||
	    strcmp(json_object_get_string(jobj_type), "reencrypt"))
		return -EINVAL;

	return reenc_keyslot_load_resilience(cd, jobj_keyslot, rp, primary);
}

const keyslot_handler reenc_keyslot = {
	.name  = "reencrypt",
	.open  = reenc_keyslot_open,
	.store = reenc_keyslot_store, /* initialization only or also per every chunk write */
	.wipe  = reenc_keyslot_wipe,
	.dump  = reenc_keyslot_dump,
	.validate  = reenc_keyslot_validate
};
