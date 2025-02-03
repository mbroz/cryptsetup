// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2, reencryption digest helpers
 *
 * Copyright (C) 2022-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2022-2025 Ondrej Kozina
 * Copyright (C) 2022-2025 Milan Broz
 */

#include "luks2_internal.h"

#define MAX_STR 64

struct jtype {
	enum { JNONE = 0, JSTR, JU64, JX64, JU32 } type;
	json_object *jobj;
	const char *id;
};

static size_t sr(struct jtype *j, uint8_t *ptr)
{
	json_object *jobj;
	size_t len = 0;
	uint64_t u64;
	uint32_t u32;

	if (!json_object_is_type(j->jobj, json_type_object))
		return 0;

	if (!json_object_object_get_ex(j->jobj, j->id, &jobj))
		return 0;

	switch(j->type) {
	case JSTR: /* JSON string */
		if (!json_object_is_type(jobj, json_type_string))
			return 0;
		len = strlen(json_object_get_string(jobj));
		if (len > MAX_STR)
			return 0;
		if (ptr)
			memcpy(ptr, json_object_get_string(jobj), len);
		break;
	case JU64: /* Unsigned 64bit integer stored as string */
		if (!json_object_is_type(jobj, json_type_string))
			break;
		len = sizeof(u64);
		if (ptr) {
			u64 = cpu_to_be64(crypt_jobj_get_uint64(jobj));
			memcpy(ptr, &u64, len);
		}
		break;
	case JX64: /* Unsigned 64bit segment size (allows "dynamic") */
		if (!json_object_is_type(jobj, json_type_string))
			break;
		if (!strcmp(json_object_get_string(jobj), "dynamic")) {
			len = strlen("dynamic");
			if (ptr)
				memcpy(ptr, json_object_get_string(jobj), len);
		} else {
			len = sizeof(u64);
			u64 = cpu_to_be64(crypt_jobj_get_uint64(jobj));
			if (ptr)
				memcpy(ptr, &u64, len);
		}
		break;
	case JU32: /* Unsigned 32bit integer, stored as JSON int */
		if (!json_object_is_type(jobj, json_type_int))
			return 0;
		len =  sizeof(u32);
		if (ptr) {
			u32 = cpu_to_be32(crypt_jobj_get_uint32(jobj));
			memcpy(ptr, &u32, len);
		}
		break;
	case JNONE:
		return 0;
	};

	return len;
}

static size_t srs(struct jtype j[], uint8_t *ptr)
{
	size_t l, len = 0;

	while(j->jobj) {
		l = sr(j, ptr);
		if (!l)
			return 0;
		len += l;
		if (ptr)
			ptr += l;
		j++;
	}
	return len;
}

static size_t segment_linear_serialize(json_object *jobj_segment, uint8_t *buffer)
{
	struct jtype j[] = {
		{ JSTR, jobj_segment, "type" },
		{ JU64, jobj_segment, "offset" },
		{ JX64, jobj_segment, "size" },
		{}
	};
	return srs(j, buffer);
}

static size_t segment_crypt_serialize(json_object *jobj_segment, uint8_t *buffer)
{
	struct jtype j[] = {
		{ JSTR, jobj_segment, "type" },
		{ JU64, jobj_segment, "offset" },
		{ JX64, jobj_segment, "size" },
		{ JU64, jobj_segment, "iv_tweak" },
		{ JSTR, jobj_segment, "encryption" },
		{ JU32, jobj_segment, "sector_size" },
		{}
	};
	return srs(j, buffer);
}

static size_t segment_serialize(json_object *jobj_segment, uint8_t *buffer)
{
	json_object *jobj_type;
	const char *segment_type;

	if (!json_object_object_get_ex(jobj_segment, "type", &jobj_type))
		return 0;

	if (!(segment_type = json_object_get_string(jobj_type)))
		return 0;

	if (!strcmp(segment_type, "crypt"))
		return segment_crypt_serialize(jobj_segment, buffer);
	else if (!strcmp(segment_type, "linear"))
		return segment_linear_serialize(jobj_segment, buffer);

	return 0;
}

static size_t backup_segments_serialize(struct luks2_hdr *hdr, uint8_t *buffer)
{
	json_object *jobj_segment;
	size_t l, len = 0;

	jobj_segment = LUKS2_get_segment_by_flag(hdr, "backup-previous");
	if (!jobj_segment || !(l = segment_serialize(jobj_segment, buffer)))
		return 0;
	len += l;
	if (buffer)
		buffer += l;

	jobj_segment = LUKS2_get_segment_by_flag(hdr, "backup-final");
	if (!jobj_segment || !(l = segment_serialize(jobj_segment, buffer)))
		return 0;
	len += l;
	if (buffer)
		buffer += l;

	jobj_segment = LUKS2_get_segment_by_flag(hdr, "backup-moved-segment");
	if (jobj_segment) {
		if (!(l = segment_serialize(jobj_segment, buffer)))
			return 0;
		len += l;
	}

	return len;
}

static size_t reenc_keyslot_serialize(struct luks2_hdr *hdr, uint8_t *buffer)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type;
	const char *area_type;
	int keyslot_reencrypt;

	keyslot_reencrypt = LUKS2_find_keyslot(hdr, "reencrypt");
	if (keyslot_reencrypt < 0)
		return 0;

	if (!(jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot_reencrypt)))
		return 0;

	if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return 0;

	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return 0;

	if (!(area_type = json_object_get_string(jobj_type)))
		return 0;

	struct jtype j[] = {
		{ JSTR, jobj_keyslot, "mode" },
		{ JSTR, jobj_keyslot, "direction" },
		{ JSTR, jobj_area,    "type" },
		{ JU64, jobj_area,    "offset" },
		{ JU64, jobj_area,    "size" },
		{}
	};
	struct jtype j_datashift[] = {
		{ JSTR, jobj_keyslot, "mode" },
		{ JSTR, jobj_keyslot, "direction" },
		{ JSTR, jobj_area,    "type" },
		{ JU64, jobj_area,    "offset" },
		{ JU64, jobj_area,    "size" },
		{ JU64, jobj_area,    "shift_size" },
		{}
	};
	struct jtype j_checksum[] = {
		{ JSTR, jobj_keyslot, "mode" },
		{ JSTR, jobj_keyslot, "direction" },
		{ JSTR, jobj_area,    "type" },
		{ JU64, jobj_area,    "offset" },
		{ JU64, jobj_area,    "size" },
		{ JSTR, jobj_area,    "hash" },
		{ JU32, jobj_area,    "sector_size" },
		{}
	};
	struct jtype j_datashift_checksum[] = {
		{ JSTR, jobj_keyslot, "mode" },
		{ JSTR, jobj_keyslot, "direction" },
		{ JSTR, jobj_area,    "type" },
		{ JU64, jobj_area,    "offset" },
		{ JU64, jobj_area,    "size" },
		{ JSTR, jobj_area,    "hash" },
		{ JU32, jobj_area,    "sector_size" },
		{ JU64, jobj_area,    "shift_size" },
		{}
	};

	if (!strcmp(area_type, "datashift-checksum"))
		return srs(j_datashift_checksum, buffer);
	else if (!strcmp(area_type, "datashift") ||
		 !strcmp(area_type, "datashift-journal"))
		return srs(j_datashift, buffer);
	else if (!strcmp(area_type, "checksum"))
		return srs(j_checksum, buffer);

	return srs(j, buffer);
}

static size_t blob_serialize(const void *blob, size_t length, uint8_t *buffer)
{
	if (buffer)
		crypt_safe_memcpy(buffer, blob, length);

	return length;
}

static int reencrypt_assembly_verification_data(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct volume_key *vks,
	uint8_t version,
	struct volume_key **r_verification_data)
{
	uint8_t *ptr;
	int digest_new, digest_old, r = -EINVAL;
	struct volume_key *verification_data = NULL, *vk_old = NULL, *vk_new = NULL;
	size_t keyslot_data_len, segments_data_len, data_len = 2;
	void *data = NULL;

	/*
	 * This works up to (including) version v207.
	 */
	assert(version < (UINT8_MAX - 0x2F));

	/* Keys - calculate length */
	digest_new = LUKS2_reencrypt_digest_new(hdr);
	digest_old = LUKS2_reencrypt_digest_old(hdr);

	if (digest_old >= 0) {
		vk_old = crypt_volume_key_by_id(vks, digest_old);
		if (!vk_old) {
			log_dbg(cd, "Key (digest id %d) required but not unlocked.", digest_old);
			return -EINVAL;
		}
		data_len += blob_serialize(crypt_volume_key_get_key(vk_old), crypt_volume_key_length(vk_old), NULL);
	}

	if (digest_new >= 0 && digest_old != digest_new) {
		vk_new = crypt_volume_key_by_id(vks, digest_new);
		if (!vk_new) {
			log_dbg(cd, "Key (digest id %d) required but not unlocked.", digest_new);
			return -EINVAL;
		}
		data_len += blob_serialize(crypt_volume_key_get_key(vk_new), crypt_volume_key_length(vk_new), NULL);
	}

	if (data_len == 2)
		return -EINVAL;

	/* Metadata - calculate length */
	if (!(keyslot_data_len = reenc_keyslot_serialize(hdr, NULL)))
		return -EINVAL;
	data_len += keyslot_data_len;

	if (!(segments_data_len = backup_segments_serialize(hdr, NULL)))
		return -EINVAL;
	data_len += segments_data_len;

	/* Alloc and fill serialization data */
	data = crypt_safe_alloc(data_len);
	if (!data)
		return -ENOMEM;

	ptr = (uint8_t*)data;

	*ptr++ = 0x76;
	*ptr++ = 0x30 + version;

	if (vk_old)
		ptr += blob_serialize(crypt_volume_key_get_key(vk_old),
				      crypt_volume_key_length(vk_old), ptr);

	if (vk_new)
		ptr += blob_serialize(crypt_volume_key_get_key(vk_new),
				      crypt_volume_key_length(vk_new), ptr);

	if (!reenc_keyslot_serialize(hdr, ptr))
		goto bad;
	ptr += keyslot_data_len;

	if (!backup_segments_serialize(hdr, ptr))
		goto bad;
	ptr += segments_data_len;

	assert((size_t)(ptr - (uint8_t*)data) == data_len);

	verification_data = crypt_alloc_volume_key_by_safe_alloc(&data);
	if (!verification_data) {
		r = -ENOMEM;
		goto bad;
	}
	*r_verification_data = verification_data;

	return 0;
bad:
	crypt_safe_free(data);
	crypt_free_volume_key(verification_data);
	return r;
}

int LUKS2_keyslot_reencrypt_digest_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint8_t version,
	struct volume_key *vks)
{
	int digest_reencrypt, keyslot_reencrypt, r;
	struct volume_key *data;

	keyslot_reencrypt = LUKS2_find_keyslot(hdr, "reencrypt");
	if (keyslot_reencrypt < 0)
		return keyslot_reencrypt;

	r = reencrypt_assembly_verification_data(cd, hdr, vks, version, &data);
	if (r < 0)
		return r;

	r = LUKS2_digest_create(cd, "pbkdf2", hdr, data);
	crypt_free_volume_key(data);
	if (r < 0)
		return r;

	digest_reencrypt = r;

	r = LUKS2_digest_assign(cd, hdr, keyslot_reencrypt, CRYPT_ANY_DIGEST, 0, 0);
	if (r < 0)
		return r;

	return LUKS2_digest_assign(cd, hdr, keyslot_reencrypt, digest_reencrypt, 1, 0);
}

int LUKS2_reencrypt_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct volume_key *vks)
{
	int r, keyslot_reencrypt;
	struct volume_key *data;
	uint8_t version;

	log_dbg(cd, "Verifying reencryption metadata.");

	keyslot_reencrypt = LUKS2_find_keyslot(hdr, "reencrypt");
	if (keyslot_reencrypt < 0)
		return keyslot_reencrypt;

	if (LUKS2_config_get_reencrypt_version(hdr, &version))
		return -EINVAL;

	r = reencrypt_assembly_verification_data(cd, hdr, vks, version, &data);
	if (r < 0)
		return r;

	r = LUKS2_digest_verify(cd, hdr, data, keyslot_reencrypt);
	crypt_free_volume_key(data);

	if (r < 0) {
		if (r == -ENOENT)
			log_dbg(cd, "Reencryption digest is missing.");
		log_err(cd, _("Reencryption metadata is invalid."));
	} else
		log_dbg(cd, "Reencryption metadata verified.");

	return r;
}
