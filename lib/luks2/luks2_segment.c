// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2, internal segment handling
 *
 * Copyright (C) 2018-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2025 Ondrej Kozina
 */

#include "luks2_internal.h"

/* use only on already validated 'segments' object */
uint64_t json_segments_get_minimal_offset(json_object *jobj_segments, unsigned blockwise)
{
	uint64_t tmp, min = blockwise ? UINT64_MAX >> SECTOR_SHIFT : UINT64_MAX;

	if (!jobj_segments)
		return 0;

	json_object_object_foreach(jobj_segments, key, val) {
		UNUSED(key);

		if (json_segment_is_backup(val))
			continue;

		tmp = json_segment_get_offset(val, blockwise);

		if (!tmp)
			return tmp;

		if (tmp < min)
			min = tmp;
	}

	return min;
}

uint64_t json_segment_get_offset(json_object *jobj_segment, unsigned blockwise)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "offset", &jobj))
		return 0;

	return blockwise ? crypt_jobj_get_uint64(jobj) >> SECTOR_SHIFT : crypt_jobj_get_uint64(jobj);
}

const char *json_segment_type(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "type", &jobj))
		return NULL;

	return json_object_get_string(jobj);
}

uint64_t json_segment_get_iv_offset(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "iv_tweak", &jobj))
		return 0;

	return crypt_jobj_get_uint64(jobj);
}

uint64_t json_segment_get_size(json_object *jobj_segment, unsigned blockwise)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "size", &jobj))
		return 0;

	return blockwise ? crypt_jobj_get_uint64(jobj) >> SECTOR_SHIFT : crypt_jobj_get_uint64(jobj);
}

static uint64_t json_segment_get_opal_size(json_object *jobj_segment, unsigned blockwise)
{
	json_object *jobj;

	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "opal_segment_size", &jobj))
		return 0;

	return blockwise ? crypt_jobj_get_uint64(jobj) >> SECTOR_SHIFT : crypt_jobj_get_uint64(jobj);
}

static bool json_segment_set_size(json_object *jobj_segment, const uint64_t *size_bytes)
{
	json_object *jobj;

	if (!jobj_segment)
		return false;

	jobj = size_bytes ? crypt_jobj_new_uint64(*size_bytes) : json_object_new_string("dynamic");
	if (!jobj)
		return false;

	json_object_object_add(jobj_segment, "size", jobj);

	return true;
}

const char *json_segment_get_cipher(json_object *jobj_segment)
{
	json_object *jobj;

	/* FIXME: Pseudo "null" cipher should be handled elsewhere */
	if (!jobj_segment ||
	    !json_object_object_get_ex(jobj_segment, "encryption", &jobj))
		return "null";

	return json_object_get_string(jobj);
}

uint32_t json_segment_get_sector_size(json_object *jobj_segment)
{
	json_object *jobj;
	int i;

	if (!jobj_segment ||
            !json_object_object_get_ex(jobj_segment, "sector_size", &jobj))
		return SECTOR_SIZE;

	i = json_object_get_int(jobj);
	return i < 0 ? SECTOR_SIZE : i;
}

int json_segment_get_opal_segment_id(json_object *jobj_segment, uint32_t *ret_opal_segment_id)
{
	json_object *jobj_segment_id;

	assert(ret_opal_segment_id);

	if (!json_object_object_get_ex(jobj_segment, "opal_segment_number", &jobj_segment_id))
		return -EINVAL;

	*ret_opal_segment_id = json_object_get_int(jobj_segment_id);

	return 0;
}

int json_segment_get_opal_key_size(json_object *jobj_segment, size_t *ret_key_size)
{
	json_object *jobj_key_size;

	assert(ret_key_size);

	if (!jobj_segment)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_segment, "opal_key_size", &jobj_key_size))
		return -EINVAL;

	*ret_key_size = json_object_get_int(jobj_key_size);

	return 0;
}

static json_object *json_segment_get_flags(json_object *jobj_segment)
{
	json_object *jobj;

	if (!jobj_segment || !(json_object_object_get_ex(jobj_segment, "flags", &jobj)))
		return NULL;
	return jobj;
}

bool json_segment_contains_flag(json_object *jobj_segment, const char *flag_str, size_t len)
{
	int r, i;
	json_object *jobj, *jobj_flags = json_segment_get_flags(jobj_segment);

	if (!jobj_flags)
		return false;

	for (i = 0; i < (int)json_object_array_length(jobj_flags); i++) {
		jobj = json_object_array_get_idx(jobj_flags, i);
		if (len)
			r = strncmp(json_object_get_string(jobj), flag_str, len);
		else
			r = strcmp(json_object_get_string(jobj), flag_str);
		if (!r)
			return true;
	}

	return false;
}

bool json_segment_is_backup(json_object *jobj_segment)
{
	return json_segment_contains_flag(jobj_segment, "backup-", 7);
}

json_object *json_segments_get_segment(json_object *jobj_segments, int segment)
{
	json_object *jobj;
	char segment_name[16];

	if (snprintf(segment_name, sizeof(segment_name), "%u", segment) < 1)
		return NULL;

	if (!json_object_object_get_ex(jobj_segments, segment_name, &jobj))
		return NULL;

	return jobj;
}

unsigned json_segments_count(json_object *jobj_segments)
{
	unsigned count = 0;

	if (!jobj_segments)
		return 0;

	json_object_object_foreach(jobj_segments, slot, val) {
		UNUSED(slot);
		if (!json_segment_is_backup(val))
			count++;
	}

	return count;
}

void json_segment_remove_flag(json_object *jobj_segment, const char *flag)
{
	json_object *jobj_flags, *jobj_flags_new;

	if (!jobj_segment)
		return;

	jobj_flags = json_segment_get_flags(jobj_segment);
	if (!jobj_flags)
		return;

	jobj_flags_new = LUKS2_array_remove(jobj_flags, flag);
	if (!jobj_flags_new)
		return;

	if (json_object_array_length(jobj_flags_new) <= 0) {
		json_object_put(jobj_flags_new);
		json_object_object_del(jobj_segment, "flags");
	} else
		json_object_object_add(jobj_segment, "flags", jobj_flags_new);
}

static json_object *_segment_create_generic(const char *type, uint64_t offset, const uint64_t *length)
{
	json_object *jobj = json_object_new_object();
	if (!jobj)
		return NULL;

	json_object_object_add(jobj, "type",		json_object_new_string(type));
	json_object_object_add(jobj, "offset",		crypt_jobj_new_uint64(offset));
	json_object_object_add(jobj, "size",		length ? crypt_jobj_new_uint64(*length) : json_object_new_string("dynamic"));

	return jobj;
}

json_object *json_segment_create_linear(uint64_t offset, const uint64_t *length, unsigned reencryption)
{
	json_object *jobj = _segment_create_generic("linear", offset, length);
	if (reencryption)
		LUKS2_segment_set_flag(jobj, "in-reencryption");
	return jobj;
}

static bool json_add_crypt_fields(json_object *jobj_segment, uint64_t iv_offset,
				  const char *cipher, const char *integrity, uint32_t integrity_key_size,
				  uint32_t sector_size, unsigned reencryption)
{
	json_object *jobj_integrity;

	assert(cipher);

	json_object_object_add(jobj_segment, "iv_tweak",    crypt_jobj_new_uint64(iv_offset));
	json_object_object_add(jobj_segment, "encryption",  json_object_new_string(cipher));
	json_object_object_add(jobj_segment, "sector_size", json_object_new_int(sector_size));

	if (integrity) {
		jobj_integrity = json_object_new_object();
		if (!jobj_integrity)
			return false;

		json_object_object_add(jobj_integrity, "type", json_object_new_string(integrity));
		json_object_object_add(jobj_integrity, "journal_encryption", json_object_new_string("none"));
		json_object_object_add(jobj_integrity, "journal_integrity", json_object_new_string("none"));
		if (integrity_key_size)
			json_object_object_add(jobj_integrity, "key_size", json_object_new_int(integrity_key_size));
		json_object_object_add(jobj_segment,   "integrity", jobj_integrity);
	}

	if (reencryption)
		LUKS2_segment_set_flag(jobj_segment, "in-reencryption");

	return true;
}

json_object *json_segment_create_crypt(uint64_t offset,
				  uint64_t iv_offset, const uint64_t *length,
				  const char *cipher, const char *integrity, uint32_t integrity_key_size,
				  uint32_t sector_size, unsigned reencryption)
{
	json_object *jobj = _segment_create_generic("crypt", offset, length);

	if (!jobj)
		return NULL;

	if (json_add_crypt_fields(jobj, iv_offset, cipher, integrity, integrity_key_size, sector_size, reencryption))
		return jobj;

	json_object_put(jobj);
	return NULL;
}

static void json_add_opal_fields(json_object *jobj_segment, const uint64_t *length,
				 uint32_t segment_number, uint32_t key_size)
{
	assert(jobj_segment);
	assert(length);

	json_object_object_add(jobj_segment, "opal_segment_number", json_object_new_int(segment_number));
	json_object_object_add(jobj_segment, "opal_key_size", json_object_new_int(key_size));
	json_object_object_add(jobj_segment, "opal_segment_size", crypt_jobj_new_uint64(*length));
}

json_object *json_segment_create_opal(uint64_t offset, const uint64_t *length,
				      uint32_t segment_number, uint32_t key_size)
{
	json_object *jobj = _segment_create_generic("hw-opal", offset, length);
	if (!jobj)
		return NULL;

	json_add_opal_fields(jobj, length, segment_number, key_size);

	return jobj;
}

json_object *json_segment_create_opal_crypt(uint64_t offset, const uint64_t *length,
					    uint32_t segment_number, uint32_t key_size,
					    uint64_t iv_offset, const char *cipher,
					    const char *integrity, uint32_t sector_size,
					    unsigned reencryption)
{
	json_object *jobj = _segment_create_generic("hw-opal-crypt", offset, length);
	if (!jobj)
		return NULL;

	json_add_opal_fields(jobj, length, segment_number, key_size);

	if (json_add_crypt_fields(jobj, iv_offset, cipher, integrity, 0, sector_size, reencryption))
		return jobj;

	json_object_put(jobj);
	return NULL;
}

uint64_t LUKS2_segment_offset(struct luks2_hdr *hdr, int segment, unsigned blockwise)
{
	return json_segment_get_offset(LUKS2_get_segment_jobj(hdr, segment), blockwise);
}

int json_segments_segment_in_reencrypt(json_object *jobj_segments)
{
	json_object *jobj_flags;

	json_object_object_foreach(jobj_segments, slot, val) {
		if (!json_object_object_get_ex(val, "flags", &jobj_flags) ||
		    !LUKS2_array_jobj(jobj_flags, "in-reencryption"))
			continue;

		return atoi(slot);
	}

	return -1;
}

uint64_t LUKS2_segment_size(struct luks2_hdr *hdr, int segment, unsigned blockwise)
{
	return json_segment_get_size(LUKS2_get_segment_jobj(hdr, segment), blockwise);
}

uint64_t LUKS2_opal_segment_size(struct luks2_hdr *hdr, int segment, unsigned blockwise)
{
	return json_segment_get_opal_size(LUKS2_get_segment_jobj(hdr, segment), blockwise);
}

bool LUKS2_segment_set_size(struct luks2_hdr *hdr, int segment, const uint64_t *segment_size_bytes)
{
	return json_segment_set_size(LUKS2_get_segment_jobj(hdr, segment), segment_size_bytes);
}

int LUKS2_segment_is_type(struct luks2_hdr *hdr, int segment, const char *type)
{
	return !strcmp(json_segment_type(LUKS2_get_segment_jobj(hdr, segment)) ?: "", type);
}

static bool json_segment_is_hw_opal_only(json_object *jobj_segment)
{
	const char *type = json_segment_type(jobj_segment);

	if (!type)
		return false;

	return !strcmp(type, "hw-opal");
}

static bool json_segment_is_hw_opal_crypt(json_object *jobj_segment)
{
	const char *type = json_segment_type(jobj_segment);

	if (!type)
		return false;

	return !strcmp(type, "hw-opal-crypt");
}

static bool json_segment_is_hw_opal(json_object *jobj_segment)
{
	return json_segment_is_hw_opal_crypt(jobj_segment) ||
	       json_segment_is_hw_opal_only(jobj_segment);
}

bool LUKS2_segment_is_hw_opal_only(struct luks2_hdr *hdr, int segment)
{
	return json_segment_is_hw_opal_only(LUKS2_get_segment_jobj(hdr, segment));
}

bool LUKS2_segment_is_hw_opal_crypt(struct luks2_hdr *hdr, int segment)
{
	return json_segment_is_hw_opal_crypt(LUKS2_get_segment_jobj(hdr, segment));
}

bool LUKS2_segment_is_hw_opal(struct luks2_hdr *hdr, int segment)
{
	return json_segment_is_hw_opal(LUKS2_get_segment_jobj(hdr, segment));
}

int LUKS2_get_opal_segment_number(struct luks2_hdr *hdr, int segment, uint32_t *ret_opal_segment_number)
{
	json_object *jobj_segment = LUKS2_get_segment_jobj(hdr, segment);

	assert(ret_opal_segment_number);

	if (!json_segment_is_hw_opal(jobj_segment))
		return -ENOENT;

	return json_segment_get_opal_segment_id(jobj_segment, ret_opal_segment_number);
}

int LUKS2_get_opal_key_size(struct luks2_hdr *hdr, int segment)
{
	size_t key_size = 0;
	json_object *jobj_segment = LUKS2_get_segment_jobj(hdr, segment);

	if (json_segment_get_opal_key_size(jobj_segment, &key_size) < 0)
		return 0;

	return key_size;
}

int LUKS2_last_segment_by_type(struct luks2_hdr *hdr, const char *type)
{
	json_object *jobj_segments;
	int last_found = -1;

	if (!type)
		return -1;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments))
		return -1;

	json_object_object_foreach(jobj_segments, slot, val) {
		if (json_segment_is_backup(val))
			continue;
		if (strcmp(type, json_segment_type(val) ?: ""))
			continue;

		if (atoi(slot) > last_found)
			last_found = atoi(slot);
	}

	return last_found;
}

int LUKS2_segment_by_type(struct luks2_hdr *hdr, const char *type)
{
	json_object *jobj_segments;
	int first_found = -1;

	if (!type)
		return -EINVAL;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments))
		return -EINVAL;

	json_object_object_foreach(jobj_segments, slot, val) {
		if (json_segment_is_backup(val))
			continue;
		if (strcmp(type, json_segment_type(val) ?: ""))
			continue;

		if (first_found < 0)
			first_found = atoi(slot);
		else if (atoi(slot) < first_found)
			first_found = atoi(slot);
	}

	return first_found;
}

int LUKS2_segment_first_unused_id(struct luks2_hdr *hdr)
{
	json_object *jobj_segments;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments))
		return -EINVAL;

	return json_object_object_length(jobj_segments);
}

int LUKS2_segment_set_flag(json_object *jobj_segment, const char *flag)
{
	json_object *jobj_flags;

	if (!jobj_segment || !flag)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_segment, "flags", &jobj_flags)) {
		jobj_flags = json_object_new_array();
		if (!jobj_flags)
			return -ENOMEM;
		json_object_object_add(jobj_segment, "flags", jobj_flags);
	}

	if (LUKS2_array_jobj(jobj_flags, flag))
		return 0;

	json_object_array_add(jobj_flags, json_object_new_string(flag));

	return 0;
}

int LUKS2_segments_set(struct crypt_device *cd, struct luks2_hdr *hdr,
		       json_object *jobj_segments, int commit)
{
	json_object_object_add(hdr->jobj, "segments", jobj_segments);

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

int LUKS2_get_segment_id_by_flag(struct luks2_hdr *hdr, const char *flag)
{
	json_object *jobj_flags, *jobj_segments = LUKS2_get_segments_jobj(hdr);

	if (!flag || !jobj_segments)
		return -ENOENT;

	json_object_object_foreach(jobj_segments, key, value) {
		if (!json_object_object_get_ex(value, "flags", &jobj_flags))
			continue;
		if (LUKS2_array_jobj(jobj_flags, flag))
			return atoi(key);
	}

	return -ENOENT;
}

json_object *LUKS2_get_segment_by_flag(struct luks2_hdr *hdr, const char *flag)
{
	json_object *jobj_flags, *jobj_segments = LUKS2_get_segments_jobj(hdr);

	if (!flag || !jobj_segments)
		return NULL;

	json_object_object_foreach(jobj_segments, key, value) {
		UNUSED(key);
		if (!json_object_object_get_ex(value, "flags", &jobj_flags))
			continue;
		if (LUKS2_array_jobj(jobj_flags, flag))
			return value;
	}

	return NULL;
}

/* compares key characteristics of both segments */
bool json_segment_cmp(json_object *jobj_segment_1, json_object *jobj_segment_2)
{
	const char *type = json_segment_type(jobj_segment_1);
	const char *type2 = json_segment_type(jobj_segment_2);

	if (!type || !type2)
		return false;

	if (strcmp(type, type2))
		return false;

	if (!strcmp(type, "crypt"))
		return (json_segment_get_sector_size(jobj_segment_1) == json_segment_get_sector_size(jobj_segment_2) &&
			!strcmp(json_segment_get_cipher(jobj_segment_1),
			        json_segment_get_cipher(jobj_segment_2)));

	return true;
}

bool LUKS2_segments_dynamic_size(struct luks2_hdr *hdr)
{
	json_object *jobj_segments, *jobj_size;

	assert(hdr);

	jobj_segments = LUKS2_get_segments_jobj(hdr);
	if (!jobj_segments)
		return false;

	json_object_object_foreach(jobj_segments, key, val) {
		UNUSED(key);

		if (json_segment_is_backup(val))
			continue;

		if (json_object_object_get_ex(val, "size", &jobj_size) &&
		    !strcmp(json_object_get_string(jobj_size), "dynamic"))
			return true;
	}

	return false;
}
