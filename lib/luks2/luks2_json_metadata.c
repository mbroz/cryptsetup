/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2020 Milan Broz
 * Copyright (C) 2015-2020 Ondrej Kozina
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

#include "luks2_internal.h"
#include "../integrity/integrity.h"
#include <assert.h>
#include <ctype.h>
#include <uuid/uuid.h>

#define LUKS_STRIPES 4000

struct interval {
	uint64_t offset;
	uint64_t length;
};

void hexprint_base64(struct crypt_device *cd, json_object *jobj,
		     const char *sep, const char *line_sep)
{
	char *buf = NULL;
	size_t buf_len;
	unsigned int i;

	if (!base64_decode_alloc(json_object_get_string(jobj),
				 json_object_get_string_len(jobj),
				 &buf, &buf_len))
		return;

	for (i = 0; i < buf_len; i++) {
		if (i && !(i % 16))
			log_std(cd, "\n\t%s", line_sep);
		log_std(cd, "%02hhx%s", buf[i], sep);
	}
	log_std(cd, "\n");
	free(buf);
}

void JSON_DBG(struct crypt_device *cd, json_object *jobj, const char *desc)
{
	if (desc)
		crypt_log(cd, CRYPT_LOG_DEBUG_JSON, desc);
	crypt_log(cd, CRYPT_LOG_DEBUG_JSON, json_object_to_json_string_ext(jobj,
		JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE));
}

/*
 * JSON array helpers
 */
struct json_object *LUKS2_array_jobj(struct json_object *array, const char *num)
{
	struct json_object *jobj1;
	int i;

	for (i = 0; i < (int) json_object_array_length(array); i++) {
		jobj1 = json_object_array_get_idx(array, i);
		if (!strcmp(num, json_object_get_string(jobj1)))
			return jobj1;
	}

	return NULL;
}

struct json_object *LUKS2_array_remove(struct json_object *array, const char *num)
{
	struct json_object *jobj1, *jobj_removing = NULL, *array_new;
	int i;

	jobj_removing = LUKS2_array_jobj(array, num);
	if (!jobj_removing)
		return NULL;

	/* Create new array without jobj_removing. */
	array_new = json_object_new_array();
	for (i = 0; i < (int) json_object_array_length(array); i++) {
		jobj1 = json_object_array_get_idx(array, i);
		if (jobj1 != jobj_removing)
			json_object_array_add(array_new, json_object_get(jobj1));
	}

	return array_new;
}

/*
 * JSON struct access helpers
 */
json_object *LUKS2_get_keyslot_jobj(struct luks2_hdr *hdr, int keyslot)
{
	json_object *jobj1, *jobj2;
	char keyslot_name[16];

	if (!hdr || keyslot < 0)
		return NULL;

	if (snprintf(keyslot_name, sizeof(keyslot_name), "%u", keyslot) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj1))
		return NULL;

	if (!json_object_object_get_ex(jobj1, keyslot_name, &jobj2))
		return NULL;

	return jobj2;
}

json_object *LUKS2_get_tokens_jobj(struct luks2_hdr *hdr)
{
	json_object *jobj_tokens;

	if (!hdr || !json_object_object_get_ex(hdr->jobj, "tokens", &jobj_tokens))
		return NULL;

	return jobj_tokens;
}

json_object *LUKS2_get_token_jobj(struct luks2_hdr *hdr, int token)
{
	json_object *jobj1, *jobj2;
	char token_name[16];

	if (!hdr || token < 0)
		return NULL;

	jobj1 = LUKS2_get_tokens_jobj(hdr);
	if (!jobj1)
		return NULL;

	if (snprintf(token_name, sizeof(token_name), "%u", token) < 1)
		return NULL;

	json_object_object_get_ex(jobj1, token_name, &jobj2);
	return jobj2;
}

json_object *LUKS2_get_digest_jobj(struct luks2_hdr *hdr, int digest)
{
	json_object *jobj1, *jobj2;
	char digest_name[16];

	if (!hdr || digest < 0)
		return NULL;

	if (snprintf(digest_name, sizeof(digest_name), "%u", digest) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "digests", &jobj1))
		return NULL;

	json_object_object_get_ex(jobj1, digest_name, &jobj2);
	return jobj2;
}

static json_object *json_get_segments_jobj(json_object *hdr_jobj)
{
	json_object *jobj_segments;

	if (!hdr_jobj || !json_object_object_get_ex(hdr_jobj, "segments", &jobj_segments))
		return NULL;

	return jobj_segments;
}

json_object *LUKS2_get_segment_jobj(struct luks2_hdr *hdr, int segment)
{
	if (!hdr)
		return NULL;

	if (segment == CRYPT_DEFAULT_SEGMENT)
		segment = LUKS2_get_default_segment(hdr);

	return json_segments_get_segment(json_get_segments_jobj(hdr->jobj), segment);
}

json_object *LUKS2_get_segments_jobj(struct luks2_hdr *hdr)
{
	return hdr ? json_get_segments_jobj(hdr->jobj) : NULL;
}

int LUKS2_segments_count(struct luks2_hdr *hdr)
{
	if (!hdr)
		return -EINVAL;

	return json_segments_count(LUKS2_get_segments_jobj(hdr));
}

int LUKS2_get_default_segment(struct luks2_hdr *hdr)
{
	int s = LUKS2_get_segment_id_by_flag(hdr, "backup-final");
	if (s >= 0)
		return s;

	if (LUKS2_segments_count(hdr) == 1)
		return 0;

	return -EINVAL;
}

/*
 * json_type_int needs to be validated first.
 * See validate_json_uint32()
 */
uint32_t crypt_jobj_get_uint32(json_object *jobj)
{
	return json_object_get_int64(jobj);
}

/* jobj has to be json_type_string and numbered */
static json_bool json_str_to_uint64(json_object *jobj, uint64_t *value)
{
	char *endptr;
	unsigned long long tmp;

	errno = 0;
	tmp = strtoull(json_object_get_string(jobj), &endptr, 10);
	if (*endptr || errno) {
		*value = 0;
		return 0;
	}

	*value = tmp;
	return 1;
}

uint64_t crypt_jobj_get_uint64(json_object *jobj)
{
	uint64_t r;
	json_str_to_uint64(jobj, &r);
	return r;
}

json_object *crypt_jobj_new_uint64(uint64_t value)
{
	/* 18446744073709551615 */
	char num[21];
	int r;
	json_object *jobj;

	r = snprintf(num, sizeof(num), "%" PRIu64, value);
	if (r < 0 || (size_t)r >= sizeof(num))
		return NULL;

	jobj = json_object_new_string(num);
	return jobj;
}

/*
 * Validate helpers
 */
static json_bool numbered(struct crypt_device *cd, const char *name, const char *key)
{
	int i;

	for (i = 0; key[i]; i++)
		if (!isdigit(key[i])) {
			log_dbg(cd, "%s \"%s\" is not in numbered form.", name, key);
			return 0;
		}
	return 1;
}

json_object *json_contains(struct crypt_device *cd, json_object *jobj, const char *name,
			   const char *section, const char *key, json_type type)
{
	json_object *sobj;

	if (!json_object_object_get_ex(jobj, key, &sobj) ||
	    !json_object_is_type(sobj, type)) {
		log_dbg(cd, "%s \"%s\" is missing \"%s\" (%s) specification.",
			section, name, key, json_type_to_name(type));
		return NULL;
	}

	return sobj;
}

json_bool validate_json_uint32(json_object *jobj)
{
	int64_t tmp;

	errno = 0;
	tmp = json_object_get_int64(jobj);

	return (errno || tmp < 0 || tmp > UINT32_MAX) ? 0 : 1;
}

static json_bool validate_keyslots_array(struct crypt_device *cd,
					 json_object *jarr, json_object *jobj_keys)
{
	json_object *jobj;
	int i = 0, length = (int) json_object_array_length(jarr);

	while (i < length) {
		jobj = json_object_array_get_idx(jarr, i);
		if (!json_object_is_type(jobj, json_type_string)) {
			log_dbg(cd, "Illegal value type in keyslots array at index %d.", i);
			return 0;
		}

		if (!json_contains(cd, jobj_keys, "", "Keyslots section",
				   json_object_get_string(jobj), json_type_object))
			return 0;

		i++;
	}

	return 1;
}

static json_bool validate_segments_array(struct crypt_device *cd,
					 json_object *jarr, json_object *jobj_segments)
{
	json_object *jobj;
	int i = 0, length = (int) json_object_array_length(jarr);

	while (i < length) {
		jobj = json_object_array_get_idx(jarr, i);
		if (!json_object_is_type(jobj, json_type_string)) {
			log_dbg(cd, "Illegal value type in segments array at index %d.", i);
			return 0;
		}

		if (!json_contains(cd, jobj_segments, "", "Segments section",
				   json_object_get_string(jobj), json_type_object))
			return 0;

		i++;
	}

	return 1;
}

static json_bool segment_has_digest(const char *segment_name, json_object *jobj_digests)
{
	json_object *jobj_segments;

	json_object_object_foreach(jobj_digests, key, val) {
		UNUSED(key);
		json_object_object_get_ex(val, "segments", &jobj_segments);
		if (LUKS2_array_jobj(jobj_segments, segment_name))
			return 1;
	}

	return 0;
}

static json_bool validate_intervals(struct crypt_device *cd,
				    int length, const struct interval *ix,
				    uint64_t metadata_size, uint64_t keyslots_area_end)
{
	int j, i = 0;

	while (i < length) {
		if (ix[i].offset < 2 * metadata_size) {
			log_dbg(cd, "Illegal area offset: %" PRIu64 ".", ix[i].offset);
			return 0;
		}

		if (!ix[i].length) {
			log_dbg(cd, "Area length must be greater than zero.");
			return 0;
		}

		if ((ix[i].offset + ix[i].length) > keyslots_area_end) {
			log_dbg(cd, "Area [%" PRIu64 ", %" PRIu64 "] overflows binary keyslots area (ends at offset: %" PRIu64 ").",
				ix[i].offset, ix[i].offset + ix[i].length, keyslots_area_end);
			return 0;
		}

		for (j = 0; j < length; j++) {
			if (i == j)
				continue;
			if ((ix[i].offset >= ix[j].offset) && (ix[i].offset < (ix[j].offset + ix[j].length))) {
				log_dbg(cd, "Overlapping areas [%" PRIu64 ",%" PRIu64 "] and [%" PRIu64 ",%" PRIu64 "].",
					ix[i].offset, ix[i].offset + ix[i].length,
					ix[j].offset, ix[j].offset + ix[j].length);
				return 0;
			}
		}

		i++;
	}

	return 1;
}

static int LUKS2_keyslot_validate(struct crypt_device *cd, json_object *hdr_jobj, json_object *hdr_keyslot, const char *key)
{
	json_object *jobj_key_size;

	if (!json_contains(cd, hdr_keyslot, key, "Keyslot", "type", json_type_string))
		return 1;
	if (!(jobj_key_size = json_contains(cd, hdr_keyslot, key, "Keyslot", "key_size", json_type_int)))
		return 1;

	/* enforce uint32_t type */
	if (!validate_json_uint32(jobj_key_size)) {
		log_dbg(cd, "Illegal field \"key_size\":%s.",
			json_object_get_string(jobj_key_size));
		return 1;
	}

	return 0;
}

int LUKS2_token_validate(struct crypt_device *cd,
			 json_object *hdr_jobj, json_object *jobj_token, const char *key)
{
	json_object *jarr, *jobj_keyslots;

	/* keyslots are not yet validated, but we need to know token doesn't reference missing keyslot */
	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return 1;

	if (!json_contains(cd, jobj_token, key, "Token", "type", json_type_string))
		return 1;

	jarr = json_contains(cd, jobj_token, key, "Token", "keyslots", json_type_array);
	if (!jarr)
		return 1;

	if (!validate_keyslots_array(cd, jarr, jobj_keyslots))
		return 1;

	return 0;
}

static int hdr_validate_json_size(struct crypt_device *cd, json_object *hdr_jobj, uint64_t hdr_json_size)
{
	json_object *jobj, *jobj1;
	const char *json;
	uint64_t json_area_size, json_size;

	json_object_object_get_ex(hdr_jobj, "config", &jobj);
	json_object_object_get_ex(jobj, "json_size", &jobj1);

	json = json_object_to_json_string_ext(hdr_jobj,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	json_area_size = crypt_jobj_get_uint64(jobj1);
	json_size = (uint64_t)strlen(json);

	if (hdr_json_size != json_area_size) {
		log_dbg(cd, "JSON area size does not match value in binary header.");
		return 1;
	}

	if (json_size > json_area_size) {
		log_dbg(cd, "JSON does not fit in the designated area.");
		return 1;
	}

	return 0;
}

int LUKS2_check_json_size(struct crypt_device *cd, const struct luks2_hdr *hdr)
{
	return hdr_validate_json_size(cd, hdr->jobj, hdr->hdr_size - LUKS2_HDR_BIN_LEN);
}

static int hdr_validate_keyslots(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj;

	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj)) {
		log_dbg(cd, "Missing keyslots section.");
		return 1;
	}

	json_object_object_foreach(jobj, key, val) {
		if (!numbered(cd, "Keyslot", key))
			return 1;
		if (LUKS2_keyslot_validate(cd, hdr_jobj, val, key))
			return 1;
	}

	return 0;
}

static int hdr_validate_tokens(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj;

	if (!json_object_object_get_ex(hdr_jobj, "tokens", &jobj)) {
		log_dbg(cd, "Missing tokens section.");
		return 1;
	}

	json_object_object_foreach(jobj, key, val) {
		if (!numbered(cd, "Token", key))
			return 1;
		if (LUKS2_token_validate(cd, hdr_jobj, val, key))
			return 1;
	}

	return 0;
}

static int hdr_validate_crypt_segment(struct crypt_device *cd,
				      json_object *jobj, const char *key, json_object *jobj_digests,
	uint64_t offset, uint64_t size)
{
	json_object *jobj_ivoffset, *jobj_sector_size, *jobj_integrity;
	uint32_t sector_size;
	uint64_t ivoffset;

	if (!(jobj_ivoffset = json_contains(cd, jobj, key, "Segment", "iv_tweak", json_type_string)) ||
	    !json_contains(cd, jobj, key, "Segment", "encryption", json_type_string) ||
	    !(jobj_sector_size = json_contains(cd, jobj, key, "Segment", "sector_size", json_type_int)))
		return 1;

	/* integrity */
	if (json_object_object_get_ex(jobj, "integrity", &jobj_integrity)) {
		if (!json_contains(cd, jobj, key, "Segment", "integrity", json_type_object) ||
		    !json_contains(cd, jobj_integrity, key, "Segment integrity", "type", json_type_string) ||
		    !json_contains(cd, jobj_integrity, key, "Segment integrity", "journal_encryption", json_type_string) ||
		    !json_contains(cd, jobj_integrity, key, "Segment integrity", "journal_integrity", json_type_string))
			return 1;
	}

	/* enforce uint32_t type */
	if (!validate_json_uint32(jobj_sector_size)) {
		log_dbg(cd, "Illegal field \"sector_size\":%s.",
			json_object_get_string(jobj_sector_size));
		return 1;
	}

	sector_size = crypt_jobj_get_uint32(jobj_sector_size);
	if (!sector_size || MISALIGNED_512(sector_size)) {
		log_dbg(cd, "Illegal sector size: %" PRIu32, sector_size);
		return 1;
	}

	if (!numbered(cd, "iv_tweak", json_object_get_string(jobj_ivoffset)) ||
	    !json_str_to_uint64(jobj_ivoffset, &ivoffset)) {
		log_dbg(cd, "Illegal iv_tweak value.");
		return 1;
	}

	if (size % sector_size) {
		log_dbg(cd, "Size field has to be aligned to sector size: %" PRIu32, sector_size);
		return 1;
	}

	return !segment_has_digest(key, jobj_digests);
}

static bool validate_segment_intervals(struct crypt_device *cd,
				    int length, const struct interval *ix)
{
	int j, i = 0;

	while (i < length) {
		if (ix[i].length == UINT64_MAX && (i != (length - 1))) {
			log_dbg(cd, "Only last regular segment is allowed to have 'dynamic' size.");
			return false;
		}

		for (j = 0; j < length; j++) {
			if (i == j)
				continue;
			if ((ix[i].offset >= ix[j].offset) && (ix[j].length == UINT64_MAX || (ix[i].offset < (ix[j].offset + ix[j].length)))) {
				log_dbg(cd, "Overlapping segments [%" PRIu64 ",%" PRIu64 "]%s and [%" PRIu64 ",%" PRIu64 "]%s.",
					ix[i].offset, ix[i].offset + ix[i].length, ix[i].length == UINT64_MAX ? "(dynamic)" : "",
					ix[j].offset, ix[j].offset + ix[j].length, ix[j].length == UINT64_MAX ? "(dynamic)" : "");
				return false;
			}
		}

		i++;
	}

	return true;
}

static int hdr_validate_segments(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj_segments, *jobj_digests, *jobj_offset, *jobj_size, *jobj_type, *jobj_flags, *jobj;
	struct interval *intervals;
	uint64_t offset, size;
	int i, r, count, first_backup = -1;

	if (!json_object_object_get_ex(hdr_jobj, "segments", &jobj_segments)) {
		log_dbg(cd, "Missing segments section.");
		return 1;
	}

	count = json_object_object_length(jobj_segments);
	if (count < 1) {
		log_dbg(cd, "Empty segments section.");
		return 1;
	}

	/* digests should already be validated */
	if (!json_object_object_get_ex(hdr_jobj, "digests", &jobj_digests))
		return 1;

	json_object_object_foreach(jobj_segments, key, val) {
		if (!numbered(cd, "Segment", key))
			return 1;

		/* those fields are mandatory for all segment types */
		if (!(jobj_type =   json_contains(cd, val, key, "Segment", "type",   json_type_string)) ||
		    !(jobj_offset = json_contains(cd, val, key, "Segment", "offset", json_type_string)) ||
		    !(jobj_size =   json_contains(cd, val, key, "Segment", "size",   json_type_string)))
			return 1;

		if (!numbered(cd, "offset", json_object_get_string(jobj_offset)) ||
		    !json_str_to_uint64(jobj_offset, &offset))
			return 1;

		/* size "dynamic" means whole device starting at 'offset' */
		if (strcmp(json_object_get_string(jobj_size), "dynamic")) {
			if (!numbered(cd, "size", json_object_get_string(jobj_size)) ||
			    !json_str_to_uint64(jobj_size, &size) || !size)
				return 1;
		} else
			size = 0;

		/* all device-mapper devices are aligned to 512 sector size */
		if (MISALIGNED_512(offset)) {
			log_dbg(cd, "Offset field has to be aligned to sector size: %" PRIu32, SECTOR_SIZE);
			return 1;
		}
		if (MISALIGNED_512(size)) {
			log_dbg(cd, "Size field has to be aligned to sector size: %" PRIu32, SECTOR_SIZE);
			return 1;
		}

		/* flags array is optional and must contain strings */
		if (json_object_object_get_ex(val, "flags", NULL)) {
			if (!(jobj_flags = json_contains(cd, val, key, "Segment", "flags", json_type_array)))
				return 1;
			for (i = 0; i < (int) json_object_array_length(jobj_flags); i++)
				if (!json_object_is_type(json_object_array_get_idx(jobj_flags, i), json_type_string))
					return 1;
		}

		i = atoi(key);
		if (json_segment_is_backup(val)) {
			if (first_backup < 0 || i < first_backup)
				first_backup = i;
		} else {
			if ((first_backup >= 0) && i >= first_backup) {
				log_dbg(cd, "Regular segment at %d is behind backup segment at %d", i, first_backup);
				return 1;
			}
		}

		/* crypt */
		if (!strcmp(json_object_get_string(jobj_type), "crypt") &&
		    hdr_validate_crypt_segment(cd, val, key, jobj_digests, offset, size))
			return 1;
	}

	if (first_backup == 0) {
		log_dbg(cd, "No regular segment.");
		return 1;
	}

	if (first_backup < 0)
		first_backup = count;

	intervals = malloc(first_backup * sizeof(*intervals));
	if (!intervals) {
		log_dbg(cd, "Not enough memory.");
		return 1;
	}

	for (i = 0; i < first_backup; i++) {
		jobj = json_segments_get_segment(jobj_segments, i);
		if (!jobj) {
			log_dbg(cd, "Gap at key %d in segments object.", i);
			free(intervals);
			return 1;
		}
		intervals[i].offset = json_segment_get_offset(jobj, 0);
		intervals[i].length = json_segment_get_size(jobj, 0) ?: UINT64_MAX;
	}

	r = !validate_segment_intervals(cd, first_backup, intervals);
	free(intervals);

	if (r)
		return 1;

	for (; i < count; i++) {
		if (!json_segments_get_segment(jobj_segments, i)) {
			log_dbg(cd, "Gap at key %d in segments object.", i);
			return 1;
		}
	}

	return 0;
}

uint64_t LUKS2_metadata_size(json_object *jobj)
{
	json_object *jobj1, *jobj2;
	uint64_t json_size;

	json_object_object_get_ex(jobj, "config", &jobj1);
	json_object_object_get_ex(jobj1, "json_size", &jobj2);
	json_str_to_uint64(jobj2, &json_size);

	return json_size + LUKS2_HDR_BIN_LEN;
}

static int hdr_validate_areas(struct crypt_device *cd, json_object *hdr_jobj)
{
	struct interval *intervals;
	json_object *jobj_keyslots, *jobj_offset, *jobj_length, *jobj_segments, *jobj_area;
	int length, ret, i = 0;
	uint64_t metadata_size;

	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return 1;

	/* segments are already validated */
	if (!json_object_object_get_ex(hdr_jobj, "segments", &jobj_segments))
		return 1;

	/* config is already validated */
	metadata_size = LUKS2_metadata_size(hdr_jobj);

	length = json_object_object_length(jobj_keyslots);

	/* Empty section */
	if (length == 0)
		return 0;

	if (length < 0) {
		log_dbg(cd, "Invalid keyslot areas specification.");
		return 1;
	}

	intervals = malloc(length * sizeof(*intervals));
	if (!intervals) {
		log_dbg(cd, "Not enough memory.");
		return -ENOMEM;
	}

	json_object_object_foreach(jobj_keyslots, key, val) {

		if (!(jobj_area = json_contains(cd, val, key, "Keyslot", "area", json_type_object)) ||
		    !json_contains(cd, jobj_area, key, "Keyslot area", "type", json_type_string) ||
		    !(jobj_offset = json_contains(cd, jobj_area, key, "Keyslot", "offset", json_type_string)) ||
		    !(jobj_length = json_contains(cd, jobj_area, key, "Keyslot", "size", json_type_string)) ||
		    !numbered(cd, "offset", json_object_get_string(jobj_offset)) ||
		    !numbered(cd, "size", json_object_get_string(jobj_length))) {
			free(intervals);
			return 1;
		}

		/* rule out values > UINT64_MAX */
		if (!json_str_to_uint64(jobj_offset, &intervals[i].offset) ||
		    !json_str_to_uint64(jobj_length, &intervals[i].length)) {
			free(intervals);
			return 1;
		}

		i++;
	}

	if (length != i) {
		free(intervals);
		return 1;
	}

	ret = validate_intervals(cd, length, intervals, metadata_size, LUKS2_hdr_and_areas_size(hdr_jobj)) ? 0 : 1;

	free(intervals);

	return ret;
}

static int hdr_validate_digests(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jarr_keys, *jarr_segs, *jobj, *jobj_keyslots, *jobj_segments;

	if (!json_object_object_get_ex(hdr_jobj, "digests", &jobj)) {
		log_dbg(cd, "Missing digests section.");
		return 1;
	}

	/* keyslots are not yet validated, but we need to know digest doesn't reference missing keyslot */
	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return 1;

	/* segments are not yet validated, but we need to know digest doesn't reference missing segment */
	if (!json_object_object_get_ex(hdr_jobj, "segments", &jobj_segments))
		return 1;

	json_object_object_foreach(jobj, key, val) {
		if (!numbered(cd, "Digest", key))
			return 1;

		if (!json_contains(cd, val, key, "Digest", "type", json_type_string) ||
		    !(jarr_keys = json_contains(cd, val, key, "Digest", "keyslots", json_type_array)) ||
		    !(jarr_segs = json_contains(cd, val, key, "Digest", "segments", json_type_array)))
			return 1;

		if (!validate_keyslots_array(cd, jarr_keys, jobj_keyslots))
			return 1;
		if (!validate_segments_array(cd, jarr_segs, jobj_segments))
			return 1;
	}

	return 0;
}

static int hdr_validate_config(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj_config, *jobj, *jobj1;
	int i;
	uint64_t keyslots_size, metadata_size, segment_offset;

	if (!json_object_object_get_ex(hdr_jobj, "config", &jobj_config)) {
		log_dbg(cd, "Missing config section.");
		return 1;
	}

	if (!(jobj = json_contains(cd, jobj_config, "section", "Config", "json_size", json_type_string)) ||
	    !json_str_to_uint64(jobj, &metadata_size))
		return 1;

	/* single metadata instance is assembled from json area size plus
	 * binary header size */
	metadata_size += LUKS2_HDR_BIN_LEN;

	if (!(jobj = json_contains(cd, jobj_config, "section", "Config", "keyslots_size", json_type_string)) ||
	    !json_str_to_uint64(jobj, &keyslots_size))
		return 1;

	if (LUKS2_check_metadata_area_size(metadata_size)) {
		log_dbg(cd, "Unsupported LUKS2 header size (%" PRIu64 ").", metadata_size);
		return 1;
	}

	if (LUKS2_check_keyslots_area_size(keyslots_size)) {
		log_dbg(cd, "Unsupported LUKS2 keyslots size (%" PRIu64 ").", keyslots_size);
		return 1;
	}

	/*
	 * validate keyslots_size fits in between (2 * metadata_size) and first
	 * segment_offset (except detached header)
	 */
	segment_offset = json_segments_get_minimal_offset(json_get_segments_jobj(hdr_jobj), 0);
	if (segment_offset &&
	    (segment_offset < keyslots_size ||
	     (segment_offset - keyslots_size) < (2 * metadata_size))) {
		log_dbg(cd, "keyslots_size is too large %" PRIu64 " (bytes). Data offset: %" PRIu64
			", keyslots offset: %" PRIu64, keyslots_size, segment_offset, 2 * metadata_size);
		return 1;
	}

	/* Flags array is optional */
	if (json_object_object_get_ex(jobj_config, "flags", &jobj)) {
		if (!json_contains(cd, jobj_config, "section", "Config", "flags", json_type_array))
			return 1;

		/* All array members must be strings */
		for (i = 0; i < (int) json_object_array_length(jobj); i++)
			if (!json_object_is_type(json_object_array_get_idx(jobj, i), json_type_string))
				return 1;
	}

	/* Requirements object is optional */
	if (json_object_object_get_ex(jobj_config, "requirements", &jobj)) {
		if (!json_contains(cd, jobj_config, "section", "Config", "requirements", json_type_object))
			return 1;

		/* Mandatory array is optional */
		if (json_object_object_get_ex(jobj, "mandatory", &jobj1)) {
			if (!json_contains(cd, jobj, "section", "Requirements", "mandatory", json_type_array))
				return 1;

			/* All array members must be strings */
			for (i = 0; i < (int) json_object_array_length(jobj1); i++)
				if (!json_object_is_type(json_object_array_get_idx(jobj1, i), json_type_string))
					return 1;
		}
	}

	return 0;
}

int LUKS2_hdr_validate(struct crypt_device *cd, json_object *hdr_jobj, uint64_t json_size)
{
	struct {
		int (*validate)(struct crypt_device *, json_object *);
	} checks[] = {
		{ hdr_validate_tokens   },
		{ hdr_validate_digests  },
		{ hdr_validate_segments },
		{ hdr_validate_keyslots },
		{ hdr_validate_config   },
		{ hdr_validate_areas    },
		{ NULL }
	};
	int i;

	if (!hdr_jobj)
		return 1;

	for (i = 0; checks[i].validate; i++)
		if (checks[i].validate && checks[i].validate(cd, hdr_jobj))
			return 1;

	if (hdr_validate_json_size(cd, hdr_jobj, json_size))
		return 1;

	/* validate keyslot implementations */
	if (LUKS2_keyslots_validate(cd, hdr_jobj))
		return 1;

	return 0;
}

/* FIXME: should we expose do_recovery parameter explicitly? */
int LUKS2_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr, int repair)
{
	int r;

	r = device_read_lock(cd, crypt_metadata_device(cd));
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s."),
			device_path(crypt_metadata_device(cd)));
		return r;
	}

	r = LUKS2_disk_hdr_read(cd, hdr, crypt_metadata_device(cd), 1, !repair);
	if (r == -EAGAIN) {
		/* unlikely: auto-recovery is required and failed due to read lock being held */
		device_read_unlock(cd, crypt_metadata_device(cd));

		/* Do not use LUKS2_device_write lock. Recovery. */
		r = device_write_lock(cd, crypt_metadata_device(cd));
		if (r < 0) {
			log_err(cd, _("Failed to acquire write lock on device %s."),
				device_path(crypt_metadata_device(cd)));
			return r;
		}

		r = LUKS2_disk_hdr_read(cd, hdr, crypt_metadata_device(cd), 1, !repair);

		device_write_unlock(cd, crypt_metadata_device(cd));
	} else
		device_read_unlock(cd, crypt_metadata_device(cd));

	return r;
}

static int hdr_cleanup_and_validate(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	LUKS2_digests_erase_unused(cd, hdr);

	return LUKS2_hdr_validate(cd, hdr->jobj, hdr->hdr_size - LUKS2_HDR_BIN_LEN);
}

int LUKS2_hdr_write_force(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	if (hdr_cleanup_and_validate(cd, hdr))
		return -EINVAL;

	return LUKS2_disk_hdr_write(cd, hdr, crypt_metadata_device(cd), false);
}

int LUKS2_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	if (hdr_cleanup_and_validate(cd, hdr))
		return -EINVAL;

	return LUKS2_disk_hdr_write(cd, hdr, crypt_metadata_device(cd), true);
}

int LUKS2_hdr_uuid(struct crypt_device *cd, struct luks2_hdr *hdr, const char *uuid)
{
	uuid_t partitionUuid;

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(cd, _("Wrong LUKS UUID format provided."));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	uuid_unparse(partitionUuid, hdr->uuid);

	return LUKS2_hdr_write(cd, hdr);
}

int LUKS2_hdr_labels(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *label, const char *subsystem, int commit)
{
	//FIXME: check if the labels are the same and skip this.

	memset(hdr->label, 0, LUKS2_LABEL_L);
	if (label)
		strncpy(hdr->label, label, LUKS2_LABEL_L-1);

	memset(hdr->subsystem, 0, LUKS2_LABEL_L);
	if (subsystem)
		strncpy(hdr->subsystem, subsystem, LUKS2_LABEL_L-1);

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

void LUKS2_hdr_free(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	if (json_object_put(hdr->jobj))
		hdr->jobj = NULL;
	else if (hdr->jobj)
		log_dbg(cd, "LUKS2 header still in use");
}

uint64_t LUKS2_keyslots_size(json_object *jobj)
{
	json_object *jobj1, *jobj2;
	uint64_t keyslots_size;

	json_object_object_get_ex(jobj, "config", &jobj1);
	json_object_object_get_ex(jobj1, "keyslots_size", &jobj2);
	json_str_to_uint64(jobj2, &keyslots_size);

	return keyslots_size;
}

uint64_t LUKS2_hdr_and_areas_size(json_object *jobj)
{
	return 2 * LUKS2_metadata_size(jobj) + LUKS2_keyslots_size(jobj);
}

int LUKS2_hdr_backup(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file)
{
	struct device *device = crypt_metadata_device(cd);
	int fd, devfd, r = 0;
	ssize_t hdr_size;
	ssize_t ret, buffer_size;
	char *buffer = NULL;

	hdr_size = LUKS2_hdr_and_areas_size(hdr->jobj);
	buffer_size = size_round_up(hdr_size, crypt_getpagesize());

	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer)
		return -ENOMEM;

	log_dbg(cd, "Storing backup of header (%zu bytes).", hdr_size);
	log_dbg(cd, "Output backup file size: %zu bytes.", buffer_size);

	r = device_read_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s."),
			device_path(crypt_metadata_device(cd)));
		crypt_safe_free(buffer);
		return r;
	}

	devfd = device_open_locked(cd, device, O_RDONLY);
	if (devfd < 0) {
		device_read_unlock(cd, device);
		log_err(cd, _("Device %s is not a valid LUKS device."), device_path(device));
		crypt_safe_free(buffer);
		return devfd == -1 ? -EINVAL : devfd;
	}

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
			   device_alignment(device), buffer, hdr_size, 0) < hdr_size) {
		device_read_unlock(cd, device);
		crypt_safe_free(buffer);
		return -EIO;
	}

	device_read_unlock(cd, device);

	fd = open(backup_file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR);
	if (fd == -1) {
		if (errno == EEXIST)
			log_err(cd, _("Requested header backup file %s already exists."), backup_file);
		else
			log_err(cd, _("Cannot create header backup file %s."), backup_file);
		crypt_safe_free(buffer);
		return -EINVAL;
	}
	ret = write_buffer(fd, buffer, buffer_size);
	close(fd);
	if (ret < buffer_size) {
		log_err(cd, _("Cannot write header backup file %s."), backup_file);
		r = -EIO;
	} else
		r = 0;

	crypt_safe_free(buffer);
	return r;
}

static int reqs_unknown(uint32_t reqs)
{
	return reqs & CRYPT_REQUIREMENT_UNKNOWN;
}

static int reqs_reencrypt(uint32_t reqs)
{
	return reqs & CRYPT_REQUIREMENT_OFFLINE_REENCRYPT;
}

static int reqs_reencrypt_online(uint32_t reqs)
{
	return reqs & CRYPT_REQUIREMENT_ONLINE_REENCRYPT;
}

int LUKS2_hdr_restore(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file)
{
	struct device *backup_device, *device = crypt_metadata_device(cd);
	int r, fd, devfd = -1, diff_uuid = 0;
	ssize_t ret, buffer_size = 0;
	char *buffer = NULL, msg[1024];
	struct luks2_hdr hdr_file;
	struct luks2_hdr tmp_hdr = {};
	uint32_t reqs = 0;

	r = device_alloc(cd, &backup_device, backup_file);
	if (r < 0)
		return r;

	r = device_read_lock(cd, backup_device);
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s."),
			device_path(backup_device));
		device_free(cd, backup_device);
		return r;
	}

	r = LUKS2_disk_hdr_read(cd, &hdr_file, backup_device, 0, 0);
	device_read_unlock(cd, backup_device);
	device_free(cd, backup_device);

	if (r < 0) {
		log_err(cd, _("Backup file does not contain valid LUKS header."));
		goto out;
	}

	/* do not allow header restore from backup with unmet requirements */
	if (LUKS2_unmet_requirements(cd, &hdr_file, CRYPT_REQUIREMENT_ONLINE_REENCRYPT, 1)) {
		log_err(cd, _("Forbidden LUKS2 requirements detected in backup %s."),
			backup_file);
		r = -ETXTBSY;
		goto out;
	}

	buffer_size = LUKS2_hdr_and_areas_size(hdr_file.jobj);
	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer) {
		r = -ENOMEM;
		goto out;
	}

	fd = open(backup_file, O_RDONLY);
	if (fd == -1) {
		log_err(cd, _("Cannot open header backup file %s."), backup_file);
		r = -EINVAL;
		goto out;
	}

	ret = read_buffer(fd, buffer, buffer_size);
	close(fd);
	if (ret < buffer_size) {
		log_err(cd, _("Cannot read header backup file %s."), backup_file);
		r = -EIO;
		goto out;
	}

	r = LUKS2_hdr_read(cd, &tmp_hdr, 0);
	if (r == 0) {
		log_dbg(cd, "Device %s already contains LUKS2 header, checking UUID and requirements.", device_path(device));
		r = LUKS2_config_get_requirements(cd, &tmp_hdr, &reqs);
		if (r)
			goto out;

		if (memcmp(tmp_hdr.uuid, hdr_file.uuid, LUKS2_UUID_L))
			diff_uuid = 1;

		if (!reqs_reencrypt(reqs)) {
			log_dbg(cd, "Checking LUKS2 header size and offsets.");
			if (LUKS2_get_data_offset(&tmp_hdr) != LUKS2_get_data_offset(&hdr_file)) {
				log_err(cd, _("Data offset differ on device and backup, restore failed."));
				r = -EINVAL;
				goto out;
			}
			/* FIXME: what could go wrong? Erase if we're fine with consequences */
			if (buffer_size != (ssize_t) LUKS2_hdr_and_areas_size(tmp_hdr.jobj)) {
				log_err(cd, _("Binary header with keyslot areas size differ on device and backup, restore failed."));
				r = -EINVAL;
				goto out;
			}
		}
	}

	r = snprintf(msg, sizeof(msg), _("Device %s %s%s%s%s"), device_path(device),
		     r ? _("does not contain LUKS2 header. Replacing header can destroy data on that device.") :
			 _("already contains LUKS2 header. Replacing header will destroy existing keyslots."),
		     diff_uuid ? _("\nWARNING: real device header has different UUID than backup!") : "",
		     reqs_unknown(reqs) ? _("\nWARNING: unknown LUKS2 requirements detected in real device header!"
					    "\nReplacing header with backup may corrupt the data on that device!") : "",
		     reqs_reencrypt(reqs) ? _("\nWARNING: Unfinished offline reencryption detected on the device!"
					      "\nReplacing header with backup may corrupt data.") : "");
	if (r < 0 || (size_t) r >= sizeof(msg)) {
		r = -ENOMEM;
		goto out;
	}

	if (!crypt_confirm(cd, msg)) {
		r = -EINVAL;
		goto out;
	}

	log_dbg(cd, "Storing backup of header (%zu bytes) to device %s.", buffer_size, device_path(device));

	/* Do not use LUKS2_device_write lock for checking sequence id on restore */
	r = device_write_lock(cd, device);
	if (r < 0) {
		log_err(cd, _("Failed to acquire write lock on device %s."),
			device_path(device));
		goto out;
	}

	devfd = device_open_locked(cd, device, O_RDWR);
	if (devfd < 0) {
		if (errno == EACCES)
			log_err(cd, _("Cannot write to device %s, permission denied."),
				device_path(device));
		else
			log_err(cd, _("Cannot open device %s."), device_path(device));
		device_write_unlock(cd, device);
		r = -EINVAL;
		goto out;
	}

	if (write_lseek_blockwise(devfd, device_block_size(cd, device),
			    device_alignment(device), buffer, buffer_size, 0) < buffer_size)
		r = -EIO;
	else
		r = 0;

	device_write_unlock(cd, device);
out:
	LUKS2_hdr_free(cd, hdr);
	LUKS2_hdr_free(cd, &hdr_file);
	LUKS2_hdr_free(cd, &tmp_hdr);
	crypt_safe_memzero(&hdr_file, sizeof(hdr_file));
	crypt_safe_memzero(&tmp_hdr, sizeof(tmp_hdr));
	crypt_safe_free(buffer);

	device_sync(cd, device);

	return r;
}

/*
 * Persistent config flags
 */
static const struct  {
	uint32_t flag;
	const char *description;
} persistent_flags[] = {
	{ CRYPT_ACTIVATE_ALLOW_DISCARDS,         "allow-discards" },
	{ CRYPT_ACTIVATE_SAME_CPU_CRYPT,         "same-cpu-crypt" },
	{ CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS, "submit-from-crypt-cpus" },
	{ CRYPT_ACTIVATE_NO_JOURNAL,             "no-journal" },
	{ 0, NULL }
};

int LUKS2_config_get_flags(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t *flags)
{
	json_object *jobj1, *jobj_config, *jobj_flags;
	int i, j, found;

	if (!hdr || !flags)
		return -EINVAL;

	*flags = 0;

	if (!json_object_object_get_ex(hdr->jobj, "config", &jobj_config))
		return 0;

	if (!json_object_object_get_ex(jobj_config, "flags", &jobj_flags))
		return 0;

	for (i = 0; i < (int) json_object_array_length(jobj_flags); i++) {
		jobj1 = json_object_array_get_idx(jobj_flags, i);
		found = 0;
		for (j = 0; persistent_flags[j].description && !found; j++)
			if (!strcmp(persistent_flags[j].description,
				    json_object_get_string(jobj1))) {
				*flags |= persistent_flags[j].flag;
				log_dbg(cd, "Using persistent flag %s.",
					json_object_get_string(jobj1));
				found = 1;
			}
		if (!found)
			log_verbose(cd, _("Ignored unknown flag %s."),
				    json_object_get_string(jobj1));
	}

	return 0;
}

int LUKS2_config_set_flags(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t flags)
{
	json_object *jobj_config, *jobj_flags;
	int i;

	if (!json_object_object_get_ex(hdr->jobj, "config", &jobj_config))
		return 0;

	jobj_flags = json_object_new_array();

	for (i = 0; persistent_flags[i].description; i++) {
		if (flags & persistent_flags[i].flag) {
			log_dbg(cd, "Setting persistent flag: %s.", persistent_flags[i].description);
			json_object_array_add(jobj_flags,
				json_object_new_string(persistent_flags[i].description));
		}
	}

	/* Replace or add new flags array */
	json_object_object_add(jobj_config, "flags", jobj_flags);

	return LUKS2_hdr_write(cd, hdr);
}

/*
 * json format example (mandatory array must not be ignored,
 * all other future fields may be added later)
 *
 * "requirements": {
 *       mandatory : [],
 *       optional0 : [],
 *       optional1 : "lala"
 * }
 */

/* LUKS2 library requirements */
static const struct  {
	uint32_t flag;
	const char *description;
} requirements_flags[] = {
	{ CRYPT_REQUIREMENT_OFFLINE_REENCRYPT, "offline-reencrypt" },
	{ CRYPT_REQUIREMENT_ONLINE_REENCRYPT, "online-reencrypt" },
	{ 0, NULL }
};

static uint32_t get_requirement_by_name(const char *requirement)
{
	int i;

	for (i = 0; requirements_flags[i].description; i++)
		if (!strcmp(requirement, requirements_flags[i].description))
			return requirements_flags[i].flag;

	return CRYPT_REQUIREMENT_UNKNOWN;
}

/*
 * returns count of requirements (past cryptsetup 2.0 release)
 */
int LUKS2_config_get_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t *reqs)
{
	json_object *jobj_config, *jobj_requirements, *jobj_mandatory, *jobj;
	int i, len;
	uint32_t req;

	assert(hdr);
	if (!hdr || !reqs)
		return -EINVAL;

	*reqs = 0;

	if (!json_object_object_get_ex(hdr->jobj, "config", &jobj_config))
		return 0;

	if (!json_object_object_get_ex(jobj_config, "requirements", &jobj_requirements))
		return 0;

	if (!json_object_object_get_ex(jobj_requirements, "mandatory", &jobj_mandatory))
		return 0;

	len = (int) json_object_array_length(jobj_mandatory);
	if (len <= 0)
		return 0;

	log_dbg(cd, "LUKS2 requirements detected:");

	for (i = 0; i < len; i++) {
		jobj = json_object_array_get_idx(jobj_mandatory, i);
		req = get_requirement_by_name(json_object_get_string(jobj));
		log_dbg(cd, "%s - %sknown", json_object_get_string(jobj),
				        reqs_unknown(req) ? "un" : "");
		*reqs |= req;
	}

	return 0;
}

int LUKS2_config_set_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs, bool commit)
{
	json_object *jobj_config, *jobj_requirements, *jobj_mandatory, *jobj;
	int i, r = -EINVAL;

	if (!hdr)
		return -EINVAL;

	jobj_mandatory = json_object_new_array();
	if (!jobj_mandatory)
		return -ENOMEM;

	for (i = 0; requirements_flags[i].description; i++) {
		if (reqs & requirements_flags[i].flag) {
			jobj = json_object_new_string(requirements_flags[i].description);
			if (!jobj) {
				r = -ENOMEM;
				goto err;
			}
			json_object_array_add(jobj_mandatory, jobj);
			/* erase processed flag from input set */
			reqs &= ~(requirements_flags[i].flag);
		}
	}

	/* any remaining bit in requirements is unknown therefore illegal */
	if (reqs) {
		log_dbg(cd, "Illegal requirement flag(s) requested");
		goto err;
	}

	if (!json_object_object_get_ex(hdr->jobj, "config", &jobj_config))
		goto err;

	if (!json_object_object_get_ex(jobj_config, "requirements", &jobj_requirements)) {
		jobj_requirements = json_object_new_object();
		if (!jobj_requirements) {
			r = -ENOMEM;
			goto err;
		}
		json_object_object_add(jobj_config, "requirements", jobj_requirements);
	}

	if (json_object_array_length(jobj_mandatory) > 0) {
		/* replace mandatory field with new values */
		json_object_object_add(jobj_requirements, "mandatory", jobj_mandatory);
	} else {
		/* new mandatory field was empty, delete old one */
		json_object_object_del(jobj_requirements, "mandatory");
		json_object_put(jobj_mandatory);
	}

	/* remove empty requirements object */
	if (!json_object_object_length(jobj_requirements))
		json_object_object_del(jobj_config, "requirements");

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
err:
	json_object_put(jobj_mandatory);
	return r;
}

/*
 * Header dump
 */
static void hdr_dump_config(struct crypt_device *cd, json_object *hdr_jobj)
{

	json_object *jobj1, *jobj_config, *jobj_flags, *jobj_requirements, *jobj_mandatory;
	int i = 0, flags = 0, reqs = 0;

	log_std(cd, "Flags:       \t");

	if (json_object_object_get_ex(hdr_jobj, "config", &jobj_config)) {
		if (json_object_object_get_ex(jobj_config, "flags", &jobj_flags))
			flags = (int) json_object_array_length(jobj_flags);
		if (json_object_object_get_ex(jobj_config, "requirements", &jobj_requirements) &&
		    json_object_object_get_ex(jobj_requirements, "mandatory", &jobj_mandatory))
			reqs = (int) json_object_array_length(jobj_mandatory);
	}

	for (i = 0; i < flags; i++) {
		jobj1 = json_object_array_get_idx(jobj_flags, i);
		log_std(cd, "%s ", json_object_get_string(jobj1));
	}

	log_std(cd, "%s\n%s", flags > 0 ? "" : "(no flags)", reqs > 0 ? "" : "\n");

	if (reqs > 0) {
		log_std(cd, "Requirements:\t");
		for (i = 0; i < reqs; i++) {
			jobj1 = json_object_array_get_idx(jobj_mandatory, i);
			log_std(cd, "%s ", json_object_get_string(jobj1));
		}
		log_std(cd, "\n\n");
	}
}

static const char *get_priority_desc(json_object *jobj)
{
	crypt_keyslot_priority priority;
	json_object *jobj_priority;
	const char *text;

	if (json_object_object_get_ex(jobj, "priority", &jobj_priority))
		priority = (crypt_keyslot_priority)(int)json_object_get_int(jobj_priority);
	else
		priority = CRYPT_SLOT_PRIORITY_NORMAL;

	switch (priority) {
		case CRYPT_SLOT_PRIORITY_IGNORE: text = "ignored"; break;
		case CRYPT_SLOT_PRIORITY_PREFER: text = "preferred"; break;
		case CRYPT_SLOT_PRIORITY_NORMAL: text = "normal"; break;
		default: text = "invalid";
	}

	return text;
}

static void hdr_dump_keyslots(struct crypt_device *cd, json_object *hdr_jobj)
{
	char slot[16];
	json_object *keyslots_jobj, *digests_jobj, *jobj2, *jobj3, *val;
	const char *tmps;
	int i, j, r;

	log_std(cd, "Keyslots:\n");
	json_object_object_get_ex(hdr_jobj, "keyslots", &keyslots_jobj);

	for (j = 0; j < LUKS2_KEYSLOTS_MAX; j++) {
		(void) snprintf(slot, sizeof(slot), "%i", j);
		json_object_object_get_ex(keyslots_jobj, slot, &val);
		if (!val)
			continue;

		json_object_object_get_ex(val, "type", &jobj2);
		tmps = json_object_get_string(jobj2);

		r = LUKS2_keyslot_for_segment(crypt_get_hdr(cd, CRYPT_LUKS2), j, CRYPT_ONE_SEGMENT);
		log_std(cd, "  %s: %s%s\n", slot, tmps, r == -ENOENT ? " (unbound)" : "");

		if (json_object_object_get_ex(val, "key_size", &jobj2))
			log_std(cd, "\tKey:        %u bits\n", crypt_jobj_get_uint32(jobj2) * 8);

		log_std(cd, "\tPriority:   %s\n", get_priority_desc(val));

		LUKS2_keyslot_dump(cd, j);

		json_object_object_get_ex(hdr_jobj, "digests", &digests_jobj);
		json_object_object_foreach(digests_jobj, key2, val2) {
			json_object_object_get_ex(val2, "keyslots", &jobj2);
			for (i = 0; i < (int) json_object_array_length(jobj2); i++) {
				jobj3 = json_object_array_get_idx(jobj2, i);
				if (!strcmp(slot, json_object_get_string(jobj3))) {
					log_std(cd, "\tDigest ID:  %s\n", key2);
				}
			}
		}
	}
}

static void hdr_dump_tokens(struct crypt_device *cd, json_object *hdr_jobj)
{
	char token[16];
	json_object *tokens_jobj, *jobj2, *jobj3, *val;
	const char *tmps;
	int i, j;

	log_std(cd, "Tokens:\n");
	json_object_object_get_ex(hdr_jobj, "tokens", &tokens_jobj);

	for (j = 0; j < LUKS2_TOKENS_MAX; j++) {
		(void) snprintf(token, sizeof(token), "%i", j);
		json_object_object_get_ex(tokens_jobj, token, &val);
		if (!val)
			continue;

		json_object_object_get_ex(val, "type", &jobj2);
		tmps = json_object_get_string(jobj2);
		log_std(cd, "  %s: %s\n", token, tmps);

		LUKS2_token_dump(cd, j);

		json_object_object_get_ex(val, "keyslots", &jobj2);
		for (i = 0; i < (int) json_object_array_length(jobj2); i++) {
			jobj3 = json_object_array_get_idx(jobj2, i);
			log_std(cd, "\tKeyslot:  %s\n", json_object_get_string(jobj3));
		}
	}
}

static void hdr_dump_segments(struct crypt_device *cd, json_object *hdr_jobj)
{
	char segment[16];
	json_object *jobj_segments, *jobj_segment, *jobj1, *jobj2;
	int i, j, flags;
	uint64_t value;

	log_std(cd, "Data segments:\n");
	json_object_object_get_ex(hdr_jobj, "segments", &jobj_segments);

	for (i = 0; i < LUKS2_SEGMENT_MAX; i++) {
		(void) snprintf(segment, sizeof(segment), "%i", i);
		if (!json_object_object_get_ex(jobj_segments, segment, &jobj_segment))
			continue;

		json_object_object_get_ex(jobj_segment, "type", &jobj1);
		log_std(cd, "  %s: %s\n", segment, json_object_get_string(jobj1));

		json_object_object_get_ex(jobj_segment, "offset", &jobj1);
		json_str_to_uint64(jobj1, &value);
		log_std(cd, "\toffset: %" PRIu64 " [bytes]\n", value);

		json_object_object_get_ex(jobj_segment, "size", &jobj1);
		if (!(strcmp(json_object_get_string(jobj1), "dynamic")))
			log_std(cd, "\tlength: (whole device)\n");
		else {
			json_str_to_uint64(jobj1, &value);
			log_std(cd, "\tlength: %" PRIu64 " [bytes]\n", value);
		}

		if (json_object_object_get_ex(jobj_segment, "encryption", &jobj1))
			log_std(cd, "\tcipher: %s\n", json_object_get_string(jobj1));

		if (json_object_object_get_ex(jobj_segment, "sector_size", &jobj1))
			log_std(cd, "\tsector: %" PRIu32 " [bytes]\n", crypt_jobj_get_uint32(jobj1));

		if (json_object_object_get_ex(jobj_segment, "integrity", &jobj1) &&
		    json_object_object_get_ex(jobj1, "type", &jobj2))
			log_std(cd, "\tintegrity: %s\n", json_object_get_string(jobj2));

		if (json_object_object_get_ex(jobj_segment, "flags", &jobj1) &&
		    (flags = (int)json_object_array_length(jobj1)) > 0) {
			jobj2 = json_object_array_get_idx(jobj1, 0);
			log_std(cd, "\tflags : %s", json_object_get_string(jobj2));
			for (j = 1; j < flags; j++) {
				jobj2 = json_object_array_get_idx(jobj1, j);
				log_std(cd, ", %s", json_object_get_string(jobj2));
			}
			log_std(cd, "\n");
		}

		log_std(cd, "\n");
	}
}

static void hdr_dump_digests(struct crypt_device *cd, json_object *hdr_jobj)
{
	char key[16];
	json_object *jobj1, *jobj2, *val;
	const char *tmps;
	int i;

	log_std(cd, "Digests:\n");
	json_object_object_get_ex(hdr_jobj, "digests", &jobj1);

	for (i = 0; i < LUKS2_DIGEST_MAX; i++) {
		(void) snprintf(key, sizeof(key), "%i", i);
		json_object_object_get_ex(jobj1, key, &val);
		if (!val)
			continue;

		json_object_object_get_ex(val, "type", &jobj2);
		tmps = json_object_get_string(jobj2);
		log_std(cd, "  %s: %s\n", key, tmps);

		LUKS2_digest_dump(cd, i);
	}
}

int LUKS2_hdr_dump(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	if (!hdr->jobj)
		return -EINVAL;

	JSON_DBG(cd, hdr->jobj, NULL);

	log_std(cd, "LUKS header information\n");
	log_std(cd, "Version:       \t%u\n", hdr->version);
	log_std(cd, "Epoch:         \t%" PRIu64 "\n", hdr->seqid);
	log_std(cd, "Metadata area: \t%" PRIu64 " [bytes]\n", LUKS2_metadata_size(hdr->jobj));
	log_std(cd, "Keyslots area: \t%" PRIu64 " [bytes]\n", LUKS2_keyslots_size(hdr->jobj));
	log_std(cd, "UUID:          \t%s\n", *hdr->uuid ? hdr->uuid : "(no UUID)");
	log_std(cd, "Label:         \t%s\n", *hdr->label ? hdr->label : "(no label)");
	log_std(cd, "Subsystem:     \t%s\n", *hdr->subsystem ? hdr->subsystem : "(no subsystem)");

	hdr_dump_config(cd, hdr->jobj);
	hdr_dump_segments(cd, hdr->jobj);
	hdr_dump_keyslots(cd, hdr->jobj);
	hdr_dump_tokens(cd, hdr->jobj);
	hdr_dump_digests(cd, hdr->jobj);

	return 0;
}

int LUKS2_get_data_size(struct luks2_hdr *hdr, uint64_t *size, bool *dynamic)
{
	int sector_size;
	json_object *jobj_segments, *jobj_size;
	uint64_t tmp = 0;

	if (!size || !json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments))
		return -EINVAL;

	json_object_object_foreach(jobj_segments, key, val) {
		UNUSED(key);
		if (json_segment_is_backup(val))
			continue;

		json_object_object_get_ex(val, "size", &jobj_size);
		if (!strcmp(json_object_get_string(jobj_size), "dynamic")) {
			sector_size = json_segment_get_sector_size(val);
			/* last dynamic segment must have at least one sector in size */
			if (tmp)
				*size = tmp + (sector_size > 0 ? sector_size : SECTOR_SIZE);
			else
				*size = 0;
			if (dynamic)
				*dynamic = true;
			return 0;
		}

		tmp += crypt_jobj_get_uint64(jobj_size);
	}

	/* impossible, real device size must not be zero */
	if (!tmp)
		return -EINVAL;

	*size = tmp;
	if (dynamic)
		*dynamic = false;
	return 0;
}

uint64_t LUKS2_get_data_offset(struct luks2_hdr *hdr)
{
	crypt_reencrypt_info ri;
	json_object *jobj;

	ri = LUKS2_reenc_status(hdr);
	if (ri == CRYPT_REENCRYPT_CLEAN || ri == CRYPT_REENCRYPT_CRASH) {
		jobj = LUKS2_get_segment_by_flag(hdr, "backup-final");
		if (jobj)
			return json_segment_get_offset(jobj, 1);
	}

	return json_segments_get_minimal_offset(LUKS2_get_segments_jobj(hdr), 1);
}

const char *LUKS2_get_cipher(struct luks2_hdr *hdr, int segment)
{
	json_object *jobj_segment;

	if (!hdr)
		return NULL;

	if (segment == CRYPT_DEFAULT_SEGMENT)
		segment = LUKS2_get_default_segment(hdr);

	jobj_segment = json_segments_get_segment(json_get_segments_jobj(hdr->jobj), segment);
	if (!jobj_segment)
		return NULL;

	/* FIXME: default encryption (for other segment types) must be string here. */
	return json_segment_get_cipher(jobj_segment) ?: "null";
}

crypt_reencrypt_info LUKS2_reenc_status(struct luks2_hdr *hdr)
{
	uint32_t reqs;

	/*
	 * Any unknown requirement or offline reencryption should abort
	 * anything related to online-reencryption handling
	 */
	if (LUKS2_config_get_requirements(NULL, hdr, &reqs))
		return CRYPT_REENCRYPT_INVALID;

	if (!reqs_reencrypt_online(reqs))
		return CRYPT_REENCRYPT_NONE;

	if (json_segments_segment_in_reencrypt(LUKS2_get_segments_jobj(hdr)) < 0)
		return CRYPT_REENCRYPT_CLEAN;

	return CRYPT_REENCRYPT_CRASH;
}

const char *LUKS2_get_keyslot_cipher(struct luks2_hdr *hdr, int keyslot, size_t *key_size)
{
	json_object *jobj_keyslot, *jobj_area, *jobj1;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return NULL;

	if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return NULL;

	/* currently we only support raw length preserving area encryption */
	json_object_object_get_ex(jobj_area, "type", &jobj1);
	if (strcmp(json_object_get_string(jobj1), "raw"))
		return NULL;

	if (!json_object_object_get_ex(jobj_area, "key_size", &jobj1))
		return NULL;
	*key_size = json_object_get_int(jobj1);

	if (!json_object_object_get_ex(jobj_area, "encryption", &jobj1))
		return NULL;

	return json_object_get_string(jobj1);
}

const char *LUKS2_get_integrity(struct luks2_hdr *hdr, int segment)
{
	json_object *jobj1, *jobj2, *jobj3;

	jobj1 = LUKS2_get_segment_jobj(hdr, segment);
	if (!jobj1)
		return NULL;

	if (!json_object_object_get_ex(jobj1, "integrity", &jobj2))
		return NULL;

	if (!json_object_object_get_ex(jobj2, "type", &jobj3))
		return NULL;

	return json_object_get_string(jobj3);
}

/* FIXME: this only ensures that once we have journal encryption, it is not ignored. */
/* implement segment count and type restrictions (crypt and only single crypt) */
static int LUKS2_integrity_compatible(struct luks2_hdr *hdr)
{
	json_object *jobj1, *jobj2, *jobj3, *jobj4;
	const char *str;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return 0;

	if (!(jobj2 = LUKS2_get_segment_jobj(hdr, CRYPT_DEFAULT_SEGMENT)))
		return 0;

	if (!json_object_object_get_ex(jobj2, "integrity", &jobj3))
		return 0;

	if (!json_object_object_get_ex(jobj3, "journal_encryption", &jobj4) ||
	    !(str = json_object_get_string(jobj4)) ||
	    strcmp(str, "none"))
		return 0;

	if (!json_object_object_get_ex(jobj3, "journal_integrity", &jobj4) ||
	    !(str = json_object_get_string(jobj4)) ||
	    strcmp(str, "none"))
		return 0;

	return 1;
}

static int LUKS2_keyslot_get_volume_key_size(struct luks2_hdr *hdr, const char *keyslot)
{
	json_object *jobj1, *jobj2, *jobj3;

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj1))
		return -1;

	if (!json_object_object_get_ex(jobj1, keyslot, &jobj2))
		return -1;

	if (!json_object_object_get_ex(jobj2, "key_size", &jobj3))
		return -1;

	return json_object_get_int(jobj3);
}

/* Key size used for encryption of keyslot */
int LUKS2_get_keyslot_stored_key_size(struct luks2_hdr *hdr, int keyslot)
{
	char keyslot_name[16];

	if (snprintf(keyslot_name, sizeof(keyslot_name), "%u", keyslot) < 1)
		return -1;

	return LUKS2_keyslot_get_volume_key_size(hdr, keyslot_name);
}

int LUKS2_get_volume_key_size(struct luks2_hdr *hdr, int segment)
{
	json_object *jobj_digests, *jobj_digest_segments, *jobj_digest_keyslots, *jobj1;
	char buf[16];

	if (segment == CRYPT_DEFAULT_SEGMENT)
		segment = LUKS2_get_default_segment(hdr);

	if (snprintf(buf, sizeof(buf), "%u", segment) < 1)
		return -1;

	json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

	json_object_object_foreach(jobj_digests, key, val) {
		UNUSED(key);
		json_object_object_get_ex(val, "segments", &jobj_digest_segments);
		json_object_object_get_ex(val, "keyslots", &jobj_digest_keyslots);

		if (!LUKS2_array_jobj(jobj_digest_segments, buf))
			continue;
		if (json_object_array_length(jobj_digest_keyslots) <= 0)
			continue;

		jobj1 = json_object_array_get_idx(jobj_digest_keyslots, 0);

		return LUKS2_keyslot_get_volume_key_size(hdr, json_object_get_string(jobj1));
	}

	return -1;
}

int LUKS2_get_sector_size(struct luks2_hdr *hdr)
{
	json_object *jobj_segment;

	jobj_segment = LUKS2_get_segment_jobj(hdr, CRYPT_DEFAULT_SEGMENT);
	if (!jobj_segment)
		return SECTOR_SIZE;

	return json_segment_get_sector_size(jobj_segment) ?: SECTOR_SIZE;
}

int LUKS2_assembly_multisegment_dmd(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct volume_key *vks,
	json_object *jobj_segments,
	struct crypt_dm_active_device *dmd)
{
	struct volume_key *vk;
	json_object *jobj;
	enum devcheck device_check;
	int r;
	unsigned s = 0;
	uint64_t data_offset, segment_size, segment_offset, segment_start = 0;
	struct dm_target *t = &dmd->segment;

	if (dmd->flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_OK;
	else
		device_check = DEV_EXCL;

	data_offset = LUKS2_reencrypt_data_offset(hdr, true);

	r = device_block_adjust(cd, crypt_data_device(cd), device_check,
			                                data_offset, &dmd->size, &dmd->flags);
	if (r)
		return r;

	r = dm_targets_allocate(&dmd->segment, json_segments_count(jobj_segments));
	if (r)
		goto err;

	r = -EINVAL;

	while (t) {
		jobj = json_segments_get_segment(jobj_segments, s);
		if (!jobj) {
			log_dbg(cd, "Internal error. Segment %u is null.", s);
			r = -EINVAL;
			goto err;
		}

		segment_offset = json_segment_get_offset(jobj, 1);
		segment_size = json_segment_get_size(jobj, 1);
		/* 'dynamic' length allowed in last segment only */
		if (!segment_size && !t->next)
			segment_size = dmd->size - segment_start;
		if (!segment_size) {
			log_dbg(cd, "Internal error. Wrong segment size %u", s);
			r = -EINVAL;
			goto err;
		}

		if (!strcmp(json_segment_type(jobj), "crypt")) {
			vk = crypt_volume_key_by_id(vks, LUKS2_digest_by_segment(hdr, s));
			if (!vk) {
				log_err(cd, _("Missing key for dm-crypt segment %u"), s);
				r = -EINVAL;
				goto err;
			}

			r = dm_crypt_target_set(t, segment_start, segment_size,
					crypt_data_device(cd), vk,
					json_segment_get_cipher(jobj),
					json_segment_get_iv_offset(jobj),
					segment_offset, "none", 0,
					json_segment_get_sector_size(jobj));
			if (r) {
				log_err(cd, _("Failed to set dm-crypt segment."));
				goto err;
			}
		} else if (!strcmp(json_segment_type(jobj), "linear")) {
			r = dm_linear_target_set(t, segment_start, segment_size, crypt_data_device(cd), segment_offset);
			if (r) {
				log_err(cd, _("Failed to set dm-linear segment."));
				goto err;
			}
		} else {
			r = -EINVAL;
			goto err;
		}

		segment_start += segment_size;
		t = t->next;
		s++;
	}

	return r;
err:
	dm_targets_free(cd, dmd);
	return r;
}

/* FIXME: This shares almost all code with activate_multi_custom */
static int _reload_custom_multi(struct crypt_device *cd,
	const char *name,
	struct volume_key *vks,
	json_object *jobj_segments,
	uint64_t device_size,
	uint32_t flags)
{
	int r;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
	struct crypt_dm_active_device dmd =  {
		.uuid   = crypt_get_uuid(cd),
		.size = device_size >> SECTOR_SHIFT
	};

	/* do not allow activation when particular requirements detected */
	if ((r = LUKS2_unmet_requirements(cd, hdr, CRYPT_REQUIREMENT_ONLINE_REENCRYPT, 0)))
		return r;

	/* Add persistent activation flags */
	if (!(flags & CRYPT_ACTIVATE_IGNORE_PERSISTENT))
		LUKS2_config_get_flags(cd, hdr, &dmd.flags);

	dmd.flags |= (flags | CRYPT_ACTIVATE_SHARED);

	r = LUKS2_assembly_multisegment_dmd(cd, hdr, vks, jobj_segments, &dmd);
	if (!r)
		r = dm_reload_device(cd, name, &dmd, 0, 0);

	dm_targets_free(cd, &dmd);
	return r;
}

int LUKS2_reload(struct crypt_device *cd,
	const char *name,
	struct volume_key *vks,
	uint64_t device_size,
	uint32_t flags)
{
	if (crypt_get_integrity_tag_size(cd))
		return -ENOTSUP;

	return _reload_custom_multi(cd, name, vks,
			LUKS2_get_segments_jobj(crypt_get_hdr(cd, CRYPT_LUKS2)), device_size, flags);
}

int LUKS2_activate_multi(struct crypt_device *cd,
	const char *name,
	struct volume_key *vks,
	uint64_t device_size,
	uint32_t flags)
{
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
	json_object *jobj_segments = LUKS2_get_segments_jobj(hdr);
	int r;
	struct crypt_dm_active_device dmd = {
		.size	= device_size,
		.uuid   = crypt_get_uuid(cd)
	};

	/* do not allow activation when particular requirements detected */
	if ((r = LUKS2_unmet_requirements(cd, hdr, CRYPT_REQUIREMENT_ONLINE_REENCRYPT, 0)))
		return r;

	/* Add persistent activation flags */
	if (!(flags & CRYPT_ACTIVATE_IGNORE_PERSISTENT))
		LUKS2_config_get_flags(cd, hdr, &dmd.flags);

	dmd.flags |= flags;

	r = LUKS2_assembly_multisegment_dmd(cd, hdr, vks, jobj_segments, &dmd);
	if (!r)
		r = dm_create_device(cd, name, CRYPT_LUKS2, &dmd);

	dm_targets_free(cd, &dmd);
	return r;
}

int LUKS2_activate(struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	uint32_t flags)
{
	int r;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
	struct crypt_dm_active_device dmdi = {}, dmd = {
		.uuid   = crypt_get_uuid(cd)
	};

	/* do not allow activation when particular requirements detected */
	if ((r = LUKS2_unmet_requirements(cd, hdr, 0, 0)))
		return r;

	r = dm_crypt_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd),
			vk, crypt_get_cipher_spec(cd), crypt_get_iv_offset(cd),
			crypt_get_data_offset(cd), crypt_get_integrity(cd) ?: "none",
			crypt_get_integrity_tag_size(cd), crypt_get_sector_size(cd));
	if (r < 0)
		return r;

	/* Add persistent activation flags */
	if (!(flags & CRYPT_ACTIVATE_IGNORE_PERSISTENT))
		LUKS2_config_get_flags(cd, hdr, &dmd.flags);

	dmd.flags |= flags;

	if (crypt_get_integrity_tag_size(cd)) {
		if (!LUKS2_integrity_compatible(hdr)) {
			log_err(cd, _("Unsupported device integrity configuration."));
			return -EINVAL;
		}

		if (dmd.flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) {
			log_err(cd, _("Discard/TRIM is not supported."));
			return -EINVAL;
		}

		r = INTEGRITY_create_dmd_device(cd, NULL, NULL, NULL, NULL, &dmdi, dmd.flags, 0);
		if (r)
			return r;

		dmdi.flags |= CRYPT_ACTIVATE_PRIVATE;
		dmdi.uuid = dmd.uuid;
		dmd.segment.u.crypt.offset = 0;
		dmd.segment.size = dmdi.segment.size;

		r = create_or_reload_device_with_integrity(cd, name, CRYPT_LUKS2, &dmd, &dmdi);
	} else
		r = create_or_reload_device(cd, name, CRYPT_LUKS2, &dmd);

	dm_targets_free(cd, &dmd);
	dm_targets_free(cd, &dmdi);

	return r;
}

static bool is_reencryption_helper(const char *name)
{
	size_t len;

	if (!name)
		return false;

	len = strlen(name);
	return (len >= 9 && (!strncmp(name + len - 8, "-hotzone-", 9) ||
			     !strcmp(name + len - 8, "-overlay")));

}

static bool contains_reencryption_helper(char **names)
{
	while (*names) {
		if (is_reencryption_helper(*names++))
			return true;
	}

	return false;
}

int LUKS2_deactivate(struct crypt_device *cd, const char *name, struct luks2_hdr *hdr, struct crypt_dm_active_device *dmd, uint32_t flags)
{
	int r, ret;
	struct dm_target *tgt;
	crypt_status_info ci;
	struct crypt_dm_active_device dmdc;
	char **dep, deps_uuid_prefix[40], *deps[MAX_DM_DEPS+1] = { 0 };
	const char *namei = NULL;
	struct crypt_lock_handle *reencrypt_lock = NULL;

	if (!dmd || !dmd->uuid || strncmp(CRYPT_LUKS2, dmd->uuid, sizeof(CRYPT_LUKS2)-1))
		return -EINVAL;

	/* uuid mismatch with metadata (if available) */
	if (hdr && crypt_uuid_cmp(dmd->uuid, hdr->uuid))
		return -EINVAL;

	r = snprintf(deps_uuid_prefix, sizeof(deps_uuid_prefix), CRYPT_SUBDEV "-%.32s", dmd->uuid + 6);
	if (r < 0 || (size_t)r != (sizeof(deps_uuid_prefix) - 1))
		return -EINVAL;

	tgt = &dmd->segment;

	/* TODO: We have LUKS2 dependencies now */
	if (hdr && single_segment(dmd) && tgt->type == DM_CRYPT && crypt_get_integrity_tag_size(cd))
		namei = device_dm_name(tgt->data_device);

	r = dm_device_deps(cd, name, deps_uuid_prefix, deps, ARRAY_SIZE(deps));
	if (r < 0)
		goto out;

	if (contains_reencryption_helper(deps)) {
		r = crypt_reencrypt_lock_by_dm_uuid(cd, dmd->uuid, &reencrypt_lock);
		if (r) {
			if (r == -EBUSY)
				log_err(cd, _("Reencryption in-progress. Cannot deactivate device."));
			else
				log_err(cd, _("Failed to get reencryption lock."));
			goto out;
		}
	}

	dep = deps;
	while (*dep) {
		if (is_reencryption_helper(*dep) && (dm_status_suspended(cd, *dep) > 0)) {
			if (dm_error_device(cd, *dep))
				log_err(cd, _("Failed to replace suspended device %s with dm-error target."), *dep);
		}
		dep++;
	}

	r = dm_query_device(cd, name, DM_ACTIVE_CRYPT_KEY | DM_ACTIVE_CRYPT_KEYSIZE, &dmdc);
	if (r < 0) {
		memset(&dmdc, 0, sizeof(dmdc));
		dmdc.segment.type = DM_UNKNOWN;
	}

	/* Remove top level device first */
	r = dm_remove_device(cd, name, flags);
	if (!r) {
		tgt = &dmdc.segment;
		while (tgt) {
			if (tgt->type == DM_CRYPT)
				crypt_drop_keyring_key_by_description(cd, tgt->u.crypt.vk->key_description, LOGON_KEY);
			tgt = tgt->next;
		}
	}
	dm_targets_free(cd, &dmdc);

	/* TODO: We have LUKS2 dependencies now */
	if (r >= 0 && namei) {
		log_dbg(cd, "Deactivating integrity device %s.", namei);
		r = dm_remove_device(cd, namei, 0);
	}

	if (!r) {
		ret = 0;
		dep = deps;
		while (*dep) {
			log_dbg(cd, "Deactivating LUKS2 dependent device %s.", *dep);
			r = dm_query_device(cd, *dep, DM_ACTIVE_CRYPT_KEY | DM_ACTIVE_CRYPT_KEYSIZE, &dmdc);
			if (r < 0) {
				memset(&dmdc, 0, sizeof(dmdc));
				dmdc.segment.type = DM_UNKNOWN;
			}

			r = dm_remove_device(cd, *dep, flags);
			if (r < 0) {
				ci = crypt_status(cd, *dep);
				if (ci == CRYPT_BUSY)
					log_err(cd, _("Device %s is still in use."), *dep);
				if (ci == CRYPT_INACTIVE)
					r = 0;
			}
			if (!r) {
				tgt = &dmdc.segment;
				while (tgt) {
					if (tgt->type == DM_CRYPT)
						crypt_drop_keyring_key_by_description(cd, tgt->u.crypt.vk->key_description, LOGON_KEY);
					tgt = tgt->next;
				}
			}
			dm_targets_free(cd, &dmdc);
			if (r && !ret)
				ret = r;
			dep++;
		}
		r = ret;
	}

out:
	crypt_reencrypt_unlock(cd, reencrypt_lock);
	dep = deps;
	while (*dep)
		free(*dep++);

	return r;
}

int LUKS2_unmet_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs_mask, int quiet)
{
	uint32_t reqs;
	int r = LUKS2_config_get_requirements(cd, hdr, &reqs);

	if (r) {
		if (!quiet)
			log_err(cd, _("Failed to read LUKS2 requirements."));
		return r;
	}

	/* do not mask unknown requirements check */
	if (reqs_unknown(reqs)) {
		if (!quiet)
			log_err(cd, _("Unmet LUKS2 requirements detected."));
		return -ETXTBSY;
	}

	/* mask out permitted requirements */
	reqs &= ~reqs_mask;

	if (reqs_reencrypt(reqs) && !quiet)
		log_err(cd, _("Operation incompatible with device marked for legacy reencryption. Aborting."));
	if (reqs_reencrypt_online(reqs) && !quiet)
		log_err(cd, _("Operation incompatible with device marked for LUKS2 reencryption. Aborting."));

	/* any remaining unmasked requirement fails the check */
	return reqs ? -EINVAL : 0;
}

/*
 * NOTE: this routine is called on json object that failed validation.
 * 	 Proceed with caution :)
 *
 * known glitches so far:
 *
 * any version < 2.0.3:
 *  - luks2 keyslot pbkdf params change via crypt_keyslot_change_by_passphrase()
 *    could leave previous type parameters behind. Correct this by purging
 *    all params not needed by current type.
 */
void LUKS2_hdr_repair(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj_keyslots;

	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return;
	if (!json_object_is_type(jobj_keyslots, json_type_object))
		return;

	LUKS2_keyslots_repair(cd, jobj_keyslots);
}

void json_object_object_del_by_uint(json_object *jobj, unsigned key)
{
	char key_name[16];

	if (snprintf(key_name, sizeof(key_name), "%u", key) < 1)
		return;
	json_object_object_del(jobj, key_name);
}

int json_object_object_add_by_uint(json_object *jobj, unsigned key, json_object *jobj_val)
{
	char key_name[16];

	if (snprintf(key_name, sizeof(key_name), "%u", key) < 1)
		return -EINVAL;

#if HAVE_DECL_JSON_OBJECT_OBJECT_ADD_EX
	return json_object_object_add_ex(jobj, key_name, jobj_val, 0) ? -ENOMEM : 0;
#else
	json_object_object_add(jobj, key_name, jobj_val);
	return 0;
#endif
}

/* jobj_dst must contain pointer initialized to NULL (see json-c json_object_deep_copy API) */
int json_object_copy(json_object *jobj_src, json_object **jobj_dst)
{
	if (!jobj_src || !jobj_dst || *jobj_dst)
		return -1;

#if HAVE_DECL_JSON_OBJECT_DEEP_COPY
	return json_object_deep_copy(jobj_src, jobj_dst, NULL);
#else
	*jobj_dst = json_tokener_parse(json_object_get_string(jobj_src));
	return *jobj_dst ? 0 : -1;
#endif
}
