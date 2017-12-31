/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2017, Milan Broz. All rights reserved.
 * Copyright (C) 2015-2017, Ondrej Kozina. All rights reserved.
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

	for (i = 0; i < buf_len / 2; i++)
		log_std(cd, "%02hhx%s", buf[i], sep);
	log_std(cd, "\n\t%s", line_sep);
	for (i = buf_len / 2; i < buf_len; i++)
		log_std(cd, "%02hhx%s", buf[i], sep);
	log_std(cd, "\n");
	free(buf);
}

void JSON_DBG(json_object *jobj, const char *desc)
{
	/* FIXME: make this conditional and disable for stable release. */
	if (desc)
		log_dbg("%s:", desc);
	log_dbg("%s", json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY));
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

	if (!hdr)
		return NULL;

	if (snprintf(keyslot_name, sizeof(keyslot_name), "%u", keyslot) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj1))
		return NULL;

	json_object_object_get_ex(jobj1, keyslot_name, &jobj2);
	return jobj2;
}

json_object *LUKS2_get_token_jobj(struct luks2_hdr *hdr, int token)
{
	json_object *jobj1, *jobj2;
	char token_name[16];

	if (!hdr)
		return NULL;

	if (snprintf(token_name, sizeof(token_name), "%u", token) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "tokens", &jobj1))
		return NULL;

	json_object_object_get_ex(jobj1, token_name, &jobj2);
	return jobj2;
}

json_object *LUKS2_get_digest_jobj(struct luks2_hdr *hdr, int digest)
{
	json_object *jobj1, *jobj2;
	char digest_name[16];

	if (!hdr)
		return NULL;

	if (snprintf(digest_name, sizeof(digest_name), "%u", digest) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "digests", &jobj1))
		return NULL;

	json_object_object_get_ex(jobj1, digest_name, &jobj2);
	return jobj2;
}

json_object *LUKS2_get_segment_jobj(struct luks2_hdr *hdr, int segment)
{
	json_object *jobj1, *jobj2;
	char segment_name[16];

	if (!hdr)
		return NULL;

	if (snprintf(segment_name, sizeof(segment_name), "%u", segment) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return NULL;

	if (!json_object_object_get_ex(jobj1, segment_name, &jobj2))
		return NULL;

	return jobj2;
}

/*
 * json_type_int needs to be validated first.
 * See validate_json_uint32()
 */
uint32_t json_object_get_uint32(json_object *jobj)
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
	if (*endptr || errno || tmp > UINT64_MAX) {
		log_dbg("Failed to parse uint64_t type from string %s.",
			json_object_get_string(jobj));
		*value = 0;
		return FALSE;
	}

	*value = tmp;
	return TRUE;
}

uint64_t json_object_get_uint64(json_object *jobj)
{
	uint64_t r;
	return json_str_to_uint64(jobj, &r) ? r : 0;
}

json_object *json_object_new_uint64(uint64_t value)
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
static json_bool numbered(const char *name, const char *key)
{
	int i;

	for (i = 0; key[i]; i++)
		if (!isdigit(key[i])) {
			log_dbg("%s \"%s\" is not in numbered form.", name, key);
			return FALSE;
		}
	return TRUE;
}

static json_object *contains(json_object *jobj, const char *name,
			     const char *section, const char *key, json_type type)
{
	json_object *sobj;

	if (!json_object_object_get_ex(jobj, key, &sobj) ||
	    !json_object_is_type(sobj, type)) {
		log_dbg("%s \"%s\" is missing \"%s\" (%s) specification.",
			section, name, key, json_type_to_name(type));
		return NULL;
	}

	return sobj;
}

/* use only on already validated 'segments' object */
static uint64_t get_first_data_offset(json_object *jobj_segs, const char *type)
{
	json_object *jobj_offset, *jobj_type;
	uint64_t tmp, min = UINT64_MAX;

	json_object_object_foreach(jobj_segs, key, val) {
		UNUSED(key);

		if (type) {
			json_object_object_get_ex(val, "type", &jobj_type);
			if (strcmp(type, json_object_get_string(jobj_type)))
				continue;
		}

		json_object_object_get_ex(val, "offset", &jobj_offset);
		tmp = json_object_get_uint64(jobj_offset);

		if (!tmp)
			return tmp;

		if (tmp < min)
			min = tmp;
	}

	return min;
}

static json_bool validate_json_uint32(json_object *jobj)
{
	int64_t tmp;

	errno = 0;
	tmp = json_object_get_int64(jobj);

	return (errno || tmp < 0 || tmp > UINT32_MAX) ? FALSE : TRUE;
}

static json_bool validate_keyslots_array(json_object *jarr, json_object *jobj_keys)
{
	json_object *jobj;
	int i = 0, length = (int) json_object_array_length(jarr);

	while (i < length) {
		jobj = json_object_array_get_idx(jarr, i);
		if (!json_object_is_type(jobj, json_type_string)) {
			log_dbg("Illegal value type in keyslots array at index %d.", i);
			return FALSE;
		}

		if (!contains(jobj_keys, "", "Keyslots section", json_object_get_string(jobj), json_type_object))
			return FALSE;

		i++;
	}

	return TRUE;
}

static json_bool validate_segments_array(json_object *jarr, json_object *jobj_segments)
{
	json_object *jobj;
	int i = 0, length = (int) json_object_array_length(jarr);

	while (i < length) {
		jobj = json_object_array_get_idx(jarr, i);
		if (!json_object_is_type(jobj, json_type_string)) {
			log_dbg("Illegal value type in segments array at index %d.", i);
			return FALSE;
		}

		if (!contains(jobj_segments, "", "Segments section", json_object_get_string(jobj), json_type_object))
			return FALSE;

		i++;
	}

	return TRUE;
}

static json_bool segment_has_digest(const char *segment_name, json_object *jobj_digests)
{
	json_object *jobj_segments;

	json_object_object_foreach(jobj_digests, key, val) {
		UNUSED(key);
		json_object_object_get_ex(val, "segments", &jobj_segments);
		if (LUKS2_array_jobj(jobj_segments, segment_name))
			return TRUE;
	}

	return FALSE;
}

static json_bool validate_intervals(int length, const struct interval *ix, uint64_t *data_offset)
{
	int j, i = 0;

	while (i < length) {
		if (ix[i].offset < 2 * LUKS2_HDR_16K_LEN) {
			log_dbg("Illegal area offset: %" PRIu64 ".", ix[i].offset);
			return FALSE;
		}

		if (!ix[i].length) {
			log_dbg("Area length must be greater than zero.");
			return FALSE;
		}

		/* first segment at offset 0 means we have detached header. Do not check then. */
		if (*data_offset && (ix[i].offset + ix[i].length) > *data_offset) {
			log_dbg("Area [%" PRIu64 ", %" PRIu64 "] intersects with segment starting at offset: %" PRIu64,
				ix[i].offset, ix[i].offset + ix[i].length, *data_offset);
			return FALSE;
		}

		for (j = 0; j < length; j++) {
			if (i == j)
				continue;
			if ((ix[i].offset >= ix[j].offset) && (ix[i].offset < (ix[j].offset + ix[j].length))) {
				log_dbg("Overlapping areas [%" PRIu64 ",%" PRIu64 "] and [%" PRIu64 ",%" PRIu64 "].",
					ix[i].offset, ix[i].offset + ix[i].length,
					ix[j].offset, ix[j].offset + ix[j].length);
				return FALSE;
			}
		}

		i++;
	}

	return TRUE;
}

static int hdr_validate_areas(json_object *hdr_jobj);
int LUKS2_keyslot_validate(json_object *hdr_jobj, json_object *hdr_keyslot, const char *key)
{
	json_object *jobj_key_size;

	if (!contains(hdr_keyslot, key, "Keyslot", "type", json_type_string))
		return 1;
	if (!(jobj_key_size = contains(hdr_keyslot, key, "Keyslot", "key_size", json_type_int)))
		return 1;

	/* enforce uint32_t type */
	if (!validate_json_uint32(jobj_key_size)) {
		log_dbg("Illegal field \"key_size\":%s.",
			json_object_get_string(jobj_key_size));
		return 1;
	}

	if (hdr_validate_areas(hdr_jobj))
		return 1;

	return 0;
}

int LUKS2_token_validate(json_object *hdr_jobj, json_object *jobj_token, const char *key)
{
	json_object *jarr, *jobj_keyslots;

	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return 1;

	if (!contains(jobj_token, key, "Token", "type", json_type_string))
		return 1;

	jarr = contains(jobj_token, key, "Token", "keyslots", json_type_array);
	if (!jarr)
		return 1;

	if (!validate_keyslots_array(jarr, jobj_keyslots))
		return 1;

	return 0;
}

static int hdr_validate_json_size(json_object *hdr_jobj)
{
	json_object *jobj, *jobj1;

	json_object_object_get_ex(hdr_jobj, "config", &jobj);
	json_object_object_get_ex(jobj, "json_size", &jobj1);

	return (strlen(json_object_to_json_string_ext(hdr_jobj, JSON_C_TO_STRING_PLAIN)) > json_object_get_uint64(jobj1));
}

int LUKS2_check_json_size(const struct luks2_hdr *hdr)
{
	return hdr_validate_json_size(hdr->jobj);
}

static int hdr_validate_keyslots(json_object *hdr_jobj)
{
	json_object *jobj;

	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj)) {
		log_dbg("Missing keyslots section.");
		return 1;
	}

	json_object_object_foreach(jobj, key, val) {
		if (!numbered("Keyslot", key))
			return 1;
		if (LUKS2_keyslot_validate(hdr_jobj, val, key))
			return 1;
	}

	return 0;
}

static int hdr_validate_tokens(json_object *hdr_jobj)
{
	json_object *jobj;

	if (!json_object_object_get_ex(hdr_jobj, "tokens", &jobj)) {
		log_dbg("Missing tokens section.");
		return 1;
	}

	json_object_object_foreach(jobj, key, val) {
		if (!numbered("Token", key))
			return 1;
		if (LUKS2_token_validate(hdr_jobj, val, key))
			return 1;
	}

	return 0;
}

static int hdr_validate_segments(json_object *hdr_jobj)
{
	json_object *jobj, *jobj_digests, *jobj_offset, *jobj_ivoffset,
		    *jobj_length, *jobj_sector_size, *jobj_type, *jobj_integrity;
	uint32_t sector_size;
	uint64_t ivoffset, offset, length;

	if (!json_object_object_get_ex(hdr_jobj, "segments", &jobj)) {
		log_dbg("Missing segments section.");
		return 1;
	}

	if (json_object_object_length(jobj) < 1) {
		log_dbg("Empty segments section.");
		return 1;
	}

	/* digests should already be validated */
	if (!json_object_object_get_ex(hdr_jobj, "digests", &jobj_digests))
		return 1;

	json_object_object_foreach(jobj, key, val) {
		if (!numbered("Segment", key))
			return 1;

		if (!contains(val, key, "Segment", "type",     json_type_string) ||
		    !(jobj_offset = contains(val, key, "Segment", "offset", json_type_string)) ||
		    !(jobj_ivoffset = contains(val, key, "Segment", "iv_tweak", json_type_string)) ||
		    !(jobj_length = contains(val, key, "Segment", "size", json_type_string)) ||
		    !contains(val, key, "Segment", "encryption",   json_type_string) ||
		    !(jobj_sector_size = contains(val, key, "Segment", "sector_size", json_type_int)))
			return 1;

		/* integrity */
		if (json_object_object_get_ex(val, "integrity", &jobj_integrity)) {
			if (!contains(val, key, "Segment", "integrity", json_type_object) ||
			    !contains(jobj_integrity, key, "Segment integrity", "type", json_type_string) ||
			    !contains(jobj_integrity, key, "Segment integrity", "journal_encryption", json_type_string) ||
			    !contains(jobj_integrity, key, "Segment integrity", "journal_integrity", json_type_string))
				return 1;
		}

		/* enforce uint32_t type */
		if (!validate_json_uint32(jobj_sector_size)) {
			log_dbg("Illegal field \"sector_size\":%s.",
				json_object_get_string(jobj_sector_size));
			return 1;
		}

		sector_size = json_object_get_uint32(jobj_sector_size);
		if (!sector_size || sector_size % 512) {
			log_dbg("Illegal sector size: %" PRIu32, sector_size);
			return 1;
		}

		if (!numbered("offset", json_object_get_string(jobj_offset)) ||
		    !numbered("iv_tweak", json_object_get_string(jobj_ivoffset)))
			return 1;

		/* rule out values > UINT64_MAX */
		if (!json_str_to_uint64(jobj_offset, &offset) ||
		    !json_str_to_uint64(jobj_ivoffset, &ivoffset))
			return 1;

		if (offset % sector_size) {
			log_dbg("Offset field has to be aligned to sector size: %" PRIu32, sector_size);
			return 1;
		}

		if (ivoffset % sector_size) {
			log_dbg("IV offset field has to be aligned to sector size: %" PRIu32, sector_size);
			return 1;
		}

		/* length "dynamic" means whole device starting at 'offset' */
		if (strcmp(json_object_get_string(jobj_length), "dynamic")) {
			if (!numbered("size", json_object_get_string(jobj_length)) ||
			    !json_str_to_uint64(jobj_length, &length))
				return 1;

			if (length % sector_size) {
				log_dbg("Length field has to be aligned to sector size: %" PRIu32, sector_size);
				return 1;
			}
		}

		json_object_object_get_ex(val, "type", &jobj_type);
		if (!strcmp(json_object_get_string(jobj_type), "crypt") &&
		    !segment_has_digest(key, jobj_digests))
			return 1;
	}

	return 0;
}

static int hdr_validate_areas(json_object *hdr_jobj)
{
	struct interval *intervals;
	json_object *jobj_keyslots, *jobj_offset, *jobj_length, *jobj_segments, *jobj_area;
	int length, ret, i = 0;
	uint64_t first_offset;

	/* keyslots should already be validated */
	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return 1;

	/* segments should already be validated */
	if (!json_object_object_get_ex(hdr_jobj, "segments", &jobj_segments))
		return 1;

	length = json_object_object_length(jobj_keyslots);

	/* Empty section */
	if (length == 0)
		return 0;

	if (length < 0) {
		log_dbg("Invalid keyslot areas specification.");
		return 1;
	}

	intervals = malloc(length * sizeof(*intervals));
	if (!intervals) {
		log_dbg("Not enough memory.");
		return -ENOMEM;
	}

	json_object_object_foreach(jobj_keyslots, key, val) {

		if (!(jobj_area = contains(val, key, "Keyslot", "area", json_type_object)) ||
		    !(jobj_offset = contains(jobj_area, key, "Keyslot", "offset", json_type_string)) ||
		    !(jobj_length = contains(jobj_area, key, "Keyslot", "size", json_type_string)) ||
		    !numbered("offset", json_object_get_string(jobj_offset)) ||
		    !numbered("size", json_object_get_string(jobj_length))) {
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

	first_offset = get_first_data_offset(jobj_segments, NULL);

	ret = validate_intervals(length, intervals, &first_offset) ? 0 : 1;

	free(intervals);

	return ret;
}

static int hdr_validate_digests(json_object *hdr_jobj)
{
	json_object *jarr_keys, *jarr_segs, *jobj, *jobj_keyslots, *jobj_segments;

	if (!json_object_object_get_ex(hdr_jobj, "digests", &jobj)) {
		log_dbg("Missing digests section.");
		return 1;
	}

	/* keyslots should already be validated */
	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return 1;

	/* segments are not validated atm, but we need to know digest doesn't reference missing segment */
	if (!json_object_object_get_ex(hdr_jobj, "segments", &jobj_segments))
		return 1;

	json_object_object_foreach(jobj, key, val) {
		if (!numbered("Digest", key))
			return 1;

		if (!contains(val, key, "Digest", "type", json_type_string) ||
		    !(jarr_keys = contains(val, key, "Digest", "keyslots", json_type_array)) ||
		    !(jarr_segs = contains(val, key, "Digest", "segments", json_type_array)))
			return 1;

		if (!validate_keyslots_array(jarr_keys, jobj_keyslots))
			return 1;
		if (!validate_segments_array(jarr_segs, jobj_segments))
			return 1;
	}

	return 0;
}

/* requires keyslots and segments sections being already validated */
static int validate_keyslots_size(json_object *hdr_jobj, json_object *jobj_keyslots_size)
{
	json_object *jobj_keyslots, *jobj, *jobj1;
	uint64_t keyslots_size, segment_offset, keyslots_area_sum = 0;

	if (!json_str_to_uint64(jobj_keyslots_size, &keyslots_size))
		return 1;

	if (keyslots_size % 4096) {
		log_dbg("keyslots_size is not 4 KiB aligned");
		return 1;
	}

	if (keyslots_size > LUKS2_MAX_KEYSLOTS_SIZE) {
		log_dbg("keyslots_size is too large. The cap is %" PRIu64 " bytes", (uint64_t) LUKS2_MAX_KEYSLOTS_SIZE);
		return 1;
	}

	json_object_object_get_ex(hdr_jobj, "segments", &jobj);
	segment_offset = get_first_data_offset(jobj, "crypt");
	if (segment_offset &&
	    (segment_offset < keyslots_size ||
	     (segment_offset - keyslots_size) < (2 * LUKS2_HDR_16K_LEN))) {
		log_dbg("keyslots_size is too large %" PRIu64 " (bytes). Data offset: %" PRIu64 ", keyslots offset: %d", keyslots_size, segment_offset, 2 * LUKS2_HDR_16K_LEN);
		return 1;
	}

	json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots);

	json_object_object_foreach(jobj_keyslots, key, val) {
		UNUSED(key);
		json_object_object_get_ex(val, "area", &jobj);
		json_object_object_get_ex(jobj, "size", &jobj1);
		keyslots_area_sum += json_object_get_uint64(jobj1);
	}

	if (keyslots_area_sum > keyslots_size) {
		log_dbg("Sum of all keyslot area sizes (%" PRIu64 ") is greater than value in config section %" PRIu64, keyslots_area_sum, keyslots_size);
		return 1;
	}

	return 0;
}

static int hdr_validate_config(json_object *hdr_jobj)
{
	json_object *jobj_config, *jobj, *jobj1;
	int i;
	uint64_t json_size;

	if (!json_object_object_get_ex(hdr_jobj, "config", &jobj_config)) {
		log_dbg("Missing config section.");
		return 1;
	}

	if (!(jobj = contains(jobj_config, "section", "Config", "json_size", json_type_string)) ||
	    !json_str_to_uint64(jobj, &json_size))
		return 1;

	/* currently it's hardcoded */
	if (json_size != (LUKS2_HDR_16K_LEN - LUKS2_HDR_BIN_LEN)) {
		log_dbg("Invalid json_size %" PRIu64, json_size);
		return 1;
	}

	if (json_size % 4096) {
		log_dbg("Json area is not properly aligned to 4 KiB.");
		return 1;
	}

	if (!(jobj = contains(jobj_config, "section", "Config", "keyslots_size", json_type_string)))
		return 1;

	if (validate_keyslots_size(hdr_jobj, jobj))
		return 1;

	/* Flags array is optional */
	if (json_object_object_get_ex(jobj_config, "flags", &jobj)) {
		if (!contains(jobj_config, "section", "Config", "flags", json_type_array))
			return 1;

		/* All array members must be strings */
		for (i = 0; i < (int) json_object_array_length(jobj); i++)
			if (!json_object_is_type(json_object_array_get_idx(jobj, i), json_type_string))
				return 1;
	}

	/* Requirements object is optional */
	if (json_object_object_get_ex(jobj_config, "requirements", &jobj)) {
		if (!contains(jobj_config, "section", "Config", "requirements", json_type_object))
			return 1;

		/* Mandatory array is optional */
		if (json_object_object_get_ex(jobj, "mandatory", &jobj1)) {
			if (!contains(jobj, "section", "Requirements", "mandatory", json_type_array))
				return 1;

			/* All array members must be strings */
			for (i = 0; i < (int) json_object_array_length(jobj1); i++)
				if (!json_object_is_type(json_object_array_get_idx(jobj1, i), json_type_string))
					return 1;
		}
	}

	return 0;
}

int LUKS2_hdr_validate(json_object *hdr_jobj)
{
	struct {
		int (*validate)(json_object *);
	} checks[] = {
		{ hdr_validate_keyslots },
		{ hdr_validate_tokens   },
		{ hdr_validate_digests  },
		{ hdr_validate_segments },
		{ hdr_validate_areas    },
		{ hdr_validate_config   },
		{ NULL }
	};
	int i;

	if (!hdr_jobj)
		return 1;

	for (i = 0; checks[i].validate; i++)
		if (checks[i].validate && checks[i].validate(hdr_jobj))
			return 1;

	if (hdr_validate_json_size(hdr_jobj)) {
		log_dbg("Json header is too large.");
		return 1;
	}

	return 0;
}

int LUKS2_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	int r;

	r = device_read_lock(cd, crypt_metadata_device(cd));
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s.\n"),
			device_path(crypt_metadata_device(cd)));
		return r;
	}

	r = LUKS2_disk_hdr_read(cd, hdr, crypt_metadata_device(cd), 1);
	if (r == -EAGAIN) {
		/* unlikely: auto-recovery is required and failed due to read lock being held */
		device_read_unlock(crypt_metadata_device(cd));

		r = device_write_lock(cd, crypt_metadata_device(cd));
		if (r) {
			log_err(cd, _("Failed to acquire write lock on device %s.\n"),
				device_path(crypt_metadata_device(cd)));
			return r;
		}

		r = LUKS2_disk_hdr_read(cd, hdr, crypt_metadata_device(cd), 1);

		device_write_unlock(crypt_metadata_device(cd));
	} else
		device_read_unlock(crypt_metadata_device(cd));

	return r;
}

/* NOTE: is called before LUKS2 validation routines */
static void LUKS2_hdr_free_unused_objects(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	/* erase unused digests (no assigned keyslot or segment) */
	LUKS2_digests_erase_unused(cd, hdr);
}

int LUKS2_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	/* FIXME: we risk to hide future internal implementation bugs with this */
	LUKS2_hdr_free_unused_objects(cd, hdr);

	if (LUKS2_hdr_validate(hdr->jobj))
		return -EINVAL;

	return LUKS2_disk_hdr_write(cd, hdr, crypt_metadata_device(cd));
}

int LUKS2_hdr_uuid(struct crypt_device *cd, struct luks2_hdr *hdr, const char *uuid)
{
	uuid_t partitionUuid;

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(cd, _("Wrong LUKS UUID format provided.\n"));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	uuid_unparse(partitionUuid, hdr->uuid);

	/* FIXME: why is this not LUKS2_hdr_write? */
	return LUKS2_disk_hdr_write(cd, hdr, crypt_metadata_device(cd));
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

void LUKS2_hdr_free(struct luks2_hdr *hdr)
{
	if (json_object_put(hdr->jobj))
		hdr->jobj = NULL;
	else if (hdr->jobj)
		log_dbg("LUKS2 header still in use");
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
	json_object *jobj1, *jobj2;
	uint64_t json_size;

	json_object_object_get_ex(jobj, "config", &jobj1);
	json_object_object_get_ex(jobj1, "json_size", &jobj2);
	json_str_to_uint64(jobj2, &json_size);

	return 2 * (json_size + LUKS2_HDR_BIN_LEN) + LUKS2_keyslots_size(jobj);
}

int LUKS2_hdr_backup(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file)
{
	struct device *device = crypt_metadata_device(cd);
	int r = 0, devfd = -1;
	ssize_t hdr_size;
	ssize_t buffer_size;
	char *buffer = NULL;

	hdr_size = LUKS2_hdr_and_areas_size(hdr->jobj);
	buffer_size = size_round_up(hdr_size, crypt_getpagesize());

	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer)
		return -ENOMEM;

	log_dbg("Storing backup of header (%zu bytes).", hdr_size);
	log_dbg("Output backup file size: %zu bytes.", buffer_size);

	r = device_read_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s.\n"),
			device_path(crypt_metadata_device(cd)));
		crypt_safe_free(buffer);
		return r;
	}

	devfd = device_open_locked(device, O_RDONLY);
	if (devfd < 0) {
		device_read_unlock(device);
		log_err(cd, _("Device %s is not a valid LUKS device.\n"), device_path(device));
		crypt_safe_free(buffer);
		return devfd == -1 ? -EINVAL : devfd;
	}

	if (read_blockwise(devfd, device_block_size(device),
			   device_alignment(device), buffer, hdr_size) < hdr_size) {
		close(devfd);
		device_read_unlock(device);
		crypt_safe_free(buffer);
		return -EIO;
	}
	close(devfd);

	device_read_unlock(device);

	devfd = open(backup_file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR);
	if (devfd == -1) {
		if (errno == EEXIST)
			log_err(cd, _("Requested header backup file %s already exists.\n"), backup_file);
		else
			log_err(cd, _("Cannot create header backup file %s.\n"), backup_file);
		crypt_safe_free(buffer);
		return -EINVAL;
	}
	if (write_buffer(devfd, buffer, buffer_size) < buffer_size) {
		log_err(cd, _("Cannot write header backup file %s.\n"), backup_file);
		r = -EIO;
	} else
		r = 0;

	close(devfd);
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

int LUKS2_hdr_restore(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file)
{
	struct device *backup_device, *device = crypt_metadata_device(cd);
	int r, devfd = -1, diff_uuid = 0;
	ssize_t buffer_size = 0;
	char *buffer = NULL, msg[1024];
	struct luks2_hdr hdr_file;
	struct luks2_hdr tmp_hdr = {};
	uint32_t reqs = 0;

	r = device_alloc(&backup_device, backup_file);
	if (r < 0)
		return r;

	/* FIXME: why lock backup device ? */
	r = device_read_lock(cd, backup_device);
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s.\n"),
			device_path(backup_device));
		device_free(backup_device);
		return r;
	}

	r = LUKS2_disk_hdr_read(cd, &hdr_file, backup_device, 0);
	device_read_unlock(backup_device);
	device_free(backup_device);

	if (r < 0) {
		log_err(cd, _("Backup file doesn't contain valid LUKS header.\n"));
		goto out;
	}

	/* do not allow header restore from backup with unmet requirements */
	if (LUKS2_unmet_requirements(cd, &hdr_file, 0, 1)) {
		log_err(cd, _("Forbidden LUKS2 requirements detected in backup %s.\n"),
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

	devfd = open(backup_file, O_RDONLY);
	if (devfd == -1) {
		log_err(cd, _("Cannot open header backup file %s.\n"), backup_file);
		r = -EINVAL;
		goto out;
	}

	if (read_buffer(devfd, buffer, buffer_size) < buffer_size) {
		log_err(cd, _("Cannot read header backup file %s.\n"), backup_file);
		r = -EIO;
		goto out;
	}
	close(devfd);
	devfd = -1;

	r = LUKS2_hdr_read(cd, &tmp_hdr);
	if (r == 0) {
		log_dbg("Device %s already contains LUKS2 header, checking UUID and requirements.", device_path(device));
		r = LUKS2_config_get_requirements(cd, &tmp_hdr, &reqs);
		if (r)
			goto out;

		if (memcmp(tmp_hdr.uuid, hdr_file.uuid, LUKS2_UUID_L))
			diff_uuid = 1;

		if (!reqs_reencrypt(reqs)) {
			log_dbg("Checking LUKS2 header size and offsets.");
			if (LUKS2_get_data_offset(&tmp_hdr) != LUKS2_get_data_offset(&hdr_file)) {
				log_err(cd, _("Data offset differ on device and backup, restore failed.\n"));
				r = -EINVAL;
				goto out;
			}
			/* FIXME: what could go wrong? Erase if we're fine with consequences */
			if (buffer_size != (ssize_t) LUKS2_hdr_and_areas_size(tmp_hdr.jobj)) {
				log_err(cd, _("Binary header with keyslot areas size differ on device and backup, restore failed.\n"));
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

	log_dbg("Storing backup of header (%zu bytes) to device %s.", buffer_size, device_path(device));

	/* TODO: perform header restore on bdev in stand-alone routine? */
	r = device_write_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s.\n"),
			device_path(device));
		goto out;
	}

	devfd = device_open_locked(device, O_RDWR);
	if (devfd < 0) {
		if (errno == EACCES)
			log_err(cd, _("Cannot write to device %s, permission denied.\n"),
				device_path(device));
		else
			log_err(cd, _("Cannot open device %s.\n"), device_path(device));
		device_write_unlock(device);
		r = -EINVAL;
		goto out;
	}

	if (write_blockwise(devfd, device_block_size(device),
			    device_alignment(device), buffer, buffer_size) < buffer_size)
		r = -EIO;
	else
		r = 0;

	device_write_unlock(device);
	/* end of TODO */

out:
	LUKS2_hdr_free(&hdr_file);
	LUKS2_hdr_free(&tmp_hdr);
	crypt_memzero(&hdr_file, sizeof(hdr_file));
	crypt_memzero(&tmp_hdr, sizeof(tmp_hdr));
	crypt_safe_free(buffer);

	if (devfd >= 0)
		close(devfd);

	if (!r) {
		LUKS2_hdr_free(hdr);
		r = LUKS2_hdr_read(cd, hdr);
	}

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
	int i, j;

	if (!hdr || !flags)
		return -EINVAL;

	if (!json_object_object_get_ex(hdr->jobj, "config", &jobj_config))
		return 0;

	if (!json_object_object_get_ex(jobj_config, "flags", &jobj_flags))
		return 0;

	for (i = 0; i < (int) json_object_array_length(jobj_flags); i++) {
		jobj1 = json_object_array_get_idx(jobj_flags, i);
		for (j = 0; persistent_flags[j].description; j++) {
			if (!strcmp(persistent_flags[j].description,
				    json_object_get_string(jobj1))) {
				*flags |= persistent_flags[j].flag;
				log_dbg("Using persistent flag %s.",
					json_object_get_string(jobj1));
				break;
			}
			log_verbose(cd, _("Ignored unknown flag %s."),
				json_object_get_string(jobj1));
		}
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
		if (flags & persistent_flags[i].flag)
			json_object_array_add(jobj_flags,
				json_object_new_string(persistent_flags[i].description));
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

	log_dbg("LUKS2 requirements detected:");

	for (i = 0; i < len; i++) {
		jobj = json_object_array_get_idx(jobj_mandatory, i);
		req = get_requirement_by_name(json_object_get_string(jobj));
		log_dbg("%s - %sknown", json_object_get_string(jobj),
				        reqs_unknown(req) ? "un" : "");
		*reqs |= req;
	}

	return 0;
}

int LUKS2_config_set_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs)
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
		log_dbg("Illegal requirement flag(s) requested");
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

	return LUKS2_hdr_write(cd, hdr);
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

		r = LUKS2_keyslot_for_segment(crypt_get_hdr(cd, CRYPT_LUKS2), j, CRYPT_DEFAULT_SEGMENT);
		log_std(cd, "  %s: %s%s\n", slot, tmps, r == -ENOENT ? " (unbound)" : "");

		if (json_object_object_get_ex(val, "key_size", &jobj2))
			log_std(cd, "\tKey:        %u bits\n", json_object_get_uint32(jobj2) * 8);

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

/* FIXME: sort segments when more segments available later */
static void hdr_dump_segments(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj1, *jobj2, *jobj3;
	uint64_t value;

	log_std(cd, "Data segments:\n");
	json_object_object_get_ex(hdr_jobj, "segments", &jobj1);

	json_object_object_foreach(jobj1, key, val) {
		json_object_object_get_ex(val, "type", &jobj2);
		log_std(cd, "  %s: %s\n", key, json_object_get_string(jobj2));

		json_object_object_get_ex(val, "offset", &jobj3);
		json_str_to_uint64(jobj3, &value);
		log_std(cd, "\toffset: %" PRIu64 " [bytes]\n", value);

		json_object_object_get_ex(val, "size", &jobj3);
		if (!(strcmp(json_object_get_string(jobj3), "dynamic")))
			log_std(cd, "\tlength: (whole device)\n");
		else {
			json_str_to_uint64(jobj3, &value);
			log_std(cd, "\tlength: %" PRIu64 " [bytes]\n", value);
		}

		json_object_object_get_ex(val, "encryption", &jobj3);
		log_std(cd, "\tcipher: %s\n", json_object_get_string(jobj3));

		json_object_object_get_ex(val, "sector_size", &jobj3);
		log_std(cd, "\tsector: %" PRIu32 " [bytes]\n", json_object_get_uint32(jobj3));

		if (json_object_object_get_ex(val, "integrity", &jobj2) &&
		    json_object_object_get_ex(jobj2, "type", &jobj3))
			log_std(cd, "\tintegrity: %s\n", json_object_get_string(jobj3));

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

	JSON_DBG(hdr->jobj, NULL);

	log_std(cd, "LUKS header information\n");
	log_std(cd, "Version:       \t%u\n", hdr->version);
	log_std(cd, "Epoch:         \t%" PRIu64 "\n", hdr->seqid);
	log_std(cd, "Metadata area: \t%zu bytes\n", hdr->hdr_size - LUKS2_HDR_BIN_LEN);
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

uint64_t LUKS2_get_data_offset(struct luks2_hdr *hdr)
{
	json_object *jobj1;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return 0;

	return get_first_data_offset(jobj1, "crypt") / SECTOR_SIZE;
}

const char *LUKS2_get_cipher(struct luks2_hdr *hdr, int segment)
{
	json_object *jobj1, *jobj2, *jobj3;
	char buf[16];

	if (segment < 0 || snprintf(buf, sizeof(buf), "%u", segment) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return NULL;

	if (!json_object_object_get_ex(jobj1, buf, &jobj2))
		return NULL;

	if (!json_object_object_get_ex(jobj2, "encryption", &jobj3))
		return NULL;

	return json_object_get_string(jobj3);
}

const char *LUKS2_get_integrity(struct luks2_hdr *hdr, int segment)
{
	json_object *jobj1, *jobj2, *jobj3, *jobj4;
	char buf[16];

	if (segment < 0 || snprintf(buf, sizeof(buf), "%u", segment) < 1)
		return NULL;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return NULL;

	if (!json_object_object_get_ex(jobj1, buf, &jobj2))
		return NULL;

	if (!json_object_object_get_ex(jobj2, "integrity", &jobj3))
		return NULL;

	if (!json_object_object_get_ex(jobj3, "type", &jobj4))
		return NULL;

	return json_object_get_string(jobj4);
}

/* FIXME: this only ensures that once we have journal encryption, it is not ignored. */
static int LUKS2_integrity_compatible(struct luks2_hdr *hdr)
{
	json_object *jobj1, *jobj2, *jobj3, *jobj4;
	const char *str;

	if (!json_object_object_get_ex(hdr->jobj, "segments", &jobj1))
		return 0;

	if (!json_object_object_get_ex(jobj1, CRYPT_DEFAULT_SEGMENT_STR, &jobj2))
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
		return 0;

	if (!json_object_object_get_ex(jobj1, keyslot, &jobj2))
		return 0;

	if (!json_object_object_get_ex(jobj2, "key_size", &jobj3))
		return 0;

	return json_object_get_int(jobj3);
}

int LUKS2_get_keyslot_key_size(struct luks2_hdr *hdr, int keyslot)
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
	json_object *jobj1, *jobj_segment;

	jobj_segment = LUKS2_get_segment_jobj(hdr, CRYPT_DEFAULT_SEGMENT);
	if (!jobj_segment)
		return SECTOR_SIZE;

	json_object_object_get_ex(jobj_segment, "sector_size", &jobj1);
	if (!jobj1)
		return SECTOR_SIZE;

	return json_object_get_int(jobj1);
}

int LUKS2_activate(struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	uint32_t flags)
{
	int r;
	enum devcheck device_check;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
	struct crypt_dm_active_device dmd = {
		.target = DM_CRYPT,
		.uuid   = crypt_get_uuid(cd),
		.flags  = flags,
		.size   = 0,
		.data_device = crypt_data_device(cd),
		.u.crypt = {
			.vk     = vk,
			.offset = crypt_get_data_offset(cd),
			.cipher = LUKS2_get_cipher(hdr, 0),
			.integrity = crypt_get_integrity(cd),
			.iv_offset = 0,
			.tag_size = crypt_get_integrity_tag_size(cd),
			.sector_size = crypt_get_sector_size(cd)
		}
	};
	char dm_int_name[PATH_MAX], dm_int_dev_name[PATH_MAX];
	struct device *device = NULL;

	/* do not allow activation when particular requirements detected */
	if ((r = LUKS2_unmet_requirements(cd, hdr, 0, 0)))
		return r;

	/* Add persistent activation flags */
	if (!(flags & CRYPT_ACTIVATE_IGNORE_PERSISTENT))
		LUKS2_config_get_flags(cd, hdr, &dmd.flags);

	if (dmd.flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_SHARED;
	else
		device_check = DEV_EXCL;

	if (dmd.u.crypt.tag_size) {
		if (!LUKS2_integrity_compatible(hdr)) {
			log_err(cd, "Unsupported device integrity configuration.\n");
			return -EINVAL;
		}

		snprintf(dm_int_name, sizeof(dm_int_name), "%s_dif", name);
		r = INTEGRITY_activate(cd, dm_int_name, NULL, NULL, NULL, NULL, flags);
		if (r)
			return r;

		snprintf(dm_int_dev_name, sizeof(dm_int_dev_name), "%s/%s", dm_get_dir(), dm_int_name);
		r = device_alloc(&device, dm_int_dev_name);
		if (r) {
			dm_remove_device(cd, dm_int_name, 0);
			return r;
		}

		/* Space for IV metadata only */
		if (!dmd.u.crypt.integrity)
			dmd.u.crypt.integrity = "none";

		dmd.data_device = device;
		dmd.u.crypt.offset = 0;

		r = INTEGRITY_data_sectors(cd, crypt_data_device(cd),
					   crypt_get_data_offset(cd) * SECTOR_SIZE,
					   &dmd.size);
		if (r < 0) {
			log_err(cd, "Cannot detect integrity device size.\n");
			device_free(device);
			dm_remove_device(cd, dm_int_name, 0);
			return r;
		}
	}

	r = device_block_adjust(cd, dmd.data_device, device_check,
				 dmd.u.crypt.offset, &dmd.size, &dmd.flags);
	if (!r)
		r = dm_create_device(cd, name, CRYPT_LUKS2, &dmd, 0);

	if (r < 0 && dmd.u.crypt.integrity)
		dm_remove_device(cd, dm_int_name, 0);

	device_free(device);
	return r;
}

int LUKS2_unmet_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs_mask, int quiet)
{
	uint32_t reqs;
	int r = LUKS2_config_get_requirements(cd, hdr, &reqs);

	if (r) {
		if (!quiet)
			log_err(cd, _("Failed to read LUKS2 requirements.\n"));
		return r;
	}

	/* do not mask unknown requirements check */
	if (reqs_unknown(reqs)) {
		if (!quiet)
			log_err(cd, _("Unmet LUKS2 requirements detected.\n"));
		return -ETXTBSY;
	}

	/* mask out permitted requirements */
	reqs &= ~reqs_mask;

	if (reqs_reencrypt(reqs) && !quiet)
		log_err(cd, _("Offline reencryption in progress. Aborting.\n"));

	/* any remaining unmasked requirement fails the check */
	return reqs ? -EINVAL : 0;
}
