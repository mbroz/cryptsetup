// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2025 Milan Broz
 * Copyright (C) 2015-2025 Ondrej Kozina
 */

#include "luks2_internal.h"
#include "luks2/hw_opal/hw_opal.h"
#include "../integrity/integrity.h"
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

	if (crypt_base64_decode(&buf, &buf_len, json_object_get_string(jobj),
				json_object_get_string_len(jobj)))
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
	if (!array_new)
		return NULL;

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

	if (LUKS2_segments_count(hdr) >= 1)
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
static bool json_str_to_uint64(json_object *jobj, uint64_t *value)
{
	char *endptr;
	unsigned long long tmp;

	errno = 0;
	tmp = strtoull(json_object_get_string(jobj), &endptr, 10);
	if (*endptr || errno) {
		*value = 0;
		return false;
	}

	*value = tmp;
	return true;
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
static bool numbered(struct crypt_device *cd, const char *name, const char *key)
{
	int i;

	for (i = 0; key[i]; i++)
		if (!isdigit(key[i])) {
			log_dbg(cd, "%s \"%s\" is not in numbered form.", name, key);
			return false;
		}
	return true;
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

json_object *json_contains_string(struct crypt_device *cd, json_object *jobj,
				  const char *name, const char *section, const char *key)
{
	json_object *sobj = json_contains(cd, jobj, name, section, key, json_type_string);

	if (!sobj)
		return NULL;

	if (strlen(json_object_get_string(sobj)) < 1)
		return NULL;

	return sobj;
}

bool validate_json_uint32(json_object *jobj)
{
	int64_t tmp;

	errno = 0;
	tmp = json_object_get_int64(jobj);

	return (errno || tmp < 0 || tmp > UINT32_MAX) ? false : true;
}

static bool validate_keyslots_array(struct crypt_device *cd, json_object *jarr, json_object *jobj_keys)
{
	json_object *jobj;
	int i = 0, length = (int) json_object_array_length(jarr);

	while (i < length) {
		jobj = json_object_array_get_idx(jarr, i);
		if (!json_object_is_type(jobj, json_type_string)) {
			log_dbg(cd, "Illegal value type in keyslots array at index %d.", i);
			return false;
		}

		if (!json_contains(cd, jobj_keys, "", "Keyslots section",
				   json_object_get_string(jobj), json_type_object))
			return false;

		i++;
	}

	return true;
}

static bool validate_segments_array(struct crypt_device *cd, json_object *jarr, json_object *jobj_segments)
{
	json_object *jobj;
	int i = 0, length = (int) json_object_array_length(jarr);

	while (i < length) {
		jobj = json_object_array_get_idx(jarr, i);
		if (!json_object_is_type(jobj, json_type_string)) {
			log_dbg(cd, "Illegal value type in segments array at index %d.", i);
			return false;
		}

		if (!json_contains(cd, jobj_segments, "", "Segments section",
				   json_object_get_string(jobj), json_type_object))
			return false;

		i++;
	}

	return true;
}

static bool segment_has_digest(const char *segment_name, json_object *jobj_digests)
{
	json_object *jobj_segments;

	json_object_object_foreach(jobj_digests, key, val) {
		UNUSED(key);
		json_object_object_get_ex(val, "segments", &jobj_segments);
		if (LUKS2_array_jobj(jobj_segments, segment_name))
			return true;
	}

	return false;
}


static bool validate_intervals(struct crypt_device *cd,
			       int length, const struct interval *ix,
			       uint64_t metadata_size, uint64_t keyslots_area_end)
{
	int j, i = 0;

	while (i < length) {
		/* Offset cannot be inside primary or secondary JSON area */
		if (ix[i].offset < 2 * metadata_size) {
			log_dbg(cd, "Illegal area offset: %" PRIu64 ".", ix[i].offset);
			return false;
		}

		if (!ix[i].length) {
			log_dbg(cd, "Area length must be greater than zero.");
			return false;
		}

		if (ix[i].offset > (UINT64_MAX - ix[i].length)) {
			log_dbg(cd, "Interval offset+length overflow.");
			return false;
		}

		if ((ix[i].offset + ix[i].length) > keyslots_area_end) {
			log_dbg(cd, "Area [%" PRIu64 ", %" PRIu64 "] overflows binary keyslots area (ends at offset: %" PRIu64 ").",
				ix[i].offset, ix[i].offset + ix[i].length, keyslots_area_end);
			return false;
		}

		for (j = 0; j < length; j++) {
			if (i == j)
				continue;

			if (ix[j].offset > (UINT64_MAX - ix[j].length)) {
				log_dbg(cd, "Interval offset+length overflow.");
				return false;
			}

			if ((ix[i].offset >= ix[j].offset) && (ix[i].offset < (ix[j].offset + ix[j].length))) {
				log_dbg(cd, "Overlapping areas [%" PRIu64 ",%" PRIu64 "] and [%" PRIu64 ",%" PRIu64 "].",
					ix[i].offset, ix[i].offset + ix[i].length,
					ix[j].offset, ix[j].offset + ix[j].length);
				return false;
			}
		}

		i++;
	}

	return true;
}

static int LUKS2_keyslot_validate(struct crypt_device *cd, json_object *hdr_keyslot, const char *key)
{
	json_object *jobj_key_size;

	if (!json_contains_string(cd, hdr_keyslot, key, "Keyslot", "type"))
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

	if (!json_contains_string(cd, jobj_token, key, "Token", "type"))
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

	json = crypt_jobj_to_string_on_disk(hdr_jobj);
	if (!json)
		return 1;

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

	if (!(jobj = json_contains(cd, hdr_jobj, "", "JSON area", "keyslots", json_type_object)))
		return 1;

	json_object_object_foreach(jobj, key, val) {
		if (!numbered(cd, "Keyslot", key))
			return 1;
		if (LUKS2_keyslot_validate(cd, val, key))
			return 1;
	}

	return 0;
}

static int hdr_validate_tokens(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj;

	if (!(jobj = json_contains(cd, hdr_jobj, "", "JSON area", "tokens", json_type_object)))
		return 1;

	json_object_object_foreach(jobj, key, val) {
		if (!numbered(cd, "Token", key))
			return 1;
		if (LUKS2_token_validate(cd, hdr_jobj, val, key))
			return 1;
	}

	return 0;
}

static int hdr_validate_crypt_segment(struct crypt_device *cd, json_object *jobj,
				      const char *key, json_object *jobj_digests,
				      uint64_t size)
{
	int r;
	json_object *jobj_ivoffset, *jobj_sector_size, *jobj_integrity;
	uint32_t sector_size;
	uint64_t ivoffset;

	if (!(jobj_ivoffset = json_contains_string(cd, jobj, key, "Segment", "iv_tweak")) ||
	    !json_contains_string(cd, jobj, key, "Segment", "encryption") ||
	    !(jobj_sector_size = json_contains(cd, jobj, key, "Segment", "sector_size", json_type_int)))
		return 1;

	/* integrity */
	if (json_object_object_get_ex(jobj, "integrity", &jobj_integrity)) {
		if (!json_contains(cd, jobj, key, "Segment", "integrity", json_type_object) ||
		    !json_contains_string(cd, jobj_integrity, key, "Segment integrity", "type") ||
		    !json_contains_string(cd, jobj_integrity, key, "Segment integrity", "journal_encryption") ||
		    !json_contains_string(cd, jobj_integrity, key, "Segment integrity", "journal_integrity"))
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

	r = segment_has_digest(key, jobj_digests);

	if (!r)
		log_dbg(cd, "Crypt segment %s not assigned to key digest.", key);

	return !r;
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

			if (ix[j].length != UINT64_MAX && ix[j].offset > (UINT64_MAX - ix[j].length)) {
				log_dbg(cd, "Interval offset+length overflow.");
				return false;
			}

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

static int reqs_opal(uint32_t reqs)
{
	return reqs & CRYPT_REQUIREMENT_OPAL;
}

static int reqs_inline_hw_tags(uint32_t reqs)
{
	return reqs & CRYPT_REQUIREMENT_INLINE_HW_TAGS;
}

/*
 * Config section requirements object must be valid.
 * Also general segments section must be validated first.
 */
static int validate_reencrypt_segments(struct crypt_device *cd, json_object *hdr_jobj, json_object *jobj_segments, int first_backup, int segments_count)
{
	json_object *jobj, *jobj_backup_previous = NULL, *jobj_backup_final = NULL;
	uint32_t reqs;
	int i;
	struct luks2_hdr dummy = {
		.jobj = hdr_jobj
	};

	LUKS2_config_get_requirements(cd, &dummy, &reqs);

	if (reqs_reencrypt_online(reqs)) {
		for (i = first_backup; i < segments_count; i++) {
			jobj = json_segments_get_segment(jobj_segments, i);
			if (!jobj)
				return 1;
			if (json_segment_contains_flag(jobj, "backup-final", 0))
				jobj_backup_final = jobj;
			else if (json_segment_contains_flag(jobj, "backup-previous", 0))
				jobj_backup_previous = jobj;
		}

		if (!jobj_backup_final || !jobj_backup_previous) {
			log_dbg(cd, "Backup segment is missing.");
			return 1;
		}

		for (i = 0; i < first_backup; i++) {
			jobj = json_segments_get_segment(jobj_segments, i);
			if (!jobj)
				return 1;

			if (json_segment_contains_flag(jobj, "in-reencryption", 0)) {
				if (!json_segment_cmp(jobj, jobj_backup_final)) {
					log_dbg(cd, "Segment in reencryption does not match backup final segment.");
					return 1;
				}
				continue;
			}

			if (!json_segment_cmp(jobj, jobj_backup_final) &&
			    !json_segment_cmp(jobj, jobj_backup_previous)) {
				log_dbg(cd, "Segment does not match neither backup final or backup previous segment.");
				return 1;
			}
		}
	}

	return 0;
}

static int hdr_validate_segments(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj_segments, *jobj_digests, *jobj_offset, *jobj_size, *jobj_type, *jobj_flags, *jobj;
	uint64_t offset, size, opal_segment_size;
	int i, r, count, first_backup = -1;
	struct interval *intervals = NULL;

	if (!(jobj_segments = json_contains(cd, hdr_jobj, "", "JSON area", "segments", json_type_object)))
		return 1;

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
		if (!(jobj_type =   json_contains_string(cd, val, key, "Segment", "type")) ||
		    !(jobj_offset = json_contains_string(cd, val, key, "Segment", "offset")) ||
		    !(jobj_size =   json_contains_string(cd, val, key, "Segment", "size")))
			return 1;

		if (!numbered(cd, "offset", json_object_get_string(jobj_offset)))
			return 1;

		if (!json_str_to_uint64(jobj_offset, &offset)) {
			log_dbg(cd, "Illegal segment offset value.");
			return 1;
		}

		/* size "dynamic" means whole device starting at 'offset' */
		if (strcmp(json_object_get_string(jobj_size), "dynamic")) {
			if (!numbered(cd, "size", json_object_get_string(jobj_size)))
				return 1;
			if (!json_str_to_uint64(jobj_size, &size) || !size) {
				log_dbg(cd, "Illegal segment size value.");
				return 1;
			}
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
		    hdr_validate_crypt_segment(cd, val, key, jobj_digests, size))
			return 1;

		/* opal */
		if (!strncmp(json_object_get_string(jobj_type), "hw-opal", 7)) {
			if (!size) {
				log_dbg(cd, "segment type %s does not support dynamic size.",
					json_object_get_string(jobj_type));
				return 1;
			}
			if (!json_contains(cd, val, key, "Segment", "opal_segment_number", json_type_int) ||
			    !json_contains(cd, val, key, "Segment", "opal_key_size", json_type_int) ||
			    !(jobj_size = json_contains_string(cd, val, key, "Segment", "opal_segment_size")))
				return 1;
			if (!numbered(cd, "opal_segment_size", json_object_get_string(jobj_size)))
				return 1;
			if (!json_str_to_uint64(jobj_size, &opal_segment_size) || !opal_segment_size) {
				log_dbg(cd, "Illegal OPAL segment size value.");
				return 1;
			}
			if (size > opal_segment_size) {
				log_dbg(cd, "segment size overflows OPAL locking range size.");
				return 1;
			}
			if (!strcmp(json_object_get_string(jobj_type), "hw-opal-crypt") &&
			    hdr_validate_crypt_segment(cd, val, key, jobj_digests, size))
				return 1;
		}
	}

	if (first_backup == 0) {
		log_dbg(cd, "No regular segment.");
		return 1;
	}

	/* avoid needlessly large allocation when first backup segment is invalid */
	if (first_backup >= count) {
		log_dbg(cd, "Gap between last regular segment and backup segment at key %d.", first_backup);
		return 1;
	}

	if (first_backup < 0)
		first_backup = count;

	if ((size_t)first_backup < SIZE_MAX / sizeof(*intervals))
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

	return validate_reencrypt_segments(cd, hdr_jobj, jobj_segments, first_backup, count);
}

static uint64_t LUKS2_metadata_size_jobj(json_object *jobj)
{
	json_object *jobj1, *jobj2;
	uint64_t json_size;

	json_object_object_get_ex(jobj, "config", &jobj1);
	json_object_object_get_ex(jobj1, "json_size", &jobj2);
	json_str_to_uint64(jobj2, &json_size);

	return json_size + LUKS2_HDR_BIN_LEN;
}

uint64_t LUKS2_metadata_size(struct luks2_hdr *hdr)
{
	return LUKS2_metadata_size_jobj(hdr->jobj);
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
	metadata_size = LUKS2_metadata_size_jobj(hdr_jobj);

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
		    !json_contains_string(cd, jobj_area, key, "Keyslot area", "type") ||
		    !(jobj_offset = json_contains_string(cd, jobj_area, key, "Keyslot", "offset")) ||
		    !(jobj_length = json_contains_string(cd, jobj_area, key, "Keyslot", "size")) ||
		    !numbered(cd, "offset", json_object_get_string(jobj_offset)) ||
		    !numbered(cd, "size", json_object_get_string(jobj_length))) {
			free(intervals);
			return 1;
		}

		/* rule out values > UINT64_MAX */
		if (!json_str_to_uint64(jobj_offset, &intervals[i].offset) ||
		    !json_str_to_uint64(jobj_length, &intervals[i].length)) {
			log_dbg(cd, "Illegal keyslot area values.");
			free(intervals);
			return 1;
		}

		i++;
	}

	if (length != i) {
		free(intervals);
		return 1;
	}

	ret = validate_intervals(cd, length, intervals, metadata_size, LUKS2_hdr_and_areas_size_jobj(hdr_jobj)) ? 0 : 1;

	free(intervals);

	return ret;
}

static int hdr_validate_digests(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jarr_keys, *jarr_segs, *jobj, *jobj_keyslots, *jobj_segments;

	if (!(jobj = json_contains(cd, hdr_jobj, "", "JSON area", "digests", json_type_object)))
		return 1;

	/* keyslots are not yet validated, but we need to know digest doesn't reference missing keyslot */
	if (!(jobj_keyslots = json_contains(cd, hdr_jobj, "", "JSON area", "keyslots", json_type_object)))
		return 1;

	/* segments are not yet validated, but we need to know digest doesn't reference missing segment */
	if (!(jobj_segments = json_contains(cd, hdr_jobj, "", "JSON area", "segments", json_type_object)))
		return 1;

	json_object_object_foreach(jobj, key, val) {
		if (!numbered(cd, "Digest", key))
			return 1;

		if (!json_contains_string(cd, val, key, "Digest", "type") ||
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

/* requirements being validated in stand-alone routine */
static int hdr_validate_config(struct crypt_device *cd, json_object *hdr_jobj)
{
	json_object *jobj_config, *jobj;
	int i;
	uint64_t keyslots_size, metadata_size, segment_offset;

	if (!(jobj_config = json_contains(cd, hdr_jobj, "", "JSON area", "config", json_type_object)))
		return 1;

	if (!(jobj = json_contains_string(cd, jobj_config, "section", "Config", "json_size")))
		return 1;
	if (!json_str_to_uint64(jobj, &metadata_size)) {
		log_dbg(cd, "Illegal config json_size value.");
		return 1;
	}

	/* single metadata instance is assembled from json area size plus
	 * binary header size */
	metadata_size += LUKS2_HDR_BIN_LEN;

	if (!(jobj = json_contains_string(cd, jobj_config, "section", "Config", "keyslots_size")))
		return 1;
	if(!json_str_to_uint64(jobj, &keyslots_size)) {
		log_dbg(cd, "Illegal config keyslot_size value.");
		return 1;
	}

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

	return 0;
}

static bool reencrypt_candidate_flag(const char *flag)
{
	const char *ptr;

	assert(flag);

	if (!strcmp(flag, "online-reencrypt"))
		return true;

	if (strncmp(flag, "online-reencrypt-v", 18))
		return false;

	ptr = flag + 18;
	if (!*ptr)
		return false;

	while (*ptr) {
		if (!isdigit(*ptr))
			return false;
		ptr++;
	}

	return true;
}

static int hdr_validate_requirements(struct crypt_device *cd, json_object *hdr_jobj)
{
	int i;
	json_object *jobj_config, *jobj, *jobj1;
	unsigned online_reencrypt_flag = 0;

	if (!(jobj_config = json_contains(cd, hdr_jobj, "", "JSON area", "config", json_type_object)))
		return 1;

	/* Requirements object is optional */
	if (json_object_object_get_ex(jobj_config, "requirements", &jobj)) {
		if (!json_contains(cd, jobj_config, "section", "Config", "requirements", json_type_object))
			return 1;

		/* Mandatory array is optional */
		if (json_object_object_get_ex(jobj, "mandatory", &jobj1)) {
			if (!json_contains(cd, jobj, "section", "Requirements", "mandatory", json_type_array))
				return 1;

			/* All array members must be strings */
			for (i = 0; i < (int) json_object_array_length(jobj1); i++) {
				if (!json_object_is_type(json_object_array_get_idx(jobj1, i), json_type_string))
					return 1;

				if (reencrypt_candidate_flag(json_object_get_string(json_object_array_get_idx(jobj1, i))))
					online_reencrypt_flag++;

			}
		}
	}

	if (online_reencrypt_flag > 1) {
		log_dbg(cd, "Multiple online reencryption requirement flags detected.");
		return 1;
	}

	return 0;
}

int LUKS2_hdr_validate(struct crypt_device *cd, json_object *hdr_jobj, uint64_t json_size)
{
	struct {
		int (*validate)(struct crypt_device *, json_object *);
	} checks[] = {
		{ hdr_validate_requirements },
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

static bool hdr_json_free(json_object **jobj)
{
	assert(jobj);

	if (json_object_put(*jobj))
		*jobj = NULL;

	return (*jobj == NULL);
}

static int hdr_update_copy_for_rollback(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	json_object **jobj_copy;

	assert(hdr);
	assert(hdr->jobj);

	jobj_copy = (json_object **)&hdr->jobj_rollback;

	if (!hdr_json_free(jobj_copy)) {
		log_dbg(cd, "LUKS2 rollback metadata copy still in use");
		return -EINVAL;
	}

	return json_object_copy(hdr->jobj, jobj_copy) ? -ENOMEM : 0;
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

	if (!r && (r = hdr_update_copy_for_rollback(cd, hdr)))
		log_dbg(cd, "Failed to update rollback LUKS2 metadata.");

	return r;
}

static int hdr_cleanup_and_validate(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	LUKS2_digests_erase_unused(cd, hdr);

	return LUKS2_hdr_validate(cd, hdr->jobj, hdr->hdr_size - LUKS2_HDR_BIN_LEN);
}

int LUKS2_hdr_write_force(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	int r;

	if (hdr_cleanup_and_validate(cd, hdr))
		return -EINVAL;

	r = LUKS2_disk_hdr_write(cd, hdr, crypt_metadata_device(cd), false);

	if (!r && (r = hdr_update_copy_for_rollback(cd, hdr)))
		log_dbg(cd, "Failed to update rollback LUKS2 metadata.");

	return r;
}

int LUKS2_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	int r;

	if (hdr_cleanup_and_validate(cd, hdr))
		return -EINVAL;

	r = LUKS2_disk_hdr_write(cd, hdr, crypt_metadata_device(cd), true);

	if (!r && (r = hdr_update_copy_for_rollback(cd, hdr)))
		log_dbg(cd, "Failed to update rollback LUKS2 metadata.");

	return r;
}

int LUKS2_hdr_rollback(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	json_object **jobj_copy;

	assert(hdr->jobj_rollback);

	log_dbg(cd, "Rolling back in-memory LUKS2 json metadata.");

	jobj_copy = (json_object **)&hdr->jobj;

	if (!hdr_json_free(jobj_copy)) {
		log_dbg(cd, "LUKS2 header still in use");
		return -EINVAL;
	}

	return json_object_copy(hdr->jobj_rollback, jobj_copy) ? -ENOMEM : 0;
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
	if ((label && strlen(label) >= LUKS2_LABEL_L) ||
	    (subsystem && strlen(subsystem) >= LUKS2_LABEL_L)) {
		log_err(cd, _("Label is too long."));
		return -EINVAL;
	}

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
	json_object **jobj;

	assert(hdr);

	jobj = (json_object **)&hdr->jobj;

	if (!hdr_json_free(jobj))
		log_dbg(cd, "LUKS2 header still in use");

	jobj = (json_object **)&hdr->jobj_rollback;

	if (!hdr_json_free(jobj))
		log_dbg(cd, "LUKS2 rollback metadata copy still in use");
}

static uint64_t LUKS2_keyslots_size_jobj(json_object *jobj)
{
	json_object *jobj1, *jobj2;
	uint64_t keyslots_size;

	json_object_object_get_ex(jobj, "config", &jobj1);
	json_object_object_get_ex(jobj1, "keyslots_size", &jobj2);
	json_str_to_uint64(jobj2, &keyslots_size);

	return keyslots_size;
}

uint64_t LUKS2_keyslots_size(struct luks2_hdr *hdr)
{
	return LUKS2_keyslots_size_jobj(hdr->jobj);
}

uint64_t LUKS2_hdr_and_areas_size_jobj(json_object *jobj)
{
	return 2 * LUKS2_metadata_size_jobj(jobj) + LUKS2_keyslots_size_jobj(jobj);
}

uint64_t LUKS2_hdr_and_areas_size(struct luks2_hdr *hdr)
{
	return LUKS2_hdr_and_areas_size_jobj(hdr->jobj);
}

int LUKS2_hdr_backup(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file)
{
	struct device *device = crypt_metadata_device(cd);
	int fd, devfd, r = 0;
	ssize_t hdr_size;
	ssize_t ret, buffer_size;
	char *buffer = NULL;

	hdr_size = LUKS2_hdr_and_areas_size(hdr);
	buffer_size = size_round_up(hdr_size, crypt_getpagesize());

	buffer = malloc(buffer_size);
	if (!buffer)
		return -ENOMEM;

	log_dbg(cd, "Storing backup of header (%zu bytes).", hdr_size);
	log_dbg(cd, "Output backup file size: %zu bytes.", buffer_size);

	r = device_read_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s."),
			device_path(crypt_metadata_device(cd)));
		goto out;
	}

	devfd = device_open_locked(cd, device, O_RDONLY);
	if (devfd < 0) {
		device_read_unlock(cd, device);
		log_err(cd, _("Device %s is not a valid LUKS device."), device_path(device));
		r = (devfd == -1) ? -EINVAL : devfd;
		goto out;
	}

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
			   device_alignment(device), buffer, hdr_size, 0) < hdr_size) {
		device_read_unlock(cd, device);
		r = -EIO;
		goto out;
	}

	device_read_unlock(cd, device);

	fd = open(backup_file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR);
	if (fd == -1) {
		if (errno == EEXIST)
			log_err(cd, _("Requested header backup file %s already exists."), backup_file);
		else
			log_err(cd, _("Cannot create header backup file %s."), backup_file);
		r = -EINVAL;
		goto out;
	}
	ret = write_buffer(fd, buffer, buffer_size);
	close(fd);
	if (ret < buffer_size) {
		log_err(cd, _("Cannot write header backup file %s."), backup_file);
		r = -EIO;
	} else
		r = 0;
out:
	crypt_safe_memzero(buffer, buffer_size);
	free(buffer);
	return r;
}

int LUKS2_hdr_restore(struct crypt_device *cd, struct luks2_hdr *hdr,
		     const char *backup_file)
{
	struct device *backup_device, *device = crypt_metadata_device(cd);
	int r, fd, devfd = -1, diff_uuid = 0;
	ssize_t ret, buffer_size = 0;
	char *buffer = NULL, msg[1024];
	struct luks2_hdr hdr_file = {}, tmp_hdr = {};
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
	if (LUKS2_unmet_requirements(cd, &hdr_file,
	    CRYPT_REQUIREMENT_ONLINE_REENCRYPT | CRYPT_REQUIREMENT_INLINE_HW_TAGS, 1)) {
		log_err(cd, _("Forbidden LUKS2 requirements detected in backup %s."),
			backup_file);
		r = -ETXTBSY;
		goto out;
	}

	buffer_size = LUKS2_hdr_and_areas_size(&hdr_file);
	buffer = malloc(buffer_size);
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
		LUKS2_config_get_requirements(cd, &tmp_hdr, &reqs);

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
			if (buffer_size != (ssize_t) LUKS2_hdr_and_areas_size(&tmp_hdr)) {
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
	crypt_safe_memzero(buffer, buffer_size);
	free(buffer);
	device_sync(cd, device);
	return r;
}

/*
 * Persistent config flags
 */
static const struct  {
	uint64_t flag;
	const char *description;
} persistent_flags[] = {
	{ CRYPT_ACTIVATE_ALLOW_DISCARDS,         "allow-discards" },
	{ CRYPT_ACTIVATE_SAME_CPU_CRYPT,         "same-cpu-crypt" },
	{ CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS, "submit-from-crypt-cpus" },
	{ CRYPT_ACTIVATE_NO_JOURNAL,             "no-journal" },
	{ CRYPT_ACTIVATE_NO_READ_WORKQUEUE,      "no-read-workqueue" },
	{ CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE,     "no-write-workqueue" },
	{ CRYPT_ACTIVATE_HIGH_PRIORITY,          "high_priority" },
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
	if (!jobj_flags)
		return -ENOMEM;

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
struct requirement_flag {
	uint32_t flag;
	uint8_t version;
	const char *description;
};

static const struct requirement_flag unknown_requirement_flag = { CRYPT_REQUIREMENT_UNKNOWN, 0, NULL };

static const struct requirement_flag requirements_flags[] = {
	{ CRYPT_REQUIREMENT_OFFLINE_REENCRYPT,1, "offline-reencrypt" },
	{ CRYPT_REQUIREMENT_ONLINE_REENCRYPT, 2, "online-reencrypt-v2" },
	{ CRYPT_REQUIREMENT_ONLINE_REENCRYPT, 3, "online-reencrypt-v3" },
	{ CRYPT_REQUIREMENT_ONLINE_REENCRYPT, 1, "online-reencrypt" },
	{ CRYPT_REQUIREMENT_INLINE_HW_TAGS,   1, "inline-hw-tags" },
	{ CRYPT_REQUIREMENT_OPAL,	      1, "opal" },
	{ 0, 0, NULL }
};

static const struct requirement_flag *get_requirement_by_name(const char *requirement)
{
	int i;

	for (i = 0; requirements_flags[i].description; i++)
		if (!strcmp(requirement, requirements_flags[i].description))
			return requirements_flags + i;

	return &unknown_requirement_flag;
}

static json_object *mandatory_requirements_jobj(struct luks2_hdr *hdr)
{
	json_object *jobj_config, *jobj_requirements, *jobj_mandatory;

	assert(hdr);

	if (!json_object_object_get_ex(hdr->jobj, "config", &jobj_config))
		return NULL;

	if (!json_object_object_get_ex(jobj_config, "requirements", &jobj_requirements))
		return NULL;

	if (!json_object_object_get_ex(jobj_requirements, "mandatory", &jobj_mandatory))
		return NULL;

	return jobj_mandatory;
}

bool LUKS2_reencrypt_requirement_candidate(struct luks2_hdr *hdr)
{
	json_object *jobj_mandatory;
	int i, len;

	assert(hdr);

	jobj_mandatory = mandatory_requirements_jobj(hdr);
	if (!jobj_mandatory)
		return false;

	len = (int) json_object_array_length(jobj_mandatory);
	if (len <= 0)
		return false;

	for (i = 0; i < len; i++) {
		if (reencrypt_candidate_flag(json_object_get_string(json_object_array_get_idx(jobj_mandatory, i))))
			return true;
	}

	return false;
}

int LUKS2_config_get_reencrypt_version(struct luks2_hdr *hdr, uint8_t *version)
{
	json_object *jobj_mandatory, *jobj;
	int i, len;
	const struct requirement_flag *req;

	assert(hdr);
	assert(version);

	jobj_mandatory = mandatory_requirements_jobj(hdr);
	if (!jobj_mandatory)
		return -ENOENT;

	len = (int) json_object_array_length(jobj_mandatory);
	if (len <= 0)
		return -ENOENT;

	for (i = 0; i < len; i++) {
		jobj = json_object_array_get_idx(jobj_mandatory, i);

		/* search for requirements prefixed with "online-reencrypt" */
		if (strncmp(json_object_get_string(jobj), "online-reencrypt", 16))
			continue;

		/* check current library is aware of the requirement */
		req = get_requirement_by_name(json_object_get_string(jobj));
		if (req->flag == CRYPT_REQUIREMENT_UNKNOWN)
			continue;

		*version = req->version;

		return 0;
	}

	return -ENOENT;
}

static const struct requirement_flag *stored_requirement_name_by_id(struct luks2_hdr *hdr, uint32_t req_id)
{
	json_object *jobj_mandatory, *jobj;
	int i, len;
	const struct requirement_flag *req;

	assert(hdr);

	jobj_mandatory = mandatory_requirements_jobj(hdr);
	if (!jobj_mandatory)
		return NULL;

	len = (int) json_object_array_length(jobj_mandatory);
	if (len <= 0)
		return NULL;

	for (i = 0; i < len; i++) {
		jobj = json_object_array_get_idx(jobj_mandatory, i);
		req = get_requirement_by_name(json_object_get_string(jobj));
		if (req->flag == req_id)
			return req;
	}

	return NULL;
}

/*
 * returns count of requirements (past cryptsetup 2.0 release)
 */
void LUKS2_config_get_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t *reqs)
{
	json_object *jobj_mandatory, *jobj;
	int i, len;
	const struct requirement_flag *req;

	assert(hdr);
	assert(reqs);

	*reqs = 0;

	jobj_mandatory = mandatory_requirements_jobj(hdr);
	if (!jobj_mandatory)
		return;

	len = (int) json_object_array_length(jobj_mandatory);
	if (len <= 0)
		return;

	log_dbg(cd, "LUKS2 requirements detected:");

	for (i = 0; i < len; i++) {
		jobj = json_object_array_get_idx(jobj_mandatory, i);
		req = get_requirement_by_name(json_object_get_string(jobj));
		log_dbg(cd, "%s - %sknown", json_object_get_string(jobj),
				        reqs_unknown(req->flag) ? "un" : "");
		*reqs |= req->flag;
	}
}

int LUKS2_config_set_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs, bool commit)
{
	json_object *jobj_config, *jobj_requirements, *jobj_mandatory, *jobj;
	int i, r = -EINVAL;
	const struct requirement_flag *req;
	uint64_t req_id;

	if (!hdr)
		return -EINVAL;

	jobj_mandatory = json_object_new_array();
	if (!jobj_mandatory)
		return -ENOMEM;

	for (i = 0; requirements_flags[i].description; i++) {
		req_id = reqs & requirements_flags[i].flag;
		if (req_id) {
			/* retain already stored version of requirement flag */
			req = stored_requirement_name_by_id(hdr, req_id);
			if (req)
				jobj = json_object_new_string(req->description);
			else
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

static json_object *LUKS2_get_mandatory_requirements_filtered_jobj(struct luks2_hdr *hdr,
	uint32_t filter_req_ids)
{
	int i, len;
	const struct requirement_flag *req;
	json_object *jobj_mandatory, *jobj_mandatory_filtered, *jobj;

	jobj_mandatory_filtered = json_object_new_array();
	if (!jobj_mandatory_filtered)
		return NULL;

	jobj_mandatory = mandatory_requirements_jobj(hdr);
	if (!jobj_mandatory)
		return jobj_mandatory_filtered;

	len = (int) json_object_array_length(jobj_mandatory);

	for (i = 0; i < len; i++) {
		jobj = json_object_array_get_idx(jobj_mandatory, i);
		req = get_requirement_by_name(json_object_get_string(jobj));
		if (req->flag == CRYPT_REQUIREMENT_UNKNOWN || req->flag & filter_req_ids)
			continue;
		json_object_array_add(jobj_mandatory_filtered,
			json_object_new_string(req->description));
	}

	return jobj_mandatory_filtered;
}

/*
 * The function looks for specific version of requirement id.
 * If it can't be fulfilled function fails.
 */
int LUKS2_config_set_requirement_version(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint32_t req_id,
	uint8_t req_version,
	bool commit)
{
	json_object *jobj_config, *jobj_requirements, *jobj_mandatory;
	const struct requirement_flag *req;
	int r = -EINVAL;

	if (!hdr || req_id == CRYPT_REQUIREMENT_UNKNOWN)
		return -EINVAL;

	req = requirements_flags;

	while (req->description) {
		/* we have a match */
		if (req->flag == req_id && req->version == req_version)
			break;
		req++;
	}

	if (!req->description)
		return -EINVAL;

	/*
	 * Creates copy of mandatory requirements set without specific requirement
	 * (no matter the version) we want to set.
	 */
	jobj_mandatory = LUKS2_get_mandatory_requirements_filtered_jobj(hdr, req_id);
	if (!jobj_mandatory)
		return -ENOMEM;

	json_object_array_add(jobj_mandatory, json_object_new_string(req->description));

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

	json_object_object_add(jobj_requirements, "mandatory", jobj_mandatory);

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
		if (snprintf(slot, sizeof(slot), "%i", j) < 0)
			slot[0] = '\0';
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
		if (snprintf(token, sizeof(token), "%i", j) < 0)
			token[0] = '\0';
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
			log_std(cd, "\tKeyslot:    %s\n", json_object_get_string(jobj3));
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
		if (snprintf(segment, sizeof(segment), "%i", i) < 0)
			segment[0] = '\0';
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
		else
			log_std(cd, "\tcipher: (no SW encryption)\n");

		if (json_object_object_get_ex(jobj_segment, "sector_size", &jobj1))
			log_std(cd, "\tsector: %" PRIu32 " [bytes]\n", crypt_jobj_get_uint32(jobj1));

		if (json_object_object_get_ex(jobj_segment, "integrity", &jobj1) &&
		    json_object_object_get_ex(jobj1, "type", &jobj2))
			log_std(cd, "\tintegrity: %s\n", json_object_get_string(jobj2));

		if (json_object_object_get_ex(jobj_segment, "integrity", &jobj1) &&
		    json_object_object_get_ex(jobj1, "key_size", &jobj2))
			log_std(cd, "\tintegrity key size: %" PRIu32 " [bits]\n", crypt_jobj_get_uint32(jobj2) * 8);

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

		json_object_object_get_ex(jobj_segment, "type", &jobj1);
		if (!strncmp(json_object_get_string(jobj1), "hw-opal", 7)) {
			log_std(cd, "\tHW OPAL encryption:\n");
			json_object_object_get_ex(jobj_segment, "opal_segment_number", &jobj1);
			log_std(cd, "\t\tOPAL segment number: %" PRIu32 "\n", crypt_jobj_get_uint32(jobj1));
			json_object_object_get_ex(jobj_segment, "opal_key_size", &jobj1);
			log_std(cd, "\t\tOPAL key: %" PRIu32 " bits\n", crypt_jobj_get_uint32(jobj1) * 8);
			json_object_object_get_ex(jobj_segment, "opal_segment_size", &jobj1);
			json_str_to_uint64(jobj1, &value);
			log_std(cd, "\t\tOPAL segment length: %" PRIu64 " [bytes]\n", value);
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
		if (snprintf(key, sizeof(key), "%i", i) < 0)
			key[0] = '\0';
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
	log_std(cd, "Metadata area: \t%" PRIu64 " [bytes]\n", LUKS2_metadata_size(hdr));
	log_std(cd, "Keyslots area: \t%" PRIu64 " [bytes]\n", LUKS2_keyslots_size(hdr));
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

int LUKS2_hdr_dump_json(struct crypt_device *cd, struct luks2_hdr *hdr, const char **json)
{
	const char *json_buf;

	json_buf = json_object_to_json_string_ext(hdr->jobj,
		JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);

	if (!json_buf)
		return -EINVAL;

	if (json)
		*json = json_buf;
	else
		crypt_log(cd, CRYPT_LOG_NORMAL, json_buf);

	return 0;
}

int LUKS2_get_data_size(struct luks2_hdr *hdr, uint64_t *size, bool *dynamic)
{
	int i, len, sector_size;
	json_object *jobj_segments, *jobj_segment, *jobj_size;
	uint64_t tmp = 0;

	if (!size || !json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments))
		return -EINVAL;

	len = json_object_object_length(jobj_segments);

	for (i = 0; i < len; i++) {
		if (!(jobj_segment = json_segments_get_segment(jobj_segments, i)))
			return -EINVAL;

		if (json_segment_is_backup(jobj_segment))
			break;

		json_object_object_get_ex(jobj_segment, "size", &jobj_size);
		if (!strcmp(json_object_get_string(jobj_size), "dynamic")) {
			sector_size = json_segment_get_sector_size(jobj_segment);
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

	ri = LUKS2_reencrypt_status(hdr);
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

crypt_reencrypt_info LUKS2_reencrypt_status(struct luks2_hdr *hdr)
{
	uint32_t reqs;

	LUKS2_config_get_requirements(NULL, hdr, &reqs);

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

int LUKS2_get_integrity_key_size(struct luks2_hdr *hdr, int segment)
{
	json_object *jobj1, *jobj2, *jobj3;

	jobj1 = LUKS2_get_segment_jobj(hdr, segment);
	if (!jobj1)
		return -1;

	if (!json_object_object_get_ex(jobj1, "integrity", &jobj2))
		return -1;

	/* The value is optional, do not fail if not present */
	if (!json_object_object_get_ex(jobj2, "key_size", &jobj3))
		return 0;

	return json_object_get_int(jobj3);
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

int LUKS2_get_old_volume_key_size(struct luks2_hdr *hdr)
{
	int old_segment;

	assert(hdr);

	old_segment = LUKS2_reencrypt_segment_old(hdr);
	if (old_segment < 0)
		return old_segment;

	return LUKS2_get_volume_key_size(hdr, old_segment);
}

uint32_t LUKS2_get_sector_size(struct luks2_hdr *hdr)
{
	return json_segment_get_sector_size(LUKS2_get_segment_jobj(hdr, CRYPT_DEFAULT_SEGMENT));
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
					segment_offset, "none", 0, 0,
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
	struct volume_key *crypt_key,
	struct volume_key *opal_key,
	uint32_t flags)
{
	int r;
	bool dynamic, read_lock, write_lock, opal_lock_on_error = false;
	uint32_t opal_segment_number, req_flags;
	uint64_t range_offset_sectors, range_length_sectors, device_length_bytes;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
	struct crypt_dm_active_device dmdi = {}, dmd = {
		.uuid   = crypt_get_uuid(cd)
	};
	struct crypt_lock_handle *opal_lh = NULL;

	/* do not allow activation when particular requirements detected */
	if ((r = LUKS2_unmet_requirements(cd, hdr,
	     CRYPT_REQUIREMENT_OPAL | CRYPT_REQUIREMENT_INLINE_HW_TAGS, 0)))
		return r;

	/* Check that cipher is in compatible format */
	if (!crypt_get_cipher(cd)) {
		log_err(cd, _("No known cipher specification pattern detected in LUKS2 header."));
		return -EINVAL;
	}

	if ((r = LUKS2_get_data_size(hdr, &device_length_bytes, &dynamic)))
		return r;

	if (dynamic && opal_key) {
		log_err(cd, _("OPAL device must have static device size."));
		return -EINVAL;
	}

	if (!dynamic)
		dmd.size = device_length_bytes / SECTOR_SIZE;

	if (opal_key) {
		r = crypt_opal_supported(cd, crypt_data_device(cd));
		if (r < 0)
			return r;

		r = LUKS2_get_opal_segment_number(hdr, CRYPT_DEFAULT_SEGMENT, &opal_segment_number);
		if (r < 0)
			return -EINVAL;

		range_length_sectors = LUKS2_opal_segment_size(hdr, CRYPT_DEFAULT_SEGMENT, 1);

		if (crypt_get_integrity_tag_size(cd)) {
			if (dmd.size >= range_length_sectors) {
				log_err(cd, _("Encrypted OPAL device with integrity must be smaller than locking range."));
				return -EINVAL;
			}
		} else {
			if (range_length_sectors != dmd.size) {
				log_err(cd, _("OPAL device must have same size as locking range."));
				return -EINVAL;
			}
		}

		range_offset_sectors = crypt_get_data_offset(cd) + crypt_dev_partition_offset(device_path(crypt_data_device(cd)));
		r = opal_exclusive_lock(cd, crypt_data_device(cd), &opal_lh);
		if (r < 0) {
			log_err(cd, _("Failed to acquire OPAL lock on device %s."), device_path(crypt_data_device(cd)));
			return -EINVAL;
		}

		r = opal_range_check_attributes_and_get_lock_state(cd, crypt_data_device(cd), opal_segment_number,
						opal_key, &range_offset_sectors, &range_length_sectors,
						&read_lock, &write_lock);
		if (r < 0)
			goto out;

		opal_lock_on_error = read_lock && write_lock;
		if (!opal_lock_on_error && !(flags & CRYPT_ACTIVATE_REFRESH))
			log_std(cd, _("OPAL device is %s already unlocked.\n"),
				    device_path(crypt_data_device(cd)));

		r = opal_unlock(cd, crypt_data_device(cd), opal_segment_number, opal_key);
		if (r < 0)
			goto out;
	}

	if (LUKS2_segment_is_type(hdr, CRYPT_DEFAULT_SEGMENT, "crypt") ||
	    LUKS2_segment_is_type(hdr, CRYPT_DEFAULT_SEGMENT, "hw-opal-crypt")) {
		r = dm_crypt_target_set(&dmd.segment, 0,
					dmd.size, crypt_data_device(cd),
					crypt_key, crypt_get_cipher_spec(cd),
					crypt_get_iv_offset(cd), crypt_get_data_offset(cd),
					crypt_get_integrity(cd) ?: "none",
					crypt_get_integrity_key_size(cd, true), crypt_get_integrity_tag_size(cd),
					crypt_get_sector_size(cd));
	} else
		r = dm_linear_target_set(&dmd.segment, 0,
					 dmd.size, crypt_data_device(cd),
					 crypt_get_data_offset(cd));

	if (r < 0)
		goto out;

	/* Add persistent activation flags */
	if (!(flags & CRYPT_ACTIVATE_IGNORE_PERSISTENT))
		LUKS2_config_get_flags(cd, hdr, &dmd.flags);

	dmd.flags |= flags;

	if (crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &req_flags)) {
		r = -EINVAL;
		goto out;
	}

	if (crypt_get_integrity_tag_size(cd) &&
	    !(req_flags & CRYPT_REQUIREMENT_INLINE_HW_TAGS)) {
		if (!LUKS2_integrity_compatible(hdr)) {
			log_err(cd, _("Unsupported device integrity configuration."));
			r = -EINVAL;
			goto out;
		}

		if (dmd.flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) {
			log_err(cd, _("Discard/TRIM is not supported."));
			r = -EINVAL;
			goto out;
		}

		r = INTEGRITY_create_dmd_device(cd, NULL, NULL, NULL, NULL, &dmdi, dmd.flags, 0);
		if (r)
			goto out;

		if (!dynamic && dmdi.size != dmd.size) {
			log_err(cd, _("Underlying dm-integrity device with unexpected provided data sectors."));
			r = -EINVAL;
			goto out;
		}

		dmdi.flags |= CRYPT_ACTIVATE_PRIVATE;
		dmdi.uuid = dmd.uuid;
		dmd.segment.u.crypt.offset = 0;
		if (dynamic)
			dmd.segment.size = dmdi.segment.size;

		r = create_or_reload_device_with_integrity(cd, name,
							   opal_key ? CRYPT_LUKS2_HW_OPAL : CRYPT_LUKS2,
							   &dmd, &dmdi);
	} else
		r = create_or_reload_device(cd, name,
					    opal_key ? CRYPT_LUKS2_HW_OPAL : CRYPT_LUKS2,
					    &dmd);

	dm_targets_free(cd, &dmd);
	dm_targets_free(cd, &dmdi);
out:
	if (r < 0 && opal_lock_on_error)
		opal_lock(cd, crypt_data_device(cd), opal_segment_number);

	opal_exclusive_unlock(cd, opal_lh);

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
	bool dm_opal_uuid;
	int r, ret;
	struct dm_target *tgt;
	crypt_status_info ci;
	struct crypt_dm_active_device dmdc;
	uint32_t opal_segment_number;
	char **dep, deps_uuid_prefix[40], *deps[MAX_DM_DEPS+1] = { 0 };
	char *iname = NULL;
	struct crypt_lock_handle *reencrypt_lock = NULL, *opal_lh = NULL;

	if (!dmd || !dmd->uuid || strncmp(CRYPT_LUKS2, dmd->uuid, sizeof(CRYPT_LUKS2)-1))
		return -EINVAL;

	/* uuid mismatch with metadata (if available) */
	if (hdr && dm_uuid_cmp(dmd->uuid, hdr->uuid))
		return -EINVAL;

	r = snprintf(deps_uuid_prefix, sizeof(deps_uuid_prefix), CRYPT_SUBDEV "-%.32s", dmd->uuid + 6);
	if (r < 0 || (size_t)r != (sizeof(deps_uuid_prefix) - 1))
		return -EINVAL;

	/* check if active device has LUKS2-OPAL dm uuid prefix */
	dm_opal_uuid = !dm_uuid_type_cmp(dmd->uuid, CRYPT_LUKS2_HW_OPAL);
	if (dm_opal_uuid && hdr && !LUKS2_segment_is_hw_opal(hdr, CRYPT_DEFAULT_SEGMENT))
		return -EINVAL;

	tgt = &dmd->segment;

	/* TODO: We have LUKS2 dependencies now */
	if (tgt->type == DM_CRYPT && tgt->u.crypt.tag_size)
	    iname = dm_get_active_iname(cd, name);

	r = dm_device_deps(cd, name, deps_uuid_prefix, deps, ARRAY_SIZE(deps));
	if (r < 0)
		goto out;

	if (contains_reencryption_helper(deps)) {
		r = LUKS2_reencrypt_lock_by_dm_uuid(cd, dmd->uuid, &reencrypt_lock);
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
				crypt_volume_key_drop_kernel_key(cd, tgt->u.crypt.vk);
			tgt = tgt->next;
		}
	}
	dm_targets_free(cd, &dmdc);

	/* TODO: We have LUKS2 dependencies now */
	if (r >= 0 && iname) {
		log_dbg(cd, "Deactivating integrity device %s.", iname);
		r = dm_remove_device(cd, iname, 0);
	}

	if (!r) {
		ret = 0;
		dep = deps;
		while (*dep) {
			/*
			 * FIXME: dm-integrity has now proper SUBDEV prefix so
			 * it would be deactivated here, but due to specific
			 * dm_remove_device(iname) above the iname device
			 * is no longer active. This will be fixed when
			 * we switch to SUBDEV deactivation after 2.8 release.
			 */
			if (iname && !strcmp(*dep, iname)) {
				dep++;
				continue;
			}

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
						crypt_volume_key_drop_kernel_key(cd, tgt->u.crypt.vk);
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

	if (!r && dm_opal_uuid) {
		if (hdr) {
			if (LUKS2_get_opal_segment_number(hdr, CRYPT_DEFAULT_SEGMENT, &opal_segment_number)) {
				log_err(cd, _("Device %s was deactivated but hardware OPAL device cannot be locked."),
					name);
				r = -EINVAL;
				goto out;
			}
		} else {
			/* Guess OPAL range number for LUKS2-OPAL device with missing header */
			opal_segment_number = 1;
			ret = crypt_dev_get_partition_number(device_path(crypt_data_device(cd)));
			if (ret > 0)
				opal_segment_number = ret;
		}

		if (crypt_data_device(cd)) {
			r = opal_exclusive_lock(cd, crypt_data_device(cd), &opal_lh);
			if (r < 0) {
				log_err(cd, _("Failed to acquire OPAL lock on device %s."), device_path(crypt_data_device(cd)));
				goto out;
			}
		}

		if (!crypt_data_device(cd) || opal_lock(cd, crypt_data_device(cd), opal_segment_number))
			log_err(cd, _("Device %s was deactivated but hardware OPAL device cannot be locked."), name);
	}
out:
	opal_exclusive_unlock(cd, opal_lh);
	LUKS2_reencrypt_unlock(cd, reencrypt_lock);
	free(iname);
	dep = deps;
	while (*dep)
		free(*dep++);

	return r;
}

int LUKS2_unmet_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint64_t reqs_mask, int quiet)
{
	uint32_t reqs;

	LUKS2_config_get_requirements(cd, hdr, &reqs);

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
	if (reqs_opal(reqs) && !quiet)
		log_err(cd, _("Operation incompatible with device using OPAL. Aborting."));
	if (reqs_inline_hw_tags(reqs) && !quiet)
		log_err(cd, _("Operation incompatible with device using inline HW tags. Aborting."));

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

int json_object_object_add_by_uint_by_ref(json_object *jobj, unsigned key, json_object **jobj_val_ref)
{
	int r;

	assert(jobj);
	assert(jobj_val_ref);

	r = json_object_object_add_by_uint(jobj, key, *jobj_val_ref);
	if (!r)
		*jobj_val_ref = NULL;

	return r;
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

int LUKS2_split_crypt_and_opal_keys(struct crypt_device *cd __attribute__((unused)),
		struct luks2_hdr *hdr,
		const struct volume_key *vk,
		struct volume_key **ret_crypt_key,
		struct volume_key **ret_opal_key)
{
	int r;
	uint32_t opal_segment_number;
	size_t opal_user_key_size;
	json_object *jobj_segment;
	struct volume_key *opal_key, *crypt_key;

	assert(vk);
	assert(ret_crypt_key);
	assert(ret_opal_key);

	jobj_segment = LUKS2_get_segment_jobj(hdr, CRYPT_DEFAULT_SEGMENT);
	if (!jobj_segment)
		return -EINVAL;

	r = json_segment_get_opal_segment_id(jobj_segment, &opal_segment_number);
	if (r < 0)
		return -EINVAL;

	r = json_segment_get_opal_key_size(jobj_segment, &opal_user_key_size);
	if (r < 0)
		return -EINVAL;

	if (crypt_volume_key_length(vk) < opal_user_key_size)
		return -EINVAL;

	/* OPAL SEGMENT only */
	if (crypt_volume_key_length(vk) == opal_user_key_size) {
		*ret_crypt_key = NULL;
		*ret_opal_key = NULL;
		return 0;
	}

	opal_key = crypt_alloc_volume_key(opal_user_key_size, crypt_volume_key_get_key(vk));
	if (!opal_key)
		return -ENOMEM;

	crypt_key = crypt_alloc_volume_key(crypt_volume_key_length(vk) - opal_user_key_size,
					   crypt_volume_key_get_key(vk) + opal_user_key_size);
	if (!crypt_key) {
		crypt_free_volume_key(opal_key);
		return -ENOMEM;
	}

	*ret_opal_key = opal_key;
	*ret_crypt_key = crypt_key;

	return 0;
}
