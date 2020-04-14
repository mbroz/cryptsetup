/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2020 Milan Broz
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

#ifndef _CRYPTSETUP_LUKS2_INTERNAL_H
#define _CRYPTSETUP_LUKS2_INTERNAL_H

#include <stdio.h>
#include <errno.h>
#include <json-c/json.h>

#include "internal.h"
#include "base64.h"
#include "luks2.h"

#define UNUSED(x) (void)(x)

/* override useless forward slash escape when supported by json-c */
#ifndef JSON_C_TO_STRING_NOSLASHESCAPE
#define JSON_C_TO_STRING_NOSLASHESCAPE 0
#endif

/*
 * On-disk access function prototypes
 */
int LUKS2_disk_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr,
			struct device *device, int do_recovery, int do_blkprobe);
int LUKS2_disk_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr,
			 struct device *device, bool seqid_check);

/*
 * JSON struct access helpers
 */
json_object *LUKS2_get_keyslot_jobj(struct luks2_hdr *hdr, int keyslot);
json_object *LUKS2_get_token_jobj(struct luks2_hdr *hdr, int token);
json_object *LUKS2_get_digest_jobj(struct luks2_hdr *hdr, int digest);
json_object *LUKS2_get_segment_jobj(struct luks2_hdr *hdr, int segment);
json_object *LUKS2_get_tokens_jobj(struct luks2_hdr *hdr);
json_object *LUKS2_get_segments_jobj(struct luks2_hdr *hdr);

void hexprint_base64(struct crypt_device *cd, json_object *jobj,
		     const char *sep, const char *line_sep);

uint64_t crypt_jobj_get_uint64(json_object *jobj);
uint32_t crypt_jobj_get_uint32(json_object *jobj);
json_object *crypt_jobj_new_uint64(uint64_t value);

int json_object_object_add_by_uint(json_object *jobj, unsigned key, json_object *jobj_val);
void json_object_object_del_by_uint(json_object *jobj, unsigned key);
int json_object_copy(json_object *jobj_src, json_object **jobj_dst);

void JSON_DBG(struct crypt_device *cd, json_object *jobj, const char *desc);

/*
 * LUKS2 JSON validation
 */

/* validation helper */
json_bool validate_json_uint32(json_object *jobj);
json_object *json_contains(struct crypt_device *cd, json_object *jobj, const char *name,
			   const char *section, const char *key, json_type type);

int LUKS2_hdr_validate(struct crypt_device *cd, json_object *hdr_jobj, uint64_t json_size);
int LUKS2_check_json_size(struct crypt_device *cd, const struct luks2_hdr *hdr);
int LUKS2_token_validate(struct crypt_device *cd, json_object *hdr_jobj,
			 json_object *jobj_token, const char *key);
void LUKS2_token_dump(struct crypt_device *cd, int token);

/*
 * LUKS2 JSON repair for known glitches
 */
void LUKS2_hdr_repair(struct crypt_device *cd, json_object *jobj_hdr);
void LUKS2_keyslots_repair(struct crypt_device *cd, json_object *jobj_hdr);

/*
 * JSON array helpers
 */
struct json_object *LUKS2_array_jobj(struct json_object *array, const char *num);
struct json_object *LUKS2_array_remove(struct json_object *array, const char *num);

/*
 * Plugins API
 */

/**
 * LUKS2 keyslots handlers (EXPERIMENTAL)
 */
typedef int (*keyslot_alloc_func)(struct crypt_device *cd, int keyslot,
				  size_t volume_key_len,
				  const struct luks2_keyslot_params *params);
typedef int (*keyslot_update_func)(struct crypt_device *cd, int keyslot,
				   const struct luks2_keyslot_params *params);
typedef int (*keyslot_open_func) (struct crypt_device *cd, int keyslot,
				  const char *password, size_t password_len,
				  char *volume_key, size_t volume_key_len);
typedef int (*keyslot_store_func)(struct crypt_device *cd, int keyslot,
				  const char *password, size_t password_len,
				  const char *volume_key, size_t volume_key_len);
typedef int (*keyslot_wipe_func) (struct crypt_device *cd, int keyslot);
typedef int (*keyslot_dump_func) (struct crypt_device *cd, int keyslot);
typedef int (*keyslot_validate_func) (struct crypt_device *cd, json_object *jobj_keyslot);
typedef void(*keyslot_repair_func) (struct crypt_device *cd, json_object *jobj_keyslot);

/* see LUKS2_luks2_to_luks1 */
int placeholder_keyslot_alloc(struct crypt_device *cd,
	int keyslot,
	uint64_t area_offset,
	uint64_t area_length,
	size_t volume_key_len);

/* validate all keyslot implementations in hdr json */
int LUKS2_keyslots_validate(struct crypt_device *cd, json_object *hdr_jobj);

typedef struct  {
	const char *name;
	keyslot_alloc_func alloc;
	keyslot_update_func update;
	keyslot_open_func  open;
	keyslot_store_func store;
	keyslot_wipe_func  wipe;
	keyslot_dump_func  dump;
	keyslot_validate_func validate;
	keyslot_repair_func repair;
} keyslot_handler;

/* can not fit prototype alloc function */
int reenc_keyslot_alloc(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const struct crypt_params_reencrypt *params);

/**
 * LUKS2 digest handlers (EXPERIMENTAL)
 */
typedef int (*digest_verify_func)(struct crypt_device *cd, int digest,
				  const char *volume_key, size_t volume_key_len);
typedef int (*digest_store_func) (struct crypt_device *cd, int digest,
				  const char *volume_key, size_t volume_key_len);
typedef int (*digest_dump_func)  (struct crypt_device *cd, int digest);

typedef struct  {
	const char *name;
	digest_verify_func verify;
	digest_store_func  store;
	digest_dump_func   dump;
} digest_handler;

/**
 * LUKS2 token handlers (internal use only)
 */
typedef int (*builtin_token_get_func) (json_object *jobj_token, void *params);
typedef int (*builtin_token_set_func) (json_object **jobj_token, const void *params);

typedef struct {
	/* internal only section used by builtin tokens */
	builtin_token_get_func get;
	builtin_token_set_func set;
	/* public token handler */
	const crypt_token_handler *h;
} token_handler;

int token_keyring_set(json_object **, const void *);
int token_keyring_get(json_object *, void *);

int LUKS2_find_area_gap(struct crypt_device *cd, struct luks2_hdr *hdr,
			size_t keylength, uint64_t *area_offset, uint64_t *area_length);
int LUKS2_find_area_max_gap(struct crypt_device *cd, struct luks2_hdr *hdr,
			    uint64_t *area_offset, uint64_t *area_length);

int LUKS2_check_cipher(struct crypt_device *cd,
		      size_t keylength,
		      const char *cipher,
		      const char *cipher_mode);

static inline const char *crypt_reencrypt_mode_to_str(crypt_reencrypt_mode_info mi)
{
	if (mi == CRYPT_REENCRYPT_REENCRYPT)
		return "reencrypt";
	if (mi == CRYPT_REENCRYPT_ENCRYPT)
		return "encrypt";
	if (mi == CRYPT_REENCRYPT_DECRYPT)
		return "decrypt";
	return "<unknown>";
}

#endif
