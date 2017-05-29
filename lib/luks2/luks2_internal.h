/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2017, Milan Broz. All rights reserved.
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
#include <fcntl.h>
#include <errno.h>
#include <json-c/json.h>

#include "internal.h"
#include "base64.h"
#include "luks2.h"

#define UNUSED(x) (void)(x)

/*
 * On-disk access function prototypes
 */
int LUKS2_disk_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr,
			struct device *device, int do_recovery);
int LUKS2_disk_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr,
			 struct device *device);

/*
 * JSON struct access helpers
 */
json_object *LUKS2_get_keyslot_jobj(struct luks2_hdr *hdr, int keyslot);
json_object *LUKS2_get_token_jobj(struct luks2_hdr *hdr, int token);
json_object *LUKS2_get_digest_jobj(struct luks2_hdr *hdr, int keyslot);
json_object *LUKS2_get_segment_jobj(struct luks2_hdr *hdr, int segment);

void hexprint_base64(struct crypt_device *cd, json_object *jobj,
		     const char *sep, const char *line_sep);

json_object *parse_json_len(const char *json_area, int length, int *end_offset);
uint64_t json_object_get_uint64(json_object *jobj);
uint32_t json_object_get_uint32(json_object *jobj);

/*
 * LUKS2 JSON validation
 */

int LUKS2_hdr_validate(json_object *hdr_jobj);
int LUKS2_keyslot_validate(json_object *hdr_jobj, json_object *hdr_keyslot, const char *key);
int LUKS2_check_json_size(const struct luks2_hdr *hdr);
int LUKS2_token_validate(json_object *hdr_jobj, json_object *jobj_token, const char *key);
void LUKS2_token_dump(struct crypt_device *cd, int token);

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
				  size_t volume_key_len);
typedef int (*keyslot_open_func) (struct crypt_device *cd, int keyslot,
				  const char *password, size_t password_len,
				  char *volume_key, size_t volume_key_len);
typedef int (*keyslot_store_func)(struct crypt_device *cd, int keyslot,
				  const char *password, size_t password_len,
				  const char *volume_key, size_t volume_key_len);
typedef int (*keyslot_wipe_func) (struct crypt_device *cd, int keyslot);
typedef int (*keyslot_dump_func) (struct crypt_device *cd, int keyslot);
typedef int (*keyslot_validate_func) (struct crypt_device *cd, int keyslot);

typedef struct  {
	const char *name;
	keyslot_alloc_func alloc;
	keyslot_open_func  open;
	keyslot_store_func store;
	keyslot_wipe_func  wipe;
	keyslot_dump_func  dump;
	keyslot_validate_func validate;
} keyslot_handler;

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

int crypt_digest_register(const digest_handler *handler);
const digest_handler *LUKS2_digest_handler_type(struct crypt_device *cd, const char *type);

#define CRYPT_ANY_DIGEST -1
int crypt_keyslot_assign_digest(struct crypt_device *cd, int keyslot, int digest);
int crypt_keyslot_unassign_digest(struct crypt_device *cd, int keyslot, int digest);

int crypt_keyslot_create(struct crypt_device *cd, int keyslot, const char *type, const char *json);

#define CRYPT_ANY_TOKEN -1
int LUKS2_find_area_gap(struct crypt_device *cd, struct luks2_hdr *hdr,
			size_t keylength, uint64_t *area_offset, uint64_t *area_length);

#endif
