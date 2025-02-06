// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2 (with JSON internals)
 *
 * Copyright (C) 2015-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2025 Milan Broz
 */

#ifndef _CRYPTSETUP_LUKS2_INTERNAL_H
#define _CRYPTSETUP_LUKS2_INTERNAL_H

#include <stdio.h>
#include <errno.h>
#include <json-c/json.h>

#include "internal.h"
#include "luks2.h"

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
int LUKS2_device_write_lock(struct crypt_device *cd,
	struct luks2_hdr *hdr, struct device *device);

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

/*
 * Generate json format string representation libcryptsetup uses
 * to store json metadata on disk.
 */
static inline const char *crypt_jobj_to_string_on_disk(json_object *jobj)
{
	return json_object_to_json_string_ext(jobj,
			JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
}

int json_object_object_add_by_uint(json_object *jobj, unsigned key, json_object *jobj_val);
int json_object_object_add_by_uint_by_ref(json_object *jobj, unsigned key, json_object **jobj_val_ref);
void json_object_object_del_by_uint(json_object *jobj, unsigned key);
int json_object_copy(json_object *jobj_src, json_object **jobj_dst);

void JSON_DBG(struct crypt_device *cd, json_object *jobj, const char *desc);

/*
 * LUKS2 JSON validation
 */

/* validation helper */
bool validate_json_uint32(json_object *jobj);
json_object *json_contains(struct crypt_device *cd, json_object *jobj, const char *name,
			   const char *section, const char *key, json_type type);
json_object *json_contains_string(struct crypt_device *cd, json_object *jobj,
				  const char *name, const char *section, const char *key);

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
json_object *LUKS2_array_jobj(json_object *array, const char *num);
json_object *LUKS2_array_remove(json_object *array, const char *num);

/*
 * Plugins API
 */

/**
 * LUKS2 keyslots handlers
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
typedef void(*keyslot_repair_func) (json_object *jobj_keyslot);

/* see LUKS2_luks2_to_luks1 */
int placeholder_keyslot_alloc(struct crypt_device *cd,
	int keyslot,
	uint64_t area_offset,
	uint64_t area_length);

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

struct reenc_protection {
	enum { REENC_PROTECTION_NOT_SET = 0,
	       REENC_PROTECTION_NONE,
	       REENC_PROTECTION_CHECKSUM,
	       REENC_PROTECTION_JOURNAL,
	       REENC_PROTECTION_DATASHIFT } type;

	union {
	struct {
		char hash[LUKS2_CHECKSUM_ALG_L];
		struct crypt_hash *ch;
		size_t hash_size;
		/* buffer for checksums */
		void *checksums;
		size_t checksums_len;
		size_t block_size;
	} csum;
	struct {
		uint64_t data_shift;
	} ds;
	} p;
};

/**
 * LUKS2 digest handlers
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

int keyring_open(struct crypt_device *cd,
	int token,
	char **buffer,
	size_t *buffer_len,
	void *usrptr);

void keyring_dump(struct crypt_device *cd, const char *json);

int keyring_validate(struct crypt_device *cd, const char *json);

void keyring_buffer_free(void *buffer, size_t buffer_size);

struct crypt_token_handler_v2 {
	const char *name;
	crypt_token_open_func open;
	crypt_token_buffer_free_func buffer_free;
	crypt_token_validate_func validate;
	crypt_token_dump_func dump;

	/* here ends v1. Do not touch anything above */

	crypt_token_open_pin_func open_pin;
	crypt_token_version_func version;

	void *dlhandle;
};

/*
 * Initial sequence of structure members in union 'u' must be always
 * identical. Version 4 must fully contain version 3 which must
 * subsequently fully contain version 2, etc.
 *
 * See C standard, section 6.5.2.3, item 5.
 */
struct crypt_token_handler_internal {
	uint32_t version;
	union {
		crypt_token_handler v1; /* deprecated public structure */
		struct crypt_token_handler_v2 v2; /* internal helper v2 structure */
	} u;
};

int LUKS2_find_area_gap(struct crypt_device *cd, struct luks2_hdr *hdr,
			size_t keylength, uint64_t *area_offset, uint64_t *area_length);
int LUKS2_find_area_max_gap(struct crypt_device *cd, struct luks2_hdr *hdr,
			    uint64_t *area_offset, uint64_t *area_length);

uint64_t LUKS2_hdr_and_areas_size_jobj(json_object *jobj);

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

/*
 * Generic LUKS2 keyslot
 */
int LUKS2_keyslot_reencrypt_store(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const void *buffer,
	size_t buffer_length);

int LUKS2_keyslot_reencrypt_allocate(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const struct crypt_params_reencrypt *params,
	size_t alignment);

int LUKS2_keyslot_reencrypt_update_needed(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const struct crypt_params_reencrypt *params,
	size_t alignment);

int LUKS2_keyslot_reencrypt_update(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const struct crypt_params_reencrypt *params,
	size_t alignment,
	struct volume_key *vks);

int LUKS2_keyslot_reencrypt_load(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	struct reenc_protection *rp,
	bool primary);

int LUKS2_keyslot_reencrypt_digest_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint8_t version,
	struct volume_key *vks);

int LUKS2_keyslot_dump(struct crypt_device *cd,
	int keyslot);

int LUKS2_keyslot_jobj_area(json_object *jobj_keyslot, uint64_t *offset, uint64_t *length);

/* JSON helpers */
uint64_t json_segment_get_offset(json_object *jobj_segment, unsigned blockwise);
const char *json_segment_type(json_object *jobj_segment);
uint64_t json_segment_get_iv_offset(json_object *jobj_segment);
uint64_t json_segment_get_size(json_object *jobj_segment, unsigned blockwise);
const char *json_segment_get_cipher(json_object *jobj_segment);
uint32_t json_segment_get_sector_size(json_object *jobj_segment);
int json_segment_get_opal_segment_id(json_object *jobj_segment, uint32_t *ret_opal_segment_id);
int json_segment_get_opal_key_size(json_object *jobj_segment, size_t *ret_key_size);
bool json_segment_is_backup(json_object *jobj_segment);
json_object *json_segments_get_segment(json_object *jobj_segments, int segment);
unsigned json_segments_count(json_object *jobj_segments);
void json_segment_remove_flag(json_object *jobj_segment, const char *flag);
uint64_t json_segments_get_minimal_offset(json_object *jobj_segments, unsigned blockwise);
json_object *json_segment_create_linear(uint64_t offset, const uint64_t *length, unsigned reencryption);
json_object *json_segment_create_crypt(uint64_t offset, uint64_t iv_offset, const uint64_t *length,
				       const char *cipher, const char *integrity, uint32_t integrity_key_size,
				       uint32_t sector_size, unsigned reencryption);
json_object *json_segment_create_opal(uint64_t offset, const uint64_t *length,
				      uint32_t segment_number, uint32_t key_size);
json_object *json_segment_create_opal_crypt(uint64_t offset, const uint64_t *length,
					    uint32_t segment_number, uint32_t key_size,
					    uint64_t iv_offset, const char *cipher,
					    const char *integrity, uint32_t sector_size,
					    unsigned reencryption);
int json_segments_segment_in_reencrypt(json_object *jobj_segments);
bool json_segment_cmp(json_object *jobj_segment_1, json_object *jobj_segment_2);
bool json_segment_contains_flag(json_object *jobj_segment, const char *flag_str, size_t len);

int LUKS2_assembly_multisegment_dmd(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct volume_key *vks,
	json_object *jobj_segments,
	struct crypt_dm_active_device *dmd);

/*
 * Generic LUKS2 segment
 */
int LUKS2_segments_count(struct luks2_hdr *hdr);

int LUKS2_segment_first_unused_id(struct luks2_hdr *hdr);

int LUKS2_segment_set_flag(json_object *jobj_segment, const char *flag);

json_object *LUKS2_get_segment_by_flag(struct luks2_hdr *hdr, const char *flag);

int LUKS2_get_segment_id_by_flag(struct luks2_hdr *hdr, const char *flag);

int LUKS2_segments_set(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	json_object *jobj_segments,
	int commit);

uint64_t LUKS2_segment_offset(struct luks2_hdr *hdr,
	int segment,
	unsigned blockwise);

uint64_t LUKS2_segment_size(struct luks2_hdr *hdr,
	int segment,
	unsigned blockwise);

uint64_t LUKS2_opal_segment_size(struct luks2_hdr *hdr,
	int segment,
	unsigned blockwise);

int LUKS2_segment_is_type(struct luks2_hdr *hdr,
	int segment,
	const char *type);

int LUKS2_segment_by_type(struct luks2_hdr *hdr,
	const char *type);

int LUKS2_last_segment_by_type(struct luks2_hdr *hdr,
	const char *type);

int LUKS2_get_default_segment(struct luks2_hdr *hdr);

int LUKS2_reencrypt_digest_new(struct luks2_hdr *hdr);
int LUKS2_reencrypt_digest_old(struct luks2_hdr *hdr);
int LUKS2_reencrypt_segment_new(struct luks2_hdr *hdr);
int LUKS2_reencrypt_segment_old(struct luks2_hdr *hdr);
int LUKS2_reencrypt_data_offset(struct luks2_hdr *hdr, bool blockwise);

int LUKS2_reencrypt_max_hotzone_size(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct reenc_protection *rp,
	int reencrypt_keyslot,
	uint64_t *r_length);

void LUKS2_reencrypt_protection_erase(struct reenc_protection *rp);

/*
 * Generic LUKS2 digest
 */
int LUKS2_digest_verify_by_digest(struct crypt_device *cd,
	int digest,
	const struct volume_key *vk);

void LUKS2_digests_erase_unused(struct crypt_device *cd,
	struct luks2_hdr *hdr);

int LUKS2_digest_dump(struct crypt_device *cd,
	int digest);

/*
 * Generic LUKS2 token
 */
int LUKS2_tokens_count(struct luks2_hdr *hdr);

/*
 * LUKS2 generic
 */
int LUKS2_reload(struct crypt_device *cd,
	const char *name,
	struct volume_key *vks,
	uint64_t device_size,
	uint32_t flags);

int LUKS2_keyslot_for_segment(struct luks2_hdr *hdr, int keyslot, int segment);
int LUKS2_find_keyslot(struct luks2_hdr *hdr, const char *type);
int LUKS2_set_keyslots_size(struct luks2_hdr *hdr, uint64_t data_offset);

#endif
