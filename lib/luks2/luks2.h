// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2025 Milan Broz
 */

#ifndef _CRYPTSETUP_LUKS2_ONDISK_H
#define _CRYPTSETUP_LUKS2_ONDISK_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "libcryptsetup.h"

#define LUKS2_MAGIC_1ST "LUKS\xba\xbe"
#define LUKS2_MAGIC_2ND "SKUL\xba\xbe"
#define LUKS2_MAGIC_L 6
#define LUKS2_UUID_L 40
#define LUKS2_LABEL_L 48
#define LUKS2_SALT_L 64
#define LUKS2_CHECKSUM_ALG_L 32
#define LUKS2_CHECKSUM_L 64

#define LUKS2_KEYSLOTS_MAX       32
#define LUKS2_TOKENS_MAX         32
#define LUKS2_SEGMENT_MAX        32

#define LUKS2_BUILTIN_TOKEN_PREFIX "luks2-"
#define LUKS2_BUILTIN_TOKEN_PREFIX_LEN 6

#define LUKS2_TOKEN_NAME_MAX 64

#define LUKS2_TOKEN_KEYRING LUKS2_BUILTIN_TOKEN_PREFIX "keyring"

#define LUKS2_DIGEST_MAX 8

#define LUKS2_MIN_INTEGRITY_KEY_BYTES 16

#define CRYPT_ANY_SEGMENT -1
#define CRYPT_DEFAULT_SEGMENT -2
#define CRYPT_ONE_SEGMENT -3

#define CRYPT_ANY_DIGEST -1

/* 20 MiBs */
#define LUKS2_DEFAULT_NONE_REENCRYPTION_LENGTH 0x1400000

/* 1 GiB */
#define LUKS2_REENCRYPT_MAX_HOTZONE_LENGTH 0x40000000

/* supported reencryption requirement versions */
#define LUKS2_REENCRYPT_REQ_VERSION         UINT8_C(2)
#define LUKS2_DECRYPT_DATASHIFT_REQ_VERSION UINT8_C(3)

/* see reencrypt_assembly_verification_data() in luks2_reencrypt_digest.c */
/*	LUKS2_REENCRYPT_MAX_VERSION         UINT8_C(207) */

struct device;
struct luks2_reencrypt;
struct reenc_protection;
struct crypt_lock_handle;
struct crypt_dm_active_device;
struct luks_phdr; /* LUKS1 for conversion */

/*
 * LUKS2 header on-disk.
 *
 * Binary header is followed by JSON area.
 * JSON area is followed by keyslot area and data area,
 * these are described in JSON metadata.
 *
 * Note: uuid, csum_alg are intentionally on the same offset as LUKS1
 * (checksum alg replaces hash in LUKS1)
 *
 * String (char) should be zero terminated.
 * Padding should be wiped.
 * Checksum is calculated with csum zeroed (+ full JSON area).
 */
struct luks2_hdr_disk {
	char		magic[LUKS2_MAGIC_L];
	uint16_t	version;	/* Version 2 */
	uint64_t	hdr_size;	/* in bytes, including JSON area */
	uint64_t	seqid;		/* increased on every update */
	char		label[LUKS2_LABEL_L];
	char		checksum_alg[LUKS2_CHECKSUM_ALG_L];
	uint8_t		salt[LUKS2_SALT_L]; /* unique for every header/offset */
	char		uuid[LUKS2_UUID_L];
	char		subsystem[LUKS2_LABEL_L]; /* owner subsystem label */
	uint64_t	hdr_offset;	/* offset from device start in bytes */
	char		_padding[184];
	uint8_t		csum[LUKS2_CHECKSUM_L];
	char		_padding4096[7*512];
	/* JSON area starts here */
} __attribute__ ((packed));

/*
 * LUKS2 header in-memory.
 */
struct luks2_hdr {
	size_t		hdr_size;
	uint64_t	seqid;
	unsigned int	version;
	char		label[LUKS2_LABEL_L];
	char		subsystem[LUKS2_LABEL_L];
	char		checksum_alg[LUKS2_CHECKSUM_ALG_L];
	uint8_t		salt1[LUKS2_SALT_L];
	uint8_t		salt2[LUKS2_SALT_L];
	char		uuid[LUKS2_UUID_L];
	void		*jobj;
	void		*jobj_rollback;
	size_t		on_disk_json_end_offset;
};

struct luks2_keyslot_params {
	enum { LUKS2_KEYSLOT_AF_LUKS1 = 0 } af_type;
	enum { LUKS2_KEYSLOT_AREA_RAW = 0 } area_type;

	union {
	struct {
		char hash[LUKS2_CHECKSUM_ALG_L]; // or include luks.h
		unsigned int stripes;
	} luks1;
	} af;

	union {
	struct {
		char encryption[65]; // or include utils_crypt.h
		size_t key_size;
	} raw;
	} area;
};

/*
 * Supportable header sizes (hdr_disk + JSON area)
 * Also used as offset for the 2nd header.
 */
#define LUKS2_HDR_16K_LEN 0x4000

#define LUKS2_HDR_BIN_LEN sizeof(struct luks2_hdr_disk)

//#define LUKS2_DEFAULT_HDR_SIZE 0x400000  /* 4 MiB */
#define LUKS2_DEFAULT_HDR_SIZE 0x1000000 /* 16 MiB */

#define LUKS2_MAX_KEYSLOTS_SIZE 0x8000000 /* 128 MiB */

#define LUKS2_HDR_OFFSET_MAX 0x400000 /* 4 MiB */

#define LUKS2_HDR_MAX_MDA_SIZE 2 * LUKS2_HDR_OFFSET_MAX + LUKS2_MAX_KEYSLOTS_SIZE

/* Offsets for secondary header (for scan if primary header is corrupted). */
#define LUKS2_HDR2_OFFSETS { 0x04000, 0x008000, 0x010000, 0x020000, \
                             0x40000, 0x080000, 0x100000, 0x200000, LUKS2_HDR_OFFSET_MAX }

int LUKS2_hdr_version_unlocked(struct crypt_device *cd,
	const char *backup_file);

int LUKS2_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr, int repair);
int LUKS2_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr);
int LUKS2_hdr_write_force(struct crypt_device *cd, struct luks2_hdr *hdr);
int LUKS2_hdr_rollback(struct crypt_device *cd, struct luks2_hdr *hdr);
int LUKS2_hdr_dump(struct crypt_device *cd, struct luks2_hdr *hdr);
int LUKS2_hdr_dump_json(struct crypt_device *cd, struct luks2_hdr *hdr,	const char **json);

int LUKS2_hdr_uuid(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *uuid);

int LUKS2_hdr_labels(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *label,
	const char *subsystem,
	int commit);

void LUKS2_hdr_free(struct crypt_device *cd, struct luks2_hdr *hdr);

int LUKS2_hdr_backup(struct crypt_device *cd,
		     struct luks2_hdr *hdr,
		     const char *backup_file);
int LUKS2_hdr_restore(struct crypt_device *cd,
		      struct luks2_hdr *hdr,
		      const char *backup_file);

uint64_t LUKS2_hdr_and_areas_size(struct luks2_hdr *hdr);
uint64_t LUKS2_keyslots_size(struct luks2_hdr *hdr);
uint64_t LUKS2_metadata_size(struct luks2_hdr *hdr);

int LUKS2_keyslot_cipher_incompatible(struct crypt_device *cd, const char *cipher_spec);

/*
 * Generic LUKS2 keyslot
 */
int LUKS2_keyslot_open(struct crypt_device *cd,
	int keyslot,
	int segment,
	const char *password,
	size_t password_len,
	struct volume_key **vk);

int LUKS2_keyslot_context_open_all_segments(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	struct crypt_keyslot_context *kc_old,
	struct crypt_keyslot_context *kc_new,
	struct volume_key **vks);

int LUKS2_keyslot_store(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *password,
	size_t password_len,
	const struct volume_key *vk,
	const struct luks2_keyslot_params *params);

int LUKS2_keyslot_wipe(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot);

crypt_keyslot_priority LUKS2_keyslot_priority_get(struct luks2_hdr *hdr, int keyslot);

int LUKS2_keyslot_priority_set(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	crypt_keyslot_priority priority,
	int commit);

int LUKS2_keyslot_swap(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int keyslot2);

/*
 * Segments
 */

bool LUKS2_segment_set_size(struct luks2_hdr *hdr,
	int segment,
	const uint64_t *segment_size_bytes);

bool LUKS2_segment_is_hw_opal(struct luks2_hdr *hdr, int segment);
bool LUKS2_segment_is_hw_opal_crypt(struct luks2_hdr *hdr, int segment);
bool LUKS2_segment_is_hw_opal_only(struct luks2_hdr *hdr, int segment);

int LUKS2_get_opal_segment_number(struct luks2_hdr *hdr, int segment,
				  uint32_t *ret_opal_segment_number);
int LUKS2_get_opal_key_size(struct luks2_hdr *hdr, int segment);

bool LUKS2_segments_dynamic_size(struct luks2_hdr *hdr);

/*
 * Generic LUKS2 token
 */
int LUKS2_token_json_get(struct luks2_hdr *hdr,
	int token,
	const char **json);

int LUKS2_token_assign(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int token,
	int assign,
	int commit);

int LUKS2_token_is_assigned(struct luks2_hdr *hdr,
	int keyslot,
	int token);

int LUKS2_token_assignment_copy(struct crypt_device *cd,
			struct luks2_hdr *hdr,
			int keyslot_from,
			int keyslot_to,
			int commit);

int LUKS2_token_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char *json,
	int commit);

crypt_token_info LUKS2_token_status(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char **type);

int LUKS2_token_unlock_key(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int token,
	const char *type,
	const char *pin,
	size_t pin_size,
	int segment,
	void *usrptr,
	struct volume_key **vk);

int LUKS2_token_keyring_get(struct luks2_hdr *hdr,
	int token,
	struct crypt_token_params_luks2_keyring *keyring_params);

int LUKS2_token_keyring_json(char *buffer, size_t buffer_size,
	const struct crypt_token_params_luks2_keyring *keyring_params);

int LUKS2_token_unlock_passphrase(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char *type,
	const char *pin,
	size_t pin_size,
	void *usrptr,
	char **passphrase,
	size_t *passphrase_size);

void crypt_token_unload_external_all(struct crypt_device *cd);

/*
 * Generic LUKS2 digest
 */
int LUKS2_digest_verify_by_any_matching(struct crypt_device *cd,
		const struct volume_key *vk);

int LUKS2_digest_verify_by_segment(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment,
	const struct volume_key *vk);

int LUKS2_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	int keyslot);

int LUKS2_digest_assign(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int digest,
	int assign,
	int commit);

int LUKS2_digest_segment_assign(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment,
	int digest,
	int assign,
	int commit);

int LUKS2_digest_by_keyslot(struct luks2_hdr *hdr, int keyslot);

int LUKS2_digest_by_segment(struct luks2_hdr *hdr, int segment);

int LUKS2_digest_create(struct crypt_device *cd,
	const char *type,
	struct luks2_hdr *hdr,
	const struct volume_key *vk);

/*
 * LUKS2 generic
 */
int LUKS2_activate(struct crypt_device *cd,
	const char *name,
	struct volume_key *crypt_key,
	struct volume_key *opal_key,
	uint32_t flags);

int LUKS2_activate_multi(struct crypt_device *cd,
	const char *name,
	struct volume_key *vks,
	uint64_t device_size,
	uint32_t flags);

int LUKS2_deactivate(struct crypt_device *cd,
	const char *name,
	struct luks2_hdr *hdr,
	struct crypt_dm_active_device *dmd,
	uint32_t flags);

int LUKS2_generate_hdr(
	struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	const char *cipher_spec,
	const char *integrity,
	uint32_t integrity_key_size, /* in bytes, only if separate (HMAC) */
	const char *uuid,
	unsigned int sector_size,
	uint64_t data_offset,
	uint64_t metadata_size_bytes,
	uint64_t keyslots_size_bytes,
	uint64_t device_size_bytes,
	uint32_t opal_segment_number,
	uint32_t opal_key_size);

int LUKS2_hdr_get_storage_params(struct crypt_device *cd,
			    uint64_t alignment_offset_bytes,
			    uint64_t alignment_bytes,
			    uint64_t *ret_metadata_size_bytes,
			    uint64_t *ret_keyslots_size_bytes,
			    uint64_t *ret_data_offset_bytes);

int LUKS2_check_metadata_area_size(uint64_t metadata_size);
int LUKS2_check_keyslots_area_size(uint64_t keyslots_size);

int LUKS2_wipe_header_areas(struct crypt_device *cd,
	struct luks2_hdr *hdr);

uint64_t LUKS2_get_data_offset(struct luks2_hdr *hdr);
int LUKS2_get_data_size(struct luks2_hdr *hdr, uint64_t *size, bool *dynamic);
uint32_t LUKS2_get_sector_size(struct luks2_hdr *hdr);
const char *LUKS2_get_cipher(struct luks2_hdr *hdr, int segment);
const char *LUKS2_get_integrity(struct luks2_hdr *hdr, int segment);
int LUKS2_get_integrity_key_size(struct luks2_hdr *hdr, int segment);
int LUKS2_keyslot_params_default(struct crypt_device *cd, struct luks2_hdr *hdr,
	 struct luks2_keyslot_params *params);
int LUKS2_get_old_volume_key_size(struct luks2_hdr *hdr);
int LUKS2_get_volume_key_size(struct luks2_hdr *hdr, int segment);
int LUKS2_get_keyslot_stored_key_size(struct luks2_hdr *hdr, int keyslot);
const char *LUKS2_get_keyslot_cipher(struct luks2_hdr *hdr, int keyslot, size_t *key_size);
int LUKS2_keyslot_find_empty(struct crypt_device *cd, struct luks2_hdr *hdr, size_t keylength);
int LUKS2_keyslot_active_count(struct luks2_hdr *hdr, int segment);
crypt_keyslot_info LUKS2_keyslot_info(struct luks2_hdr *hdr, int keyslot);
int LUKS2_keyslot_area(struct luks2_hdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length);
int LUKS2_keyslot_pbkdf(struct luks2_hdr *hdr, int keyslot, struct crypt_pbkdf_type *pbkdf);

int LUKS2_split_crypt_and_opal_keys(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct volume_key *vk,
		struct volume_key **ret_crypt_key,
		struct volume_key **ret_opal_key);

/*
 * Permanent activation flags stored in header
 */
int LUKS2_config_get_flags(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t *flags);
int LUKS2_config_set_flags(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t flags);

/*
 * Requirements for device activation or header modification
 */
void LUKS2_config_get_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t *reqs);
int LUKS2_config_set_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs, bool commit);
int LUKS2_config_set_requirement_version(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t req_id, uint8_t req_version, bool commit);

int LUKS2_config_get_reencrypt_version(struct luks2_hdr *hdr, uint8_t *version);

bool LUKS2_reencrypt_requirement_candidate(struct luks2_hdr *hdr);

int LUKS2_unmet_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint64_t reqs_mask, int quiet);

int LUKS2_key_description_by_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int segment);
int LUKS2_volume_key_load_in_keyring_by_digest(struct crypt_device *cd,
		struct volume_key *vk, int digest);

int LUKS2_luks1_to_luks2(struct crypt_device *cd,
			 struct luks_phdr *hdr1,
			 struct luks2_hdr *hdr2);
int LUKS2_luks2_to_luks1(struct crypt_device *cd,
			 struct luks2_hdr *hdr2,
			 struct luks_phdr *hdr1);

/*
 * LUKS2 reencryption
 */
int LUKS2_reencrypt_locked_recovery_by_vks(struct crypt_device *cd,
	struct volume_key *vks);

void LUKS2_reencrypt_free(struct crypt_device *cd,
	struct luks2_reencrypt *rh);

crypt_reencrypt_info LUKS2_reencrypt_status(struct luks2_hdr *hdr);

crypt_reencrypt_info LUKS2_reencrypt_get_params(struct luks2_hdr *hdr,
	struct crypt_params_reencrypt *params);

int LUKS2_reencrypt_lock(struct crypt_device *cd,
	struct crypt_lock_handle **reencrypt_lock);

int LUKS2_reencrypt_lock_by_dm_uuid(struct crypt_device *cd,
	const char *dm_uuid,
	struct crypt_lock_handle **reencrypt_lock);

void LUKS2_reencrypt_unlock(struct crypt_device *cd,
	struct crypt_lock_handle *reencrypt_lock);

int LUKS2_reencrypt_check_device_size(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint64_t check_size,
	uint64_t *dev_size,
	bool device_exclusive_check,
	bool dynamic);

int LUKS2_reencrypt_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct volume_key *vks);

unsigned LUKS2_reencrypt_vks_count(struct luks2_hdr *hdr);

#endif
