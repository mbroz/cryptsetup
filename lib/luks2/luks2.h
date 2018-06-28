/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2018, Milan Broz. All rights reserved.
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

#ifndef _CRYPTSETUP_LUKS2_ONDISK_H
#define _CRYPTSETUP_LUKS2_ONDISK_H

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

#define LUKS2_BUILTIN_TOKEN_PREFIX "luks2-"
#define LUKS2_BUILTIN_TOKEN_PREFIX_LEN 6

#define LUKS2_TOKEN_KEYRING LUKS2_BUILTIN_TOKEN_PREFIX "keyring"

#define LUKS2_DIGEST_MAX 8

#define CRYPT_ANY_SEGMENT -1
#define CRYPT_DEFAULT_SEGMENT 0
#define CRYPT_DEFAULT_SEGMENT_STR "0"

#define CRYPT_ANY_DIGEST -1

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
typedef struct json_object json_object;
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
	json_object	*jobj;
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

#define LUKS2_HDR_DEFAULT_LEN 0x400000 /* 4 MiB */

#define LUKS2_MAX_KEYSLOTS_SIZE 0x8000000 /* 128 MiB */

/* Offsets for secondary header (for scan if primary header is corrupted). */
#define LUKS2_HDR2_OFFSETS { 0x04000, 0x008000, 0x010000, 0x020000, \
                             0x40000, 0x080000, 0x100000, 0x200000, 0x400000 }

int LUKS2_hdr_version_unlocked(struct crypt_device *cd,
	const char *backup_file);

int LUKS2_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr, int repair);
int LUKS2_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr);
int LUKS2_hdr_dump(struct crypt_device *cd, struct luks2_hdr *hdr);

int LUKS2_hdr_uuid(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *uuid);

int LUKS2_hdr_labels(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *label,
	const char *subsystem,
	int commit);

void LUKS2_hdr_free(struct luks2_hdr *hdr);

int LUKS2_hdr_backup(struct crypt_device *cd,
		     struct luks2_hdr *hdr,
		     const char *backup_file);
int LUKS2_hdr_restore(struct crypt_device *cd,
		      struct luks2_hdr *hdr,
		      const char *backup_file);

uint64_t LUKS2_hdr_and_areas_size(json_object *jobj);
uint64_t LUKS2_keyslots_size(json_object *jobj);

int LUKS2_keyslot_cipher_incompatible(struct crypt_device *cd);

/*
 * Generic LUKS2 keyslot
 */
int LUKS2_keyslot_open(struct crypt_device *cd,
	int keyslot,
	int segment,
	const char *password,
	size_t password_len,
	struct volume_key **vk);

int LUKS2_keyslot_store(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *password,
	size_t password_len,
	const struct volume_key *vk,
	const struct luks2_keyslot_params *params);

int LUKS2_keyslot_wipe(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int wipe_area_only);

int LUKS2_keyslot_dump(struct crypt_device *cd,
	int keyslot);

crypt_keyslot_priority LUKS2_keyslot_priority_get(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot);

int LUKS2_keyslot_priority_set(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	crypt_keyslot_priority priority,
	int commit);

/*
 * Generic LUKS2 token
 */
int LUKS2_token_json_get(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char **json);

int LUKS2_token_assign(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int token,
	int assign,
	int commit);

int LUKS2_token_is_assigned(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int token);

int LUKS2_token_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char *json,
	int commit);

crypt_token_info LUKS2_token_status(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char **type);

int LUKS2_builtin_token_get(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char *type,
	void *params);

int LUKS2_builtin_token_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char *type,
	const void *params,
	int commit);

int LUKS2_token_open_and_activate(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		int token,
		const char *name,
		uint32_t flags,
		void *usrptr);

int LUKS2_token_open_and_activate_any(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *name,
	uint32_t flags);

int LUKS2_tokens_count(struct luks2_hdr *hdr);

/*
 * Generic LUKS2 digest
 */
int LUKS2_digest_by_segment(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment);

int LUKS2_digest_verify_by_segment(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment,
	const struct volume_key *vk);

void LUKS2_digests_erase_unused(struct crypt_device *cd,
	struct luks2_hdr *hdr);

int LUKS2_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct volume_key *vk,
	int keyslot);

int LUKS2_digest_dump(struct crypt_device *cd,
	int digest);

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

int LUKS2_digest_by_keyslot(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot);

int LUKS2_digest_create(struct crypt_device *cd,
	const char *type,
	struct luks2_hdr *hdr,
	const struct volume_key *vk);

/*
 * LUKS2 generic
 */
int LUKS2_activate(struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	uint32_t flags);

int LUKS2_keyslot_luks2_format(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *cipher,
	size_t keylength);

int LUKS2_generate_hdr(
	struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	const char *cipherName,
	const char *cipherMode,
	const char *integrity,
	const char *uuid,
	unsigned int sector_size,
	unsigned int alignPayload,
	unsigned int alignOffset,
	int detached_metadata_device);

uint64_t LUKS2_get_data_offset(struct luks2_hdr *hdr);
int LUKS2_get_sector_size(struct luks2_hdr *hdr);
const char *LUKS2_get_cipher(struct luks2_hdr *hdr, int segment);
const char *LUKS2_get_integrity(struct luks2_hdr *hdr, int segment);
int LUKS2_keyslot_params_default(struct crypt_device *cd, struct luks2_hdr *hdr,
	size_t key_size, struct luks2_keyslot_params *params);
int LUKS2_get_keyslot_params(struct luks2_hdr *hdr, int keyslot,
	struct luks2_keyslot_params *params);
int LUKS2_get_volume_key_size(struct luks2_hdr *hdr, int segment);
int LUKS2_get_keyslot_key_size(struct luks2_hdr *hdr, int keyslot);
int LUKS2_keyslot_find_empty(struct luks2_hdr *hdr, const char *type);
int LUKS2_keyslot_active_count(struct luks2_hdr *hdr, int segment);
int LUKS2_keyslot_for_segment(struct luks2_hdr *hdr, int keyslot, int segment);
crypt_keyslot_info LUKS2_keyslot_info(struct luks2_hdr *hdr, int keyslot);
int LUKS2_keyslot_area(struct luks2_hdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length);
/*
 * Permanent activation flags stored in header
 */
int LUKS2_config_get_flags(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t *flags);
int LUKS2_config_set_flags(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t flags);

/*
 * Requirements for device activation or header modification
 */
int LUKS2_config_get_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t *reqs);
int LUKS2_config_set_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs);

int LUKS2_unmet_requirements(struct crypt_device *cd, struct luks2_hdr *hdr, uint32_t reqs_mask, int quiet);

int LUKS2_key_description_by_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int segment);
int LUKS2_volume_key_load_in_keyring_by_keyslot(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int keyslot);

struct luks_phdr;
int LUKS2_luks1_to_luks2(struct crypt_device *cd,
			 struct luks_phdr *hdr1,
			 struct luks2_hdr *hdr2);
int LUKS2_luks2_to_luks1(struct crypt_device *cd,
			 struct luks2_hdr *hdr2,
			 struct luks_phdr *hdr1);

#endif
