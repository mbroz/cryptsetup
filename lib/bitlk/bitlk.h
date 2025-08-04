// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * BITLK (BitLocker-compatible) header definition
 *
 * Copyright (C) 2019-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2019-2025 Milan Broz
 * Copyright (C) 2019-2025 Vojtech Trefny
 */

#ifndef _CRYPTSETUP_BITLK_H
#define _CRYPTSETUP_BITLK_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct crypt_device;
struct device;
struct volume_key;

#define BITLK_NONCE_SIZE 12
#define BITLK_SALT_SIZE 16
#define BITLK_VMK_MAC_TAG_SIZE 16
#define BITLK_VALIDATION_VMK_HEADER_SIZE 8
#define BITLK_VALIDATION_VMK_DATA_SIZE 72

#define BITLK_STATE_NORMAL 0x0004

typedef enum {
	BITLK_ENCRYPTION_TYPE_NORMAL = 0,
	BITLK_ENCRYPTION_TYPE_EOW,
	BITLK_ENCRYPTION_TYPE_UNKNOWN,
} BITLKEncryptionType;

typedef enum {
	BITLK_PROTECTION_CLEAR_KEY = 0,
	BITLK_PROTECTION_TPM,
	BITLK_PROTECTION_STARTUP_KEY,
	BITLK_PROTECTION_TPM_PIN,
	BITLK_PROTECTION_RECOVERY_PASSPHRASE,
	BITLK_PROTECTION_PASSPHRASE,
	BITLK_PROTECTION_SMART_CARD,
	BITLK_PROTECTION_UNKNOWN,
} BITLKVMKProtection;

typedef enum {
	BITLK_ENTRY_TYPE_PROPERTY = 0x0000,
	BITLK_ENTRY_TYPE_VMK = 0x0002,
	BITLK_ENTRY_TYPE_FVEK = 0x0003,
	BITLK_ENTRY_TYPE_STARTUP_KEY = 0x0006,
	BITLK_ENTRY_TYPE_DESCRIPTION = 0x0007,
	BITLK_ENTRY_TYPE_VOLUME_HEADER = 0x000f,
	BITLK_ENTRY_TYPE_VOLUME_GUID = 0x0019,
} BITLKFVEEntryType;

typedef enum {
	BITLK_ENTRY_VALUE_ERASED = 0x0000,
	BITLK_ENTRY_VALUE_KEY = 0x0001,
	BITLK_ENTRY_VALUE_STRING = 0x0002,
	BITLK_ENTRY_VALUE_STRETCH_KEY = 0x0003,
	BITLK_ENTRY_VALUE_USE_KEY = 0x0004,
	BITLK_ENTRY_VALUE_ENCRYPTED_KEY = 0x0005,
	BITLK_ENTRY_VALUE_TPM_KEY = 0x0006,
	BITLK_ENTRY_VALUE_VALIDATION = 0x0007,
	BITLK_ENTRY_VALUE_VMK = 0x0008,
	BITLK_ENTRY_VALUE_EXTERNAL_KEY = 0x0009,
	BITLK_ENTRY_VALUE_OFFSET_SIZE = 0x000f,
	BITLK_ENTRY_VALUE_RECOVERY_TIME = 0x015,
	BITLK_ENTRY_VALUE_GUID = 0x0017,
	BITLK_ENTRY_VALUE_HINT = 0x0018,
} BITLKFVEEntryValue;

struct bitlk_vmk {
	char *guid;
	char *name;
	BITLKVMKProtection protection;
	uint8_t salt[BITLK_SALT_SIZE];
	uint8_t mac_tag[BITLK_VMK_MAC_TAG_SIZE];
	uint8_t nonce[BITLK_NONCE_SIZE];
	struct volume_key *vk;
	struct bitlk_vmk *next;
};

struct bitlk_fvek {
	uint8_t mac_tag[BITLK_VMK_MAC_TAG_SIZE];
	uint8_t nonce[BITLK_NONCE_SIZE];
	struct volume_key *vk;
};

struct bitlk_validation {
	uint8_t mac_tag[BITLK_VMK_MAC_TAG_SIZE];
	uint8_t nonce[BITLK_NONCE_SIZE];
	/* technically, this is not "VMK", but some sources call it this way */
	uint8_t enc_datum[BITLK_VALIDATION_VMK_DATA_SIZE];
};

struct bitlk_metadata {
	uint16_t sector_size;
	uint64_t volume_size;
	bool togo;
	bool state;
	BITLKEncryptionType type;
	const char *cipher;
	const char *cipher_mode;
	uint16_t key_size;
	char *guid;
	uint64_t creation_time;
	char *description;
	uint64_t metadata_offset[3];
	uint32_t metadata_version;
	uint64_t volume_header_offset;
	uint64_t volume_header_size;
	const char *sha256_fve[32];
	struct bitlk_vmk *vmks;
	struct bitlk_fvek *fvek;
	struct bitlk_validation *validation;
};

int BITLK_read_sb(struct crypt_device *cd, struct bitlk_metadata *params);

int BITLK_dump(struct crypt_device *cd, struct device *device, struct bitlk_metadata *params);

int BITLK_get_volume_key(struct crypt_device *cd,
			 const char *password,
			 size_t passwordLen,
			 const struct bitlk_metadata *params,
			 struct volume_key **open_fvek_key);

int BITLK_activate_by_volume_key(struct crypt_device *cd,
				 const char *name,
				 struct volume_key *vk,
				 const struct bitlk_metadata *params,
				 uint32_t flags);

void BITLK_bitlk_fvek_free(struct bitlk_fvek *fvek);
void BITLK_bitlk_vmk_free(struct bitlk_vmk *vmk);
void BITLK_bitlk_metadata_free(struct bitlk_metadata *params);

#endif
