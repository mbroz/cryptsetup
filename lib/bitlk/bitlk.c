/*
 * BITLK (BitLocker-compatible) volume handling
 *
 * Copyright (C) 2019-2024 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2019-2024 Milan Broz
 * Copyright (C) 2019-2024 Vojtech Trefny
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <errno.h>
#include <string.h>
#include <uuid/uuid.h>
#include <time.h>
#include <limits.h>

#include "bitlk.h"
#include "internal.h"

#define BITLK_BOOTCODE_V1 "\xeb\x52\x90"
#define BITLK_BOOTCODE_V2 "\xeb\x58\x90"
#define BITLK_SIGNATURE "-FVE-FS-"
#define BITLK_SIGNATURE_TOGO "MSWIN4.1"
#define BITLK_HEADER_METADATA_OFFSET 160
#define BITLK_HEADER_METADATA_OFFSET_TOGO 424

/* FVE metadata header is split into two parts */
#define BITLK_FVE_METADATA_BLOCK_HEADER_LEN 64
#define BITLK_FVE_METADATA_HEADER_LEN 48
#define BITLK_FVE_METADATA_HEADERS_LEN BITLK_FVE_METADATA_BLOCK_HEADER_LEN + BITLK_FVE_METADATA_HEADER_LEN

/* total size of the FVE area (64 KiB) */
#define BITLK_FVE_METADATA_SIZE 64 * 1024

#define BITLK_ENTRY_HEADER_LEN 8
#define BITLK_VMK_HEADER_LEN 28

#define BITLK_OPEN_KEY_METADATA_LEN 12

#define BITLK_RECOVERY_KEY_LEN 55
#define BITLK_RECOVERY_PARTS 8
#define BITLK_RECOVERY_PART_LEN 6

#define BITLK_BEK_FILE_HEADER_LEN 48
#define BITLK_STARTUP_KEY_HEADER_LEN 24

#define BITLK_KDF_HASH "sha256"
#define BITLK_KDF_ITERATION_COUNT 0x100000

/* maximum number of segments for the DM device */
#define MAX_BITLK_SEGMENTS 10

/* January 1, 1970 as MS file time */
#define EPOCH_AS_FILETIME 116444736000000000
#define HUNDREDS_OF_NANOSECONDS 10000000

/* not available in older version of libuuid */
#ifndef UUID_STR_LEN
#define UUID_STR_LEN	37
#endif

/* known types of GUIDs from the BITLK superblock */
const uint8_t BITLK_GUID_NORMAL[16] = { 0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a,
					0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01 };
const uint8_t BITLK_GUID_EOW[16] = { 0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d,
				     0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8 };

/* taken from libfdisk gpt.c -- TODO: this is a good candidate for adding to libuuid */
struct bitlk_guid {
	uint32_t   time_low;
	uint16_t   time_mid;
	uint16_t   time_hi_and_version;
	uint8_t    clock_seq_hi;
	uint8_t    clock_seq_low;
	uint8_t    node[6];
} __attribute__ ((packed));

static void swap_guid(struct bitlk_guid *guid) {
	guid->time_low = swab32(guid->time_low);
	guid->time_mid = swab16(guid->time_mid);
	guid->time_hi_and_version = swab16(guid->time_hi_and_version);
}

static void guid_to_string(struct bitlk_guid *guid, char *out) {
	swap_guid(guid);
	uuid_unparse((unsigned char *) guid, out);
}

typedef enum {
	BITLK_SEGTYPE_CRYPT,
	BITLK_SEGTYPE_ZERO,
} BitlkSegmentType;

struct segment {
	uint64_t offset;
	uint64_t length;
	uint64_t iv_offset;
	BitlkSegmentType type;
};

struct bitlk_signature {
	uint8_t boot_code[3];
	uint8_t signature[8];
	uint16_t sector_size;
} __attribute__ ((packed));

struct bitlk_superblock {
	struct bitlk_guid guid;
	uint64_t fve_offset[3];
} __attribute__ ((packed));

struct bitlk_fve_metadata {
	/* FVE metadata block header */
	uint8_t signature[8];
	uint16_t fve_size;
	uint16_t fve_version;
	uint16_t curr_state;
	uint16_t next_state;
	uint64_t volume_size;
	uint32_t unknown2;
	uint32_t volume_header_size;
	uint64_t fve_offset[3];
	uint64_t volume_header_offset;
	/* FVE metadata header */
	uint32_t metadata_size;
	uint32_t metadata_version;
	uint32_t metadata_header_size;
	uint32_t metada_size_copy;
	struct bitlk_guid guid;
	uint32_t next_nonce;
	uint16_t encryption;
	uint16_t unknown3;
	uint64_t creation_time;
} __attribute__ ((packed));

struct bitlk_entry_header_block {
	uint64_t offset;
	uint64_t size;
} __attribute__ ((packed));

struct bitlk_entry_vmk {
	struct bitlk_guid guid;
	uint8_t modified[8];
	uint16_t _unknown;
	uint16_t protection;
} __attribute__ ((packed));

struct bitlk_kdf_data {
	char last_sha256[32];
	char initial_sha256[32];
	char salt[16];
	uint64_t count;
};

struct bitlk_bek_header {
	uint32_t metadata_size;
	uint32_t metadata_version;
	uint32_t metadata_header_size;
	uint32_t metada_size_copy;
	struct bitlk_guid guid;
	uint32_t next_nonce;
	uint16_t encryption;
	uint16_t unknown;
	uint64_t creation_time;
} __attribute__ ((packed));

static BITLKVMKProtection get_vmk_protection(uint16_t protection)
{
	switch (protection) {
	case 0x0000:
		return BITLK_PROTECTION_CLEAR_KEY;
	case 0x0100:
		return BITLK_PROTECTION_TPM;
	case 0x0200:
		return BITLK_PROTECTION_STARTUP_KEY;
	case 0x0500:
		return BITLK_PROTECTION_TPM_PIN;
	case 0x0800:
		return BITLK_PROTECTION_RECOVERY_PASSPHRASE;
	case 0x1000:
		return BITLK_PROTECTION_SMART_CARD;
	case 0x2000:
		return BITLK_PROTECTION_PASSPHRASE;
	default:
		return BITLK_PROTECTION_UNKNOWN;
	}
}

static const char* get_vmk_protection_string(BITLKVMKProtection protection)
{
	switch (protection) {
	case BITLK_PROTECTION_CLEAR_KEY:
		return "VMK protected with clear key";
	case BITLK_PROTECTION_TPM:
		return "VMK protected with TPM";
	case BITLK_PROTECTION_STARTUP_KEY:
		return "VMK protected with startup key";
	case BITLK_PROTECTION_TPM_PIN:
		return "VMK protected with TPM and PIN";
	case BITLK_PROTECTION_PASSPHRASE:
		return "VMK protected with passphrase";
	case BITLK_PROTECTION_RECOVERY_PASSPHRASE:
		return "VMK protected with recovery passphrase";
	case BITLK_PROTECTION_SMART_CARD:
		return "VMK protected with smart card";
	default:
		return "VMK with unknown protection";
	}
}

static const char* get_bitlk_type_string(BITLKEncryptionType type)
{
	switch (type)
	{
	case BITLK_ENCRYPTION_TYPE_NORMAL:
		return "normal";
	case BITLK_ENCRYPTION_TYPE_EOW:
		return "encrypt-on-write";
	default:
		return "unknown";
	}
}

static uint64_t filetime_to_unixtime(uint64_t time)
{
	return (time - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS;
}

static int parse_vmk_entry(struct crypt_device *cd, uint8_t *data, int start, int end, struct bitlk_vmk **vmk)
{
	uint16_t key_entry_size = 0;
	uint16_t key_entry_type = 0;
	uint16_t key_entry_value = 0;
	size_t key_size = 0;
	char *string = NULL;
	const char *key = NULL;
	struct volume_key *vk = NULL;
	bool supported = false;
	int r = 0;

	/* only passphrase or recovery passphrase vmks are supported (can be used to activate) */
	supported = (*vmk)->protection == BITLK_PROTECTION_PASSPHRASE ||
		    (*vmk)->protection == BITLK_PROTECTION_RECOVERY_PASSPHRASE ||
		    (*vmk)->protection == BITLK_PROTECTION_STARTUP_KEY;

	while ((end - start) >= (ssize_t)(sizeof(key_entry_size) + sizeof(key_entry_type) + sizeof(key_entry_value))) {
		/* size of this entry */
		memcpy(&key_entry_size, data + start, sizeof(key_entry_size));
		key_entry_size = le16_to_cpu(key_entry_size);
		if (key_entry_size == 0)
			break;

		if (key_entry_size > (end - start))
			return -EINVAL;

		/* type and value of this entry */
		memcpy(&key_entry_type, data + start + sizeof(key_entry_size), sizeof(key_entry_type));
		memcpy(&key_entry_value,
		       data + start + sizeof(key_entry_size) + sizeof(key_entry_type),
		       sizeof(key_entry_value));
		key_entry_type = le16_to_cpu(key_entry_type);
		key_entry_value = le16_to_cpu(key_entry_value);

		if (key_entry_type != BITLK_ENTRY_TYPE_PROPERTY) {
			if (supported) {
				log_err(cd, _("Unexpected metadata entry type '%u' found when parsing supported Volume Master Key."), key_entry_type);
				return -EINVAL;
			} else {
				log_dbg(cd, "Unexpected metadata entry type '%u' found when parsing unsupported VMK.", key_entry_type);
			}
		}

		/* stretch key with salt, skip 4 B (encryption method of the stretch key) */
		if (key_entry_value == BITLK_ENTRY_VALUE_STRETCH_KEY) {
			if ((end - start) < (BITLK_ENTRY_HEADER_LEN + BITLK_SALT_SIZE + 4))
				return -EINVAL;
			memcpy((*vmk)->salt,
			       data + start + BITLK_ENTRY_HEADER_LEN + 4,
			       BITLK_SALT_SIZE);
		/* AES-CCM encrypted key */
		} else if (key_entry_value == BITLK_ENTRY_VALUE_ENCRYPTED_KEY) {
			if (key_entry_size < (BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE + BITLK_VMK_MAC_TAG_SIZE))
				return -EINVAL;
			/* nonce */
			memcpy((*vmk)->nonce,
			       data + start + BITLK_ENTRY_HEADER_LEN,
			       BITLK_NONCE_SIZE);
			/* MAC tag */
			memcpy((*vmk)->mac_tag,
			       data + start + BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE,
			       BITLK_VMK_MAC_TAG_SIZE);
			/* AES-CCM encrypted key */
			key_size = key_entry_size - (BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE + BITLK_VMK_MAC_TAG_SIZE);
			key = (const char *) data + start + BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE + BITLK_VMK_MAC_TAG_SIZE;
			vk = crypt_alloc_volume_key(key_size, key);
			if (vk == NULL)
				return -ENOMEM;
			crypt_volume_key_add_next(&((*vmk)->vk), vk);
		/* clear key for a partially decrypted volume */
		} else if (key_entry_value == BITLK_ENTRY_VALUE_KEY) {
			/* We currently don't want to support opening a partially decrypted
			 * device so we don't need to store this key.
			 *
			 * key_size = key_entry_size - (BITLK_ENTRY_HEADER_LEN + 4);
			 * key = (const char *) data + start + BITLK_ENTRY_HEADER_LEN + 4;
			 * vk = crypt_alloc_volume_key(key_size, key);
			 * if (vk == NULL)
			 * 	return -ENOMEM;
			 * crypt_volume_key_add_next(&((*vmk)->vk), vk);
			 */
			log_dbg(cd, "Skipping clear key metadata entry.");
		/* unknown timestamps in recovery protected VMK */
		} else if (key_entry_value == BITLK_ENTRY_VALUE_RECOVERY_TIME) {
			;
		} else if (key_entry_value == BITLK_ENTRY_VALUE_STRING) {
			if (key_entry_size < BITLK_ENTRY_HEADER_LEN)
				return -EINVAL;
			string = malloc((key_entry_size - BITLK_ENTRY_HEADER_LEN) * 2 + 1);
			if (!string)
				return -ENOMEM;
			r = crypt_utf16_to_utf8(&string, CONST_CAST(char16_t *)(data + start + BITLK_ENTRY_HEADER_LEN),
						     key_entry_size - BITLK_ENTRY_HEADER_LEN);
			if (r < 0 || !string) {
				free(string);
				log_err(cd, _("Invalid string found when parsing Volume Master Key."));
				return -EINVAL;
			} else if ((*vmk)->name != NULL) {
				if (supported) {
					log_err(cd, _("Unexpected string ('%s') found when parsing supported Volume Master Key."), string);
					free(string);
					return -EINVAL;
				}
				log_dbg(cd, "Unexpected string ('%s') found when parsing unsupported VMK.", string);
				free(string);
				string = NULL;
			} else {
				/* Assume that strings in VMK are the name of the VMK */
				(*vmk)->name = string;
				string = NULL;
			}
		/* no idea what this is, lets hope it's not important */
		} else if (key_entry_value == BITLK_ENTRY_VALUE_USE_KEY && (*vmk)->protection == BITLK_PROTECTION_STARTUP_KEY) {
			;
		} else {
			if (supported) {
				log_err(cd, _("Unexpected metadata entry value '%u' found when parsing supported Volume Master Key."), key_entry_value);
				return -EINVAL;
			} else {
				log_dbg(cd, "Unexpected metadata entry value '%u' found when parsing unsupported VMK.", key_entry_value);
			}
		}

		start += key_entry_size;
	}

	return 0;
}

void BITLK_bitlk_fvek_free(struct bitlk_fvek *fvek)
{
	if (!fvek)
		return;

	crypt_free_volume_key(fvek->vk);
	free(fvek);
}

void BITLK_bitlk_vmk_free(struct bitlk_vmk *vmk)
{
	struct bitlk_vmk *vmk_next = NULL;

	while (vmk) {
		if (vmk->guid)
			free(vmk->guid);
		if (vmk->name)
			free(vmk->name);
		crypt_free_volume_key(vmk->vk);
		vmk_next = vmk->next;
		free(vmk);
		vmk = vmk_next;
	}
}

void BITLK_bitlk_metadata_free(struct bitlk_metadata *metadata)
{
	if (!metadata)
		return;

	free(metadata->guid);
	if (metadata->description)
		free(metadata->description);
	BITLK_bitlk_vmk_free(metadata->vmks);
	BITLK_bitlk_fvek_free(metadata->fvek);
}

int BITLK_read_sb(struct crypt_device *cd, struct bitlk_metadata *params)
{
	int devfd;
	struct device *device = crypt_metadata_device(cd);
	struct bitlk_signature sig = {};
	struct bitlk_superblock sb = {};
	struct bitlk_fve_metadata fve = {};
	struct bitlk_entry_vmk entry_vmk = {};
	uint8_t *fve_entries = NULL;
	size_t fve_entries_size = 0;
	uint32_t fve_metadata_size = 0;
	int fve_offset = 0;
	char guid_buf[UUID_STR_LEN] = {0};
	uint16_t entry_size = 0;
	uint16_t entry_type = 0;
	int i = 0;
	int r = 0;
	int start = 0;
	size_t key_size = 0;
	const char *key = NULL;
	char *description = NULL;

	struct bitlk_vmk *vmk = NULL;
	struct bitlk_vmk *vmk_p = params->vmks;

	devfd = device_open(cd, crypt_data_device(cd), O_RDONLY);
	if (devfd < 0) {
		r = -EINVAL;
		goto out;
	}

	/* read and check the signature */
	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
		device_alignment(device), &sig, sizeof(sig), 0) != sizeof(sig)) {
		log_dbg(cd, "Failed to read BITLK signature from %s.", device_path(device));
		r = -EIO;
		goto out;
	}

	if (memcmp(sig.signature, BITLK_SIGNATURE, sizeof(sig.signature)) == 0) {
		params->togo = false;
		fve_offset = BITLK_HEADER_METADATA_OFFSET;
	} else if (memcmp(sig.signature, BITLK_SIGNATURE_TOGO, sizeof(sig.signature)) == 0) {
		params->togo = true;
		fve_offset = BITLK_HEADER_METADATA_OFFSET_TOGO;
	} else {
		log_dbg(cd, "Invalid or unknown signature for BITLK device.");
		r = -EINVAL;
		goto out;
	}

	if (memcmp(sig.boot_code, BITLK_BOOTCODE_V1, sizeof(sig.boot_code)) == 0) {
		log_err(cd, _("BITLK version 1 is currently not supported."));
		r = -ENOTSUP;
		goto out;
	} else if (memcmp(sig.boot_code, BITLK_BOOTCODE_V2, sizeof(sig.boot_code)) == 0)
		;
	else {
		log_err(cd, _("Invalid or unknown boot signature for BITLK device."));
		r = -EINVAL;
		goto out;
	}

	params->sector_size = le16_to_cpu(sig.sector_size);
	if (params->sector_size == 0) {
		log_dbg(cd, "Got sector size 0, assuming 512.");
		params->sector_size = SECTOR_SIZE;
	}

	if (!(params->sector_size == 512 || params->sector_size == 4096)) {
		log_err(cd, _("Unsupported sector size %" PRIu16 "."), params->sector_size);
		r = -EINVAL;
		goto out;
	}

	/* read GUID and FVE metadata offsets */
	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
		device_alignment(device), &sb, sizeof(sb), fve_offset) != sizeof(sb)) {
		log_err(cd, _("Failed to read BITLK header from %s."), device_path(device));
		r = -EINVAL;
		goto out;
	}

	/* get encryption "type" based on the GUID from BITLK superblock */
	if (memcmp(&sb.guid, BITLK_GUID_NORMAL, 16) == 0)
		params->type = BITLK_ENCRYPTION_TYPE_NORMAL;
	else if (memcmp(&sb.guid, BITLK_GUID_EOW, 16) == 0)
		params->type = BITLK_ENCRYPTION_TYPE_EOW;
	else
		params->type = BITLK_ENCRYPTION_TYPE_UNKNOWN;
	log_dbg(cd, "BITLK type from GUID: %s.", get_bitlk_type_string(params->type));

	for (i = 0; i < 3; i++)
		params->metadata_offset[i] = le64_to_cpu(sb.fve_offset[i]);

	log_dbg(cd, "Reading BITLK FVE metadata of size %zu on device %s, offset %" PRIu64 ".",
		sizeof(fve), device_path(device), params->metadata_offset[0]);

	/* read FVE metadata from the first metadata area */
	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
		device_alignment(device), &fve, sizeof(fve), params->metadata_offset[0]) != sizeof(fve) ||
		memcmp(fve.signature, BITLK_SIGNATURE, sizeof(fve.signature)) ||
		le16_to_cpu(fve.fve_version) != 2) {
		log_err(cd, _("Failed to read BITLK FVE metadata from %s."), device_path(device));
		r = -EINVAL;
		goto out;
	}

	/* check encryption state for the device */
	params->state = true;
	if (le16_to_cpu(fve.curr_state) != BITLK_STATE_NORMAL || le16_to_cpu(fve.next_state) != BITLK_STATE_NORMAL) {
		params->state = false;
		log_dbg(cd, "Unknown/unsupported state detected. Current state: %"PRIu16", next state: %"PRIu16".",
			le16_to_cpu(fve.curr_state), le16_to_cpu(fve.next_state));
	}

	params->volume_size = le64_to_cpu(fve.volume_size);
	params->metadata_version = le16_to_cpu(fve.fve_version);

	switch (le16_to_cpu(fve.encryption)) {
	/* AES-CBC with Elephant difuser */
	case 0x8000:
		params->key_size = 256;
		params->cipher = "aes";
		params->cipher_mode = "cbc-elephant";
		break;
	case 0x8001:
		params->key_size = 512;
		params->cipher = "aes";
		params->cipher_mode = "cbc-elephant";
		break;
	/* AES-CBC */
	case 0x8002:
		params->key_size = 128;
		params->cipher = "aes";
		params->cipher_mode = "cbc-eboiv";
		break;
	case 0x8003:
		params->key_size = 256;
		params->cipher = "aes";
		params->cipher_mode = "cbc-eboiv";
		break;
	/* AES-XTS */
	case 0x8004:
		params->key_size = 256;
		params->cipher = "aes";
		params->cipher_mode = "xts-plain64";
		break;
	case 0x8005:
		params->key_size = 512;
		params->cipher = "aes";
		params->cipher_mode = "xts-plain64";
		break;
	default:
		log_err(cd, _("Unknown or unsupported encryption type."));
		params->key_size = 0;
		params->cipher = NULL;
		params->cipher_mode = NULL;
		r = -ENOTSUP;
		goto out;
	};

	/* device GUID */
	guid_to_string(&fve.guid, guid_buf);
	params->guid = strdup(guid_buf);
	if (!params->guid) {
		r = -ENOMEM;
		goto out;
	}

	params->creation_time = filetime_to_unixtime(le64_to_cpu(fve.creation_time));

	fve_metadata_size = le32_to_cpu(fve.metadata_size);
	if (fve_metadata_size < (BITLK_FVE_METADATA_HEADER_LEN + sizeof(entry_size) + sizeof(entry_type)) ||
	    fve_metadata_size > BITLK_FVE_METADATA_SIZE) {
		r = -EINVAL;
		goto out;
	}
	fve_entries_size = fve_metadata_size - BITLK_FVE_METADATA_HEADER_LEN;

	/* read and parse all FVE metadata entries */
	fve_entries = malloc(fve_entries_size);
	if (!fve_entries) {
		r = -ENOMEM;
		goto out;
	}
	memset(fve_entries, 0, fve_entries_size);

	log_dbg(cd, "Reading BITLK FVE metadata entries of size %zu on device %s, offset %" PRIu64 ".",
		fve_entries_size, device_path(device), params->metadata_offset[0] + BITLK_FVE_METADATA_HEADERS_LEN);

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
		device_alignment(device), fve_entries, fve_entries_size,
		params->metadata_offset[0] + BITLK_FVE_METADATA_HEADERS_LEN) != (ssize_t)fve_entries_size) {
		log_err(cd, _("Failed to read BITLK metadata entries from %s."), device_path(device));
		r = -EINVAL;
		goto out;
	}

	while ((fve_entries_size - start) >= (sizeof(entry_size) + sizeof(entry_type))) {

		/* size of this entry */
		memcpy(&entry_size, fve_entries + start, sizeof(entry_size));
		entry_size = le16_to_cpu(entry_size);
		if (entry_size == 0)
			break;

		if (entry_size > (fve_entries_size - start)) {
			r = -EINVAL;
			goto out;
		}

		/* type of this entry */
		memcpy(&entry_type, fve_entries + start + sizeof(entry_size), sizeof(entry_type));
		entry_type = le16_to_cpu(entry_type);

		/* VMK */
		if (entry_type == BITLK_ENTRY_TYPE_VMK) {
			if (entry_size < (BITLK_ENTRY_HEADER_LEN + sizeof(entry_vmk))) {
				r = -EINVAL;
				goto out;
			}
			/* skip first four variables in the entry (entry size, type, value and version) */
			memcpy(&entry_vmk,
			       fve_entries + start + BITLK_ENTRY_HEADER_LEN,
			       sizeof(entry_vmk));

			vmk = malloc(sizeof(struct bitlk_vmk));
			if (!vmk) {
				r = -ENOMEM;
				goto out;
			}
			memset(vmk, 0, sizeof(struct bitlk_vmk));

			guid_to_string(&entry_vmk.guid, guid_buf);
			vmk->guid = strdup (guid_buf);

			vmk->name = NULL;

			vmk->protection = get_vmk_protection(le16_to_cpu(entry_vmk.protection));

			/* more data in another entry list */
			r = parse_vmk_entry(cd, fve_entries,
			                      start + BITLK_ENTRY_HEADER_LEN + BITLK_VMK_HEADER_LEN,
					      start + entry_size, &vmk);
			if (r < 0) {
				BITLK_bitlk_vmk_free(vmk);
				goto out;
			}

			if (params->vmks == NULL)
				params->vmks = vmk;
			else
				vmk_p->next = vmk;

			vmk_p = vmk;
			vmk = vmk->next;
		/* FVEK */
		} else if (entry_type == BITLK_ENTRY_TYPE_FVEK && !params->fvek) {
			if (entry_size < (BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE + BITLK_VMK_MAC_TAG_SIZE)) {
				r = -EINVAL;
				goto out;
			}
			params->fvek = malloc(sizeof(struct bitlk_fvek));
			if (!params->fvek) {
				r = -ENOMEM;
				goto out;
			}
			memcpy(params->fvek->nonce,
			       fve_entries + start + BITLK_ENTRY_HEADER_LEN,
			       BITLK_NONCE_SIZE);
			/* MAC tag */
			memcpy(params->fvek->mac_tag,
			       fve_entries + start + BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE,
			       BITLK_VMK_MAC_TAG_SIZE);
			/* AES-CCM encrypted key */
			key_size = entry_size - (BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE + BITLK_VMK_MAC_TAG_SIZE);
			key = (const char *) fve_entries + start + BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE + BITLK_VMK_MAC_TAG_SIZE;
			params->fvek->vk = crypt_alloc_volume_key(key_size, key);
			if (params->fvek->vk == NULL) {
				r = -ENOMEM;
				goto out;
			}
		/* volume header info (location and size) */
		} else if (entry_type == BITLK_ENTRY_TYPE_VOLUME_HEADER) {
			struct bitlk_entry_header_block entry_header;
			if ((fve_entries_size - start) < (BITLK_ENTRY_HEADER_LEN + sizeof(entry_header))) {
				r = -EINVAL;
				goto out;
			}
			memcpy(&entry_header,
			       fve_entries + start + BITLK_ENTRY_HEADER_LEN,
			       sizeof(entry_header));
			params->volume_header_offset = le64_to_cpu(entry_header.offset);
			params->volume_header_size = le64_to_cpu(entry_header.size);
		/* volume description (utf-16 string) */
		} else if (entry_type == BITLK_ENTRY_TYPE_DESCRIPTION && !params->description) {
			if (entry_size < BITLK_ENTRY_HEADER_LEN) {
				r = -EINVAL;
				goto out;
			}
			description = malloc((entry_size - BITLK_ENTRY_HEADER_LEN) * 2 + 1);
			if (!description) {
				r = -ENOMEM;
				goto out;
			}
			r = crypt_utf16_to_utf8(&description, CONST_CAST(char16_t *)(fve_entries + start + BITLK_ENTRY_HEADER_LEN),
					                  entry_size - BITLK_ENTRY_HEADER_LEN);
			if (r < 0) {
				free(description);
				BITLK_bitlk_vmk_free(vmk);
				log_err(cd, _("Failed to convert BITLK volume description"));
				goto out;
			}
			params->description = description;
		}

		start += entry_size;
	}

out:
	if (fve_entries)
		free(fve_entries);
	return r;
}

int BITLK_dump(struct crypt_device *cd, struct device *device, struct bitlk_metadata *params)
{
	struct volume_key *vk_p;
	struct bitlk_vmk *vmk_p;
	char time[32];
	int next_id = 0;
	int i = 0;

	log_std(cd, "Info for BITLK%s device %s.\n", params->togo ? " To Go" : "", device_path(device));
	log_std(cd, "Version:      \t%u\n", params->metadata_version);
	log_std(cd, "GUID:         \t%s\n", params->guid);
	log_std(cd, "Sector size:  \t%u [bytes]\n", params->sector_size);
	log_std(cd, "Volume size:  \t%" PRIu64 " [bytes]\n", params->volume_size);
	if (ctime_r((time_t *)&params->creation_time, time))
		log_std(cd, "Created:      \t%s", time);
	log_std(cd, "Description:  \t%s\n", params->description);
	log_std(cd, "Cipher name:  \t%s\n", params->cipher);
	log_std(cd, "Cipher mode:  \t%s\n", params->cipher_mode);
	log_std(cd, "Cipher key:   \t%u bits\n", params->key_size);

	log_std(cd, "\n");

	log_std(cd, "Keyslots:\n");
	vmk_p = params->vmks;
	while (vmk_p) {
		log_std(cd, " %d: VMK\n", next_id);
		if (vmk_p->name != NULL) {
			log_std(cd, "\tName:       \t%s\n", vmk_p->name);
		}
		log_std(cd, "\tGUID:       \t%s\n", vmk_p->guid);
		log_std(cd, "\tProtection: \t%s\n", get_vmk_protection_string (vmk_p->protection));
		log_std(cd, "\tSalt:       \t");
		crypt_log_hex(cd, (const char *) vmk_p->salt, 16, "", 0, NULL);
		log_std(cd, "\n");

		vk_p = vmk_p->vk;
		while (vk_p) {
			log_std(cd, "\tKey data size:\t%zu [bytes]\n", vk_p->keylength);
			vk_p = vk_p->next;
		}
		vmk_p = vmk_p->next;
		next_id++;
	}

	log_std(cd, " %d: FVEK\n", next_id);
	log_std(cd, "\tKey data size:\t%zu [bytes]\n", params->fvek->vk->keylength);

	log_std(cd, "\n");

	log_std(cd, "Metadata segments:\n");

	for (i = 0; i < 3; i++) {
		log_std(cd, " %d: FVE metadata area\n", i);
		log_std(cd, "\tOffset: \t%" PRIu64 " [bytes]\n", params->metadata_offset[i]);
		log_std(cd, "\tSize:   \t%d [bytes]\n", BITLK_FVE_METADATA_SIZE);
	}

	log_std(cd, " %d: Volume header\n", i);
	log_std(cd, "\tOffset: \t%" PRIu64 " [bytes]\n", params->volume_header_offset);
	log_std(cd, "\tSize:   \t%" PRIu64 " [bytes]\n", params->volume_header_size);
	log_std(cd, "\tCipher: \t%s-%s\n", params->cipher, params->cipher_mode);

	return 0;
}

/* check if given passphrase can be a recovery key (has right format) and convert it */
static int get_recovery_key(struct crypt_device *cd,
			    const char *password,
			    size_t passwordLen,
			    struct volume_key **rc_key)
{
	unsigned int i, j = 0;
	uint16_t parts[BITLK_RECOVERY_PARTS] = {0};
	char part_str[BITLK_RECOVERY_PART_LEN + 1] = {0};
	long part_num = 0;

	/* check the passphrase it should be:
	    - 55 characters
	    - 8 groups of 6 divided by '-'
	    - each part is a number dividable by 11
	*/
	if (passwordLen != BITLK_RECOVERY_KEY_LEN) {
		if (passwordLen == BITLK_RECOVERY_KEY_LEN + 1 && password[passwordLen - 1] == '\n') {
			/* looks like a recovery key with an extra newline, possibly from a key file */
			passwordLen--;
			log_dbg(cd, "Possible extra EOL stripped from the recovery key.");
		} else
			return 0;
	}

	for (i = BITLK_RECOVERY_PART_LEN; i < passwordLen; i += BITLK_RECOVERY_PART_LEN + 1) {
		if (password[i] != '-')
			return 0;
	}

	for (i = 0, j = 0; i < passwordLen; i += BITLK_RECOVERY_PART_LEN + 1, j++) {
		strncpy(part_str, password + i, BITLK_RECOVERY_PART_LEN);

		errno = 0;
		part_num = strtol(part_str, NULL, 10);
		if ((errno == ERANGE && (part_num == LONG_MAX || part_num == LONG_MIN)) ||
		    (errno != 0 && part_num == 0))
			return -errno;

		if (part_num % 11 != 0)
			return 0;
		parts[j] = cpu_to_le16(part_num / 11);
	}

	*rc_key = crypt_alloc_volume_key(16, (const char*) parts);
	if (*rc_key == NULL)
		return -ENOMEM;

	return 0;
}

static int parse_external_key_entry(struct crypt_device *cd,
				    const char *data,
				    int start,
				    int end,
				    struct volume_key **vk,
				    const struct bitlk_metadata *params)
{
	uint16_t key_entry_size = 0;
	uint16_t key_entry_type = 0;
	uint16_t key_entry_value = 0;
	size_t key_size = 0;
	const char *key = NULL;
	struct bitlk_guid guid;
	char guid_buf[UUID_STR_LEN] = {0};

	while ((end - start) >= (ssize_t)(sizeof(key_entry_size) + sizeof(key_entry_type) + sizeof(key_entry_value))) {
		/* size of this entry */
		memcpy(&key_entry_size, data + start, sizeof(key_entry_size));
		key_entry_size = le16_to_cpu(key_entry_size);
		if (key_entry_size == 0)
			break;

		if (key_entry_size > (end - start))
			return -EINVAL;

		/* type and value of this entry */
		memcpy(&key_entry_type, data + start + sizeof(key_entry_size), sizeof(key_entry_type));
		memcpy(&key_entry_value,
		       data + start + sizeof(key_entry_size) + sizeof(key_entry_type),
		       sizeof(key_entry_value));
		key_entry_type = le16_to_cpu(key_entry_type);
		key_entry_value = le16_to_cpu(key_entry_value);

		if (key_entry_type != BITLK_ENTRY_TYPE_PROPERTY && key_entry_type != BITLK_ENTRY_TYPE_VOLUME_GUID) {
			log_err(cd, _("Unexpected metadata entry type '%u' found when parsing external key."), key_entry_type);
			return -EINVAL;
		}

		if (key_entry_value == BITLK_ENTRY_VALUE_KEY) {
			if (key_entry_size < (BITLK_ENTRY_HEADER_LEN + 4))
				return -EINVAL;
			key_size = key_entry_size - (BITLK_ENTRY_HEADER_LEN + 4);
			key = (const char *) data + start + BITLK_ENTRY_HEADER_LEN + 4;
			*vk = crypt_alloc_volume_key(key_size, key);
			if (*vk == NULL)
				return -ENOMEM;
			return 0;
		/* optional "ExternalKey" string, we can safely ignore it */
		} else if (key_entry_value == BITLK_ENTRY_VALUE_STRING)
			;
		/* GUID of the BitLocker device we are trying to open with this key */
		else if (key_entry_value == BITLK_ENTRY_VALUE_GUID) {
			if ((end - start) < (ssize_t)(BITLK_ENTRY_HEADER_LEN + sizeof(struct bitlk_guid)))
				return -EINVAL;
			memcpy(&guid, data + start + BITLK_ENTRY_HEADER_LEN, sizeof(struct bitlk_guid));
			guid_to_string(&guid, guid_buf);
			if (strcmp(guid_buf, params->guid) != 0) {
				log_err(cd, _("BEK file GUID '%s' does not match GUID of the volume."), guid_buf);
				return -EINVAL;
			}
		} else {
			log_err(cd, _("Unexpected metadata entry value '%u' found when parsing external key."), key_entry_value);
			return -EINVAL;
		}

		start += key_entry_size;
	}

	/* if we got here we failed to parse the metadata */
	return -EINVAL;
}

/* check if given passphrase can be a startup key (has right format) and convert it */
static int get_startup_key(struct crypt_device *cd,
			   const char *password,
			   size_t passwordLen,
			   const struct bitlk_vmk *vmk,
			   struct volume_key **su_key,
			   const struct bitlk_metadata *params)
{
	struct bitlk_bek_header bek_header = {0};
	char guid_buf[UUID_STR_LEN] = {0};

	uint16_t key_entry_size = 0;
	uint16_t key_entry_type = 0;
	uint16_t key_entry_value = 0;

	if (passwordLen < (BITLK_BEK_FILE_HEADER_LEN + sizeof(key_entry_size) + sizeof(key_entry_type) + sizeof(key_entry_value)))
		return -EPERM;

	memcpy(&bek_header, password, BITLK_BEK_FILE_HEADER_LEN);

	/* metadata should contain GUID of the VMK this startup key is used for */
	guid_to_string(&bek_header.guid, guid_buf);
	if (strcmp(guid_buf, vmk->guid) == 0)
		log_dbg(cd, "Found matching startup key for VMK %s", vmk->guid);
	else
		return -EPERM;

	if (le32_to_cpu(bek_header.metadata_version) != 1) {
		log_err(cd, _("Unsupported BEK metadata version %" PRIu32), le32_to_cpu(bek_header.metadata_version));
		return -ENOTSUP;
	}

	if (le32_to_cpu(bek_header.metadata_size) != passwordLen) {
		log_err(cd, _("Unexpected BEK metadata size %" PRIu32 " does not match BEK file length"),
			le32_to_cpu(bek_header.metadata_size));
		return -EINVAL;
	}

	/* we are expecting exactly one metadata entry starting immediately after the header */
	memcpy(&key_entry_size, password + BITLK_BEK_FILE_HEADER_LEN, sizeof(key_entry_size));
	key_entry_size = le16_to_cpu(key_entry_size);
	if (key_entry_size < BITLK_ENTRY_HEADER_LEN) {
		log_dbg(cd, "Unexpected metadata entry size %" PRIu16 " when parsing BEK file", key_entry_size);
		return -EINVAL;
	}

	/* type and value of this entry */
	memcpy(&key_entry_type, password + BITLK_BEK_FILE_HEADER_LEN + sizeof(key_entry_size), sizeof(key_entry_type));
	memcpy(&key_entry_value,
	       password + BITLK_BEK_FILE_HEADER_LEN + sizeof(key_entry_size) + sizeof(key_entry_type),
	       sizeof(key_entry_value));
	key_entry_type = le16_to_cpu(key_entry_type);
	key_entry_value = le16_to_cpu(key_entry_value);

	if (key_entry_type == BITLK_ENTRY_TYPE_STARTUP_KEY && key_entry_value == BITLK_ENTRY_VALUE_EXTERNAL_KEY) {
		return parse_external_key_entry(cd, password,
						BITLK_BEK_FILE_HEADER_LEN + BITLK_ENTRY_HEADER_LEN + BITLK_STARTUP_KEY_HEADER_LEN,
						passwordLen, su_key, params);
	} else {
		log_err(cd, _("Unexpected metadata entry found when parsing startup key."));
		log_dbg(cd, "Entry type: %u, entry value: %u", key_entry_type, key_entry_value);
		return -EINVAL;
	}
}

static int bitlk_kdf(const char *password,
		     size_t passwordLen,
		     bool recovery,
		     const uint8_t *salt,
		     struct volume_key **vk)
{
	struct bitlk_kdf_data kdf = {};
	struct crypt_hash *hd = NULL;
	int len = 0;
	char16_t *utf16Password = NULL;
	int i = 0;
	int r = 0;

	memcpy(kdf.salt, salt, 16);

	r = crypt_hash_init(&hd, BITLK_KDF_HASH);
	if (r < 0)
		return r;
	len = crypt_hash_size(BITLK_KDF_HASH);
	if (len < 0) {
		crypt_hash_destroy(hd);
		return len;
	}

	if (!recovery) {
		/* passphrase: convert to UTF-16 first, then sha256(sha256(pw)) */
		utf16Password = crypt_safe_alloc(sizeof(char16_t) * (passwordLen + 1));
		if (!utf16Password) {
			r = -ENOMEM;
			goto out;
		}
		r = crypt_utf8_to_utf16(&utf16Password, CONST_CAST(char*)password, passwordLen);
		if (r < 0)
			goto out;

		crypt_hash_write(hd, (char*)utf16Password, passwordLen * 2);
		r = crypt_hash_final(hd, kdf.initial_sha256, len);
		if (r < 0)
			goto out;

		crypt_hash_write(hd, kdf.initial_sha256, len);
		r = crypt_hash_final(hd, kdf.initial_sha256, len);
		if (r < 0)
			goto out;
	} else {
		/* recovery passphrase: already converted in #get_recovery_key, now just sha256(rpw) */
		crypt_hash_write(hd, password, passwordLen);
		r = crypt_hash_final(hd, kdf.initial_sha256, len);
		if (r < 0)
			goto out;
	}

	for (i = 0; i < BITLK_KDF_ITERATION_COUNT; i++) {
		crypt_hash_write(hd, (const char*) &kdf, sizeof(kdf));
		r = crypt_hash_final(hd, kdf.last_sha256, len);
		if (r < 0)
			goto out;
		kdf.count = cpu_to_le64(le64_to_cpu(kdf.count) + 1);
	}

	*vk = crypt_alloc_volume_key(len, kdf.last_sha256);

out:
	crypt_safe_free(utf16Password);
	if (hd)
		crypt_hash_destroy(hd);
	return r;
}

static int decrypt_key(struct crypt_device *cd,
		       struct volume_key **vk,
		       struct volume_key *enc_key,
		       struct volume_key *key,
		       const uint8_t *tag, size_t tag_size,
		       const uint8_t *iv, size_t iv_size,
		       bool is_fvek)
{
	char *outbuf;
	int r;
	uint16_t key_size = 0;

	outbuf = crypt_safe_alloc(enc_key->keylength);
	if (!outbuf)
		return -ENOMEM;

	r = crypt_bitlk_decrypt_key(key->key, key->keylength, enc_key->key, outbuf, enc_key->keylength,
				(const char*)iv, iv_size, (const char*)tag, tag_size);
	if (r < 0) {
		if (r == -ENOTSUP)
			log_err(cd, _("This operation is not supported."));
		goto out;
	}

	/* key_data has it's size as part of the metadata */
	memcpy(&key_size, outbuf, 2);
	key_size = le16_to_cpu(key_size);
	if (enc_key->keylength != key_size) {
		log_err(cd, _("Unexpected key data size."));
		log_dbg(cd, "Expected key data size: %zu, got %" PRIu16 "", enc_key->keylength, key_size);

		r = -EINVAL;
		goto out;
	}

	if (is_fvek && strcmp(crypt_get_cipher_mode(cd), "cbc-elephant") == 0 &&
		crypt_get_volume_key_size(cd) == 32) {
		/* 128bit AES-CBC with Elephant -- key size is 256 bit (2 keys) but key data is 512 bits,
		   data: 16B CBC key, 16B empty, 16B elephant key, 16B empty */
		memcpy(outbuf + 16 + BITLK_OPEN_KEY_METADATA_LEN,
			outbuf + 2 * 16 + BITLK_OPEN_KEY_METADATA_LEN, 16);
		key_size = 32 + BITLK_OPEN_KEY_METADATA_LEN;
	}


	*vk = crypt_alloc_volume_key(key_size - BITLK_OPEN_KEY_METADATA_LEN,
					(const char *)(outbuf + BITLK_OPEN_KEY_METADATA_LEN));
	r = *vk ? 0 : -ENOMEM;
out:
	crypt_safe_free(outbuf);
	return r;
}

int BITLK_get_volume_key(struct crypt_device *cd,
			 const char *password,
			 size_t passwordLen,
			 const struct bitlk_metadata *params,
			 struct volume_key **open_fvek_key)
{
	int r = 0;
	struct volume_key *open_vmk_key = NULL;
	struct volume_key *vmk_dec_key = NULL;
	struct volume_key *recovery_key = NULL;
	const struct bitlk_vmk *next_vmk = NULL;

	next_vmk = params->vmks;
	while (next_vmk) {
		if (next_vmk->protection == BITLK_PROTECTION_PASSPHRASE) {
			r = bitlk_kdf(password, passwordLen, false, next_vmk->salt, &vmk_dec_key);
			if (r) {
				/* something wrong happened, but we still want to check other key slots */
				next_vmk = next_vmk->next;
				continue;
			}
		} else if (next_vmk->protection == BITLK_PROTECTION_RECOVERY_PASSPHRASE) {
			r = get_recovery_key(cd, password, passwordLen, &recovery_key);
			if (r) {
				/* something wrong happened, but we still want to check other key slots */
				next_vmk = next_vmk->next;
				continue;
			}
			if (recovery_key == NULL) {
				/* r = 0 but no key -> given passphrase is not a recovery passphrase */
				r = -EPERM;
				next_vmk = next_vmk->next;
				continue;
			}
			log_dbg(cd, "Trying to use given password as a recovery key.");
			r = bitlk_kdf(recovery_key->key, recovery_key->keylength,
				      true, next_vmk->salt, &vmk_dec_key);
			crypt_free_volume_key(recovery_key);
			if (r)
				return r;
		} else if (next_vmk->protection == BITLK_PROTECTION_STARTUP_KEY) {
			r = get_startup_key(cd, password, passwordLen, next_vmk, &vmk_dec_key, params);
			if (r) {
				next_vmk = next_vmk->next;
				continue;
			}
			log_dbg(cd, "Trying to use external key found in provided password.");
		} else {
			/* only passphrase, recovery passphrase and startup key VMKs supported right now */
			log_dbg(cd, "Skipping %s", get_vmk_protection_string(next_vmk->protection));
			next_vmk = next_vmk->next;
			if (r == 0)
				/* we need to set error code in case we have only unsupported VMKs */
				r = -ENOTSUP;
			continue;
		}

		log_dbg(cd, "Trying to decrypt %s.", get_vmk_protection_string(next_vmk->protection));
		r = decrypt_key(cd, &open_vmk_key, next_vmk->vk, vmk_dec_key,
				next_vmk->mac_tag, BITLK_VMK_MAC_TAG_SIZE,
				next_vmk->nonce, BITLK_NONCE_SIZE, false);
		if (r < 0) {
			log_dbg(cd, "Failed to decrypt VMK using provided passphrase.");
			crypt_free_volume_key(vmk_dec_key);
			if (r == -ENOTSUP)
				return r;
			next_vmk = next_vmk->next;
			continue;
		}
		crypt_free_volume_key(vmk_dec_key);

		r = decrypt_key(cd, open_fvek_key, params->fvek->vk, open_vmk_key,
				params->fvek->mac_tag, BITLK_VMK_MAC_TAG_SIZE,
				params->fvek->nonce, BITLK_NONCE_SIZE, true);
		if (r < 0) {
			log_dbg(cd, "Failed to decrypt FVEK using VMK.");
			crypt_free_volume_key(open_vmk_key);
			if (r == -ENOTSUP)
				return r;
		} else {
			crypt_free_volume_key(open_vmk_key);
			break;
		}

		next_vmk = next_vmk->next;
	}

	if (r) {
		log_dbg(cd, "No more VMKs to try.");
		return r;
	}

	return 0;
}

static int _activate_check(struct crypt_device *cd,
		           const struct bitlk_metadata *params)
{
	const struct bitlk_vmk *next_vmk = NULL;

	if (!params->state) {
		log_err(cd, _("This BITLK device is in an unsupported state and cannot be activated."));
		return -ENOTSUP;
	}

	if (params->type != BITLK_ENCRYPTION_TYPE_NORMAL) {
		log_err(cd, _("BITLK devices with type '%s' cannot be activated."), get_bitlk_type_string(params->type));
		return -ENOTSUP;
	}

	next_vmk = params->vmks;
	while (next_vmk) {
		if (next_vmk->protection == BITLK_PROTECTION_CLEAR_KEY) {
			log_err(cd, _("Activation of partially decrypted BITLK device is not supported."));
			return -ENOTSUP;
		}
		next_vmk = next_vmk->next;
	}

	return 0;
}

static int _activate(struct crypt_device *cd,
		     const char *name,
		     struct volume_key *open_fvek_key,
		     const struct bitlk_metadata *params,
		     uint32_t flags)
{
	int r = 0;
	int i = 0;
	int j = 0;
	int min = 0;
	int num_segments = 0;
	struct crypt_dm_active_device dmd = {
		.flags = flags,
	};
	struct dm_target *next_segment = NULL;
	struct segment segments[MAX_BITLK_SEGMENTS] = {};
	struct segment temp;
	uint64_t next_start = 0;
	uint64_t next_end = 0;
	uint64_t last_segment = 0;
	uint32_t dmt_flags = 0;

	r = _activate_check(cd, params);
	if (r)
		return r;

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_EXCL,
				0, &dmd.size, &dmd.flags);
	if (r)
		return r;

	if (dmd.size * SECTOR_SIZE != params->volume_size)
		log_std(cd, _("WARNING: BitLocker volume size %" PRIu64 " does not match the underlying device size %" PRIu64 ""),
			params->volume_size,
			dmd.size * SECTOR_SIZE);

	/* there will be always 4 dm-zero segments: 3x metadata, 1x FS header */
	for (i = 0; i < 3; i++) {
		segments[num_segments].offset = params->metadata_offset[i] / SECTOR_SIZE;
		segments[num_segments].length = BITLK_FVE_METADATA_SIZE / SECTOR_SIZE;
		segments[num_segments].iv_offset = 0;
		segments[num_segments].type = BITLK_SEGTYPE_ZERO;
		num_segments++;
	}
	segments[num_segments].offset = params->volume_header_offset / SECTOR_SIZE;
	segments[num_segments].length = params->volume_header_size / SECTOR_SIZE;
	segments[num_segments].iv_offset = 0;
	segments[num_segments].type = BITLK_SEGTYPE_ZERO;
	num_segments++;

	/* filesystem header (moved from the special location) */
	segments[num_segments].offset = 0;
	segments[num_segments].length = params->volume_header_size / SECTOR_SIZE;
	segments[num_segments].iv_offset = params->volume_header_offset / SECTOR_SIZE;
	segments[num_segments].type = BITLK_SEGTYPE_CRYPT;
	num_segments++;

	/* now fill gaps between the dm-zero segments with dm-crypt */
	last_segment = params->volume_header_size / SECTOR_SIZE;
	while (true) {
		next_start = dmd.size;
		next_end = dmd.size;

		/* start of the next segment: end of the first existing segment after the last added */
		for (i = 0; i < num_segments; i++)
			if (segments[i].offset + segments[i].length < next_start && segments[i].offset + segments[i].length >= last_segment)
				next_start = segments[i].offset + segments[i].length;

		/* end of the next segment: start of the next segment after start we found above */
		for (i = 0; i < num_segments; i++)
			if (segments[i].offset < next_end && segments[i].offset >= next_start)
				next_end = segments[i].offset;

		/* two zero segments next to each other, just bump the last_segment
		   so the algorithm moves */
		if (next_end - next_start == 0) {
			last_segment = next_end + 1;
			continue;
		}

		segments[num_segments].offset = next_start;
		segments[num_segments].length = next_end - next_start;
		segments[num_segments].iv_offset = next_start;
		segments[num_segments].type = BITLK_SEGTYPE_CRYPT;
		last_segment = next_end;
		num_segments++;

		if (next_end == dmd.size)
			break;

		if (num_segments == 10) {
			log_dbg(cd, "Failed to calculate number of dm-crypt segments for open.");
			r = -EINVAL;
			goto out;
		}
	}

	/* device mapper needs the segment sorted */
	for (i = 0; i < num_segments - 1; i++) {
		min = i;
		for (j = i + 1; j < num_segments; j++)
			if (segments[j].offset < segments[min].offset)
				min = j;

		if (min != i) {
			temp.offset = segments[min].offset;
			temp.length = segments[min].length;
			temp.iv_offset = segments[min].iv_offset;
			temp.type = segments[min].type;

			segments[min].offset = segments[i].offset;
			segments[min].length = segments[i].length;
			segments[min].iv_offset = segments[i].iv_offset;
			segments[min].type = segments[i].type;

			segments[i].offset = temp.offset;
			segments[i].length = temp.length;
			segments[i].iv_offset = temp.iv_offset;
			segments[i].type = temp.type;
		}
	}

	if (params->sector_size != SECTOR_SIZE)
		dmd.flags |= CRYPT_ACTIVATE_IV_LARGE_SECTORS;

	r = dm_targets_allocate(&dmd.segment, num_segments);
	if (r)
		goto out;
	next_segment = &dmd.segment;

	for (i = 0; i < num_segments; i++) {
		if (segments[i].type == BITLK_SEGTYPE_ZERO)
			r = dm_zero_target_set(next_segment,
					       segments[i].offset,
					       segments[i].length);
		else if (segments[i].type == BITLK_SEGTYPE_CRYPT)
			r = dm_crypt_target_set(next_segment,
						segments[i].offset,
						segments[i].length,
						crypt_data_device(cd),
						open_fvek_key,
						crypt_get_cipher_spec(cd),
						segments[i].iv_offset,
						segments[i].iv_offset,
						NULL, 0,
						params->sector_size);
		if (r)
			goto out;

		next_segment = next_segment->next;
	}

	log_dbg(cd, "Trying to activate BITLK on device %s%s%s.",
		device_path(crypt_data_device(cd)), name ? " with name " :"", name ?: "");

	r = dm_create_device(cd, name, CRYPT_BITLK, &dmd);
	if (r < 0) {
		dm_flags(cd, DM_CRYPT, &dmt_flags);
		if (!strcmp(params->cipher_mode, "cbc-eboiv") && !(dmt_flags & DM_BITLK_EBOIV_SUPPORTED)) {
			log_err(cd, _("Cannot activate device, kernel dm-crypt is missing support for BITLK IV."));
			r = -ENOTSUP;
		}
		if (!strcmp(params->cipher_mode, "cbc-elephant") && !(dmt_flags & DM_BITLK_ELEPHANT_SUPPORTED)) {
			log_err(cd, _("Cannot activate device, kernel dm-crypt is missing support for BITLK Elephant diffuser."));
			r = -ENOTSUP;
		}
		if ((dmd.flags & CRYPT_ACTIVATE_IV_LARGE_SECTORS) && !(dmt_flags & DM_SECTOR_SIZE_SUPPORTED)) {
			log_err(cd, _("Cannot activate device, kernel dm-crypt is missing support for large sector size."));
			r = -ENOTSUP;
		}
		if (dm_flags(cd, DM_ZERO, &dmt_flags) < 0) {
			log_err(cd, _("Cannot activate device, kernel dm-zero module is missing."));
			r = -ENOTSUP;
		}
	}
out:
	dm_targets_free(cd, &dmd);
	return r;
}

int BITLK_activate_by_passphrase(struct crypt_device *cd,
				 const char *name,
				 const char *password,
				 size_t passwordLen,
				 const struct bitlk_metadata *params,
				 uint32_t flags)
{
	int r = 0;
	struct volume_key *open_fvek_key = NULL;

	r = _activate_check(cd, params);
	if (r)
		return r;

	r = BITLK_get_volume_key(cd, password, passwordLen, params, &open_fvek_key);
	if (r < 0)
		goto out;

	/* Password verify only */
	if (!name)
		goto out;

	r = _activate(cd, name, open_fvek_key, params, flags);
out:
	crypt_free_volume_key(open_fvek_key);
	return r;
}

int BITLK_activate_by_volume_key(struct crypt_device *cd,
				 const char *name,
				 const char *volume_key,
				 size_t volume_key_size,
				 const struct bitlk_metadata *params,
				 uint32_t flags)
{
	int r = 0;
	struct volume_key *open_fvek_key = NULL;

	r = _activate_check(cd, params);
	if (r)
		return r;

	open_fvek_key = crypt_alloc_volume_key(volume_key_size, volume_key);
	if (!open_fvek_key)
		return -ENOMEM;

	r = _activate(cd, name, open_fvek_key, params, flags);

	crypt_free_volume_key(open_fvek_key);
	return r;
}
