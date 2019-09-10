/*
 * BITLK (BitLocker-compatible) volume handling
 *
 * Copyright (C) 2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2019 Milan Broz
 * Copyright (C) 2019 Vojtech Trefny
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <uuid/uuid.h>
#include <time.h>
#include <iconv.h>

#include "libcryptsetup.h"
#include "bitlk.h"
#include "internal.h"
#include "bitops.h"

#define BITLK_BOOTCODE_V1 "\xeb\x52\x90"
#define BITLK_BOOTCODE_V2 "\xeb\x58\x90"
#define BITLK_SIGNATURE "-FVE-FS-"
#define BITLK_SIGNATURE_TOGO "MSWIN4.1"
#define BITLK_HEADER_METADATA_OFFSET 160
#define BITLK_HEADER_METADATA_OFFSET_TOGO 424

#define BITLK_FVE_METADATA_HEADER_LEN 64 + 48
#define BITLK_FVE_METADATA_SIZE 64 * 1024
#define BITLK_ENTRY_HEADER_LEN 8
#define BITLK_VMK_HEADER_LEN 28

/* January 1, 1970 as MS file time */
#define EPOCH_AS_FILETIME 116444736000000000
#define HUNDREDS_OF_NANOSECONDS 10000000

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

struct bitlk_signature {
	uint8_t boot_code[3];
	uint8_t signature[8];
} __attribute__ ((packed));

struct bitlk_superblock {
	struct bitlk_guid guid;
	uint64_t fve_offset[3];
} __attribute__ ((packed));

struct bitlk_fve_metadata {
	uint8_t signature[8];
	uint16_t fve_size;
	uint16_t fve_version;
	uint32_t unknown;
	uint64_t volume_size;
	uint32_t unknown2;
	uint32_t volume_header_size;
	uint64_t fve_offset[3];
	uint64_t volume_header_offset;
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
	default:
		return "VMK with unknown protection";
	}
}

/* TODO -- move to some utils file */
static void hexprint(struct crypt_device *cd, const char *d, int n, const char *sep)
{
	int i;
	for(i = 0; i < n; i++)
		log_std(cd, "%02hhx%s", (const char)d[i], sep);
}

static uint64_t filetime_to_unixtime(uint64_t time)
{
	return (time - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS;
}

static int convert_to_utf8(struct crypt_device *cd, uint8_t *input, size_t inlen, char **out)
{
	char *outbuf = NULL;
	iconv_t ic;
	size_t ic_inlen = inlen;
	size_t ic_outlen = inlen;
	char *ic_outbuf = NULL;
	size_t r = 0;

	outbuf = malloc(inlen);
	if (outbuf == NULL)
		return -ENOMEM;

	memset(outbuf, 0, inlen);
	ic_outbuf = outbuf;

	ic = iconv_open("UTF-8", "UTF-16");
	r = iconv(ic, (char **) &input, &ic_inlen, &ic_outbuf, &ic_outlen);
	iconv_close(ic);

	if (r == 0)
		*out = strdup(outbuf);
	else {
		*out = NULL;
		log_dbg(cd, "Failed to covert volume description: %s", strerror(errno));
		r = 0;
	}

	free(outbuf);
	return r;
}

static int parse_vmk_entry(struct crypt_device *cd, uint8_t *data, int start, int end, struct bitlk_vmk **vmk)
{
	uint16_t key_entry_size = 0;
	uint16_t key_entry_type = 0;
	uint16_t key_entry_value = 0;
	size_t key_size = 0;
	const char *key = NULL;
	struct volume_key *vk = NULL;

	while (end - start > 2) {
		/* size of this entry */
		memcpy(&key_entry_size, data + start, sizeof(key_entry_size));
		if (key_entry_size == 0)
			break;

		/* type and value of this entry */
		memcpy(&key_entry_type, data + start + sizeof(key_entry_size), sizeof(key_entry_type));
		memcpy(&key_entry_value,
		       data + start + sizeof(key_entry_size) + sizeof(key_entry_type),
		       sizeof(key_entry_value));

		if (key_entry_type != BITLK_ENTRY_TYPE_PROPERTY) {
			log_err(cd, _("Unexpected metadata entry found when parsing VMK."));
			return -EINVAL;
		}

		/* stretch key with salt, skip 4 B (encryption method of the stretch key) */
		if (key_entry_value == BITLK_ENTRY_VALUE_STRETCH_KEY)
			memcpy((*vmk)->salt,
			       data + start + BITLK_ENTRY_HEADER_LEN + 4,
			       sizeof((*vmk)->salt));
		/* AES-CCM encrypted key */
		else if (key_entry_value == BITLK_ENTRY_VALUE_ENCRYPTED_KEY) {
			/* nonce */
			memcpy((*vmk)->nonce,
			       data + start + BITLK_ENTRY_HEADER_LEN,
			       sizeof((*vmk)->nonce));
			/* MAC tag */
			memcpy((*vmk)->mac_tag,
			       data + start + BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE,
			       sizeof((*vmk)->mac_tag));
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
		} else {
			log_err(cd, _("Unexpected metadata entry found when parsing VMK."));
			return -EINVAL;
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
}

void BITLK_bitlk_vmk_free(struct bitlk_vmk *vmk)
{
	struct bitlk_vmk *vmk_next = NULL;

	while (vmk) {
		if (vmk->guid)
			free(vmk->guid);
		crypt_free_volume_key(vmk->vk);
		vmk_next = vmk->next;
		free(vmk);
		vmk = vmk_next;
	}
}

void BITLK_bitlk_metadata_free(struct bitlk_metadata *metadata)
{
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
	struct bitlk_signature sig = {0};
	struct bitlk_superblock sb = {0};
	struct bitlk_fve_metadata fve = {0};
	struct bitlk_entry_vmk entry_vmk = {0};
	uint8_t *fve_entries = NULL;
	int fve_offset = 0;
	char guid_buf[UUID_STR_LEN] = {0};
	uint16_t entry_size = 0;
	uint16_t entry_type = 0;
	int r = 0;
	int start = 0;
	int end = 0;
	size_t key_size = 0;
	const char *key = NULL;

	struct bitlk_vmk *vmk = NULL;
	struct bitlk_vmk *vmk_p = params->vmks;

	devfd = device_open(cd, crypt_data_device(cd), O_RDONLY);
	if (devfd < 0) {
		r = -EINVAL;
		goto out;
	}

	/* read and check the BitLocker signature */
	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
		device_alignment(device), &sig, sizeof(sig), 0) != sizeof(sig)) {
		log_err(cd, _("Failed to read bitlocker signature from %s."), device_path(device));
		r = -EINVAL;
		goto out;
	}

	if (memcmp(sig.boot_code, BITLK_BOOTCODE_V1, sizeof(sig.boot_code)) == 0) {
		log_err(cd, _("BitLocker version from Windows Vista is currently not supported"));
		r = -ENOTSUP;
		goto out;
	} else if (memcmp(sig.boot_code, BITLK_BOOTCODE_V2, sizeof(sig.boot_code)) == 0)
		;
	else {
		log_std(cd, _("Invalid or unknown boot signature for a BitLocker device."));
		r = -EINVAL;
		goto out;
	}

	if (memcmp(sig.signature, BITLK_SIGNATURE, sizeof(sig.signature)) == 0) {
		params->togo = false;
		fve_offset = BITLK_HEADER_METADATA_OFFSET;
	} else if (memcmp(sig.signature, BITLK_SIGNATURE_TOGO, sizeof(sig.signature)) == 0) {
		params->togo = true;
		fve_offset = BITLK_HEADER_METADATA_OFFSET_TOGO;
	} else {
		log_std(cd, _("Invalid or unknown signature for a BitLocker device."));
		r = -EINVAL;
		goto out;
	}

	/* read GUID and FVE metadata offsets */
	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
		device_alignment(device), &sb, sizeof(sb), fve_offset) != sizeof(sb)) {
		log_err(cd, _("Failed to read BitLocker header from %s."), device_path(device));
		r = -EINVAL;
		goto out;
	}

	log_dbg(cd, "Reading BitLocker FVE metadata of size %zu on device %s, offset %" PRIu64 ".",
		sizeof(fve), device_path(device), sb.fve_offset[0]);

	/* read FVE metadata from the first metadata area */
	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
		device_alignment(device), &fve, sizeof(fve), sb.fve_offset[0]) != sizeof(fve) ||
		memcmp(fve.signature, BITLK_SIGNATURE, sizeof(fve.signature)) ||
		fve.fve_version != 2) {
		log_err(cd, _("Failed to read BitLocker FVE metadata from %s."), device_path(device));
		r = -EINVAL;
		goto out;
	}

	params->metadata_version = le32_to_cpu(fve.fve_version);
	for (int i = 0; i < 3; i++)
		params->metadata_offset[i] = le64_to_cpu(sb.fve_offset[i]);

	switch (fve.encryption) {
	/* AES-CBC with Elephant difuser */
	case 0x8000:
		params->key_size = 128;
		params->cipher = "aes";
		params->cipher_mode = "cbc-elephant";
		break;
	case 0x8001:
		params->key_size = 256;
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
		params->key_size = 128;
		params->cipher = "aes";
		params->cipher_mode = "xts-plain64";
		break;
	case 0x8005:
		params->key_size = 256;
		params->cipher = "aes";
		params->cipher_mode = "xts-plain64";
		break;
	default:
		log_err (cd, _("Unknown or unsupported encryption"));
		params->key_size = 0;
		params->cipher = NULL;
		params->cipher_mode = NULL;
		r = -ENOTSUP;
		goto out;
	};

	/* BitLocker device GUID */
	guid_to_string(&fve.guid, guid_buf);
	params->guid = strdup(guid_buf);
	if (!params->guid) {
		r = -ENOMEM;
		goto out;
	}

	params->creation_time = filetime_to_unixtime(le64_to_cpu(fve.creation_time));

	/* read and parse all FVE metadata entries */
	fve_entries = malloc(fve.metadata_size - fve.fve_size);
	if (!fve_entries) {
		r = -ENOMEM;
		goto out;
	}
	memset(fve_entries, 0, (fve.metadata_size - fve.fve_size));

	log_dbg(cd, "Reading BitLocker FVE metadata entries of size %" PRIu32 " on device %s, offset %" PRIu64 ".",
		fve.metadata_size - fve.fve_size, device_path(device),
		sb.fve_offset[0] + BITLK_FVE_METADATA_HEADER_LEN);

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
		device_alignment(device), fve_entries, fve.metadata_size - fve.fve_size,
		sb.fve_offset[0] + BITLK_FVE_METADATA_HEADER_LEN) != fve.metadata_size - fve.fve_size) {
		log_err(cd, _("Failed to read BitLocker metadata entries from %s."), device_path(device));
		r = -EINVAL;
		goto out;
	}

	end = fve.metadata_size - fve.fve_size;
	while (end - start > 2) {
		/* size of this entry */
		memcpy(&entry_size, fve_entries + start, sizeof(entry_size));
		if (entry_size == 0)
			break;

		/* type of this entry */
		memcpy(&entry_type, fve_entries + start + sizeof(entry_size), sizeof(entry_type));

		/* VMK */
		if (entry_type == BITLK_ENTRY_TYPE_VMK) {
			/* skip first four variables in the entry (entry size, type, value and version) */
			memcpy(&entry_vmk,
			       fve_entries + start + BITLK_ENTRY_HEADER_LEN,
			       sizeof(entry_vmk));

			vmk = malloc(sizeof(struct bitlk_vmk));
			memset(vmk, 0, sizeof(struct bitlk_vmk));

			guid_to_string(&entry_vmk.guid, guid_buf);
			vmk->guid = strdup (guid_buf);

			vmk->protection = get_vmk_protection(entry_vmk.protection);

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
		} else if (entry_type == BITLK_ENTRY_TYPE_FVEK) {
			params->fvek = malloc(sizeof(struct bitlk_fvek));
			memcpy(params->fvek->nonce,
			       fve_entries + start + BITLK_ENTRY_HEADER_LEN,
			       sizeof(params->fvek->nonce));
			/* MAC tag */
			memcpy(params->fvek->mac_tag,
			       fve_entries + start + BITLK_ENTRY_HEADER_LEN + BITLK_NONCE_SIZE,
			       sizeof(params->fvek->mac_tag));
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
			memcpy(&entry_header,
			       fve_entries + start + BITLK_ENTRY_HEADER_LEN,
			       sizeof(entry_header));
			params->volume_header_offset = le64_to_cpu(entry_header.offset);
			params->volume_header_size = le64_to_cpu(entry_header.size);
		/* volume description (utf-16 string) */
		} else if (entry_type == BITLK_ENTRY_TYPE_DESCRIPTION) {
			r = convert_to_utf8(cd, fve_entries + start + BITLK_ENTRY_HEADER_LEN,
					    entry_size - BITLK_ENTRY_HEADER_LEN,
					    &(params->description));
			if (r < 0) {
				BITLK_bitlk_vmk_free(vmk);
				goto out;
			}
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
	int next_id = 0;
	int i = 0;

	log_std(cd, "Info for BITLK%s device %s.\n", params->togo ? " To Go" : "", device_path(device));
	log_std(cd, "Version:      \t%u\n", params->metadata_version);
	log_std(cd, "GUID:         \t%s\n", params->guid);
	log_std(cd, "Created:      \t%s", ctime((time_t *)&(params->creation_time)));
	log_std(cd, "Description:  \t%s\n", params->description);
	log_std(cd, "Cipher name:  \t%s\n", params->cipher);
	log_std(cd, "Cipher mode:  \t%s\n", params->cipher_mode);
	log_std(cd, "Cipher key:   \t%u bits\n", params->key_size);

	log_std(cd, "\n");

	log_std(cd, "Keyslots:\n");
	vmk_p = params->vmks;
	while (vmk_p) {
		log_std(cd, " %d: VMK\n", next_id);
		log_std(cd, "\tGUID:       \t%s\n", vmk_p->guid);
		log_std(cd, "\tProtection: \t%s\n", get_vmk_protection_string (vmk_p->protection));
		log_std(cd, "\tSalt:       \t");
		hexprint(cd, (const char *) vmk_p->salt, 16, "");

		vk_p = params->vmks->vk;
		while (vk_p) {
			log_std(cd, "\n");
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

int BITLK_activate(struct crypt_device *cd,
		   const char *name,
		   const char *password,
		   size_t passwordLen,
		   const struct bitlk_metadata *params,
		   uint32_t flags)
{
	int r;
	struct crypt_dm_active_device dmd = {
		.flags = flags,
	};

	/* FIXME: Password verify only */
	if (!name)
		return -EINVAL;

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_EXCL,
				crypt_get_data_offset(cd), &dmd.size, &dmd.flags);
	if (r)
		return r;

	/* FIXME: Example - two segments device */
	r = dm_targets_allocate(&dmd.segment, 2);
	if (r)
		goto out;

	/* First sector mapped to DM_LINEAR */
	r = dm_linear_target_set(&dmd.segment, 0, 1, crypt_data_device(cd), 0);
		if (r)
		goto out;

	/* The rest is mapped to DM_ZERO (for now) */
	r = dm_zero_target_set(dmd.segment.next, 1, dmd.size - 1);
	if (r)
		goto out;

	log_dbg(cd, "Trying to activate BITLK on device %s%s%s.",
		device_path(crypt_data_device(cd)), name ? "with name " :"", name ?: "");

	r = dm_create_device(cd, name, CRYPT_BITLK, &dmd);
out:
	dm_targets_free(cd, &dmd);
	return r;
}
