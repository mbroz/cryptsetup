/*
 * dm-verity volume handling
 *
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
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
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <uuid/uuid.h>

#include "libcryptsetup.h"
#include "verity.h"
#include "internal.h"

#define VERITY_SIGNATURE "verity\0\0"

/* https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity#verity-superblock-format */
struct verity_sb {
	uint8_t  signature[8];	/* "verity\0\0" */
	uint32_t version;	/* superblock version */
	uint32_t hash_type;	/* 0 - Chrome OS, 1 - normal */
	uint8_t  uuid[16];	/* UUID of hash device */
	uint8_t  algorithm[32];/* hash algorithm name */
	uint32_t data_block_size; /* data block in bytes */
	uint32_t hash_block_size; /* hash block in bytes */
	uint64_t data_blocks;	/* number of data blocks */
	uint16_t salt_size;	/* salt size */
	uint8_t  _pad1[6];
	uint8_t  salt[256];	/* salt */
	uint8_t  _pad2[168];
} __attribute__((packed));

/* Read verity superblock from disk */
int VERITY_read_sb(struct crypt_device *cd,
		   uint64_t sb_offset,
		   char **uuid_string,
		   struct crypt_params_verity *params)
{
	struct device *device = crypt_metadata_device(cd);
	struct verity_sb sb = {};
	ssize_t hdr_size = sizeof(struct verity_sb);
	int devfd, sb_version;

	log_dbg(cd, "Reading VERITY header of size %zu on device %s, offset %" PRIu64 ".",
		sizeof(struct verity_sb), device_path(device), sb_offset);

	if (params->flags & CRYPT_VERITY_NO_HEADER) {
		log_err(cd, _("Verity device %s does not use on-disk header."),
			device_path(device));
		return -EINVAL;
	}

	if (MISALIGNED_512(sb_offset)) {
		log_err(cd, _("Unsupported VERITY hash offset."));
		return -EINVAL;
	}

	devfd = device_open(cd, device, O_RDONLY);
	if (devfd < 0) {
		log_err(cd, _("Cannot open device %s."), device_path(device));
		return -EINVAL;
	}

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
				 device_alignment(device), &sb, hdr_size,
				 sb_offset) < hdr_size)
		return -EIO;

	if (memcmp(sb.signature, VERITY_SIGNATURE, sizeof(sb.signature))) {
		log_err(cd, _("Device %s is not a valid VERITY device."),
			device_path(device));
		return -EINVAL;
	}

	sb_version = le32_to_cpu(sb.version);
	if (sb_version != 1) {
		log_err(cd, _("Unsupported VERITY version %d."), sb_version);
		return -EINVAL;
	}
	params->hash_type = le32_to_cpu(sb.hash_type);
	if (params->hash_type > VERITY_MAX_HASH_TYPE) {
		log_err(cd, _("Unsupported VERITY hash type %d."), params->hash_type);
		return -EINVAL;
	}

	params->data_block_size = le32_to_cpu(sb.data_block_size);
	params->hash_block_size = le32_to_cpu(sb.hash_block_size);
	if (VERITY_BLOCK_SIZE_OK(params->data_block_size) ||
	    VERITY_BLOCK_SIZE_OK(params->hash_block_size)) {
		log_err(cd, _("Unsupported VERITY block size."));
		return -EINVAL;
	}
	params->data_size = le64_to_cpu(sb.data_blocks);

	params->hash_name = strndup((const char*)sb.algorithm, sizeof(sb.algorithm));
	if (!params->hash_name)
		return -ENOMEM;
	if (crypt_hash_size(params->hash_name) <= 0) {
		log_err(cd, _("Hash algorithm %s not supported."),
			params->hash_name);
		free(CONST_CAST(char*)params->hash_name);
		params->hash_name = NULL;
		return -EINVAL;
	}

	params->salt_size = le16_to_cpu(sb.salt_size);
	if (params->salt_size > sizeof(sb.salt)) {
		log_err(cd, _("VERITY header corrupted."));
		free(CONST_CAST(char*)params->hash_name);
		params->hash_name = NULL;
		return -EINVAL;
	}
	params->salt = malloc(params->salt_size);
	if (!params->salt) {
		free(CONST_CAST(char*)params->hash_name);
		params->hash_name = NULL;
		return -ENOMEM;
	}
	memcpy(CONST_CAST(char*)params->salt, sb.salt, params->salt_size);

	if ((*uuid_string = malloc(40)))
		uuid_unparse(sb.uuid, *uuid_string);

	params->hash_area_offset = sb_offset;
	return 0;
}

/* Write verity superblock to disk */
int VERITY_write_sb(struct crypt_device *cd,
		   uint64_t sb_offset,
		   const char *uuid_string,
		   struct crypt_params_verity *params)
{
	struct device *device = crypt_metadata_device(cd);
	struct verity_sb sb = {};
	ssize_t hdr_size = sizeof(struct verity_sb);
	char *algorithm;
	uuid_t uuid;
	int r, devfd;

	log_dbg(cd, "Updating VERITY header of size %zu on device %s, offset %" PRIu64 ".",
		sizeof(struct verity_sb), device_path(device), sb_offset);

	if (!uuid_string || uuid_parse(uuid_string, uuid) == -1) {
		log_err(cd, _("Wrong VERITY UUID format provided on device %s."),
			device_path(device));
		return -EINVAL;
	}

	if (params->flags & CRYPT_VERITY_NO_HEADER) {
		log_err(cd, _("Verity device %s does not use on-disk header."),
			device_path(device));
		return -EINVAL;
	}

	devfd = device_open(cd, device, O_RDWR);
	if (devfd < 0) {
		log_err(cd, _("Cannot open device %s."), device_path(device));
		return -EINVAL;
	}

	memcpy(&sb.signature, VERITY_SIGNATURE, sizeof(sb.signature));
	sb.version         = cpu_to_le32(1);
	sb.hash_type       = cpu_to_le32(params->hash_type);
	sb.data_block_size = cpu_to_le32(params->data_block_size);
	sb.hash_block_size = cpu_to_le32(params->hash_block_size);
	sb.salt_size       = cpu_to_le16(params->salt_size);
	sb.data_blocks     = cpu_to_le64(params->data_size);
	algorithm = (char *)sb.algorithm;
	algorithm[sizeof(sb.algorithm)-1] = '\0';
	strncpy(algorithm, params->hash_name, sizeof(sb.algorithm)-1);
	memcpy(sb.salt, params->salt, params->salt_size);
	memcpy(sb.uuid, uuid, sizeof(sb.uuid));

	r = write_lseek_blockwise(devfd, device_block_size(cd, device), device_alignment(device),
				  (char*)&sb, hdr_size, sb_offset) < hdr_size ? -EIO : 0;
	if (r)
		log_err(cd, _("Error during update of verity header on device %s."),
			device_path(device));

	device_sync(cd, device);

	return r;
}

/* Calculate hash offset in hash blocks */
uint64_t VERITY_hash_offset_block(struct crypt_params_verity *params)
{
	uint64_t hash_offset = params->hash_area_offset;

	if (params->flags & CRYPT_VERITY_NO_HEADER)
		return hash_offset / params->hash_block_size;

	hash_offset += sizeof(struct verity_sb);
	hash_offset += params->hash_block_size - 1;

	return hash_offset / params->hash_block_size;
}

int VERITY_UUID_generate(struct crypt_device *cd, char **uuid_string)
{
	uuid_t uuid;

	*uuid_string = malloc(40);
	if (!*uuid_string)
		return -ENOMEM;
	uuid_generate(uuid);
	uuid_unparse(uuid, *uuid_string);
	return 0;
}

/* Activate verity device in kernel device-mapper */
int VERITY_activate(struct crypt_device *cd,
		     const char *name,
		     const char *root_hash,
		     size_t root_hash_size,
		     const char *signature_description,
		     struct device *fec_device,
		     struct crypt_params_verity *verity_hdr,
		     uint32_t activation_flags)
{
	uint32_t dmv_flags;
	unsigned int fec_errors = 0;
	int r;
	struct crypt_dm_active_device dmd = {
		.size = verity_hdr->data_size * verity_hdr->data_block_size / 512,
		.flags = activation_flags,
		.uuid = crypt_get_uuid(cd),
	};

	log_dbg(cd, "Trying to activate VERITY device %s using hash %s.",
		name ?: "[none]", verity_hdr->hash_name);

	if (verity_hdr->flags & CRYPT_VERITY_CHECK_HASH) {
		if (signature_description) {
			log_err(cd, _("Root hash signature verification is not supported."));
			return -EINVAL;
		}

		log_dbg(cd, "Verification of data in userspace required.");
		r = VERITY_verify(cd, verity_hdr, root_hash, root_hash_size);

		if (r == -EPERM && fec_device) {
			log_dbg(cd, "Verification failed, trying to repair with FEC device.");
			r = VERITY_FEC_process(cd, verity_hdr, fec_device, 1, &fec_errors);
			if (r < 0)
				log_err(cd, _("Errors cannot be repaired with FEC device."));
			else if (fec_errors)
				log_err(cd, _("Found %u repairable errors with FEC device."),
					fec_errors);
		}

		if (r < 0)
			return r;
	}

	if (!name)
		return 0;

	r = device_block_adjust(cd, crypt_metadata_device(cd), DEV_OK,
				0, NULL, NULL);
	if (r)
		return r;

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_EXCL,
				0, &dmd.size, &dmd.flags);
	if (r)
		return r;

	if (fec_device) {
		r = device_block_adjust(cd, fec_device, DEV_OK,
					0, NULL, NULL);
		if (r)
			return r;
	}

	r = dm_verity_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd),
			crypt_metadata_device(cd), fec_device, root_hash,
			root_hash_size, signature_description,
			VERITY_hash_offset_block(verity_hdr),
			VERITY_hash_blocks(cd, verity_hdr), verity_hdr);

	if (r)
		return r;

	r = dm_create_device(cd, name, CRYPT_VERITY, &dmd);
	if (r < 0 && (dm_flags(cd, DM_VERITY, &dmv_flags) || !(dmv_flags & DM_VERITY_SUPPORTED))) {
		log_err(cd, _("Kernel does not support dm-verity mapping."));
		r = -ENOTSUP;
	}
	if (r < 0 && signature_description && !(dmv_flags & DM_VERITY_SIGNATURE_SUPPORTED)) {
		log_err(cd, _("Kernel does not support dm-verity signature option."));
		r = -ENOTSUP;
	}
	if (r < 0)
		goto out;

	r = dm_status_verity_ok(cd, name);
	if (r < 0)
		goto out;

	if (!r)
		log_err(cd, _("Verity device detected corruption after activation."));

	r = 0;
out:
	dm_targets_free(cd, &dmd);
	return r;
}
