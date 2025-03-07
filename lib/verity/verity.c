// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * dm-verity volume handling
 *
 * Copyright (C) 2012-2025 Red Hat, Inc. All rights reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
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
		log_dbg(cd, "No VERITY signature detected.");
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

	/* Update block size to be used for loop devices */
	device_set_block_size(crypt_metadata_device(cd), params->hash_block_size);
	device_set_block_size(crypt_data_device(cd), params->data_block_size);

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

static void _to_lower(char *str)
{
	for(; *str; str++)
		if (isupper(*str))
			*str = tolower(*str);
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
	size_t block_size;
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

	/* Avoid possible increasing of image size - FEC could fail later because of it */
	block_size = device_block_size(cd, device);
	if (block_size > params->hash_block_size) {
		device_disable_direct_io(device);
		block_size = params->hash_block_size;
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

	/* Kernel always use lower-case */
	algorithm = (char *)sb.algorithm;
	strncpy(algorithm, params->hash_name, sizeof(sb.algorithm)-1);
	algorithm[sizeof(sb.algorithm)-1] = '\0';
	_to_lower(algorithm);

	memcpy(sb.salt, params->salt, params->salt_size);
	memcpy(sb.uuid, uuid, sizeof(sb.uuid));

	r = write_lseek_blockwise(devfd, block_size, device_alignment(device),
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

int VERITY_UUID_generate(char **uuid_string)
{
	uuid_t uuid;

	*uuid_string = malloc(40);
	if (!*uuid_string)
		return -ENOMEM;
	uuid_generate(uuid);
	uuid_unparse(uuid, *uuid_string);
	return 0;
}

int VERITY_verify_params(struct crypt_device *cd,
	struct crypt_params_verity *hdr,
	bool signed_root_hash,
	struct device *fec_device,
	struct volume_key *root_hash)
{
	bool userspace_verification;
	int v, r;
	unsigned int fec_errors = 0;

	assert(cd);
	assert(hdr);
	assert(root_hash);

	log_dbg(cd, "Verifying VERITY device using hash %s.",
		hdr->hash_name);

	userspace_verification = hdr->flags & CRYPT_VERITY_CHECK_HASH;

	if (userspace_verification && signed_root_hash) {
		log_err(cd, _("Root hash signature verification is not supported."));
		return -EINVAL;
	}

	if ((hdr->flags & CRYPT_VERITY_ROOT_HASH_SIGNATURE) && !signed_root_hash) {
		log_err(cd, _("Root hash signature required."));
		return -EINVAL;
	}

	if (!userspace_verification)
		return 0;

	log_dbg(cd, "Verification of VERITY data in userspace required.");
	r = VERITY_verify(cd, hdr, crypt_volume_key_get_key(root_hash),
			  crypt_volume_key_length(root_hash));

	if ((r == -EPERM || r == -EFAULT) && fec_device) {
		v = r;
		log_dbg(cd, "Verification failed, trying to repair with FEC device.");
		r = VERITY_FEC_process(cd, hdr, fec_device, 1, &fec_errors);
		if (r < 0)
			log_err(cd, _("Errors cannot be repaired with FEC device."));
		else if (fec_errors) {
			log_err(cd, _("Found %u repairable errors with FEC device."),
				fec_errors);
			/* If root hash failed, we cannot be sure it was properly repaired */
		}
		if (v == -EFAULT)
			r = -EPERM;
	}

	return r;
}

/* Activate verity device in kernel device-mapper */
int VERITY_activate(struct crypt_device *cd,
		     const char *name,
		     struct volume_key *root_hash,
		     struct volume_key *signature,
		     struct device *fec_device,
		     struct crypt_params_verity *verity_hdr,
		     uint32_t activation_flags)
{
	uint64_t dmv_flags;
	int r;
	key_serial_t kid = 0;
	char *description = NULL;
	struct crypt_dm_active_device dmd = { 0 };

	assert(name);
	assert(root_hash);
	assert(verity_hdr);

	dmd.size = verity_hdr->data_size * verity_hdr->data_block_size / 512;
	dmd.flags = activation_flags;
	dmd.uuid = crypt_get_uuid(cd);

	log_dbg(cd, "Activating VERITY device %s using hash %s.",
		name, verity_hdr->hash_name);

	if (signature) {
		r = asprintf(&description, "cryptsetup:%s%s%s",
			 crypt_get_uuid(cd) ?: "", crypt_get_uuid(cd) ? "-" : "", name);
		if (r < 0)
			return -EINVAL;

		log_dbg(cd, "Adding signature %s (type user) into thread keyring.", description);
		kid = keyring_add_key_in_thread_keyring(USER_KEY, description,
							crypt_volume_key_get_key(signature),
							crypt_volume_key_length(signature));
		if (kid < 0) {
			log_dbg(cd, "keyring_add_key_in_thread_keyring failed with errno %d.", errno);
			log_err(cd, _("Failed to load key in kernel keyring."));
			free(description);
			return -EINVAL;
		}
	}

	r = device_block_adjust(cd, crypt_metadata_device(cd), DEV_OK,
				0, NULL, NULL);
	if (r)
		goto out;

	r = device_block_adjust(cd, crypt_data_device(cd),
				activation_flags & CRYPT_ACTIVATE_SHARED ? DEV_OK : DEV_EXCL,
				0, &dmd.size, &dmd.flags);
	if (r)
		goto out;

	if (fec_device) {
		r = device_block_adjust(cd, fec_device, DEV_OK,
					0, NULL, NULL);
		if (r)
			goto out;
	}

	r = dm_verity_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd),
			crypt_metadata_device(cd), fec_device, crypt_volume_key_get_key(root_hash),
			crypt_volume_key_length(root_hash), description,
			VERITY_hash_offset_block(verity_hdr),
			VERITY_FEC_blocks(cd, fec_device, verity_hdr), verity_hdr);

	if (r)
		goto out;

	r = dm_create_device(cd, name, CRYPT_VERITY, &dmd);
	if (r < 0 && (dm_flags(cd, DM_VERITY, &dmv_flags) || !(dmv_flags & DM_VERITY_SUPPORTED))) {
		log_err(cd, _("Kernel does not support dm-verity mapping."));
		r = -ENOTSUP;
	}
	if (r < 0 && signature && !(dmv_flags & DM_VERITY_SIGNATURE_SUPPORTED)) {
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
	if (signature) {
		log_dbg(cd, "Unlinking signature (id: %" PRIi32 ") from thread keyring.", kid);

		if (keyring_unlink_key_from_thread_keyring(kid))
			log_dbg(cd, "keyring_unlink_key_from_thread_keyring failed with errno %d.", errno);
	}
	free(description);
	dm_targets_free(cd, &dmd);
	return r;
}

int VERITY_dump(struct crypt_device *cd,
		struct crypt_params_verity *verity_hdr,
		const char *root_hash,
		unsigned int root_hash_size,
		struct device *fec_device)
{
	uint64_t hash_blocks, verity_blocks, fec_blocks = 0, rs_blocks = 0;
	bool fec_on_hash_device = false;

	hash_blocks  = VERITY_hash_blocks(cd, verity_hdr);
	verity_blocks = VERITY_hash_offset_block(verity_hdr) + hash_blocks;

	if (fec_device && verity_hdr->fec_roots) {
		fec_blocks = VERITY_FEC_blocks(cd, fec_device, verity_hdr);
		rs_blocks  = VERITY_FEC_RS_blocks(fec_blocks, verity_hdr->fec_roots);
		fec_on_hash_device = device_is_identical(crypt_metadata_device(cd), fec_device) > 0;
		/*
		* No way to access fec_area_offset directly.
		* Assume FEC area starts directly after hash blocks.
		*/
		if (fec_on_hash_device)
			verity_blocks += rs_blocks;
	}

	log_std(cd, "VERITY header information for %s.\n", device_path(crypt_metadata_device(cd)));
	log_std(cd, "UUID:            \t%s\n", crypt_get_uuid(cd) ?: "");
	log_std(cd, "Hash type:       \t%u\n", verity_hdr->hash_type);
	log_std(cd, "Data blocks:     \t%" PRIu64 "\n", verity_hdr->data_size);
	log_std(cd, "Data block size: \t%u [bytes]\n", verity_hdr->data_block_size);
	log_std(cd, "Hash blocks:     \t%" PRIu64 "\n", hash_blocks);
	log_std(cd, "Hash block size: \t%u [bytes]\n", verity_hdr->hash_block_size);
	log_std(cd, "Hash algorithm:  \t%s\n", verity_hdr->hash_name);
	if (fec_device && fec_blocks) {
		log_std(cd, "FEC RS roots:   \t%" PRIu32 "\n", verity_hdr->fec_roots);
		log_std(cd, "FEC blocks:     \t%" PRIu64 "\n", rs_blocks);
	}

	log_std(cd, "Salt:            \t");
	if (verity_hdr->salt_size)
		crypt_log_hex(cd, verity_hdr->salt, verity_hdr->salt_size, "", 0, NULL);
	else
		log_std(cd, "-");
	log_std(cd, "\n");

	if (root_hash) {
		log_std(cd, "Root hash:      \t");
		crypt_log_hex(cd, root_hash, root_hash_size, "", 0, NULL);
		log_std(cd, "\n");
	}

	/* As dump can take only hash device, we have no idea about offsets here. */
	if (verity_hdr->hash_area_offset == 0)
		log_std(cd, "Hash device size: \t%" PRIu64 " [bytes]\n", verity_blocks * verity_hdr->hash_block_size);

	if (fec_device && verity_hdr->fec_area_offset == 0 && fec_blocks && !fec_on_hash_device)
		log_std(cd, "FEC device size: \t%" PRIu64 " [bytes]\n", rs_blocks * verity_hdr->data_block_size);

	return 0;
}
