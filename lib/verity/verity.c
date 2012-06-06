/*
 * dm-verity volume handling
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>

#include "libcryptsetup.h"
#include "verity.h"
#include "internal.h"

/* Read verity superblock from disk */
int VERITY_read_sb(struct crypt_device *cd,
		   const char *device,
		   size_t sb_offset,
		   struct crypt_params_verity *params)
{
	struct verity_sb sb = {};
	ssize_t hdr_size = sizeof(struct verity_sb);
	int devfd = 0;
	long long sb_data_blocks;

	log_dbg("Reading VERITY header of size %d on device %s, offset %u.",
		sizeof(struct verity_sb), device, (unsigned)sb_offset);

	devfd = open(device ,O_RDONLY | O_DIRECT);
	if(devfd == -1) {
		log_err(cd, _("Cannot open device %s.\n"), device);
		return -EINVAL;
	}

	if(lseek(devfd, sb_offset, SEEK_SET) < 0 ||
	   read_blockwise(devfd, &sb, hdr_size) < hdr_size) {
		close(devfd);
		return -EIO;
	}
	close(devfd);

	if (memcmp(sb.signature, VERITY_SIGNATURE, sizeof(sb.signature))) {
		log_err(cd, _("Device %s is not a valid VERITY device.\n"), device);
		return -EINVAL;
	}

	if (sb.version > 1) {
		log_err(cd, _("Unsupported VERITY version %d.\n"), sb.version);
		return -EINVAL;
	}

	if (sb.data_block_bits < 9 || sb.data_block_bits >= 31 ||
	    sb.hash_block_bits < 9 || sb.hash_block_bits >= 31 ||
	    !memchr(sb.algorithm, 0, sizeof(sb.algorithm)) ||
	    ntohs(sb.salt_size) > VERITY_MAX_SALT_SIZE) {
		log_err(cd, _("VERITY header corrupted.\n"));
		return -EINVAL;
	}

	sb_data_blocks = ((unsigned long long)ntohl(sb.data_blocks_hi) << 31 << 1) |
				ntohl(sb.data_blocks_lo);
	if (sb_data_blocks < 0 ||
	    (off_t)sb_data_blocks < 0 ||
	    (off_t)sb_data_blocks != sb_data_blocks) {
		log_err(cd, _("VERITY header data block size mismatch.\n"));
		return -EINVAL;
	}

	// FIXME alloc error
	params->hash_name = strdup((const char*)sb.algorithm);
	params->data_block_size = 1 << sb.data_block_bits;
	params->hash_block_size = 1 << sb.hash_block_bits;
	params->data_size = sb_data_blocks;
	params->salt_size = ntohs(sb.salt_size);
	params->salt = malloc(params->salt_size);
	memcpy(CONST_CAST(char*)params->salt, sb.salt, params->salt_size);
	params->hash_area_offset = sb_offset;
	params->version = sb.version;

	return 0;
}

/* Write verity superblock to disk */
int VERITY_write_sb(struct crypt_device *cd,
		   const char *device,
		   size_t sb_offset,
		   struct crypt_params_verity *params)
{
	struct verity_sb sb = {};
	ssize_t hdr_size = sizeof(struct verity_sb);
	int r, devfd = 0;

	log_dbg("Updating VERITY header of size %d on device %s, offset %u.",
		sizeof(struct verity_sb), device, (unsigned)sb_offset);

	devfd = open(device, O_RDWR | O_DIRECT);
	if(devfd == -1) {
		log_err(cd, _("Cannot open device %s.\n"), device);
		return -EINVAL;
	}

	memcpy(&sb.signature, VERITY_SIGNATURE, sizeof(sb.signature));
	sb.version = params->version;
	sb.data_block_bits = ffs(params->data_block_size) - 1;
	sb.hash_block_bits = ffs(params->hash_block_size) - 1;
	sb.salt_size = htons(params->salt_size);
	sb.data_blocks_hi = htonl(params->data_size >> 31 >> 1);
	sb.data_blocks_lo = htonl(params->data_size & 0xFFFFFFFF);
	strncpy((char *)sb.algorithm, params->hash_name, sizeof(sb.algorithm));
	memcpy(sb.salt, params->salt, params->salt_size);

	r = write_lseek_blockwise(devfd, (char*)&sb, hdr_size, sb_offset) < hdr_size ? -EIO : 0;
	if (r)
		log_err(cd, _("Error during update of verity header on device %s.\n"), device);
	close(devfd);

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

/* Activate verity device in kernel device-mapper */
int VERITY_activate(struct crypt_device *cd,
		     const char *name,
		     const char *hash_device,
		     const char *root_hash,
		     size_t root_hash_size,
		     struct crypt_params_verity *verity_hdr,
		     uint32_t flags)
{
	struct crypt_dm_active_verity dmd;
	uint64_t offset = 0;
	int r;

	log_dbg("Trying to activate VERITY device %s using hash %s.",
		name ?: "[none]", verity_hdr->hash_name);

	if (flags & CRYPT_VERITY_CHECK_HASH) {
		r = VERITY_verify(cd, verity_hdr,
				  crypt_get_device_name(cd), hash_device,
				  root_hash, root_hash_size);
		if (r < 0)
			return r;
	}

	if (!name)
		return 0;

	dmd.data_device = crypt_get_device_name(cd);
	dmd.hash_device = hash_device;
	dmd.root_hash = root_hash;
	dmd.root_hash_size = root_hash_size;
	dmd.hash_offset = VERITY_hash_offset_block(verity_hdr),
	dmd.flags = CRYPT_ACTIVATE_READONLY;
	dmd.size = verity_hdr->data_size * verity_hdr->data_block_size / 512;

	r = device_check_and_adjust(cd, dmd.data_device, DEV_EXCL,
				    &dmd.size, &offset, &dmd.flags);
	if (r)
		return r;

	r = dm_create_verity(name, verity_hdr, &dmd);
	if (r < 0)
		return r;

	r = dm_status_verity_ok(name);
	if (r < 0)
		return r;

	if (!r)
		log_err(cd, _("Verity device detected corruption after activation.\n"));
	return 0;
}
