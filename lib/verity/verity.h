/*
 * dm-verity volume handling
 *
 * Copyright (C) 2012-2024 Red Hat, Inc. All rights reserved.
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

#ifndef _VERITY_H
#define _VERITY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define VERITY_MAX_HASH_TYPE 1
#define VERITY_BLOCK_SIZE_OK(x)	((x) % 512 || (x) < 512 || \
				(x) > (512 * 1024) || (x) & ((x)-1))

struct crypt_device;
struct crypt_params_verity;
struct device;
struct volume_key;

int VERITY_read_sb(struct crypt_device *cd,
		   uint64_t sb_offset,
		   char **uuid,
		   struct crypt_params_verity *params);

int VERITY_write_sb(struct crypt_device *cd,
		   uint64_t sb_offset,
		   const char *uuid_string,
		   struct crypt_params_verity *params);

int VERITY_activate(struct crypt_device *cd,
		     const char *name,
		     struct volume_key *root_hash,
		     struct volume_key *signature,
		     struct device *fec_device,
		     struct crypt_params_verity *verity_hdr,
		     uint32_t activation_flags);

int VERITY_verify_params(struct crypt_device *cd,
	struct crypt_params_verity *hdr,
	bool signed_root_hash,
	struct device *fec_device,
	struct volume_key *root_hash);

int VERITY_verify(struct crypt_device *cd,
		struct crypt_params_verity *verity_hdr,
		const char *root_hash,
		size_t root_hash_size);

int VERITY_create(struct crypt_device *cd,
		  struct crypt_params_verity *verity_hdr,
		  const char *root_hash,
		  size_t root_hash_size);

int VERITY_FEC_process(struct crypt_device *cd,
		      struct crypt_params_verity *params,
		      struct device *fec_device,
		      int check_fec,
		      unsigned int *errors);

uint64_t VERITY_hash_offset_block(struct crypt_params_verity *params);

uint64_t VERITY_hash_blocks(struct crypt_device *cd, struct crypt_params_verity *params);

uint64_t VERITY_FEC_blocks(struct crypt_device *cd,
			   struct device *fec_device,
			   struct crypt_params_verity *params);
uint64_t VERITY_FEC_RS_blocks(uint64_t blocks, uint32_t roots);

int VERITY_UUID_generate(char **uuid_string);

int VERITY_dump(struct crypt_device *cd,
		struct crypt_params_verity *verity_hdr,
		const char *root_hash,
		unsigned int root_hash_size,
		struct device *fec_device);

#endif
