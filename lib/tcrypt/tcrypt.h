/*
 * TCRYPT (TrueCrypt-compatible)  header defitinion
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2014, Milan Broz
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

#include "libcryptsetup.h"

#ifndef _CRYPTSETUP_TCRYPT_H
#define _CRYPTSETUP_TCRYPT_H

#define TCRYPT_HDR_SALT_LEN 64
#define TCRYPT_HDR_IV_LEN   16
#define TCRYPT_HDR_LEN     448
#define TCRYPT_HDR_KEY_LEN 192
#define TCRYPT_HDR_MAGIC "TRUE"
#define TCRYPT_HDR_MAGIC_LEN 4

#define TCRYPT_HDR_HIDDEN_OFFSET_OLD -1536
#define TCRYPT_HDR_HIDDEN_OFFSET 65536

#define TCRYPT_HDR_HIDDEN_OFFSET_BCK -65536
#define TCRYPT_HDR_OFFSET_BCK -131072

#define TCRYPT_HDR_SYSTEM_OFFSET 31744

#define TCRYPT_LRW_IKEY_LEN 16
#define TCRYPT_KEY_POOL_LEN 64
#define TCRYPT_KEYFILE_LEN  1048576

#define TCRYPT_HDR_FLAG_SYSTEM    (1 << 0)
#define TCRYPT_HDR_FLAG_NONSYSTEM (1 << 1)

struct tcrypt_phdr {
	char salt[TCRYPT_HDR_SALT_LEN];

	/* encrypted part, TCRYPT_HDR_LEN bytes */
	union {
	struct __attribute__((__packed__)) {
		char     magic[TCRYPT_HDR_MAGIC_LEN];
		uint16_t version;
		uint16_t version_tc;
		uint32_t keys_crc32;
		uint64_t _reserved1[2]; /* data/header ctime */
		uint64_t hidden_volume_size;
		uint64_t volume_size;
		uint64_t mk_offset;
		uint64_t mk_size;
		uint32_t flags;
		uint32_t sector_size;
		uint8_t  _reserved2[120];
		uint32_t header_crc32;
		char     keys[256];
	} d;
	char e[TCRYPT_HDR_LEN];
	};
} __attribute__((__packed__));

struct crypt_dm_active_device;
struct volume_key;
struct device;

int TCRYPT_read_phdr(struct crypt_device *cd,
		     struct tcrypt_phdr *hdr,
		     struct crypt_params_tcrypt *params);

int TCRYPT_init_by_name(struct crypt_device *cd, const char *name,
			const struct crypt_dm_active_device *dmd,
			struct device **device,
			struct crypt_params_tcrypt *tcrypt_params,
			struct tcrypt_phdr *tcrypt_hdr);

int TCRYPT_activate(struct crypt_device *cd,
		     const char *name,
		     struct tcrypt_phdr *hdr,
		     struct crypt_params_tcrypt *params,
		     uint32_t flags);

int TCRYPT_deactivate(struct crypt_device *cd,
		      const char *name);

uint64_t TCRYPT_get_data_offset(struct crypt_device *cd,
				struct tcrypt_phdr *hdr,
				struct crypt_params_tcrypt *params);

uint64_t TCRYPT_get_iv_offset(struct crypt_device *cd,
			      struct tcrypt_phdr *hdr,
			      struct crypt_params_tcrypt *params);

int TCRYPT_get_volume_key(struct crypt_device *cd,
			  struct tcrypt_phdr *hdr,
			  struct crypt_params_tcrypt *params,
			  struct volume_key **vk);

int TCRYPT_dump(struct crypt_device *cd,
		struct tcrypt_phdr *hdr,
		struct crypt_params_tcrypt *params);

#endif
