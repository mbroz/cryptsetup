/*
 * libdevmapper - device-mapper backend for cryptsetup
 *
 * Copyright (C) 2004, Christophe Saout <christophe@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
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

#ifndef _UTILS_DM_H
#define _UTILS_DM_H

/* device-mapper library helpers */
#include <inttypes.h>

struct crypt_device;
struct volume_key;

/* Device mapper backend - kernel support flags */
#define DM_KEY_WIPE_SUPPORTED (1 << 0)	/* key wipe message */
#define DM_LMK_SUPPORTED      (1 << 1)	/* lmk mode */
#define DM_SECURE_SUPPORTED   (1 << 2)	/* wipe (secure) buffer flag */
#define DM_PLAIN64_SUPPORTED  (1 << 3)	/* plain64 IV */
#define DM_DISCARDS_SUPPORTED (1 << 4)	/* discards/TRIM option is supported */
uint32_t dm_flags(void);

#define DM_ACTIVE_DEVICE	(1 << 0)
#define DM_ACTIVE_CIPHER	(1 << 1)
#define DM_ACTIVE_UUID		(1 << 2)
#define DM_ACTIVE_KEYSIZE	(1 << 3)
#define DM_ACTIVE_KEY		(1 << 4)

struct crypt_dm_active_device {
	const char *device;
	const char *cipher;
	const char *uuid;

	/* Active key for device */
	struct volume_key *vk;

	/* struct crypt_active_device */
	uint64_t offset;	/* offset in sectors */
	uint64_t iv_offset;	/* IV initilisation sector */
	uint64_t size;		/* active device size */
	uint32_t flags;		/* activation flags */
};

const char *dm_get_dir(void);
int dm_init(struct crypt_device *context, int check_kernel);
void dm_exit(void);
int dm_remove_device(const char *name, int force, uint64_t size);
int dm_status_device(const char *name);
int dm_status_suspended(const char *name);
int dm_query_device(const char *name, uint32_t get_flags,
		    struct crypt_dm_active_device *dmd);
int dm_create_device(const char *name,
		      const char *type,
		      struct crypt_dm_active_device *dmd,
		      int reload);
int dm_suspend_and_wipe_key(const char *name);
int dm_resume_and_reinstate_key(const char *name,
				size_t key_size,
				const char *key);
char *dm_device_path(const char *prefix, int major, int minor);
int dm_is_dm_device(int major, int minor);
int dm_is_dm_kernel_name(const char *name);
int dm_check_segment(const char *name, uint64_t offset, uint64_t size);

#endif /* _UTILS_DM_H */
