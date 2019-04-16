/*
 * LUKS - Linux Unified Key Setup
 *
 * Copyright (C) 2004-2006 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2019 Milan Broz
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

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include "luks.h"
#include "af.h"
#include "internal.h"

static void _error_hint(struct crypt_device *ctx, const char *device,
			const char *cipher, const char *mode, size_t keyLength)
{
	char *c, cipher_spec[MAX_CIPHER_LEN * 3];

	if (snprintf(cipher_spec, sizeof(cipher_spec), "%s-%s", cipher, mode) < 0)
		return;

	log_err(ctx, _("Failed to setup dm-crypt key mapping for device %s.\n"
			"Check that kernel supports %s cipher (check syslog for more info)."),
			device, cipher_spec);

	if (!strncmp(mode, "xts", 3) && (keyLength != 256 && keyLength != 512))
		log_err(ctx, _("Key size in XTS mode must be 256 or 512 bits."));
	else if (!(c = strchr(mode, '-')) || strlen(c) < 4)
		log_err(ctx, _("Cipher specification should be in [cipher]-[mode]-[iv] format."));
}

static int LUKS_endec_template(char *src, size_t srcLength,
			       const char *cipher, const char *cipher_mode,
			       struct volume_key *vk,
			       unsigned int sector,
			       ssize_t (*func)(int, size_t, size_t, void *, size_t),
			       int mode,
			       struct crypt_device *ctx)
{
	char name[PATH_MAX], path[PATH_MAX];
	char cipher_spec[MAX_CIPHER_LEN * 3];
	struct crypt_dm_active_device dmd = {
		.flags = CRYPT_ACTIVATE_PRIVATE,
	};
	int r, devfd = -1, remove_dev = 0;
	size_t bsize, keyslot_alignment, alignment;

	log_dbg(ctx, "Using dmcrypt to access keyslot area.");

	bsize = device_block_size(ctx, crypt_metadata_device(ctx));
	alignment = device_alignment(crypt_metadata_device(ctx));
	if (!bsize || !alignment)
		return -EINVAL;

	if (bsize > LUKS_ALIGN_KEYSLOTS)
		keyslot_alignment = LUKS_ALIGN_KEYSLOTS;
	else
		keyslot_alignment = bsize;
	dmd.size = size_round_up(srcLength, keyslot_alignment) / SECTOR_SIZE;

	if (mode == O_RDONLY)
		dmd.flags |= CRYPT_ACTIVATE_READONLY;

	if (snprintf(name, sizeof(name), "temporary-cryptsetup-%d", getpid()) < 0)
		return -ENOMEM;
	if (snprintf(path, sizeof(path), "%s/%s", dm_get_dir(), name) < 0)
		return -ENOMEM;
	if (snprintf(cipher_spec, sizeof(cipher_spec), "%s-%s", cipher, cipher_mode) < 0)
		return -ENOMEM;

	r = device_block_adjust(ctx, crypt_metadata_device(ctx), DEV_OK,
				sector, &dmd.size, &dmd.flags);
	if (r < 0) {
		log_err(ctx, _("Device %s doesn't exist or access denied."),
			device_path(crypt_metadata_device(ctx)));
		return -EIO;
	}

	if (mode != O_RDONLY && dmd.flags & CRYPT_ACTIVATE_READONLY) {
		log_err(ctx, _("Cannot write to device %s, permission denied."),
			device_path(crypt_metadata_device(ctx)));
		return -EACCES;
	}

	r = dm_crypt_target_set(&dmd.segment, 0, dmd.size,
			crypt_metadata_device(ctx), vk, cipher_spec, 0, sector,
			NULL, 0, SECTOR_SIZE);
	if (r)
		goto out;

	r = dm_create_device(ctx, name, "TEMP", &dmd);
	if (r < 0) {
		if (r != -EACCES && r != -ENOTSUP)
			_error_hint(ctx, device_path(crypt_metadata_device(ctx)),
				    cipher, cipher_mode, vk->keylength * 8);
		r = -EIO;
		goto out;
	}
	remove_dev = 1;

	devfd = open(path, mode | O_DIRECT | O_SYNC);
	if (devfd == -1) {
		log_err(ctx, _("Failed to open temporary keystore device."));
		r = -EIO;
		goto out;
	}

	r = func(devfd, bsize, alignment, src, srcLength);
	if (r < 0) {
		log_err(ctx, _("Failed to access temporary keystore device."));
		r = -EIO;
	} else
		r = 0;
 out:
	dm_targets_free(ctx, &dmd);
	if (devfd != -1)
		close(devfd);
	if (remove_dev)
		dm_remove_device(ctx, name, CRYPT_DEACTIVATE_FORCE);
	return r;
}

int LUKS_encrypt_to_storage(char *src, size_t srcLength,
			    const char *cipher,
			    const char *cipher_mode,
			    struct volume_key *vk,
			    unsigned int sector,
			    struct crypt_device *ctx)
{

	struct device *device = crypt_metadata_device(ctx);
	struct crypt_storage *s;
	int devfd = -1, r = 0;

	/* Only whole sector writes supported */
	if (MISALIGNED_512(srcLength))
		return -EINVAL;

	/* Encrypt buffer */
	r = crypt_storage_init(&s, SECTOR_SIZE, cipher, cipher_mode, vk->key, vk->keylength);

	if (r)
		log_dbg(ctx, "Userspace crypto wrapper cannot use %s-%s (%d).",
			cipher, cipher_mode, r);

	/* Fallback to old temporary dmcrypt device */
	if (r == -ENOTSUP || r == -ENOENT)
		return LUKS_endec_template(src, srcLength, cipher, cipher_mode,
					   vk, sector, write_blockwise, O_RDWR, ctx);

	if (r) {
		_error_hint(ctx, device_path(device), cipher, cipher_mode,
			    vk->keylength * 8);
		return r;
	}

	log_dbg(ctx, "Using userspace crypto wrapper to access keyslot area.");

	r = crypt_storage_encrypt(s, 0, srcLength, src);
	crypt_storage_destroy(s);

	if (r)
		return r;

	r = -EIO;

	/* Write buffer to device */
	if (device_is_locked(device))
		devfd = device_open_locked(ctx, device, O_RDWR);
	else
		devfd = device_open(ctx, device, O_RDWR);
	if (devfd < 0)
		goto out;

	if (write_lseek_blockwise(devfd, device_block_size(ctx, device),
				  device_alignment(device), src, srcLength,
				  sector * SECTOR_SIZE) < 0)
		goto out;

	r = 0;
out:
	if (devfd >= 0) {
		device_sync(ctx, device, devfd);
		close(devfd);
	}
	if (r)
		log_err(ctx, _("IO error while encrypting keyslot."));

	return r;
}

int LUKS_decrypt_from_storage(char *dst, size_t dstLength,
			      const char *cipher,
			      const char *cipher_mode,
			      struct volume_key *vk,
			      unsigned int sector,
			      struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	struct crypt_storage *s;
	struct stat st;
	int devfd = -1, r = 0;

	/* Only whole sector reads supported */
	if (MISALIGNED_512(dstLength))
		return -EINVAL;

	r = crypt_storage_init(&s, SECTOR_SIZE, cipher, cipher_mode, vk->key, vk->keylength);

	if (r)
		log_dbg(ctx, "Userspace crypto wrapper cannot use %s-%s (%d).",
			cipher, cipher_mode, r);

	/* Fallback to old temporary dmcrypt device */
	if (r == -ENOTSUP || r == -ENOENT)
		return LUKS_endec_template(dst, dstLength, cipher, cipher_mode,
					   vk, sector, read_blockwise, O_RDONLY, ctx);

	if (r) {
		_error_hint(ctx, device_path(device), cipher, cipher_mode,
			    vk->keylength * 8);
		return r;
	}

	log_dbg(ctx, "Using userspace crypto wrapper to access keyslot area.");

	/* Read buffer from device */
	if (device_is_locked(device))
		devfd = device_open_locked(ctx, device, O_RDONLY);
	else
		devfd = device_open(ctx, device, O_RDONLY);
	if (devfd < 0) {
		log_err(ctx, _("Cannot open device %s."), device_path(device));
		crypt_storage_destroy(s);
		return -EIO;
	}

	if (read_lseek_blockwise(devfd, device_block_size(ctx, device),
				 device_alignment(device), dst, dstLength,
				 sector * SECTOR_SIZE) < 0) {
		if (!fstat(devfd, &st) && (st.st_size < (off_t)dstLength))
			log_err(ctx, _("Device %s is too small."), device_path(device));
		else
			log_err(ctx, _("IO error while decrypting keyslot."));

		close(devfd);
		crypt_storage_destroy(s);
		return -EIO;
	}

	close(devfd);

	/* Decrypt buffer */
	r = crypt_storage_decrypt(s, 0, dstLength, dst);
	crypt_storage_destroy(s);

	return r;
}
