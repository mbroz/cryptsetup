/*
 * Generic wrapper for storage functions
 * (experimental only)
 *
 * Copyright (C) 2018-2020, Ondrej Kozina
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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "utils_storage_wrappers.h"
#include "internal.h"

struct crypt_storage_wrapper {
	crypt_storage_wrapper_type type;
	int dev_fd;
	int block_size;
	size_t mem_alignment;
	uint64_t data_offset;
	union {
	struct {
		struct crypt_storage *s;
		uint64_t iv_start;
	} cb;
	struct {
		int dmcrypt_fd;
		char name[PATH_MAX];
	} dm;
	} u;
};

static int crypt_storage_backend_init(struct crypt_device *cd,
		struct crypt_storage_wrapper *w,
		uint64_t iv_start,
		int sector_size,
		const char *cipher,
		const char *cipher_mode,
		const struct volume_key *vk,
		uint32_t flags)
{
	int r;
	struct crypt_storage *s;

	/* iv_start, sector_size */
	r = crypt_storage_init(&s, sector_size, cipher, cipher_mode, vk->key, vk->keylength);
	if (r)
		return r;

	if ((flags & DISABLE_KCAPI) && crypt_storage_kernel_only(s)) {
		log_dbg(cd, "Could not initialize userspace block cipher and kernel fallback is disabled.");
		crypt_storage_destroy(s);
		return -ENOTSUP;
	}

	w->type = USPACE;
	w->u.cb.s = s;
	w->u.cb.iv_start = iv_start;

	return 0;
}

static int crypt_storage_dmcrypt_init(
	struct crypt_device *cd,
	struct crypt_storage_wrapper *cw,
	struct device *device,
	uint64_t device_offset,
	uint64_t iv_start,
	int sector_size,
	const char *cipher_spec,
	struct volume_key *vk,
	int open_flags)
{
	static int counter = 0;
	char path[PATH_MAX];
	struct crypt_dm_active_device dmd = {
		.flags = CRYPT_ACTIVATE_PRIVATE,
	};
	int mode, r, fd = -1;

	log_dbg(cd, "Using temporary dmcrypt to access data.");

	if (snprintf(cw->u.dm.name, sizeof(cw->u.dm.name), "temporary-cryptsetup-%d-%d", getpid(), counter++) < 0)
		return -ENOMEM;
	if (snprintf(path, sizeof(path), "%s/%s", dm_get_dir(), cw->u.dm.name) < 0)
		return -ENOMEM;

	r = device_block_adjust(cd, device, DEV_OK,
				device_offset, &dmd.size, &dmd.flags);
	if (r < 0) {
		log_err(cd, _("Device %s does not exist or access denied."),
			device_path(device));
		return -EIO;
	}

	mode = open_flags | O_DIRECT;
	if (dmd.flags & CRYPT_ACTIVATE_READONLY)
		mode = (open_flags & ~O_ACCMODE) | O_RDONLY;

	if (vk->key_description)
		dmd.flags |= CRYPT_ACTIVATE_KEYRING_KEY;

	r = dm_crypt_target_set(&dmd.segment, 0, dmd.size,
			    device,
			    vk,
			    cipher_spec,
			    iv_start,
			    device_offset,
			    NULL,
			    0,
			    sector_size);
	if (r)
		return r;

	r = dm_create_device(cd, cw->u.dm.name, "TEMP", &dmd);
	if (r < 0) {
		if (r != -EACCES && r != -ENOTSUP)
			log_dbg(cd, "error hint would be nice");
		r = -EIO;
	}

	dm_targets_free(cd, &dmd);

	if (r)
		return r;

	fd = open(path, mode);
	if (fd < 0) {
		log_dbg(cd, "Failed to open %s", path);
		dm_remove_device(cd, cw->u.dm.name, CRYPT_DEACTIVATE_FORCE);
		return -EINVAL;
	}

	cw->type = DMCRYPT;
	cw->u.dm.dmcrypt_fd = fd;

	return 0;
}

int crypt_storage_wrapper_init(struct crypt_device *cd,
	struct crypt_storage_wrapper **cw,
	struct device *device,
	uint64_t data_offset,
	uint64_t iv_start,
	int sector_size,
	const char *cipher,
	struct volume_key *vk,
	uint32_t flags)
{
	int open_flags, r;
	char _cipher[MAX_CIPHER_LEN], mode[MAX_CIPHER_LEN];
	struct crypt_storage_wrapper *w;

	/* device-mapper restrictions */
	if (data_offset & ((1 << SECTOR_SHIFT) - 1))
		return -EINVAL;

	if (crypt_parse_name_and_mode(cipher, _cipher, NULL, mode))
		return -EINVAL;

	open_flags = O_CLOEXEC | ((flags & OPEN_READONLY) ? O_RDONLY : O_RDWR);

	w = malloc(sizeof(*w));
	if (!w)
		return -ENOMEM;

	memset(w, 0, sizeof(*w));
	w->data_offset = data_offset;
	w->mem_alignment = device_alignment(device);
	w->block_size = device_block_size(cd, device);
	if (!w->block_size || !w->mem_alignment) {
		log_dbg(cd, "block size or alignment error.");
		r = -EINVAL;
		goto err;
	}

	w->dev_fd = device_open(cd, device, open_flags);
	if (w->dev_fd < 0) {
		r = -EINVAL;
		goto err;
	}

	if (!strcmp(_cipher, "cipher_null")) {
		log_dbg(cd, "Requested cipher_null, switching to noop wrapper.");
		w->type = NONE;
		*cw = w;
		return 0;
	}

	if (!vk) {
		log_dbg(cd, "no key passed.");
		r = -EINVAL;
		goto err;
	}

	r = crypt_storage_backend_init(cd, w, iv_start, sector_size, _cipher, mode, vk, flags);
	if (!r) {
		*cw = w;
		return 0;
	}

	log_dbg(cd, "Failed to initialize userspace block cipher.");

	if ((r != -ENOTSUP && r != -ENOENT) || (flags & DISABLE_DMCRYPT))
		goto err;

	r = crypt_storage_dmcrypt_init(cd, w, device, data_offset >> SECTOR_SHIFT, iv_start,
			sector_size, cipher, vk, open_flags);
	if (r) {
		log_dbg(cd, "Dm-crypt backend failed to initialize.");
		goto err;
	}
	*cw = w;
	return 0;
err:
	crypt_storage_wrapper_destroy(w);
	/* wrapper destroy */
	return r;
}

/* offset is relative to sector_start */
ssize_t crypt_storage_wrapper_read(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length)
{
	return read_lseek_blockwise(cw->dev_fd,
			cw->block_size,
			cw->mem_alignment,
			buffer,
			buffer_length,
			cw->data_offset + offset);
}

ssize_t crypt_storage_wrapper_read_decrypt(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length)
{
	int r;
	ssize_t read;

	if (cw->type == DMCRYPT)
		return read_lseek_blockwise(cw->u.dm.dmcrypt_fd,
				cw->block_size,
				cw->mem_alignment,
				buffer,
				buffer_length,
				offset);

	read = read_lseek_blockwise(cw->dev_fd,
			cw->block_size,
			cw->mem_alignment,
			buffer,
			buffer_length,
			cw->data_offset + offset);
	if (cw->type == NONE || read < 0)
		return read;

	r = crypt_storage_decrypt(cw->u.cb.s,
			cw->u.cb.iv_start + (offset >> SECTOR_SHIFT),
			read,
			buffer);
	if (r)
		return -EINVAL;

	return read;
}

ssize_t crypt_storage_wrapper_decrypt(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length)
{
	int r;
	ssize_t read;

	if (cw->type == NONE)
		return 0;

	if (cw->type == DMCRYPT) {
		/* there's nothing we can do, just read/decrypt via dm-crypt */
		read = crypt_storage_wrapper_read_decrypt(cw, offset, buffer, buffer_length);
		if (read < 0 || (size_t)read != buffer_length)
			return -EINVAL;
		return 0;
	}

	r = crypt_storage_decrypt(cw->u.cb.s,
			cw->u.cb.iv_start + (offset >> SECTOR_SHIFT),
			buffer_length,
			buffer);
	if (r)
		return r;

	return 0;
}

ssize_t crypt_storage_wrapper_write(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length)
{
	return write_lseek_blockwise(cw->dev_fd,
			cw->block_size,
			cw->mem_alignment,
			buffer,
			buffer_length,
			cw->data_offset + offset);
}

ssize_t crypt_storage_wrapper_encrypt_write(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length)
{
	if (cw->type == DMCRYPT)
		return write_lseek_blockwise(cw->u.dm.dmcrypt_fd,
				cw->block_size,
				cw->mem_alignment,
				buffer,
				buffer_length,
				offset);

	if (cw->type == USPACE &&
	    crypt_storage_encrypt(cw->u.cb.s,
		    cw->u.cb.iv_start + (offset >> SECTOR_SHIFT),
		    buffer_length, buffer))
		return -EINVAL;

	return write_lseek_blockwise(cw->dev_fd,
			cw->block_size,
			cw->mem_alignment,
			buffer,
			buffer_length,
			cw->data_offset + offset);
}

ssize_t crypt_storage_wrapper_encrypt(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length)
{
	if (cw->type == NONE)
		return 0;

	if (cw->type == DMCRYPT)
		return -ENOTSUP;

	if (crypt_storage_encrypt(cw->u.cb.s,
			cw->u.cb.iv_start + (offset >> SECTOR_SHIFT),
			buffer_length,
			buffer))
		return -EINVAL;

	return 0;
}

void crypt_storage_wrapper_destroy(struct crypt_storage_wrapper *cw)
{
	if (!cw)
		return;

	if (cw->type == USPACE)
		crypt_storage_destroy(cw->u.cb.s);
	if (cw->type == DMCRYPT) {
		close(cw->u.dm.dmcrypt_fd);
		dm_remove_device(NULL, cw->u.dm.name, CRYPT_DEACTIVATE_FORCE);
	}

	free(cw);
}

int crypt_storage_wrapper_datasync(const struct crypt_storage_wrapper *cw)
{
	if (!cw)
		return -EINVAL;
	if (cw->type == DMCRYPT)
		return fdatasync(cw->u.dm.dmcrypt_fd);
	else
		return fdatasync(cw->dev_fd);
}

crypt_storage_wrapper_type crypt_storage_wrapper_get_type(const struct crypt_storage_wrapper *cw)
{
	return cw ? cw->type : NONE;
}
