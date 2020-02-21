/*
 * utils_wipe - wipe a device
 *
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2020 Milan Broz
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

#include <stdlib.h>
#include <errno.h>
#include "internal.h"

/*
 * Wipe using Peter Gutmann method described in
 * http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
 * Note: used only for rotational device (and even there it is not needed today...)
 */
static void wipeSpecial(char *buffer, size_t buffer_size, unsigned int turn)
{
	unsigned int i;

	unsigned char write_modes[][3] = {
		{"\x55\x55\x55"}, {"\xaa\xaa\xaa"}, {"\x92\x49\x24"},
		{"\x49\x24\x92"}, {"\x24\x92\x49"}, {"\x00\x00\x00"},
		{"\x11\x11\x11"}, {"\x22\x22\x22"}, {"\x33\x33\x33"},
		{"\x44\x44\x44"}, {"\x55\x55\x55"}, {"\x66\x66\x66"},
		{"\x77\x77\x77"}, {"\x88\x88\x88"}, {"\x99\x99\x99"},
		{"\xaa\xaa\xaa"}, {"\xbb\xbb\xbb"}, {"\xcc\xcc\xcc"},
		{"\xdd\xdd\xdd"}, {"\xee\xee\xee"}, {"\xff\xff\xff"},
		{"\x92\x49\x24"}, {"\x49\x24\x92"}, {"\x24\x92\x49"},
		{"\x6d\xb6\xdb"}, {"\xb6\xdb\x6d"}, {"\xdb\x6d\xb6"}
	};

	for (i = 0; i < buffer_size / 3; ++i) {
		memcpy(buffer, write_modes[turn], 3);
		buffer += 3;
	}
}

static int crypt_wipe_special(struct crypt_device *cd, int fd, size_t bsize,
			      size_t alignment, char *buffer,
			      uint64_t offset, size_t size)
{
	int r = 0;
	unsigned int i;
	ssize_t written;

	for (i = 0; i < 39; ++i) {
		if (i <  5) {
			r = crypt_random_get(cd, buffer, size, CRYPT_RND_NORMAL);
		} else if (i >=  5 && i < 32) {
			wipeSpecial(buffer, size, i - 5);
			r = 0;
		} else if (i >= 32 && i < 38) {
			r = crypt_random_get(cd, buffer, size, CRYPT_RND_NORMAL);
		} else if (i >= 38 && i < 39) {
			memset(buffer, 0xFF, size);
			r = 0;
		}
		if (r < 0)
			return -EIO;

		written = write_lseek_blockwise(fd, bsize, alignment,
						buffer, size, offset);
		if (written < 0 || written != (ssize_t)size)
			return -EIO;
	}

	/* Rewrite it finally with random */
	if (crypt_random_get(cd, buffer, size, CRYPT_RND_NORMAL) < 0)
		return -EIO;

	written = write_lseek_blockwise(fd, bsize, alignment, buffer, size, offset);
	if (written < 0 || written != (ssize_t)size)
		return -EIO;

	return 0;
}

static int wipe_block(struct crypt_device *cd, int devfd, crypt_wipe_pattern pattern,
		      char *sf, size_t device_block_size, size_t alignment,
		      size_t wipe_block_size, uint64_t offset, bool *need_block_init)
{
	int r;

	if (pattern == CRYPT_WIPE_SPECIAL)
		return crypt_wipe_special(cd, devfd, device_block_size, alignment,
					  sf, offset, wipe_block_size);

	if (*need_block_init) {
		if (pattern == CRYPT_WIPE_ZERO) {
			memset(sf, 0, wipe_block_size);
			*need_block_init = false;
			r = 0;
		} else if (pattern == CRYPT_WIPE_RANDOM) {
			r = crypt_random_get(cd, sf, wipe_block_size,
					     CRYPT_RND_NORMAL) ? -EIO : 0;
			*need_block_init = true;
		} else if (pattern == CRYPT_WIPE_ENCRYPTED_ZERO) {
			// FIXME
			r = crypt_random_get(cd, sf, wipe_block_size,
					     CRYPT_RND_NORMAL) ? -EIO : 0;
			*need_block_init = true;
		} else
			r = -EINVAL;

		if (r)
			return r;
	}

	if (write_blockwise(devfd, device_block_size, alignment, sf,
			    wipe_block_size) == (ssize_t)wipe_block_size)
		return 0;

	return -EIO;
}

int crypt_wipe_device(struct crypt_device *cd,
	struct device *device,
	crypt_wipe_pattern pattern,
	uint64_t offset,
	uint64_t length,
	size_t wipe_block_size,
	int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
	void *usrptr)
{
	int r, devfd;
	size_t bsize, alignment;
	char *sf = NULL;
	uint64_t dev_size;
	bool need_block_init = true;

	/* Note: LUKS1 calls it with wipe_block not aligned to multiple of bsize */
	bsize = device_block_size(cd, device);
	alignment = device_alignment(device);
	if (!bsize || !alignment || !wipe_block_size)
		return -EINVAL;

	/* FIXME: if wipe_block_size < bsize, then a wipe is highly ineffective */

	/* Everything must be aligned to SECTOR_SIZE */
	if (MISALIGNED_512(offset) || MISALIGNED_512(length) || MISALIGNED_512(wipe_block_size))
		return -EINVAL;

	if (device_is_locked(device))
		devfd = device_open_locked(cd, device, O_RDWR);
	else
		devfd = device_open(cd, device, O_RDWR);
	if (devfd < 0)
		return errno ? -errno : -EINVAL;

	if (length)
		dev_size = offset + length;
	else {
		r = device_size(device, &dev_size);
		if (r)
			goto out;

		if (dev_size <= offset) {
			r = -EINVAL;
			goto out;
		}
	}

	r = posix_memalign((void **)&sf, alignment, wipe_block_size);
	if (r)
		goto out;

	if (lseek64(devfd, offset, SEEK_SET) < 0) {
		log_err(cd, _("Cannot seek to device offset."));
		r = -EINVAL;
		goto out;
	}

	if (progress && progress(dev_size, offset, usrptr)) {
		r = -EINVAL; /* No change yet, treat this as a parameter error */
		goto out;
	}

	if (pattern == CRYPT_WIPE_SPECIAL && !device_is_rotational(device)) {
		log_dbg(cd, "Non-rotational device, using random data wipe mode.");
		pattern = CRYPT_WIPE_RANDOM;
	}

	while (offset < dev_size) {
		if ((offset + wipe_block_size) > dev_size)
			wipe_block_size = dev_size - offset;

		//log_dbg("Wipe %012" PRIu64 "-%012" PRIu64 " bytes", offset, offset + wipe_block_size);

		r = wipe_block(cd, devfd, pattern, sf, bsize, alignment,
			       wipe_block_size, offset, &need_block_init);
		if (r) {
			log_err(cd,_("Device wipe error, offset %" PRIu64 "."), offset);
			break;
		}

		offset += wipe_block_size;

		if (progress && progress(dev_size, offset, usrptr)) {
			r = -EINTR;
			break;
		}
	}

	device_sync(cd, device);
out:
	free(sf);
	return r;
}

int crypt_wipe(struct crypt_device *cd,
	const char *dev_path,
	crypt_wipe_pattern pattern,
	uint64_t offset,
	uint64_t length,
	size_t wipe_block_size,
	uint32_t flags,
	int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
	void *usrptr)
{
	struct device *device;
	int r;

	if (!cd)
		return -EINVAL;

	if (!dev_path)
		device = crypt_data_device(cd);
	else {
		r = device_alloc_no_check(&device, dev_path);
		if (r < 0)
			return r;

		if (flags & CRYPT_WIPE_NO_DIRECT_IO)
			device_disable_direct_io(device);
	}

	if (!wipe_block_size)
		wipe_block_size = 1024*1024;

	log_dbg(cd, "Wipe [%u] device %s, offset %" PRIu64 ", length %" PRIu64 ", block %zu.",
		(unsigned)pattern, device_path(device), offset, length, wipe_block_size);

	r = crypt_wipe_device(cd, device, pattern, offset, length,
			      wipe_block_size, progress, usrptr);

	if (dev_path)
		device_free(cd, device);

	return r;
}
