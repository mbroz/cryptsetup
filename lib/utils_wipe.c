/*
 * utils_wipe - wipe a device
 *
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2011-2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2012, Milan Broz
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
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "libcryptsetup.h"
#include "internal.h"

#define MAXIMUM_WIPE_BYTES	1024 * 1024 * 32 /* 32 MiB */

static ssize_t _crypt_wipe_zero(int fd, int bsize, char *buffer,
				uint64_t offset, uint64_t size)
{
	memset(buffer, 0, size);
	return write_lseek_blockwise(fd, bsize, buffer, size, offset);
}

static ssize_t _crypt_wipe_random(int fd, int bsize, char *buffer,
				  uint64_t offset, uint64_t size)
{
	if (crypt_random_get(NULL, buffer, size, CRYPT_RND_NORMAL) < 0)
		return -EINVAL;

	return write_lseek_blockwise(fd, bsize, buffer, size, offset);
}

/*
 * Wipe using Peter Gutmann method described in
 * http://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
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

	for(i = 0; i < buffer_size / 3; ++i) {
		memcpy(buffer, write_modes[turn], 3);
		buffer += 3;
	}
}

static ssize_t _crypt_wipe_disk(int fd, int bsize, char *buffer,
				uint64_t offset, uint64_t size)
{
	int r;
	unsigned int i;
	ssize_t written;

	for(i = 0; i < 39; ++i) {
		if (i <  5) {
			r = crypt_random_get(NULL, buffer, size, CRYPT_RND_NORMAL);
		} else if(i >=  5 && i < 32) {
			wipeSpecial(buffer, size, i - 5);
			r = 0;
		} else if(i >= 32 && i < 38) {
			r = crypt_random_get(NULL, buffer, size, CRYPT_RND_NORMAL);
		} else if(i >= 38 && i < 39) {
			memset(buffer, 0xFF, size);
			r = 0;
		}
		if (r < 0)
			return r;

		written = write_lseek_blockwise(fd, bsize, buffer, size, offset);
		if (written < 0 || written != (ssize_t)size)
			return written;
	}

	/* Rewrite it finally with random */
	return _crypt_wipe_random(fd, bsize, buffer, offset, size);
}

static ssize_t _crypt_wipe_ssd(int fd, int bsize, char *buffer,
			       uint64_t offset, uint64_t size)
{
	// FIXME: for now just rewrite it by random
	return _crypt_wipe_random(fd, bsize, buffer, offset, size);
}

int crypt_wipe(struct device *device,
	       uint64_t offset,
	       uint64_t size,
	       crypt_wipe_type type,
	       int exclusive)
{
	struct stat st;
	char *buffer;
	int devfd, flags, bsize;
	ssize_t written;

	if (!size || size % SECTOR_SIZE || (size > MAXIMUM_WIPE_BYTES)) {
		log_dbg("Unsuported wipe size for device %s: %ld.",
			device_path(device), (unsigned long)size);
		return -EINVAL;
	}

	if (stat(device_path(device), &st) < 0) {
		log_dbg("Device %s not found.", device_path(device));
		return -EINVAL;
	}

	if (type == CRYPT_WIPE_DISK && S_ISBLK(st.st_mode)) {
		if (!crypt_dev_is_rotational(major(st.st_rdev),
						minor(st.st_rdev))) {
			type = CRYPT_WIPE_SSD;
			log_dbg("Non-rotational device, using SSD wipe mode.");
		} else
			log_dbg("Rotational device, using normal wipe mode.");
	}

	bsize = device_block_size(device);
	if (bsize <= 0)
		return -EINVAL;

	buffer = malloc(size);
	if (!buffer)
		return -ENOMEM;

	flags = O_RDWR;

	/* use O_EXCL only for block devices */
	if (exclusive && S_ISBLK(st.st_mode))
		flags |= O_EXCL;

	/* coverity[toctou] */
	devfd = device_open(device, flags);
	if (devfd == -1) {
		free(buffer);
		return errno ? -errno : -EINVAL;
	}

	// FIXME: use fixed block size and loop here
	switch (type) {
		case CRYPT_WIPE_ZERO:
			written = _crypt_wipe_zero(devfd, bsize, buffer, offset, size);
			break;
		case CRYPT_WIPE_DISK:
			written = _crypt_wipe_disk(devfd, bsize, buffer, offset, size);
			break;
		case CRYPT_WIPE_SSD:
			written = _crypt_wipe_ssd(devfd, bsize, buffer, offset, size);
			break;
		case CRYPT_WIPE_RANDOM:
			written = _crypt_wipe_random(devfd, bsize, buffer, offset, size);
			break;
		default:
			log_dbg("Unsuported wipe type requested: (%d)", type);
			written = -1;
	}

	close(devfd);
	free(buffer);

	if (written != (ssize_t)size || written < 0)
		return -EIO;

	return 0;
}
