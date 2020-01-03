/*
 * utils - miscellaneous I/O utilities for cryptsetup
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
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

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#include "utils_io.h"

static ssize_t _read_buffer(int fd, void *buf, size_t length, volatile int *quit)
{
	size_t read_size = 0;
	ssize_t r;

	if (fd < 0 || !buf)
		return -EINVAL;

	do {
		r = read(fd, buf, length - read_size);
		if (r == -1 && errno != EINTR)
			return r;
		if (r > 0) {
			read_size += (size_t)r;
			buf = (uint8_t*)buf + r;
		}
		if (r == 0 || (quit && *quit))
			return (ssize_t)read_size;
	} while (read_size != length);

	return (ssize_t)length;
}

ssize_t read_buffer(int fd, void *buf, size_t length)
{
	return _read_buffer(fd, buf, length, NULL);
}

ssize_t read_buffer_intr(int fd, void *buf, size_t length, volatile int *quit)
{
	return _read_buffer(fd, buf, length, quit);
}

static ssize_t _write_buffer(int fd, const void *buf, size_t length, volatile int *quit)
{
	size_t write_size = 0;
	ssize_t w;

	if (fd < 0 || !buf || !length)
		return -EINVAL;

	do {
		w = write(fd, buf, length - write_size);
		if (w < 0 && errno != EINTR)
			return w;
		if (w > 0) {
			write_size += (size_t) w;
			buf = (const uint8_t*)buf + w;
		}
		if (w == 0 || (quit && *quit))
			return (ssize_t)write_size;
	} while (write_size != length);

	return (ssize_t)write_size;
}

ssize_t write_buffer(int fd, const void *buf, size_t length)
{
	return _write_buffer(fd, buf, length, NULL);
}

ssize_t write_buffer_intr(int fd, const void *buf, size_t length, volatile int *quit)
{
	return _write_buffer(fd, buf, length, quit);
}

ssize_t write_blockwise(int fd, size_t bsize, size_t alignment,
			void *orig_buf, size_t length)
{
	void *hangover_buf = NULL, *buf = NULL;
	size_t hangover, solid;
	ssize_t r, ret = -1;

	if (fd == -1 || !orig_buf || !bsize || !alignment)
		return -1;

	hangover = length % bsize;
	solid = length - hangover;

	if ((size_t)orig_buf & (alignment - 1)) {
		if (posix_memalign(&buf, alignment, length))
			return -1;
		memcpy(buf, orig_buf, length);
	} else
		buf = orig_buf;

	if (solid) {
		r = write_buffer(fd, buf, solid);
		if (r < 0 || r != (ssize_t)solid)
			goto out;
	}

	if (hangover) {
		if (posix_memalign(&hangover_buf, alignment, bsize))
			goto out;
		memset(hangover_buf, 0, bsize);

		r = read_buffer(fd, hangover_buf, bsize);
		if (r < 0)
			goto out;

		if (lseek(fd, -(off_t)r, SEEK_CUR) < 0)
			goto out;

		memcpy(hangover_buf, (char*)buf + solid, hangover);

		r = write_buffer(fd, hangover_buf, bsize);
		if (r < 0 || r < (ssize_t)hangover)
			goto out;
	}
	ret = length;
out:
	free(hangover_buf);
	if (buf != orig_buf)
		free(buf);
	return ret;
}

ssize_t read_blockwise(int fd, size_t bsize, size_t alignment,
		       void *orig_buf, size_t length)
{
	void *hangover_buf = NULL, *buf = NULL;
	size_t hangover, solid;
	ssize_t r, ret = -1;

	if (fd == -1 || !orig_buf || !bsize || !alignment)
		return -1;

	hangover = length % bsize;
	solid = length - hangover;

	if ((size_t)orig_buf & (alignment - 1)) {
		if (posix_memalign(&buf, alignment, length))
			return -1;
	} else
		buf = orig_buf;

	r = read_buffer(fd, buf, solid);
	if (r < 0 || r != (ssize_t)solid)
		goto out;

	if (hangover) {
		if (posix_memalign(&hangover_buf, alignment, bsize))
			goto out;
		r = read_buffer(fd, hangover_buf, bsize);
		if (r <  0 || r < (ssize_t)hangover)
			goto out;

		memcpy((char *)buf + solid, hangover_buf, hangover);
	}
	ret = length;
out:
	free(hangover_buf);
	if (buf != orig_buf) {
		if (ret != -1)
			memcpy(orig_buf, buf, length);
		free(buf);
	}
	return ret;
}

/*
 * Combines llseek with blockwise write. write_blockwise can already deal with short writes
 * but we also need a function to deal with short writes at the start. But this information
 * is implicitly included in the read/write offset, which can not be set to non-aligned
 * boundaries. Hence, we combine llseek with write.
 */
ssize_t write_lseek_blockwise(int fd, size_t bsize, size_t alignment,
			      void *buf, size_t length, off_t offset)
{
	void *frontPadBuf = NULL;
	size_t frontHang, innerCount = 0;
	ssize_t r, ret = -1;

	if (fd == -1 || !buf || !bsize || !alignment)
		return -1;

	if (offset < 0)
		offset = lseek(fd, offset, SEEK_END);

	if (offset < 0)
		return -1;

	frontHang = offset % bsize;

	if (lseek(fd, offset - frontHang, SEEK_SET) < 0)
		return -1;

	if (frontHang && length) {
		if (posix_memalign(&frontPadBuf, alignment, bsize))
			return -1;

		innerCount = bsize - frontHang;
		if (innerCount > length)
			innerCount = length;

		r = read_buffer(fd, frontPadBuf, bsize);
		if (r < 0 || r < (ssize_t)(frontHang + innerCount))
			goto out;

		memcpy((char*)frontPadBuf + frontHang, buf, innerCount);

		if (lseek(fd, offset - frontHang, SEEK_SET) < 0)
			goto out;

		r = write_buffer(fd, frontPadBuf, bsize);
		if (r < 0 || r != (ssize_t)bsize)
			goto out;

		buf = (char*)buf + innerCount;
		length -= innerCount;
	}

	ret = length ? write_blockwise(fd, bsize, alignment, buf, length) : 0;
	if (ret >= 0)
		ret += innerCount;
out:
	free(frontPadBuf);
	return ret;
}

ssize_t read_lseek_blockwise(int fd, size_t bsize, size_t alignment,
			     void *buf, size_t length, off_t offset)
{
	void *frontPadBuf = NULL;
	size_t frontHang, innerCount = 0;
	ssize_t r, ret = -1;

	if (fd == -1 || !buf || bsize <= 0)
		return -1;

	if (offset < 0)
		offset = lseek(fd, offset, SEEK_END);

	if (offset < 0)
		return -1;

	frontHang = offset % bsize;

	if (lseek(fd, offset - frontHang, SEEK_SET) < 0)
		return -1;

	if (frontHang && length) {
		if (posix_memalign(&frontPadBuf, alignment, bsize))
			return -1;

		innerCount = bsize - frontHang;
		if (innerCount > length)
			innerCount = length;

		r = read_buffer(fd, frontPadBuf, bsize);
		if (r < 0 || r < (ssize_t)(frontHang + innerCount))
			goto out;

		memcpy(buf, (char*)frontPadBuf + frontHang, innerCount);

		buf = (char*)buf + innerCount;
		length -= innerCount;
	}

	ret = read_blockwise(fd, bsize, alignment, buf, length);
	if (ret >= 0)
		ret += innerCount;
out:
	free(frontPadBuf);
	return ret;
}
