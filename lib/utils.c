/*
 * utils - miscellaneous device utilities for cryptsetup
 *
 * Copyright (C) 2004, Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
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
#include <sys/mman.h>
#include <sys/resource.h>

#include "internal.h"

unsigned crypt_getpagesize(void)
{
	long r = sysconf(_SC_PAGESIZE);
	return r < 0 ? DEFAULT_MEM_ALIGNMENT : r;
}

static int get_alignment(int fd)
{
	int alignment = DEFAULT_MEM_ALIGNMENT;

#ifdef _PC_REC_XFER_ALIGN
	alignment = fpathconf(fd, _PC_REC_XFER_ALIGN);
	if (alignment < 0)
		alignment = DEFAULT_MEM_ALIGNMENT;
#endif
	return alignment;
}

static void *aligned_malloc(void **base, int size, int alignment)
{
#ifdef HAVE_POSIX_MEMALIGN
	return posix_memalign(base, alignment, size) ? NULL : *base;
#else
/* Credits go to Michal's padlock patches for this alignment code */
	char *ptr;

	ptr  = malloc(size + alignment);
	if(ptr == NULL) return NULL;

	*base = ptr;
	if(alignment > 1 && ((long)ptr & (alignment - 1))) {
		ptr += alignment - ((long)(ptr) & (alignment - 1));
	}
	return ptr;
#endif
}

ssize_t write_blockwise(int fd, int bsize, void *orig_buf, size_t count)
{
	void *hangover_buf, *hangover_buf_base = NULL;
	void *buf, *buf_base = NULL;
	int r, hangover, solid, alignment;
	ssize_t ret = -1;

	if (fd == -1 || !orig_buf || bsize <= 0)
		return -1;

	hangover = count % bsize;
	solid = count - hangover;
	alignment = get_alignment(fd);

	if ((long)orig_buf & (alignment - 1)) {
		buf = aligned_malloc(&buf_base, count, alignment);
		if (!buf)
			goto out;
		memcpy(buf, orig_buf, count);
	} else
		buf = orig_buf;

	r = write(fd, buf, solid);
	if (r < 0 || r != solid)
		goto out;

	if (hangover) {
		hangover_buf = aligned_malloc(&hangover_buf_base, bsize, alignment);
		if (!hangover_buf)
			goto out;

		r = read(fd, hangover_buf, bsize);
		if (r < 0 || r < hangover)
			goto out;

		if (r < bsize)
			bsize = r;

		r = lseek(fd, -bsize, SEEK_CUR);
		if (r < 0)
			goto out;
		memcpy(hangover_buf, (char*)buf + solid, hangover);

		r = write(fd, hangover_buf, bsize);
		if (r < 0 || r < hangover)
			goto out;
	}
	ret = count;
out:
	free(hangover_buf_base);
	if (buf != orig_buf)
		free(buf_base);
	return ret;
}

ssize_t read_blockwise(int fd, int bsize, void *orig_buf, size_t count) {
	void *hangover_buf, *hangover_buf_base = NULL;
	void *buf, *buf_base = NULL;
	int r, hangover, solid, alignment;
	ssize_t ret = -1;

	if (fd == -1 || !orig_buf || bsize <= 0)
		return -1;

	hangover = count % bsize;
	solid = count - hangover;
	alignment = get_alignment(fd);

	if ((long)orig_buf & (alignment - 1)) {
		buf = aligned_malloc(&buf_base, count, alignment);
		if (!buf)
			return -1;
	} else
		buf = orig_buf;

	r = read(fd, buf, solid);
	if(r < 0 || r != solid)
		goto out;

	if (hangover) {
		hangover_buf = aligned_malloc(&hangover_buf_base, bsize, alignment);
		if (!hangover_buf)
			goto out;
		r = read(fd, hangover_buf, bsize);
		if (r <  0 || r < hangover)
			goto out;

		memcpy((char *)buf + solid, hangover_buf, hangover);
	}
	ret = count;
out:
	free(hangover_buf_base);
	if (buf != orig_buf) {
		memcpy(orig_buf, buf, count);
		free(buf_base);
	}
	return ret;
}

/*
 * Combines llseek with blockwise write. write_blockwise can already deal with short writes
 * but we also need a function to deal with short writes at the start. But this information
 * is implicitly included in the read/write offset, which can not be set to non-aligned
 * boundaries. Hence, we combine llseek with write.
 */
ssize_t write_lseek_blockwise(int fd, int bsize, char *buf, size_t count, off_t offset) {
	char *frontPadBuf;
	void *frontPadBuf_base = NULL;
	int r, frontHang;
	size_t innerCount = 0;
	ssize_t ret = -1;

	if (fd == -1 || !buf || bsize <= 0)
		return -1;

	frontHang = offset % bsize;

	if (lseek(fd, offset - frontHang, SEEK_SET) < 0)
		goto out;

	if (frontHang) {
		frontPadBuf = aligned_malloc(&frontPadBuf_base,
					     bsize, get_alignment(fd));
		if (!frontPadBuf)
			goto out;

		r = read(fd, frontPadBuf, bsize);
		if (r < 0 || r != bsize)
			goto out;

		innerCount = bsize - frontHang;
		if (innerCount > count)
			innerCount = count;

		memcpy(frontPadBuf + frontHang, buf, innerCount);

		if (lseek(fd, offset - frontHang, SEEK_SET) < 0)
			goto out;

		r = write(fd, frontPadBuf, bsize);
		if (r < 0 || r != bsize)
			goto out;

		buf += innerCount;
		count -= innerCount;
	}

	ret = count ? write_blockwise(fd, bsize, buf, count) : 0;
	if (ret >= 0)
		ret += innerCount;
out:
	free(frontPadBuf_base);

	return ret;
}

/* MEMLOCK */
#define DEFAULT_PROCESS_PRIORITY -18

static int _priority;
static int _memlock_count = 0;

// return 1 if memory is locked
int crypt_memlock_inc(struct crypt_device *ctx)
{
	if (!_memlock_count++) {
		log_dbg("Locking memory.");
		if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1) {
			log_dbg("Cannot lock memory with mlockall.");
			_memlock_count--;
			return 0;
		}
		errno = 0;
		if (((_priority = getpriority(PRIO_PROCESS, 0)) == -1) && errno)
			log_err(ctx, _("Cannot get process priority.\n"));
		else
			if (setpriority(PRIO_PROCESS, 0, DEFAULT_PROCESS_PRIORITY))
				log_dbg("setpriority %d failed: %s",
					DEFAULT_PROCESS_PRIORITY, strerror(errno));
	}
	return _memlock_count ? 1 : 0;
}

int crypt_memlock_dec(struct crypt_device *ctx)
{
	if (_memlock_count && (!--_memlock_count)) {
		log_dbg("Unlocking memory.");
		if (munlockall() == -1)
			log_err(ctx, _("Cannot unlock memory.\n"));
		if (setpriority(PRIO_PROCESS, 0, _priority))
			log_dbg("setpriority %d failed: %s", _priority, strerror(errno));
	}
	return _memlock_count ? 1 : 0;
}
