/*
 * utils - miscellaneous device utilities for cryptsetup
 *
 * Copyright (C) 2004, Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2018, Milan Broz
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
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include "internal.h"

size_t crypt_getpagesize(void)
{
	long r = sysconf(_SC_PAGESIZE);
	return r <= 0 ? DEFAULT_MEM_ALIGNMENT : (size_t)r;
}

unsigned crypt_cpusonline(void)
{
	long r = sysconf(_SC_NPROCESSORS_ONLN);
	return r < 0 ? 1 : r;
}

uint64_t crypt_getphysmemory_kb(void)
{
	long pagesize, phys_pages;
	uint64_t phys_memory_kb;

	pagesize = sysconf(_SC_PAGESIZE);
	phys_pages = sysconf(_SC_PHYS_PAGES);

	if (pagesize < 0 || phys_pages < 0)
		return 0;

	phys_memory_kb = pagesize / 1024;
	phys_memory_kb *= phys_pages;

	return phys_memory_kb;
}

ssize_t read_buffer(int fd, void *buf, size_t count)
{
	size_t read_size = 0;
	ssize_t r;

	if (fd < 0 || !buf)
		return -EINVAL;

	do {
		r = read(fd, buf, count - read_size);
		if (r == -1 && errno != EINTR)
			return r;
		if (r == 0)
			return (ssize_t)read_size;
		if (r > 0) {
			read_size += (size_t)r;
			buf = (uint8_t*)buf + r;
		}
	} while (read_size != count);

	return (ssize_t)count;
}

ssize_t write_buffer(int fd, const void *buf, size_t count)
{
	size_t write_size = 0;
	ssize_t w;

	if (fd < 0 || !buf || !count)
		return -EINVAL;

	do {
		w = write(fd, buf, count - write_size);
		if (w < 0 && errno != EINTR)
			return w;
		if (w == 0)
			return (ssize_t)write_size;
		if (w > 0) {
			write_size += (size_t) w;
			buf = (const uint8_t*)buf + w;
		}
	} while (write_size != count);

	return (ssize_t)write_size;
}

ssize_t write_blockwise(int fd, size_t bsize, size_t alignment,
			void *orig_buf, size_t count)
{
	void *hangover_buf = NULL, *buf = NULL;
	size_t hangover, solid;
	ssize_t r, ret = -1;

	if (fd == -1 || !orig_buf || !bsize || !alignment)
		return -1;

	hangover = count % bsize;
	solid = count - hangover;

	if ((size_t)orig_buf & (alignment - 1)) {
		if (posix_memalign(&buf, alignment, count))
			return -1;
		memcpy(buf, orig_buf, count);
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

		r = read_buffer(fd, hangover_buf, bsize);
		if (r < 0 || r < (ssize_t)hangover)
			goto out;

		if (r < (ssize_t)bsize)
			bsize = r;

		if (lseek(fd, -(off_t)bsize, SEEK_CUR) < 0)
			goto out;

		memcpy(hangover_buf, (char*)buf + solid, hangover);

		r = write_buffer(fd, hangover_buf, bsize);
		if (r < 0 || r < (ssize_t)hangover)
			goto out;
	}
	ret = count;
out:
	free(hangover_buf);
	if (buf != orig_buf)
		free(buf);
	return ret;
}

ssize_t read_blockwise(int fd, size_t bsize, size_t alignment,
		       void *orig_buf, size_t count)
{
	void *hangover_buf = NULL, *buf = NULL;
	size_t hangover, solid;
	ssize_t r, ret = -1;

	if (fd == -1 || !orig_buf || !bsize || !alignment)
		return -1;

	hangover = count % bsize;
	solid = count - hangover;

	if ((size_t)orig_buf & (alignment - 1)) {
		if (posix_memalign(&buf, alignment, count))
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
	ret = count;
out:
	free(hangover_buf);
	if (buf != orig_buf) {
		memcpy(orig_buf, buf, count);
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
			      void *buf, size_t count, off_t offset)
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

	if (frontHang) {
		if (posix_memalign(&frontPadBuf, alignment, bsize))
			return -1;

		innerCount = bsize - frontHang;
		if (innerCount > count)
			innerCount = count;

		r = read_buffer(fd, frontPadBuf, bsize);
		if (r < 0 || r < (ssize_t)(frontHang + innerCount))
			goto out;

		memcpy((char*)frontPadBuf + frontHang, buf, innerCount);

		if (lseek(fd, offset - frontHang, SEEK_SET) < 0)
			goto out;

		r = write_buffer(fd, frontPadBuf, frontHang + innerCount);
		if (r < 0 || r != (ssize_t)(frontHang + innerCount))
			goto out;

		buf = (char*)buf + innerCount;
		count -= innerCount;
	}

	ret = count ? write_blockwise(fd, bsize, alignment, buf, count) : 0;
	if (ret >= 0)
		ret += innerCount;
out:
	free(frontPadBuf);
	return ret;
}

ssize_t read_lseek_blockwise(int fd, size_t bsize, size_t alignment,
			     void *buf, size_t count, off_t offset)
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

	if (frontHang) {
		if (posix_memalign(&frontPadBuf, alignment, bsize))
			return -1;

		innerCount = bsize - frontHang;
		if (innerCount > count)
			innerCount = count;

		r = read_buffer(fd, frontPadBuf, bsize);
		if (r < 0 || r < (ssize_t)(frontHang + innerCount))
			goto out;

		memcpy(buf, (char*)frontPadBuf + frontHang, innerCount);

		buf = (char*)buf + innerCount;
		count -= innerCount;
	}

	ret = read_blockwise(fd, bsize, alignment, buf, count);
	if (ret >= 0)
		ret += innerCount;
out:
	free(frontPadBuf);
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

/* Keyfile processing */

/*
 * A simple call to lseek(3) might not be possible for some inputs (e.g.
 * reading from a pipe), so this function instead reads of up to BUFSIZ bytes
 * at a time until the specified number of bytes. It returns -1 on read error
 * or when it reaches EOF before the requested number of bytes have been
 * discarded.
 */
static int keyfile_seek(int fd, uint64_t bytes)
{
	char tmp[BUFSIZ];
	size_t next_read;
	ssize_t bytes_r;
	off64_t r;

	r = lseek64(fd, bytes, SEEK_CUR);
	if (r > 0)
		return 0;
	if (r < 0 && errno != ESPIPE)
		return -1;

	while (bytes > 0) {
		/* figure out how much to read */
		next_read = bytes > sizeof(tmp) ? sizeof(tmp) : (size_t)bytes;

		bytes_r = read(fd, tmp, next_read);
		if (bytes_r < 0) {
			if (errno == EINTR)
				continue;

			crypt_memzero(tmp, sizeof(tmp));
			/* read error */
			return -1;
		}

		if (bytes_r == 0)
			/* EOF */
			break;

		bytes -= bytes_r;
	}

	crypt_memzero(tmp, sizeof(tmp));
	return bytes == 0 ? 0 : -1;
}

int crypt_keyfile_device_read(struct crypt_device *cd,  const char *keyfile,
			      char **key, size_t *key_size_read,
			      uint64_t keyfile_offset, size_t keyfile_size_max,
			      uint32_t flags)
{
	int fd, regular_file, char_to_read = 0, char_read = 0, unlimited_read = 0;
	int r = -EINVAL, newline;
	char *pass = NULL;
	size_t buflen, i;
	uint64_t file_read_size;
	struct stat st;

	if (!key || !key_size_read)
		return -EINVAL;

	*key = NULL;
	*key_size_read = 0;

	fd = keyfile ? open(keyfile, O_RDONLY) : STDIN_FILENO;
	if (fd < 0) {
		log_err(cd, _("Failed to open key file.\n"));
		return -EINVAL;
	}

	if (isatty(fd)) {
		log_err(cd, _("Cannot read keyfile from a terminal.\n"));
		r = -EINVAL;
		goto out_err;
	}

	/* If not requested otherwise, we limit input to prevent memory exhaustion */
	if (keyfile_size_max == 0) {
		keyfile_size_max = DEFAULT_KEYFILE_SIZE_MAXKB * 1024 + 1;
		unlimited_read = 1;
		/* use 4k for buffer (page divisor but avoid huge pages) */
		buflen = 4096 - sizeof(struct safe_allocation);
	} else
		buflen = keyfile_size_max;

	regular_file = 0;
	if (keyfile) {
		if (stat(keyfile, &st) < 0) {
			log_err(cd, _("Failed to stat key file.\n"));
			goto out_err;
		}
		if (S_ISREG(st.st_mode)) {
			regular_file = 1;
			file_read_size = (uint64_t)st.st_size;

			if (keyfile_offset > file_read_size) {
				log_err(cd, _("Cannot seek to requested keyfile offset.\n"));
				goto out_err;
			}
			file_read_size -= keyfile_offset;

			/* known keyfile size, alloc it in one step */
			if (file_read_size >= (uint64_t)keyfile_size_max)
				buflen = keyfile_size_max;
			else if (file_read_size)
				buflen = file_read_size;
		}
	}

	pass = crypt_safe_alloc(buflen);
	if (!pass) {
		log_err(cd, _("Out of memory while reading passphrase.\n"));
		goto out_err;
	}

	/* Discard keyfile_offset bytes on input */
	if (keyfile_offset && keyfile_seek(fd, keyfile_offset) < 0) {
		log_err(cd, _("Cannot seek to requested keyfile offset.\n"));
		goto out_err;
	}

	for (i = 0, newline = 0; i < keyfile_size_max; i += char_read) {
		if (i == buflen) {
			buflen += 4096;
			pass = crypt_safe_realloc(pass, buflen);
			if (!pass) {
				log_err(cd, _("Out of memory while reading passphrase.\n"));
				r = -ENOMEM;
				goto out_err;
			}
		}

		if (flags & CRYPT_KEYFILE_STOP_EOL) {
			/* If we should stop on newline, we must read the input
			 * one character at the time. Otherwise we might end up
			 * having read some bytes after the newline, which we
			 * promised not to do.
			 */
			char_to_read = 1;
		} else {
			/* char_to_read = min(keyfile_size_max - i, buflen - i) */
			char_to_read = keyfile_size_max < buflen ?
				keyfile_size_max - i : buflen - i;
		}
		char_read = read_buffer(fd, &pass[i], char_to_read);
		if (char_read < 0) {
			log_err(cd, _("Error reading passphrase.\n"));
			r = -EPIPE;
			goto out_err;
		}

		if (char_read == 0)
			break;
		/* Stop on newline only if not requested read from keyfile */
		if ((flags & CRYPT_KEYFILE_STOP_EOL) && pass[i] == '\n') {
			newline = 1;
			pass[i] = '\0';
			break;
		}
	}

	/* Fail if piped input dies reading nothing */
	if (!i && !regular_file && !newline) {
		log_dbg("Nothing read on input.");
		r = -EPIPE;
		goto out_err;
	}

	/* Fail if we exceeded internal default (no specified size) */
	if (unlimited_read && i == keyfile_size_max) {
		log_err(cd, _("Maximum keyfile size exceeded.\n"));
		goto out_err;
	}

	if (!unlimited_read && i != keyfile_size_max) {
		log_err(cd, _("Cannot read requested amount of data.\n"));
		goto out_err;
	}

	*key = pass;
	*key_size_read = i;
	r = 0;
out_err:
	if (fd != STDIN_FILENO)
		close(fd);

	if (r)
		crypt_safe_free(pass);
	return r;
}

int crypt_keyfile_read(struct crypt_device *cd,  const char *keyfile,
		       char **key, size_t *key_size_read,
		       size_t keyfile_offset, size_t keyfile_size_max,
		       uint32_t flags)
{
	return crypt_keyfile_device_read(cd, keyfile, key, key_size_read,
					 keyfile_offset, keyfile_size_max, flags);
}

int kernel_version(uint64_t *kversion)
{
	struct utsname uts;
	uint16_t maj, min, patch, rel;
	int r = -EINVAL;

	if (uname(&uts) < 0)
		return r;

	if (sscanf(uts.release, "%" SCNu16  ".%" SCNu16 ".%" SCNu16 "-%" SCNu16,
		   &maj, &min, &patch, &rel) == 4)
		r = 0;
	else if (sscanf(uts.release,  "%" SCNu16 ".%" SCNu16 ".%" SCNu16,
			&maj, &min, &patch) == 3) {
		rel = 0;
		r = 0;
	}

	if (!r)
		*kversion = version(maj, min, patch, rel);

	return r;
}
