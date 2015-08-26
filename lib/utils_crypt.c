/*
 * utils_crypt - cipher utilities for cryptsetup
 *
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

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "libcryptsetup.h"
#include "nls.h"
#include "utils_crypt.h"

#define log_dbg(x) crypt_log(NULL, CRYPT_LOG_DEBUG, x)
#define log_err(cd, x) crypt_log(cd, CRYPT_LOG_ERROR, x)

struct safe_allocation {
	size_t	size;
	char	data[0];
};

int crypt_parse_name_and_mode(const char *s, char *cipher, int *key_nums,
			      char *cipher_mode)
{
	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]-%" MAX_CIPHER_LEN_STR "s",
		   cipher, cipher_mode) == 2) {
		if (!strcmp(cipher_mode, "plain"))
			strncpy(cipher_mode, "cbc-plain", 10);
		if (key_nums) {
			char *tmp = strchr(cipher, ':');
			*key_nums = tmp ? atoi(++tmp) : 1;
			if (!*key_nums)
				return -EINVAL;
		}

		return 0;
	}

	/* Short version for "empty" cipher */
	if (!strcmp(s, "null")) {
		strncpy(cipher, "cipher_null", MAX_CIPHER_LEN);
		strncpy(cipher_mode, "ecb", 9);
		if (key_nums)
			*key_nums = 0;
		return 0;
	}

	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]", cipher) == 1) {
		strncpy(cipher_mode, "cbc-plain", 10);
		if (key_nums)
			*key_nums = 1;
		return 0;
	}

	return -EINVAL;
}

/*
 * Replacement for memset(s, 0, n) on stack that can be optimized out
 * Also used in safe allocations for explicit memory wipe.
 */
void crypt_memzero(void *s, size_t n)
{
	volatile uint8_t *p = (volatile uint8_t *)s;

	while(n--)
		*p++ = 0;
}

/* safe allocations */
void *crypt_safe_alloc(size_t size)
{
	struct safe_allocation *alloc;

	if (!size)
		return NULL;

	alloc = malloc(size + offsetof(struct safe_allocation, data));
	if (!alloc)
		return NULL;

	alloc->size = size;
	crypt_memzero(&alloc->data, size);

	/* coverity[leaked_storage] */
	return &alloc->data;
}

void crypt_safe_free(void *data)
{
	struct safe_allocation *alloc;

	if (!data)
		return;

	alloc = (struct safe_allocation *)
		((char *)data - offsetof(struct safe_allocation, data));

	crypt_memzero(data, alloc->size);

	alloc->size = 0x55aa55aa;
	free(alloc);
}

void *crypt_safe_realloc(void *data, size_t size)
{
	struct safe_allocation *alloc;
	void *new_data;

	new_data = crypt_safe_alloc(size);

	if (new_data && data) {

		alloc = (struct safe_allocation *)
			((char *)data - offsetof(struct safe_allocation, data));

		if (size > alloc->size)
			size = alloc->size;

		memcpy(new_data, data, size);
	}

	crypt_safe_free(data);
	return new_data;
}

/*
 * A simple call to lseek(3) might not be possible for some inputs (e.g.
 * reading from a pipe), so this function instead reads of up to BUFSIZ bytes
 * at a time until the specified number of bytes. It returns -1 on read error
 * or when it reaches EOF before the requested number of bytes have been
 * discarded.
 */
static int keyfile_seek(int fd, size_t bytes)
{
	char tmp[BUFSIZ];
	size_t next_read;
	ssize_t bytes_r;
	off_t r;

	r = lseek(fd, bytes, SEEK_CUR);
	if (r > 0)
		return 0;
	if (r < 0 && errno != ESPIPE)
		return -1;

	while (bytes > 0) {
		/* figure out how much to read */
		next_read = bytes > sizeof(tmp) ? sizeof(tmp) : bytes;

		bytes_r = read(fd, tmp, next_read);
		if (bytes_r < 0) {
			if (errno == EINTR)
				continue;

			/* read error */
			return -1;
		}

		if (bytes_r == 0)
			/* EOF */
			break;

		bytes -= bytes_r;
	}

	return bytes == 0 ? 0 : -1;
}

int crypt_keyfile_read(struct crypt_device *cd,  const char *keyfile,
		       char **key, size_t *key_size_read,
		       size_t keyfile_offset, size_t keyfile_size_max,
		       uint32_t flags)
{
	int fd, regular_file, char_read, unlimited_read = 0;
	int r = -EINVAL, newline;
	char *pass = NULL;
	size_t buflen, i, file_read_size;
	struct stat st;

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

	/* If not requsted otherwise, we limit input to prevent memory exhaustion */
	if (keyfile_size_max == 0) {
		keyfile_size_max = DEFAULT_KEYFILE_SIZE_MAXKB * 1024;
		unlimited_read = 1;
	}

	/* use 4k for buffer (page divisor but avoid huge pages) */
	buflen = 4096 - sizeof(struct safe_allocation);
	regular_file = 0;
	if (keyfile) {
		if(stat(keyfile, &st) < 0) {
			log_err(cd, _("Failed to stat key file.\n"));
			goto out_err;
		}
		if(S_ISREG(st.st_mode)) {
			regular_file = 1;
			file_read_size = (size_t)st.st_size;

			if (keyfile_offset > file_read_size) {
				log_err(cd, _("Cannot seek to requested keyfile offset.\n"));
				goto out_err;
			}
			file_read_size -= keyfile_offset;

			/* known keyfile size, alloc it in one step */
			if (file_read_size >= keyfile_size_max)
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

	for(i = 0, newline = 0; i < keyfile_size_max; i++) {
		if(i == buflen) {
			buflen += 4096;
			pass = crypt_safe_realloc(pass, buflen);
			if (!pass) {
				log_err(cd, _("Out of memory while reading passphrase.\n"));
				r = -ENOMEM;
				goto out_err;
			}
		}

		char_read = read(fd, &pass[i], 1);
		if (char_read < 0) {
			log_err(cd, _("Error reading passphrase.\n"));
			goto out_err;
		}

		/* Stop on newline only if not requested read from keyfile */
		if (char_read == 0)
			break;
		if ((flags & CRYPT_KEYFILE_STOP_EOL) && pass[i] == '\n') {
			newline = 1;
			pass[i] = '\0';
			break;
		}
	}

	/* Fail if piped input dies reading nothing */
	if(!i && !regular_file && !newline) {
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
	if(fd != STDIN_FILENO)
		close(fd);

	if (r)
		crypt_safe_free(pass);
	return r;
}

ssize_t crypt_hex_to_bytes(const char *hex, char **result, int safe_alloc)
{
	char buf[3] = "xx\0", *endp, *bytes;
	size_t i, len;

	len = strlen(hex);
	if (len % 2)
		return -EINVAL;
	len /= 2;

	bytes = safe_alloc ? crypt_safe_alloc(len) : malloc(len);
	if (!bytes)
		return -ENOMEM;

	for (i = 0; i < len; i++) {
		memcpy(buf, &hex[i * 2], 2);
		bytes[i] = strtoul(buf, &endp, 16);
		if (endp != &buf[2]) {
			safe_alloc ? crypt_safe_free(bytes) : free(bytes);
			return -EINVAL;
		}
	}
	*result = bytes;
	return i;
}
