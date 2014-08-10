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
#include <termios.h>

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
	memset(&alloc->data, 0, size);

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

	memset(data, 0, alloc->size);

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

/* Password reading helpers */
static int untimed_read(int fd, char *pass, size_t maxlen)
{
	ssize_t i;

	i = read(fd, pass, maxlen);
	if (i > 0) {
		pass[i-1] = '\0';
		i = 0;
	} else if (i == 0) { /* EOF */
		*pass = 0;
		i = -1;
	}
	return i;
}

static int timed_read(int fd, char *pass, size_t maxlen, long timeout)
{
	struct timeval t;
	fd_set fds = {}; /* Just to avoid scan-build false report for FD_SET */
	int failed = -1;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	t.tv_sec = timeout;
	t.tv_usec = 0;

	if (select(fd+1, &fds, NULL, NULL, &t) > 0)
		failed = untimed_read(fd, pass, maxlen);

	return failed;
}

static int interactive_pass(const char *prompt, char *pass, size_t maxlen,
		long timeout)
{
	struct termios orig, tmp;
	int failed = -1;
	int infd, outfd;

	if (maxlen < 1)
		goto out_err;

	/* Read and write to /dev/tty if available */
	infd = open("/dev/tty", O_RDWR);
	if (infd == -1) {
		infd = STDIN_FILENO;
		outfd = STDERR_FILENO;
	} else
		outfd = infd;

	if (tcgetattr(infd, &orig))
		goto out_err;

	memcpy(&tmp, &orig, sizeof(tmp));
	tmp.c_lflag &= ~ECHO;

	if (prompt && write(outfd, prompt, strlen(prompt)) < 0)
		goto out_err;

	tcsetattr(infd, TCSAFLUSH, &tmp);
	if (timeout)
		failed = timed_read(infd, pass, maxlen, timeout);
	else
		failed = untimed_read(infd, pass, maxlen);
	tcsetattr(infd, TCSAFLUSH, &orig);

out_err:
	if (!failed && write(outfd, "\n", 1)) {};

	if (infd != STDIN_FILENO)
		close(infd);
	return failed;
}

static int crypt_get_key_tty(const char *prompt,
			     char **key, size_t *key_size,
			     int timeout, int verify,
			     struct crypt_device *cd)
{
	int key_size_max = DEFAULT_PASSPHRASE_SIZE_MAX;
	int r = -EINVAL;
	char *pass = NULL, *pass_verify = NULL;

	log_dbg("Interactive passphrase entry requested.");

	pass = crypt_safe_alloc(key_size_max + 1);
	if (!pass) {
		log_err(cd, _("Out of memory while reading passphrase.\n"));
		return -ENOMEM;
	}

	if (interactive_pass(prompt, pass, key_size_max, timeout)) {
		log_err(cd, _("Error reading passphrase from terminal.\n"));
		goto out_err;
	}
	pass[key_size_max] = '\0';

	if (verify) {
		pass_verify = crypt_safe_alloc(key_size_max);
		if (!pass_verify) {
			log_err(cd, _("Out of memory while reading passphrase.\n"));
			r = -ENOMEM;
			goto out_err;
		}

		if (interactive_pass(_("Verify passphrase: "),
		    pass_verify, key_size_max, timeout)) {
			log_err(cd, _("Error reading passphrase from terminal.\n"));
			goto out_err;
		}

		if (strncmp(pass, pass_verify, key_size_max)) {
			log_err(cd, _("Passphrases do not match.\n"));
			r = -EPERM;
			goto out_err;
		}
	}

	*key = pass;
	*key_size = strlen(pass);
	r = 0;
out_err:
	crypt_safe_free(pass_verify);
	if (r)
		crypt_safe_free(pass);
	return r;
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

/*
 * Note: --key-file=- is interpreted as a read from a binary file (stdin)
 * key_size_max == 0 means detect maximum according to input type (tty/file)
 * timeout and verify options only applies to tty input
 */
int crypt_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  size_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file, int timeout, int verify,
		  struct crypt_device *cd)
{
	int fd, regular_file, read_stdin, char_read, unlimited_read = 0;
	int r = -EINVAL;
	char *pass = NULL;
	size_t buflen, i, file_read_size;
	struct stat st;

	*key = NULL;
	*key_size = 0;

	/* Passphrase read from stdin? */
	read_stdin = (!key_file || !strcmp(key_file, "-")) ? 1 : 0;

	if (read_stdin && isatty(STDIN_FILENO)) {
		if (keyfile_offset) {
			log_err(cd, _("Cannot use offset with terminal input.\n"));
			return -EINVAL;
		}
		return crypt_get_key_tty(prompt, key, key_size, timeout, verify, cd);
	}

	if (read_stdin)
		log_dbg("STDIN descriptor passphrase entry requested.");
	else
		log_dbg("File descriptor passphrase entry requested.");

	/* If not requsted otherwise, we limit input to prevent memory exhaustion */
	if (keyfile_size_max == 0) {
		keyfile_size_max = DEFAULT_KEYFILE_SIZE_MAXKB * 1024;
		unlimited_read = 1;
	}

	fd = read_stdin ? STDIN_FILENO : open(key_file, O_RDONLY);
	if (fd < 0) {
		log_err(cd, _("Failed to open key file.\n"));
		return -EINVAL;
	}

	/* use 4k for buffer (page divisor but avoid huge pages) */
	buflen = 4096 - sizeof(struct safe_allocation);
	regular_file = 0;
	if(!read_stdin) {
		if(stat(key_file, &st) < 0) {
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

	for(i = 0; i < keyfile_size_max; i++) {
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
		if(char_read == 0 || (!key_file && pass[i] == '\n'))
			break;
	}

	/* Fail if piped input dies reading nothing */
	if(!i && !regular_file) {
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
	*key_size = i;
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

/*
 * Device size string parsing, suffixes:
 * s|S - 512 bytes sectors
 * k  |K  |m  |M  |g  |G  |t  |T   - 1024 base
 * kiB|KiB|miB|MiB|giB|GiB|tiB|TiB - 1024 base
 * kb |KB |mM |MB |gB |GB |tB |TB  - 1000 base
 */
int crypt_string_to_size(struct crypt_device *cd, const char *s, uint64_t *size)
{
	char *endp = NULL;
	size_t len;
	uint64_t mult_base, mult, tmp;

	*size = strtoull(s, &endp, 10);
	if (!isdigit(s[0]) ||
	    (errno == ERANGE && *size == ULLONG_MAX) ||
	    (errno != 0 && *size == 0))
		return -EINVAL;

	if (!endp || !*endp)
		return 0;

	len = strlen(endp);
	/* Allow "B" and "iB" suffixes */
	if (len > 3 ||
	   (len == 3 && (endp[1] != 'i' || endp[2] != 'B')) ||
	   (len == 2 && endp[1] != 'B'))
		return -EINVAL;

	if (len == 1 || len == 3)
		mult_base = 1024;
	else
		mult_base = 1000;

	mult = 1;
	switch (endp[0]) {
	case 's':
	case 'S': mult = 512;
		break;
	case 't':
	case 'T': mult *= mult_base;
		 /* Fall through */
	case 'g':
	case 'G': mult *= mult_base;
		 /* Fall through */
	case 'm':
	case 'M': mult *= mult_base;
		 /* Fall through */
	case 'k':
	case 'K': mult *= mult_base;
		break;
	default:
		return -EINVAL;
	}

	tmp = *size * mult;
	if ((tmp / *size) != mult) {
		log_dbg("Device size overflow.");
		return -EINVAL;
	}

	*size = tmp;
	return 0;
}
