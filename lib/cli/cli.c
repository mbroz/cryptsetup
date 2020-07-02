/*
 * libcryptsetup_cli - cryptsetup command line tools library
 *
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2020 Milan Broz
 * Copyright (C) 2020 Ondrej Kozina
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
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "nls.h"
#include "utils_loop.h"
#include "utils_io.h"
#include "libcryptsetup.h"
#include "libcryptsetup_cli.h"
#include "cli_internal.h"

#define LOG_MAX_LEN 4096

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

#if defined ENABLE_PWQUALITY
#include <pwquality.h>

static int tools_check_pwquality(const char *password)
{
	int r;
	void *auxerror;
	pwquality_settings_t *pwq;

	log_dbg("Checking new password using default pwquality settings.");
	pwq = pwquality_default_settings();
	if (!pwq)
		return -EINVAL;

	r = pwquality_read_config(pwq, NULL, &auxerror);
	if (r) {
		log_err(_("Cannot check password quality: %s"),
			pwquality_strerror(NULL, 0, r, auxerror));
		pwquality_free_settings(pwq);
		return -EINVAL;
	}

	r = pwquality_check(pwq, password, NULL, NULL, &auxerror);
	if (r < 0) {
		log_err(_("Password quality check failed:\n %s"),
			pwquality_strerror(NULL, 0, r, auxerror));
		r = -EPERM;
	} else {
		log_dbg("New password libpwquality score is %d.", r);
		r = 0;
	}

	pwquality_free_settings(pwq);
	return r;
}
#elif defined ENABLE_PASSWDQC
#include <passwdqc.h>

static int tools_check_pwquality(const char *password)
{
	passwdqc_params_t params;
	char *parse_reason;
	const char *check_reason;
	const char *config = PASSWDQC_CONFIG_FILE;

	passwdqc_params_reset(&params);

	if (*config && passwdqc_params_load(&params, &parse_reason, config)) {
		log_err(_("Cannot check password quality: %s"),
			(parse_reason ? parse_reason : "Out of memory"));
		free(parse_reason);
		return -EINVAL;
	}

	check_reason = passwdqc_check(&params.qc, password, NULL, NULL);
	if (check_reason) {
		log_err(_("Password quality check failed: Bad passphrase (%s)"),
			check_reason);
		return -EPERM;
	}

	return 0;
}
#else /* !(ENABLE_PWQUALITY || ENABLE_PASSWDQC) */
static int tools_check_pwquality(const char *password)
{
	return 0;
}
#endif /* ENABLE_PWQUALITY || ENABLE_PASSWDQC */

static int interactive_pass(const char *prompt, char *pass, size_t maxlen,
		long timeout)
{
	struct termios orig, tmp;
	int failed = -1;
	int infd, outfd;

	if (maxlen < 1)
		return failed;

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

	*key = NULL;
	*key_size = 0;

	log_dbg("Interactive passphrase entry requested.");

	pass = crypt_safe_alloc(key_size_max + 1);
	if (!pass) {
		log_err( _("Out of memory while reading passphrase."));
		return -ENOMEM;
	}

	if (interactive_pass(prompt, pass, key_size_max, timeout)) {
		log_err(_("Error reading passphrase from terminal."));
		goto out_err;
	}
	pass[key_size_max] = '\0';

	if (verify) {
		pass_verify = crypt_safe_alloc(key_size_max);
		if (!pass_verify) {
			log_err(_("Out of memory while reading passphrase."));
			r = -ENOMEM;
			goto out_err;
		}

		if (interactive_pass(_("Verify passphrase: "),
		    pass_verify, key_size_max, timeout)) {
			log_err(_("Error reading passphrase from terminal."));
			goto out_err;
		}

		if (strncmp(pass, pass_verify, key_size_max)) {
			log_err(_("Passphrases do not match."));
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

static int tools_is_stdin(const char *key_file)
{
	if (!key_file)
		return 1;

	return strcmp(key_file, "-") ? 0 : 1;
}

/*
 * Note: --key-file=- is interpreted as a read from a binary file (stdin)
 * key_size_max == 0 means detect maximum according to input type (tty/file)
 */
int crypt_cli_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  uint64_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd, struct crypt_cli *ctx __attribute__((unused)))
{
	char tmp[PATH_MAX], *backing_file;
	int r = -EINVAL;

	if (tools_is_stdin(key_file)) {
		if (isatty(STDIN_FILENO)) {
			if (keyfile_offset) {
				log_err(_("Cannot use offset with terminal input."));
			} else {
				if (!prompt && !crypt_get_device_name(cd))
					snprintf(tmp, sizeof(tmp), _("Enter passphrase: "));
				else if (!prompt) {
					backing_file = crypt_loop_backing_file(crypt_get_device_name(cd));
					snprintf(tmp, sizeof(tmp), _("Enter passphrase for %s: "), backing_file ?: crypt_get_device_name(cd));
					free(backing_file);
				}
				r = crypt_get_key_tty(prompt ?: tmp, key, key_size, timeout, verify, cd);
			}
		} else {
			log_dbg("STDIN descriptor passphrase entry requested.");
			/* No keyfile means STDIN with EOL handling (\n will end input)). */
			r = crypt_keyfile_device_read(cd, NULL, key, key_size,
					keyfile_offset, keyfile_size_max,
					key_file ? 0 : CRYPT_KEYFILE_STOP_EOL);
		}
	} else {
		log_dbg("File descriptor passphrase entry requested.");
		r = crypt_keyfile_device_read(cd, key_file, key, key_size,
					      keyfile_offset, keyfile_size_max, 0);
	}

	/* Check pwquality for password (not keyfile) */
	if (pwquality && !key_file && !r)
		r = tools_check_pwquality(*key);

	return r;
}

int crypt_cli_read_mk(const char *file, char **key, size_t keysize)
{
	int fd;
	ssize_t ret;

	if (!keysize || !key)
		return -EINVAL;

	*key = crypt_safe_alloc(keysize);
	if (!*key)
		return -ENOMEM;

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		log_err(_("Cannot read keyfile %s."), file);
		goto fail;
	}

	ret = read_buffer(fd, *key, keysize);
	if (ret < 0 || (size_t)ret != keysize) {
		log_err(_("Cannot read %d bytes from keyfile %s."), keysize, file);
		close(fd);
		goto fail;
	}
	close(fd);
	return 0;
fail:
	crypt_safe_free(*key);
	*key = NULL;
	return -EINVAL;
}

static const struct tools_arg *find_arg_in_args(const char *name, const struct tools_arg *args, size_t args_len)
{
	size_t i;

	if (!args || !args_len)
		return NULL;

	for (i = 0; i < args_len; i++) {
		if (args[i].name && !strcmp(name, args[i].name))
			return args + i;
	}

	return NULL;
}

static const struct tools_arg *find_arg_by_name(struct crypt_cli *ctx, const char *name)
{
	return find_arg_in_args(name, ctx->core_args, ctx->core_args_count);
}

int crypt_cli_arg_value(struct crypt_cli *ctx, const char *name, void *value)
{
	const struct tools_arg *arg;

	if (!name || !ctx || !value)
		return -EINVAL;

	arg = find_arg_by_name(ctx, name);
	if (!arg)
		return -ENOENT;

	switch (arg->type) {
	case CRYPT_ARG_BOOL:
		*((bool *)value) = arg->set;
		break;
	case CRYPT_ARG_STRING:
		*((char **)value) = arg->u.str_value;
		break;
	case CRYPT_ARG_INT32:
		*((int32_t *)value) = arg->u.i32_value;
		break;
	case CRYPT_ARG_UINT32:
		*((uint32_t *)value) = arg->u.u32_value;
		break;
	case CRYPT_ARG_INT64:
		*((int64_t *)value) = arg->u.i64_value;
		break;
	case CRYPT_ARG_UINT64:
		*((uint64_t *)value) = arg->u.u64_value;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int crypt_cli_arg_type(struct crypt_cli *ctx, const char *name, crypt_arg_type_info *type)
{
	const struct tools_arg *arg;

	if (!name || !type || !ctx)
		return -EINVAL;

	arg = find_arg_by_name(ctx, name);
	if (!arg)
		return -ENOENT;

	*type = arg->type;

	return 0;
}

bool crypt_cli_arg_set(struct crypt_cli *ctx, const char *name)
{
	const struct tools_arg *arg;

	if (!name || !ctx)
		return false;

	arg = find_arg_by_name(ctx, name);
	if (!arg)
		return false;

	return arg->set;
}

__attribute__((format(printf, 5, 6)))
void crypt_cli_logger(struct crypt_device *cd, int level, const char *file, int line,
	     const char *format, ...)
{
	va_list argp;
	char target[LOG_MAX_LEN + 2];

	va_start(argp, format);

	if (vsnprintf(&target[0], LOG_MAX_LEN, format, argp) > 0) {
		/* All verbose and error messages in tools end with EOL. */
		if (level == CRYPT_LOG_VERBOSE || level == CRYPT_LOG_ERROR || level == CRYPT_LOG_DEBUG ||
		    level == CRYPT_LOG_DEBUG_JSON)
			strncat(target, "\n", LOG_MAX_LEN);

		crypt_log(cd, level, target);
	}

	va_end(argp);
}
