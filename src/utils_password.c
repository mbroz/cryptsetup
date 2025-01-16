// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Password quality check wrapper
 *
 * Copyright (C) 2012-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2025 Milan Broz
 */

#include "cryptsetup.h"
#include <termios.h>

#if ENABLE_PWQUALITY
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
	} else
		r = 0;

	pwquality_free_settings(pwq);
	return r;
}
#elif ENABLE_PASSWDQC
#include <passwdqc.h>

static int tools_check_passwdqc(const char *password)
{
	passwdqc_params_t params;
	char *parse_reason = NULL;
	const char *check_reason;
	const char *config = PASSWDQC_CONFIG_FILE;
	int r = -EINVAL;

	passwdqc_params_reset(&params);

	if (*config && passwdqc_params_load(&params, &parse_reason, config)) {
		log_err(_("Cannot check password quality: %s"),
			(parse_reason ? parse_reason : "Out of memory"));
		goto out;
	}

	check_reason = passwdqc_check(&params.qc, password, NULL, NULL);
	if (check_reason) {
		log_err(_("Password quality check failed: Bad passphrase (%s)"),
			check_reason);
		r = -EPERM;
	} else
		r = 0;
out:
#if HAVE_PASSWDQC_PARAMS_FREE
	passwdqc_params_free(&params);
#endif
	free(parse_reason);
	return r;
}
#endif /* ENABLE_PWQUALITY || ENABLE_PASSWDQC */

/* coverity[ +tainted_string_sanitize_content : arg-0 ] */
static int tools_check_password(const char *password)
{
#if ENABLE_PWQUALITY
	return tools_check_pwquality(password);
#elif ENABLE_PASSWDQC
	return tools_check_passwdqc(password);
#else
	UNUSED(password);
	return 0;
#endif
}

/* Password reading helpers */

/* coverity[ -taint_source : arg-1 ] */
static ssize_t read_tty_eol(int fd, char *pass, size_t maxlen)
{
	bool eol = false;
	ssize_t r, read_size = 0;

	if (maxlen > SSIZE_MAX)
		return -1;

	do {
		r = read(fd, pass, maxlen - read_size);
		if ((r == -1 && errno != EINTR) || quit)
			return -1;
		if (r >= 0) {
			if (!r || pass[r-1] == '\n')
				eol = true;
			/* coverity[overflow:FALSE] */
			read_size += r;
			pass = pass + r;
		}
	} while (!eol && (size_t)read_size != maxlen);

	return read_size;
}

/* The pass buffer is zeroed and has trailing \0 already " */
static int untimed_read(int fd, char *pass, size_t maxlen, size_t *realsize)
{
	ssize_t i;

	i = read_tty_eol(fd, pass, maxlen);
	if (i > 0) {
		if (pass[i-1] == '\n') {
			pass[i-1] = '\0';
			*realsize = i - 1;
		} else
			*realsize = i;
		i = 0;
	} else if (i == 0) /* empty input */
		i = -1;

	return i;
}

static int timed_read(int fd, char *pass, size_t maxlen, size_t *realsize, long timeout)
{
	struct timeval t;
	fd_set fds = {}; /* Just to avoid scan-build false report for FD_SET */
	int failed = -1;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	t.tv_sec = timeout;
	t.tv_usec = 0;

	if (select(fd+1, &fds, NULL, NULL, &t) > 0)
		failed = untimed_read(fd, pass, maxlen, realsize);

	return failed;
}

static int interactive_pass(const char *prompt, char *pass, size_t maxlen,
		long timeout)
{
	struct termios orig, tmp;
	int failed = -1;
	int infd, outfd;
	size_t realsize = 0;
	bool close_fd = false;

	if (maxlen < 1)
		return failed;

	/* Read and write to /dev/tty if available */
	infd = open("/dev/tty", O_RDWR);
	if (infd == -1) {
		infd = STDIN_FILENO;
		outfd = STDERR_FILENO;
	} else {
		outfd = infd;
		close_fd = true;
	}

	if (tcgetattr(infd, &orig))
		goto out;

	memcpy(&tmp, &orig, sizeof(tmp));
	tmp.c_lflag &= ~ECHO;

	if (prompt && write(outfd, prompt, strlen(prompt)) < 0)
		goto out;

	tcsetattr(infd, TCSAFLUSH, &tmp);
	if (timeout)
		failed = timed_read(infd, pass, maxlen, &realsize, timeout);
	else
		failed = untimed_read(infd, pass, maxlen, &realsize);
	tcsetattr(infd, TCSAFLUSH, &orig);
out:
	if (!failed && write(outfd, "\n", 1)) {};

	if (realsize == maxlen)
		log_err(_("Read stopped at maximal interactive input length, passphrase can be trimmed."));

	if (close_fd)
		close(infd);
	return failed;
}

static int crypt_get_key_tty(const char *prompt,
			     char **key, size_t *key_size,
			     int timeout, int verify)
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
		goto out;
	}

	if (verify) {
		pass_verify = crypt_safe_alloc(key_size_max + 1);
		if (!pass_verify) {
			log_err(_("Out of memory while reading passphrase."));
			r = -ENOMEM;
			goto out;
		}

		if (interactive_pass(_("Verify passphrase: "),
		    pass_verify, key_size_max, timeout)) {
			log_err(_("Error reading passphrase from terminal."));
			goto out;
		}

		if (strncmp(pass, pass_verify, key_size_max)) {
			log_err(_("Passphrases do not match."));
			r = -EPERM;
			goto out;
		}
	}

	*key = pass;
	/* coverity[string_null] (crypt_safe_alloc wipes string with additional \0) */
	*key_size = strlen(pass);
	r = 0;
out:
	crypt_safe_free(pass_verify);
	if (r)
		crypt_safe_free(pass);
	return r;
}

/*
 * Note: --key-file=- is interpreted as a read from a binary file (stdin)
 * key_size_max == 0 means detect maximum according to input type (tty/file)
 */
int tools_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  uint64_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd)
{
	char tmp[PATH_MAX], *backing_file;
	int r = -EINVAL, block;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	if (tools_is_stdin(key_file)) {
		if (isatty(STDIN_FILENO)) {
			if (keyfile_offset) {
				log_err(_("Cannot use offset with terminal input."));
			} else {
				r = 0;
				if (!prompt && !crypt_get_device_name(cd))
					r = snprintf(tmp, sizeof(tmp), _("Enter passphrase: "));
				else if (!prompt) {
					backing_file = crypt_loop_backing_file(crypt_get_device_name(cd));
					r = snprintf(tmp, sizeof(tmp), _("Enter passphrase for %s: "), backing_file ?: crypt_get_device_name(cd));
					free(backing_file);
				}
				if (r >= 0)
					r = crypt_get_key_tty(prompt ?: tmp, key, key_size, timeout, verify);
				else
					r = -EINVAL;
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

	if (block && !quit)
		set_int_block(1);

	/* Check pwquality for password (not keyfile) */
	if (pwquality && !key_file && !r)
		r = tools_check_password(*key);

	return r;
}

void tools_passphrase_msg(int r)
{
	if (r == -EPERM)
		log_err(_("No key available with this passphrase."));
	else if (r == -ENOENT)
		log_err(_("No usable keyslot is available."));
}
