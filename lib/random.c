// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup kernel RNG access functions
 *
 * Copyright (C) 2010-2025 Red Hat, Inc. All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>

#include "libcryptsetup.h"
#include "internal.h"

static int random_initialised = 0;

#define URANDOM_DEVICE	"/dev/urandom"
static int urandom_fd = -1;

#define RANDOM_DEVICE	"/dev/random"
static int random_fd = -1;

/* Read random chunk - gathered data usually appears with this granularity */
#define RANDOM_DEVICE_CHUNK	8

/* Timeout to print warning if no random data (entropy) */
#define RANDOM_DEVICE_TIMEOUT	5

/* URANDOM_DEVICE access */
static int _get_urandom(char *buf, size_t len)
{
	int r;
	size_t old_len = len;
	char *old_buf = buf;

	assert(urandom_fd != -1);

	while (len) {
		r = read(urandom_fd, buf, len);
		if (r == -1 && errno != EINTR)
			return -EINVAL;
		if (r > 0) {
			len -= r;
			buf += r;
		}
	}

	assert(len == 0);
	assert((size_t)(buf - old_buf) == old_len);

	return 0;
}

static void _get_random_progress(struct crypt_device *ctx, int warn,
				 size_t expected_len, size_t read_len)
{
	if (warn)
		log_std(ctx,
			_("System is out of entropy while generating volume key.\n"
			  "Please move mouse or type some text in another window "
			  "to gather some random events.\n"));

	log_std(ctx, _("Generating key (%d%% done).\n"),
		(int)((expected_len - read_len) * 100 / expected_len));
}

/* RANDOM_DEVICE access */
static int _get_random(struct crypt_device *ctx, char *buf, size_t len)
{
	int r, warn_once = 1;
	size_t n, old_len = len;
	char *old_buf = buf;
	fd_set fds;
	struct timeval tv;

	assert(random_fd != -1);

	while (len) {
		FD_ZERO(&fds);
		FD_SET(random_fd, &fds);

		tv.tv_sec = RANDOM_DEVICE_TIMEOUT;
		tv.tv_usec = 0;

		r = select(random_fd + 1, &fds, NULL, NULL, &tv);
		if(r == -1)
			return -EINVAL;

		if(!r) {
			_get_random_progress(ctx, warn_once, old_len, len);
			warn_once = 0;
			continue;
		}

		do {
			n = RANDOM_DEVICE_CHUNK;
			if (len < RANDOM_DEVICE_CHUNK)
				n = len;

			r = read(random_fd, buf, n);

			if (r == -1 && errno == EINTR) {
				r = 0;
				continue;
			}

			/* bogus read? */
			if(r > (int)n)
				return -EINVAL;

			/* random device is opened with O_NONBLOCK, EAGAIN is expected */
			if (r == -1 && (errno != EAGAIN && errno != EWOULDBLOCK))
				return -EINVAL;

			if (r > 0) {
				len -= r;
				buf += r;
			}
		} while (len && r > 0);
	}

	assert(len == 0);
	assert((size_t)(buf - old_buf) == old_len);

	if (!warn_once)
		_get_random_progress(ctx, 0, old_len, len);

	return 0;
}
/* Initialisation of both RNG file descriptors is mandatory */
int crypt_random_init(struct crypt_device *ctx)
{
	if (random_initialised)
		return 0;

	/* Used for CRYPT_RND_NORMAL */
	if(urandom_fd == -1)
		urandom_fd = open(URANDOM_DEVICE, O_RDONLY | O_CLOEXEC);
	if(urandom_fd == -1)
		goto err;

	/* Used for CRYPT_RND_KEY */
	if(random_fd == -1)
		random_fd = open(RANDOM_DEVICE, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if(random_fd == -1)
		goto err;

	if (crypt_fips_mode())
		log_verbose(ctx, _("Running in FIPS mode."));

	random_initialised = 1;
	return 0;
err:
	crypt_random_exit();
	log_err(ctx, _("Fatal error during RNG initialisation."));
	return -ENOSYS;
}

/* coverity[ -taint_source : arg-1 ] */
int crypt_random_get(struct crypt_device *ctx, char *buf, size_t len, int quality)
{
	int status, rng_type;

	switch(quality) {
	case CRYPT_RND_NORMAL:
		status = _get_urandom(buf, len);
		break;
	case CRYPT_RND_SALT:
		if (crypt_fips_mode())
			status = crypt_backend_rng(buf, len, quality, 1);
		else
			status = _get_urandom(buf, len);
		break;
	case CRYPT_RND_KEY:
		if (crypt_fips_mode()) {
			status = crypt_backend_rng(buf, len, quality, 1);
			break;
		}
		rng_type = ctx ? crypt_get_rng_type(ctx) :
				 crypt_random_default_key_rng();
		switch (rng_type) {
		case CRYPT_RNG_URANDOM:
			status = _get_urandom(buf, len);
			break;
		case CRYPT_RNG_RANDOM:
			status = _get_random(ctx, buf, len);
			break;
		default:
			abort();
		}
		break;
	default:
		log_err(ctx, _("Unknown RNG quality requested."));
		return -EINVAL;
	}

	if (status)
		log_err(ctx, _("Error reading from RNG."));

	return status;
}

void crypt_random_exit(void)
{
	random_initialised = 0;

	if(random_fd != -1) {
		(void)close(random_fd);
		random_fd = -1;
	}

	if(urandom_fd != -1) {
		(void)close(urandom_fd);
		urandom_fd = -1;
	}
}

int crypt_random_default_key_rng(void)
{
	/* coverity[pointless_string_compare] */
	if (!strcmp(DEFAULT_RNG, RANDOM_DEVICE))
		return CRYPT_RNG_RANDOM;

	/* coverity[pointless_string_compare] */
	if (!strcmp(DEFAULT_RNG, URANDOM_DEVICE))
		return CRYPT_RNG_URANDOM;

	/* RNG misconfiguration is fatal */
	abort();
}
