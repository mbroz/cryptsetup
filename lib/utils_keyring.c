/*
 * kernel keyring utilities
 *
 * Copyright (C) 2016-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2018, Ondrej Kozina. All rights reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef HAVE_KEY_SERIAL_T
#define HAVE_KEY_SERIAL_T
#include <stdint.h>
typedef int32_t key_serial_t;
#endif

#include "utils_crypt.h"
#include "utils_keyring.h"

#ifdef KERNEL_KEYRING

#include <linux/keyctl.h>

/* request_key */
static key_serial_t request_key(const char *type,
	const char *description,
	const char *callout_info,
	key_serial_t keyring)
{
	return syscall(__NR_request_key, type, description, callout_info, keyring);
}

/* add_key */
static key_serial_t add_key(const char *type,
	const char *description,
	const void *payload,
	size_t plen,
	key_serial_t keyring)
{
	return syscall(__NR_add_key, type, description, payload, plen, keyring);
}

/* keyctl_read */
static long keyctl_read(key_serial_t key, char *buffer, size_t buflen)
{
	return syscall(__NR_keyctl, KEYCTL_READ, key, buffer, buflen);
}

/* keyctl_revoke */
static long keyctl_revoke(key_serial_t key)
{
	return syscall(__NR_keyctl, KEYCTL_REVOKE, key);
}

/* keyctl_unlink */
static long keyctl_unlink(key_serial_t key, key_serial_t keyring)
{
	return syscall(__NR_keyctl, KEYCTL_UNLINK, key, keyring);
}
#endif

int keyring_check(void)
{
#ifdef KERNEL_KEYRING
	/* logon type key descriptions must be in format "prefix:description" */
	return syscall(__NR_request_key, "logon", "dummy", NULL, 0) == -1l && errno != ENOSYS;
#else
	return 0;
#endif
}

int keyring_add_key_in_thread_keyring(const char *key_desc, const void *key, size_t key_size)
{
#ifdef KERNEL_KEYRING
	key_serial_t kid;

	kid = add_key("logon", key_desc, key, key_size, KEY_SPEC_THREAD_KEYRING);
	if (kid < 0)
		return -errno;

	return 0;
#else
	return -ENOTSUP;
#endif
}

int keyring_get_passphrase(const char *key_desc,
		      char **passphrase,
		      size_t *passphrase_len)
{
#ifdef KERNEL_KEYRING
	int err;
	key_serial_t kid;
	long ret;
	char *buf = NULL;
	size_t len = 0;

	do
		kid = request_key("user", key_desc, NULL, 0);
	while (kid < 0 && errno == EINTR);

	if (kid < 0)
		return -errno;

	/* just get payload size */
	ret = keyctl_read(kid, NULL, 0);
	if (ret > 0) {
		len = ret;
		buf = malloc(len);
		if (!buf)
			return -ENOMEM;

		/* retrieve actual payload data */
		ret = keyctl_read(kid, buf, len);
	}

	if (ret < 0) {
		err = errno;
		if (buf)
			crypt_memzero(buf, len);
		free(buf);
		return -err;
	}

	*passphrase = buf;
	*passphrase_len = len;

	return 0;
#else
	return -ENOTSUP;
#endif
}

int keyring_revoke_and_unlink_key(const char *key_desc)
{
#ifdef KERNEL_KEYRING
	key_serial_t kid;

	do
		kid = request_key("logon", key_desc, NULL, 0);
	while (kid < 0 && errno == EINTR);

	if (kid < 0)
		return 0;

	if (keyctl_revoke(kid))
		return -errno;

	/*
	 * best effort only. the key could have been linked
	 * in some other keyring and its payload is now
	 * revoked anyway.
	 */
	keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING);
	keyctl_unlink(kid, KEY_SPEC_PROCESS_KEYRING);
	keyctl_unlink(kid, KEY_SPEC_USER_KEYRING);

	return 0;
#else
	return -ENOTSUP;
#endif
}
