/*
 * kernel keyring utilities
 *
 * Copyright (C) 2016-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2020 Ondrej Kozina
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

#include "libcryptsetup.h"
#include "utils_keyring.h"

#ifndef HAVE_KEY_SERIAL_T
#define HAVE_KEY_SERIAL_T
typedef int32_t key_serial_t;
#endif

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#ifdef KERNEL_KEYRING

static const struct {
	key_type_t type;
	const char *type_name;
} key_types[] = {
	{ LOGON_KEY,	"logon" },
	{ USER_KEY,	"user"	},
};

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

int keyring_add_key_in_thread_keyring(key_type_t ktype, const char *key_desc, const void *key, size_t key_size)
{
#ifdef KERNEL_KEYRING
	key_serial_t kid;
	const char *type_name = key_type_name(ktype);

	if (!type_name || !key_desc)
		return -EINVAL;

	kid = add_key(type_name, key_desc, key, key_size, KEY_SPEC_THREAD_KEYRING);
	if (kid < 0)
		return -errno;

	return 0;
#else
	return -ENOTSUP;
#endif
}

/* currently used in client utilities only */
int keyring_add_key_in_user_keyring(key_type_t ktype, const char *key_desc, const void *key, size_t key_size)
{
#ifdef KERNEL_KEYRING
	const char *type_name = key_type_name(ktype);
	key_serial_t kid;

	if (!type_name || !key_desc)
		return -EINVAL;

	kid = add_key(type_name, key_desc, key, key_size, KEY_SPEC_USER_KEYRING);
	if (kid < 0)
		return -errno;

	return 0;
#else
	return -ENOTSUP;
#endif
}

/* alias for the same code */
int keyring_get_key(const char *key_desc,
		    char **key,
		    size_t *key_size)
{
	return keyring_get_passphrase(key_desc, key, key_size);
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
		kid = request_key(key_type_name(USER_KEY), key_desc, NULL, 0);
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
			crypt_safe_memzero(buf, len);
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

static int keyring_revoke_and_unlink_key_type(const char *type_name, const char *key_desc)
{
#ifdef KERNEL_KEYRING
	key_serial_t kid;

	if (!type_name || !key_desc)
		return -EINVAL;

	do
		kid = request_key(type_name, key_desc, NULL, 0);
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

const char *key_type_name(key_type_t type)
{
#ifdef KERNEL_KEYRING
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(key_types); i++)
		if (type == key_types[i].type)
			return key_types[i].type_name;
#endif
	return NULL;
}

int keyring_revoke_and_unlink_key(key_type_t ktype, const char *key_desc)
{
	return keyring_revoke_and_unlink_key_type(key_type_name(ktype), key_desc);
}
