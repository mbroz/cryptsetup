/*
 * kernel keyring utilities
 *
 * Copyright (C) 2016-2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016, Ondrej Kozina. All rights reserved.
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

#include "internal.h"
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

	log_dbg("Loading key %s (%zu bytes) in thread keyring", key_desc, key_size);

	kid = add_key("logon", key_desc, key, key_size, KEY_SPEC_THREAD_KEYRING);
	if (kid < 0) {
		switch (errno) {
		case EINVAL:
			log_dbg("add_key: the payload data is invalid.");
			break;
		case ENOMEM:
			log_dbg("add_key: insufficient memory to create a key.");
			break;
		case EDQUOT:
			log_dbg("add_key: quota would exceed.");
			break;
		}
		return -errno;
	}

	return 0;
#else
	return -EINVAL;
#endif
}

#ifdef KERNEL_KEYRING
static key_serial_t request_key_verbose(const char *type,
	const char *key_desc,
	const char *callout_info,
	key_serial_t keyring)
{
	key_serial_t kid;

	/*
	 * Search for a key in this particular order (first found, first served):
	 *
	 * 1) thread keyring
	 * 2) process keyring
	 * 3) user keyring (if exists) or user session keyring (if exists)
	 */
	kid = request_key(type, key_desc, callout_info, keyring);
	if (kid < 0) {
		switch (errno) {
		case EACCES:
			log_dbg("request_key: The keyring wasn't available for modification by the user.");
			break;
		case EINTR:
			log_dbg("request_key: The request was interrupted by a signal.");
			break;
		case EDQUOT:
			log_dbg("request_key: The key quota for this user would be exceeded by creating this key or linking it to the keyring.");
			break;
		case EKEYEXPIRED:
			log_dbg("request_key: An expired key was found, but no replacement could be obtained.");
			break;
		case EKEYREVOKED:
			log_dbg("request_key: A revoked key was found, but no replacement could be obtained.");
			break;
		case ENOKEY:
			log_dbg("request_key: No matching key was found.");
			break;
		/* NOTE following error codes are unreachable unless key generation is triggered */
		case EKEYREJECTED:
			log_dbg("request_key: The attempt to generate a new key was rejected.");
			break;
		case ENOMEM:
			log_dbg("request_key: Insufficient memory to create a key.");
			break;
		}
	}

	return kid;
}
#endif

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

	log_dbg("Looking for key described with '%s'.", key_desc);

	do
		kid = request_key_verbose("user", key_desc, NULL, 0);
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
		crypt_memzero(buf, len);
		free(buf);
		switch (err) {
		case ENOKEY:
			log_dbg("keyctl_read: The key specified is invalid.");
			break;
		case EKEYEXPIRED:
			log_dbg("keyctl_read: The key specified has expired.");
			break;
		case EKEYREVOKED:
			log_dbg("keyctl_read: The key specified had been revoked.");
			break;
		case EACCES:
			log_dbg("keyctl_read: The key exists, but is not readable by the calling process.");
			break;
		}
		return -err;
	}

	*passphrase = buf;
	*passphrase_len = len;

	return 0;
#else
	return -EINVAL;
#endif
}

int keyring_revoke_and_unlink_key(const char *key_desc)
{
#ifdef KERNEL_KEYRING
	key_serial_t kid;

	log_dbg("requesting keyring key %s for removal", key_desc);

	do
		kid = request_key_verbose("logon", key_desc, NULL, 0);
	while (kid < 0 && errno == EINTR);

	if (kid < 0)
		return 0;

	log_dbg("Revoking key %s", key_desc);

	if (keyctl_revoke(kid)) {
		switch (errno) {
		case ENOKEY:
			log_dbg ("keyctl_revoke: The specified key does not exist.");
			break;
		case EKEYREVOKED:
			log_dbg("keyctl_revoke: The key has already been revoked.");
			break;
		case EACCES:
			log_dbg("keyctl_revoke: The name key exists, but is not writable by the calling process.");
			return -errno;
		default:
			log_dbg("keyctl_revoke: Unexpected errno: %d", errno);
		}
	}

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
	return -EINVAL;
#endif
}
