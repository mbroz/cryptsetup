/*
 * kernel keyring utilities
 *
 * Copyright (C) 2016-2023 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2023 Ondrej Kozina
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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "libcryptsetup.h"
#include "libcryptsetup_macros.h"
#include "utils_keyring.h"

#ifndef HAVE_KEY_SERIAL_T
#define HAVE_KEY_SERIAL_T
typedef int32_t key_serial_t;
#endif

#ifdef KERNEL_KEYRING

static const struct {
	key_type_t type;
	const char *type_name;
} key_types[] = {
	{ LOGON_KEY,	"logon" },
	{ USER_KEY,	"user"	},
	{ BIG_KEY,	"big_key"	},
	{ TRUSTED_KEY,	"trusted"	},
	{ ENCRYPTED_KEY,	"encrypted"	},
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

/* keyctl_describe */
static long keyctl_describe(key_serial_t id, char *buffer, size_t buflen)
{
	return syscall(__NR_keyctl, KEYCTL_DESCRIBE, id, buffer, buflen);
}

/* keyctl_read */
static long keyctl_read(key_serial_t key, char *buffer, size_t buflen)
{
	return syscall(__NR_keyctl, KEYCTL_READ, key, buffer, buflen);
}

/* key handle permissions mask */
typedef uint32_t key_perm_t;
#define KEY_POS_ALL	0x3f000000
#define KEY_USR_ALL	0x003f0000

static long keyctl_setperm(key_serial_t id, key_perm_t perm)
{
	return syscall(__NR_keyctl, KEYCTL_SETPERM, id, perm);
}

/* keyctl_link */
static long keyctl_link(key_serial_t key, key_serial_t keyring)
{
	return syscall(__NR_keyctl, KEYCTL_LINK, key, keyring);
}

/* keyctl_unlink */
static long keyctl_unlink(key_serial_t key, key_serial_t keyring)
{
	return syscall(__NR_keyctl, KEYCTL_UNLINK, key, keyring);
}

/* inspired by keyutils written by David Howells (dhowells@redhat.com) */
static key_serial_t keyring_process_proc_keys_line(char *line, const char *type, const char *desc,
						   key_serial_t destringid)
{
	char typebuf[40], rdesc[1024], *kdesc, *cp;
	int ndesc, n;
	key_serial_t id;
	int dlen;

	assert(desc);
	dlen = strlen(desc);
	cp = line + strlen(line);

	ndesc = 0;
	n = sscanf(line, "%x %*s %*u %*s %*x %*d %*d %s %n",
			&id, typebuf, &ndesc);
	if (n == 2 && ndesc > 0 && ndesc <= cp - line) {
		if (strcmp(typebuf, type) != 0)
			return 0;
		kdesc = line + ndesc;
		if (memcmp(kdesc, desc, dlen) != 0)
			return 0;
		if (kdesc[dlen] != ':' &&
				kdesc[dlen] != '\0' &&
				kdesc[dlen] != ' ')
			return 0;
		kdesc[dlen] = '\0';

		/* The key type appends extra stuff to the end of the
		 * description after a colon in /proc/keys.  Colons,
		 * however, are allowed in descriptions, so we need to
		 * make a further check. */
		n = keyctl_describe(id, rdesc, sizeof(rdesc) - 1);
		if (n < 0)
			return 0;
		if ((size_t)n >= sizeof(rdesc) - 1)
			return 0;
		rdesc[n] = '\0';

		cp = strrchr(rdesc, ';');
		if (!cp)
			return 0;
		cp++;
		if (strcmp(cp, desc) != 0)
			return 0;


		if (destringid && keyctl_link(id, destringid) == -1)
			return 0;

		return id;
	}

	return 0;
}

/* inspired by keyutils written by David Howells (dhowells@redhat.com), returns 0 ID on failure */

static key_serial_t find_key_by_type_and_desc(const char *type, const char *desc, key_serial_t destringid)
{
	key_serial_t id;
	int f;
	char buf[1024];
	char *newline;
	size_t buffer_len = 0;

	int n;

	do {
		id = request_key(type, desc, NULL, 0);
	} while (id < 0 && errno == EINTR);
	if (id >= 0 || errno == ENOMEM)
		return id;

	f = open("/proc/keys", O_RDONLY);
	if (f < 0)
		return 0;

	while ((n = read(f, buf + buffer_len, sizeof(buf) - buffer_len - 1)) > 0) {
		buffer_len += n;
		buf[buffer_len] = '\0';
		newline = strchr(buf, '\n');
		while (newline != NULL && buffer_len != 0) {
			*newline = '\0';

			if ((id = keyring_process_proc_keys_line(buf, type, desc, destringid))) {
				close(f);
				return id;
			}

			buffer_len -= newline - buf + 1;
			assert(buffer_len <= sizeof(buf) - 1);
			memmove(buf, newline + 1, buffer_len);
			buf[buffer_len] = '\0';
			newline = strchr(buf, '\n');
		}
	}

	close(f);
	return 0;
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

int keyring_read_by_id(const char *key_desc,
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

	kid = keyring_by_name(key_desc);
	if (kid < 0)
		return kid;
	else if (kid == 0)
		return -ENOENT;

	/* just get payload size */
	ret = keyctl_read(kid, NULL, 0);
	if (ret > 0) {
		len = ret;
		buf = crypt_safe_alloc(len);
		if (!buf)
			return -ENOMEM;

		/* retrieve actual payload data */
		ret = keyctl_read(kid, buf, len);
	}

	if (ret < 0) {
		err = errno;
		crypt_safe_free(buf);
		return -err;
	}

	*passphrase = buf;
	*passphrase_len = len;

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

	do {
		kid = request_key(key_type_name(USER_KEY), key_desc, NULL, 0);
	} while (kid < 0 && errno == EINTR);

	if (kid < 0)
		return -errno;

	/* just get payload size */
	ret = keyctl_read(kid, NULL, 0);
	if (ret > 0) {
		len = ret;
		buf = crypt_safe_alloc(len);
		if (!buf)
			return -ENOMEM;

		/* retrieve actual payload data */
		ret = keyctl_read(kid, buf, len);
	}

	if (ret < 0) {
		err = errno;
		crypt_safe_free(buf);
		return -err;
	}

	*passphrase = buf;
	*passphrase_len = len;

	return 0;
#else
	return -ENOTSUP;
#endif
}

static int keyring_link_key_to_keyring_key_type(const char *type_name, const char *key_desc,
						key_serial_t keyring_to_link)
{
#ifdef KERNEL_KEYRING
	long r;
	key_serial_t kid;

	if (!type_name || !key_desc)
		return -EINVAL;

	do {
		kid = request_key(type_name, key_desc, NULL, 0);
	} while (kid < 0 && errno == EINTR);

	if (kid < 0)
		return 0;

	/* see https://mjg59.dreamwidth.org/37333.html */
	if (keyring_to_link == KEY_SPEC_USER_KEYRING || keyring_to_link == KEY_SPEC_USER_SESSION_KEYRING)
		keyctl_setperm(kid, KEY_POS_ALL | KEY_USR_ALL);
	r = keyctl_link(kid, keyring_to_link);
	if (r < 0)
		return -errno;

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

	do {
		kid = request_key(type_name, key_desc, NULL, 0);
	} while (kid < 0 && errno == EINTR);

	if (kid < 0)
		return 0;

	if (keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING))
		return -errno;

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

int32_t keyring_by_name(const char *name)
{
	int32_t id = 0;
#ifdef KERNEL_KEYRING
	char *end;
	char *name_copy, *name_copy_p;

	if (name[0] == '@') {
		if (strcmp(name, "@t" ) == 0) return KEY_SPEC_THREAD_KEYRING;
		if (strcmp(name, "@p" ) == 0) return KEY_SPEC_PROCESS_KEYRING;
		if (strcmp(name, "@s" ) == 0) return KEY_SPEC_SESSION_KEYRING;
		if (strcmp(name, "@u" ) == 0) return KEY_SPEC_USER_KEYRING;
		if (strcmp(name, "@us") == 0) return KEY_SPEC_USER_SESSION_KEYRING;
		if (strcmp(name, "@g" ) == 0) return KEY_SPEC_GROUP_KEYRING;
		if (strcmp(name, "@a" ) == 0) return KEY_SPEC_REQKEY_AUTH_KEY;

		return 0;
	}

	/* handle a lookup-by-name request "%<type>:<desc>", eg: "%keyring:_ses" */
	name_copy = strdup(name);
	if (!name_copy)
		goto out;
	name_copy_p = name_copy;

	if (name_copy_p[0] == '%') {
		const char *type;

		name_copy_p++;
		if (!*name_copy_p)
			goto out;

		if (*name_copy_p == ':') {
			type = "keyring";
			name_copy_p++;
		} else {
			type = name_copy_p;
			name_copy_p = strchr(name_copy_p, ':');
			if (!name_copy_p)
				goto out;
			*(name_copy_p++) = '\0';
		}

		if (!*name_copy_p)
			goto out;

		id = find_key_by_type_and_desc(type, name_copy_p, 0);
		goto out;
	}

	id = strtoul(name, &end, 0);
	if (*end)
		id = 0;

out:
	if (name_copy)
		free(name_copy);
#endif
	return id;
}

key_type_t key_type_by_name(const char *name)
{
#ifdef KERNEL_KEYRING
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(key_types); i++)
		if (!strcmp(key_types[i].type_name, name))
			return key_types[i].type;
#endif
	return INVALID_KEY;
}

int keyring_link_key_to_keyring(key_type_t ktype, const char *key_desc, key_serial_t keyring_to_link)
{
	return keyring_link_key_to_keyring_key_type(key_type_name(ktype), key_desc, keyring_to_link);
}

int keyring_revoke_and_unlink_key(key_type_t ktype, const char *key_desc)
{
	return keyring_revoke_and_unlink_key_type(key_type_name(ktype), key_desc);
}
