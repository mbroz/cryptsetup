// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kernel keyring utilities
 *
 * Copyright (C) 2016-2024 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2024 Ondrej Kozina
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "libcryptsetup.h"
#include "libcryptsetup_macros.h"
#include "utils_keyring.h"

#ifdef KERNEL_KEYRING

static const struct {
	key_type_t type;
	const char *type_name;
} key_types[] = {
	{ LOGON_KEY,     "logon" },
	{ USER_KEY,      "user" },
	{ BIG_KEY,       "big_key" },
	{ TRUSTED_KEY,   "trusted" },
	{ ENCRYPTED_KEY, "encrypted" },
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
	char typebuf[41], rdesc[1024], *kdesc, *cp;
	int ndesc, n;
	key_serial_t id;
	int dlen;

	assert(desc);
	dlen = strlen(desc);
	cp = line + strlen(line);

	ndesc = 0;
	n = sscanf(line, "%x %*s %*u %*s %*x %*d %*d %40s %n",
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

	ssize_t n;

	do {
		id = request_key(type, desc, NULL, 0);
	} while (id < 0 && errno == EINTR);
	if (id >= 0 || errno == ENOMEM)
		return id;

	f = open("/proc/keys", O_RDONLY);
	if (f < 0)
		return 0;

	while ((n = read(f, buf + buffer_len, sizeof(buf) - buffer_len - 1)) > 0) {
		/* coverity[overflow:FALSE] */
		buffer_len += (size_t)n;
		buf[buffer_len] = '\0';
		newline = strchr(buf, '\n');
		while (newline != NULL && buffer_len != 0) {
			*newline = '\0';

			if ((id = keyring_process_proc_keys_line(buf, type, desc, destringid))) {
				close(f);
				return id;
			}

			buffer_len -= newline - buf + 1;
			if (buffer_len >= sizeof(buf)) {
				close(f);
				return 0;
			}
			memmove(buf, newline + 1, buffer_len);
			buf[buffer_len] = '\0';
			newline = strchr(buf, '\n');
		}
	}

	close(f);
	return 0;
}

int keyring_check(void)
{
	/* logon type key descriptions must be in format "prefix:description" */
	return syscall(__NR_request_key, "logon", "dummy", NULL, 0) == -1l && errno != ENOSYS;
}

static key_serial_t keyring_add_key_in_keyring(key_type_t ktype,
		const char *key_desc,
		const void *key,
		size_t key_size,
		key_serial_t keyring)
{
	const char *type_name = key_type_name(ktype);

	if (!type_name || !key_desc)
		return -EINVAL;

	return add_key(type_name, key_desc, key, key_size, keyring);
}

key_serial_t keyring_add_key_in_thread_keyring(key_type_t ktype, const char *key_desc, const void *key, size_t key_size)
{
	return keyring_add_key_in_keyring(ktype, key_desc, key, key_size, KEY_SPEC_THREAD_KEYRING);
}

key_serial_t keyring_new_trusted_key(int key_size, const char *key_description)
{
	int r;
	char command[256];
	/* the 'add key' syscall has to be fed a 'new' command, with the key size to create a new trusted key
	 */
	r = snprintf(command, 8, "new %i", key_size);
	printf("command = %s, r=%i\n", command, r);
	if (r < 0)
		return r;
	return keyring_add_key_in_keyring(TRUSTED_KEY,
				key_description, command, r,
				KEY_SPEC_THREAD_KEYRING);
}

key_serial_t keyring_load_keyblob_in_thread_keyring(key_type_t ktype, const char *key_description, const char *keyblob)
{
	int r;
	char *command;

	assert(ktype == TRUSTED_KEY || ktype == ENCRYPTED_KEY);

	/* the 'add key' syscall has to be fed a 'load' command, with the keyblob data as the 'key' value */
	r = asprintf(&command, "load %s", keyblob);
	if (r < 0)
		return r;
	r = keyring_add_key_in_keyring(ktype,
			key_description, command, r,
			KEY_SPEC_THREAD_KEYRING);
	free(command);
	return r;
}

int keyring_split_keystring_keyblob(const char* combined, char **keystring, char **keyblob)
{
	const char *delimiter = strstr(combined, "::");
	if (!delimiter) {
		return -EINVAL;
	}

	size_t keystring_len = delimiter - combined;
	size_t keyblob_len = strlen(delimiter + 2);

	assert(keystring);
	assert(keyblob);

	/* +1 for null terminator */
	*keystring = (char *)malloc(keystring_len + 1);
	if (!*keystring)
		return -ENOMEM;
	*keyblob = (char *)malloc(keyblob_len + 1);
	if (!*keyblob) {
		free(*keystring);
		return -ENOMEM;
	}

	strncpy(*keystring, combined, keystring_len);
	(*keystring)[keystring_len] = '\0';

	/* Skip the "::" and copy the keyblob */
	strcpy(*keyblob, delimiter + 2);

	return 0;
}

key_serial_t keyring_request_key_id(key_type_t key_type,
		const char *key_description)
{
	key_serial_t kid;

	do {
		kid = request_key(key_type_name(key_type), key_description, NULL, 0);
	} while (kid < 0 && errno == EINTR);

	return kid;
}

int keyring_read_key(key_serial_t kid,
		char **key,
		size_t *key_size)
{
	long r;
	char *buf = NULL;
	size_t len = 0;

	assert(key);
	assert(key_size);

	/* just get payload size */
	r = keyctl_read(kid, NULL, 0);
	if (r > 0) {
		len = r;
		buf = crypt_safe_alloc(len);
		if (!buf)
			return -ENOMEM;

		/* retrieve actual payload data */
		r = keyctl_read(kid, buf, len);
	}

	if (r < 0) {
		crypt_safe_free(buf);
		return -EINVAL;
	}

	*key = buf;
	*key_size = len;

	return 0;
}

int keyring_unlink_key_from_keyring(key_serial_t kid, key_serial_t keyring_id)
{
	return keyctl_unlink(kid, keyring_id) < 0 ? -EINVAL : 0;
}

int keyring_unlink_key_from_thread_keyring(key_serial_t kid)
{
	return keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING) < 0 ? -EINVAL : 0;
}

const char *key_type_name(key_type_t type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(key_types); i++)
		if (type == key_types[i].type)
			return key_types[i].type_name;

	return NULL;
}

key_type_t keyring_type_and_name(const char *key_name, const char **name)
{
	char type[16], *name_tmp;
	size_t type_len;

	if (!key_name || key_name[0] != '%')
		return INVALID_KEY;

	key_name++;
	if (!*key_name || *key_name == ':')
		return INVALID_KEY;

	name_tmp = strchr(key_name, ':');
	if (!name_tmp)
		return INVALID_KEY;
	name_tmp++;

	type_len = name_tmp - key_name - 1;
	if (type_len >= sizeof(type) - 1)
		return INVALID_KEY;

	memcpy(type, key_name, type_len);
	type[type_len] = '\0';

	if (name)
		*name = name_tmp;

	return key_type_by_name(type);
}

key_serial_t keyring_find_key_id_by_name(const char *key_name)
{
	key_serial_t id = 0;
	char *end;
	char *name_copy, *name_copy_p;
	int key_size;
	char *key_type = NULL, *key_desc = NULL;

	assert(key_name);

	if (key_name[0] == '@') {
		if (strcmp(key_name, "@t" ) == 0) return KEY_SPEC_THREAD_KEYRING;
		if (strcmp(key_name, "@p" ) == 0) return KEY_SPEC_PROCESS_KEYRING;
		if (strcmp(key_name, "@s" ) == 0) return KEY_SPEC_SESSION_KEYRING;
		if (strcmp(key_name, "@u" ) == 0) return KEY_SPEC_USER_KEYRING;
		if (strcmp(key_name, "@us") == 0) return KEY_SPEC_USER_SESSION_KEYRING;
		if (strcmp(key_name, "@g" ) == 0) return KEY_SPEC_GROUP_KEYRING;
		if (strcmp(key_name, "@a" ) == 0) return KEY_SPEC_REQKEY_AUTH_KEY;

		return 0;
	}

	name_copy = strdup(key_name);
	if (!name_copy)
		goto out;
	name_copy_p = name_copy;

	/* handle a lookup-by-name request "%<type>:<desc>", eg: "%keyring:_ses" */
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

	/* handle a lookup-by-name request ":<key-size>:<type>:<desc>" */
	if (name_copy_p[0] == ':') {
		if (keyring_parse_keystring(name_copy_p, &key_size, &key_type, &key_desc))
			goto out;

		id = find_key_by_type_and_desc(key_type, key_desc, 0);
		goto out;
	}

	id = strtoul(key_name, &end, 0);
	if (*end)
		id = 0;

out:
	if (name_copy)
		free(name_copy);
	if (key_type)
		free(key_type);
	if (key_desc)
		free(key_desc);

	return id;
}

int keyring_parse_keystring(const char *key_string, int *size, char **type, char **description)
{
	char *p, *copy = strdup(key_string);
	int r = -1;
	/*
	 * <key_string>
	 * The kernel keyring key is identified by string in following format:
	 * :<key_size>:<key_type>:<key_description>.
	 */

	p = strtok(copy, ":");
	if (size) {
		*size = atoi(p);
		if (!*size)
			goto out;
	}

	p = strtok(NULL, ":");
	if (!p)
		goto out;

	if (type)
		*type = strdup(p);

	p = strtok(NULL, ":");
	if (!p)
		goto out;

	if (description)
		*description = strdup(p);

	r = 0;
out:
	if (copy)
		free(copy);
	return r;
}

static bool numbered(const char *str)
{
	char *endp;

	errno = 0;
	(void) strtol(str, &endp, 0);
	if (errno == ERANGE)
		return false;

	return *endp == '\0' ? true : false;
}

key_serial_t keyring_find_keyring_id_by_name(const char *keyring_name)
{
	assert(keyring_name);

	/* "%:" is abbreviation for the type keyring */
	if ((keyring_name[0] == '@' && keyring_name[1] != 'a') ||
	    strstr(keyring_name, "%:") || strstr(keyring_name, "%keyring:") ||
	    numbered(keyring_name))
		return keyring_find_key_id_by_name(keyring_name);

	return 0;
}

key_type_t key_type_by_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(key_types); i++)
		if (!strcmp(key_types[i].type_name, name))
			return key_types[i].type;

	return INVALID_KEY;
}

key_serial_t keyring_add_key_to_custom_keyring(key_type_t ktype,
				      const char *key_desc,
				      const void *key,
				      size_t key_size,
				      key_serial_t keyring_to_link)
{
	const char *type_name = key_type_name(ktype);

	if (!type_name || !key_desc)
		return -EINVAL;

	return add_key(type_name, key_desc, key, key_size, keyring_to_link);
}

#else /* KERNEL_KEYRING */
#pragma GCC diagnostic ignored "-Wunused-parameter"

int keyring_check(void)
{
	return 0;
}

key_serial_t keyring_add_key_in_thread_keyring(key_type_t ktype, const char *key_desc, const void *key, size_t key_size)
{
	return -ENOTSUP;
}

key_serial_t keyring_request_key_id(key_type_t key_type,
		const char *key_description)
{
	return -ENOTSUP;
}

int keyring_read_key(key_serial_t kid,
		char **key,
		size_t *key_size)
{
	return -ENOTSUP;
}

int keyring_read_by_id(const char *key_desc, char **passphrase, size_t *passphrase_len)
{
	return -ENOTSUP;
}

const char *key_type_name(key_type_t type)
{
	return NULL;
}

key_type_t keyring_type_and_name(const char *key_name, const char **name)
{
	return INVALID_KEY;
}

key_serial_t keyring_find_key_id_by_name(const char *key_name)
{
	return 0;
}

key_serial_t keyring_find_keyring_id_by_name(const char *keyring_name)
{
	return 0;
}

key_type_t key_type_by_name(const char *name)
{
	return INVALID_KEY;
}

key_serial_t keyring_add_key_to_custom_keyring(key_type_t ktype,
				      const char *key_desc,
				      const void *key,
				      size_t key_size,
				      key_serial_t keyring_to_link)
{
	return -ENOTSUP;
}

int keyring_unlink_key_from_keyring(key_serial_t kid, key_serial_t keyring_id)
{
	return -ENOTSUP;
}

int keyring_unlink_key_from_thread_keyring(key_serial_t kid)
{
	return -ENOTSUP;
}
#endif
