// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kernel keyring syscall wrappers
 *
 * Copyright (C) 2016-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2025 Ondrej Kozina
 */

#ifndef _UTILS_KEYRING
#define _UTILS_KEYRING

#include <stddef.h>
#include <stdint.h>

#ifndef HAVE_KEY_SERIAL_T
#define HAVE_KEY_SERIAL_T
typedef int32_t key_serial_t;
#endif

typedef enum { LOGON_KEY = 0, USER_KEY, BIG_KEY, TRUSTED_KEY, ENCRYPTED_KEY, INVALID_KEY } key_type_t;

const char *key_type_name(key_type_t ktype);
key_type_t key_type_by_name(const char *name);
key_type_t keyring_type_and_name(const char *key_name, const char **name);
key_serial_t keyring_find_key_id_by_name(const char *key_name);
key_serial_t keyring_find_keyring_id_by_name(const char *keyring_name);

int keyring_check(void);

key_serial_t keyring_request_key_id(key_type_t key_type,
		const char *key_description);

int keyring_read_keysize(key_serial_t kid,
		size_t *r_key_size);

int keyring_read_key(key_serial_t kid,
		char **key,
		size_t *key_size);

key_serial_t keyring_add_key_in_thread_keyring(
	key_type_t ktype,
	const char *key_desc,
	const void *key,
	size_t key_size);

key_serial_t keyring_add_key_to_keyring(key_type_t ktype, const char *key_desc, const void *key,
				      size_t key_size, key_serial_t keyring_to_link);
int keyring_unlink_key_from_keyring(key_serial_t kid, key_serial_t keyring_id);
int keyring_unlink_key_from_thread_keyring(key_serial_t kid);

#endif
