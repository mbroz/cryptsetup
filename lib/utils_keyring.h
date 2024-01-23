/*
 * kernel keyring syscall wrappers
 *
 * Copyright (C) 2016-2024 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2024 Ondrej Kozina
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
key_serial_t keyring_find_key_id_by_name(const char *key_name);
key_serial_t keyring_find_keyring_id_by_name(const char *keyring_name);

int keyring_check(void);

key_serial_t keyring_request_key_id(key_type_t key_type,
		const char *key_description);

int keyring_read_key(key_serial_t kid,
		char **key,
		size_t *key_size);

key_serial_t keyring_add_key_in_thread_keyring(
	key_type_t ktype,
	const char *key_desc,
	const void *key,
	size_t key_size);

key_serial_t keyring_add_key_to_custom_keyring(key_type_t ktype, const char *key_desc, const void *key,
				      size_t key_size, key_serial_t keyring_to_link);
int keyring_unlink_key_from_keyring(key_serial_t kid, key_serial_t keyring_id);
int keyring_unlink_key_from_thread_keyring(key_serial_t kid);

#endif
