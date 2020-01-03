/*
 * kernel keyring syscall wrappers
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

#ifndef _UTILS_KEYRING
#define _UTILS_KEYRING

#include <stddef.h>

typedef enum { LOGON_KEY = 0, USER_KEY } key_type_t;

const char *key_type_name(key_type_t ktype);

int keyring_check(void);

int keyring_get_key(const char *key_desc,
		    char **key,
		    size_t *key_size);

int keyring_get_passphrase(const char *key_desc,
		      char **passphrase,
		      size_t *passphrase_len);

int keyring_add_key_in_thread_keyring(
	key_type_t ktype,
	const char *key_desc,
	const void *key,
	size_t key_size);

int keyring_add_key_in_user_keyring(
	key_type_t ktype,
	const char *key_desc,
	const void *key,
	size_t key_size);

int keyring_revoke_and_unlink_key(key_type_t ktype, const char *key_desc);

#endif
