/*
 * Argon2 PBKDF2 library wrapper
 *
 * Copyright (C) 2016, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016, Milan Broz
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <errno.h>
#include "crypto_backend.h"
#include "argon2/argon2.h"

int argon2(const char *password, size_t password_length,
	   const char *salt, size_t salt_length,
	   char *key, size_t key_length,
	   uint32_t iterations, uint32_t memory, uint32_t parallel)
{
	int r;

	r = argon2i_hash_raw(iterations, memory, parallel, password, password_length,
			     salt, salt_length, key, key_length);

	switch (r) {
	case ARGON2_OK:
		r = 0;
		break;
	case ARGON2_MEMORY_ALLOCATION_ERROR:
	case ARGON2_FREE_MEMORY_CBK_NULL:
	case ARGON2_ALLOCATE_MEMORY_CBK_NULL:
		r = -ENOMEM;
		break;
	default:
		r = -EINVAL;
	}

	return r;
}
