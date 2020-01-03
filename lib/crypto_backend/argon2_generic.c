/*
 * Argon2 PBKDF2 library wrapper
 *
 * Copyright (C) 2016-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2020 Milan Broz
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
#include "crypto_backend_internal.h"
#if HAVE_ARGON2_H
#include <argon2.h>
#else
#include "argon2/argon2.h"
#endif

#define CONST_CAST(x) (x)(uintptr_t)

int argon2(const char *type, const char *password, size_t password_length,
	   const char *salt, size_t salt_length,
	   char *key, size_t key_length,
	   uint32_t iterations, uint32_t memory, uint32_t parallel)
{
#if !USE_INTERNAL_ARGON2 && !HAVE_ARGON2_H
	return -EINVAL;
#else
	argon2_type atype;
	argon2_context context = {
		.flags = ARGON2_DEFAULT_FLAGS,
		.version = ARGON2_VERSION_NUMBER,
		.t_cost = (uint32_t)iterations,
		.m_cost = (uint32_t)memory,
		.lanes = (uint32_t)parallel,
		.threads = (uint32_t)parallel,
		.out = (uint8_t *)key,
		.outlen = (uint32_t)key_length,
		.pwd = CONST_CAST(uint8_t *)password,
		.pwdlen = (uint32_t)password_length,
		.salt = CONST_CAST(uint8_t *)salt,
		.saltlen = (uint32_t)salt_length,
	};
	int r;

	if (!strcmp(type, "argon2i"))
		atype = Argon2_i;
	else if(!strcmp(type, "argon2id"))
		atype = Argon2_id;
	else
		return -EINVAL;

	switch (argon2_ctx(&context, atype)) {
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
#endif
}
