// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Argon2 PBKDF2 library wrapper
 *
 * Copyright (C) 2016-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2025 Milan Broz
 */

#include <errno.h>
#include "crypto_backend_internal.h"

/* Check for HAVE_ARGON2_H is run only if libargon2 code is used */
#if USE_INTERNAL_ARGON2 || HAVE_ARGON2_H

#define CONST_CAST(x) (x)(uintptr_t)

#if HAVE_ARGON2_H
#include <argon2.h>
#else
#include "argon2/argon2.h"
#endif

int argon2(const char *type, const char *password, size_t password_length,
	   const char *salt, size_t salt_length,
	   char *key, size_t key_length,
	   uint32_t iterations, uint32_t memory, uint32_t parallel)
{
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

	/* This code must not be run if crypt backend library natively supports Argon2 */
	assert(!(crypt_backend_flags() & CRYPT_BACKEND_ARGON2));

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
}

#else /* USE_INTERNAL_ARGON2 || HAVE_ARGON2_H */
#pragma GCC diagnostic ignored "-Wunused-parameter"

int argon2(const char *type, const char *password, size_t password_length,
	   const char *salt, size_t salt_length,
	   char *key, size_t key_length,
	   uint32_t iterations, uint32_t memory, uint32_t parallel)
{
	return -EINVAL;
}

#endif

/* Additional string for crypt backend version */
const char *crypt_argon2_version(void)
{
	const char *version = "";

	if (crypt_backend_flags() & CRYPT_BACKEND_ARGON2)
		return version;

#if HAVE_ARGON2_H /* this has priority over internal argon2 */
	version = " [external libargon2]";
#elif USE_INTERNAL_ARGON2
	version = " [cryptsetup libargon2]";
#endif
	return version;
}
