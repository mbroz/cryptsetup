/*
 * Argon2 PBKDF2 library wrapper
 *
 * Copyright (C) 2016-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2018, Milan Broz
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

#if 0
#include <stdio.h>

struct test_vector {
	argon2_type type;
	unsigned int memory;
	unsigned int iterations;
	unsigned int parallelism;
	const char *password;
	unsigned int password_length;
	const char *salt;
	unsigned int salt_length;
	const char *key;
	unsigned int key_length;
	const char *ad;
	unsigned int ad_length;
	const char *output;
	unsigned int output_length;
};

struct test_vector test_vectors[] = {
	/* Argon2 RFC */
	{
		Argon2_i, 32, 3, 4,
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01", 32,
		"\x02\x02\x02\x02\x02\x02\x02\x02"
		"\x02\x02\x02\x02\x02\x02\x02\x02", 16,
		"\x03\x03\x03\x03\x03\x03\x03\x03", 8,
		"\x04\x04\x04\x04\x04\x04\x04\x04"
		"\x04\x04\x04\x04", 12,
		"\xc8\x14\xd9\xd1\xdc\x7f\x37\xaa"
		"\x13\xf0\xd7\x7f\x24\x94\xbd\xa1"
		"\xc8\xde\x6b\x01\x6d\xd3\x88\xd2"
		"\x99\x52\xa4\xc4\x67\x2b\x6c\xe8", 32
	},
	{
		Argon2_id, 32, 3, 4,
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01", 32,
		"\x02\x02\x02\x02\x02\x02\x02\x02"
		"\x02\x02\x02\x02\x02\x02\x02\x02", 16,
		"\x03\x03\x03\x03\x03\x03\x03\x03", 8,
		"\x04\x04\x04\x04\x04\x04\x04\x04"
		"\x04\x04\x04\x04", 12,
		"\x0d\x64\x0d\xf5\x8d\x78\x76\x6c"
		"\x08\xc0\x37\xa3\x4a\x8b\x53\xc9"
		"\xd0\x1e\xf0\x45\x2d\x75\xb6\x5e"
		"\xb5\x25\x20\xe9\x6b\x01\xe6\x59", 32
	}
};

static void printhex(const char *s, const char *buf, size_t len)
{
	size_t i;

	printf("%s: ", s);
	for (i = 0; i < len; i++)
		printf("\\x%02x", (unsigned char)buf[i]);
	printf("\n");
	fflush(stdout);
}

static int argon2_test_vectors(void)
{
	char result[64];
	int i, r;
	struct test_vector *vec;
	argon2_context context;

	printf("Argon2 running test vectors\n");

	for (i = 0; i < (sizeof(test_vectors) / sizeof(*test_vectors)); i++) {
		vec = &test_vectors[i];
		memset(result, 0, sizeof(result));
		memset(&context, 0, sizeof(context));

		context.flags = ARGON2_DEFAULT_FLAGS;
		context.version = ARGON2_VERSION_NUMBER;
		context.out = (uint8_t *)result;
		context.outlen = (uint32_t)vec->output_length;
		context.pwd = (uint8_t *)vec->password;
		context.pwdlen = (uint32_t)vec->password_length;
		context.salt = (uint8_t *)vec->salt;
		context.saltlen = (uint32_t)vec->salt_length;
		context.secret = (uint8_t *)vec->key;
		context.secretlen = (uint32_t)vec->key_length;;
		context.ad = (uint8_t *)vec->ad;
		context.adlen = (uint32_t)vec->ad_length;
		context.t_cost = vec->iterations;
		context.m_cost = vec->memory;
		context.lanes = vec->parallelism;
		context.threads = vec->parallelism;

		r = argon2_ctx(&context, vec->type);
		if (r != ARGON2_OK) {
			printf("Argon2 failed %i, vector %d\n", r, i);
			return -EINVAL;
		}
		if (memcmp(result, vec->output, vec->output_length) != 0) {
			printf("vector %u\n", i);
			printhex(" got", result, vec->output_length);
			printhex("want", vec->output, vec->output_length);
			return -EINVAL;
		}
	}
	return 0;
}
#endif
