// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Command line arguments parsing helpers
 *
 * Copyright (C) 2020-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2020-2025 Ondrej Kozina
 */

#ifndef UTILS_ARG_MACROS_H
#define UTILS_ARG_MACROS_H

#include <assert.h>

#define ARG_SET(X) !!tool_core_args[(X)].set

#define ARG_STR(X) ({ \
	assert(tool_core_args[(X)].type == CRYPT_ARG_STRING); \
	tool_core_args[(X)].u.str_value; \
})

#define ARG_INT32(X) ({ \
	assert(tool_core_args[(X)].type == CRYPT_ARG_INT32); \
	tool_core_args[(X)].u.i32_value; \
})

#define ARG_UINT32(X) ({ \
	assert(tool_core_args[(X)].type == CRYPT_ARG_UINT32); \
	tool_core_args[(X)].u.u32_value; \
})

#define ARG_INT64(X) ({ \
	assert(tool_core_args[(X)].type == CRYPT_ARG_INT64); \
	tool_core_args[(X)].u.i64_value; \
})

#define ARG_UINT64(X) ({ \
	assert(tool_core_args[(X)].type == CRYPT_ARG_UINT64); \
	tool_core_args[(X)].u.u64_value; \
})

#define ARG_SET_TRUE(X) do { \
        tool_core_args[(X)].set = true; \
} while (0)

#define ARG_SET_STR(X, Y) \
do { \
	char *str; \
	assert(tool_core_args[(X)].set == false && tool_core_args[(X)].type == CRYPT_ARG_STRING); \
	str = (Y); \
	assert(str != NULL); \
	tool_core_args[(X)].u.str_value = str; \
	tool_core_args[(X)].set = true; \
} while (0)

#define ARG_SET_INT32(X, Y) \
do { \
	assert(tool_core_args[(X)].set == false && tool_core_args[(X)].type == CRYPT_ARG_INT32); \
	tool_core_args[(X)].u.i32_value = (Y); \
	tool_core_args[(X)].set = true; \
} while (0)

#define ARG_SET_UINT32(X, Y) \
do { \
	assert(tool_core_args[(X)].set == false && tool_core_args[(X)].type == CRYPT_ARG_UINT32); \
	tool_core_args[(X)].u.u32_value = (Y); \
	tool_core_args[(X)].set = true; \
} while (0)

#define ARG_SET_INT64(X, Y) \
do { \
	assert(tool_core_args[(X)].set == false && tool_core_args[(X)].type == CRYPT_ARG_INT64); \
	tool_core_args[(X)].u.i64_value = (Y); \
	tool_core_args[(X)].set = true; \
} while (0)

#define ARG_SET_UINT64(X, Y) \
do { \
	assert(tool_core_args[(X)].set == false && tool_core_args[(X)].type == CRYPT_ARG_UINT64); \
	tool_core_args[(X)].u.u64_value = (Y); \
	tool_core_args[(X)].set = true; \
} while (0)


#define ARG_INIT_ALIAS(X) \
do { \
	assert(tool_core_args[(X)].type == CRYPT_ARG_ALIAS); \
	tool_core_args[(X)].u.o.ptr = &tool_core_args[tool_core_args[(X)].u.o.id]; \
} while (0)

#endif
