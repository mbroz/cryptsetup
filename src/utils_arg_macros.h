/*
 * Command line arguments parsing helpers
 *
 * Copyright (C) 2020-2023 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2020-2023 Ondrej Kozina
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
