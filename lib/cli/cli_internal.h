/*
 * libcryptsetup_cli - cryptsetup command line tools library
 *
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2020 Milan Broz
 * Copyright (C) 2020 Ondrej Kozina
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

#ifndef CLI_INTERNAL_H
#define CLI_INTERNAL_H

#include <stdbool.h>
#include <sys/types.h>

#define MAX_ACTIONS 16

struct tools_arg {
	const char *name;
	bool set;
	crypt_arg_type_info type;
	union {
		char *str_value;
		uint64_t u64_value;
		uint32_t u32_value;
		int32_t i32_value;
		int64_t i64_value;
	} u;
	const char *actions_array[MAX_ACTIONS];
};

struct crypt_cli {
	const struct tools_arg *core_args;
	size_t core_args_count;
};

#endif
