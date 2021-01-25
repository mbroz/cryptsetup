/*
 * Command line arguments helpers
 *
 * Copyright (C) 2020-2021 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2020-2021 Ondrej Kozina
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

#ifndef CRYPTSETUP_REENCRYPT_ARGS_H
#define CRYPTSETUP_REENCRYPT_ARGS_H

#include "utils_arg_names.h"
#include "utils_arg_macros.h"

enum {
OPT_UNUSED_ID = 0,
#define ARG(A, B, C, D, E, F, G) A ## _ID,
#include "cryptsetup_reencrypt_arg_list.h"
#undef ARG
};

static struct tools_arg tool_core_args[] = { { NULL, false, CRYPT_ARG_BOOL }, // UNUSED
#define ARG(A, B, C, D, E, F, G) { A, false, F, G },
#include "cryptsetup_reencrypt_arg_list.h"
#undef ARG
};

#endif
