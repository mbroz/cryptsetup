/*
 * Command line arguments helpers
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

#ifndef VERITYSETUP_ARGS_H
#define VERITYSETUP_ARGS_H

#include "utils_arg_names.h"
#include "utils_arg_macros.h"

#define CLOSE_ACTION	"close"
#define DUMP_ACTION	"dump"
#define FORMAT_ACTION	"format"
#define OPEN_ACTION	"open"
#define STATUS_ACTION	"status"
#define VERIFY_ACTION	"verify"

#define OPT_DEFERRED_ACTIONS			{ CLOSE_ACTION }
#define OPT_IGNORE_CORRUPTION_ACTIONS		{ OPEN_ACTION }
#define OPT_IGNORE_ZERO_BLOCKS_ACTIONS		{ OPEN_ACTION }
#define OPT_PANIC_ON_CORRUPTION_ACTIONS		{ OPEN_ACTION }
#define OPT_RESTART_ON_CORRUPTION_ACTIONS	{ OPEN_ACTION }
#define OPT_ROOT_HASH_FILE_ACTIONS		{ FORMAT_ACTION, OPEN_ACTION, VERIFY_ACTION }
#define OPT_ROOT_HASH_SIGNATURE_ACTIONS		{ OPEN_ACTION }
#define OPT_USE_TASKLETS_ACTIONS		{ OPEN_ACTION }

enum {
OPT_UNUSED_ID = 0,
#define ARG(A, B, C, D, E, F, G, H) A ## _ID,
#include "veritysetup_arg_list.h"
#undef ARG
};

static struct tools_arg tool_core_args[] = { { NULL, false, CRYPT_ARG_BOOL }, // UNUSED
#define ARG(A, B, C, D, E, F, G, H) { A, false, F, G, H },
#include "veritysetup_arg_list.h"
#undef ARG
};

#endif
