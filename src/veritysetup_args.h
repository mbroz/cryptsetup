// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Command line arguments helpers
 *
 * Copyright (C) 2020-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2020-2025 Ondrej Kozina
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
#define OPT_ERROR_AS_CORRUPTION_ACTIONS		{ OPEN_ACTION }
#define OPT_ROOT_HASH_FILE_ACTIONS		{ FORMAT_ACTION, OPEN_ACTION, VERIFY_ACTION }
#define OPT_ROOT_HASH_SIGNATURE_ACTIONS		{ OPEN_ACTION }
#define OPT_USE_TASKLETS_ACTIONS		{ OPEN_ACTION }
#define OPT_SHARED_ACTIONS			{ OPEN_ACTION }

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
