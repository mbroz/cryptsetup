// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Command line arguments helpers
 *
 * Copyright (C) 2020-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2020-2025 Ondrej Kozina
 */

#ifndef INTEGRITYSETUP_ARGS_H
#define INTEGRITYSETUP_ARGS_H

#include "utils_arg_names.h"
#include "utils_arg_macros.h"

#define DUMP_ACTION	"dump"
#define FORMAT_ACTION	"format"
#define CLOSE_ACTION	"close"
#define OPEN_ACTION	"open"
#define RESIZE_ACTION	"resize"
#define STATUS_ACTION	"status"

#define OPT_ALLOW_DISCARDS_ACTIONS		{ OPEN_ACTION }
#define OPT_DEFERRED_ACTIONS			{ CLOSE_ACTION }
#define OPT_DEVICE_SIZE_ACTIONS			{ RESIZE_ACTION }
#define OPT_DISABLE_BLKID_ACTIONS		{ FORMAT_ACTION }
#define OPT_INTEGRITY_INLINE_ACTIONS		{ FORMAT_ACTION }
#define OPT_INTEGRITY_RECALCULATE_ACTIONS	{ OPEN_ACTION }
#define OPT_INTERLEAVE_SECTORS_ACTIONS		{ FORMAT_ACTION }
#define OPT_JOURNAL_SIZE_ACTIONS		{ FORMAT_ACTION }
#define OPT_NO_WIPE_ACTIONS			{ FORMAT_ACTION }
#define OPT_PROGRESS_JSON_ACTIONS		{ FORMAT_ACTION, RESIZE_ACTION }
#define OPT_SECTOR_SIZE_ACTIONS			{ FORMAT_ACTION }
#define OPT_SIZE_ACTIONS			{ RESIZE_ACTION }
#define OPT_TAG_SIZE_ACTIONS			{ FORMAT_ACTION }
#define OPT_WIPE_ACTIONS			{ RESIZE_ACTION }

enum {
OPT_UNUSED_ID = 0,
#define ARG(A, B, C, D, E, F, G, H) A ## _ID,
#include "integritysetup_arg_list.h"
#undef ARG
};

static struct tools_arg tool_core_args[] = { { NULL, false, CRYPT_ARG_BOOL }, // UNUSED
#define ARG(A, B, C, D, E, F, G, H) { A, false, F, G, H },
#include "integritysetup_arg_list.h"
#undef ARG
};

#endif
