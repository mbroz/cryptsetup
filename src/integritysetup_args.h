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
