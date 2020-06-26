/*
 * Command line arguments helpers
 *
 * Copyright (C) 2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2020 Ondrej Kozina
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

#ifndef CRYPTSETUP_ARGS_H
#define CRYPTSETUP_ARGS_H

#include "utils_arg_names.h"
#include "utils_arg_macros.h"
#include "lib/cli/cli_internal.h"

#define BITLKDUMP_ACTION	"bitlkDump"
#define BENCHMARK_ACTION	"benchmark"
#define CLOSE_ACTION		"close"
#define CONFIG_ACTION		"config"
#define CONVERT_ACTION		"convert"
#define ERASE_ACTION		"erase"
#define ISLUKS_ACTION		"isLuks"
#define ADDKEY_ACTION		"luksAddKey"
#define CHANGEKEY_ACTION	"luksChangeKey"
#define CONVERTKEY_ACTION	"luksConvertKey"
#define LUKSDUMP_ACTION		"luksDump"
#define FORMAT_ACTION		"luksFormat"
#define HEADERBACKUP_ACTION	"luksHeaderBackup"
#define HEADERRESTORE_ACTION	"luksHeaderRestore"
#define KILLKEY_ACTION		"luksKillSlot"
#define REMOVEKEY_ACTION	"luksRemoveKey"
#define RESUME_ACTION		"luksResume"
#define SUSPEND_ACTION		"luksSuspend"
#define UUID_ACTION		"luksUUID"
#define OPEN_ACTION		"open"
#define REENCRYPT_ACTION	"reencrypt"
#define REPAIR_ACTION		"repair"
#define RESIZE_ACTION		"resize"
#define STATUS_ACTION		"status"
#define TCRYPTDUMP_ACTION	"tcryptDump"
#define TOKEN_ACTION		"token"

/* avoid unshielded commas in ARG() macros later */
#define OPT_ALIGN_PAYLOAD_ACTIONS		{ FORMAT_ACTION }
#define OPT_ALLOW_DISCARDS_ACTIONS		{ OPEN_ACTION }
#define OPT_DEFERRED_ACTIONS			{ CLOSE_ACTION }
#define OPT_HOTZONE_SIZE_ACTIONS		{ REENCRYPT_ACTION }
#define OPT_INTEGRITY_ACTIONS			{ FORMAT_ACTION }
#define OPT_KEY_SIZE_ACTIONS			{ OPEN_ACTION, BENCHMARK_ACTION, FORMAT_ACTION, REENCRYPT_ACTION, ADDKEY_ACTION }
#define OPT_KEY_SLOT_ACTIONS			{ OPEN_ACTION, REENCRYPT_ACTION, CONFIG_ACTION, FORMAT_ACTION, ADDKEY_ACTION, CHANGEKEY_ACTION, CONVERTKEY_ACTION, LUKSDUMP_ACTION, TOKEN_ACTION }
#define OPT_LABEL_ACTIONS			{ CONFIG_ACTION, FORMAT_ACTION }
#define OPT_LUKS2_KEYSLOTS_SIZE_ACTIONS		{ REENCRYPT_ACTION, FORMAT_ACTION }
#define OPT_LUKS2_METADATA_SIZE_ACTIONS		{ REENCRYPT_ACTION, FORMAT_ACTION }
#define OPT_OFFSET_ACTIONS			{ OPEN_ACTION, REENCRYPT_ACTION, FORMAT_ACTION }
#define OPT_PERSISTENT_ACTIONS			{ OPEN_ACTION }
#define OPT_PRIORITY_ACTIONS			{ CONFIG_ACTION }
#define OPT_REFRESH_ACTIONS			{ OPEN_ACTION }
#define OPT_SECTOR_SIZE_ACTIONS			{ OPEN_ACTION, REENCRYPT_ACTION, FORMAT_ACTION }
#define OPT_SERIALIZE_MEMORY_HARD_PBKDF_ACTIONS { OPEN_ACTION }
#define OPT_SKIP_ACTIONS			{ OPEN_ACTION }
#define OPT_SUBSYSTEM_ACTIONS			{ CONFIG_ACTION, FORMAT_ACTION }
#define OPT_TCRYPT_BACKUP_ACTIONS		{ OPEN_ACTION, TCRYPTDUMP_ACTION }
#define OPT_TCRYPT_HIDDEN_ACTIONS		{ OPEN_ACTION, TCRYPTDUMP_ACTION }
#define OPT_TCRYPT_SYSTEM_ACTIONS		{ OPEN_ACTION, TCRYPTDUMP_ACTION }
#define OPT_TEST_PASSPHRASE_ACTIONS		{ OPEN_ACTION }
#define OPT_UNBOUND_ACTIONS			{ ADDKEY_ACTION, LUKSDUMP_ACTION }
#define OPT_USE_RANDOM_ACTIONS			{ FORMAT_ACTION }
#define OPT_USE_URANDOM_ACTIONS			{ FORMAT_ACTION }
#define OPT_UUID_ACTIONS			{ FORMAT_ACTION, UUID_ACTION }

enum {
OPT_UNUSED_ID = 0, /* leave unused due to popt library */
#define ARG(A, B, C, D, E, F, G, H) A ## _ID,
#include "cryptsetup_arg_list.h"
#undef ARG
};

static struct tools_arg tool_core_args[] = { { NULL, false, CRYPT_ARG_BOOL }, /* leave unused due to popt library */
#define ARG(A, B, C, D, E, F, G, H) { A, false, F, G, H },
#include "cryptsetup_arg_list.h"
#undef ARG
};

static inline void args_reset_default_values(struct tools_arg *args)
{
	struct tools_arg tmp[] = { { NULL, false, CRYPT_ARG_BOOL }, // UNUSED
	#define ARG(A, B, C, D, E, F, G, H ) { A, false, F, G, H },
	#include "cryptsetup_arg_list.h"
	#undef ARG
	};

	memcpy(args, tmp, sizeof(tmp));
}

#endif
