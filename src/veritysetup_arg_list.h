/*
 * Veritysetup command line arguments list
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

/* long name, short name, popt type, help description, units, internal argument type, default value, allowed actions (empty=global) */

ARG(OPT_CANCEL_DEFERRED, '\0', POPT_ARG_NONE, N_("Cancel a previously set deferred device removal"), NULL, CRYPT_ARG_BOOL, {}, OPT_DEFERRED_ACTIONS)

ARG(OPT_CHECK_AT_MOST_ONCE, '\0', POPT_ARG_NONE, N_("Verify data block only the first time it is read"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DATA_BLOCK_SIZE, '\0', POPT_ARG_STRING, N_("Block size on the data device"), N_("bytes"), CRYPT_ARG_UINT32, { .u32_value = DEFAULT_VERITY_DATA_BLOCK }, {})

ARG(OPT_DATA_BLOCKS, '\0', POPT_ARG_STRING, N_("The number of blocks in the data file"), N_("blocks"), CRYPT_ARG_UINT64, {}, {})

ARG(OPT_DEBUG, '\0', POPT_ARG_NONE, N_("Show debug messages"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DEFERRED, '\0', POPT_ARG_NONE, N_("Device removal is deferred until the last user closes it"), NULL, CRYPT_ARG_BOOL, {}, OPT_DEFERRED_ACTIONS)

ARG(OPT_FEC_DEVICE, '\0', POPT_ARG_STRING, N_("Path to device with error correction data"), N_("path"), CRYPT_ARG_STRING, {}, {})

ARG(OPT_FEC_OFFSET, '\0', POPT_ARG_STRING, N_("Starting offset on the FEC device"), N_("bytes"), CRYPT_ARG_UINT64, {}, {})

ARG(OPT_FEC_ROOTS, '\0', POPT_ARG_STRING, N_("FEC parity bytes"), N_("bytes"), CRYPT_ARG_UINT32, { .u32_value = DEFAULT_VERITY_FEC_ROOTS }, {})

ARG(OPT_FORMAT, '\0', POPT_ARG_STRING, N_("Format type (1 - normal, 0 - original Chrome OS)"), N_("number"), CRYPT_ARG_UINT32, { .u32_value = 1 }, {})

ARG(OPT_HASH, 'h',  POPT_ARG_STRING, N_("Hash algorithm"), N_("string"), CRYPT_ARG_STRING, { .str_value = CONST_CAST(void *)DEFAULT_VERITY_HASH }, {})

ARG(OPT_HASH_BLOCK_SIZE, '\0', POPT_ARG_STRING, N_("Block size on the hash device"), N_("bytes"), CRYPT_ARG_UINT32, { .u32_value = DEFAULT_VERITY_HASH_BLOCK }, {})

ARG(OPT_HASH_OFFSET, '\0', POPT_ARG_STRING, N_("Starting offset on the hash device"), N_("bytes"), CRYPT_ARG_UINT64, {}, {})

ARG(OPT_IGNORE_CORRUPTION, '\0', POPT_ARG_NONE, N_("Ignore corruption, log it only"), NULL, CRYPT_ARG_BOOL, {}, OPT_IGNORE_CORRUPTION_ACTIONS)

ARG(OPT_IGNORE_ZERO_BLOCKS, '\0', POPT_ARG_NONE, N_("Do not verify zeroed blocks"), NULL, CRYPT_ARG_BOOL, {}, OPT_IGNORE_ZERO_BLOCKS_ACTIONS)

ARG(OPT_NO_SUPERBLOCK, '\0', POPT_ARG_NONE, N_("Do not use verity superblock"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_PANIC_ON_CORRUPTION, '\0', POPT_ARG_NONE, N_("Panic kernel if corruption is detected"), NULL, CRYPT_ARG_BOOL, {}, OPT_PANIC_ON_CORRUPTION_ACTIONS)

ARG(OPT_RESTART_ON_CORRUPTION, '\0', POPT_ARG_NONE, N_("Restart kernel if corruption is detected"), NULL, CRYPT_ARG_BOOL, {}, OPT_RESTART_ON_CORRUPTION_ACTIONS)

ARG(OPT_ROOT_HASH_FILE, '\0', POPT_ARG_STRING, N_("Path to root hash file"), NULL, CRYPT_ARG_STRING, {}, OPT_ROOT_HASH_FILE_ACTIONS)

ARG(OPT_ROOT_HASH_SIGNATURE, '\0', POPT_ARG_STRING, N_("Path to root hash signature file"), NULL, CRYPT_ARG_STRING, {}, OPT_ROOT_HASH_SIGNATURE_ACTIONS)

ARG(OPT_SALT, 's', POPT_ARG_STRING, N_("Salt"), N_("hex string"), CRYPT_ARG_STRING, {}, {})

ARG(OPT_USE_TASKLETS, '\0', POPT_ARG_NONE, N_("Use kernel tasklets for performance"), NULL, CRYPT_ARG_BOOL, {}, OPT_USE_TASKLETS_ACTIONS)

ARG(OPT_UUID, '\0', POPT_ARG_STRING, N_("UUID for device to use"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_VERBOSE, 'v', POPT_ARG_NONE, N_("Shows more detailed error messages"), NULL, CRYPT_ARG_BOOL, {}, {})
