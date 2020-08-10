/*
 * Cryptsetup-reencrypt command line arguments list
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

/* long name, short name, popt type, help description, units, internal argument type, default value */

ARG(OPT_BATCH_MODE, 'q', POPT_ARG_NONE, N_("Do not ask for confirmation"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_BLOCK_SIZE, 'B', POPT_ARG_STRING, N_("Reencryption block size"), N_("MiB"), CRYPT_ARG_UINT32, { .u32_value = 4 })

ARG(OPT_CIPHER, 'c', POPT_ARG_STRING, N_("The cipher used to encrypt the disk (see /proc/crypto)"), NULL, CRYPT_ARG_STRING, {})

ARG(OPT_DEBUG, '\0', POPT_ARG_NONE, N_("Show debug messages"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_DECRYPT, '\0', POPT_ARG_NONE, N_("Permanently decrypt device (remove encryption)"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_DEVICE_SIZE, '\0', POPT_ARG_STRING, N_("Use only specified device size (ignore rest of device). DANGEROUS!"), N_("bytes"), CRYPT_ARG_UINT64, {})

ARG(OPT_HASH, 'h', POPT_ARG_STRING, N_("The hash used to create the encryption key from the passphrase"), NULL, CRYPT_ARG_STRING, {})

ARG(OPT_HEADER, '\0', POPT_ARG_STRING, N_("Device or file with separated LUKS header"), NULL, CRYPT_ARG_STRING, {})

ARG(OPT_ITER_TIME, 'i', POPT_ARG_STRING, N_("PBKDF iteration time for LUKS (in ms)"), N_("msecs"), CRYPT_ARG_UINT32, {})

ARG(OPT_KEEP_KEY, '\0', POPT_ARG_NONE, N_("Do not change key, no data area reencryption"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_KEY_FILE, 'd', POPT_ARG_STRING, N_("Read the key from a file"), NULL, CRYPT_ARG_STRING, {})

ARG(OPT_KEY_SIZE, 's', POPT_ARG_STRING, N_("The size of the encryption key"), N_("BITS"), CRYPT_ARG_UINT32, {})

ARG(OPT_KEYFILE_OFFSET, '\0', POPT_ARG_STRING, N_("Number of bytes to skip in keyfile"), N_("bytes"), CRYPT_ARG_UINT64, {})

ARG(OPT_KEYFILE_SIZE, 'l', POPT_ARG_STRING, N_("Limits the read from keyfile"), N_("bytes"), CRYPT_ARG_UINT32, {})

ARG(OPT_KEY_SLOT, 'S', POPT_ARG_STRING, N_("Use only this slot (others will be disabled)"), "INT", CRYPT_ARG_INT32, { .i32_value = CRYPT_ANY_SLOT })

ARG(OPT_MASTER_KEY_FILE, '\0', POPT_ARG_STRING, N_("Read new volume (master) key from file"), NULL, CRYPT_ARG_STRING, {})

ARG(OPT_NEW, 'N', POPT_ARG_NONE, N_("Create new header on not encrypted device"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_PBKDF, '\0', POPT_ARG_STRING, N_("PBKDF algorithm (for LUKS2): argon2i, argon2id, pbkdf2"), NULL, CRYPT_ARG_STRING, {})

ARG(OPT_PBKDF_FORCE_ITERATIONS, '\0', POPT_ARG_STRING, N_("PBKDF iterations cost (forced, disables benchmark)"), "LONG", CRYPT_ARG_UINT32, {})

ARG(OPT_PBKDF_MEMORY, '\0', POPT_ARG_STRING, N_("PBKDF memory cost limit"), N_("kilobytes"), CRYPT_ARG_UINT32, { .u32_value = DEFAULT_LUKS2_MEMORY_KB })

ARG(OPT_PBKDF_PARALLEL, '\0', POPT_ARG_STRING, N_("PBKDF parallel cost"), N_("threads"), CRYPT_ARG_UINT32, { .u32_value = DEFAULT_LUKS2_PARALLEL_THREADS })

ARG(OPT_PROGRESS_FREQUENCY, '\0', POPT_ARG_STRING, N_("Progress line update (in seconds)"), N_("secs"), CRYPT_ARG_UINT32, {})

ARG(OPT_REDUCE_DEVICE_SIZE, '\0', POPT_ARG_STRING, N_("Reduce data device size (move data offset). DANGEROUS!"), N_("bytes"), CRYPT_ARG_UINT64, {})

ARG(OPT_TRIES, 'T', POPT_ARG_STRING, N_("How often the input of the passphrase can be retried"), "INT", CRYPT_ARG_UINT32, { .u32_value = 3 })

ARG(OPT_TYPE, 'M', POPT_ARG_STRING,  N_("Type of LUKS metadata: luks1, luks2"), NULL, CRYPT_ARG_STRING, {})

ARG(OPT_USE_DIRECTIO, '\0', POPT_ARG_NONE, N_("Use direct-io when accessing devices"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_USE_FSYNC, '\0', POPT_ARG_NONE, N_("Use fsync after each block"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_USE_RANDOM, '\0', POPT_ARG_NONE, N_("Use /dev/random for generating volume key"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_USE_URANDOM, '\0', POPT_ARG_NONE, N_("Use /dev/urandom for generating volume key"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_UUID, '\0', POPT_ARG_STRING, N_("The UUID used to resume decryption"), NULL, CRYPT_ARG_STRING, {})

ARG(OPT_VERBOSE, 'v', POPT_ARG_NONE, N_("Shows more detailed error messages"), NULL, CRYPT_ARG_BOOL, {})

ARG(OPT_WRITE_LOG, '\0', POPT_ARG_NONE, N_("Update log file after every block"), NULL, CRYPT_ARG_BOOL, {})
