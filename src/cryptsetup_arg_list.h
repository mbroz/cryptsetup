// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Cryptsetup command line arguments list
 *
 * Copyright (C) 2020-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2020-2025 Ondrej Kozina
 */

/* long name, short name, popt type, help description, units, internal argument type, default value, allowed actions (empty=global) */

ARG(OPT_ACTIVE_NAME, '\0', POPT_ARG_STRING, N_("Override device autodetection of dm device to be reencrypted"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_ALIGN_PAYLOAD, '\0', POPT_ARG_STRING, N_("Align payload at <n> sector boundaries - for luksFormat"), N_("SECTORS"), CRYPT_ARG_UINT32, {}, OPT_ALIGN_PAYLOAD_ACTIONS)

ARG(OPT_ALLOW_DISCARDS, '\0', POPT_ARG_NONE, N_("Allow discards (aka TRIM) requests for device"), NULL, CRYPT_ARG_BOOL, {}, OPT_ALLOW_DISCARDS_ACTIONS)

ARG(OPT_BATCH_MODE, 'q', POPT_ARG_NONE, N_("Do not ask for confirmation"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_CANCEL_DEFERRED, '\0', POPT_ARG_NONE, N_("Cancel a previously set deferred device removal"), NULL, CRYPT_ARG_BOOL, {}, OPT_DEFERRED_ACTIONS)

ARG(OPT_CIPHER, 'c', POPT_ARG_STRING, N_("The cipher used to encrypt the disk (see /proc/crypto)"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_DEBUG, '\0', POPT_ARG_NONE, N_("Show debug messages"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DEBUG_JSON, '\0', POPT_ARG_NONE, N_("Show debug messages including JSON metadata"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DECRYPT, '\0', POPT_ARG_NONE, N_("Decrypt LUKS2 device (remove encryption)"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DEFERRED, '\0', POPT_ARG_NONE, N_("Device removal is deferred until the last user closes it"), NULL, CRYPT_ARG_BOOL, {}, OPT_DEFERRED_ACTIONS)

ARG(OPT_DEVICE_SIZE, '\0', POPT_ARG_STRING, N_("Use only specified device size (ignore rest of device), DANGEROUS!"), N_("bytes"), CRYPT_ARG_UINT64, {}, OPT_DEVICE_SIZE_ACTIONS)

ARG(OPT_DISABLE_BLKID, '\0', POPT_ARG_NONE, N_("Disable blkid on-disk signature detection and wiping"), NULL, CRYPT_ARG_BOOL, {}, OPT_DISABLE_BLKID_ACTIONS)

ARG(OPT_DISABLE_EXTERNAL_TOKENS, '\0', POPT_ARG_NONE, N_("Disable loading of external LUKS2 token plugins"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DISABLE_KEYRING, '\0', POPT_ARG_NONE, N_("Disable loading volume keys via kernel keyring"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DISABLE_LOCKS, '\0', POPT_ARG_NONE, N_("Disable locking of on-disk metadata"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DISABLE_VERACRYPT, '\0', POPT_ARG_NONE, N_("Do not scan for VeraCrypt compatible device"), NULL, CRYPT_ARG_BOOL, {}, OPT_DISABLE_VERACRYPT_ACTIONS)

ARG(OPT_DUMP_JSON, '\0', POPT_ARG_NONE, N_("Dump info in JSON format (LUKS2 only)"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_DUMP_VOLUME_KEY, '\0', POPT_ARG_NONE, N_("Dump volume key instead of keyslots info"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_ENCRYPT, '\0', POPT_ARG_NONE, N_("Encrypt LUKS2 device (in-place encryption)"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_EXTERNAL_TOKENS_PATH, '\0', POPT_ARG_STRING, N_("Path to directory with external token handlers (plugins)."), NULL, CRYPT_ARG_STRING, {}, OPT_EXTERNAL_TOKENS_PATH_ACTIONS)

ARG(OPT_FORCE_PASSWORD, '\0', POPT_ARG_NONE, N_("Disable password quality check (if enabled)"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_FORCE_OFFLINE_REENCRYPT, '\0', POPT_ARG_NONE, N_("Force offline LUKS2 reencryption and bypass active device detection"), NULL, CRYPT_ARG_BOOL, {}, OPT_FORCE_OFFLINE_REENCRYPT_ACTIONS)

ARG(OPT_FORCE_NO_KEYSLOTS, '\0', POPT_ARG_NONE, N_("Force dangerous reencryption operation erasing all remaining keyslots"), NULL, CRYPT_ARG_BOOL, {}, OPT_FORCE_NO_KEYSLOTS_ACTIONS)

ARG(OPT_HASH, 'h', POPT_ARG_STRING, N_("The hash used to create the encryption key from the passphrase"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_HEADER, '\0', POPT_ARG_STRING, N_("Device or file with separated LUKS header"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_HEADER_BACKUP_FILE, '\0', POPT_ARG_STRING, N_("File with LUKS header and keyslots backup"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_HOTZONE_SIZE, '\0', POPT_ARG_STRING, N_("Maximal reencryption hotzone size"), N_("bytes"), CRYPT_ARG_UINT64, {}, OPT_HOTZONE_SIZE_ACTIONS)

ARG(OPT_HW_OPAL, '\0', POPT_ARG_NONE, N_("Use HW OPAL encryption together with SW encryption"), NULL, CRYPT_ARG_BOOL, {}, OPT_HW_OPAL_ACTIONS)

ARG(OPT_HW_OPAL_FACTORY_RESET, '\0', POPT_ARG_NONE, N_("Wipe WHOLE OPAL disk on luksErase"), NULL, CRYPT_ARG_BOOL, {}, OPT_ERASE_ACTIONS)

ARG(OPT_HW_OPAL_ONLY, '\0', POPT_ARG_NONE, N_("Use only HW OPAL encryption"), NULL, CRYPT_ARG_BOOL, {}, OPT_HW_OPAL_ONLY_ACTIONS)

ARG(OPT_INIT_ONLY, '\0', POPT_ARG_NONE, N_("Initialize LUKS2 reencryption in metadata only"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_INTEGRITY, 'I', POPT_ARG_STRING, N_("Data integrity algorithm (LUKS2 only)"), NULL, CRYPT_ARG_STRING, {}, OPT_INTEGRITY_ACTIONS)

ARG(OPT_INTEGRITY_INLINE, '\0', POPT_ARG_NONE, N_("Use inline mode (use HW integrity field)"), NULL, CRYPT_ARG_BOOL, {}, OPT_INTEGRITY_INLINE_ACTIONS)

ARG(OPT_INTEGRITY_KEY_SIZE, '\0', POPT_ARG_STRING, N_("The size of the data integrity key"), N_("BITS"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_INTEGRITY_LEGACY_PADDING,'\0', POPT_ARG_NONE, N_("Use inefficient legacy padding (old kernels)"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_INTEGRITY_NO_JOURNAL, '\0', POPT_ARG_NONE, N_("Disable journal for integrity device"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_INTEGRITY_NO_WIPE, '\0', POPT_ARG_NONE, N_("Do not wipe device after format"), NULL, CRYPT_ARG_BOOL, {}, OPT_INTEGRITY_NO_WIPE_ACTIONS)

ARG(OPT_ITER_TIME, 'i', POPT_ARG_STRING, N_("PBKDF iteration time for LUKS (in ms)"), N_("msecs"), CRYPT_ARG_UINT32, {}, OPT_ITER_TIME_ACTIONS)

ARG(OPT_IV_LARGE_SECTORS, '\0', POPT_ARG_NONE, N_("Use IV counted in sector size (not in 512 bytes)"), NULL , CRYPT_ARG_BOOL, {}, OPT_IV_LARGE_SECTORS_ACTIONS)

ARG(OPT_JSON_FILE, '\0', POPT_ARG_STRING, N_("Read or write the json from or to a file"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_KEEP_KEY, '\0', POPT_ARG_NONE, N_("Do not change volume key"), NULL, CRYPT_ARG_BOOL, {}, OPT_KEEP_KEY_ACTIONS)

ARG(OPT_KEY_DESCRIPTION, '\0', POPT_ARG_STRING, N_("Keyring key description"), NULL, CRYPT_ARG_STRING, {}, OPT_KEY_DESCRIPTION_ACTIONS)

ARG(OPT_KEY_FILE, 'd', POPT_ARG_STRING, N_("Read the key from a file"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_KEY_SIZE, 's', POPT_ARG_STRING, N_("The size of the encryption key"), N_("BITS"), CRYPT_ARG_UINT32, {}, OPT_KEY_SIZE_ACTIONS)

ARG(OPT_KEY_SLOT, 'S', POPT_ARG_STRING, N_("Slot number for new key (default is first free)"), "INT", CRYPT_ARG_INT32, { .i32_value = CRYPT_ANY_SLOT }, OPT_KEY_SLOT_ACTIONS)

ARG(OPT_KEYFILE_OFFSET, '\0', POPT_ARG_STRING, N_("Number of bytes to skip in keyfile"), N_("bytes"), CRYPT_ARG_UINT64, {}, {})

ARG(OPT_KEYFILE_SIZE, 'l', POPT_ARG_STRING, N_("Limits the read from keyfile"), N_("bytes"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_KEYSLOT_CIPHER, '\0', POPT_ARG_STRING, N_("LUKS2 keyslot: The cipher used for keyslot encryption"), NULL, CRYPT_ARG_STRING, {}, OPT_KEYSLOT_CIPHER_ACTIONS)

ARG(OPT_KEYSLOT_KEY_SIZE, '\0', POPT_ARG_STRING, N_("LUKS2 keyslot: The size of the encryption key"), N_("BITS"), CRYPT_ARG_UINT32, {}, OPT_KEYSLOT_KEY_SIZE_ACTIONS)

ARG(OPT_LABEL, '\0', POPT_ARG_STRING, N_("Set label for the LUKS2 device"), NULL, CRYPT_ARG_STRING, {}, OPT_LABEL_ACTIONS)

ARG(OPT_LINK_VK_TO_KEYRING, '\0', POPT_ARG_STRING, N_("Set keyring where to link volume key"), NULL, CRYPT_ARG_STRING, {}, OPT_LINK_VK_TO_KEYRING_ACTIONS)

ARG(OPT_LUKS2_KEYSLOTS_SIZE, '\0', POPT_ARG_STRING, N_("LUKS2 header keyslots area size"), N_("bytes"), CRYPT_ARG_UINT64, {}, OPT_LUKS2_KEYSLOTS_SIZE_ACTIONS)

ARG(OPT_LUKS2_METADATA_SIZE, '\0', POPT_ARG_STRING, N_("LUKS2 header metadata area size"), N_("bytes"), CRYPT_ARG_UINT64, {}, OPT_LUKS2_METADATA_SIZE_ACTIONS)

ARG(OPT_NEW_KEYFILE, '\0', POPT_ARG_STRING, N_("Read the key for a new slot from a file"), NULL, CRYPT_ARG_STRING, {}, OPT_NEW_KEYFILE_ACTIONS)

ARG(OPT_NEW_KEYFILE_OFFSET , '\0', POPT_ARG_STRING, N_("Number of bytes to skip in newly added keyfile"), N_("bytes"), CRYPT_ARG_UINT64, {}, {})

ARG(OPT_NEW_KEYFILE_SIZE, '\0', POPT_ARG_STRING, N_("Limits the read from newly added keyfile"), N_("bytes"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_NEW_KEY_DESCRIPTION, '\0', POPT_ARG_STRING, N_("Keyring new key description"), NULL, CRYPT_ARG_STRING, {}, OPT_NEW_KEY_DESCRIPTION_ACTIONS)

ARG(OPT_NEW_KEY_SIZE, '\0', POPT_ARG_STRING, N_("The size of the new encryption key"), N_("BITS"), CRYPT_ARG_UINT32, {}, OPT_NEW_KEY_SIZE_ACTIONS)

ARG(OPT_NEW_KEY_SLOT, '\0', POPT_ARG_STRING, N_("Slot number for new key (default is first free)"), "INT", CRYPT_ARG_INT32, { .i32_value = CRYPT_ANY_SLOT }, OPT_NEW_KEY_SLOT_ACTIONS)

ARG(OPT_NEW_TOKEN_ID, '\0', POPT_ARG_STRING, N_("Token number (default: any)"), "INT", CRYPT_ARG_INT32, { .i32_value = CRYPT_ANY_TOKEN }, OPT_NEW_TOKEN_ID_ACTIONS)

ARG(OPT_NEW_VOLUME_KEY_FILE, '\0', POPT_ARG_STRING, N_("Use the new volume key from file"), NULL, CRYPT_ARG_STRING, {}, OPT_NEW_VOLUME_KEY_FILE_ACTIONS)

ARG(OPT_NEW_VOLUME_KEY_KEYRING, '\0', POPT_ARG_STRING, N_("Use the specified keyring key as new volume key"), NULL, CRYPT_ARG_STRING, {}, OPT_NEW_VOLUME_KEY_KEYRING_ACTIONS)

ARG(OPT_OFFSET, 'o', POPT_ARG_STRING, N_("The start offset in the backend device"), N_("SECTORS"), CRYPT_ARG_UINT64, {}, OPT_OFFSET_ACTIONS)

ARG(OPT_PBKDF, '\0', POPT_ARG_STRING, N_("PBKDF algorithm (for LUKS2): argon2i, argon2id, pbkdf2"), NULL, CRYPT_ARG_STRING, {}, OPT_PBKDF_ACTIONS)

ARG(OPT_PBKDF_FORCE_ITERATIONS, '\0', POPT_ARG_STRING, N_("PBKDF iterations cost (forced, disables benchmark)"), "LONG", CRYPT_ARG_UINT32, {}, OPT_PBKDF_FORCE_ITERATIONS_ACTIONS)

ARG(OPT_PBKDF_MEMORY, '\0', POPT_ARG_STRING, N_("PBKDF memory cost limit"), N_("kilobytes"), CRYPT_ARG_UINT32, { .u32_value = DEFAULT_LUKS2_MEMORY_KB }, {})

ARG(OPT_PBKDF_PARALLEL, '\0', POPT_ARG_STRING, N_("PBKDF parallel cost"), N_("threads"), CRYPT_ARG_UINT32, { .u32_value = DEFAULT_LUKS2_PARALLEL_THREADS }, {})

ARG(OPT_PERF_HIGH_PRIORITY, '\0', POPT_ARG_NONE, N_("Set dm-crypt workqueues and the writer thread to high priority"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_PERF_NO_READ_WORKQUEUE, '\0', POPT_ARG_NONE, N_("Bypass dm-crypt workqueue and process read requests synchronously"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_PERF_NO_WRITE_WORKQUEUE, '\0', POPT_ARG_NONE, N_("Bypass dm-crypt workqueue and process write requests synchronously"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_PERF_SAME_CPU_CRYPT, '\0', POPT_ARG_NONE, N_("Use dm-crypt same_cpu_crypt performance compatibility option"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_PERF_SUBMIT_FROM_CRYPT_CPUS, '\0', POPT_ARG_NONE, N_("Use dm-crypt submit_from_crypt_cpus performance compatibility option"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_PERSISTENT, '\0', POPT_ARG_NONE, N_("Set activation flags persistent for device"), NULL, CRYPT_ARG_BOOL, {}, OPT_PERSISTENT_ACTIONS)

ARG(OPT_PRIORITY, '\0', POPT_ARG_STRING, N_("Keyslot priority: ignore, normal, prefer"), NULL, CRYPT_ARG_STRING, {}, OPT_PRIORITY_ACTIONS)

ARG(OPT_PROGRESS_JSON, '\0', POPT_ARG_NONE, N_("Print progress data in json format (suitable for machine processing)"), NULL, CRYPT_ARG_BOOL, {}, OPT_PROGRESS_JSON_ACTIONS)

ARG(OPT_PROGRESS_FREQUENCY, '\0', POPT_ARG_STRING, N_("Progress line update (in seconds)"), N_("secs"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_READONLY, 'r', POPT_ARG_NONE, N_("Create a readonly mapping"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_REDUCE_DEVICE_SIZE, '\0', POPT_ARG_STRING, N_("Reduce data device size (move data offset), DANGEROUS!"), N_("bytes"), CRYPT_ARG_UINT64, {}, {})

ARG(OPT_REFRESH, '\0', POPT_ARG_NONE, N_("Refresh (reactivate) device with new parameters"), NULL, CRYPT_ARG_BOOL, {}, OPT_REFRESH_ACTIONS)

ARG(OPT_RESILIENCE, '\0', POPT_ARG_STRING, N_("Reencryption hotzone resilience type (checksum,journal,none)"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_RESILIENCE_HASH, '\0', POPT_ARG_STRING, N_("Reencryption hotzone checksums hash"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_RESUME_ONLY, '\0', POPT_ARG_NONE, N_("Resume initialized LUKS2 reencryption only"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_SECTOR_SIZE, '\0', POPT_ARG_STRING, N_("Encryption sector size (default: 512 bytes)"), "INT", CRYPT_ARG_UINT32, {}, OPT_SECTOR_SIZE_ACTIONS)

ARG(OPT_SERIALIZE_MEMORY_HARD_PBKDF, '\0', POPT_ARG_NONE, N_("Use global lock to serialize memory hard PBKDF (OOM workaround)"), NULL, CRYPT_ARG_BOOL, {}, OPT_SERIALIZE_MEMORY_HARD_PBKDF_ACTIONS)

ARG(OPT_SHARED, '\0', POPT_ARG_NONE, N_("Share device with another non-overlapping crypt segment"), NULL, CRYPT_ARG_BOOL, {}, OPT_SHARED_ACTIONS )

ARG(OPT_SIZE, 'b', POPT_ARG_STRING, N_("The size of the device"), N_("SECTORS"), CRYPT_ARG_UINT64, {}, OPT_SIZE_ACTIONS)

ARG(OPT_SKIP, 'p', POPT_ARG_STRING, N_("How many sectors of the encrypted data to skip at the beginning"), N_("SECTORS"), CRYPT_ARG_UINT64, {}, OPT_SKIP_ACTIONS)

ARG(OPT_SUBSYSTEM, '\0', POPT_ARG_STRING, N_("Set subsystem label for the LUKS2 device"), NULL, CRYPT_ARG_STRING, {}, OPT_SUBSYSTEM_ACTIONS)

ARG(OPT_TEST_ARGS, '\0', POPT_ARG_NONE, N_("Do not run action, just validate all command line parameters"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_TEST_PASSPHRASE, '\0', POPT_ARG_NONE, N_("Do not activate device, just check passphrase"), NULL, CRYPT_ARG_BOOL, {}, OPT_TEST_PASSPHRASE_ACTIONS)

ARG(OPT_TIMEOUT, 't', POPT_ARG_STRING, N_("Timeout for interactive passphrase prompt (in seconds)"), N_("secs"), CRYPT_ARG_UINT32, {}, {})

ARG(OPT_TOKEN_ID, '\0', POPT_ARG_STRING, N_("Token number (default: any)"), "INT", CRYPT_ARG_INT32, { .i32_value = CRYPT_ANY_TOKEN }, {})

ARG(OPT_TOKEN_ONLY, '\0', POPT_ARG_NONE, N_("Do not ask for passphrase if activation by token fails"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_TOKEN_REPLACE, '\0', POPT_ARG_NONE, N_("Replace the current token"), NULL, CRYPT_ARG_BOOL, {}, OPT_TOKEN_REPLACE_ACTIONS)

ARG(OPT_TOKEN_TYPE, '\0', POPT_ARG_STRING, N_("Restrict allowed token types used to retrieve LUKS2 key"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_TCRYPT_BACKUP, '\0', POPT_ARG_NONE, N_("Use backup (secondary) TCRYPT header"), NULL, CRYPT_ARG_BOOL, {}, OPT_TCRYPT_BACKUP_ACTIONS)

ARG(OPT_TCRYPT_HIDDEN, '\0', POPT_ARG_NONE, N_("Use hidden header (hidden TCRYPT device)"), NULL, CRYPT_ARG_BOOL, {}, OPT_TCRYPT_HIDDEN_ACTIONS)

ARG(OPT_TCRYPT_SYSTEM, '\0', POPT_ARG_NONE, N_("Device is system TCRYPT drive (with bootloader)"), NULL, CRYPT_ARG_BOOL, {}, OPT_TCRYPT_SYSTEM_ACTIONS)

ARG(OPT_TRIES, 'T', POPT_ARG_STRING, N_("How often the input of the passphrase can be retried"), "INT", CRYPT_ARG_UINT32, { .u32_value = 3 }, {})

ARG(OPT_TYPE, 'M', POPT_ARG_STRING, N_("Type of device metadata: luks, luks1, luks2, plain, loopaes, tcrypt, bitlk"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_UNBOUND, '\0', POPT_ARG_NONE, N_("Create or dump unbound LUKS2 keyslot (unassigned to data segment) or LUKS2 token (unassigned to keyslot)"), NULL, CRYPT_ARG_BOOL, {}, OPT_UNBOUND_ACTIONS)

ARG(OPT_USE_RANDOM, '\0', POPT_ARG_NONE, N_("Use /dev/random for generating volume key"), NULL, CRYPT_ARG_BOOL, {}, OPT_USE_RANDOM_ACTIONS)

ARG(OPT_USE_URANDOM, '\0', POPT_ARG_NONE, N_("Use /dev/urandom for generating volume key"), NULL, CRYPT_ARG_BOOL, {}, OPT_USE_URANDOM_ACTIONS)

ARG(OPT_UUID, '\0', POPT_ARG_STRING, N_("UUID for device to use"), NULL, CRYPT_ARG_STRING, {}, OPT_UUID_ACTIONS)

ARG(OPT_VERACRYPT, '\0', POPT_ARG_NONE, N_("Scan also for VeraCrypt compatible device"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_VERACRYPT_PIM, '\0', POPT_ARG_STRING, N_("Personal Iteration Multiplier for VeraCrypt compatible device"), "INT", CRYPT_ARG_UINT32, {}, OPT_VERACRYPT_PIM_ACTIONS)

ARG(OPT_VERACRYPT_QUERY_PIM, '\0', POPT_ARG_NONE, N_("Query Personal Iteration Multiplier for VeraCrypt compatible device"), NULL, CRYPT_ARG_BOOL, {}, OPT_VERACRYPT_QUERY_PIM_ACTIONS)

ARG(OPT_VERBOSE, 'v', POPT_ARG_NONE, N_("Shows more detailed error messages"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_VERIFY_PASSPHRASE, 'y', POPT_ARG_NONE, N_("Verifies the passphrase by asking for it twice"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_VOLUME_KEY_FILE, '\0', POPT_ARG_STRING, N_("Use the volume key from file"), NULL, CRYPT_ARG_STRING, {}, {})

ARG(OPT_VOLUME_KEY_KEYRING, '\0', POPT_ARG_STRING, N_("Use the specified keyring key as a volume key"), NULL, CRYPT_ARG_STRING, {}, {})

/* added for reencryption */

ARG(OPT_BLOCK_SIZE, 'B', POPT_ARG_STRING, N_("Reencryption block size"), N_("MiB"), CRYPT_ARG_UINT32, { .u32_value = 4 }, {})

ARG(OPT_NEW, 'N', POPT_ARG_NONE, N_("Create new header on not encrypted device"), NULL, CRYPT_ARG_ALIAS, { .o.id = OPT_ENCRYPT_ID }, {})

ARG(OPT_USE_DIRECTIO, '\0', POPT_ARG_NONE, N_("Use direct-io when accessing devices"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_USE_FSYNC, '\0', POPT_ARG_NONE, N_("Use fsync after each block"), NULL, CRYPT_ARG_BOOL, {}, {})

ARG(OPT_WRITE_LOG, '\0', POPT_ARG_NONE, N_("Update log file after every block"), NULL, CRYPT_ARG_BOOL, {}, {})

/* aliases */

ARG(OPT_DUMP_MASTER_KEY, '\0', POPT_ARG_NONE, N_("Alias for --dump-volume-key"), NULL, CRYPT_ARG_ALIAS, { .o.id = OPT_DUMP_VOLUME_KEY_ID}, {})

ARG(OPT_MASTER_KEY_FILE, '\0', POPT_ARG_STRING, N_("Alias for --volume-key-file"), NULL, CRYPT_ARG_ALIAS, { .o.id = OPT_VOLUME_KEY_FILE_ID}, {})
