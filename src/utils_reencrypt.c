// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup - action re-encryption utilities
 *
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 * Copyright (C) 2021-2025 Ondrej Kozina
 */

#include <uuid/uuid.h>

#include "cryptsetup.h"
#include "cryptsetup_args.h"
#include "utils_luks.h"

extern int64_t data_shift;
extern const char *device_type;
extern const char *set_pbkdf;

enum device_status_info {
	DEVICE_LUKS2 = 0,	/* LUKS2 device */
	DEVICE_LUKS2_REENCRYPT,	/* LUKS2 device in reencryption  */
	DEVICE_LUKS1,		/* LUKS1 device */
	DEVICE_LUKS1_UNUSABLE,	/* LUKS1 device in reencryption (legacy) */
	DEVICE_NOT_LUKS,	/* device is not LUKS type */
	DEVICE_INVALID		/* device is invalid */
};

static void _set_reencryption_flags(uint32_t *flags)
{
	if (ARG_SET(OPT_INIT_ONLY_ID))
		*flags |= CRYPT_REENCRYPT_INITIALIZE_ONLY;

	if (ARG_SET(OPT_RESUME_ONLY_ID))
		*flags |= CRYPT_REENCRYPT_RESUME_ONLY;

	if ((ARG_SET(OPT_VOLUME_KEY_FILE_ID) || ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) &&
	    (ARG_SET(OPT_NEW_VOLUME_KEY_FILE_ID) || ARG_SET(OPT_NEW_VOLUME_KEY_KEYRING_ID)))
		*flags |= CRYPT_REENCRYPT_CREATE_NEW_DIGEST;
}

static int set_keyslot_params(struct crypt_device *cd, int keyslot)
{
	const char *cipher;
	struct crypt_pbkdf_type pbkdf;
	size_t key_size;

	cipher = crypt_keyslot_get_encryption(cd, keyslot, &key_size);
	if (!cipher)
		return -EINVAL;

	if (crypt_is_cipher_null(cipher)) {
		log_dbg("Keyslot %d uses cipher_null. "
			"Replacing with default encryption in new keyslot.", keyslot);
		cipher = DEFAULT_LUKS2_KEYSLOT_CIPHER;
		key_size = DEFAULT_LUKS2_KEYSLOT_KEYBITS / 8;
	}

	if (crypt_keyslot_set_encryption(cd, cipher, key_size))
		return -EINVAL;

	/* if requested any of those just reinitialize context pbkdf */
	if (set_pbkdf || ARG_SET(OPT_HASH_ID) || ARG_SET(OPT_PBKDF_FORCE_ITERATIONS_ID) ||
	    ARG_SET(OPT_ITER_TIME_ID))
		return set_pbkdf_params(cd, CRYPT_LUKS2);

	if (crypt_keyslot_get_pbkdf(cd, keyslot, &pbkdf))
		return -EINVAL;

	pbkdf.flags |= CRYPT_PBKDF_NO_BENCHMARK;

	return crypt_set_pbkdf_type(cd, &pbkdf);
}

static int get_active_device_name(struct crypt_device *cd,
	const char *data_device,
	char **r_active_name)
{
	char *msg;
	int r;

	assert(data_device);

	r = tools_lookup_crypt_device(cd, crypt_get_type(cd), data_device, r_active_name);
	if (r > 0) {
		log_dbg("Device %s has %d active holders.", data_device, r);

		if (!*r_active_name) {
			log_err(_("Device %s is still in use."), data_device);
			return -EINVAL;
		}
		if (!ARG_SET(OPT_BATCH_MODE_ID))
			log_std(_("Auto-detected active dm device '%s' for data device %s.\n"),
				*r_active_name, data_device);
	} else if (r < 0) {
		if (r != -ENOTBLK) {
			log_err(_("Failed to auto-detect device %s holders."), data_device);
			return -EINVAL;
		}

		r = -EINVAL;
		if (!ARG_SET(OPT_BATCH_MODE_ID)) {
			log_std(_("Device %s is not a block device.\n"), data_device);

			r = asprintf(&msg, _("Unable to decide if device %s is activated or not.\n"
					     "Are you sure you want to proceed with reencryption in offline mode?\n"
					     "It may lead to data corruption if the device is actually activated.\n"
					     "To run reencryption in online mode, use --active-name parameter instead.\n"), data_device);
			if (r < 0)
				return -ENOMEM;
			r = noDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
			free(msg);
		} else {
			log_err(_("Device %s is not a block device. Can not auto-detect if it is active or not.\n"
				"Use --force-offline-reencrypt to bypass the check and run in offline mode (dangerous!)."), data_device);
		}
	} else {
		*r_active_name = NULL;
		log_dbg("Device %s is unused. Proceeding with offline reencryption.", data_device);
	}

	return r;
}

static int reencrypt_get_active_name(struct crypt_device *cd,
	const char *data_device,
	char **r_active_name)
{
	assert(cd);
	assert(r_active_name);

	if (ARG_SET(OPT_ACTIVE_NAME_ID))
		return (*r_active_name = strdup(ARG_STR(OPT_ACTIVE_NAME_ID))) ? 0 : -ENOMEM;

	return get_active_device_name(cd, data_device, r_active_name);
}

static int decrypt_verify_and_set_params(struct crypt_params_reencrypt *params)
{
	const char *resilience;

	assert(params);

	if (!ARG_SET(OPT_RESILIENCE_ID))
		return 0;

	resilience = ARG_STR(OPT_RESILIENCE_ID);

	if (!strcmp(resilience, "datashift") ||
	    !strcmp(resilience, "none")) {
		log_err(_("Requested --resilience option cannot be applied "
			  "to current reencryption operation."));
		return -EINVAL;
	} else if (!strcmp(resilience, "journal"))
		params->resilience = "datashift-journal";
	else if (!strcmp(resilience, "checksum"))
		params->resilience = "datashift-checksum";
	else if (!strcmp(resilience, "datashift-checksum") ||
		 !strcmp(resilience, "datashift-journal"))
		params->resilience = resilience;
	else {
		log_err(_("Unsupported resilience mode %s"), resilience);
		return -EINVAL;
	}

	return 0;
}

static int reencrypt_verify_and_update_params(struct crypt_params_reencrypt *params,
	char **r_hash)
{
	assert(params);
	assert(r_hash);

	if (ARG_SET(OPT_ENCRYPT_ID) && params->mode != CRYPT_REENCRYPT_ENCRYPT) {
		log_err(_("Device is not in LUKS2 encryption. Conflicting option --encrypt."));
		return -EINVAL;
	}

	if (ARG_SET(OPT_DECRYPT_ID) && params->mode != CRYPT_REENCRYPT_DECRYPT) {
		log_err(_("Device is not in LUKS2 decryption. Conflicting option --decrypt."));
		return -EINVAL;
	}

	if (ARG_SET(OPT_RESILIENCE_ID)) {
		if (!strcmp(params->resilience, "datashift") &&
		    strcmp(ARG_STR(OPT_RESILIENCE_ID), "datashift")) {
			log_err(_("Device is in reencryption using datashift resilience. "
				  "Requested --resilience option cannot be applied."));
			return -EINVAL;
		}
		if (strcmp(params->resilience, "datashift") &&
		    !strcmp(ARG_STR(OPT_RESILIENCE_ID), "datashift")) {
			log_err(_("Requested --resilience option cannot be applied "
				  "to current reencryption operation."));
			return -EINVAL;
		}

		if (!strncmp(params->resilience, "datashift-", 10)) {
			/* decryption with datashift in progress */
			if (decrypt_verify_and_set_params(params))
				return -EINVAL;
		} else if (!strncmp(ARG_STR(OPT_RESILIENCE_ID), "datashift-", 10)) {
			log_err(_("Requested --resilience option cannot be applied "
				  "to current reencryption operation."));
			return -EINVAL;
		} else
			params->resilience = ARG_STR(OPT_RESILIENCE_ID);

		/* we have to copy hash string returned by API */
		if (params->hash && !ARG_SET(OPT_RESILIENCE_HASH_ID)) {
			/* r_hash owns the memory. Freed by caller */
			*r_hash = strdup(params->hash);
			if (!*r_hash)
				return -ENOMEM;
			params->hash = *r_hash;
		}

		/* Add default hash when switching to checksum based resilience */
		if (!params->hash && !ARG_SET(OPT_RESILIENCE_HASH_ID) &&
		    (!strcmp(params->resilience, "checksum") ||
		    !strcmp(params->resilience, "datashift-checksum")))
			params->hash = "sha256";

		if (ARG_SET(OPT_RESILIENCE_HASH_ID))
			params->hash = ARG_STR(OPT_RESILIENCE_HASH_ID);
	} else
		params->resilience = NULL;

	params->max_hotzone_size = ARG_UINT64(OPT_HOTZONE_SIZE_ID) / SECTOR_SIZE;
	params->device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE;
	params->flags = CRYPT_REENCRYPT_RESUME_ONLY;

	return 0;
}

static int reencrypt_hint_force_offline_reencrypt(const char *data_device)
{
	struct stat st;

	if (ARG_SET(OPT_ACTIVE_NAME_ID) ||
	    !ARG_SET(OPT_BATCH_MODE_ID) ||
	    ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID))
		return 0;

	if (stat(data_device, &st) == 0 && S_ISREG(st.st_mode)) {
		log_err(_("Device %s is not a block device. Can not auto-detect if it is active or not.\n"
			"Use --force-offline-reencrypt to bypass the check and run in offline mode (dangerous!)."), data_device);
		return -EINVAL;
	}

	return 0;
}

static int reencrypt_multi_key_unlock(struct crypt_device *cd,
				       const struct crypt_params_reencrypt *params,
				       struct crypt_keyslot_context **r_kc1,
				       struct crypt_keyslot_context **r_kc2)
{
	int r, tries, keysize_bytes, new_keysize_bytes;
	struct crypt_keyslot_context *kc1 = NULL, *kc2 = NULL;

	assert(cd);
	assert(params);
	assert(r_kc1);
	assert(r_kc2);

	keysize_bytes = crypt_get_old_volume_key_size(cd);
	new_keysize_bytes = crypt_get_volume_key_size(cd);

	if (!keysize_bytes && ARG_SET(OPT_KEY_SIZE_ID))
		keysize_bytes = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;
	if (!new_keysize_bytes && ARG_SET(OPT_NEW_KEY_SIZE_ID))
		new_keysize_bytes = ARG_UINT32(OPT_NEW_KEY_SIZE_ID) / 8;

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID) && !keysize_bytes) {
		log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --key-size option."));
		return -EINVAL;
	}

	if (ARG_SET(OPT_NEW_VOLUME_KEY_FILE_ID) && !new_keysize_bytes) {
		log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --new-key-size option."));
		return -EINVAL;
	}

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID) ||
	    ARG_SET(OPT_NEW_VOLUME_KEY_FILE_ID) ||
	    ARG_SET(OPT_VOLUME_KEY_KEYRING_ID) ||
	    ARG_SET(OPT_NEW_VOLUME_KEY_KEYRING_ID)) {
		r = luks_init_keyslot_contexts_by_volume_keys(cd, ARG_STR(OPT_VOLUME_KEY_FILE_ID),
							      ARG_STR(OPT_NEW_VOLUME_KEY_FILE_ID),
							      keysize_bytes, new_keysize_bytes,
							      ARG_STR(OPT_VOLUME_KEY_KEYRING_ID),
							      ARG_STR(OPT_NEW_VOLUME_KEY_KEYRING_ID),
							      &kc1, &kc2);
		if (r < 0)
			return r;

		r = crypt_activate_by_keyslot_context(cd, NULL, ARG_INT32(OPT_KEY_SLOT_ID),
						      kc1, ARG_INT32(OPT_NEW_KEY_SLOT_ID), kc2,
						      0);
		if (r == -ESRCH)
			log_err(_("Device requires two volume keys."));
		if (r == -EPERM)
			log_err(_("Volume key does not match the volume."));
	} else {
		r = luks_try_token_unlock(cd, ARG_INT32(OPT_KEY_SLOT_ID),
					  ARG_INT32(OPT_TOKEN_ID_ID), NULL,
					  ARG_STR(OPT_TOKEN_TYPE_ID), 0,
					  set_tries_tty(false), true,
					  ARG_SET(OPT_TOKEN_ONLY_ID) || ARG_SET(OPT_TOKEN_ID_ID) || ARG_SET(OPT_TOKEN_TYPE_ID),
					  &kc1);

		if (r >= 0 || quit || ARG_SET(OPT_TOKEN_ONLY_ID))
			goto out;

		r = -ENOENT;

		tries = set_tries_tty(true);
		do {
			crypt_keyslot_context_free(kc1);
			kc1 = NULL;
			r = luks_init_keyslot_context(cd, NULL, verify_passphrase(0), false, &kc1);
			if (r < 0)
				goto out;

			r = crypt_activate_by_keyslot_context(cd, NULL, ARG_INT32(OPT_KEY_SLOT_ID),
							      kc1, ARG_INT32(OPT_NEW_KEY_SLOT_ID),
							      kc1, 0);

			tools_keyslot_msg(r, UNLOCKED);
			tools_passphrase_msg(r);
			check_signal(&r);
		} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
	}

out:
	if (r >= 0) {
		*r_kc1 = kc1;
		*r_kc2 = kc2;
	} else {
		crypt_keyslot_context_free(kc1);
		crypt_keyslot_context_free(kc2);
	}

	return r;
}

static int reencrypt_single_key_unlock(struct crypt_device *cd,
				       const struct crypt_params_reencrypt *params,
				       struct crypt_keyslot_context **r_kc)
{
	int r, tries, keysize = 0;
	struct crypt_keyslot_context *kc = NULL, *dummy = NULL;

	assert(params);
	assert(r_kc);

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID) || ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
		if (params->mode == CRYPT_REENCRYPT_DECRYPT)
			keysize = crypt_get_old_volume_key_size(cd);
		else if (params->mode == CRYPT_REENCRYPT_ENCRYPT)
			keysize = crypt_get_volume_key_size(cd);

		if (!keysize && ARG_SET(OPT_KEY_SIZE_ID))
			keysize = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;

		if (!keysize && !ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
			log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --key-size option."));
			return -EINVAL;
		}

		r = luks_init_keyslot_contexts_by_volume_keys(cd, ARG_STR(OPT_VOLUME_KEY_FILE_ID),
							      NULL /* unused */,
							      keysize,
							      0 /* unused */,
							      ARG_STR(OPT_VOLUME_KEY_KEYRING_ID),
							      NULL /* unused */,
							      &kc, &dummy);
		if (r < 0)
			goto out;
		r = crypt_activate_by_keyslot_context(cd, NULL, ARG_INT32(OPT_KEY_SLOT_ID),
						      kc, CRYPT_ANY_SLOT, NULL, 0);
	} else {
		r = luks_try_token_unlock(cd, ARG_INT32(OPT_KEY_SLOT_ID),
					  ARG_INT32(OPT_TOKEN_ID_ID), NULL,
					  ARG_STR(OPT_TOKEN_TYPE_ID), 0,
					  set_tries_tty(false), true,
					  ARG_SET(OPT_TOKEN_ONLY_ID) || ARG_SET(OPT_TOKEN_ID_ID) || ARG_SET(OPT_TOKEN_TYPE_ID),
					  &kc);

		if (r >= 0 || quit || ARG_SET(OPT_TOKEN_ONLY_ID))
			goto out;

		r = -ENOENT;

		tries = set_tries_tty(true);
		do {
			crypt_keyslot_context_free(kc);
			kc = NULL;
			r = luks_init_keyslot_context(cd, NULL, verify_passphrase(0), false, &kc);
			if (r < 0)
				goto out;

			r = crypt_activate_by_keyslot_context(cd, NULL, ARG_INT32(OPT_KEY_SLOT_ID),
							      kc, CRYPT_ANY_SLOT, NULL, 0);

			tools_keyslot_msg(r, UNLOCKED);
			tools_passphrase_msg(r);
			check_signal(&r);
		} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
	}

out:
	if (r >= 0)
		*r_kc = kc;
	else
		crypt_keyslot_context_free(kc);

	crypt_keyslot_context_free(dummy); /* unused */

	return r;
}

static int reencrypt_luks2_load(struct crypt_device *cd, const char *data_device)
{
	char *msg;
	crypt_reencrypt_info ri;
	int r;
	char *active_name = NULL, *hash = NULL;
	struct crypt_params_reencrypt params = {};
	struct crypt_keyslot_context *kc = NULL, *kc2 = NULL;

	ri = crypt_reencrypt_status(cd, &params);
	if (ri == CRYPT_REENCRYPT_CRASH)
		log_err(_("Device requires reencryption recovery. Run repair first."));

	if (ri != CRYPT_REENCRYPT_CLEAN)
		return -EINVAL;

	r = reencrypt_verify_and_update_params(&params, &hash);
	if (r < 0)
		return r;

	r = reencrypt_hint_force_offline_reencrypt(data_device);
	if (r < 0)
		goto out;

	if (!ARG_SET(OPT_BATCH_MODE_ID) && !ARG_SET(OPT_RESUME_ONLY_ID)) {
		r = asprintf(&msg, _("Device %s is already in LUKS2 reencryption. "
				     "Do you wish to resume previously initialised operation?"),
			     crypt_get_metadata_device_name(cd) ?: crypt_get_device_name(cd));
		if (r < 0) {
			r = -ENOMEM;
			goto out;
		}
		r = yesDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
		free(msg);
		if (r < 0)
			goto out;
	}

	if (params.mode == CRYPT_REENCRYPT_REENCRYPT)
		r = reencrypt_multi_key_unlock(cd, &params, &kc, &kc2);
	else
		r = reencrypt_single_key_unlock(cd, &params, &kc);
	if (r < 0)
		goto out;

	if (!ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID))
		r = reencrypt_get_active_name(cd, data_device, &active_name);
	if (r >= 0)
		r = crypt_reencrypt_init_by_keyslot_context(cd, active_name, kc, kc2 ?: kc,
							    ARG_INT32(OPT_KEY_SLOT_ID),
							    ARG_INT32(OPT_NEW_KEY_SLOT_ID),
							    NULL, NULL, &params);
out:
	free(hash);
	crypt_keyslot_context_free(kc);
	crypt_keyslot_context_free(kc2);
	free(active_name);
	return r;
}

/*
 *   1: in-progress
 *   0: clean luks2 device
 * < 0: error
 */
static int luks2_reencrypt_in_progress(struct crypt_device *cd)
{
	uint32_t flags;

	if (crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &flags))
		return -EINVAL;

	return flags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT;
}

/*
 * Returns crypt context for:
 *   DEVICE_LUKS2
 *   DEVICE_LUKS2_REENCRYPT
 *   DEVICE_LUKS1
 */
static enum device_status_info load_luks(struct crypt_device **r_cd,
	const char *header_device,
	const char *data_device)
{
	int r;
	struct crypt_device *cd;
	struct stat st;

	assert(r_cd);
	assert(data_device);

	if (header_device && stat(header_device, &st) < 0 && errno == ENOENT)
		return DEVICE_NOT_LUKS;

	if (crypt_init_data_device(&cd, uuid_or_device(header_device ?: data_device), data_device))
		return DEVICE_INVALID;

	if ((r = crypt_load(cd, CRYPT_LUKS, NULL))) {
		crypt_free(cd);

		if (r == -EBUSY) /* luks2 locking error (message printed by libcryptsetup) */
			return DEVICE_INVALID;

		r = reencrypt_luks1_in_progress(uuid_or_device(header_device ?: data_device));
		if (!r)
			return DEVICE_LUKS1_UNUSABLE;

		return DEVICE_NOT_LUKS;
	}

	if (isLUKS2(crypt_get_type(cd))) {
		r = luks2_reencrypt_in_progress(cd);
		if (r < 0) {
			crypt_free(cd);
			return DEVICE_INVALID;
		}
	}

	*r_cd = cd;

	if (r > 0)
		return DEVICE_LUKS2_REENCRYPT;

	return isLUKS2(crypt_get_type(cd)) ? DEVICE_LUKS2 : DEVICE_LUKS1;
}

static bool luks2_reencrypt_eligible(struct crypt_device *cd)
{
	uint32_t flags;
	struct crypt_params_integrity ip = { 0 };

	if (crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &flags))
		return false;

	if (flags & CRYPT_REQUIREMENT_OFFLINE_REENCRYPT) {
		log_err(_("Legacy LUKS2 reencryption is no longer supported."));
		return false;
	}

	if (flags & CRYPT_REQUIREMENT_OPAL) {
		log_err(_("Can not reencrypt LUKS2 device configured to use OPAL."));
		return false;
	}

	/* raw integrity info is available since 2.0 */
	if (crypt_get_integrity_info(cd, &ip) || ip.tag_size) {
		log_err(_("Reencryption of device with integrity profile is not supported."));
		return false;
	}

	/* Check that cipher is in compatible format */
	if (!crypt_get_cipher(cd)) {
		log_err(_("No known cipher specification pattern detected in LUKS2 header."));
		return false;
	}

	return true;
}

static enum device_status_info check_luks_device(const char *device)
{
	enum device_status_info dev_st;
	struct crypt_device *cd = NULL;

	dev_st = load_luks(&cd, NULL, device);
	crypt_free(cd);

	return dev_st;
}

static int reencrypt_check_data_sb_block_size(const char *data_device, uint32_t new_sector_size)
{
	int r;
	char sb_name[32];
	unsigned block_size;

	assert(data_device);

	r = tools_superblock_block_size(data_device, sb_name, sizeof(sb_name), &block_size);
	if (r <= 0)
		return r;

	if (new_sector_size > block_size) {
		log_err(_("Requested --sector-size %" PRIu32 " is incompatible with %s superblock\n"
			  "(block size: %" PRIu32 " bytes) detected on device %s."),
			new_sector_size, sb_name, block_size, data_device);
		return -EINVAL;
	}

	return 0;
}

static int reencrypt_check_active_device_sb_block_size(const char *active_device, uint32_t new_sector_size)
{
	int r;
	char dm_device[PATH_MAX];

	r = snprintf(dm_device, sizeof(dm_device), "%s/%s", crypt_get_dir(), active_device);
	if (r < 0 || (size_t)r >= sizeof(dm_device))
		return -EINVAL;

	return reencrypt_check_data_sb_block_size(dm_device, new_sector_size);
}

static int reencrypt_is_header_detached(const char *header_device, const char *data_device)
{
	int r;
	struct stat st;
	struct crypt_device *cd;

	if (!header_device)
		return 0;

	if (header_device && stat(header_device, &st) < 0 && errno == ENOENT)
		return 1;

	if ((r = crypt_init_data_device(&cd, header_device, data_device)))
		return r;

	r = crypt_header_is_detached(cd);
	crypt_free(cd);
	return r;
}

static int encrypt_luks2_init(struct crypt_device **cd, const char *data_device, const char *device_name)
{
	int keyslot, r, fd;
	uuid_t uuid;
	char *tmp, uuid_str[37], header_file[PATH_MAX] = { 0 };
	uint32_t activate_flags = 0;
	const struct crypt_params_luks2 luks2_params = {
		.sector_size = ARG_UINT32(OPT_SECTOR_SIZE_ID) ?: SECTOR_SIZE
	};
	struct crypt_params_reencrypt params = {
		.mode = CRYPT_REENCRYPT_ENCRYPT,
		.direction = data_shift < 0 ? CRYPT_REENCRYPT_BACKWARD : CRYPT_REENCRYPT_FORWARD,
		.resilience = ARG_STR(OPT_RESILIENCE_ID) ?: "checksum",
		.hash = ARG_STR(OPT_RESILIENCE_HASH_ID) ?: "sha256",
		.max_hotzone_size = ARG_UINT64(OPT_HOTZONE_SIZE_ID) / SECTOR_SIZE,
		.device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE,
		.luks2 = &luks2_params,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY
	};
	struct crypt_keyslot_context *kc = NULL;

	_set_reencryption_flags(&params.flags);

	if (!data_shift) {
		r = reencrypt_is_header_detached(ARG_STR(OPT_HEADER_ID), data_device);
		if (r < 0)
			return r;
		if (!r) {
			log_err(_("Encryption without detached header (--header) is not possible without data device size reduction (--reduce-device-size)."));
			return -ENOTSUP;
		}
	}

	/* The --reduce-device-size has to be at least twice the size of first moved segment (LUKS2
	 * data offset) */
	if (!ARG_SET(OPT_HEADER_ID) && ARG_UINT64(OPT_OFFSET_ID) &&
	    data_shift && (ARG_UINT64(OPT_OFFSET_ID) > (uint64_t)(imaxabs(data_shift) / (2 * SECTOR_SIZE)))) {
		log_err(_("Requested data offset must be less than or equal to half of --reduce-device-size parameter."));
		return -EINVAL;
	}

	/* It's useless to do data device reduction and than use smaller value */
	if (!ARG_SET(OPT_HEADER_ID) && ARG_UINT64(OPT_OFFSET_ID) &&
	    data_shift && (ARG_UINT64(OPT_OFFSET_ID) < (uint64_t)(imaxabs(data_shift) / (2 * SECTOR_SIZE)))) {
		data_shift = -(ARG_UINT64(OPT_OFFSET_ID) * 2 * SECTOR_SIZE);
		if (data_shift >= 0)
			return -EINVAL;
		log_std(_("Adjusting --reduce-device-size value to twice the --offset %" PRIu64 " (sectors).\n"), ARG_UINT64(OPT_OFFSET_ID) * 2);
	}

	if (ARG_SET(OPT_UUID_ID) && uuid_parse(ARG_STR(OPT_UUID_ID), uuid) == -1) {
		log_err(_("Wrong LUKS UUID format provided."));
		return -EINVAL;
	}

	if (ARG_SET(OPT_SECTOR_SIZE_ID)) {
		r = reencrypt_check_data_sb_block_size(data_device, ARG_UINT32(OPT_SECTOR_SIZE_ID));
		if (r < 0)
			return r;
	}

	if (!ARG_SET(OPT_UUID_ID)) {
		uuid_generate(uuid);
		uuid_unparse(uuid, uuid_str);
		if (!(tmp = strdup(uuid_str)))
			return -ENOMEM;
		ARG_SET_STR(OPT_UUID_ID, tmp);
	}

	if (!ARG_SET(OPT_HEADER_ID)) {
		r = snprintf(header_file, sizeof(header_file), "LUKS2-temp-%s.new", ARG_STR(OPT_UUID_ID));
		if (r < 0 || (size_t)r >= sizeof(header_file))
			return -EINVAL;

		fd = open(header_file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
		if (fd == -1) {
			if (errno == EEXIST)
				log_err(_("Temporary header file %s already exists. Aborting."), header_file);
			else
				log_err(_("Cannot create temporary header file %s."), header_file);
			return -EINVAL;
		}

		r = posix_fallocate(fd, 0, 4096);
		close(fd);
		if (r) {
			log_err(_("Cannot create temporary header file %s."), header_file);
			r = -EINVAL;
			goto out;
		}

		if (!(tmp = strdup(header_file))) {
			r = -ENOMEM;
			goto out;
		}
		ARG_SET_STR(OPT_HEADER_ID, tmp);

		/*
		 * FIXME: just override offset here, but we should support both.
		 * offset and implicit offset via data shift (lvprepend?)
		 */
		if (!ARG_UINT64(OPT_OFFSET_ID))
			ARG_SET_UINT64(OPT_OFFSET_ID, imaxabs(data_shift) / (2 * SECTOR_SIZE));
		data_shift >>= 1;
		params.flags |= CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT;
	} else if (data_shift < 0) {
		if (!ARG_SET(OPT_LUKS2_METADATA_SIZE_ID))
			ARG_SET_UINT64(OPT_LUKS2_METADATA_SIZE_ID, 0x4000); /* missing default here */
		if (!ARG_SET(OPT_LUKS2_KEYSLOTS_SIZE_ID))
			ARG_SET_UINT64(OPT_LUKS2_KEYSLOTS_SIZE_ID, -data_shift - 2 * ARG_UINT64(OPT_LUKS2_METADATA_SIZE_ID));
		if (2 * ARG_UINT64(OPT_LUKS2_METADATA_SIZE_ID) + ARG_UINT64(OPT_LUKS2_KEYSLOTS_SIZE_ID) > (uint64_t)-data_shift) {
			log_err(_("LUKS2 metadata size is larger than data shift value."));
			return -EINVAL;
		}
	}

	r = luksFormat(cd, &kc);
	if (r < 0)
		goto out;

	if (!luks2_reencrypt_eligible(*cd)) {
		r = -EINVAL;
		goto out;
	}

	if (data_shift) {
		params.data_shift = imaxabs(data_shift) / SECTOR_SIZE,
		params.resilience = "datashift";
	}
	keyslot = !ARG_SET(OPT_KEY_SLOT_ID) ? 0 : ARG_INT32(OPT_KEY_SLOT_ID);
	r = crypt_reencrypt_init_by_keyslot_context(*cd, NULL, NULL, kc,
						    CRYPT_ANY_SLOT, keyslot,
						    crypt_get_cipher(*cd),
						    crypt_get_cipher_mode(*cd),
						    &params);
	if (r < 0) {
		crypt_keyslot_destroy(*cd, keyslot);
		goto out;
	}

	/* Restore temporary header in head of data device */
	if (*header_file) {
		crypt_free(*cd);
		*cd = NULL;

		r = crypt_init(cd, data_device);
		if (!r)
			r = crypt_header_restore(*cd, CRYPT_LUKS2, header_file);

		if (r) {
			log_err(_("Failed to place new header at head of device %s."), data_device);
			goto out;
		}
	}

	/* activate device */
	if (device_name) {
		set_activation_flags(&activate_flags);
		r = crypt_activate_by_keyslot_context(*cd, device_name,
						      ARG_INT32(OPT_KEY_SLOT_ID), kc,
						      CRYPT_ANY_SLOT, NULL,
						      activate_flags);
		if (r >= 0)
			log_std(_("%s/%s is now active and ready for online encryption.\n"), crypt_get_dir(), device_name);
	}

	if (r < 0)
		goto out;

	/* just load reencryption context to continue reencryption */
	if (!ARG_SET(OPT_INIT_ONLY_ID)) {
		params.flags &= ~CRYPT_REENCRYPT_INITIALIZE_ONLY;
		r = crypt_reencrypt_init_by_keyslot_context(*cd, device_name, NULL, kc,
							    CRYPT_ANY_SLOT, keyslot,
							    NULL, NULL, &params);
	}
out:
	crypt_keyslot_context_free(kc);
	if (*header_file)
		unlink(header_file);
	return r;
}

static enum device_status_info load_luks2_by_name(struct crypt_device **r_cd, const char *active_name, const char *header_device)
{
	int r;
	struct crypt_device *cd;
	struct stat st;

	assert(r_cd);
	assert(active_name);

	if (header_device && stat(header_device, &st) < 0 && errno == ENOENT)
		return DEVICE_NOT_LUKS;

	r = crypt_init_by_name_and_header(&cd, active_name, header_device);
	if (r)
		return DEVICE_INVALID;

	if (!isLUKS2(crypt_get_type(cd))) {
		log_err(_("Active device %s is not LUKS2."), active_name);
		crypt_free(cd);
		return DEVICE_INVALID;
	}

	r = luks2_reencrypt_in_progress(cd);
	if (r < 0) {
		crypt_free(cd);
		return DEVICE_INVALID;
	}

	*r_cd = cd;

	return !r ? DEVICE_LUKS2 : DEVICE_LUKS2_REENCRYPT;
}

static int reencrypt_restore_header(struct crypt_device **cd,
	const char *data_device, const char *header)
{
	int r;

	assert(cd);
	assert(data_device);
	assert(header);

	crypt_free(*cd);
	*cd = NULL;

	log_verbose(_("Restoring original LUKS2 header."));

	r = crypt_init(cd, data_device);
	if (r < 0)
		return r;

	r = crypt_header_restore(*cd, CRYPT_LUKS2, header);
	if (r < 0)
		log_err(_("Original LUKS2 header restore failed."));

	return r;
}

static int decrypt_luks2_datashift_init(struct crypt_device **cd,
	const char *expheader)
{
	int fd, r;
	struct stat hdr_st;
	char *msg, *data_device, *active_name = NULL;
	bool remove_header = false;
	struct crypt_params_reencrypt params = {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "datashift-checksum",
		.hash = ARG_STR(OPT_RESILIENCE_HASH_ID) ?: "sha256",
		.device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE,
		.max_hotzone_size = ARG_UINT64(OPT_HOTZONE_SIZE_ID) / SECTOR_SIZE,
		.flags = CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT
	};
	struct crypt_keyslot_context *kc = NULL;

	assert(expheader);
	assert(cd && *cd);

	params.data_shift = crypt_get_data_offset(*cd);

	if (!(data_device = strdup(crypt_get_device_name(*cd))))
		return -ENOMEM;

	if (!ARG_SET(OPT_BATCH_MODE_ID)) {
		r = asprintf(&msg, _("Header file %s does not exist. Do you want to initialize LUKS2 "
				     "decryption of device %s and export LUKS2 header to file %s?"),
			     expheader, data_device, expheader);
		if (r < 0) {
			r = -ENOMEM;
			goto out;
		}
		r = yesDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
		free(msg);
		if (r < 0)
			goto out;
	}

	if ((r = decrypt_verify_and_set_params(&params)))
		goto out;

	r = reencrypt_hint_force_offline_reencrypt(data_device);
	if (r < 0)
		goto out;

	r = reencrypt_single_key_unlock(*cd, &params, &kc);
	if (r < 0)
		goto out;

	r = crypt_header_backup(*cd, CRYPT_LUKS2, expheader);
	if (r < 0)
		goto out;

	remove_header = true;

	fd = open(expheader, O_RDONLY);
	if (fd < 0)
		goto out;

	if (fstat(fd, &hdr_st)) {
		close(fd);
		r = -EINVAL;
		goto out;
	}

	r = fchmod(fd, hdr_st.st_mode  | S_IRUSR | S_IWUSR);
	close(fd);
	if (r) {
		log_err(_("Failed to add read/write permissions to exported header file."));
		r = -EINVAL;
		goto out;
	}

	crypt_free(*cd);
	*cd = NULL;

	/* reload with exported header */
	if (ARG_SET(OPT_ACTIVE_NAME_ID)) {
		if (load_luks2_by_name(cd, ARG_STR(OPT_ACTIVE_NAME_ID), expheader) != DEVICE_LUKS2) {
			r = -EINVAL;
			goto out;
		}
	} else {
		if ((r = crypt_init_data_device(cd, expheader, data_device)))
			goto out;
		if ((r = crypt_load(*cd, CRYPT_LUKS2, NULL)))
			goto out;
	}

	_set_reencryption_flags(&params.flags);

	if (!ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID))
		r = reencrypt_get_active_name(*cd, data_device, &active_name);

	if (r < 0)
		goto out;

	r = tools_wipe_all_signatures(data_device, active_name == NULL, true);
	if (r < 0) {
		/* if header restore fails keep original header backup */
		if (reencrypt_restore_header(cd, data_device, expheader) < 0)
			remove_header = false;
		goto out;
	}

	remove_header = false;

	r = crypt_reencrypt_init_by_keyslot_context(*cd, active_name, kc, NULL,
						    ARG_INT32(OPT_KEY_SLOT_ID),
						    CRYPT_ANY_SLOT, NULL, NULL, &params);

	if (r < 0 && crypt_reencrypt_status(*cd, NULL) == CRYPT_REENCRYPT_NONE) {
		/* if restore is successful we can remove header backup */
		if (!reencrypt_restore_header(cd, data_device, expheader))
			remove_header = true;
	}
out:
	free(active_name);
	free(data_device);
	crypt_keyslot_context_free(kc);

	if (r < 0 && !remove_header && !stat(expheader, &hdr_st) && S_ISREG(hdr_st.st_mode))
		log_err(_("Reencryption initialization failed. Header backup is available in %s."),
			expheader);
	if (remove_header)
		unlink(expheader);

	return r;
}

static int decrypt_luks2_init(struct crypt_device *cd, const char *data_device)
{
	int r;
	char *active_name = NULL;
	struct crypt_params_reencrypt params = {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = data_shift > 0 ? CRYPT_REENCRYPT_FORWARD : CRYPT_REENCRYPT_BACKWARD,
		.resilience = data_shift ? "datashift" : (ARG_STR(OPT_RESILIENCE_ID) ?: "checksum"),
		.hash = ARG_STR(OPT_RESILIENCE_HASH_ID) ?: "sha256",
		.data_shift = imaxabs(data_shift) / SECTOR_SIZE,
		.device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE,
		.max_hotzone_size = ARG_UINT64(OPT_HOTZONE_SIZE_ID) / SECTOR_SIZE,
	};
	struct crypt_keyslot_context *kc = NULL;

	if (!luks2_reencrypt_eligible(cd))
		return -EINVAL;

	if ((!crypt_get_metadata_device_name(cd) || crypt_header_is_detached(cd) <= 0 ||
	    crypt_get_data_offset(cd) > 0)) {
		log_err(_("LUKS2 decryption is supported with detached header device only (with data offset set to 0)."));
		return -ENOTSUP;
	}

	r = reencrypt_hint_force_offline_reencrypt(data_device);
	if (r < 0)
		return r;

	_set_reencryption_flags(&params.flags);

	r = reencrypt_single_key_unlock(cd, &params, &kc);
	if (r < 0)
		goto out;

	if (!ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID))
		r = reencrypt_get_active_name(cd, data_device, &active_name);
	if (r >= 0)
		r = crypt_reencrypt_init_by_keyslot_context(cd, active_name, kc, NULL,
							    ARG_INT32(OPT_KEY_SLOT_ID),
							    CRYPT_ANY_SLOT, NULL, NULL,
							    &params);

out:
	free(active_name);
	crypt_keyslot_context_free(kc);
	return r;
}

struct unlocked_token {
	/* token keyslot context */
	struct crypt_keyslot_context *p_kc;
	int id;
};

struct unlocked_keyslot {
	/* just pointer */
	struct crypt_keyslot_context *p_kc;
	int id;
	int new_id;
};

struct keyslot_contexts {
	struct unlocked_keyslot ks[16];
	struct unlocked_token tkns[16];

	/* available unlock methods linked in keyslot struct */
	struct crypt_keyslot_context *kc[16];

	/* contains pointer to context unlocking existing volume key */
	struct crypt_keyslot_context *p_old_kc;
	struct crypt_keyslot_context *p_new_kc;

	/* contains new generated volume key in CRYPT_KC_TYPE_KEY context type */
	struct crypt_keyslot_context *new_kc;

	bool vk_generated;

	/* contains new keyslot id for reencryption initialization */
	int new_key_id;
	int old_key_id;

	unsigned last_ks;
	unsigned last_kc;
	unsigned last_tkn;
};

static struct crypt_keyslot_context *try_token(struct crypt_device *cd,
					       struct keyslot_contexts *kcs,
					       int keyslot)
{
	unsigned i;
	struct crypt_keyslot_context *pkc;

	assert(cd);
	assert(kcs);
	assert(kcs->last_tkn < ARRAY_SIZE(kcs->tkns));
	assert(keyslot >= 0);

	for (i = 0; i < kcs->last_tkn; i++) {
		pkc = kcs->tkns[i].p_kc;

		if (crypt_token_is_assigned(cd, kcs->tkns[i].id, keyslot) == 0 &&
		    crypt_activate_by_keyslot_context(cd, NULL, keyslot, pkc, CRYPT_ANY_SLOT, NULL, 0) == keyslot) {
				tools_keyslot_msg(keyslot, UNLOCKED);
				return pkc;
		}
	}

	return NULL;
}

static bool reencrypt_keyslot_for_unlock(struct keyslot_contexts *kcs, int keyslot)
{
	unsigned i;

	for (i = 0; i < kcs->last_ks; i++) {
		if (kcs->ks[i].id == keyslot)
			return true;
	}

	return false;
}

static bool reencrypt_keyslot_is_unlocked(struct keyslot_contexts *kcs, int keyslot)
{
	unsigned i;

	for (i = 0; i < kcs->last_ks; i++) {
		if (kcs->ks[i].id == keyslot)
			return (kcs->ks[i].p_kc != NULL);
	}

	return false;
}

static bool reencrypt_token_for_unlock(struct keyslot_contexts *kcs, int token)
{
	unsigned i;

	for (i = 0; i < kcs->last_tkn; i++) {
		if (kcs->tkns[i].id == token)
			return true;
	}

	return false;
}

static struct crypt_keyslot_context *reencrypt_get_token_context(struct keyslot_contexts *kcs,
								 int token)
{
	unsigned i;

	for (i = 0; i < kcs->last_tkn; i++) {
		if (kcs->tkns[i].id == token)
			return kcs->tkns[i].p_kc;
	}

	return NULL;
}

static void reencrypt_token_add_for_unlock(struct keyslot_contexts *kcs, int token)
{
	assert(kcs);
	assert(token >= 0);

	if (reencrypt_token_for_unlock(kcs, token))
		return;

	kcs->tkns[kcs->last_tkn++].id = token;

	log_dbg("Token %d candidate for keyslot unlock.", token);
}

static void reencrypt_token_add(struct keyslot_contexts *kcs,
				int token,
				struct crypt_keyslot_context *token_kc)
{
	unsigned i;

	assert(kcs);
	assert(token >= 0);
	assert(token_kc);

	for (i = 0; i < kcs->last_tkn; i++) {
		if (kcs->tkns[i].id == token) {
			kcs->kc[kcs->last_kc++] = kcs->tkns[i].p_kc = token_kc;
			return;
		}
	}

	abort();
}

static void reencrypt_keyslot_unlocked_by_context(struct keyslot_contexts *kcs,
						  int keyslot,
						  struct crypt_keyslot_context *kc)
{
	unsigned i;

	assert(kcs);
	assert(kc);
	assert(keyslot >= 0);

	for (i = 0; i < kcs->last_ks; i++) {
		if (kcs->ks[i].id == keyslot) {
			kcs->ks[i].p_kc = kc;
			kcs->ks[i].new_id = -1;
			return;
		}
	}

	abort();
}

/* Add keyslot in unlock candidates */
static void reencrypt_keyslot_add_for_unlock(struct keyslot_contexts *kcs, int keyslot)
{
	assert(kcs);
	assert(keyslot >= 0);

	kcs->ks[kcs->last_ks].id = keyslot;
	kcs->ks[kcs->last_ks++].new_id = -1;
}

static void reencrypt_token_unlocks_keyslot(struct keyslot_contexts *kcs,
					    int token,
					    int keyslot,
					    struct crypt_keyslot_context *token_kc)
{
	assert(kcs);
	assert(token_kc);

	reencrypt_token_add(kcs, token, token_kc);
	reencrypt_keyslot_unlocked_by_context(kcs, keyslot, token_kc);
}

static void reencrypt_keyslot_unlocked_by_context_new(struct keyslot_contexts *kcs,
						      int keyslot,
						      struct crypt_keyslot_context *kc)
{
	assert(kcs);
	assert(kc);
	assert(keyslot >= 0);

	kcs->kc[kcs->last_kc++] = kc;
	reencrypt_keyslot_unlocked_by_context(kcs, keyslot, kc);
}

/* returns unlocked keyslot id or negative errno */
static int single_token(struct crypt_device *cd,
			int token,
			int slot_to_check,
			struct keyslot_contexts *kcs)
{
	int r;
	struct crypt_keyslot_context *kc;

	r = crypt_token_is_assigned(cd, token, slot_to_check);
	if (r != 0)
		return r;

	if (reencrypt_keyslot_is_unlocked(kcs, slot_to_check)) {
		log_dbg("Keyslot %d already unlocked.", slot_to_check);
		return slot_to_check;
	}

	kc = reencrypt_get_token_context(kcs, token);
	if (kc) {
		r = crypt_activate_by_keyslot_context(cd, NULL, slot_to_check, kc,
						      CRYPT_ANY_SLOT, NULL, 0);
		if (r == slot_to_check) {
			log_dbg("Token %d unlocks keyslot %d", token, slot_to_check);
			reencrypt_keyslot_unlocked_by_context(kcs, slot_to_check, kc);
		}

		return r;
	}

	r = luks_try_token_unlock(cd, slot_to_check, token, NULL,
				  ARG_STR(OPT_TOKEN_TYPE_ID), 0, /* FIXME: do we need any? */
				  set_tries_tty(false), true, true, &kc);
	if (r == slot_to_check) {
		log_dbg("Token %d unlocks keyslot %d", token, slot_to_check);
		reencrypt_token_unlocks_keyslot(kcs, token, slot_to_check, kc);
	}

	return r;
}

static int reencrypt_unlock_keyslot(struct keyslot_contexts *kcs,
			   struct crypt_device *cd,
			   const char *msg,
			   int slot_to_check)
{
	struct crypt_keyslot_context *kc;
	int retry_count, r = -EINVAL;

	assert(cd);
	assert(kcs);
	assert(slot_to_check >= 0);

	if (reencrypt_keyslot_is_unlocked(kcs, slot_to_check))
		return slot_to_check;

	/* try already initialized token kc */
	kc = try_token(cd, kcs, slot_to_check);
	if (kc) {
		reencrypt_keyslot_unlocked_by_context(kcs, slot_to_check, kc);

		return slot_to_check;
	}

	retry_count = set_tries_tty(false);
	do {
		r = luks_init_keyslot_context(cd, msg, verify_passphrase(0), false, &kc);
		if (r < 0)
			return r;

		r = crypt_activate_by_keyslot_context(cd, NULL, slot_to_check,
						      kc, CRYPT_ANY_SLOT, NULL, 0);
		tools_keyslot_msg(r, UNLOCKED);
		if (r == slot_to_check) {
			reencrypt_keyslot_unlocked_by_context_new(kcs, slot_to_check, kc);

			return slot_to_check;
		}
		crypt_keyslot_context_free(kc);
		tools_passphrase_msg(r);
		check_signal(&r);
	} while ((r == -EPERM || r == -ERANGE) && (--retry_count > 0));

	return r;
}

/*
 * Returns 1 if keyslot should be unlocked and it
 * was not added in unlock queue yet.
 *
 * Return 0 if keyslot can not be used or
 * already added in unlock queue.
 *
 * Negative errno on error.
 */
static int reencrypt_add_token_keyslot(struct crypt_device *cd,
		struct keyslot_contexts *kcs,
		int token,
		int keyslot)
{
	assert(kcs);
	assert(token >= 0);
	assert(keyslot >= 0);

	switch (crypt_keyslot_status(cd, keyslot)) {
	case CRYPT_SLOT_INVALID:
		return -EINVAL;
	case CRYPT_SLOT_ACTIVE:
	case CRYPT_SLOT_ACTIVE_LAST:
		break;
	default:
		return 0;
	}

	if (crypt_token_is_assigned(cd, token, keyslot))
		return 0;

	reencrypt_token_add_for_unlock(kcs, token);

	/* continue if keyslot is already added in unlock queue */
	if (reencrypt_keyslot_for_unlock(kcs, keyslot))
		return 0;

	log_dbg("Keyslot %d candidate for unlock.", keyslot);

	reencrypt_keyslot_add_for_unlock(kcs, keyslot);
	return 1;
}

static int reencrypt_add_single_token_keyslots(struct crypt_device *cd,
		struct keyslot_contexts *kcs,
		int token,
		int keyslot,
		const char *token_type)
{
	int ks, r;
	const char *type;
	unsigned count = 0;

	assert(token >= 0);

	switch (crypt_token_status(cd, token, &type)) {
	case CRYPT_TOKEN_INVALID:
		return -EINVAL;
	case CRYPT_TOKEN_INACTIVE:
		return 0;
	default:
		break;
	}

	if (token_type && strcmp(token_type, type))
		return 0;

	if (keyslot != CRYPT_ANY_SLOT)
		return reencrypt_add_token_keyslot(cd, kcs, token, keyslot);

	for (ks = 0; ks < crypt_keyslot_max(CRYPT_LUKS2); ks++) {
		r = reencrypt_add_token_keyslot(cd, kcs, token, ks);
		if (r < 0)
			return r;

		if (r > 0)
			count++;
	}

	return count;
}

static int reencrypt_add_token_keyslots_for_unlock(struct crypt_device *cd,
						   struct keyslot_contexts *kcs,
						   int token,
						   const char *token_type,
						   int keyslot)
{
	int r;
	unsigned count = 0;

	if (token != CRYPT_ANY_TOKEN)
		return reencrypt_add_single_token_keyslots(cd, kcs, token, keyslot, token_type);

	for (token = 0; token < crypt_token_max(CRYPT_LUKS2); token++) {
		r = reencrypt_add_single_token_keyslots(cd, kcs, token, keyslot, token_type);
		if (r < 0)
			return r;

		if (r > 0)
			count++;
	}

	return count;
}

static int reencrypt_add_keyslots_for_unlock(struct crypt_device *cd,
					   struct keyslot_contexts *kcs,
					   bool vk_change,
					   bool only_token_keyslots)
{
	int i, new_vk_slot = (vk_change ? 1 : 0), max = crypt_keyslot_max(CRYPT_LUKS2),
	    unlocked, active = 0, unbound = 0;

	/*
	 * Returns negative errno on error or count of added candidate keyslots
	 * suitable for device activation using the token based on input
	 * parameters and token<->keyslot assignment.
	 *
	 * Every keyslot is counted at most once.
	 */
	i = reencrypt_add_token_keyslots_for_unlock(cd, kcs, ARG_INT32(OPT_TOKEN_ID_ID),
						    ARG_STR(OPT_TOKEN_TYPE_ID),
						    ARG_INT32(OPT_KEY_SLOT_ID));
	if (i < 0)
		return i;

	/* token based reencryption preferred and no keyslot
	 * could be used for reencryption */
	if (!i && only_token_keyslots) {
		log_err(_("No token could unlock the device."));
		return -ENOENT;
	}

	unlocked = i;

	for (i = 0; i < max; i++) {
		switch (crypt_keyslot_status(cd, i)) {
		case CRYPT_SLOT_INVALID:
			return -EINVAL;
		case CRYPT_SLOT_ACTIVE:
			/* fall-through */
		case CRYPT_SLOT_ACTIVE_LAST:
			/* only count additional keyslots added in the loop */
			active++;
			if (!only_token_keyslots && !reencrypt_keyslot_for_unlock(kcs, i) &&
			    (!ARG_SET(OPT_KEY_SLOT_ID) || ARG_INT32(OPT_KEY_SLOT_ID) == i)) {
				reencrypt_keyslot_add_for_unlock(kcs, i);
				unlocked++;
				log_dbg("Keyslot %d candidate for unlock by passphrase prompt.", i);
			}
			break;
		case CRYPT_SLOT_UNBOUND:
			unbound++;
			/* fall-through */
		default:
			break;
		}
	}

	/* at least one keyslot for reencryption plus new volume key (if needed) */
	if (active + unbound + new_vk_slot + 1 > max) {
		log_err(_("Not enough free keyslots for reencryption."));
		return -EINVAL;
	}

	if (!vk_change)
		return 0;

	if ((ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT) &&
            (2 * unlocked + unbound + 1 > max)) {
		log_err(_("Not enough free keyslots for reencryption."));
		return -EINVAL;
	}

	return 0;
}

static int reencrypt_unlock_keyslots(struct crypt_device *cd,
				     struct keyslot_contexts *kcs,
				     bool vk_change)
{
	bool only_single_keyslot;
	char msg[128];
	crypt_keyslot_info ki;
	int i, r = 0;

	assert(cd);
	assert(kcs);

	only_single_keyslot = (vk_change && ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT &&
			       (ARG_SET(OPT_KEY_FILE_ID) || ARG_SET(OPT_KEY_DESCRIPTION_ID)));

	if (ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT) {
		for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS2); i++) {
			ki = crypt_keyslot_status(cd, i);
			switch (ki) {
			case CRYPT_SLOT_INVALID:
				r = -EINVAL;
				goto out;
			case CRYPT_SLOT_ACTIVE:
				if (only_single_keyslot) {
					log_err(_("Key file or keyring key description can be used only with "
						  "--key-slot or with exactly one key slot active."));
					r = -EINVAL;
					goto out;
				}
				/* fall-through */
			case CRYPT_SLOT_ACTIVE_LAST:
				if (snprintf(msg, sizeof(msg), _("Enter passphrase for key slot %d: "), i) < 0)
					return -EINVAL;
				r = reencrypt_unlock_keyslot(kcs, cd, msg, i);
				if (r < 0 || !vk_change)
					goto out;
				break;
			case CRYPT_SLOT_INACTIVE:
			case CRYPT_SLOT_UNBOUND:
				r = 0;
				break;
			}
		}
	} else {
		if (snprintf(msg, sizeof(msg), _("Enter passphrase for key slot %d: "),
			     ARG_INT32(OPT_KEY_SLOT_ID)) < 0)
			return -EINVAL;
		r = reencrypt_unlock_keyslot(kcs, cd, msg, ARG_INT32(OPT_KEY_SLOT_ID));
	}
out:
	return r < 0 ? r : 0;
}

static int assign_tokens(struct crypt_device *cd, int keyslot_old, int keyslot_new)
{
	int token = 0, r = crypt_token_is_assigned(cd, token, keyslot_old);

	while (r != -EINVAL) {
		if (!r && (token != crypt_token_assign_keyslot(cd, token, keyslot_new)))
			return -EINVAL;
		token++;
		r = crypt_token_is_assigned(cd, token, keyslot_old);
	}

	/* we reached max token number, exit */
	return 0;
}

static void reencrypt_keyslot_contexts_destroy(struct keyslot_contexts *kcs)
{
	unsigned i;

	if (!kcs)
		return;

	crypt_keyslot_context_free(kcs->new_kc);

	for (i = 0; i < kcs->last_kc; i++)
		crypt_keyslot_context_free(kcs->kc[i]);
}

static bool token_error_unavailable(int r)
{
	return (r == -ENOENT || r == -EPERM || r == -ENOANO || r == -EAGAIN);
}

/* returns count of unlocked keyslots or negative errno */
static int init_token_keyslot_context(struct crypt_device *cd,
				      int token,
				      struct keyslot_contexts *kcs)
{
	int r;
	unsigned i, count = 0;

	assert(kcs);

	for (i = 0; i < kcs->last_ks; i++) {
		r = single_token(cd, token, kcs->ks[i].id, kcs);
		if (r < 0 && !token_error_unavailable(r))
			return r;
		if (r >= 0)
			count++;
	}

	return count ? 0 : -ENOENT;
}

static int reencrypt_unlock_keyslots_by_tokens(struct crypt_device *cd,
					  struct keyslot_contexts *kcs)
{
	int r;
	unsigned i, count = 0;

	assert(kcs);

	for (i = 0; i < kcs->last_tkn; i++) {
		r = init_token_keyslot_context(cd, kcs->tkns[i].id, kcs);
		if (r < 0 && !token_error_unavailable(r))
			return r;
		if (r >= 0)
			count++;
	}

	return count;
}

static int reencrypt_initialize_keyslot_contexts(struct crypt_device *cd,
		bool vk_generated,
		bool prefer_token,
		struct crypt_keyslot_context *old_kc,
		struct crypt_keyslot_context *new_kc,
		struct keyslot_contexts *kcs)
{
	int r;

	assert(cd);
	assert(kcs);

	if (new_kc) {
		kcs->vk_generated = vk_generated;
		kcs->new_key_id = CRYPT_ANY_SLOT;
		kcs->p_new_kc = new_kc;
	}

	if (old_kc) {
		kcs->p_old_kc = old_kc;
		if (!new_kc)
			kcs->p_new_kc = old_kc;

		kcs->old_key_id = CRYPT_ANY_SLOT;
		return 0;
	}

	/* Based on input parameters (--token-id, --token-type, --keyslot, ...)
	 * it will create a list of keyslots and tokens suitable for reencryption.
	 * No keyslot or token is unlocked yet. First we need to establish if there
	 * are enough free keyslots to proceed with the reencryption */
	r = reencrypt_add_keyslots_for_unlock(cd, kcs, new_kc != NULL, prefer_token);
	if (r)
		return r;

	/*  First unlock keyslots by tokens */
	r = reencrypt_unlock_keyslots_by_tokens(cd, kcs);
	if (r < 0)
		return r;

	/* if tokens were preferred and no keyslot
	 * could be unlocked, abort */
	if (!r && prefer_token)
		return -ENOENT;

	/* unlock remaining keyslots only if token
	 * based reencryption was not requested */
	if (!prefer_token) {
		r = reencrypt_unlock_keyslots(cd, kcs, new_kc != NULL);
		if (r < 0)
			return r;
	}

	if (!kcs->p_old_kc) {
		assert(kcs->ks[0].p_kc);
		assert(kcs->ks[0].id >= 0);
		kcs->p_old_kc = kcs->ks[0].p_kc;
		kcs->old_key_id = kcs->ks[0].id;
	}

	return 0;
}

static int reencrypt_active_keyslots_count(struct crypt_device *cd)
{
	int i;
	unsigned count = 0;

	assert(cd);
	assert(isLUKS2(crypt_get_type(cd)));

	for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS2); i++) {
		switch (crypt_keyslot_status(cd, i)) {
		case CRYPT_SLOT_INVALID:
			return -EINVAL;
		case CRYPT_SLOT_ACTIVE: /* fall-through */
		case CRYPT_SLOT_ACTIVE_LAST:
			count++;
			break;
		case CRYPT_SLOT_INACTIVE: /* fall-through */
		case CRYPT_SLOT_UNBOUND:
			break;
		}
	}

	return count;
}

static int reencrypt_add_new_keyslots(struct crypt_device *cd,
				      bool prefer_token,
				      struct keyslot_contexts *kcs)
{
	char *vk_new;
	int r, new_key_size;
	unsigned i;
	uint32_t new_key_flags = CRYPT_VOLUME_KEY_NO_SEGMENT;

	assert(cd);
	assert(kcs);

	if (!kcs->last_ks)
		return -ENOENT;

	for (i = 0; i < kcs->last_ks; i++) {
		if (!kcs->ks[i].p_kc) {
			/*
			 * A token may be assigned to multiple
			 * keyslots and not be able to open all
			 */
			if (!prefer_token)
				return -EINVAL;
			continue;
		}

		r = set_keyslot_params(cd, kcs->ks[i].id);
		if (r < 0)
			return r;

		/* new volume key has no digest yet */
		if (!(new_key_flags & CRYPT_VOLUME_KEY_DIGEST_REUSE)) {
			r = crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, kcs->p_new_kc,
								 CRYPT_ANY_SLOT, kcs->ks[i].p_kc,
								 new_key_flags);
			tools_keyslot_msg(r, CREATED);
			if (r < 0)
				return r;

			kcs->ks[i].new_id = r;

			/* key was generated in crypt_keyslot_add_by_keyslot_context() above.
			 * I need to extract actual new key for additional keyslots and reencrypt
			 * init call later */
			if (kcs->vk_generated) {
				new_key_size = crypt_keyslot_get_key_size(cd, kcs->ks[i].new_id);
				if (new_key_size <= 0)
					return r;

				vk_new = crypt_safe_alloc((size_t)new_key_size);
				if (!vk_new)
					return -ENOMEM;

				r = crypt_volume_key_get_by_keyslot_context(cd, kcs->ks[i].new_id,
									    vk_new,
									    &(size_t){new_key_size},
									    kcs->ks[i].p_kc);
				if (r < 0) {
					crypt_safe_free(vk_new);
					return r;
				}

				r = crypt_keyslot_context_init_by_volume_key(cd, vk_new,
									     (size_t)new_key_size,
									     &kcs->new_kc);
				crypt_safe_free(vk_new);
				if (r < 0)
					return r;
				kcs->p_new_kc = kcs->new_kc;
			}
			r = assign_tokens(cd, kcs->ks[i].id, kcs->ks[i].new_id);
			if (r < 0)
				return r;

			kcs->new_key_id = kcs->ks[i].new_id;
			new_key_flags |= CRYPT_VOLUME_KEY_DIGEST_REUSE;
		} else {
			r = crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, kcs->new_kc,
					CRYPT_ANY_SLOT, kcs->ks[i].p_kc, new_key_flags);

			tools_keyslot_msg(r, CREATED);
			if (r < 0)
				return r;

			kcs->ks[i].new_id = r;
			r = assign_tokens(cd, kcs->ks[i].id, kcs->ks[i].new_id);
			if (r < 0)
				return r;
		}
	}

	return 0;
}

static int reencrypt_luks2_init(struct crypt_device *cd, const char *data_device)
{
	bool sector_size_change, sector_size_increase, vk_change, vk_generated = false,
	     prefer_token = (ARG_SET(OPT_TOKEN_ONLY_ID) || ARG_SET(OPT_TOKEN_ID_ID) || ARG_SET(OPT_TOKEN_TYPE_ID));
	size_t i;
	int r, new_key_size = 0, key_size = 0;
	char cipher[MAX_CIPHER_LEN], mode[MAX_CIPHER_LEN], *vk, *vk_new, *vk_description,
	     *active_name = NULL;
	uint32_t active_slots;
	const char *new_cipher = NULL;
	struct crypt_keyslot_context *old_key_kc = NULL, *new_key_kc = NULL;
	struct keyslot_contexts kcs = {};
	struct crypt_params_luks2 luks2_params = {};
	struct crypt_params_reencrypt params = {
		.mode = CRYPT_REENCRYPT_REENCRYPT,
		.direction = data_shift < 0 ? CRYPT_REENCRYPT_BACKWARD : CRYPT_REENCRYPT_FORWARD,
		.resilience = data_shift ? "datashift" : (ARG_STR(OPT_RESILIENCE_ID) ?: "checksum"),
		.hash = ARG_STR(OPT_RESILIENCE_HASH_ID) ?: "sha256",
		.data_shift = imaxabs(data_shift) / SECTOR_SIZE,
		.max_hotzone_size = ARG_UINT64(OPT_HOTZONE_SIZE_ID) / SECTOR_SIZE,
		.device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE,
		.luks2 = &luks2_params,
	};

	if (!luks2_reencrypt_eligible(cd))
		return -EINVAL;

	_set_reencryption_flags(&params.flags);

	/* cipher */
	if (ARG_SET(OPT_CIPHER_ID))
		new_cipher = ARG_STR(OPT_CIPHER_ID);
	else if (!ARG_SET(OPT_CIPHER_ID) && crypt_is_cipher_null(crypt_get_cipher(cd))) {
		log_std(_("Switching data encryption cipher to %s.\n"), DEFAULT_CIPHER(LUKS1));
		new_cipher = DEFAULT_CIPHER(LUKS1);
	}

	if (!new_cipher) {
		strncpy(cipher, crypt_get_cipher(cd), MAX_CIPHER_LEN - 1);
		strncpy(mode, crypt_get_cipher_mode(cd), MAX_CIPHER_LEN - 1);
		cipher[MAX_CIPHER_LEN-1] = '\0';
		mode[MAX_CIPHER_LEN-1] = '\0';
	} else {
		if ((r = crypt_parse_name_and_mode(new_cipher, cipher, NULL, mode))) {
			log_err(_("No known cipher specification pattern detected."));
			return r;
		}

		/* the segment cipher is identical with existing one */
		if (!strcmp(cipher, crypt_get_cipher(cd)) && !strcmp(mode, crypt_get_cipher_mode(cd)))
			new_cipher = NULL;
	}

	/* sector size */
	luks2_params.sector_size = ARG_UINT32(OPT_SECTOR_SIZE_ID) ?: (uint32_t)crypt_get_sector_size(cd);
	sector_size_change = luks2_params.sector_size != (uint32_t)crypt_get_sector_size(cd);
	sector_size_increase = luks2_params.sector_size > (uint32_t)crypt_get_sector_size(cd);

	/* key size */
	key_size = crypt_get_volume_key_size(cd);
	if (!key_size && ARG_SET(OPT_KEY_SIZE_ID))
		key_size = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;
	if (!key_size && !ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
		/* No keyslot assigned to default segment */
		log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --key-size option."));
		return -EINVAL;
	}

	/* new key size */
	if (!ARG_SET(OPT_NEW_VOLUME_KEY_KEYRING_ID)) {
		if (ARG_SET(OPT_NEW_KEY_SIZE_ID))
			new_key_size = ARG_UINT32(OPT_NEW_KEY_SIZE_ID);

		if (new_key_size || new_cipher)
			new_key_size = get_adjusted_key_size(cipher, mode, new_key_size,
							 DEFAULT_LUKS1_KEYBITS, 0);
		else
			new_key_size = key_size;

		if (new_key_size <= 0) {
			log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --new-key-size option."));
			return -EINVAL;
		}
	}

	/* get active slots count */
	r = reencrypt_active_keyslots_count(cd);
	if (r < 0)
		return r;
	active_slots = r;

	/* volume key */
	vk_change = !ARG_SET(OPT_KEEP_KEY_ID);

	/*
	 * --volume-key-keyring must take precedence over --volume-key-file due
	 * to possibly unset key_size
	 */
	if (ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
		r = tools_parse_vk_description(ARG_STR(OPT_VOLUME_KEY_KEYRING_ID), &vk_description);
		if (r < 0)
			goto out;
		r = crypt_keyslot_context_init_by_vk_in_keyring(cd, vk_description, &old_key_kc);
		free(vk_description);
		if (r < 0)
			goto out;
	}

	if (!old_key_kc && ARG_SET(OPT_VOLUME_KEY_FILE_ID) && key_size > 0) {
		r = tools_read_vk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), &vk, key_size);
		if (r < 0)
			goto out;
		r = crypt_keyslot_context_init_by_volume_key(cd, vk, (size_t)key_size, &old_key_kc);
		crypt_safe_free(vk);
		if (r < 0)
			goto out;
	}

	if (old_key_kc) {
		r = crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, old_key_kc,
						      CRYPT_ANY_SLOT, NULL, 0);
		if (r == -EPERM)
			log_err(_("Volume key does not match the volume."));
		if (r < 0)
			goto out;
	}

	/*
	 * --new-volume-key-keyring must take precedence over --new-volume-key-file due
	 * to possibly unset new_key_size
	 */
	if (vk_change && ARG_SET(OPT_NEW_VOLUME_KEY_KEYRING_ID)) {
		if (active_slots && old_key_kc && !ARG_SET(OPT_FORCE_NO_KEYSLOTS_ID)) {
			log_err(_("Use --force-no-keyslots to reencrypt device with active keyslots by passing volume keys directly."));
			return -EINVAL;
		}

		r = tools_parse_vk_description(ARG_STR(OPT_NEW_VOLUME_KEY_KEYRING_ID), &vk_description);
		if (r < 0)
			goto out;

		r = crypt_keyslot_context_init_by_vk_in_keyring(cd, vk_description, &new_key_kc);
		free(vk_description);
		if (r < 0)
			goto out;
	}

	if (vk_change && !new_key_kc && ARG_SET(OPT_NEW_VOLUME_KEY_FILE_ID)) {
		if (!ARG_SET(OPT_NEW_KEY_SIZE_ID)) {
			log_err(_("Option --new-volume-key-file must be paired with --new-key-size"));
			r = -EINVAL;
			goto out;
		}
		if (active_slots && old_key_kc && !ARG_SET(OPT_FORCE_NO_KEYSLOTS_ID)) {
			log_err(_("Use --force-no-keyslots to reencrypt device with active keyslots by passing volume keys directly."));
			return -EINVAL;
		}

		r = tools_read_vk(ARG_STR(OPT_NEW_VOLUME_KEY_FILE_ID), &vk_new, new_key_size);
		if (r < 0)
			goto out;

		r = crypt_keyslot_context_init_by_volume_key(cd, vk_new, (size_t)new_key_size,
							     &new_key_kc);
		crypt_safe_free(vk_new);
		if (r < 0)
			goto out;
	}

	/* verify if passed new volume key does not match already existing volume key */
	if (new_key_kc) {
		r = crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, new_key_kc,
						      CRYPT_ANY_SLOT, NULL, 0);
		if (r >= 0) {
			/* passed key was valid volume key */
			crypt_keyslot_context_free(new_key_kc);
			new_key_kc = NULL;
			vk_change = false;
		}
	}

	/* initialize 'empty' new keyslot context to get new volume key generated later */
	if (vk_change && !new_key_kc) {
		r = crypt_keyslot_context_init_by_volume_key(cd, NULL, (size_t)new_key_size,
							     &new_key_kc);
		if (r < 0)
			goto out;
		vk_generated = true;
	}

	if (!vk_change && !new_cipher && !sector_size_change) {
		log_err(_("No data segment parameters changed. Reencryption aborted."));
		r = -EINVAL;
		goto out;
	}

	/* unlocks keyslots  */
	r = reencrypt_initialize_keyslot_contexts(cd, vk_generated, prefer_token, old_key_kc,
						  new_key_kc, &kcs);
	if (r < 0)
		goto out;

	if (!ARG_SET(OPT_INIT_ONLY_ID) || (tools_blkid_supported() && sector_size_increase)) {
		r = reencrypt_hint_force_offline_reencrypt(data_device);
		if (r < 0)
			goto out;
	}

	if (vk_change && active_slots && !ARG_SET(OPT_FORCE_NO_KEYSLOTS_ID)) {
		r = reencrypt_add_new_keyslots(cd, prefer_token, &kcs);
		if (r < 0)
			goto out;
	}

	/*
	 * with --init-only lookup active device only if
	 * blkid probes are allowed and sector size increase
	 * is requested.
	 */
	if (!ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID) &&
	    (!ARG_SET(OPT_INIT_ONLY_ID) || (tools_blkid_supported() && sector_size_increase))) {
		r = reencrypt_get_active_name(cd, data_device, &active_name);
		if (r < 0)
			goto out;
	}

	if (sector_size_increase && !active_name && tools_blkid_supported() &&
	    !ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID)) {
		log_err(_("Encryption sector size increase on offline device is not supported.\n"
			  "Activate the device first or use --force-offline-reencrypt option (dangerous!)."));
		r = -EINVAL;
		goto out;
	}

	if (sector_size_increase && active_name) {
		r = reencrypt_check_active_device_sb_block_size(active_name, luks2_params.sector_size);
		if (r < 0)
			goto out;
	}

	r = crypt_reencrypt_init_by_keyslot_context(cd,
			ARG_SET(OPT_INIT_ONLY_ID) ? NULL : active_name,
			kcs.p_old_kc, kcs.p_new_kc,
			kcs.old_key_id, kcs.new_key_id,
			cipher, mode, &params);

out:
	crypt_keyslot_context_free(old_key_kc);
	crypt_keyslot_context_free(new_key_kc);
	if (r < 0 && crypt_reencrypt_status(cd, NULL) == CRYPT_REENCRYPT_NONE) {
		for (i = 0; i < kcs.last_ks; i++) {
			if (kcs.ks[i].new_id >= 0 && kcs.ks[i].new_id != kcs.ks[i].id &&
			    crypt_keyslot_destroy(cd, kcs.ks[i].new_id))
				log_dbg("Failed to remove keyslot %d with unbound key.",
					kcs.ks[i].new_id);
		}
	}
	reencrypt_keyslot_contexts_destroy(&kcs);
	free(active_name);
	return r;
}

static int reencrypt_luks2_resume(struct crypt_device *cd)
{
	int r;
	char *backing_file = NULL;
	struct tools_progress_params prog_parms = {
		.frequency = ARG_UINT32(OPT_PROGRESS_FREQUENCY_ID),
		.batch_mode = ARG_SET(OPT_BATCH_MODE_ID),
		.json_output = ARG_SET(OPT_PROGRESS_JSON_ID),
		.interrupt_message = _("\nReencryption interrupted."),
		.device = tools_get_device_name(crypt_get_device_name(cd), &backing_file)
	};

	if (ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID) && !ARG_SET(OPT_BATCH_MODE_ID))
		log_std(_("Resuming LUKS reencryption in forced offline mode.\n"));

	set_int_handler(0);
	r = crypt_reencrypt_run(cd, tools_progress, &prog_parms);
	free(backing_file);
	return r;
}

static int check_broken_luks_signature(const char *device)
{
	int r;
	size_t count;

	if (ARG_SET(OPT_DISABLE_BLKID_ID))
		return 0;

	r = tools_detect_signatures(device, PRB_ONLY_LUKS, &count, ARG_SET(OPT_BATCH_MODE_ID));
	if (r < 0) {
		if (r == -EIO)
			log_err(_("Blkid scan failed for %s."), device);
		return -EINVAL;
	}
	if (count) {
		log_err(_("Device %s contains broken LUKS metadata. Aborting operation."), device);
		return -EINVAL;
	}

	return 0;
}

static int _encrypt(struct crypt_device *cd, const char *type, enum device_status_info dev_st, int action_argc, const char **action_argv)
{
	const char *device_ptr;
	enum device_status_info data_dev_st;
	struct stat st;
	struct crypt_device *encrypt_cd = NULL;
	int r = -EINVAL;

	if (dev_st == DEVICE_LUKS2 || dev_st == DEVICE_LUKS1) {
		log_err(_("Device %s is already LUKS device. Aborting operation."),
			uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]));
		return -EINVAL;
	}

	if (dev_st == DEVICE_NOT_LUKS &&
	    (!ARG_SET(OPT_HEADER_ID) || !stat(ARG_STR(OPT_HEADER_ID), &st))) {
		device_ptr = ARG_SET(OPT_HEADER_ID) ? ARG_STR(OPT_HEADER_ID) : action_argv[0];
		r = check_broken_luks_signature(device_ptr);
		if (r < 0)
			return r;
	}

	/* check data device type/state */
	if (ARG_SET(OPT_HEADER_ID)) {
		device_ptr = cd ? crypt_get_device_name(cd) : action_argv[0];
		data_dev_st = check_luks_device(device_ptr);

		if (data_dev_st == DEVICE_INVALID)
			return -EINVAL;

		if (data_dev_st == DEVICE_LUKS2 || data_dev_st == DEVICE_LUKS1) {
			log_err(_("Device %s is already LUKS device. Aborting operation."),
				device_ptr);
			return -EINVAL;
		}

		if (data_dev_st == DEVICE_LUKS2_REENCRYPT || data_dev_st == DEVICE_LUKS1_UNUSABLE) {
			log_err(_("Device %s is already in LUKS reencryption. Aborting operation."),
				device_ptr);
			return -EINVAL;
		}

		r = check_broken_luks_signature(device_ptr);
		if (r < 0)
			return r;
	}

	if (!type)
		type = crypt_get_default_type();

	if (dev_st == DEVICE_LUKS1_UNUSABLE || isLUKS1(type)) {
		r = reencrypt_is_header_detached(ARG_STR(OPT_HEADER_ID), action_argv[0]);
		if (r < 0)
			return r;
		if (!r && !ARG_SET(OPT_REDUCE_DEVICE_SIZE_ID)) {
			log_err(_("Encryption without detached header (--header) is not possible without data device size reduction (--reduce-device-size)."));
			return -ENOTSUP;
		}
		return reencrypt_luks1(action_argv[0]);
	} else if (dev_st == DEVICE_NOT_LUKS) {
		r = encrypt_luks2_init(&encrypt_cd, action_argv[0], action_argc > 1 ? action_argv[1] : NULL);
		if (r < 0 || ARG_SET(OPT_INIT_ONLY_ID)) {
			crypt_free(encrypt_cd);
			return r;
		}
		cd = encrypt_cd;
		dev_st = DEVICE_LUKS2_REENCRYPT;
	} else if (dev_st == DEVICE_LUKS2_REENCRYPT &&
		   (r = reencrypt_luks2_load(cd, action_argv[0])) < 0)
		return r;

	if (dev_st != DEVICE_LUKS2_REENCRYPT)
		return -EINVAL;

	r = reencrypt_luks2_resume(cd);

	crypt_free(encrypt_cd);
	return r;
}

static int _decrypt(struct crypt_device **cd, enum device_status_info dev_st, const char *data_device)
{
	int r;
	struct stat st;
	bool export_header = false;

	assert(cd);

	if (dev_st == DEVICE_LUKS1 || dev_st == DEVICE_LUKS1_UNUSABLE ||
	    (dev_st == DEVICE_NOT_LUKS && ARG_SET(OPT_UUID_ID) && !ARG_SET(OPT_HEADER_ID)))
		return reencrypt_luks1(data_device);

	/* header file does not exist, try loading device type from data device */
	if (dev_st == DEVICE_NOT_LUKS && ARG_SET(OPT_HEADER_ID) &&
	    (stat(ARG_STR(OPT_HEADER_ID), &st) < 0) && errno == ENOENT) {
		if (ARG_SET(OPT_ACTIVE_NAME_ID))
			dev_st = load_luks2_by_name(cd, ARG_STR(OPT_ACTIVE_NAME_ID), NULL);
		else
			dev_st = load_luks(cd, NULL, uuid_or_device(data_device));

		/*
		 * If data device is not LUKS2 report 'header is missing' error
		 * message user would get originally.
		 */
		if (dev_st != DEVICE_LUKS2) {
			log_err(_("Device %s does not exist or access denied."),
				ARG_STR(OPT_HEADER_ID));
			return -EINVAL;
		}

		export_header = true;
	}

	if (dev_st == DEVICE_LUKS2_REENCRYPT) {
		if ((r = reencrypt_luks2_load(*cd, data_device)) < 0)
			return r;
	} else if (dev_st == DEVICE_LUKS2) {
		if (!luks2_reencrypt_eligible(*cd))
			return -EINVAL;
		if (!ARG_SET(OPT_HEADER_ID)) {
			log_err(_("LUKS2 decryption requires --header option."));
			return -EINVAL;
		}

		if (export_header)
			r = decrypt_luks2_datashift_init(cd, ARG_STR(OPT_HEADER_ID));
		else
			r = decrypt_luks2_init(*cd, data_device);

		if (r < 0 || ARG_SET(OPT_INIT_ONLY_ID))
			return r;
	} else if (dev_st == DEVICE_NOT_LUKS) {
		log_err(_("Device %s is not a valid LUKS device."),
			ARG_STR(OPT_HEADER_ID) ?: uuid_or_device(data_device));
		return -EINVAL;
	}

	r = reencrypt_luks2_resume(*cd);
	return r;
}

static int _reencrypt(struct crypt_device *cd, enum device_status_info dev_st, const char *data_device)
{
	int r;

	if (dev_st == DEVICE_LUKS1 || dev_st == DEVICE_LUKS1_UNUSABLE)
		return reencrypt_luks1(data_device);
	else if (dev_st == DEVICE_LUKS2_REENCRYPT) {
		if ((r = reencrypt_luks2_load(cd, data_device)) < 0)
			return r;
	} else if (dev_st == DEVICE_LUKS2) {
		r = reencrypt_luks2_init(cd, data_device);
		if (r < 0|| ARG_SET(OPT_INIT_ONLY_ID))
			return r;
	} else
		return -EINVAL;

	return reencrypt_luks2_resume(cd);
}

int reencrypt(int action_argc, const char **action_argv)
{
	enum device_status_info dev_st;
	int r = -EINVAL;
	struct crypt_device *cd = NULL;
	const char *type = luksType(device_type);

	if (action_argc < 1 && (!ARG_SET(OPT_ACTIVE_NAME_ID) || ARG_SET(OPT_ENCRYPT_ID))) {
		log_err(_("Command requires device as argument."));
		return r;
	}

	if (ARG_SET(OPT_ACTIVE_NAME_ID))
		dev_st = load_luks2_by_name(&cd, ARG_STR(OPT_ACTIVE_NAME_ID), ARG_STR(OPT_HEADER_ID));
	else
		dev_st = load_luks(&cd, ARG_STR(OPT_HEADER_ID), uuid_or_device(action_argv[0]));

	if (dev_st == DEVICE_INVALID)
		return r;

	if (dev_st == DEVICE_LUKS1 && isLUKS2(type)) {
		log_err(_("Conflicting versions. Device %s is LUKS1."),
			uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]));
		goto out;
	}

	if (dev_st == DEVICE_LUKS1_UNUSABLE && isLUKS2(type)) {
		log_err(_("Conflicting versions. Device %s is in LUKS1 reencryption."),
			uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]));
		goto out;
	}

	if (dev_st == DEVICE_LUKS2 && isLUKS1(type)) {
		log_err(_("Conflicting versions. Device %s is LUKS2."),
			uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]));
		goto out;
	}

	if (dev_st == DEVICE_LUKS2_REENCRYPT && isLUKS1(type)) {
		log_err(_("Conflicting versions. Device %s is in LUKS2 reencryption."),
			uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]));
		goto out;
	}

	if (dev_st == DEVICE_LUKS2_REENCRYPT && ARG_SET(OPT_INIT_ONLY_ID)) {
		log_err(_("LUKS2 reencryption already initialized. Aborting operation."));
		r = -EINVAL;
		goto out;
	}

	if (ARG_SET(OPT_RESUME_ONLY_ID) &&
	    (dev_st == DEVICE_LUKS2 || dev_st == DEVICE_LUKS1 || dev_st == DEVICE_NOT_LUKS)) {
		log_err(_("Device reencryption not in progress."));
		r = -EINVAL;
		goto out;
	}

	if (ARG_SET(OPT_ENCRYPT_ID))
		r = _encrypt(cd, type, dev_st, action_argc, action_argv);
	else if (ARG_SET(OPT_DECRYPT_ID))
		r = _decrypt(&cd, dev_st, action_argv[0]);
	else
		r = _reencrypt(cd, dev_st, action_argv[0]);

out:
	crypt_free(cd);
	return r;
}
