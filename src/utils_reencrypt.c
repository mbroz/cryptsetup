/*
 * cryptsetup - action re-encryption utilities
 *
 * Copyright (C) 2009-2023 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2023 Milan Broz
 * Copyright (C) 2021-2023 Ondrej Kozina
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
}

static int reencrypt_check_passphrase(struct crypt_device *cd,
	int keyslot,
	const char *passphrase,
	size_t passphrase_len)
{
	int r;

	assert(cd);

	r = crypt_activate_by_passphrase(cd, NULL, keyslot,
					 passphrase, passphrase_len, 0);
	check_signal(&r);
	tools_passphrase_msg(r);
	tools_keyslot_msg(r, UNLOCKED);

	return r;
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

static int reencrypt_luks2_load(struct crypt_device *cd, const char *data_device)
{
	char *msg;
	crypt_reencrypt_info ri;
	int r;
	size_t passwordLen;
	char *active_name = NULL, *hash = NULL, *password = NULL;
	struct crypt_params_reencrypt params = {};

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

	r = tools_get_key(NULL, &password, &passwordLen,
			ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID),
			ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_TIMEOUT_ID),
			verify_passphrase(0), 0, cd);
	if (r < 0)
		goto out;

	if (!ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID))
		r = reencrypt_get_active_name(cd, data_device, &active_name);
	if (r >= 0)
		r = crypt_reencrypt_init_by_passphrase(cd, active_name, password,
				passwordLen, ARG_INT32(OPT_KEY_SLOT_ID),
				ARG_INT32(OPT_KEY_SLOT_ID), NULL, NULL, &params);
out:
	free(hash);
	crypt_safe_free(password);
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
	size_t passwordLen;
	char *tmp, uuid_str[37], header_file[PATH_MAX] = { 0 }, *password = NULL;
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

	if (!ARG_SET(OPT_HEADER_ID) && ARG_UINT64(OPT_OFFSET_ID) &&
	    data_shift && (ARG_UINT64(OPT_OFFSET_ID) > (uint64_t)(imaxabs(data_shift) / (2 * SECTOR_SIZE)))) {
		log_err(_("Requested data offset must be less than or equal to half of --reduce-device-size parameter."));
		return -EINVAL;
	}

	/* TODO: ask user to confirm. It's useless to do data device reduction and than use smaller value */
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

	r = luksFormat(cd, &password, &passwordLen);
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
	r = crypt_reencrypt_init_by_passphrase(*cd, NULL, password, passwordLen,
			CRYPT_ANY_SLOT, keyslot, crypt_get_cipher(*cd),
			crypt_get_cipher_mode(*cd), &params);
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
		r = crypt_activate_by_passphrase(*cd, device_name, ARG_INT32(OPT_KEY_SLOT_ID), password, passwordLen, activate_flags);
		if (r >= 0)
			log_std(_("%s/%s is now active and ready for online encryption.\n"), crypt_get_dir(), device_name);
	}

	if (r < 0)
		goto out;

	/* just load reencryption context to continue reencryption */
	if (!ARG_SET(OPT_INIT_ONLY_ID)) {
		params.flags &= ~CRYPT_REENCRYPT_INITIALIZE_ONLY;
		r = crypt_reencrypt_init_by_passphrase(*cd, device_name, password, passwordLen,
				CRYPT_ANY_SLOT, keyslot, NULL, NULL, &params);
	}
out:
	crypt_safe_free(password);
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
	const char *data_device,
	const char *expheader)
{
	int fd, r;
	size_t passwordLen;
	struct stat hdr_st;
	bool remove_header = false;
	char *msg, *active_name = NULL, *password = NULL;
	struct crypt_params_reencrypt params = {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "datashift-checksum",
		.hash = ARG_STR(OPT_RESILIENCE_HASH_ID) ?: "sha256",
		.data_shift = crypt_get_data_offset(*cd),
		.device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE,
		.max_hotzone_size = ARG_UINT64(OPT_HOTZONE_SIZE_ID) / SECTOR_SIZE,
		.flags = CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT
	};

	if (!ARG_SET(OPT_BATCH_MODE_ID)) {
		r = asprintf(&msg, _("Header file %s does not exist. Do you want to initialize LUKS2 "
				     "decryption of device %s and export LUKS2 header to file %s?"),
			     expheader, data_device, expheader);
		if (r < 0)
			return -ENOMEM;
		r = yesDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
		free(msg);
		if (r < 0)
			return r;
	}

	if ((r = decrypt_verify_and_set_params(&params)))
		return r;

	r = reencrypt_hint_force_offline_reencrypt(data_device);
	if (r < 0)
		return r;

	r = tools_get_key(NULL, &password, &passwordLen,
			ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID),
			ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_TIMEOUT_ID),
			verify_passphrase(0), 0, *cd);
	if (r < 0)
		return r;

	r = reencrypt_check_passphrase(*cd, ARG_INT32(OPT_KEY_SLOT_ID), password, passwordLen);
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

	r = crypt_reencrypt_init_by_passphrase(*cd, active_name, password,
			passwordLen, ARG_INT32(OPT_KEY_SLOT_ID), CRYPT_ANY_SLOT,
			NULL, NULL, &params);

	if (r < 0 && crypt_reencrypt_status(*cd, NULL) == CRYPT_REENCRYPT_NONE) {
		/* if restore is successful we can remove header backup */
		if (!reencrypt_restore_header(cd, data_device, expheader))
			remove_header = true;
	}
out:
	free(active_name);
	crypt_safe_free(password);

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
	size_t passwordLen;
	char *active_name = NULL, *password = NULL;
	struct crypt_params_reencrypt params = {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = data_shift > 0 ? CRYPT_REENCRYPT_FORWARD : CRYPT_REENCRYPT_BACKWARD,
		.resilience = data_shift ? "datashift" : (ARG_STR(OPT_RESILIENCE_ID) ?: "checksum"),
		.hash = ARG_STR(OPT_RESILIENCE_HASH_ID) ?: "sha256",
		.data_shift = imaxabs(data_shift) / SECTOR_SIZE,
		.device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE,
		.max_hotzone_size = ARG_UINT64(OPT_HOTZONE_SIZE_ID) / SECTOR_SIZE,
	};

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

	r = tools_get_key(NULL, &password, &passwordLen,
			ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	r = reencrypt_check_passphrase(cd, ARG_INT32(OPT_KEY_SLOT_ID), password, passwordLen);
	if (r < 0)
		goto out;

	if (!ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID))
		r = reencrypt_get_active_name(cd, data_device, &active_name);
	if (r >= 0)
		r = crypt_reencrypt_init_by_passphrase(cd, active_name, password,
				passwordLen, ARG_INT32(OPT_KEY_SLOT_ID), CRYPT_ANY_SLOT, NULL, NULL, &params);

out:
	free(active_name);
	crypt_safe_free(password);
	return r;
}

struct keyslot_passwords {
	char *password;
	size_t passwordLen;
	int new;
};

static struct keyslot_passwords *init_keyslot_passwords(size_t count)
{
	size_t i;
	struct keyslot_passwords *tmp = calloc(count, sizeof(struct keyslot_passwords));

	if (!tmp)
		return tmp;

	for (i = 0; i < count; i++)
		tmp[i].new = -1;

	return tmp;
}

static int init_passphrase(struct keyslot_passwords *kp, size_t keyslot_passwords_length,
			   struct crypt_device *cd, const char *msg, int slot_to_check)
{
	crypt_keyslot_info ki;
	char *password;
	int r = -EINVAL, retry_count;
	size_t passwordLen;

	if (slot_to_check != CRYPT_ANY_SLOT) {
		ki = crypt_keyslot_status(cd, slot_to_check);
		if (ki < CRYPT_SLOT_ACTIVE || ki == CRYPT_SLOT_UNBOUND)
			return -ENOENT;
	}

	retry_count = set_tries_tty();

	while (retry_count--) {
		r = tools_get_key(msg,  &password, &passwordLen, 0, 0,
				  ARG_STR(OPT_KEY_FILE_ID), 0, 0, 0 /*pwquality*/, cd);
		if (r < 0)
			return r;
		if (quit) {
			crypt_safe_free(password);
			password = NULL;
			passwordLen = 0;
			return -EAGAIN;
		}

		r = crypt_activate_by_passphrase(cd, NULL, slot_to_check,
						 password, passwordLen, 0);
		if (r < 0) {
			crypt_safe_free(password);
			password = NULL;
			passwordLen = 0;
		}
		if (r < 0 && r != -EPERM)
			return r;

		if (r >= 0) {
			tools_keyslot_msg(r, UNLOCKED);
			if ((size_t)r >= keyslot_passwords_length) {
				crypt_safe_free(password);
				return -EINVAL;
			}
			kp[r].password = password;
			kp[r].passwordLen = passwordLen;
			break;
		}
		tools_passphrase_msg(r);
	}

	password = NULL;
	passwordLen = 0;

	return r;
}

static int _check_luks2_keyslots(struct crypt_device *cd, bool vk_change)
{
	int i, new_vk_slot = (vk_change ? 1 : 0), max = crypt_keyslot_max(CRYPT_LUKS2), active = 0, unbound = 0;

	if (max < 0)
		return max;

	for (i = 0; i < max; i++) {
		switch (crypt_keyslot_status(cd, i)) {
		case CRYPT_SLOT_INVALID:
			return -EINVAL;
		case CRYPT_SLOT_ACTIVE:
			/* fall-through */
		case CRYPT_SLOT_ACTIVE_LAST:
			active++;
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
            (2 * active + unbound + 1 > max)) {
		log_err(_("Not enough free keyslots for reencryption."));
		return -EINVAL;
	}

	return 0;
}

static int fill_keyslot_passwords(struct crypt_device *cd,
		struct keyslot_passwords *kp, size_t kp_size,
		bool vk_change)
{
	char msg[128];
	crypt_keyslot_info ki;
	int i, r = 0;

	if (vk_change && ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT && ARG_SET(OPT_KEY_FILE_ID)) {
		for (i = 0; (size_t)i < kp_size; i++) {
			ki = crypt_keyslot_status(cd, i);
			if (ki == CRYPT_SLOT_INVALID)
				return -EINVAL;
			if (ki == CRYPT_SLOT_ACTIVE) {
				log_err(_("Key file can be used only with --key-slot or with "
					  "exactly one key slot active."));
				return -EINVAL;
			}
		}
	}

	if (ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT) {
		for (i = 0; (size_t)i < kp_size; i++) {
			if (snprintf(msg, sizeof(msg), _("Enter passphrase for key slot %d: "), i) < 0)
				return -EINVAL;
			r = init_passphrase(kp, kp_size, cd, msg, i);
			/* no need to initialize all keyslots with --keep-key */
			if (r >= 0 && !vk_change)
				break;
			if (r == -ENOENT)
				r = 0;
			if (r < 0)
				break;
		}
	} else {
		if (snprintf(msg, sizeof(msg), _("Enter passphrase for key slot %u: "), ARG_INT32(OPT_KEY_SLOT_ID)) < 0)
			return -EINVAL;
		r = init_passphrase(kp, kp_size, cd, msg, ARG_INT32(OPT_KEY_SLOT_ID));
	}

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

static int reencrypt_luks2_init(struct crypt_device *cd, const char *data_device)
{
	bool vk_size_change, sector_size_change, sector_size_increase, vk_change;
	size_t i, vk_size, kp_size;
	int r, keyslot_old = CRYPT_ANY_SLOT, keyslot_new = CRYPT_ANY_SLOT, key_size;
	char cipher[MAX_CIPHER_LEN], mode[MAX_CIPHER_LEN], *vk = NULL, *active_name = NULL;
	const char *new_cipher = NULL;
	struct keyslot_passwords *kp = NULL;
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
	if (ARG_SET(OPT_KEY_SIZE_ID) || new_cipher)
		key_size = get_adjusted_key_size(mode, DEFAULT_LUKS1_KEYBITS, 0);
	else
		key_size = crypt_get_volume_key_size(cd);

	if (!key_size)
		return -EINVAL;
	vk_size = key_size;

	vk_size_change = key_size != crypt_get_volume_key_size(cd);

	/* volume key */
	vk_change = !ARG_SET(OPT_KEEP_KEY_ID);

	if (vk_change && ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		r = tools_read_vk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), &vk, key_size);
		if (r < 0)
			goto out;

		if (!crypt_volume_key_verify(cd, vk, key_size)) {
			/* passed key was valid volume key */
			vk_change = false;
			crypt_safe_free(vk);
			vk = NULL;
		}
	}

	if (!vk_change && !vk_size_change && !new_cipher && !sector_size_change) {
		log_err(_("No data segment parameters changed. Reencryption aborted."));
		r = -EINVAL;
		goto out;
	}

	if (!ARG_SET(OPT_INIT_ONLY_ID) || (tools_blkid_supported() && sector_size_increase)) {
		r = reencrypt_hint_force_offline_reencrypt(data_device);
		if (r < 0)
			goto out;
	}

	r = _check_luks2_keyslots(cd, vk_change);
	if (r)
		goto out;

	r = crypt_keyslot_max(CRYPT_LUKS2);
	if (r < 0)
		goto out;
	kp_size = r;

	kp = init_keyslot_passwords(kp_size);
	if (!kp) {
		r = -ENOMEM;
		goto out;
	}

	/* coverity[overrun-call] */
	r = fill_keyslot_passwords(cd, kp, kp_size, vk_change);
	if (r)
		goto out;

	r = -ENOENT;

	for (i = 0; i < kp_size; i++) {
		if (!vk_change) {
			if (kp[i].password) {
				r = keyslot_old = kp[i].new = i;
				break;
			}
			continue;
		}

		if (kp[i].password && keyslot_new < 0) {
			r = set_keyslot_params(cd, i);
			if (r < 0)
				break;
			r = crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, vk, key_size,
					kp[i].password, kp[i].passwordLen, CRYPT_VOLUME_KEY_NO_SEGMENT);
			tools_keyslot_msg(r, CREATED);
			if (r < 0)
				break;

			kp[i].new = r;
			keyslot_new = r;
			keyslot_old = i;
			if (!vk) {
				/* key generated in crypt_keyslot_add_by_key() call above */
				vk = crypt_safe_alloc(key_size);
				if (!vk) {
					r = -ENOMEM;
					break;
				}
				r = crypt_volume_key_get(cd, keyslot_new, vk, &vk_size, kp[i].password, kp[i].passwordLen);
				if (r < 0)
					break;
			}
			r = assign_tokens(cd, i, r);
			if (r < 0)
				break;
		} else if (kp[i].password) {
			r = set_keyslot_params(cd, i);
			if (r < 0)
				break;
			r = crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, vk, key_size,
					kp[i].password, kp[i].passwordLen, CRYPT_VOLUME_KEY_NO_SEGMENT | CRYPT_VOLUME_KEY_DIGEST_REUSE);
			tools_keyslot_msg(r, CREATED);
			if (r < 0)
				break;
			kp[i].new = r;
			r = assign_tokens(cd, i, r);
			if (r < 0)
				break;
		}
	}

	if (r < 0)
		goto out;

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

	r = crypt_reencrypt_init_by_passphrase(cd,
			ARG_SET(OPT_INIT_ONLY_ID) ? NULL : active_name,
			kp[keyslot_old].password, kp[keyslot_old].passwordLen,
			keyslot_old, kp[keyslot_old].new, cipher, mode, &params);
out:
	crypt_safe_free(vk);
	if (kp) {
		for (i = 0; i < kp_size; i++) {
			crypt_safe_free(kp[i].password);
			if (r < 0 && kp[i].new >= 0 && kp[i].new != (int)i &&
			    crypt_reencrypt_status(cd, NULL) == CRYPT_REENCRYPT_NONE &&
			    crypt_keyslot_destroy(cd, kp[i].new))
				log_dbg("Failed to remove keyslot %d with unbound key.", kp[i].new);
		}
		free(kp);
	}
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

	if (dev_st == DEVICE_LUKS1 || dev_st == DEVICE_LUKS1_UNUSABLE)
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
			r = decrypt_luks2_datashift_init(cd, data_device, ARG_STR(OPT_HEADER_ID));
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
