/*
 * cryptsetup - action re-encryption utilities
 *
 * Copyright (C) 2009-2021 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2021 Milan Broz
 * Copyright (C) 2021 Ondrej Kozina
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

static void _set_reencryption_flags(uint32_t *flags)
{
	if (ARG_SET(OPT_INIT_ONLY_ID))
		*flags |= CRYPT_REENCRYPT_INITIALIZE_ONLY;

	if (ARG_SET(OPT_RESUME_ONLY_ID))
		*flags |= CRYPT_REENCRYPT_RESUME_ONLY;
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
		log_dbg("Keyslot %d uses cipher_null. Replacing with default encryption in new keyslot.", keyslot);
		cipher = DEFAULT_LUKS2_KEYSLOT_CIPHER;
		key_size = DEFAULT_LUKS2_KEYSLOT_KEYBITS / 8;
	}

	if (crypt_keyslot_set_encryption(cd, cipher, key_size))
		return -EINVAL;

	/* if requested any of those just reinitialize context pbkdf */
	if (set_pbkdf || ARG_SET(OPT_HASH_ID) || ARG_SET(OPT_PBKDF_FORCE_ITERATIONS_ID) || ARG_SET(OPT_ITER_TIME_ID))
		return set_pbkdf_params(cd, CRYPT_LUKS2);

	if (crypt_keyslot_get_pbkdf(cd, keyslot, &pbkdf))
		return -EINVAL;

	pbkdf.flags |= CRYPT_PBKDF_NO_BENCHMARK;

	return crypt_set_pbkdf_type(cd, &pbkdf);
}

static int auto_detect_active_name(struct crypt_device *cd, const char *data_device, char *dm_name, size_t dm_name_len)
{
	int r;

	r = tools_lookup_crypt_device(cd, crypt_get_type(cd), data_device, dm_name, dm_name_len);
	if (r > 0)
		log_dbg("Device %s has %d active holders.", data_device, r);

	return r;
}

static int _get_device_active_name(struct crypt_device *cd, const char *data_device, char *buffer, size_t buffer_size)
{
	char *msg;
	int r;

	r = auto_detect_active_name(cd, data_device, buffer, buffer_size);
	if (r > 0) {
		if (*buffer == '\0') {
			log_err(_("Device %s is still in use."), data_device);
			return -EINVAL;
		}
		if (!ARG_SET(OPT_BATCH_MODE_ID))
			log_std(_("Auto-detected active dm device '%s' for data device %s.\n"), buffer, data_device);
	}
	if (r < 0) {
		if (r == -ENOTBLK)
			log_std(_("Device %s is not a block device.\n"), data_device);
		else
			log_err(_("Failed to auto-detect device %s holders."), data_device);

		r = -EINVAL;
		if (!ARG_SET(OPT_BATCH_MODE_ID)) {
			r = asprintf(&msg, _("Unable to decide if device %s is activated or not.\n"
					     "Are you sure you want to proceed with reencryption in offline mode?\n"
					     "It may lead to data corruption if the device is actually activated.\n"
					     "To run reencryption in online mode, use --active-name parameter instead.\n"), data_device);
			if (r < 0)
				return -ENOMEM;
			r = noDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
			free(msg);
		}
	}

	return r;
}

static int action_reencrypt_load(struct crypt_device *cd, const char *data_device)
{
	int r;
	size_t passwordLen;
	char dm_name[PATH_MAX] = {}, *password = NULL;
	const char *active_name = NULL;
	struct crypt_params_reencrypt params = {
		.resilience = ARG_STR(OPT_RESILIENCE_ID) ?: "checksum",
		.hash = ARG_STR(OPT_RESILIENCE_HASH_ID) ?: "sha256",
		.max_hotzone_size = ARG_UINT64(OPT_HOTZONE_SIZE_ID) / SECTOR_SIZE,
		.device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE,
		.flags = CRYPT_REENCRYPT_RESUME_ONLY
	};

	r = tools_get_key(NULL, &password, &passwordLen,
			ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	if (!ARG_SET(OPT_ACTIVE_NAME_ID)) {
		r = _get_device_active_name(cd, data_device, dm_name, sizeof(dm_name));
		if (r > 0)
			active_name = dm_name;
		if (r < 0) {
			crypt_safe_free(password);
			return -EINVAL;
		}
	} else
		active_name = ARG_STR(OPT_ACTIVE_NAME_ID);

	r = crypt_reencrypt_init_by_passphrase(cd, active_name, password, passwordLen, ARG_INT32(OPT_KEY_SLOT_ID), ARG_INT32(OPT_KEY_SLOT_ID), NULL, NULL, &params);

	crypt_safe_free(password);

	return r;
}

static int action_encrypt_luks2(struct crypt_device **cd, const char *data_device, const char *device_name)
{
	char *tmp;
	const char *type;
	int keyslot, r, fd;
	uuid_t uuid;
	size_t passwordLen;
	char *msg, uuid_str[37], header_file[PATH_MAX] = { 0 }, *password = NULL;
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

	type = luksType(device_type);
	if (!type)
		type = crypt_get_default_type();

	if (!isLUKS2(type)) {
		log_err(_("Encryption is supported only for LUKS2 format."));
		return -EINVAL;
	}

	if (!data_shift && !ARG_SET(OPT_HEADER_ID)) {
		log_err(_("Encryption without detached header (--header) is not possible without data device size reduction (--reduce-device-size)."));
		return -ENOTSUP;
	}

	if (!ARG_SET(OPT_HEADER_ID) && ARG_UINT64(OPT_OFFSET_ID) && data_shift && (ARG_UINT64(OPT_OFFSET_ID) > (imaxabs(data_shift) / (2 * SECTOR_SIZE)))) {
		log_err(_("Requested data offset must be less than or equal to half of --reduce-device-size parameter."));
		return -EINVAL;
	}

	/* TODO: ask user to confirm. It's useless to do data device reduction and than use smaller value */
	if (!ARG_SET(OPT_HEADER_ID) && ARG_UINT64(OPT_OFFSET_ID) && data_shift && (ARG_UINT64(OPT_OFFSET_ID) < (imaxabs(data_shift) / (2 * SECTOR_SIZE)))) {
		data_shift = -(ARG_UINT64(OPT_OFFSET_ID) * 2 * SECTOR_SIZE);
		if (data_shift >= 0)
			return -EINVAL;
		log_std(_("Adjusting --reduce-device-size value to twice the --offset %" PRIu64 " (sectors).\n"), ARG_UINT64(OPT_OFFSET_ID) * 2);
	}

	if (ARG_SET(OPT_UUID_ID) && uuid_parse(ARG_STR(OPT_UUID_ID), uuid) == -1) {
		log_err(_("Wrong LUKS UUID format provided."));
		return -EINVAL;
	}

	if (!ARG_SET(OPT_UUID_ID)) {
		uuid_generate(uuid);
		uuid_unparse(uuid, uuid_str);
		if (!(tmp = strdup(uuid_str)))
			return -ENOMEM;
		ARG_SET_STR(OPT_UUID_ID, tmp);
	}

	/* Check the data device is not LUKS device already */
	if ((r = crypt_init(cd, data_device)))
		return r;
	r = crypt_load(*cd, CRYPT_LUKS, NULL);
	crypt_free(*cd);
	*cd = NULL;
	if (!r && !ARG_SET(OPT_BATCH_MODE_ID)) {
		r = asprintf(&msg, _("Detected LUKS device on %s. Do you want to encrypt that LUKS device again?"), data_device);
		if (r == -1)
			return -ENOMEM;

		r = yesDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
		free(msg);
		if (r < 0)
			return r;
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

static int action_decrypt_luks2(struct crypt_device *cd, const char *data_device)
{
	int r;
	char dm_name[PATH_MAX], *password = NULL;
	const char *active_name = NULL;
	struct crypt_params_reencrypt params = {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = data_shift > 0 ? CRYPT_REENCRYPT_FORWARD : CRYPT_REENCRYPT_BACKWARD,
		.resilience = data_shift ? "datashift" : (ARG_STR(OPT_RESILIENCE_ID) ?: "checksum"),
		.hash = ARG_STR(OPT_RESILIENCE_HASH_ID) ?: "sha256",
		.data_shift = imaxabs(data_shift) / SECTOR_SIZE,
		.device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE,
		.max_hotzone_size = ARG_UINT64(OPT_HOTZONE_SIZE_ID) / SECTOR_SIZE,
	};
	size_t passwordLen;

	if (!crypt_get_metadata_device_name(cd) || crypt_header_is_detached(cd) <= 0 ||
	    crypt_get_data_offset(cd) > 0) {
		log_err(_("LUKS2 decryption is supported with detached header device only (with data offset set to 0)."));
		return -ENOTSUP;
	}

	_set_reencryption_flags(&params.flags);

	r = tools_get_key(NULL, &password, &passwordLen,
			ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	if (!ARG_SET(OPT_ACTIVE_NAME_ID)) {
		r = _get_device_active_name(cd, data_device, dm_name, sizeof(dm_name));
		if (r > 0)
			active_name = dm_name;
		if (r < 0)
			goto out;
	} else
		active_name = ARG_STR(OPT_ACTIVE_NAME_ID);

	if (!active_name)
		log_dbg("Device %s seems unused. Proceeding with offline operation.", data_device);

	r = crypt_reencrypt_init_by_passphrase(cd, active_name, password,
			passwordLen, ARG_INT32(OPT_KEY_SLOT_ID), CRYPT_ANY_SLOT, NULL, NULL, &params);
out:
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

static int _check_luks2_keyslots(struct crypt_device *cd, bool new_vk)
{
	int i, new_vk_slot = (new_vk ? 1 : 0), max = crypt_keyslot_max(CRYPT_LUKS2), active = 0, unbound = 0;

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

	if (!new_vk)
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
		bool new_vk)
{
	char msg[128];
	crypt_keyslot_info ki;
	int i, r = 0;

	if (new_vk && ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT && ARG_SET(OPT_KEY_FILE_ID)) {
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
			if (r >= 0 && !new_vk)
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

static int action_reencrypt_luks2(struct crypt_device *cd, const char *data_device)
{
	bool new_vk_size, new_sector_size, new_vk;
	size_t i, vk_size, kp_size;
	int r, keyslot_old = CRYPT_ANY_SLOT, keyslot_new = CRYPT_ANY_SLOT, key_size;
	char dm_name[PATH_MAX], cipher [MAX_CIPHER_LEN], mode[MAX_CIPHER_LEN], *vk = NULL;
	const char *active_name = NULL, *new_cipher = NULL;
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
	new_sector_size = luks2_params.sector_size != (uint32_t)crypt_get_sector_size(cd);

	/* key size */
	if (ARG_SET(OPT_KEY_SIZE_ID) || new_cipher)
		key_size = get_adjusted_key_size(mode, DEFAULT_LUKS1_KEYBITS, 0);
	else
		key_size = crypt_get_volume_key_size(cd);

	if (!key_size)
		return -EINVAL;
	vk_size = key_size;

	new_vk_size = key_size != crypt_get_volume_key_size(cd);

	/* volume key */
	new_vk = !ARG_SET(OPT_KEEP_KEY_ID);

	if (new_vk && ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		r = tools_read_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), &vk, key_size);
		if (r < 0)
			goto out;

		if (!crypt_activate_by_volume_key(cd, NULL, vk, key_size, 0)) {
			/* passed key was valid volume key */
			new_vk = false;
			crypt_safe_free(vk);
			vk = NULL;
		}
	}

	if (!new_vk && !new_vk_size && !new_cipher && !new_sector_size) {
		log_err(_("No data segment parameters changed. Reencryption aborted."));
		r = -EINVAL;
		goto out;
	}

	r = _check_luks2_keyslots(cd, new_vk);
	if (r)
		return r;

	r = crypt_keyslot_max(CRYPT_LUKS2);
	if (r < 0)
		return r;
	kp_size = r;

	kp = init_keyslot_passwords(kp_size);
	if (!kp)
		return -ENOMEM;

	r = fill_keyslot_passwords(cd, kp, kp_size, new_vk);
	if (r)
		goto out;

	r = -ENOENT;

	for (i = 0; i < kp_size; i++) {
		if (!new_vk) {
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

	if (!ARG_SET(OPT_ACTIVE_NAME_ID) && !ARG_SET(OPT_INIT_ONLY_ID)) {
		r = _get_device_active_name(cd, data_device, dm_name, sizeof(dm_name));
		if (r > 0)
			active_name = dm_name;
		if (r < 0)
			goto out;
	} else if (ARG_SET(OPT_ACTIVE_NAME_ID))
		active_name = ARG_STR(OPT_ACTIVE_NAME_ID);

	if (!active_name && !ARG_SET(OPT_INIT_ONLY_ID))
		log_dbg("Device %s seems unused. Proceeding with offline operation.", data_device);

	r = crypt_reencrypt_init_by_passphrase(cd, active_name, kp[keyslot_old].password,
			kp[keyslot_old].passwordLen, keyslot_old, kp[keyslot_old].new,
			cipher, mode, &params);
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
	return r;
}

int reencrypt(int action_argc, const char **action_argv)
{
	uint32_t flags;
	struct crypt_device *cd = NULL;
	struct crypt_params_integrity ip = { 0 };
	int r = 0;
	struct tools_progress_params prog_parms = {
		.frequency = ARG_UINT32(OPT_PROGRESS_FREQUENCY_ID),
		.batch_mode = ARG_SET(OPT_BATCH_MODE_ID)
	};

	if (action_argc < 1 && (!ARG_SET(OPT_ACTIVE_NAME_ID) || ARG_SET(OPT_ENCRYPT_ID))) {
		log_err(_("Command requires device as argument."));
		return -EINVAL;
	}

	if (!ARG_SET(OPT_ENCRYPT_ID) || ARG_SET(OPT_RESUME_ONLY_ID)) {
		if (ARG_SET(OPT_ACTIVE_NAME_ID)) {
			r = crypt_init_by_name_and_header(&cd, ARG_STR(OPT_ACTIVE_NAME_ID), ARG_STR(OPT_HEADER_ID));
			if (r || !isLUKS2(crypt_get_type(cd))) {
				log_err(_("Device %s is not a valid LUKS device."), ARG_STR(OPT_ACTIVE_NAME_ID));
				r = -EINVAL;
				goto out;
			}
		} else {
			if ((r = crypt_init_data_device(&cd, uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]), action_argv[0])))
				return r;

			if ((r = crypt_load(cd, CRYPT_LUKS, NULL))) {
				log_err(_("Device %s is not a valid LUKS device."),
					uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]));
				goto out;
			}
			if (strcmp(crypt_get_type(cd), CRYPT_LUKS2)) {
				log_err(_("Only LUKS2 format is currently supported. Please use cryptsetup-reencrypt tool for LUKS1."));
				r = -EINVAL;
				goto out;
			}
		}

		if (crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &flags)) {
			r = -EINVAL;
			goto out;
		}

		if (flags & CRYPT_REQUIREMENT_OFFLINE_REENCRYPT) {
			log_err(_("Legacy offline reencryption already in-progress. Use cryptsetup-reencrypt utility."));
			r = -EINVAL;
			goto out;
		}

		if (flags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT)
			r = -EBUSY;

		/* raw integrity info is available since 2.0 */
		if (crypt_get_integrity_info(cd, &ip) || ip.tag_size) {
			log_err(_("Reencryption of device with integrity profile is not supported."));
			r = -ENOTSUP;
			goto out;
		}
	}

	if (r == -EBUSY) {
		if (ARG_SET(OPT_INIT_ONLY_ID))
			log_err(_("LUKS2 reencryption already initialized. Aborting operation."));
		else
			r = action_reencrypt_load(cd, action_argv[0]);
	} else if (!r && ARG_SET(OPT_RESUME_ONLY_ID)) {
		log_err(_("LUKS2 device is not in reencryption."));
		r = -EINVAL;
	} else if (ARG_SET(OPT_DECRYPT_ID))
		r = action_decrypt_luks2(cd, action_argv[0]);
	else if (ARG_SET(OPT_ENCRYPT_ID) && !ARG_SET(OPT_RESUME_ONLY_ID))
		r = action_encrypt_luks2(&cd, action_argv[0], action_argc > 1 ? action_argv[1] : NULL);
	else
		r = action_reencrypt_luks2(cd, action_argv[0]);

	if (r >= 0 && !ARG_SET(OPT_INIT_ONLY_ID)) {
		set_int_handler(0);
		r = crypt_reencrypt_run(cd, tools_reencrypt_progress, &prog_parms);
	}
out:
	crypt_free(cd);

	return r;
}
