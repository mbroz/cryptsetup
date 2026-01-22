// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include <uuid/uuid.h>

#include "cryptsetup.h"
#include "cryptsetup_args.h"
#include "utils_luks.h"

static char *keyfiles[MAX_KEYFILES];
static char *keyring_links[MAX_KEYRING_LINKS];
static char *vks_in_keyring[MAX_VK_IN_KEYRING];
static char *vk_files[2];
static char *keyfile_stdin = NULL;
static uint32_t key_sizes[2];

static int keyfiles_count = 0;
static int keyring_links_count = 0;
static int vks_in_keyring_count = 0;
static int vk_files_count = 0;
static int key_sizes_count = 0;
int64_t data_shift = 0;

const char *device_type = "luks";
const char *set_pbkdf = NULL;

static const char **action_argv;
static int action_argc;
static const char *null_action_argv[] = {NULL, NULL};
static int total_keyfiles = 0;

static struct tools_log_params log_parms;

struct tools_arg tool_core_args[] = {  { NULL, false, CRYPT_ARG_BOOL, {}, {} }, /* leave unused due to popt library */
#define ARG(A, B, C, D, E, F, G, H) { A, false, F, G, H },
#include "cryptsetup_arg_list.h"
#undef ARG
};

void tools_cleanup(void)
{
	tools_args_free(tool_core_args, ARRAY_SIZE(tool_core_args));

	FREE_AND_NULL(keyfile_stdin);

	while (keyfiles_count)
		free(keyfiles[--keyfiles_count]);
	while (keyring_links_count)
		free(keyring_links[--keyring_links_count]);
	while (vks_in_keyring_count)
		free(vks_in_keyring[--vks_in_keyring_count]);
	while (vk_files_count)
		free(vk_files[--vk_files_count]);

	total_keyfiles = 0;
}

static const char *uuid_or_device_header(const char **data_device)
{
	if (data_device)
		*data_device = ARG_SET(OPT_HEADER_ID) ? action_argv[0] : NULL;

	return uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]);
}

static bool isLUKS(const char *type)
{
	return isLUKS2(type) || isLUKS1(type);
}

static int _set_keyslot_encryption_params(struct crypt_device *cd)
{
	const char *type = crypt_get_type(cd);
	int r;

	if (!ARG_SET(OPT_KEYSLOT_KEY_SIZE_ID) && !ARG_SET(OPT_KEYSLOT_CIPHER_ID))
		return 0;

	if (!isLUKS2(type)) {
		log_err(_("Keyslot encryption parameters can be set only for LUKS2 device."));
		return -EINVAL;
	}

	r = crypt_keyslot_set_encryption(cd, ARG_STR(OPT_KEYSLOT_CIPHER_ID), ARG_UINT32(OPT_KEYSLOT_KEY_SIZE_ID) / 8);
	if (r < 0)
		log_err(_("Keyslot encryption parameters are not compatible with LUKS2 keyslot encryption."));

	return r;
}

static int init_new_keyslot_context(struct crypt_device *cd,
				const char *msg,
				bool verify, bool pwquality,
				struct crypt_keyslot_context **kc)
{
	char *password;
	size_t passwordLen;
	int r = -EINVAL;

	if (ARG_SET(OPT_NEW_KEY_DESCRIPTION_ID))
		r = crypt_keyslot_context_init_by_keyring(cd, ARG_STR(OPT_NEW_KEY_DESCRIPTION_ID), kc);
	else if (ARG_SET(OPT_NEW_KEYFILE_ID) && !tools_is_stdin(ARG_STR(OPT_NEW_KEYFILE_ID)))
		r = crypt_keyslot_context_init_by_keyfile(cd, ARG_STR(OPT_NEW_KEYFILE_ID),
							  ARG_UINT32(OPT_NEW_KEYFILE_SIZE_ID),
							  ARG_UINT64(OPT_NEW_KEYFILE_OFFSET_ID), kc);
	else {
		r = tools_get_key(msg, &password, &passwordLen, ARG_UINT64(OPT_NEW_KEYFILE_OFFSET_ID),
				  ARG_UINT32(OPT_NEW_KEYFILE_SIZE_ID), ARG_STR(OPT_NEW_KEYFILE_ID),
				  ARG_UINT32(OPT_TIMEOUT_ID), verify, pwquality, cd);
		if (r < 0)
			return r;
		r = crypt_keyslot_context_init_by_passphrase(cd, password, passwordLen, kc);
		crypt_safe_free(password);
	}

	return r;
}

static int action_open_plain(void)
{
	struct crypt_device *cd = NULL, *cd1 = NULL;
	const char *pcipher, *pmode;
	char *msg, cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	struct crypt_active_device cad;
	struct crypt_params_plain params = {
		.hash = ARG_SET(OPT_HASH_ID) ? ARG_STR(OPT_HASH_ID) : DEFAULT_PLAIN_HASH,
		.skip = ARG_UINT64(OPT_SKIP_ID),
		.offset = ARG_UINT64(OPT_OFFSET_ID),
		.sector_size = ARG_UINT32(OPT_SECTOR_SIZE_ID) ?: SECTOR_SIZE
	};
	struct crypt_keyslot_context *kc = NULL;
	char *password = NULL, *vk_description_activation = NULL;
	const char *activated_name = NULL;
	size_t passwordLen, key_size_max, signatures = 0,
	       key_size = (ARG_UINT32(OPT_KEY_SIZE_ID) ?: DEFAULT_PLAIN_KEYBITS) / 8;
	uint32_t activate_flags = 0;
	bool compat_warning = false;
	int r;

	r = crypt_parse_name_and_mode(ARG_STR(OPT_CIPHER_ID) ?: DEFAULT_CIPHER(PLAIN),
				      cipher, NULL, cipher_mode);
	if (r < 0) {
		log_err(_("No known cipher specification pattern detected."));
		goto out;
	}

	/*
	 * Warn user if no cipher options and passphrase hashing is not specified.
	 * For keyfile, password hashing is not used, no need to print warning for missing --hash.
	 * Keep this enabled even in batch mode to fix scripts and avoid data corruption.
	 */
	if (!ARG_SET(OPT_CIPHER_ID) || !ARG_SET(OPT_KEY_SIZE_ID)) {
		log_err(_("WARNING: Using default options for cipher (%s-%s, key size %u bits) that could be incompatible with older versions."),
			cipher, cipher_mode, key_size * 8);
		compat_warning = true;
	}
	if (!ARG_SET(OPT_HASH_ID) && !ARG_SET(OPT_KEY_FILE_ID) && !ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
		log_err(_("WARNING: Using default options for hash (%s) that could be incompatible with older versions."), params.hash);
		compat_warning = true;
	}
	if (compat_warning)
		log_err(_("For plain mode, always use options --cipher, --key-size and if no keyfile or keyring is used, then also --hash."));

	/* FIXME: temporary hack, no hashing for keyfiles in plain mode */
	if (ARG_SET(OPT_KEY_FILE_ID) && !tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID))) {
		params.hash = NULL;
		if (!ARG_SET(OPT_BATCH_MODE_ID) && ARG_SET(OPT_HASH_ID))
			log_std(_("WARNING: The --hash parameter is being ignored "
				 "in plain mode with keyfile specified.\n"));
	}

	if (ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
		r = tools_parse_vk_description(ARG_STR(OPT_VOLUME_KEY_KEYRING_ID), &vk_description_activation);
		if (r < 0)
			goto out;
	}

	if (params.hash && !strcmp(params.hash, "plain"))
		params.hash = NULL;

	if (!ARG_SET(OPT_BATCH_MODE_ID) && !params.hash && ARG_SET(OPT_KEY_FILE_ID) && !tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID)) && ARG_SET(OPT_KEYFILE_SIZE_ID))
		log_std(_("WARNING: The --keyfile-size option is being ignored, "
			 "the read size is the same as the encryption key size.\n"));

	if (ARG_SET(OPT_REFRESH_ID)) {
		activated_name = action_argc > 1 ? action_argv[1] : action_argv[0];
		r = crypt_init_by_name_and_header(&cd1, activated_name, NULL);
		if (r)
			goto out;
		r = crypt_get_active_device(cd1, activated_name, &cad);
		if (r)
			goto out;

		/* copy known parameters from existing device */
		params.skip = crypt_get_iv_offset(cd1);
		params.offset = crypt_get_data_offset(cd1);
		params.size = cad.size;
		params.sector_size = crypt_get_sector_size(cd1);
		key_size = crypt_get_volume_key_size(cd1);

		if ((r = crypt_init(&cd, crypt_get_device_name(cd1))))
			goto out;

		activate_flags |= CRYPT_ACTIVATE_REFRESH;

		pcipher = crypt_get_cipher(cd1);
		pmode = crypt_get_cipher_mode(cd1);
	} else {
		activated_name = action_argv[1];
		if ((r = crypt_init(&cd, action_argv[0])))
			goto out;

		/* Skip blkid scan when activating plain device with offset */
		if (!ARG_UINT64(OPT_OFFSET_ID) && !ARG_SET(OPT_DISABLE_BLKID_ID)) {
			/* Print all present signatures in read-only mode */
			r = tools_detect_signatures(action_argv[0], PRB_FILTER_NONE, &signatures, ARG_SET(OPT_BATCH_MODE_ID));
			if (r < 0) {
				if (r == -EIO)
					log_err(_("Blkid scan failed for %s."), action_argv[0]);
				goto out;
			}
		}

		if (signatures && !ARG_SET(OPT_BATCH_MODE_ID)) {
			r = asprintf(&msg, _("Detected device signature(s) on %s. Proceeding further may damage existing data."), action_argv[0]);
			if (r == -1) {
				r = -ENOMEM;
				goto out;
			}

			r = yesDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
			free(msg);
			if (r < 0)
				goto out;
		}

		pcipher = cipher;
		pmode = cipher_mode;
	}

	if ((r = tools_check_newname(activated_name)))
		goto out;

	if (ARG_SET(OPT_DEVICE_SIZE_ID))
		params.size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE;
	else if (ARG_SET(OPT_SIZE_ID))
		params.size = ARG_UINT64(OPT_SIZE_ID);

	r = crypt_format(cd, CRYPT_PLAIN,
			 pcipher, pmode,
			 NULL, NULL,
			 key_size,
			 &params);
	check_signal(&r);
	if (r < 0)
		goto out;

	if (ARG_SET(OPT_SHARED_ID))
		activate_flags |= CRYPT_ACTIVATE_SHARED;

	set_activation_flags(&activate_flags);

	if (ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
		r = crypt_keyslot_context_init_by_vk_in_keyring(cd, vk_description_activation, &kc);
		if (r < 0)
			goto out;

		r = crypt_activate_by_keyslot_context(cd, activated_name, CRYPT_ANY_SLOT,
			kc, CRYPT_ANY_SLOT, NULL, activate_flags | CRYPT_ACTIVATE_KEYRING_KEY);
	} else if (!tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID))) {
		/* If no hash, key is read directly, read size is always key_size
		 * (possible --keyfile_size is ignored.
		 * If hash is specified, --keyfile_size is applied.
		 * The --keyfile_offset is applied always.
		 */
		key_size_max = params.hash ? ARG_UINT32(OPT_KEYFILE_SIZE_ID) : key_size;
		r = crypt_activate_by_keyfile_device_offset(cd, action_argv[1],
			CRYPT_ANY_SLOT, ARG_STR(OPT_KEY_FILE_ID), key_size_max,
			ARG_UINT64(OPT_KEYFILE_OFFSET_ID), activate_flags);
	} else {
		key_size_max = (ARG_SET(OPT_KEY_FILE_ID) && !params.hash) ? key_size : ARG_UINT32(OPT_KEYFILE_SIZE_ID);
		r = tools_get_key(NULL, &password, &passwordLen,
				  ARG_UINT64(OPT_KEYFILE_OFFSET_ID), key_size_max,
				  ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_TIMEOUT_ID),
				  verify_passphrase(0), 0, cd);
		if (r < 0)
			goto out;

		r = crypt_activate_by_passphrase(cd, activated_name,
			CRYPT_ANY_SLOT, password, passwordLen, activate_flags);
	}
out:
	free(vk_description_activation);
	crypt_keyslot_context_free(kc);
	crypt_free(cd);
	crypt_free(cd1);
	crypt_safe_free(password);

	return r;
}

static int action_open_loopaes(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_loopaes params = {
		.hash = ARG_STR(OPT_HASH_ID),
		.offset = ARG_UINT64(OPT_OFFSET_ID),
		.skip = ARG_SET(OPT_SKIP_ID) ? ARG_UINT64(OPT_SKIP_ID) : ARG_UINT64(OPT_OFFSET_ID)
	};
	unsigned int key_size = (ARG_UINT32(OPT_KEY_SIZE_ID) ?: DEFAULT_LOOPAES_KEYBITS) / 8;
	uint32_t activate_flags = 0;
	const char *activated_name = NULL;
	int r;

	if (!ARG_SET(OPT_KEY_FILE_ID)) {
		log_err(_("Option --key-file is required."));
		return -EINVAL;
	}

	if (ARG_SET(OPT_REFRESH_ID)) {
		activated_name = action_argc > 1 ? action_argv[1] : action_argv[0];
		if ((r = crypt_init_by_name(&cd, activated_name)))
			goto out;
		activate_flags |= CRYPT_ACTIVATE_REFRESH;
	} else {
		activated_name = action_argv[1];
		if ((r = crypt_init(&cd, action_argv[0])))
			goto out;

		r = crypt_format(cd, CRYPT_LOOPAES, ARG_STR(OPT_CIPHER_ID) ?: DEFAULT_LOOPAES_CIPHER,
				 NULL, NULL, NULL, key_size, &params);
		check_signal(&r);
		if (r < 0)
			goto out;
	}

	if ((r = tools_check_newname(activated_name)))
		goto out;

	set_activation_flags(&activate_flags);

	r = crypt_activate_by_keyfile_device_offset(cd, activated_name, CRYPT_ANY_SLOT,
		tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID)) ? "/dev/stdin" : ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID),
		ARG_UINT64(OPT_KEYFILE_OFFSET_ID), activate_flags);
out:
	crypt_free(cd);

	return r;
}

static int tcrypt_load(struct crypt_device *cd, struct crypt_params_tcrypt *params)
{
	int r, tries, eperm = 0;

	tries = set_tries_tty(false);
	do {
		/* TCRYPT header is encrypted, get passphrase now */
		r = tools_get_key(NULL, CONST_CAST(char**)&params->passphrase,
				  &params->passphrase_size, 0, 0, keyfile_stdin, ARG_UINT32(OPT_TIMEOUT_ID),
				 verify_passphrase(0), 0, cd);
		if (r < 0)
			continue;

		if (ARG_SET(OPT_VERACRYPT_QUERY_PIM_ID)) {
			char *tmp_pim_nptr = NULL;
			char *tmp_pim_end = NULL;
			size_t tmp_pim_size = 0;
			unsigned long long tmp_pim_ull = 0;

			r = tools_get_key(_("Enter VeraCrypt PIM: "),
					&tmp_pim_nptr,
					&tmp_pim_size, 0, 0, keyfile_stdin, ARG_UINT32(OPT_TIMEOUT_ID),
					verify_passphrase(0), 0, cd);
			if (r < 0)
				continue;

			tmp_pim_ull = strtoull(tmp_pim_nptr, &tmp_pim_end, 10);
			if (*tmp_pim_nptr == '\0' || !tmp_pim_end || *tmp_pim_end != '\0') {
				log_err(_("Invalid PIM value: parse error."));
				r = -EINVAL;
			} else if (tmp_pim_ull == 0) {
				log_err(_("Invalid PIM value: 0."));
				r = -EINVAL;
			} else if (tmp_pim_ull > UINT32_MAX) {
				log_err(_("Invalid PIM value: outside of range."));
				r = -ERANGE;
			}
			crypt_safe_free(tmp_pim_nptr);
			if (r < 0)
				continue;

			params->veracrypt_pim = (uint32_t)tmp_pim_ull;
			crypt_safe_memzero(&tmp_pim_ull, sizeof(tmp_pim_ull));
		}

		if (ARG_SET(OPT_TCRYPT_HIDDEN_ID))
			params->flags |= CRYPT_TCRYPT_HIDDEN_HEADER;

		if (ARG_SET(OPT_TCRYPT_SYSTEM_ID))
			params->flags |= CRYPT_TCRYPT_SYSTEM_HEADER;

		if (ARG_SET(OPT_TCRYPT_BACKUP_ID))
			params->flags |= CRYPT_TCRYPT_BACKUP_HEADER;

		r = crypt_load(cd, CRYPT_TCRYPT, params);

		if (r == -EPERM) {
			log_err(_("No device header detected with this passphrase."));
			eperm = 1;
		}

		if (r < 0) {
			crypt_safe_free(CONST_CAST(char*)params->passphrase);
			params->passphrase = NULL;
			params->passphrase_size = 0;
		}
		check_signal(&r);
	} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));

	/* Report wrong passphrase if at least one try failed */
	if (eperm && r == -EPIPE)
		r = -EPERM;

	return r;
}

static int action_open_tcrypt(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_tcrypt params = {
		.keyfiles = CONST_CAST(const char **)keyfiles,
		.keyfiles_count = keyfiles_count,
		.flags = CRYPT_TCRYPT_LEGACY_MODES |
			 (ARG_SET(OPT_DISABLE_VERACRYPT_ID) ? 0 : CRYPT_TCRYPT_VERA_MODES),
		.veracrypt_pim = ARG_UINT32(OPT_VERACRYPT_PIM_ID),
		.hash_name = ARG_STR(OPT_HASH_ID),
		.cipher = ARG_STR(OPT_CIPHER_ID),
	};
	const char *activated_name;
	uint32_t activate_flags = 0;
	int r;

	activated_name = ARG_SET(OPT_TEST_PASSPHRASE_ID) ? NULL : action_argv[1];
	if ((r = tools_check_newname(activated_name)))
		goto out;

	r = crypt_init_data_device(&cd, ARG_STR(OPT_HEADER_ID) ?: action_argv[0], action_argv[0]);
	if (r < 0)
		goto out;

	r = tcrypt_load(cd, &params);
	if (r < 0)
		goto out;

	set_activation_flags(&activate_flags);

	if (activated_name)
		r = crypt_activate_by_volume_key(cd, activated_name, NULL, 0, activate_flags);
out:
	crypt_free(cd);
	crypt_safe_free(CONST_CAST(char*)params.passphrase);
	crypt_safe_memzero(&params.veracrypt_pim, sizeof(params.veracrypt_pim));
	return r;
}

static int action_open_bitlk(void)
{
	struct crypt_device *cd = NULL;
	const char *activated_name;
	uint32_t activate_flags = 0;
	int r, tries, keysize;
	char *password = NULL;
	char *key = NULL;
	size_t passwordLen;

	activated_name = ARG_SET(OPT_TEST_PASSPHRASE_ID) ? NULL : action_argv[1];
	if ((r = tools_check_newname(activated_name)))
		goto out;

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	r = crypt_load(cd, CRYPT_BITLK, NULL);
	if (r < 0) {
		log_err(_("Device %s is not a valid BITLK device."), action_argv[0]);
		goto out;
	}
	set_activation_flags(&activate_flags);

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		keysize = crypt_get_volume_key_size(cd);
		if (!keysize && !ARG_SET(OPT_KEY_SIZE_ID)) {
			log_err(_("Cannot determine volume key size for BITLK, please use --key-size option."));
			r = -EINVAL;
			goto out;
		} else if (!keysize)
			keysize = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;

		r = tools_read_vk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), &key, keysize);
		if (r < 0)
			goto out;
		r = crypt_activate_by_volume_key(cd, activated_name,
						 key, keysize, activate_flags);
	} else {
		r = crypt_activate_by_passphrase(cd, activated_name, CRYPT_ANY_SLOT, NULL, 0, activate_flags);
		if (r != -EPERM)
			goto out;

		tries = set_tries_tty(false);
		do {
			r = tools_get_key(NULL, &password, &passwordLen,
					ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
					ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(0), 0, cd);
			if (r < 0)
				goto out;

			r = crypt_activate_by_passphrase(cd, activated_name, CRYPT_ANY_SLOT,
							password, passwordLen, activate_flags);
			tools_passphrase_msg(r);
			check_signal(&r);
			crypt_safe_free(password);
			password = NULL;
		} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
	}
out:
	crypt_safe_free(password);
	crypt_safe_free(key);
	crypt_free(cd);
	return r;
}

static int tcryptDump_with_volume_key(struct crypt_device *cd)
{
	char *vk = NULL;
	size_t vk_size;
	int r;

	if (!ARG_SET(OPT_BATCH_MODE_ID) && !yesDialog(
	    _("Header dump with volume key is sensitive information\n"
	      "which allows access to encrypted partition without passphrase.\n"
	      "This dump should be always stored encrypted on safe place."),
	      NULL))
		return -EPERM;

	vk_size = crypt_get_volume_key_size(cd);
	vk = crypt_safe_alloc(vk_size);
	if (!vk)
		return -ENOMEM;

	r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, vk, &vk_size, NULL, 0);
	if (r < 0)
		goto out;

	log_std("TCRYPT header information for %s\n", crypt_get_device_name(cd));
	log_std("Cipher chain:  \t%s\n", crypt_get_cipher(cd));
	log_std("Cipher mode:   \t%s\n", crypt_get_cipher_mode(cd));
	log_std("Payload offset:\t%d\n", (int)crypt_get_data_offset(cd));
	log_std("MK bits:       \t%d\n", (int)vk_size * 8);
	log_std("MK dump:\t");
	crypt_log_hex(NULL, vk, vk_size, " ", 16, "\n\t\t");
	log_std("\n");
out:
	crypt_safe_free(vk);
	return r;
}

static int action_tcryptDump(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_tcrypt params = {
		.keyfiles = CONST_CAST(const char **)keyfiles,
		.keyfiles_count = keyfiles_count,
		.flags = CRYPT_TCRYPT_LEGACY_MODES |
			 (ARG_SET(OPT_DISABLE_VERACRYPT_ID) ? 0: CRYPT_TCRYPT_VERA_MODES),
		.veracrypt_pim = ARG_UINT32(OPT_VERACRYPT_PIM_ID),
		.hash_name = ARG_STR(OPT_HASH_ID),
		.cipher = ARG_STR(OPT_CIPHER_ID),
	};
	int r;
	r = crypt_init_data_device(&cd, ARG_STR(OPT_HEADER_ID) ?: action_argv[0], action_argv[0]);
	if (r < 0)
		goto out;

	r = tcrypt_load(cd, &params);
	if (r < 0)
		goto out;

	if (ARG_SET(OPT_DUMP_VOLUME_KEY_ID))
		r = tcryptDump_with_volume_key(cd);
	else
		r = crypt_dump(cd);
out:
	crypt_free(cd);
	crypt_safe_free(CONST_CAST(char*)params.passphrase);
	return r;
}

static int bitlkDump_with_volume_key(struct crypt_device *cd)
{
	char *vk = NULL, *password = NULL;
	size_t passwordLen = 0;
	size_t vk_size;
	int r;

	if (!ARG_SET(OPT_BATCH_MODE_ID) && !yesDialog(
	    _("The header dump with volume key is sensitive information\n"
	      "that allows access to encrypted partition without a passphrase.\n"
	      "This dump should be stored encrypted in a safe place."),
	      NULL))
		return -EPERM;

	vk_size = crypt_get_volume_key_size(cd);
	vk = crypt_safe_alloc(vk_size);
	if (!vk)
		return -ENOMEM;

	r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, vk, &vk_size,
					password, passwordLen);
	if (r < 0) {
		r = tools_get_key(NULL, &password, &passwordLen,
					ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
					ARG_UINT32(OPT_TIMEOUT_ID), 0, 0, cd);
		if (r < 0)
			goto out;

		r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, vk, &vk_size,
						password, passwordLen);
	}

	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		r = tools_write_mk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), vk, vk_size);
		if (r < 0)
			goto out;
	}

	log_std("BITLK header information for %s\n", crypt_get_device_name(cd));
	log_std("Cipher name:   \t%s\n", crypt_get_cipher(cd));
	log_std("Cipher mode:   \t%s\n", crypt_get_cipher_mode(cd));
	log_std("UUID:          \t%s\n", crypt_get_uuid(cd));
	log_std("MK bits:       \t%d\n", (int)vk_size * 8);
	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		log_std("Key stored to file %s.\n", ARG_STR(OPT_VOLUME_KEY_FILE_ID));
		goto out;
	}
	log_std("MK dump:\t");
	crypt_log_hex(NULL, vk, vk_size, " ", 16, "\n\t\t");
	log_std("\n");
out:
	crypt_safe_free(password);
	crypt_safe_free(vk);
	return r;
}

static int action_bitlkDump(void)
{
	struct crypt_device *cd = NULL;
	int r;

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	r = crypt_load(cd, CRYPT_BITLK, NULL);
	if (r < 0) {
		log_err(_("Device %s is not a valid BITLK device."), action_argv[0]);
		goto out;
	}

	if (ARG_SET(OPT_DUMP_VOLUME_KEY_ID))
		r = bitlkDump_with_volume_key(cd);
	else
		r = crypt_dump(cd);
out:
	crypt_free(cd);
	return r;
}

static int fvault2Dump_with_volume_key(struct crypt_device *cd)
{
	char *vk = NULL;
	char *password = NULL;
	size_t vk_size = 0;
	size_t pass_len = 0;
	int r = 0;

	if (!ARG_SET(OPT_BATCH_MODE_ID) && !yesDialog(
	    _("The header dump with volume key is sensitive information\n"
	      "that allows access to encrypted partition without a passphrase.\n"
	      "This dump should be stored encrypted in a safe place."),
	      NULL))
		return -EPERM;

	vk_size = crypt_get_volume_key_size(cd);
	vk = crypt_safe_alloc(vk_size);
	if (vk == NULL)
		return -ENOMEM;

	r = tools_get_key(NULL, &password, &pass_len,
		ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID),
		ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_TIMEOUT_ID), 0, 0, cd);
	if (r < 0)
		goto out;

	r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, vk, &vk_size, password, pass_len);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;

	tools_keyslot_msg(r, UNLOCKED);

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		r = tools_write_mk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), vk, vk_size);
		if (r < 0)
			goto out;
	}

	r = crypt_dump(cd);
	if (r < 0)
		goto out;

	log_std("Volume key:       \t");
	crypt_log_hex(cd, vk, vk_size, " ", 0, NULL);
	log_std("\n");
out:
	crypt_safe_free(password);
	crypt_safe_free(vk);
	return r;
}

static int action_fvault2Dump(void)
{
	struct crypt_device *cd = NULL;
	int r = 0;

	r = crypt_init(&cd, action_argv[0]);
	if (r < 0)
		goto out;

	r = crypt_load(cd, CRYPT_FVAULT2, NULL);
	if (r < 0) {
		log_err(_("Device %s is not a valid FVAULT2 device."), action_argv[0]);
		goto out;
	}

	if (ARG_SET(OPT_DUMP_VOLUME_KEY_ID))
		r = fvault2Dump_with_volume_key(cd);
	else
		r = crypt_dump(cd);
out:
	crypt_free(cd);
	return r;
}

static int action_open_fvault2(void)
{
	struct crypt_device *cd = NULL;
	const char *activated_name;
	uint32_t activate_flags = 0;
	int r, tries, keysize;
	char *password = NULL;
	char *key = NULL;
	size_t passwordLen;

	activated_name = ARG_SET(OPT_TEST_PASSPHRASE_ID) ? NULL : action_argv[1];
	if ((r = tools_check_newname(activated_name)))
		goto out;

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	r = crypt_load(cd, CRYPT_FVAULT2, NULL);
	if (r < 0) {
		log_err(_("Device %s is not a valid FVAULT2 device."), action_argv[0]);
		goto out;
	}
	set_activation_flags(&activate_flags);

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		keysize = crypt_get_volume_key_size(cd);
		if (!keysize && !ARG_SET(OPT_KEY_SIZE_ID)) {
			log_err(_("Cannot determine volume key size for FVAULT2, please use --key-size option."));
			r = -EINVAL;
			goto out;
		} else if (!keysize)
			keysize = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;

		r = tools_read_vk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), &key, keysize);
		if (r < 0)
			goto out;
		r = crypt_activate_by_volume_key(cd, activated_name, key, keysize, activate_flags);
	} else {
		tries = set_tries_tty(false);
		do {
			r = tools_get_key(NULL, &password, &passwordLen,
				ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID),
				ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_TIMEOUT_ID),
				verify_passphrase(0), 0, cd);
			if (r < 0)
				goto out;

			r = crypt_activate_by_passphrase(cd, activated_name, CRYPT_ANY_SLOT,
				password, passwordLen, activate_flags);
			tools_passphrase_msg(r);
			check_signal(&r);
			crypt_safe_free(password);
			password = NULL;
		} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
	}
out:
	crypt_safe_free(password);
	crypt_safe_free(key);
	crypt_free(cd);
	return r;
}

static int action_close(void)
{
	struct crypt_device *cd = NULL;
	crypt_status_info ci;
	uint32_t flags = 0;
	int r;

	if (ARG_SET(OPT_DEFERRED_ID))
		flags |= CRYPT_DEACTIVATE_DEFERRED;
	if (ARG_SET(OPT_CANCEL_DEFERRED_ID))
		flags |= CRYPT_DEACTIVATE_DEFERRED_CANCEL;

	r = crypt_init_by_name_and_header(&cd, action_argv[0], ARG_STR(OPT_HEADER_ID));
	if (r == 0)
		r = crypt_deactivate_by_name(cd, action_argv[0], flags);

	if (!r && ARG_SET(OPT_DEFERRED_ID)) {
		ci = crypt_status(cd, action_argv[0]);
		if (ci == CRYPT_ACTIVE || ci == CRYPT_BUSY)
			log_std(_("Device %s is still active and scheduled for deferred removal.\n"),
				  action_argv[0]);
	}

	crypt_free(cd);
	return r;
}

static int action_resize(void)
{
	int r;
	struct crypt_active_device cad;
	uint64_t dev_size = 0;
	struct crypt_device *cd = NULL;
	struct crypt_keyslot_context *kc = NULL;

	r = crypt_init_by_name_and_header(&cd, action_argv[0], ARG_STR(OPT_HEADER_ID));
	if (r)
		goto out;

	/* FIXME: LUKS2 may enforce fixed size and it must not be changed */
	r = crypt_get_active_device(cd, action_argv[0], &cad);
	if (r)
		goto out;

	if (ARG_SET(OPT_DEVICE_SIZE_ID))
		dev_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE;
	else if (ARG_SET(OPT_SIZE_ID))
		dev_size = ARG_UINT64(OPT_SIZE_ID);

	if (ARG_SET(OPT_EXTERNAL_TOKENS_PATH_ID)) {
		r = crypt_token_set_external_path(ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
		if (r < 0) {
			log_err(_("Failed to set external tokens path %s."),
				ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
			goto out;
		}
	}

	if (cad.flags & CRYPT_ACTIVATE_KEYRING_KEY) {
		if (ARG_SET(OPT_DISABLE_KEYRING_ID)) {
			r = -EINVAL;
			log_err(_("Resize of active device requires volume key "
				  "in keyring but --disable-keyring option is set."));
				goto out;
		}

		if (isLUKS2(crypt_get_type(cd))) {
			/* try load VK in kernel keyring using token */
			r = luks_try_token_unlock(cd, ARG_INT32(OPT_KEY_SLOT_ID),
						  ARG_INT32(OPT_TOKEN_ID_ID),
						  NULL, ARG_STR(OPT_TOKEN_TYPE_ID),
						  CRYPT_ACTIVATE_KEYRING_KEY,
						  1, true,
						  ARG_SET(OPT_TOKEN_ONLY_ID) || ARG_SET(OPT_TOKEN_ID_ID) || ARG_SET(OPT_TOKEN_TYPE_ID),
						  NULL);

			if (r >= 0 || quit || ARG_SET(OPT_TOKEN_ONLY_ID))
				goto out;

			r = luks_init_keyslot_context(cd, NULL, verify_passphrase(0), false, &kc);
			if (r < 0)
				goto out;

			r = crypt_activate_by_keyslot_context(cd, NULL,ARG_INT32(OPT_KEY_SLOT_ID),
							kc, CRYPT_ANY_SLOT, NULL,
							CRYPT_ACTIVATE_KEYRING_KEY);
			tools_passphrase_msg(r);
			tools_keyslot_msg(r, UNLOCKED);
		}
	}

out:
	if (r >= 0)
		r = crypt_resize(cd, action_argv[0], dev_size);

	crypt_keyslot_context_free(kc);
	crypt_free(cd);
	return r;
}

static int action_status(void)
{
	crypt_status_info ci;
	crypt_reencrypt_info ri;
	struct crypt_active_device cad;
	struct crypt_params_integrity ip = {};
	struct crypt_device *cd = NULL;
	char *backing_file;
	const char *device;
	int path = 0, r = 0, hw_enc;

	/* perhaps a path, not a dm device name */
	if (strchr(action_argv[0], '/'))
		path = 1;

	ci = crypt_status(NULL, action_argv[0]);
	switch (ci) {
	case CRYPT_INVALID:
		r = -EINVAL;
		break;
	case CRYPT_INACTIVE:
		if (path)
			log_std("%s is inactive.\n", action_argv[0]);
		else
			log_std("%s/%s is inactive.\n", crypt_get_dir(), action_argv[0]);
		r = -ENODEV;
		break;
	case CRYPT_ACTIVE:
	case CRYPT_BUSY:
		if (path)
			log_std("%s is active%s.\n", action_argv[0],
				ci == CRYPT_BUSY ? " and is in use" : "");
		else
			log_std("%s/%s is active%s.\n", crypt_get_dir(), action_argv[0],
				ci == CRYPT_BUSY ? " and is in use" : "");

		r = crypt_init_by_name_and_header(&cd, action_argv[0], ARG_STR(OPT_HEADER_ID));
		if (r < 0)
			goto out;

		log_std("  type:    %s\n", crypt_get_type(cd) ?: "n/a");

		/* Print only CRYPT type devices */
		if (!crypt_get_cipher(cd))
			goto out;

		ri = crypt_reencrypt_status(cd, NULL);
		if (ri > CRYPT_REENCRYPT_NONE && ri < CRYPT_REENCRYPT_INVALID)
			log_std("  reencryption:  in-progress\n");

		r = crypt_get_active_device(cd, action_argv[0], &cad);
		if (r < 0)
			goto out;

		r = crypt_get_integrity_info(cd, &ip);
		if (r < 0 && r != -ENOTSUP)
			goto out;

		hw_enc = crypt_get_hw_encryption_type(cd);
		if (hw_enc < 0) {
			r = hw_enc;
			goto out;
		}

		if (hw_enc == CRYPT_SW_ONLY) {
			log_std("  cipher:  %s-%s\n", crypt_get_cipher(cd), crypt_get_cipher_mode(cd));
			log_std("  keysize: %d [bits]\n", crypt_get_volume_key_size(cd) * 8);
			log_std("  key location: %s\n", (cad.flags & CRYPT_ACTIVATE_KEYRING_KEY) ? "keyring" : "dm-crypt");
		} else if (hw_enc == CRYPT_OPAL_HW_ONLY) {
			log_std("  encryption: HW OPAL only\n");
			log_std("  OPAL keysize: %d [bits]\n", crypt_get_hw_encryption_key_size(cd) * 8);
		} else if (hw_enc == CRYPT_SW_AND_OPAL_HW) {
			log_std("  encryption: dm-crypt over HW OPAL\n");
			log_std("  OPAL keysize: %d [bits]\n", crypt_get_hw_encryption_key_size(cd) * 8);
			log_std("  cipher:  %s-%s\n", crypt_get_cipher(cd), crypt_get_cipher_mode(cd));
			log_std("  keysize: %d [bits]\n", (crypt_get_volume_key_size(cd) - crypt_get_hw_encryption_key_size(cd)) * 8);
			log_std("  key location: %s\n", (cad.flags & CRYPT_ACTIVATE_KEYRING_KEY) ? "keyring" : "dm-crypt");
		}

		if (ip.integrity)
			log_std("  integrity: %s\n", ip.integrity);
		if (ip.integrity_key_size)
			log_std("  integrity keysize: %d [bits]\n", ip.integrity_key_size * 8);
		if (ip.tag_size)
			log_std("  integrity tag size: %u [bytes] %s\n", ip.tag_size,
				(cad.flags & CRYPT_ACTIVATE_INLINE_MODE) ? " (inline HW tags)" : "");
		device = crypt_get_device_name(cd);
		log_std("  device:  %s\n", device);
		if ((backing_file = crypt_loop_backing_file(device))) {
			log_std("  loop:    %s\n", backing_file);
			free(backing_file);
		}
		log_std("  sector size:  %" PRIu64 " [bytes]\n", (uint64_t)crypt_get_sector_size(cd) ?: SECTOR_SIZE);
		log_std("  offset:  %" PRIu64 " [512-byte units] (%" PRIu64 " [bytes])\n", cad.offset, cad.offset * SECTOR_SIZE);
		log_std("  size:    %" PRIu64 " [512-byte units] (%" PRIu64 " [bytes])\n", cad.size, cad.size * SECTOR_SIZE);
		if (cad.iv_offset)
			log_std("  skipped: %" PRIu64 " [512-byte units]\n", cad.iv_offset);
		log_std("  mode:    %s%s\n", cad.flags & CRYPT_ACTIVATE_READONLY ?
					   "readonly" : "read/write",
					   (cad.flags & CRYPT_ACTIVATE_SUSPENDED) ? " (suspended)" : "");
		if (cad.flags & (CRYPT_ACTIVATE_ALLOW_DISCARDS|
				 CRYPT_ACTIVATE_SAME_CPU_CRYPT|
				 CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS|
				 CRYPT_ACTIVATE_NO_READ_WORKQUEUE|
				 CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE|
				 CRYPT_ACTIVATE_HIGH_PRIORITY))
			log_std("  flags:   %s%s%s%s%s%s\n",
				(cad.flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) ? "discards " : "",
				(cad.flags & CRYPT_ACTIVATE_SAME_CPU_CRYPT) ? "same_cpu_crypt " : "",
				(cad.flags & CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS) ? "submit_from_crypt_cpus " : "",
				(cad.flags & CRYPT_ACTIVATE_NO_READ_WORKQUEUE) ? "no_read_workqueue " : "",
				(cad.flags & CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE) ? "no_write_workqueue" : "",
				(cad.flags & CRYPT_ACTIVATE_HIGH_PRIORITY) ? "high_priority" : "");
	}
out:
	crypt_free(cd);
	if (r == -ENOTSUP)
		r = 0;
	return r;
}

static int benchmark_callback(uint32_t time_ms, void *usrptr)
{
	struct crypt_pbkdf_type *pbkdf = usrptr;
	int r = 0;

	check_signal(&r);
	if (r)
		log_err(_("Benchmark interrupted."));
	else
		log_dbg("PBKDF benchmark: memory cost = %u, iterations = %u, "
			"threads = %u (took %u ms)", pbkdf->max_memory_kb,
			pbkdf->iterations, pbkdf->parallel_threads, time_ms);
	return r;
}

static int action_benchmark_kdf(const char *kdf, const char *hash, size_t key_size)
{
	int r;
	if (!strcmp(kdf, CRYPT_KDF_PBKDF2)) {
		struct crypt_pbkdf_type pbkdf = {
			.type = CRYPT_KDF_PBKDF2,
			.hash = hash,
			.time_ms = 1000,
		};

		r = crypt_benchmark_pbkdf(NULL, &pbkdf, "foobarfo", 8, "0123456789abcdef", 16, key_size,
					&benchmark_callback, &pbkdf);
		if (r < 0)
			log_std(_("PBKDF2-%-9s     N/A\n"), hash);
		else
			log_std(_("PBKDF2-%-9s %7u iterations per second for %zu-bit key\n"),
				hash, pbkdf.iterations, key_size * 8);
	} else {
		struct crypt_pbkdf_type pbkdf = {
			.type = kdf,
			.time_ms = ARG_UINT32(OPT_ITER_TIME_ID) ?: DEFAULT_LUKS2_ITER_TIME,
			.max_memory_kb = ARG_UINT32(OPT_PBKDF_MEMORY_ID),
			.parallel_threads = ARG_UINT32(OPT_PBKDF_PARALLEL_ID)
		};

		r = crypt_benchmark_pbkdf(NULL, &pbkdf, "foobarfo", 8,
			"0123456789abcdef0123456789abcdef", 32,
			key_size, &benchmark_callback, &pbkdf);
		if (r < 0)
			log_std(_("%-10s N/A\n"), kdf);
		else
			log_std(_("%-10s %4u iterations, %5u memory, "
				"%1u parallel threads (CPUs) for "
				"%zu-bit key (requested %u ms time)\n"), kdf,
				pbkdf.iterations, pbkdf.max_memory_kb, pbkdf.parallel_threads,
				key_size * 8, pbkdf.time_ms);
	}

	return r;
}

static int benchmark_cipher_loop(const char *cipher, const char *cipher_mode,
				 size_t volume_key_size,
				 double *encryption_mbs, double *decryption_mbs)
{
	int r, buffer_size = 1024 * 1024;

	do {
		r = crypt_benchmark(NULL, cipher, cipher_mode,
				    volume_key_size, 0, buffer_size,
				    encryption_mbs, decryption_mbs);
		if (r == -ERANGE) {
			if (buffer_size < 1024 * 1024 * 65)
				buffer_size *= 2;
			else {
				log_err(_("Result of benchmark is not reliable."));
				r = -ENOENT;
			}
		}
	} while (r == -ERANGE);

	return r;
}

static int action_benchmark(void)
{
	static struct {
		const char *cipher;
		const char *mode;
		size_t key_size;
	} bciphers[] = {
		{ "aes",     "cbc", 16 },
		{ "serpent", "cbc", 16 },
		{ "twofish", "cbc", 16 },
		{ "aes",     "cbc", 32 },
		{ "serpent", "cbc", 32 },
		{ "twofish", "cbc", 32 },
		{ "aes",     "xts", 32 },
		{ "serpent", "xts", 32 },
		{ "twofish", "xts", 32 },
		{ "aes",     "xts", 64 },
		{ "serpent", "xts", 64 },
		{ "twofish", "xts", 64 },
		{  NULL, NULL, 0 }
	};
	static struct {
		const char *type;
		const char *hash;
	} bkdfs[] = {
		{ CRYPT_KDF_PBKDF2,   "sha1" },
		{ CRYPT_KDF_PBKDF2,   "sha256" },
		{ CRYPT_KDF_PBKDF2,   "sha512" },
		{ CRYPT_KDF_PBKDF2,   "ripemd160" },
		{ CRYPT_KDF_PBKDF2,   "whirlpool" },
		{ CRYPT_KDF_ARGON2I,  NULL },
		{ CRYPT_KDF_ARGON2ID, NULL },
		{ NULL, NULL }
	};
	char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	double enc_mbr = 0, dec_mbr = 0;
	int key_size = (ARG_UINT32(OPT_KEY_SIZE_ID) ?: DEFAULT_PLAIN_KEYBITS) / 8;
	int skipped = 0, width, mode_len;
	char *c;
	int i, r;

	log_std(_("# Tests are approximate using memory only (no storage IO).\n"));
	if (set_pbkdf || ARG_SET(OPT_HASH_ID)) {
		if (!set_pbkdf && ARG_SET(OPT_HASH_ID))
			set_pbkdf = CRYPT_KDF_PBKDF2;
		r = action_benchmark_kdf(set_pbkdf, ARG_STR(OPT_HASH_ID), key_size);
	} else if (ARG_SET(OPT_CIPHER_ID)) {
		r = crypt_parse_name_and_mode(ARG_STR(OPT_CIPHER_ID), cipher, NULL, cipher_mode);
		if (r < 0) {
			log_err(_("No known cipher specification pattern detected."));
			return r;
		}
		if ((c  = strchr(cipher_mode, '-')))
			*c = '\0';

		r = benchmark_cipher_loop(cipher, cipher_mode, key_size, &enc_mbr, &dec_mbr);
		if (!r) {
			if (!strncmp(cipher, "capi:", 5))
				mode_len = 0;
			else
				mode_len = strlen(cipher_mode);
			width = strlen(cipher) + mode_len + 1;
			if (width < 11)
				width = 11;

			/* TRANSLATORS: The string is header of a table and must be exactly (right side) aligned. */
			log_std(_("#%*s Algorithm |       Key |      Encryption |      Decryption\n"), width - 11, "");
			if (mode_len)
				log_std("%*s-%s  %9db  %10.1f MiB/s  %10.1f MiB/s\n", width - mode_len - 1,
					cipher, cipher_mode, key_size*8, enc_mbr, dec_mbr);
			else
				log_std("%*s  %9db  %10.1f MiB/s  %10.1f MiB/s\n", width,
					cipher, key_size*8, enc_mbr, dec_mbr);
		} else if (r < 0)
			log_err(_("Cipher %s (with %i bits key) is not available."), ARG_STR(OPT_CIPHER_ID), key_size * 8);
	} else {
		for (i = 0; bkdfs[i].type; i++) {
			r = action_benchmark_kdf(bkdfs[i].type, bkdfs[i].hash, key_size);
			check_signal(&r);
			if (r == -EINTR)
				break;
		}

		for (i = 0; bciphers[i].cipher; i++) {
			r = benchmark_cipher_loop(bciphers[i].cipher, bciphers[i].mode,
						  bciphers[i].key_size, &enc_mbr, &dec_mbr);
			check_signal(&r);
			if (r == -ENOTSUP || r == -EINTR)
				break;
			if (r == -ENOENT)
				skipped++;
			if (i == 0)
				/* TRANSLATORS: The string is header of a table and must be exactly (right side) aligned. */
				log_std(_("#     Algorithm |       Key |      Encryption |      Decryption\n"));

			if (snprintf(cipher, MAX_CIPHER_LEN, "%s-%s",
				     bciphers[i].cipher, bciphers[i].mode) < 0)
				r = -EINVAL;

			if (!r)
				log_std("%15s  %9zub  %10.1f MiB/s  %10.1f MiB/s\n",
					cipher, bciphers[i].key_size*8, enc_mbr, dec_mbr);
			else
				log_std("%15s  %9zub %17s %17s\n", cipher,
					bciphers[i].key_size*8, _("N/A"), _("N/A"));
		}
		if (skipped && skipped == i)
			r = -ENOTSUP;
	}

	if (r == -ENOTSUP) {
		log_err(_("Required kernel crypto interface not available."));
#if ENABLE_AF_ALG
		log_err( _("Ensure you have algif_skcipher kernel module loaded."));
#endif
	}
	return r;
}

static int reencrypt_metadata_repair(struct crypt_device *cd)
{
	char *password;
	size_t passwordLen;
	int r;
	struct crypt_params_reencrypt params = {
		.flags = CRYPT_REENCRYPT_REPAIR_NEEDED
	};

	if (!ARG_SET(OPT_BATCH_MODE_ID) &&
	    !yesDialog(_("Unprotected LUKS2 reencryption metadata detected. "
			 "Please verify the reencryption operation is desirable (see luksDump output)\n"
			 "and continue (upgrade metadata) only if you acknowledge the operation as genuine."),
		       _("Operation aborted.\n")))
		return -EINVAL;

	r = tools_get_key(_("Enter passphrase to protect and upgrade reencryption metadata: "),
			  &password, &passwordLen, ARG_UINT64(OPT_KEYFILE_OFFSET_ID),
			  ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_TIMEOUT_ID),
			  verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	r = crypt_reencrypt_init_by_passphrase(cd, NULL, password, passwordLen,
			ARG_INT32(OPT_KEY_SLOT_ID), ARG_INT32(OPT_KEY_SLOT_ID), NULL, NULL, &params);
	tools_passphrase_msg(r);
	if (r < 0)
		goto out;

	r = crypt_activate_by_passphrase(cd, NULL, ARG_INT32(OPT_KEY_SLOT_ID),
					 password, passwordLen, 0);
	tools_passphrase_msg(r);
	if (r >= 0)
		r = 0;

out:
	crypt_safe_free(password);
	return r;
}

static int luks2_reencrypt_repair(struct crypt_device *cd)
{
	int r;
	size_t passwordLen;
	const char *msg;
	char *password = NULL;
	struct crypt_params_reencrypt params = {};

	crypt_reencrypt_info ri = crypt_reencrypt_status(cd, &params);

	if (params.flags & CRYPT_REENCRYPT_REPAIR_NEEDED)
		return reencrypt_metadata_repair(cd);

	switch (ri) {
	case CRYPT_REENCRYPT_NONE:
		return 0;
	case CRYPT_REENCRYPT_CLEAN:
		break;
	case CRYPT_REENCRYPT_CRASH:
		if (!ARG_SET(OPT_BATCH_MODE_ID) &&
		    !yesDialog(_("Really proceed with LUKS2 reencryption recovery?"),
			       _("Operation aborted.\n")))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	if (ri == CRYPT_REENCRYPT_CLEAN)
		msg = _("Enter passphrase to verify reencryption metadata digest: ");
	else
		msg = _("Enter passphrase for reencryption recovery: ");

	r = tools_get_key(msg, &password, &passwordLen, ARG_UINT64(OPT_KEYFILE_OFFSET_ID),
			  ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_TIMEOUT_ID),
			  verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	r = crypt_activate_by_passphrase(cd, NULL, ARG_INT32(OPT_KEY_SLOT_ID),
					 password, passwordLen, 0);
	if (r < 0)
		goto out;

	if (ri == CRYPT_REENCRYPT_CLEAN) {
		r = 0;
		goto out;
	}

	r = crypt_reencrypt_init_by_passphrase(cd, NULL, password, passwordLen,
			ARG_INT32(OPT_KEY_SLOT_ID), ARG_INT32(OPT_KEY_SLOT_ID), NULL, NULL,
			&(struct crypt_params_reencrypt){ .flags = CRYPT_REENCRYPT_RECOVERY });
	if (r > 0)
		r = 0;
out:
	crypt_safe_free(password);

	return r;
}

static int action_luksRepair(void)
{
	struct crypt_device *cd = NULL;
	const char *header_device, *data_device = NULL;
	int r;

	header_device = uuid_or_device_header(&data_device);

	if ((r = crypt_init_data_device(&cd, header_device, data_device)))
		goto out;

	crypt_set_log_callback(cd, quiet_log, &log_parms);
	r = crypt_load(cd, luksType(device_type), NULL);
	crypt_set_log_callback(cd, tool_log, &log_parms);
	if (r == 0 && isLUKS2(crypt_get_type(cd))) {
		/*
		 * LUKS2 triggers autorepair in crypt_load() above
		 * LUKS1 need to call crypt_repair() even if crypt_load() is ok
		 */
		log_verbose(_("No known problems detected for LUKS header."));
		goto out;
	}

	if (!ARG_SET(OPT_DISABLE_BLKID_ID)) {
		r = tools_detect_signatures(header_device, PRB_FILTER_LUKS, NULL, ARG_SET(OPT_BATCH_MODE_ID));
		if (r < 0) {
			if (r == -EIO)
				log_err(_("Blkid scan failed for %s."), header_device);
			goto out;
		}
	}

	if (!ARG_SET(OPT_BATCH_MODE_ID) &&
	    !yesDialog(_("Really try to repair LUKS device header?"),
		       _("Operation aborted.\n")))
		r = -EINVAL;
	else
		r = crypt_repair(cd, luksType(device_type), NULL);
out:
	/* Header is ok, check if reencryption metadata needs repair/recovery. */
	if (!r && isLUKS2(crypt_get_type(cd)))
		r = luks2_reencrypt_repair(cd);

	/* Randomness analysis of LUKS keyslot binary data, this is only a hint */
	if (r == 0)
		luks_check_keyslots(cd, header_device);

	crypt_free(cd);
	return r;
}

static int _wipe_data_device(struct crypt_device *cd)
{
	char tmp_name[64], tmp_path[128], tmp_uuid[40];
	uuid_t tmp_uuid_bin;
	int r = -EINVAL;
	char *backing_file = NULL;
	struct tools_progress_params prog_parms = {
		.frequency = ARG_UINT32(OPT_PROGRESS_FREQUENCY_ID),
		.batch_mode = ARG_SET(OPT_BATCH_MODE_ID),
		.json_output = ARG_SET(OPT_PROGRESS_JSON_ID),
		.interrupt_message = _("\nWipe interrupted."),
		.device = tools_get_device_name(crypt_get_device_name(cd), &backing_file)
	};

	if (!ARG_SET(OPT_BATCH_MODE_ID))
		log_std(_("Wiping device to initialize integrity checksum.\n"
			"You can interrupt this by pressing CTRL+c "
			"(rest of not wiped device will contain invalid checksum).\n"));

	/* Activate the device a temporary one */
	uuid_generate(tmp_uuid_bin);
	uuid_unparse(tmp_uuid_bin, tmp_uuid);
	if (snprintf(tmp_name, sizeof(tmp_name), "temporary-cryptsetup-%s", tmp_uuid) < 0)
		goto out;
	if (snprintf(tmp_path, sizeof(tmp_path), "%s/%s", crypt_get_dir(), tmp_name) < 0)
		goto out;

	r = crypt_activate_by_volume_key(cd, tmp_name, NULL, 0,
		CRYPT_ACTIVATE_PRIVATE | CRYPT_ACTIVATE_NO_JOURNAL);
	if (r < 0)
		goto out;

	/* Wipe the device */
	set_int_handler(0);
	r = crypt_wipe(cd, tmp_path, CRYPT_WIPE_ZERO, 0, 0, DEFAULT_WIPE_BLOCK,
		       0, &tools_progress, &prog_parms);
	if (crypt_deactivate(cd, tmp_name))
		log_err(_("Cannot deactivate temporary device %s."), tmp_path);
	set_int_block(0);

out:
	free(backing_file);
	return r;
}

static int strcmp_or_null(const char *str, const char *expected)
{
	return !str ? 0 : strcmp(str, expected);
}

int luksFormat(struct crypt_device **r_cd, struct crypt_keyslot_context **r_kc)
{
	bool wipe_signatures = false;
	int encrypt_type, r = -EINVAL, integrity_keysize = 0, required_integrity_key_size = 0, fd, created = 0;
	struct stat st;
	const char *header_device, *type;
	char *msg = NULL, *key = NULL;
	char cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN], integrity[MAX_CIPHER_LEN];
	size_t keysize, signatures = 0;
	struct crypt_device *cd = NULL;
	struct crypt_params_luks1 params1 = {
		.hash = ARG_STR(OPT_HASH_ID) ?: DEFAULT_LUKS1_HASH,
		.data_alignment = ARG_UINT32(OPT_ALIGN_PAYLOAD_ID),
		.data_device = ARG_SET(OPT_HEADER_ID) ? action_argv[0] : NULL,
	};
	struct crypt_params_luks2 params2 = {
		.data_alignment = params1.data_alignment,
		.data_device = params1.data_device,
		.sector_size = ARG_UINT32(OPT_SECTOR_SIZE_ID),
		.label = ARG_STR(OPT_LABEL_ID),
		.subsystem = ARG_STR(OPT_SUBSYSTEM_ID)
	};
	struct crypt_params_hw_opal opal_params = {
		.user_key_size = DEFAULT_LUKS1_KEYBITS / 8
	};
	struct crypt_params_integrity integrity_params = {};
	void *params;
	struct crypt_keyslot_context *kc = NULL, *new_kc = NULL;

	type = luksType(device_type);
	if (!type)
		type = crypt_get_default_type();

	if (isLUKS2(type)) {
		if (ARG_SET(OPT_HW_OPAL_ONLY_ID) && (ARG_SET(OPT_CIPHER_ID) || ARG_SET(OPT_KEY_SIZE_ID))) {
			log_err(_("OPAL hw-only encryption does not support --cipher and --key-size, options ignored."));
		}

		params = &params2;
	} else if (isLUKS1(type)) {
		params = &params1;

		if (ARG_UINT32(OPT_SECTOR_SIZE_ID) > SECTOR_SIZE) {
			log_err(_("Unsupported encryption sector size."));
			return -EINVAL;
		}

		if (ARG_SET(OPT_INTEGRITY_ID)) {
			log_err(_("Integrity option can be used only for LUKS2 format."));
			return -EINVAL;
		}

		if (ARG_SET(OPT_LUKS2_KEYSLOTS_SIZE_ID) || ARG_SET(OPT_LUKS2_METADATA_SIZE_ID)) {
			log_err(_("Unsupported LUKS2 metadata size options."));
			return -EINVAL;
		}

		if (ARG_SET(OPT_HW_OPAL_ID) || ARG_SET(OPT_HW_OPAL_ONLY_ID)) {
			log_err(_("OPAL is supported only for LUKS2 format."));
			return -EINVAL;
		}

		if (ARG_SET(OPT_INTEGRITY_INLINE_ID)) {
			log_err(_("Inline hw tags are supported only for LUKS2 format."));
			return -EINVAL;
		}
	} else
		return -EINVAL;

	/* Create header file (must contain at least one sector)? */
	if (ARG_SET(OPT_HEADER_ID) && stat(ARG_STR(OPT_HEADER_ID), &st) < 0 && errno == ENOENT) {
		if (!ARG_SET(OPT_BATCH_MODE_ID) &&
		    !yesDialog(_("Header file does not exist, do you want to create it?"),
			       _("Operation aborted.\n")))
		    return -EPERM;

		log_dbg("Creating header file.");
		/* coverity[toctou] */
		fd = open(ARG_STR(OPT_HEADER_ID), O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
		if (fd == -1 || posix_fallocate(fd, 0, 4096))
			log_err(_("Cannot create header file %s."), ARG_STR(OPT_HEADER_ID));
		else {
			r = 0;
			created = 1;
		}
		if (fd != -1)
			close(fd);
		if (r < 0)
			return r;
	}

	header_device = ARG_STR(OPT_HEADER_ID) ?: action_argv[0];

	r = crypt_parse_name_and_mode(ARG_STR(OPT_CIPHER_ID) ?: DEFAULT_CIPHER(LUKS1),
				      cipher, NULL, cipher_mode);
	if (r < 0) {
		log_err(_("No known cipher specification pattern detected."));
		goto out;
	}

	if (ARG_SET(OPT_INTEGRITY_ID)) {
		if (ARG_SET(OPT_INTEGRITY_KEY_SIZE_ID))
			required_integrity_key_size = ARG_UINT32(OPT_INTEGRITY_KEY_SIZE_ID) / 8;
		r = crypt_parse_integrity_mode(ARG_STR(OPT_INTEGRITY_ID), integrity,
					       &integrity_keysize, required_integrity_key_size);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			if (ARG_SET(OPT_INTEGRITY_KEY_SIZE_ID) && required_integrity_key_size != integrity_keysize)
				log_err(_("Cannot use specified integrity key size."));
			goto out;
		}

		params2.integrity = integrity;
		/* FIXME: we use default integrity_params except key size */
		if (required_integrity_key_size) {
			params2.integrity_params = &integrity_params;
			integrity_params.integrity_key_size = integrity_keysize;
		}
	}

	/* Never call pwquality if using null cipher */
	if (crypt_is_cipher_null(cipher))
		ARG_SET_TRUE(OPT_FORCE_PASSWORD_ID);

	if ((r = crypt_init(&cd, header_device))) {
		if (ARG_SET(OPT_HEADER_ID))
			log_err(_("Cannot use %s as on-disk header."), header_device);
		return r;
	}

	if (ARG_SET(OPT_LUKS2_KEYSLOTS_SIZE_ID) || ARG_SET(OPT_LUKS2_METADATA_SIZE_ID)) {
		r = crypt_set_metadata_size(cd, ARG_UINT64(OPT_LUKS2_METADATA_SIZE_ID), ARG_UINT64(OPT_LUKS2_KEYSLOTS_SIZE_ID));
		if (r < 0) {
			log_err(_("Unsupported LUKS2 metadata size options."));
			goto out;
		}
	}

	if (ARG_SET(OPT_OFFSET_ID)) {
		r = crypt_set_data_offset(cd, ARG_UINT64(OPT_OFFSET_ID));
		if (r < 0)
			goto out;
	}

	/* Print all present signatures in read-only mode */
	if (!ARG_SET(OPT_DISABLE_BLKID_ID)) {
		r = tools_detect_signatures(header_device, PRB_FILTER_NONE, &signatures, ARG_SET(OPT_BATCH_MODE_ID));
		if (r < 0) {
			if (r == -EIO)
				log_err(_("Blkid scan failed for %s."), header_device);
			goto out;
		}
	}

	if (!created && !ARG_SET(OPT_BATCH_MODE_ID)) {
		r = asprintf(&msg, _("This will overwrite data on %s irrevocably."), header_device);
		if (r == -1) {
			r = -ENOMEM;
			goto out;
		}

		r = yesDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
		free(msg);
		if (r < 0)
			goto out;
	}

	keysize = get_adjusted_key_size(cipher, cipher_mode, ARG_UINT32(OPT_KEY_SIZE_ID),
					DEFAULT_LUKS1_KEYBITS, integrity_keysize);

	if (ARG_SET(OPT_HW_OPAL_ONLY_ID))
		keysize = opal_params.user_key_size;
	else if (ARG_SET(OPT_HW_OPAL_ID))
		keysize += opal_params.user_key_size;

	if (ARG_SET(OPT_USE_RANDOM_ID))
		crypt_set_rng_type(cd, CRYPT_RNG_RANDOM);
	else if (ARG_SET(OPT_USE_URANDOM_ID))
		crypt_set_rng_type(cd, CRYPT_RNG_URANDOM);

	r = luks_init_keyslot_context(cd, NULL, verify_passphrase(1),
				      !ARG_SET(OPT_FORCE_PASSWORD_ID), &new_kc);
	if (r < 0)
		goto out;

	if (ARG_SET(OPT_HW_OPAL_ID) || ARG_SET(OPT_HW_OPAL_ONLY_ID)) {
		r = tools_get_key("Enter OPAL Admin password: ", CONST_CAST(char **)&opal_params.admin_key, &opal_params.admin_key_size,
				  0, 0, NULL,
				  ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(1), !ARG_SET(OPT_FORCE_PASSWORD_ID), cd);
		if (r < 0)
			goto out;
		if (opal_params.admin_key_size == 0) {
			log_err(_("OPAL Admin password cannot be empty."));
			r = -EPERM;
			goto out;
		}
	}

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		r = tools_read_vk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), &key, keysize);
		if (r < 0)
			goto out;
	}

	r = set_pbkdf_params(cd, type);
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	/* Signature candidates found */
	if (!ARG_SET(OPT_DISABLE_BLKID_ID) && signatures &&
	    ((r = tools_wipe_all_signatures(header_device, true, false)) < 0))
		goto out;

	if (ARG_SET(OPT_INTEGRITY_LEGACY_PADDING_ID))
		crypt_set_compatibility(cd, CRYPT_COMPAT_LEGACY_INTEGRITY_PADDING);

	if (ARG_SET(OPT_HW_OPAL_ID) || ARG_SET(OPT_HW_OPAL_ONLY_ID))
		r = crypt_format_luks2_opal(cd,
			 ARG_SET(OPT_HW_OPAL_ONLY_ID) ? NULL : cipher,
			 ARG_SET(OPT_HW_OPAL_ONLY_ID) ? NULL : cipher_mode,
			 ARG_STR(OPT_UUID_ID), key, keysize, params, &opal_params);
	else if (ARG_SET(OPT_INTEGRITY_INLINE_ID))
		r = crypt_format_inline(cd, type, cipher, cipher_mode,
			 ARG_STR(OPT_UUID_ID), key, keysize, params);
	else
		r = crypt_format(cd, type, cipher, cipher_mode,
			 ARG_STR(OPT_UUID_ID), key, keysize, params);
	check_signal(&r);
	if (r < 0)
		goto out;

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	if (!key && r_kc) {
		key = crypt_safe_alloc(keysize);
		if (!key) {
			r = -ENOMEM;
			goto out;
		}
		/* Extract VK for LUKS2 encryption later */
		r = crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, key, &keysize, NULL);
		if (r < 0)
			goto out;
	}

	r = crypt_keyslot_context_init_by_volume_key(cd, key, keysize, &kc);
	if (r < 0)
		goto out;

	crypt_safe_free(key);
	key = NULL;

	r = crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, kc,
						 ARG_INT32(OPT_KEY_SLOT_ID), new_kc, 0);
	if (r < 0) {
		wipe_signatures = true;
		goto out;
	}
	tools_keyslot_msg(r, CREATED);

	if (ARG_SET(OPT_INTEGRITY_ID) && !ARG_SET(OPT_INTEGRITY_NO_WIPE_ID) &&
	    strcmp_or_null(params2.integrity, "none")) {
		r = _wipe_data_device(cd);
		/* Interrupted wipe should not fail luksFormat action */
		if (r == -EINTR)
			r = 0;
	}
out:
	crypt_safe_free(key);
	crypt_keyslot_context_free(new_kc);

	if (r < 0) {
		encrypt_type = crypt_get_hw_encryption_type(cd);
		if (encrypt_type == CRYPT_OPAL_HW_ONLY ||
		    encrypt_type == CRYPT_SW_AND_OPAL_HW) {
			(void) crypt_wipe_hw_opal(cd, CRYPT_LUKS2_SEGMENT,
				opal_params.admin_key, opal_params.admin_key_size,
				0);
		}
		if (wipe_signatures)
			(void) tools_wipe_all_signatures(header_device, true, false);
	}

	crypt_safe_free(CONST_CAST(void *)opal_params.admin_key);

	if (r >= 0 && r_cd && r_kc) {
		*r_cd = cd;
		*r_kc = kc;
		return r;
	}

	crypt_keyslot_context_free(kc);
	crypt_free(cd);

	return r;
}

static int action_luksFormat(void)
{
	return luksFormat(NULL, NULL);
}

static int action_open_luks(void)
{
	struct crypt_active_device cad;
	struct crypt_device *cd = NULL;
	const char *data_device, *header_device, *activated_name;
	uint32_t activate_flags = 0;
	int r, tries, keysize = 0;
	struct stat st;
	struct crypt_keyslot_context *kc1 = NULL, *kc2 = NULL;

	if (ARG_SET(OPT_REFRESH_ID)) {
		activated_name = action_argc > 1 ? action_argv[1] : action_argv[0];
		r = crypt_init_by_name_and_header(&cd, activated_name, ARG_STR(OPT_HEADER_ID));
		if (r)
			goto out;
		activate_flags |= CRYPT_ACTIVATE_REFRESH;
	} else {
		header_device = uuid_or_device_header(&data_device);

		activated_name = ARG_SET(OPT_TEST_PASSPHRASE_ID) ? NULL : action_argv[1];

		if ((r = crypt_init_data_device(&cd, header_device, data_device)))
			goto out;

		if ((r = crypt_load(cd, luksType(device_type), NULL))) {
			log_err(_("Device %s is not a valid LUKS device."),
				header_device);
			goto out;
		}

		if (!data_device && (crypt_get_data_offset(cd) < 8) && !ARG_SET(OPT_TEST_PASSPHRASE_ID)) {
			log_err(_("Reduced data offset is allowed only for detached LUKS header."));
			r = -EINVAL;
			goto out;
		}

		if (activated_name && !stat(crypt_get_device_name(cd), &st) && S_ISREG(st.st_mode) &&
		    crypt_get_data_offset(cd) >= ((uint64_t)st.st_size / SECTOR_SIZE)) {
			log_err(_("LUKS file container %s is too small for activation, there is no remaining space for data."),
				  crypt_get_device_name(cd));
			r = -EINVAL;
			goto out;
		}
	}

	if ((r = tools_check_newname(activated_name)))
		goto out;

	set_activation_flags(&activate_flags);

	if (ARG_SET(OPT_EXTERNAL_TOKENS_PATH_ID)) {
		r = crypt_token_set_external_path(ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
		if (r < 0) {
			log_err(_("Failed to set external tokens path %s."),
				ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
			goto out;
		}
	}

	if (ARG_SET(OPT_LINK_VK_TO_KEYRING_ID)) {
		r = tools_parse_vk_and_keyring_description(cd, keyring_links, keyring_links_count);
		if (r < 0)
			goto out;
	}

	/*
	 * When activating device in-reencryption with --volume-key-file or --volume-key-keyring
	 * the ordering of parameters does not matter. This applies also if any parameter is used
	 * twice. The library internal code tests both passed keys if they match old or new
	 * volume key digests and assign them respectively.
	 */
	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID) || ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
		if (vk_files[0] && !vk_files[1]) {
			keysize = key_sizes[0] / 8;
			if (!keysize)
				keysize = crypt_get_volume_key_size(cd);
			if (!keysize) /* only in LUKS2 decryption or with no keyslots */
				keysize = crypt_get_old_volume_key_size(cd);

			if (!keysize) {
				log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --key-size option."));
				r = -EINVAL;
				goto out;
			}
		} else if (vk_files[0] && vk_files[1])
			keysize = key_sizes[0] / 8;

		r = luks_init_keyslot_contexts_by_volume_keys(cd, vk_files[0], vk_files[1],
							      keysize, key_sizes[1] / 8,
							      vks_in_keyring[0],
							      vks_in_keyring[1],
							      &kc1, &kc2);
		if (r < 0)
			goto out;

		/* The ordering of kc1 or kc2 does not matter */
		r = crypt_activate_by_keyslot_context(cd, activated_name, CRYPT_ANY_SLOT,
						      kc1, CRYPT_ANY_SLOT, kc2, activate_flags);
		if (r == -ESRCH)
			log_err(_("Device requires two volume keys."));
		if (r == -EPERM)
			log_err(_("Volume key does not match the volume."));
	} else {
		r = luks_try_token_unlock(cd, ARG_INT32(OPT_KEY_SLOT_ID),
					  ARG_INT32(OPT_TOKEN_ID_ID), activated_name,
					  ARG_STR(OPT_TOKEN_TYPE_ID), activate_flags,
					  set_tries_tty(false), true,
					  ARG_SET(OPT_TOKEN_ONLY_ID) || ARG_SET(OPT_TOKEN_ID_ID) || ARG_SET(OPT_TOKEN_TYPE_ID),
					  NULL);

		if (r >= 0 || r == -EEXIST || quit || ARG_SET(OPT_TOKEN_ONLY_ID))
			goto out;

		tries = set_tries_tty(true);
		do {
			crypt_keyslot_context_free(kc1);
			kc1 = NULL;
			r = luks_init_keyslot_context(cd, NULL, verify_passphrase(0), false, &kc1);
			if (r < 0)
				goto out;

			r = crypt_activate_by_keyslot_context(cd, activated_name, ARG_INT32(OPT_KEY_SLOT_ID),
							      kc1, CRYPT_ANY_SLOT, kc1, activate_flags);

			tools_keyslot_msg(r, UNLOCKED);
			tools_passphrase_msg(r);
			check_signal(&r);
		} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
	}
out:
	if (r >= 0 && activated_name && activate_flags & (CRYPT_ACTIVATE_ALLOW_DISCARDS |
	    CRYPT_ACTIVATE_SAME_CPU_CRYPT | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS|
	    CRYPT_ACTIVATE_NO_READ_WORKQUEUE | CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE|
	    CRYPT_ACTIVATE_HIGH_PRIORITY) && crypt_get_hw_encryption_type(cd) == CRYPT_OPAL_HW_ONLY)
		log_err(_("Some specified activation parameters were ignored with OPAL hw-only encryption."));

	if (r >= 0 && ARG_SET(OPT_PERSISTENT_ID) &&
	    (crypt_get_active_device(cd, activated_name, &cad) ||
	     crypt_persistent_flags_set(cd, CRYPT_FLAGS_ACTIVATION, cad.flags & activate_flags)))
		log_err(_("Device activated but cannot make flags persistent."));

	crypt_keyslot_context_free(kc1);
	crypt_keyslot_context_free(kc2);
	crypt_free(cd);

	return r;
}

static int verify_keyslot(struct crypt_device *cd, int key_slot, crypt_keyslot_info ki,
			  char *msg_last, char *msg_pass, char *msg_fail,
			  const char *key_file, uint64_t keyfile_offset,
			  int keyfile_size)
{
	char *password = NULL;
	size_t passwordLen;
	int i, max, r;

	if (ki == CRYPT_SLOT_ACTIVE_LAST && !ARG_SET(OPT_BATCH_MODE_ID) && !key_file &&
	    msg_last && !ARG_SET(OPT_BATCH_MODE_ID) && !yesDialog(msg_last, msg_fail))
		return -EPERM;

	r = tools_get_key(msg_pass, &password, &passwordLen,
			  keyfile_offset, keyfile_size, key_file, ARG_UINT32(OPT_TIMEOUT_ID),
			  verify_passphrase(0), 0, cd);
	if (r < 0)
		goto out;

	if (ki == CRYPT_SLOT_ACTIVE_LAST) {
		/* check the last keyslot */
		r = crypt_activate_by_passphrase(cd, NULL, key_slot,
						 password, passwordLen, 0);
	} else {
		/* try all other keyslots */
		r = crypt_keyslot_max(crypt_get_type(cd));
		if (r < 0)
			goto out;
		max = r;

		for (i = 0; i < max ; i++) {
			if (i == key_slot)
				continue;
			ki = crypt_keyslot_status(cd, i);
			if (ki == CRYPT_SLOT_ACTIVE || ki == CRYPT_SLOT_ACTIVE_LAST)
				r = crypt_activate_by_passphrase(cd, NULL, i,
						 password, passwordLen, 0);
			if (r == i)
				break;
		}
	}

	/* Handle inactive keyslots the same as bad password here */
	if (r == -ENOENT)
		r = -EPERM;
	tools_passphrase_msg(r);
out:
	crypt_safe_free(password);
	return r;
}

static int action_luksKillSlot(void)
{
	struct crypt_device *cd = NULL;
	crypt_keyslot_info ki;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if ((r = crypt_load(cd, luksType(device_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	ki = crypt_keyslot_status(cd, ARG_INT32(OPT_KEY_SLOT_ID));
	switch (ki) {
	case CRYPT_SLOT_ACTIVE_LAST:
	case CRYPT_SLOT_ACTIVE:
	case CRYPT_SLOT_UNBOUND:
		log_verbose(_("Keyslot %d is selected for deletion."), ARG_INT32(OPT_KEY_SLOT_ID));
		break;
	case CRYPT_SLOT_INACTIVE:
		log_err(_("Keyslot %d is not active."), ARG_INT32(OPT_KEY_SLOT_ID));
		/* fall through */
	case CRYPT_SLOT_INVALID:
		r = -EINVAL;
		goto out;
	}

	if (!ARG_SET(OPT_BATCH_MODE_ID) || ARG_SET(OPT_KEY_FILE_ID) || !isatty(STDIN_FILENO)) {
		r = verify_keyslot(cd, ARG_INT32(OPT_KEY_SLOT_ID), ki,
			_("This is the last keyslot. Device will become unusable after purging this key."),
			_("Enter any remaining passphrase: "),
			_("Operation aborted, the keyslot was NOT wiped.\n"),
			ARG_STR(OPT_KEY_FILE_ID), ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID));
		tools_keyslot_msg(r, UNLOCKED);

		if (r == -EPIPE && (!ARG_SET(OPT_KEY_FILE_ID) || tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID)))) {
			log_dbg("Failed read from input, ignoring passphrase.");
			r = 0;
		}

		if (r < 0)
			goto out;
	}

	r = crypt_keyslot_destroy(cd, ARG_INT32(OPT_KEY_SLOT_ID));
	tools_keyslot_msg(ARG_INT32(OPT_KEY_SLOT_ID), REMOVED);
out:
	crypt_free(cd);
	return r;
}

static int action_luksRemoveKey(void)
{
	struct crypt_device *cd = NULL;
	char *password = NULL;
	size_t passwordLen;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if ((r = crypt_load(cd, luksType(device_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	r = tools_get_key(_("Enter passphrase to be deleted: "),
		      &password, &passwordLen,
		      ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
		      ARG_UINT32(OPT_TIMEOUT_ID),
		      verify_passphrase(0), 0,
		      cd);
	if(r < 0)
		goto out;

	r = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT,
					 password, passwordLen, 0);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	ARG_SET_INT32(OPT_KEY_SLOT_ID, r);
	log_verbose(_("Keyslot %d is selected for deletion."), ARG_INT32(OPT_KEY_SLOT_ID));

	if (crypt_keyslot_status(cd, ARG_INT32(OPT_KEY_SLOT_ID)) == CRYPT_SLOT_ACTIVE_LAST &&
	    !ARG_SET(OPT_BATCH_MODE_ID) &&
	    !yesDialog(_("This is the last keyslot. "
			 "Device will become unusable after purging this key."),
		       _("Operation aborted, the keyslot was NOT wiped.\n"))) {
		r = -EPERM;
		goto out;
	}

	r = crypt_keyslot_destroy(cd, ARG_INT32(OPT_KEY_SLOT_ID));
	tools_keyslot_msg(ARG_INT32(OPT_KEY_SLOT_ID), REMOVED);
out:
	crypt_safe_free(password);
	crypt_free(cd);
	return r;
}

static int luksAddUnboundKey(void)
{
	int r = -EINVAL, keysize = 0;
	char *key = NULL;
	const char *new_key_file = (action_argc > 1 ? action_argv[1] : NULL);
	char *password_new = NULL;
	size_t password_new_size = 0;
	struct crypt_device *cd = NULL;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL))) {
		log_err(_("Device %s is not a valid LUKS2 device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	if (ARG_SET(OPT_EXTERNAL_TOKENS_PATH_ID)) {
		r = crypt_token_set_external_path(ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
		if (r < 0) {
			log_err(_("Failed to set external tokens path %s."),
				ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
			goto out;
		}
	}

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	/* Never call pwquality if using null cipher */
	if (crypt_is_cipher_null(crypt_get_cipher(cd)))
		ARG_SET_TRUE(OPT_FORCE_PASSWORD_ID);

	keysize = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;
	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		r = tools_read_vk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), &key, keysize);
		if (r < 0)
			goto out;

		check_signal(&r);
		if (r < 0)
			goto out;
	}

	r = tools_get_key(_("Enter new passphrase for key slot: "),
			  &password_new, &password_new_size,
			  ARG_UINT64(OPT_NEW_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_NEW_KEYFILE_SIZE_ID),
			  new_key_file, ARG_UINT32(OPT_TIMEOUT_ID),
			  verify_passphrase(1), !ARG_SET(OPT_FORCE_PASSWORD_ID), cd);
	if (r < 0)
		goto out;

	r = crypt_keyslot_add_by_key(cd, ARG_INT32(OPT_KEY_SLOT_ID), key, keysize,
			password_new, password_new_size, CRYPT_VOLUME_KEY_NO_SEGMENT);
	tools_keyslot_msg(r, CREATED);
out:
	crypt_safe_free(password_new);
	crypt_safe_free(key);
	crypt_free(cd);
	return r;
}

static int _ask_for_pin(struct crypt_device *cd,
	int token_id,
	struct crypt_keyslot_context *kc)
{
	char *pin;
	size_t pin_size;
	int r;
	char msg[64];

	assert(kc);
	assert(token_id >= 0 || token_id == CRYPT_ANY_TOKEN);

	if (crypt_keyslot_context_get_type(kc) != CRYPT_KC_TYPE_TOKEN)
		return -EINVAL;

	if (token_id == CRYPT_ANY_TOKEN)
		r = snprintf(msg, sizeof(msg), _("Enter token PIN: "));
	else
		r = snprintf(msg, sizeof(msg), _("Enter token %d PIN: "), token_id);
	if (r < 0 || (size_t)r >= sizeof(msg))
		return -EINVAL;

	r = tools_get_key(msg, &pin, &pin_size, 0, 0, NULL,
			ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	r = crypt_keyslot_context_set_pin(cd, pin, pin_size, kc);
	crypt_safe_free(pin);
	return r;
}

static int try_keyslot_add(struct crypt_device *cd,
	int keyslot_existing,
	int keyslot_new,
	struct crypt_keyslot_context *kc,
	struct crypt_keyslot_context *kc_new,
	bool pin_provided,
	bool new_pin_provided)
{
	int r;

	r = crypt_keyslot_add_by_keyslot_context(cd, keyslot_existing, kc, keyslot_new, kc_new, 0);
	if (crypt_keyslot_context_get_type(kc) == CRYPT_KC_TYPE_TOKEN)
		tools_token_error_msg(crypt_keyslot_context_get_error(kc), ARG_STR(OPT_TOKEN_TYPE_ID),
				      ARG_INT32(OPT_TOKEN_ID_ID), pin_provided);
	if (crypt_keyslot_context_get_type(kc_new) == CRYPT_KC_TYPE_TOKEN)
		tools_token_error_msg(crypt_keyslot_context_get_error(kc_new), NULL,
				      ARG_INT32(OPT_NEW_TOKEN_ID_ID), new_pin_provided);
	return r;
}

static int action_luksAddKey(void)
{
	bool pin_provided = false;
	int keyslot_old, keyslot_new, keysize = 0, r = -EINVAL;
	char *key, *vk_description;
	struct crypt_device *cd = NULL;
	struct crypt_keyslot_context *p_kc_new = NULL, *kc = NULL, *kc_new = NULL;

	/* Unbound keyslot (no assigned data segment) is special case */
	if (ARG_SET(OPT_UNBOUND_ID))
		return luksAddUnboundKey();

	/* maintain backward compatibility of luksAddKey action positional parameter */
	if (action_argc > 1)
		ARG_SET_STR(OPT_NEW_KEYFILE_ID, strdup(action_argv[1]));

	keyslot_old = ARG_INT32(OPT_KEY_SLOT_ID);
	keyslot_new = ARG_INT32(OPT_NEW_KEY_SLOT_ID);

	/*
	 * maintain backward compatibility of --key-slot/-S as 'new keyslot number'
	 * unless --new-key-slot is used.
	 */
	if (!ARG_SET(OPT_NEW_KEY_SLOT_ID) && ARG_SET(OPT_KEY_SLOT_ID)) {
		if (!ARG_SET(OPT_BATCH_MODE_ID))
			log_std(_("WARNING: The --key-slot parameter is used for new keyslot number.\n"));
		keyslot_old = CRYPT_ANY_SLOT;
		keyslot_new = ARG_INT32(OPT_KEY_SLOT_ID);
	}

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if ((r = crypt_load(cd, luksType(device_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	if (ARG_SET(OPT_EXTERNAL_TOKENS_PATH_ID)) {
		r = crypt_token_set_external_path(ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
		if (r < 0) {
			log_err(_("Failed to set external tokens path %s."),
				ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
			goto out;
		}
	}

	/* Never call pwquality if using null cipher */
	if (crypt_is_cipher_null(crypt_get_cipher(cd)))
		ARG_SET_TRUE(OPT_FORCE_PASSWORD_ID);

	keysize = crypt_get_volume_key_size(cd);
	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		if (!keysize && !ARG_SET(OPT_KEY_SIZE_ID)) {
			log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --key-size option."));
			r = -EINVAL;
			goto out;
		} else if (!keysize)
			keysize = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;

		r = tools_read_vk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), &key, keysize);
		if (r < 0)
			goto out;

		r = crypt_volume_key_verify(cd, key, keysize);
		if (r == -EPERM)
			log_err(_("Volume key does not match the volume."));
		check_signal(&r);
		if (r < 0) {
			crypt_safe_free(key);
			goto out;
		}
		r = crypt_keyslot_context_init_by_volume_key(cd, key, keysize, &kc);
		crypt_safe_free(key);
	} else if (ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
		r = tools_parse_vk_description(ARG_STR(OPT_VOLUME_KEY_KEYRING_ID), &vk_description);
		if (r < 0)
			goto out;
		r = crypt_keyslot_context_init_by_vk_in_keyring(cd, vk_description, &kc);
		free(vk_description);
		if (r < 0)
			goto out;
		r = crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0);
		if (r == -EPERM)
			log_err(_("Volume key does not match the volume."));
	} else if (ARG_SET(OPT_TOKEN_ID_ID) || ARG_SET(OPT_TOKEN_TYPE_ID) || ARG_SET(OPT_TOKEN_ONLY_ID)) {
		r = crypt_keyslot_context_init_by_token(cd,
				ARG_INT32(OPT_TOKEN_ID_ID),
				ARG_STR(OPT_TOKEN_TYPE_ID),
				NULL, 0, NULL, &kc);
	} else {
		r = luks_init_keyslot_context(cd, _("Enter any existing passphrase: "),
					      verify_passphrase(0), false, &kc);
		if (r < 0)
			goto out;

		/* Check password before asking for new one */
		r = crypt_activate_by_keyslot_context(cd, NULL, keyslot_old, kc, CRYPT_ANY_SLOT, NULL, 0);
		check_signal(&r);
		tools_passphrase_msg(r);
		if (r < 0)
			goto out;
		tools_keyslot_msg(r, UNLOCKED);
	}

	if (r < 0)
		goto out;

	if (ARG_SET(OPT_NEW_TOKEN_ID_ID)) {
		if (ARG_INT32(OPT_NEW_TOKEN_ID_ID) == ARG_INT32(OPT_TOKEN_ID_ID))
			p_kc_new = kc;
		else {
			r = crypt_keyslot_context_init_by_token(cd,
					ARG_INT32(OPT_NEW_TOKEN_ID_ID),
					NULL, NULL, 0, NULL, &kc_new);
			p_kc_new = kc_new;
		}
	} else
		r = init_new_keyslot_context(cd, _("Enter new passphrase for key slot: "),
					 verify_passphrase(1), !ARG_SET(OPT_FORCE_PASSWORD_ID), &kc_new);
	if (r < 0)
		goto out;

	if (!p_kc_new)
		p_kc_new = kc_new;

	r = try_keyslot_add(cd, keyslot_old, keyslot_new, kc, p_kc_new, false, false);
	if (r >= 0 || r != -ENOANO)
		goto out;

	if (crypt_keyslot_context_get_error(kc) == -ENOANO) {
		r = _ask_for_pin(cd, ARG_INT32(OPT_TOKEN_ID_ID), kc);
		if (r < 0)
			goto out;

		pin_provided = true;

		r = try_keyslot_add(cd, keyslot_old, keyslot_new, kc, p_kc_new, pin_provided, false);
		if (r >= 0 || r != -ENOANO)
			goto out;
	}

	if (crypt_keyslot_context_get_error(p_kc_new) == -ENOANO) {
		r = _ask_for_pin(cd, ARG_INT32(OPT_NEW_TOKEN_ID_ID), p_kc_new);
		if (r < 0)
			goto out;
		r = try_keyslot_add(cd, keyslot_old, keyslot_new, kc, p_kc_new, pin_provided, true);
	}
out:
	tools_keyslot_msg(r, CREATED);
	crypt_keyslot_context_free(kc);
	crypt_keyslot_context_free(kc_new);
	crypt_free(cd);
	return r;
}

static int action_luksChangeKey(void)
{
	const char *new_key_file = (action_argc > 1 ? action_argv[1] : NULL);
	struct crypt_device *cd = NULL;
	char *password = NULL, *password_new = NULL;
	size_t password_size = 0, password_new_size = 0;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if ((r = crypt_load(cd, luksType(device_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	/* Never call pwquality if using null cipher */
	if (crypt_is_cipher_null(crypt_get_cipher(cd)))
		ARG_SET_TRUE(OPT_FORCE_PASSWORD_ID);

	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	r = tools_get_key(_("Enter passphrase to be changed: "),
		      &password, &password_size,
		      ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
		      ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(0), 0, cd);
	if (r < 0)
		goto out;

	/* Check password before asking for new one */
	r = crypt_activate_by_passphrase(cd, NULL, ARG_INT32(OPT_KEY_SLOT_ID),
					 password, password_size, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	r = tools_get_key(_("Enter new passphrase: "),
			  &password_new, &password_new_size,
			  ARG_UINT64(OPT_NEW_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_NEW_KEYFILE_SIZE_ID),
			  new_key_file,
			  ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(1), !ARG_SET(OPT_FORCE_PASSWORD_ID), cd);
	if (r < 0)
		goto out;

	r = crypt_keyslot_change_by_passphrase(cd, ARG_INT32(OPT_KEY_SLOT_ID), ARG_INT32(OPT_KEY_SLOT_ID),
		password, password_size, password_new, password_new_size);
	tools_keyslot_msg(r, CREATED);
out:
	crypt_safe_free(password);
	crypt_safe_free(password_new);
	crypt_free(cd);
	return r;
}

static int action_luksConvertKey(void)
{
	struct crypt_device *cd = NULL;
	char *password = NULL;
	size_t password_size = 0;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL))) {
		log_err(_("Device %s is not a valid LUKS2 device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	if (crypt_keyslot_status(cd, ARG_INT32(OPT_KEY_SLOT_ID)) == CRYPT_SLOT_INACTIVE) {
		r = -EINVAL;
		log_err(_("Keyslot %d is not active."), ARG_INT32(OPT_KEY_SLOT_ID));
		goto out;
	}

	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	r = tools_get_key(_("Enter passphrase for keyslot to be converted: "),
		      &password, &password_size,
		      ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
		      ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(0), 0, cd);
	if (r < 0)
		goto out;

	r = crypt_keyslot_change_by_passphrase(cd, ARG_INT32(OPT_KEY_SLOT_ID), ARG_INT32(OPT_KEY_SLOT_ID),
			password, password_size, password, password_size);
	tools_passphrase_msg(r);
	tools_keyslot_msg(r, CREATED);
out:
	crypt_safe_free(password);
	crypt_free(cd);
	return r;
}

static int action_isLuks(void)
{
	struct crypt_device *cd = NULL;
	int r;

	/* FIXME: argc > max should be checked for other operations as well */
	if (action_argc > 1) {
		log_err(_("Only one device argument for isLuks operation is supported."));
		return -ENODEV;
	}

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	crypt_set_log_callback(cd, quiet_log, &log_parms);
	r = crypt_load(cd, luksType(device_type), NULL);
out:
	crypt_free(cd);
	return r;
}

static int action_luksUUID(void)
{
	struct crypt_device *cd = NULL;
	const char *existing_uuid = NULL;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if (!ARG_SET(OPT_BATCH_MODE_ID))
		crypt_set_confirm_callback(cd, yesDialog, _("Operation aborted.\n"));

	if ((r = crypt_load(cd, luksType(device_type), NULL)))
		goto out;

	if (ARG_SET(OPT_UUID_ID))
		r = crypt_set_uuid(cd, ARG_STR(OPT_UUID_ID));
	else {
		existing_uuid = crypt_get_uuid(cd);
		log_std("%s\n", existing_uuid ?: "");
		r = existing_uuid ? 0 : 1;
	}
out:
	crypt_free(cd);
	return r;
}

static int luksDump_with_volume_key(struct crypt_device *cd)
{
	char *vk = NULL;
	struct crypt_keyslot_context *kc = NULL;
	size_t vk_size;
	int r;

	if (!ARG_SET(OPT_BATCH_MODE_ID) && !yesDialog(
	    _("The header dump with volume key is sensitive information\n"
	      "that allows access to encrypted partition without a passphrase.\n"
	      "This dump should be stored encrypted in a safe place."),
	      NULL))
		return -EPERM;

	vk_size = crypt_get_volume_key_size(cd);
	vk = crypt_safe_alloc(vk_size);
	if (!vk)
		return -ENOMEM;

	r = luks_init_keyslot_context(cd, NULL, false, false, &kc);
	if (r < 0)
		goto out;

	r = crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, vk, &vk_size, kc);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		r = tools_write_mk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), vk, vk_size);
		if (r < 0)
			goto out;
	}

	log_std("LUKS header information for %s\n", crypt_get_device_name(cd));
	log_std("Cipher name:   \t%s\n", crypt_get_cipher(cd));
	log_std("Cipher mode:   \t%s\n", crypt_get_cipher_mode(cd));
	log_std("Payload offset:\t%d\n", (int)crypt_get_data_offset(cd));
	log_std("UUID:          \t%s\n", crypt_get_uuid(cd));
	log_std("MK bits:       \t%d\n", (int)vk_size * 8);
	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		log_std("Key stored to file %s.\n", ARG_STR(OPT_VOLUME_KEY_FILE_ID));
		goto out;
	}
	log_std("MK dump:\t");
	crypt_log_hex(NULL, vk, vk_size, " ", 16, "\n\t\t");
	log_std("\n");
out:
	crypt_keyslot_context_free(kc);
	crypt_safe_free(vk);
	return r;
}

static int luksDump_with_unbound_key(struct crypt_device *cd)
{
	crypt_keyslot_info ki;
	char *uk = NULL, *password = NULL;
	size_t uk_size, passwordLen = 0;
	int r;

	ki = crypt_keyslot_status(cd, ARG_INT32(OPT_KEY_SLOT_ID));
	if (ki != CRYPT_SLOT_UNBOUND) {
		log_err(_("Keyslot %d does not contain unbound key."), ARG_INT32(OPT_KEY_SLOT_ID));
		return -EINVAL;
	}

	if (!ARG_SET(OPT_BATCH_MODE_ID) && !yesDialog(
	    _("The header dump with unbound key is sensitive information.\n"
	      "This dump should be stored encrypted in a safe place."),
	      NULL))
		return -EPERM;

	r = crypt_keyslot_get_key_size(cd, ARG_INT32(OPT_KEY_SLOT_ID));
	if (r < 0)
		return -EINVAL;
	uk_size = r;
	uk = crypt_safe_alloc(uk_size);
	if (!uk)
		return -ENOMEM;

	r = tools_get_key(NULL, &password, &passwordLen,
			  ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			  ARG_UINT32(OPT_TIMEOUT_ID), 0, 0, cd);
	if (r < 0)
		goto out;

	r = crypt_volume_key_get(cd, ARG_INT32(OPT_KEY_SLOT_ID), uk, &uk_size,
				 password, passwordLen);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		r = tools_write_mk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), uk, uk_size);
		if (r < 0)
			goto out;
	}

	log_std("LUKS header information for %s\n", crypt_get_device_name(cd));
	log_std("UUID:    \t%s\n", crypt_get_uuid(cd));
	log_std("Keyslot: \t%d\n", ARG_INT32(OPT_KEY_SLOT_ID));
	log_std("Key bits:\t%d\n", (int)uk_size * 8);
	if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		log_std("Key stored to file %s.\n", ARG_STR(OPT_VOLUME_KEY_FILE_ID));
		goto out;
	}
	log_std("Unbound Key:\t");
	crypt_log_hex(NULL, uk, uk_size, " ", 16, "\n\t\t");
	log_std("\n");
out:
	crypt_safe_free(password);
	crypt_safe_free(uk);
	return r;
}

static int action_luksDump(void)
{
	struct crypt_device *cd = NULL;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if ((r = crypt_load(cd, luksType(device_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	if (ARG_SET(OPT_EXTERNAL_TOKENS_PATH_ID)) {
		r = crypt_token_set_external_path(ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
		if (r < 0) {
			log_err(_("Failed to set external tokens path %s."),
				ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
			goto out;
		}
	}

	if (ARG_SET(OPT_DUMP_VOLUME_KEY_ID))
		r = luksDump_with_volume_key(cd);
	else if (ARG_SET(OPT_UNBOUND_ID))
		r = luksDump_with_unbound_key(cd);
	else if (ARG_SET(OPT_DUMP_JSON_ID))
		r = crypt_dump_json(cd, NULL, 0);
	else
		r = crypt_dump(cd);
out:
	crypt_free(cd);
	return r;
}

static int action_luksSuspend(void)
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_init_by_name_and_header(&cd, action_argv[0], uuid_or_device(ARG_STR(OPT_HEADER_ID)));
	if (!r) {
		r = crypt_suspend(cd, action_argv[0]);
		if (r == -ENODEV)
			log_err(_("%s is not active %s device name."), action_argv[0], "LUKS");
	}

	crypt_free(cd);
	return r;
}

static int action_luksResume(void)
{
	struct crypt_device *cd = NULL;
	char *vk_description_activation = NULL;
	int r, tries;
	struct crypt_active_device cad;
	const char *req_type = luksType(device_type);
	struct crypt_keyslot_context *kc = NULL;

	if (req_type && !isLUKS(req_type))
		return -EINVAL;

	if ((r = crypt_init_by_name_and_header(&cd, action_argv[0], uuid_or_device(ARG_STR(OPT_HEADER_ID)))))
		return r;

	if (ARG_SET(OPT_LINK_VK_TO_KEYRING_ID)) {
		r = tools_parse_vk_and_keyring_description(cd, keyring_links, keyring_links_count);
		if (r < 0)
			goto out;
	}

	r = -EINVAL;

	if (!isLUKS(crypt_get_type(cd))) {
		log_err(_("%s is not active LUKS device name or header is missing."), action_argv[0]);
		goto out;
	}

	if (req_type && strcmp(req_type, crypt_get_type(cd))) {
		log_err(_("%s is not active %s device name."), action_argv[0], req_type);
		goto out;
	}

	r = crypt_get_active_device(cd, action_argv[0], &cad);
	if (r < 0)
		goto out;

	if (!(cad.flags & CRYPT_ACTIVATE_SUSPENDED)) {
		log_err(_("Volume %s is not suspended."), action_argv[0]);
		r = -EINVAL;
		goto out;
	}

	if (ARG_SET(OPT_EXTERNAL_TOKENS_PATH_ID)) {
		r = crypt_token_set_external_path(ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
		if (r < 0) {
			log_err(_("Failed to set external tokens path %s."),
				ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
			goto out;
		}
	}

	/* try to resume LUKS2 device by token first */
	r = luks_try_token_unlock(cd, ARG_INT32(OPT_KEY_SLOT_ID), ARG_INT32(OPT_TOKEN_ID_ID),
				  action_argv[0], ARG_STR(OPT_TOKEN_TYPE_ID), 0,
				  set_tries_tty(false), false,
				  ARG_SET(OPT_TOKEN_ONLY_ID) || ARG_SET(OPT_TOKEN_ID_ID) || ARG_SET(OPT_TOKEN_TYPE_ID),
				  NULL);

	if (r >= 0 || quit || ARG_SET(OPT_TOKEN_ONLY_ID))
		goto out;

	if (ARG_SET(OPT_VOLUME_KEY_KEYRING_ID)) {
		r = tools_parse_vk_description(ARG_STR(OPT_VOLUME_KEY_KEYRING_ID), &vk_description_activation);
		if (r < 0)
			goto out;
		r = crypt_keyslot_context_init_by_vk_in_keyring(cd, vk_description_activation, &kc);
		free(vk_description_activation);
		if (r)
			goto out;
		r = crypt_resume_by_keyslot_context(cd, action_argv[0], CRYPT_ANY_SLOT, kc);
		goto out;
	}

	tries = set_tries_tty(true);
	do {
		r = luks_init_keyslot_context(cd, NULL, verify_passphrase(0), false, &kc);
		if (r < 0)
			goto out;

		r = crypt_resume_by_keyslot_context(cd, action_argv[0], ARG_INT32(OPT_KEY_SLOT_ID), kc);
		crypt_keyslot_context_free(kc);
		kc = NULL;

		tools_passphrase_msg(r);
		check_signal(&r);
		tools_keyslot_msg(r, UNLOCKED);

	} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
out:
	crypt_keyslot_context_free(kc);
	crypt_free(cd);
	return r;
}

static int action_luksBackup(void)
{
	struct crypt_device *cd = NULL;
	int r;

	if (!ARG_SET(OPT_HEADER_BACKUP_FILE_ID)) {
		log_err(_("Option --header-backup-file is required."));
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	r = crypt_header_backup(cd, NULL, ARG_STR(OPT_HEADER_BACKUP_FILE_ID));
out:
	crypt_free(cd);
	return r;
}

static int action_luksRestore(void)
{
	struct crypt_device *cd = NULL;
	int r = 0;

	if (!ARG_SET(OPT_HEADER_BACKUP_FILE_ID)) {
		log_err(_("Option --header-backup-file is required."));
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if (!ARG_SET(OPT_BATCH_MODE_ID))
		crypt_set_confirm_callback(cd, yesDialog, NULL);
	r = crypt_header_restore(cd, NULL, ARG_STR(OPT_HEADER_BACKUP_FILE_ID));
out:
	crypt_free(cd);
	return r;
}

static const char *_get_device_type(void)
{
	const char *type, *name = NULL;
	struct crypt_device *cd = NULL;

	if (action_argc > 1)
		name = action_argv[1];
	else if (action_argc == 1)
		name = action_argv[0];

	if (crypt_init_by_name_and_header(&cd, name, ARG_STR(OPT_HEADER_ID)))
		return NULL;

	type = crypt_get_type(cd);
	if (!type) {
		crypt_free(cd);
		log_err(_("%s is not cryptsetup managed device."), name);
		return NULL;
	}

	if (!strncmp(type, "LUKS", 4))
		type = "luks";
	else if (!strcmp(type, CRYPT_PLAIN))
		type = "plain";
	else if (!strcmp(type, CRYPT_LOOPAES))
		type = "loopaes";
	else {
		log_err(_("Refresh is not supported for device type %s"), type);
		type = NULL;
	}

	crypt_free(cd);

	return type;
}

static int action_open(void)
{
	int r = -EINVAL;

	if (ARG_SET(OPT_REFRESH_ID) && !device_type)
		/* read device type from active mapping */
		device_type = _get_device_type();

	if (!device_type)
		return -EINVAL;

	if (!strcmp(device_type, "luks") ||
	    !strcmp(device_type, "luks1") ||
	    !strcmp(device_type, "luks2")) {
		if (action_argc < 2 && (!ARG_SET(OPT_TEST_PASSPHRASE_ID) && !ARG_SET(OPT_REFRESH_ID)))
			goto out;
		return action_open_luks();
	} else if (!strcmp(device_type, "plain")) {
		if (action_argc < 2 && !ARG_SET(OPT_REFRESH_ID))
			goto out;
		return action_open_plain();
	} else if (!strcmp(device_type, "loopaes")) {
		if (action_argc < 2 && !ARG_SET(OPT_REFRESH_ID))
			goto out;
		return action_open_loopaes();
	} else if (!strcmp(device_type, "tcrypt")) {
		if (action_argc < 2 && !ARG_SET(OPT_TEST_PASSPHRASE_ID))
			goto out;
		return action_open_tcrypt();
	} else if (!strcmp(device_type, "bitlk")) {
		if (action_argc < 2 && !ARG_SET(OPT_TEST_PASSPHRASE_ID))
			goto out;
		return action_open_bitlk();
	} else if (!strcmp(device_type, "fvault2")) {
		if (action_argc < 2 && !ARG_SET(OPT_TEST_PASSPHRASE_ID))
			goto out;
		return action_open_fvault2();
	} else
		r = -ENOENT;
out:
	if (r == -ENOENT)
		log_err(_("Unrecognized metadata device type %s."), device_type);
	else
		log_err(_("Command requires device and mapped name as arguments."));

	return r;
}

static int opal_erase(struct crypt_device *cd, bool factory_reset) {
	char *password = NULL;
	size_t password_size = 0, keyfile_size_max;
	int r;

	/* limit PSID keyfile read if not set otherwise */
	if (!factory_reset || ARG_SET(OPT_KEYFILE_SIZE_ID))
		keyfile_size_max = ARG_UINT32(OPT_KEYFILE_SIZE_ID);
	else {
		log_dbg("Limiting PSID keyfile size to %d characters.", OPAL_PSID_LEN);
		keyfile_size_max = OPAL_PSID_LEN;
	}

	r = tools_get_key(factory_reset ? _("Enter OPAL PSID: ") : _("Enter OPAL Admin password: "),
				&password, &password_size, ARG_UINT64(OPT_KEYFILE_OFFSET_ID),
				keyfile_size_max, ARG_STR(OPT_KEY_FILE_ID),
				ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	if (factory_reset && !ARG_SET(OPT_BATCH_MODE_ID) &&
		!yesDialog(_("WARNING: WHOLE disk will be factory reset and all data will be lost! Continue?"),
			_("Operation aborted.\n"))) {
		crypt_safe_free(password);
		return -EPERM;
	}

	r = crypt_wipe_hw_opal(cd, factory_reset ? CRYPT_NO_SEGMENT : CRYPT_LUKS2_SEGMENT,
			       password, password_size, 0);

	crypt_safe_free(password);
	return r;
}

static int action_luksErase(void)
{
	struct crypt_device *cd = NULL;
	crypt_keyslot_info ki;
	char *msg = NULL;
	int i, max, r, hw_enc;

	if ((r = crypt_init_data_device(&cd, uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]), action_argv[0])))
		return r;

	/* Allow factory reset even if there's no LUKS header, as long as OPAL is enabled on the device */
	if (ARG_SET(OPT_HW_OPAL_FACTORY_RESET_ID)) {
		r = opal_erase(cd, true);
		goto out;
	}

	if ((r = crypt_load(cd, luksType(device_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	hw_enc = crypt_get_hw_encryption_type(cd);
	if (hw_enc < 0)
		goto out;
	if (hw_enc == CRYPT_OPAL_HW_ONLY || hw_enc == CRYPT_SW_AND_OPAL_HW) {
		r = opal_erase(cd, false);
		goto out;
	}

	if (asprintf(&msg, _("This operation will erase all keyslots on device %s.\n"
			    "Device will become unusable after this operation."),
			    uuid_or_device_header(NULL)) == -1) {
		r = -ENOMEM;
		goto out;
	}

	if (!ARG_SET(OPT_BATCH_MODE_ID) && !yesDialog(msg, _("Operation aborted, keyslots were NOT wiped.\n"))) {
		r = -EPERM;
		goto out;
	}

	/* Safety check */
	max = crypt_keyslot_max(crypt_get_type(cd));
	if (max <= 0) {
		r = -EINVAL;
		goto out;
	}

	for (i = 0; i < max; i++) {
		ki = crypt_keyslot_status(cd, i);
		if (ki == CRYPT_SLOT_ACTIVE || ki == CRYPT_SLOT_ACTIVE_LAST) {
			r = crypt_keyslot_destroy(cd, i);
			if (r < 0)
				goto out;
			tools_keyslot_msg(i, REMOVED);
		}
	}
out:
	free(msg);
	crypt_free(cd);
	return r;
}

static int action_luksConvert(void)
{
	struct crypt_device *cd = NULL;
	char *msg = NULL;
	const char *to_type, *from_type;
	int r;

	if (!strcmp(device_type, "luks2")) {
		to_type = CRYPT_LUKS2;
	} else if (!strcmp(device_type, "luks1")) {
		to_type = CRYPT_LUKS1;
	} else {
		log_err(_("Invalid LUKS type, only luks1 and luks2 are supported."));
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		return r;

	if ((r = crypt_load(cd, CRYPT_LUKS, NULL)) ||
	    !(from_type = crypt_get_type(cd))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		crypt_free(cd);
		return r;
	}

	if (!strcmp(from_type, to_type)) {
		log_err(_("Device is already %s type."), to_type);
		crypt_free(cd);
		return -EINVAL;
	}

	r = 0;
	if (!ARG_SET(OPT_BATCH_MODE_ID)) {
		if (asprintf(&msg, _("This operation will convert %s to %s format.\n"),
				    uuid_or_device_header(NULL), to_type) == -1)
			r = -ENOMEM;
		else if (!yesDialog(msg, _("Operation aborted, device was NOT converted.\n")))
			r = -EPERM;
	}

	r = r ?: crypt_convert(cd, to_type, NULL);

	free(msg);
	crypt_free(cd);
	return r;
}

static int _config_priority(struct crypt_device *cd)
{
	crypt_keyslot_info cs;
	crypt_keyslot_priority priority = CRYPT_SLOT_PRIORITY_INVALID;

	if (!strcmp("normal", ARG_STR(OPT_PRIORITY_ID)))
		priority = CRYPT_SLOT_PRIORITY_NORMAL;
	else if (!strcmp("prefer", ARG_STR(OPT_PRIORITY_ID)))
		priority = CRYPT_SLOT_PRIORITY_PREFER;
	else if (!strcmp("ignore", ARG_STR(OPT_PRIORITY_ID)))
		priority = CRYPT_SLOT_PRIORITY_IGNORE;

	cs = crypt_keyslot_status(cd, ARG_INT32(OPT_KEY_SLOT_ID));
	if (cs != CRYPT_SLOT_INVALID)
		return crypt_keyslot_set_priority(cd, ARG_INT32(OPT_KEY_SLOT_ID), priority);
	return -EINVAL;
}

static int _config_labels(struct crypt_device *cd)
{
	return crypt_set_label(cd, ARG_STR(OPT_LABEL_ID), ARG_STR(OPT_SUBSYSTEM_ID));
}

static int action_luksConfig(void)
{
	struct crypt_device *cd = NULL;
	int r;

	if (!ARG_SET(OPT_PRIORITY_ID) && !ARG_SET(OPT_LABEL_ID) && !ARG_SET(OPT_SUBSYSTEM_ID)) {
		log_err(_("Option --priority, --label or --subsystem is missing."));
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		return r;

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL))) {
		log_err(_("Device %s is not a valid LUKS2 device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	if (ARG_SET(OPT_PRIORITY_ID) && (r = _config_priority(cd)))
		goto out;

	if ((ARG_SET(OPT_LABEL_ID) || ARG_SET(OPT_SUBSYSTEM_ID)) && (r = _config_labels(cd)))
		goto out;
out:
	crypt_free(cd);
	return r;
}

static int _token_add(struct crypt_device *cd)
{
	int r, token;
	crypt_token_info token_info;
	const struct crypt_token_params_luks2_keyring params = {
		.key_description = ARG_STR(OPT_KEY_DESCRIPTION_ID)
	};

	if (ARG_INT32(OPT_TOKEN_ID_ID) != CRYPT_ANY_TOKEN) {
		token_info = crypt_token_status(cd, ARG_INT32(OPT_TOKEN_ID_ID), NULL);
		if (token_info < CRYPT_TOKEN_INACTIVE) {
			log_err(_("Token %d is invalid."), ARG_INT32(OPT_TOKEN_ID_ID));
			return -EINVAL;
		} else if (token_info > CRYPT_TOKEN_INACTIVE && !ARG_SET(OPT_TOKEN_REPLACE_ID)) {
			log_err(_("Token %d in use."), ARG_INT32(OPT_TOKEN_ID_ID));
			return -EINVAL;
		}
	}

	if (crypt_keyslot_status(cd, ARG_INT32(OPT_KEY_SLOT_ID)) == CRYPT_SLOT_INACTIVE) {
		log_err(_("Keyslot %d is not active."), ARG_INT32(OPT_KEY_SLOT_ID));
		return -EINVAL;
	}

	r = crypt_token_luks2_keyring_set(cd, ARG_INT32(OPT_TOKEN_ID_ID), &params);
	if (r < 0) {
		log_err(_("Failed to add luks2-keyring token %d."), ARG_INT32(OPT_TOKEN_ID_ID));
		return r;
	}

	token = r;

	if (ARG_SET(OPT_UNBOUND_ID))
		return token;

	r = crypt_token_assign_keyslot(cd, token, ARG_INT32(OPT_KEY_SLOT_ID));
	if (r < 0) {
		log_err(_("Failed to assign token %d to keyslot %d."), token, ARG_INT32(OPT_KEY_SLOT_ID));
		(void) crypt_token_json_set(cd, token, NULL);
		return r;
	}

	return token;
}

static int _token_remove(struct crypt_device *cd)
{
	crypt_token_info token_info;

	token_info = crypt_token_status(cd, ARG_INT32(OPT_TOKEN_ID_ID), NULL);
	if (token_info < CRYPT_TOKEN_INACTIVE) {
		log_err(_("Token %d is invalid."), ARG_INT32(OPT_TOKEN_ID_ID));
		return -EINVAL;
	} else if (token_info == CRYPT_TOKEN_INACTIVE) {
		log_err(_("Token %d is not in use."), ARG_INT32(OPT_TOKEN_ID_ID));
		return -EINVAL;
	}

	return crypt_token_json_set(cd, ARG_INT32(OPT_TOKEN_ID_ID), NULL);
}

static int _token_import(struct crypt_device *cd)
{
	char *json;
	size_t json_length;
	crypt_token_info token_info;
	int r, token;

	if (ARG_INT32(OPT_TOKEN_ID_ID) != CRYPT_ANY_TOKEN) {
		token_info = crypt_token_status(cd, ARG_INT32(OPT_TOKEN_ID_ID), NULL);
		if (token_info < CRYPT_TOKEN_INACTIVE) {
			log_err(_("Token %d is invalid."), ARG_INT32(OPT_TOKEN_ID_ID));
			return -EINVAL;
		} else if (token_info > CRYPT_TOKEN_INACTIVE && !ARG_SET(OPT_TOKEN_REPLACE_ID)) {
			log_err(_("Token %d in use."), ARG_INT32(OPT_TOKEN_ID_ID));
			return -EINVAL;
		}
	}

	if (crypt_keyslot_status(cd, ARG_INT32(OPT_KEY_SLOT_ID)) == CRYPT_SLOT_INACTIVE) {
		log_err(_("Keyslot %d is not active."), ARG_INT32(OPT_KEY_SLOT_ID));
		return -EINVAL;
	}

	r = tools_read_json_file(ARG_STR(OPT_JSON_FILE_ID), &json, &json_length, ARG_SET(OPT_BATCH_MODE_ID));
	if (r)
		return r;

	r = crypt_token_json_set(cd, ARG_INT32(OPT_TOKEN_ID_ID), json);
	free(json);
	if (r < 0) {
		log_err(_("Failed to import token from file."));
		return r;
	}

	token = r;

	if (ARG_INT32(OPT_KEY_SLOT_ID) != CRYPT_ANY_SLOT) {
		r = crypt_token_assign_keyslot(cd, token, ARG_INT32(OPT_KEY_SLOT_ID));
		if (r < 0) {
			log_err(_("Failed to assign token %d to keyslot %d."), token, ARG_INT32(OPT_KEY_SLOT_ID));
			(void) crypt_token_json_set(cd, token, NULL);
			return r;
		}
	}

	return token;
}

static int _token_export(struct crypt_device *cd)
{
	const char *json;
	int r;

	r = crypt_token_json_get(cd, ARG_INT32(OPT_TOKEN_ID_ID), &json);
	if (r < 0) {
		log_err(_("Failed to get token %d for export."), ARG_INT32(OPT_TOKEN_ID_ID));
		return r;
	}

	return tools_write_json_file(ARG_STR(OPT_JSON_FILE_ID), json);
}

static int _token_unassign(struct crypt_device *cd)
{
	int r = crypt_token_is_assigned(cd, ARG_INT32(OPT_TOKEN_ID_ID), ARG_INT32(OPT_KEY_SLOT_ID));

	if (r < 0) {
		if (r == -ENOENT)
			log_err(_("Token %d is not assigned to keyslot %d."), ARG_INT32(OPT_TOKEN_ID_ID), ARG_INT32(OPT_KEY_SLOT_ID));
		else
			log_err(_("Failed to unassign token %d from keyslot %d."), ARG_INT32(OPT_TOKEN_ID_ID), ARG_INT32(OPT_KEY_SLOT_ID));

		return r;
	}

	r = crypt_token_unassign_keyslot(cd, ARG_INT32(OPT_TOKEN_ID_ID), ARG_INT32(OPT_KEY_SLOT_ID));
	if (r < 0)
		log_err(_("Failed to unassign token %d from keyslot %d."), ARG_INT32(OPT_TOKEN_ID_ID), ARG_INT32(OPT_KEY_SLOT_ID));

	return r;
}

static int action_token(void)
{
	int r;
	struct crypt_device *cd = NULL;

	if ((r = crypt_init(&cd, uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[1]))))
		return r;

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL))) {
		log_err(_("Device %s is not a valid LUKS2 device."),
			uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[1]));
		crypt_free(cd);
		return r;
	}

	if (ARG_SET(OPT_EXTERNAL_TOKENS_PATH_ID)) {
		r = crypt_token_set_external_path(ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
		if (r < 0) {
			log_err(_("Failed to set external tokens path %s."),
				ARG_STR(OPT_EXTERNAL_TOKENS_PATH_ID));
			crypt_free(cd);
			return r;
		}
	}

	r = -EINVAL;

	if (!strcmp(action_argv[0], "add")) {
		r = _token_add(cd); /* adds only luks2-keyring type */
		tools_token_msg(r, CREATED);
	} else if (!strcmp(action_argv[0], "remove")) {
		r = _token_remove(cd);
		tools_token_msg(r, REMOVED);
	} else if (!strcmp(action_argv[0], "import")) {
		r = _token_import(cd);
		tools_token_msg(r, CREATED);
	} else if (!strcmp(action_argv[0], "export"))
		r = _token_export(cd);
	else if (!strcmp(action_argv[0], "unassign"))
		r = _token_unassign(cd);

	crypt_free(cd);

	return r;
}

static int action_reencrypt(void)
{
	return reencrypt(action_argc, action_argv);
}

static const char *verify_tcryptdump(void)
{
	if ((ARG_SET(OPT_TCRYPT_HIDDEN_ID) || ARG_SET(OPT_TCRYPT_SYSTEM_ID) || ARG_SET(OPT_TCRYPT_BACKUP_ID)) && (!device_type || strcmp(device_type, "tcrypt")))
		return _("Option --tcrypt-hidden, --tcrypt-system or --tcrypt-backup is supported only for TCRYPT device.");

	if ((ARG_SET(OPT_VERACRYPT_ID) || ARG_SET(OPT_DISABLE_VERACRYPT_ID)) && (!device_type || strcmp(device_type, "tcrypt")))
		return _("Option --veracrypt or --disable-veracrypt is supported only for TCRYPT device type.");

	if (ARG_SET(OPT_VERACRYPT_PIM_ID) && ARG_SET(OPT_DISABLE_VERACRYPT_ID))
		return _("Option --veracrypt-pim is supported only for VeraCrypt compatible devices.");

	if (ARG_SET(OPT_VERACRYPT_QUERY_PIM_ID)) {
		if (ARG_SET(OPT_DISABLE_VERACRYPT_ID))
			return _("Option --veracrypt-query-pim is supported only for VeraCrypt compatible devices.");
		else if (ARG_SET(OPT_VERACRYPT_PIM_ID))
			return _("The options --veracrypt-pim and --veracrypt-query-pim are mutually exclusive.");
	}

	return NULL;
}

static const char *verify_open(void)
{
	if (ARG_SET(OPT_PERSISTENT_ID) && ARG_SET(OPT_TEST_PASSPHRASE_ID))
		return _("Option --persistent is not allowed with --test-passphrase.");

	if (ARG_SET(OPT_REFRESH_ID) && ARG_SET(OPT_TEST_PASSPHRASE_ID))
		return _("Options --refresh and --test-passphrase are mutually exclusive.");

	if (ARG_SET(OPT_SHARED_ID) && strcmp_or_null(device_type, "plain"))
		return _("Option --shared is allowed only for open of plain device.");

	if (ARG_SET(OPT_SKIP_ID) && strcmp_or_null(device_type, "plain") && strcmp(device_type, "loopaes"))
		return _("Option --skip is supported only for open of plain and loopaes devices.");

	if (ARG_SET(OPT_OFFSET_ID) && strcmp_or_null(device_type, "plain") && strcmp(device_type, "loopaes"))
		return _("Option --offset with open action is only supported for plain and loopaes devices.");

	if (ARG_SET(OPT_TCRYPT_HIDDEN_ID) && ARG_SET(OPT_ALLOW_DISCARDS_ID))
		return _("Option --tcrypt-hidden cannot be combined with --allow-discards.");

	if (ARG_SET(OPT_SECTOR_SIZE_ID) &&
	    (!device_type || strcmp(device_type, "plain")))
		return _("Sector size option with open action is supported only for plain devices.");

	if (ARG_SET(OPT_IV_LARGE_SECTORS_ID) && (!device_type || strcmp(device_type, "plain") ||
	    ARG_UINT32(OPT_SECTOR_SIZE_ID) <= SECTOR_SIZE))
		return _("Large IV sectors option is supported only for opening plain type device with sector size larger than 512 bytes.");

	if (ARG_SET(OPT_TEST_PASSPHRASE_ID) && (!device_type ||
	    (strncmp(device_type, "luks", 4) && strcmp(device_type, "tcrypt") &&
	     strcmp(device_type, "bitlk") && strcmp(device_type, "fvault2"))))
		return _("Option --test-passphrase is allowed only for open of LUKS, TCRYPT, BITLK and FVAULT2 devices.");

	if (ARG_SET(OPT_DEVICE_SIZE_ID) && ARG_SET(OPT_SIZE_ID))
		return _("Options --device-size and --size cannot be combined.");

	if (ARG_SET(OPT_UNBOUND_ID) && device_type && strncmp(device_type, "luks", 4))
		return _("Option --unbound is allowed only for open of luks device.");

	if (ARG_SET(OPT_UNBOUND_ID) && !ARG_SET(OPT_TEST_PASSPHRASE_ID))
		return _("Option --unbound cannot be used without --test-passphrase.");

	if (ARG_SET(OPT_VOLUME_KEY_KEYRING_ID) && (ARG_SET(OPT_HASH_ID) ||
		ARG_SET(OPT_VOLUME_KEY_FILE_ID)) && !strcmp_or_null(device_type, "plain"))
		return _("Option --volume-key-keyring cannot be combined with --hash or --volume-key-file.");

	if (vk_files[1] && !key_sizes[1])
		return _("Both --volume-key-file options must be paired with respective --key-size options.");

	/* "open --type tcrypt" and "tcryptDump" checks are identical */
	return verify_tcryptdump();
}

static const char *verify_close(void)
{
	if (ARG_SET(OPT_CANCEL_DEFERRED_ID) && ARG_SET(OPT_DEFERRED_ID))
		return _("Options --cancel-deferred and --deferred cannot be used at the same time.");

	return NULL;
}

static const char *verify_resize(void)
{
	if (ARG_SET(OPT_DEVICE_SIZE_ID) && ARG_SET(OPT_SIZE_ID))
		return _("Options --device-size and --size cannot be combined.");

	return NULL;
}

static const char *verify_reencrypt(void)
{
	if (isLUKS1(luksType(device_type)) && ARG_SET(OPT_ACTIVE_NAME_ID))
		return _("Option --active-name can be set only for LUKS2 device.");

	if (ARG_SET(OPT_ACTIVE_NAME_ID) && ARG_SET(OPT_FORCE_OFFLINE_REENCRYPT_ID))
		return _("Options --active-name and --force-offline-reencrypt cannot be combined.");

	if (ARG_SET(OPT_NEW_VOLUME_KEY_FILE_ID) && ARG_SET(OPT_KEEP_KEY_ID))
		return _("Options --new-volume-key-file and --keep-key cannot be combined.");

	if (ARG_SET(OPT_NEW_VOLUME_KEY_KEYRING_ID) && ARG_SET(OPT_KEEP_KEY_ID))
		return _("Options --new-volume-key-keyring and --keep-key cannot be combined.");

	return NULL;
}

static const char *verify_config(void)
{
	if (ARG_SET(OPT_PRIORITY_ID) && ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT)
		return _("Keyslot specification is required.");

	return NULL;
}

static const char *verify_format(void)
{
	if (ARG_SET(OPT_ALIGN_PAYLOAD_ID) && ARG_SET(OPT_OFFSET_ID))
		return _("Options --align-payload and --offset cannot be combined.");

	if (ARG_SET(OPT_INTEGRITY_NO_WIPE_ID) && !ARG_SET(OPT_INTEGRITY_ID))
		return _("Option --integrity-no-wipe can be used only for format action with integrity extension.");

	if (ARG_SET(OPT_USE_RANDOM_ID) && ARG_SET(OPT_USE_URANDOM_ID))
		return  _("Only one of --use-[u]random options is allowed.");

	return NULL;
}

static const char *verify_addkey(void)
{
	if (ARG_SET(OPT_UNBOUND_ID) && !ARG_UINT32(OPT_KEY_SIZE_ID))
		return _("Key size is required with --unbound option.");

	return NULL;
}

static const char *verify_luksDump(void)
{
	if (ARG_SET(OPT_UNBOUND_ID) && ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT)
		return _("Keyslot specification is required.");

	return NULL;
}

static const char *verify_token(void)
{
	if (strcmp(action_argv[0], "add") &&
	    strcmp(action_argv[0], "remove") &&
	    strcmp(action_argv[0], "import") &&
	    strcmp(action_argv[0], "export") &&
	    strcmp(action_argv[0], "unassign"))
		return _("Invalid token action.");

	if (!ARG_SET(OPT_KEY_DESCRIPTION_ID) && !strcmp(action_argv[0], "add"))
		return _("--key-description parameter is mandatory for token add action.");

	if (ARG_INT32(OPT_TOKEN_ID_ID) == CRYPT_ANY_TOKEN &&
	    (!strcmp(action_argv[0], "remove") || !strcmp(action_argv[0], "export")))
		return _("Action requires specific token. Use --token-id parameter.");

	if (ARG_SET(OPT_UNBOUND_ID)) {
		if (strcmp(action_argv[0], "add"))
			return _("Option --unbound is valid only with token add action.");
		if (ARG_SET(OPT_KEY_SLOT_ID))
			return _("Options --key-slot and --unbound cannot be combined.");
	}

	if (!strcmp(action_argv[0], "unassign")) {
		if (!ARG_SET(OPT_KEY_SLOT_ID))
			return _("Action requires specific keyslot. Use --key-slot parameter.");
		if (!ARG_SET(OPT_TOKEN_ID_ID))
			return _("Action requires specific token. Use --token-id parameter.");
	}

	return NULL;
}

static struct action_type {
	const char *type;
	int (*handler)(void);
	const char *(*verify)(void);
	int required_action_argc;
	const char *arg_desc;
	const char *desc;
} action_types[] = {
	{ OPEN_ACTION,		action_open,		verify_open,		1, N_("<device> [--type <type>] [<name>]"),N_("open device as <name>") },
	{ CLOSE_ACTION,		action_close,		verify_close,		1, N_("<name>"), N_("close device (remove mapping)") },
	{ RESIZE_ACTION,	action_resize,		verify_resize,		1, N_("<name>"), N_("resize active device") },
	{ STATUS_ACTION,	action_status,		NULL,			1, N_("<name>"), N_("show device status") },
	{ BENCHMARK_ACTION,	action_benchmark,	NULL,			0, N_("[--cipher <cipher>]"), N_("benchmark cipher") },
	{ REPAIR_ACTION,	action_luksRepair,	NULL,			1, N_("<device>"), N_("try to repair on-disk metadata") },
	{ REENCRYPT_ACTION,	action_reencrypt,	verify_reencrypt,	0, N_("<device>"), N_("reencrypt LUKS2 device") },
	{ ERASE_ACTION,		action_luksErase,	NULL,			1, N_("<device>"), N_("erase all keyslots (remove encryption key)") },
	{ CONVERT_ACTION,	action_luksConvert,	NULL,			1, N_("<device>"), N_("convert LUKS from/to LUKS2 format") },
	{ CONFIG_ACTION,	action_luksConfig,	verify_config,		1, N_("<device>"), N_("set permanent configuration options for LUKS2") },
	{ FORMAT_ACTION,	action_luksFormat,	verify_format,		1, N_("<device> [<new key file>]"), N_("formats a LUKS device") },
	{ ADDKEY_ACTION,	action_luksAddKey,	verify_addkey,		1, N_("<device> [<new key file>]"), N_("add key to LUKS device") },
	{ REMOVEKEY_ACTION,	action_luksRemoveKey,	NULL,			1, N_("<device> [<key file>]"), N_("removes supplied key or key file from LUKS device") },
	{ CHANGEKEY_ACTION,	action_luksChangeKey,	NULL,			1, N_("<device> [<key file>]"), N_("changes supplied key or key file of LUKS device") },
	{ CONVERTKEY_ACTION,	action_luksConvertKey,	NULL,			1, N_("<device> [<key file>]"), N_("converts a key to new pbkdf parameters") },
	{ KILLKEY_ACTION,	action_luksKillSlot,	NULL,			2, N_("<device> <key slot>"), N_("wipes key with number <key slot> from LUKS device") },
	{ UUID_ACTION,		action_luksUUID,	NULL,			1, N_("<device>"), N_("print UUID of LUKS device") },
	{ ISLUKS_ACTION,	action_isLuks,		NULL,			1, N_("<device>"), N_("tests <device> for LUKS partition header") },
	{ LUKSDUMP_ACTION,	action_luksDump,	verify_luksDump,	1, N_("<device>"), N_("dump LUKS partition information") },
	{ TCRYPTDUMP_ACTION,	action_tcryptDump,	verify_tcryptdump,	1, N_("<device>"), N_("dump TCRYPT device information") },
	{ BITLKDUMP_ACTION,	action_bitlkDump,	NULL,			1, N_("<device>"), N_("dump BITLK device information") },
	{ FVAULT2DUMP_ACTION,	action_fvault2Dump,	NULL,			1, N_("<device>"), N_("dump FVAULT2 device information") },
	{ SUSPEND_ACTION,	action_luksSuspend,	NULL,			1, N_("<device>"), N_("Suspend LUKS device and wipe key (all IOs are frozen)") },
	{ RESUME_ACTION,	action_luksResume,	NULL,			1, N_("<device>"), N_("Resume suspended LUKS device") },
	{ HEADERBACKUP_ACTION,	action_luksBackup,	NULL,			1, N_("<device>"), N_("Backup LUKS device header and keyslots") },
	{ HEADERRESTORE_ACTION,	action_luksRestore,	NULL,			1, N_("<device>"), N_("Restore LUKS device header and keyslots") },
	{ TOKEN_ACTION,		action_token,		verify_token,		2, N_("<add|remove|import|export> <device>"), N_("Manipulate LUKS2 tokens") },
	{}
};

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	const char *path;

	if (key->shortName == '?') {
		struct action_type *action;
		const struct crypt_pbkdf_type *pbkdf_luks1, *pbkdf_luks2;

		tools_package_version(PACKAGE_NAME, true);
		poptPrintHelp(popt_context, stdout, 0);

		log_std(_("\n"
			 "<action> is one of:\n"));

		for(action = action_types; action->type; action++)
			log_std("\t%s %s - %s\n", action->type, _(action->arg_desc), _(action->desc));

		log_std(_("\n"
			  "You can also use old <action> syntax aliases:\n"
			  "\topen: create (plainOpen), luksOpen, loopaesOpen, tcryptOpen, bitlkOpen, fvault2Open\n"
			  "\tclose: remove (plainClose), luksClose, loopaesClose, tcryptClose, bitlkClose, fvault2Close\n"));
		log_std(_("\n"
			 "<name> is the device to create under %s\n"
			 "<device> is the encrypted device\n"
			 "<key slot> is the LUKS key slot number to modify\n"
			 "<key file> optional key file for the new key for luksAddKey action\n"),
			crypt_get_dir());

		log_std(_("\nDefault compiled-in metadata format is %s (for luksFormat action).\n"),
			  crypt_get_default_type());

		path = crypt_token_external_path();
		if (path) {
			log_std(_("\nLUKS2 external token plugin support is enabled.\n"));
			log_std(_("LUKS2 external token plugin path: %s.\n"), path);
		} else
			log_std(_("\nLUKS2 external token plugin support is disabled.\n"));

		pbkdf_luks1 = crypt_get_pbkdf_default(CRYPT_LUKS1);
		pbkdf_luks2 = crypt_get_pbkdf_default(CRYPT_LUKS2);
		log_std(_("\nDefault compiled-in key and passphrase parameters:\n"
			 "\tMaximum keyfile size: %dkB, "
			 "Maximum interactive passphrase length %d (characters)\n"
			 "Default PBKDF for LUKS1: %s, iteration time: %d (ms)\n"
			 "Default PBKDF for LUKS2: %s\n"
			 "\tIteration time: %d, Memory required: %dkB, Parallel threads: %d\n"),
			 DEFAULT_KEYFILE_SIZE_MAXKB, DEFAULT_PASSPHRASE_SIZE_MAX,
			 pbkdf_luks1->type,  pbkdf_luks1->time_ms,
			 pbkdf_luks2->type, pbkdf_luks2->time_ms, pbkdf_luks2->max_memory_kb,
			 pbkdf_luks2->parallel_threads);

		log_std(_("\nDefault compiled-in device cipher parameters:\n"
			 "\tloop-AES: %s, Key %d bits\n"
			 "\tplain: %s, Key: %d bits, Password hashing: %s\n"
			 "\tLUKS: %s, Key: %d bits, LUKS header hashing: %s, RNG: %s\n"),
			 DEFAULT_LOOPAES_CIPHER, DEFAULT_LOOPAES_KEYBITS,
			 DEFAULT_CIPHER(PLAIN), DEFAULT_PLAIN_KEYBITS, DEFAULT_PLAIN_HASH,
			 DEFAULT_CIPHER(LUKS1), DEFAULT_LUKS1_KEYBITS, DEFAULT_LUKS1_HASH,
			 DEFAULT_RNG);
#if ENABLE_LUKS_ADJUST_XTS_KEYSIZE && DEFAULT_LUKS1_KEYBITS != 512
		log_std(_("\tLUKS: Default keysize with XTS mode (two internal keys) will be doubled.\n"));
#endif
		tools_cleanup();
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else if (key->shortName == 'V') {
		tools_package_version(PACKAGE_NAME, true);
		tools_cleanup();
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else
		usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

static void help_args(struct action_type *action, poptContext popt_context)
{
	char buf[128];

	if (snprintf(buf, sizeof(buf), _("%s: requires %s as arguments"), action->type, action->arg_desc) < 0)
		buf[0] = '\0';
	usage(popt_context, EXIT_FAILURE, buf, poptGetInvocationName(popt_context));
}

static int run_action(struct action_type *action)
{
	int r;

	log_dbg("Running command %s.", action->type);

	set_int_handler(0);
	r = action->handler();

	/* Some functions returns keyslot # */
	if (r > 0)
		r = 0;
	check_signal(&r);

	show_status(r);
	return translate_errno(r);
}

static const char *verify_action(struct action_type *action)
{
	log_dbg("Verifying parameters for command %s.", action->type);

	return action->verify ? action->verify() : NULL;
}

static bool needs_size_conversion(unsigned arg_id)
{
	return (arg_id == OPT_DEVICE_SIZE_ID || arg_id == OPT_HOTZONE_SIZE_ID ||
		arg_id == OPT_LUKS2_KEYSLOTS_SIZE_ID || arg_id == OPT_LUKS2_METADATA_SIZE_ID ||
		arg_id == OPT_REDUCE_DEVICE_SIZE_ID);
}

static void check_key_slot_value(poptContext popt_context)
{
	if (ARG_INT32(OPT_KEY_SLOT_ID) < 0)
		usage(popt_context, EXIT_FAILURE, _("Key slot is invalid."),
		      poptGetInvocationName(popt_context));
}

static void basic_options_cb(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg,
		 void *data __attribute__((unused)))
{
	char buf[128];
	tools_parse_arg_value(popt_context, tool_core_args[key->val].type, tool_core_args + key->val, arg, key->val, needs_size_conversion);

	/* special cases additional handling */
	switch (key->val) {
	case OPT_DEBUG_JSON_ID:
		/* fall through */
	case OPT_DEBUG_ID:
		log_parms.debug = true;
		/* fall through */
	case OPT_VERBOSE_ID:
		log_parms.verbose = true;
		break;
	case OPT_DEVICE_SIZE_ID:
		if (ARG_UINT64(OPT_DEVICE_SIZE_ID) == 0)
			usage(popt_context, EXIT_FAILURE, poptStrerror(POPT_ERROR_BADNUMBER),
			      poptGetInvocationName(popt_context));
		if (ARG_UINT64(OPT_DEVICE_SIZE_ID) % SECTOR_SIZE)
			usage(popt_context, EXIT_FAILURE, _("Device size must be multiple of 512 bytes sector."),
			      poptGetInvocationName(popt_context));
		break;
	case OPT_HOTZONE_SIZE_ID:
		if (ARG_UINT64(OPT_HOTZONE_SIZE_ID) == 0)
			usage(popt_context, EXIT_FAILURE, _("Invalid max reencryption hotzone size specification."),
			      poptGetInvocationName(popt_context));
		break;
	case OPT_KEY_FILE_ID:
		if (tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID))) {
			free(keyfile_stdin);
			keyfile_stdin = strdup(ARG_STR(OPT_KEY_FILE_ID));
		} else if (keyfiles_count < MAX_KEYFILES)
			keyfiles[keyfiles_count++] = strdup(ARG_STR(OPT_KEY_FILE_ID));
		total_keyfiles++;
		break;
	case OPT_KEY_SIZE_ID:
		if (ARG_UINT32(OPT_KEY_SIZE_ID) % 8)
			usage(popt_context, EXIT_FAILURE,
			      _("Key size must be a multiple of 8 bits"),
			      poptGetInvocationName(popt_context));

		if (key_sizes_count < 2)
			key_sizes[key_sizes_count++] = ARG_UINT32(OPT_KEY_SIZE_ID);
		else {
			usage(popt_context, EXIT_FAILURE,
			      _("At most 2 key size specifications can be supplied."),
			      poptGetInvocationName(popt_context));
		}
		break;
	case OPT_INTEGRITY_KEY_SIZE_ID:
		if (ARG_UINT32(OPT_INTEGRITY_KEY_SIZE_ID) == 0)
			usage(popt_context, EXIT_FAILURE, poptStrerror(POPT_ERROR_BADNUMBER),
			      poptGetInvocationName(popt_context));
		if (ARG_UINT32(OPT_INTEGRITY_KEY_SIZE_ID) % 8)
			usage(popt_context, EXIT_FAILURE,
			      _("Key size must be a multiple of 8 bits"),
			      poptGetInvocationName(popt_context));
		break;
	case OPT_KEY_SLOT_ID:
		check_key_slot_value(popt_context);
		break;
	case OPT_KEYSLOT_KEY_SIZE_ID:
		if (ARG_UINT32(OPT_KEYSLOT_KEY_SIZE_ID) == 0)
			usage(popt_context, EXIT_FAILURE, poptStrerror(POPT_ERROR_BADNUMBER),
			      poptGetInvocationName(popt_context));
		if (ARG_UINT32(OPT_KEYSLOT_KEY_SIZE_ID) % 8)
			usage(popt_context, EXIT_FAILURE,
			      _("Key size must be a multiple of 8 bits"),
			      poptGetInvocationName(popt_context));
		break;
	case OPT_VOLUME_KEY_FILE_ID:
		if (vk_files_count < 2)
			vk_files[vk_files_count++] = strdup(ARG_STR(OPT_VOLUME_KEY_FILE_ID));
		else {
			if (snprintf(buf, sizeof(buf), _("At most %d volume key specifications can be supplied."), 2) < 0)
				buf[0] = '\0';
			usage(popt_context, EXIT_FAILURE,
			      buf,
			      poptGetInvocationName(popt_context));
		}
		break;
	case OPT_VOLUME_KEY_KEYRING_ID:
		if (vks_in_keyring_count < MAX_VK_IN_KEYRING)
			vks_in_keyring[vks_in_keyring_count++] = strdup(ARG_STR(OPT_VOLUME_KEY_KEYRING_ID));
		else {
			if (snprintf(buf, sizeof(buf), _("At most %d volume key specifications can be supplied."), MAX_KEYRING_LINKS) < 0)
				buf[0] = '\0';
			usage(popt_context, EXIT_FAILURE,
			      buf,
			      poptGetInvocationName(popt_context));
		}
		break;
	case OPT_LINK_VK_TO_KEYRING_ID:
		if (keyring_links_count < MAX_KEYRING_LINKS)
			keyring_links[keyring_links_count++] = strdup(ARG_STR(OPT_LINK_VK_TO_KEYRING_ID));
		else {

			if (snprintf(buf, sizeof(buf), _("At most %d keyring link specifications can be supplied."), MAX_KEYRING_LINKS) < 0)
				buf[0] = '\0';
			usage(popt_context, EXIT_FAILURE,
			      buf,
			      poptGetInvocationName(popt_context));
		}
		break;
	case OPT_REDUCE_DEVICE_SIZE_ID:
		if (ARG_UINT64(OPT_REDUCE_DEVICE_SIZE_ID) > 1024 * 1024 * 1024)
			usage(popt_context, EXIT_FAILURE, _("Maximum device reduce size is 1 GiB."),
			      poptGetInvocationName(popt_context));
		if (ARG_UINT64(OPT_REDUCE_DEVICE_SIZE_ID) % SECTOR_SIZE)
			usage(popt_context, EXIT_FAILURE, _("Reduce size must be multiple of 512 bytes sector."),
			      poptGetInvocationName(popt_context));
		data_shift = -(int64_t)ARG_UINT64(OPT_REDUCE_DEVICE_SIZE_ID);
		break;
	case OPT_SECTOR_SIZE_ID:
		if (ARG_UINT32(OPT_SECTOR_SIZE_ID) < SECTOR_SIZE ||
		    ARG_UINT32(OPT_SECTOR_SIZE_ID) > MAX_SECTOR_SIZE ||
		    (ARG_UINT32(OPT_SECTOR_SIZE_ID) & (ARG_UINT32(OPT_SECTOR_SIZE_ID) - 1)))
			usage(popt_context, EXIT_FAILURE,
			      _("Unsupported encryption sector size."),
			      poptGetInvocationName(popt_context));
		break;
	case OPT_PRIORITY_ID:
		if (strcmp(ARG_STR(OPT_PRIORITY_ID), "normal") &&
		    strcmp(ARG_STR(OPT_PRIORITY_ID), "prefer") &&
		    strcmp(ARG_STR(OPT_PRIORITY_ID), "ignore"))
			usage(popt_context, EXIT_FAILURE,
			_("Option --priority can be only ignore/normal/prefer."),
			poptGetInvocationName(popt_context));
		break;
	}
}

static void cryptsetup_init_arg_aliases(void)
{
	unsigned i;

	for (i = 1; i < ARRAY_SIZE(tool_core_args); i++)
		if (tool_core_args[i].type == CRYPT_ARG_ALIAS)
			ARG_INIT_ALIAS(i);
}

int main(int argc, const char **argv)
{
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		{ "version",'V', POPT_ARG_NONE,     NULL, 0, N_("Print package version"),  NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_basic_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, basic_options_cb, 0, NULL, NULL },
#define ARG(A, B, C, D, E, F, G, H) { A, B, C, NULL, A ## _ID, D, E },
#include "cryptsetup_arg_list.h"
#undef ARG
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options,  0, N_("Help options:"), NULL },
		{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, popt_basic_options, 0, NULL, NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;
	struct action_type *action;
	const char *aname, *error_message;
	int r;

	/* initialize aliases */
	cryptsetup_init_arg_aliases();

	crypt_set_log_callback(NULL, tool_log, &log_parms);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext(PACKAGE, argc, argv, popt_options, 0);
	if (!popt_context)
		exit(EXIT_FAILURE);

	poptSetOtherOptionHelp(popt_context,
	                       _("[OPTION...] <action> <action-specific>"));

	while ((r = poptGetNextOpt(popt_context)) > 0) {}

	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));

	if (!(aname = poptGetArg(popt_context)))
		usage(popt_context, EXIT_FAILURE, _("Argument <action> missing."),
		      poptGetInvocationName(popt_context));

	action_argc = 0;
	action_argv = poptGetArgs(popt_context);
	/* Make return values of poptGetArgs more consistent in case of remaining argc = 0 */
	if(!action_argv)
		action_argv = null_action_argv;

	/* Count args, somewhat unnice, change? */
	while(action_argv[action_argc] != NULL)
		action_argc++;

	/* Handle aliases */
	if (!strcmp(aname, "create")) {
		/* create command had historically switched arguments */
		if (action_argv[0] && action_argv[1]) {
			const char *tmp = action_argv[0];
			action_argv[0] = action_argv[1];
			action_argv[1] = tmp;
		}
		aname = OPEN_ACTION;
		device_type = "plain";
	} else if (!strcmp(aname, "plainOpen")) {
		aname = OPEN_ACTION;
		device_type = "plain";
	} else if (!strcmp(aname, "luksOpen")) {
		aname = OPEN_ACTION;
		device_type = "luks";
	} else if (!strcmp(aname, "loopaesOpen")) {
		aname = OPEN_ACTION;
		device_type = "loopaes";
	} else if (!strcmp(aname, "tcryptOpen")) {
		aname = OPEN_ACTION;
		device_type = "tcrypt";
	} else if (!strcmp(aname, "bitlkOpen")) {
		aname = OPEN_ACTION;
		device_type = "bitlk";
	} else if (!strcmp(aname, "fvault2Open")) {
		aname = OPEN_ACTION;
		device_type = "fvault2";
	} else if (!strcmp(aname, "tcryptDump")) {
		device_type = "tcrypt";
	} else if (!strcmp(aname, "bitlkDump")) {
		device_type = "bitlk";
	} else if (!strcmp(aname, "fvault2Dump")) {
		device_type = "fvault2";
	} else if (!strcmp(aname, "remove") ||
		   !strcmp(aname, "plainClose") ||
		   !strcmp(aname, "luksClose") ||
		   !strcmp(aname, "loopaesClose") ||
		   !strcmp(aname, "tcryptClose") ||
		   !strcmp(aname, "bitlkClose") ||
		   !strcmp(aname, "fvault2Close")) {
		aname = CLOSE_ACTION;
	} else if (!strcmp(aname, "luksErase")) {
		aname = ERASE_ACTION;
		if (ARG_SET(OPT_TYPE_ID))
			device_type = ARG_STR(OPT_TYPE_ID);
		else
			device_type = "luks";
	} else if (!strcmp(aname, "luksConfig")) {
		aname = CONFIG_ACTION;
		device_type = "luks2";
	} else if (!strcmp(aname, "refresh")) {
		aname = OPEN_ACTION;
		ARG_SET_TRUE(OPT_REFRESH_ID);
	} else if (ARG_SET(OPT_TYPE_ID))
		device_type = ARG_STR(OPT_TYPE_ID);

	/* ignore user supplied type and query device type instead */
	if (ARG_SET(OPT_REFRESH_ID))
		device_type = NULL;

	for(action = action_types; action->type; action++)
		if (strcmp(action->type, aname) == 0)
			break;

	if (!action->type)
		usage(popt_context, EXIT_FAILURE, _("Unknown action."),
		      poptGetInvocationName(popt_context));

	if (action_argc < action->required_action_argc)
		help_args(action, popt_context);

	/* this routine short circuits to exit() on error */
	tools_check_args(action->type, tool_core_args, ARRAY_SIZE(tool_core_args), popt_context);

	if (!strcmp(aname, KILLKEY_ACTION) && action_argc > 1) {
		ARG_SET_INT32(OPT_KEY_SLOT_ID, atoi(action_argv[1]));
		check_key_slot_value(popt_context);
	}

	if ((!strcmp(aname, REMOVEKEY_ACTION) ||
	     !strcmp(aname, FORMAT_ACTION)) &&
	     action_argc > 1) {
		if (ARG_SET(OPT_KEY_FILE_ID))
			log_err(_("Option --key-file takes precedence over specified key file argument."));
		else
			ARG_SET_STR(OPT_KEY_FILE_ID, strdup(action_argv[1]));
	}

	if (total_keyfiles > 1 && (strcmp_or_null(device_type, "tcrypt")))
		usage(popt_context, EXIT_FAILURE, _("Only one --key-file argument is allowed."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_PBKDF_ID) && crypt_parse_pbkdf(ARG_STR(OPT_PBKDF_ID), &set_pbkdf))
		usage(popt_context, EXIT_FAILURE,
		_("Password-based key derivation function (PBKDF) can be only pbkdf2 or argon2i/argon2id."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_PBKDF_FORCE_ITERATIONS_ID) && ARG_SET(OPT_ITER_TIME_ID))
		usage(popt_context, EXIT_FAILURE,
		_("PBKDF forced iterations cannot be combined with iteration time option."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_DISABLE_KEYRING_ID) && ARG_SET(OPT_LINK_VK_TO_KEYRING_ID))
		usage(popt_context, EXIT_FAILURE,
		_("Cannot link volume key to a keyring when keyring is disabled."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_DISABLE_KEYRING_ID) && (ARG_SET(OPT_KEY_DESCRIPTION_ID) || ARG_SET(OPT_NEW_KEY_DESCRIPTION_ID)))
		usage(popt_context, EXIT_FAILURE,
		_("Cannot use keyring key description when keyring is disabled."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_INTEGRITY_INLINE_ID) && !ARG_SET(OPT_INTEGRITY_ID))
		usage(popt_context, EXIT_FAILURE,
		_("Inline integrity must be used together with --integrity option."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_DEBUG_ID) || ARG_SET(OPT_DEBUG_JSON_ID)) {
		crypt_set_debug_level(ARG_SET(OPT_DEBUG_JSON_ID)? CRYPT_DEBUG_JSON : CRYPT_DEBUG_ALL);
		dbg_version_and_cmd(argc, argv);
	}

	/* reencrypt action specific check */

	if (ARG_SET(OPT_KEYSLOT_CIPHER_ID) != ARG_SET(OPT_KEYSLOT_KEY_SIZE_ID))
		usage(popt_context, EXIT_FAILURE, _("Options --keyslot-cipher and --keyslot-key-size must be used together."),
		      poptGetInvocationName(popt_context));

	error_message = verify_action(action);
	if (error_message)
		usage(popt_context, EXIT_FAILURE, error_message, poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_TEST_ARGS_ID)) {
		log_std(_("No action taken. Invoked with --test-args option.\n"));
		tools_cleanup();
		poptFreeContext(popt_context);
		return 0;
	}

	if (ARG_SET(OPT_DISABLE_KEYRING_ID))
		(void) crypt_volume_key_keyring(NULL, 0);

	if (ARG_SET(OPT_DISABLE_EXTERNAL_TOKENS_ID))
		(void) crypt_token_external_disable();

	if (ARG_SET(OPT_DISABLE_LOCKS_ID) && crypt_metadata_locking(NULL, 0)) {
		log_std(_("Cannot disable metadata locking."));
		r = EXIT_FAILURE;
	} else {
		r = run_action(action);
	}

	tools_cleanup();
	poptFreeContext(popt_context);
	return r;
}
