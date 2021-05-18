/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2021 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2021 Milan Broz
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

static char *keyfiles[MAX_KEYFILES];
static char *keyfile_stdin = NULL;

static int keyfiles_count = 0;
static int64_t data_shift = 0;

static const char *device_type = "luks";
static const char *set_pbkdf = NULL;

static const char **action_argv;
static int action_argc;
static const char *null_action_argv[] = {NULL, NULL};
static int total_keyfiles = 0;

static struct tools_log_params log_parms;

void tools_cleanup(void)
{
	tools_args_free(tool_core_args, ARRAY_SIZE(tool_core_args));

	FREE_AND_NULL(keyfile_stdin);

	while (keyfiles_count)
		free(keyfiles[--keyfiles_count]);

	total_keyfiles = 0;
}

static const char *uuid_or_device_header(const char **data_device)
{
	if (data_device)
		*data_device = ARG_SET(OPT_HEADER_ID) ? action_argv[0] : NULL;

	return uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[0]);
}

static const char *luksType(const char *type)
{
	if (type && !strcmp(type, "luks2"))
		return CRYPT_LUKS2;

	if (type && !strcmp(type, "luks1"))
		return CRYPT_LUKS1;

	if (type && !strcmp(type, "luks"))
		return CRYPT_LUKS; /* NULL */

	if (type && *type)
		return type;

	return CRYPT_LUKS; /* NULL */
}

static bool isLUKS1(const char *type)
{
	return type && !strcmp(type, CRYPT_LUKS1);
}

static bool isLUKS2(const char *type)
{
	return type && !strcmp(type, CRYPT_LUKS2);
}

static bool isLUKS(const char *type)
{
	return isLUKS2(type) || isLUKS1(type);
}

static int _verify_passphrase(int def)
{
	/* Batch mode switch off verify - if not overridden by -y */
	if (ARG_SET(OPT_VERIFY_PASSPHRASE_ID))
		def = 1;
	else if (ARG_SET(OPT_BATCH_MODE_ID))
		def = 0;

	/* Non-tty input doesn't allow verify */
	if (def && !isatty(STDIN_FILENO)) {
		if (ARG_SET(OPT_VERIFY_PASSPHRASE_ID))
			log_err(_("Can't do passphrase verification on non-tty inputs."));
		def = 0;
	}

	return def;
}

static void _set_activation_flags(uint32_t *flags)
{
	if (ARG_SET(OPT_READONLY_ID))
		*flags |= CRYPT_ACTIVATE_READONLY;

	if (ARG_SET(OPT_ALLOW_DISCARDS_ID))
		*flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

	if (ARG_SET(OPT_PERF_SAME_CPU_CRYPT_ID))
		*flags |= CRYPT_ACTIVATE_SAME_CPU_CRYPT;

	if (ARG_SET(OPT_PERF_SUBMIT_FROM_CRYPT_CPUS_ID))
		*flags |= CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS;

	if (ARG_SET(OPT_PERF_NO_READ_WORKQUEUE_ID))
		*flags |= CRYPT_ACTIVATE_NO_READ_WORKQUEUE;

	if (ARG_SET(OPT_PERF_NO_WRITE_WORKQUEUE_ID))
		*flags |= CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE;

	if (ARG_SET(OPT_INTEGRITY_NO_JOURNAL_ID))
		*flags |= CRYPT_ACTIVATE_NO_JOURNAL;

	/* In persistent mode, we use what is set on command line */
	if (ARG_SET(OPT_PERSISTENT_ID))
		*flags |= CRYPT_ACTIVATE_IGNORE_PERSISTENT;

	/* Only for LUKS2 but ignored elsewhere */
	if (ARG_SET(OPT_TEST_PASSPHRASE_ID))
		*flags |= CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY;

	if (ARG_SET(OPT_SERIALIZE_MEMORY_HARD_PBKDF_ID))
		*flags |= CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF;

	/* Only for plain */
	if (ARG_SET(OPT_IV_LARGE_SECTORS_ID))
		*flags |= CRYPT_ACTIVATE_IV_LARGE_SECTORS;
}

static void _set_reencryption_flags(uint32_t *flags)
{
	if (ARG_SET(OPT_INIT_ONLY_ID))
		*flags |= CRYPT_REENCRYPT_INITIALIZE_ONLY;

	if (ARG_SET(OPT_RESUME_ONLY_ID))
		*flags |= CRYPT_REENCRYPT_RESUME_ONLY;
}

static int _set_keyslot_encryption_params(struct crypt_device *cd)
{
	const char *type = crypt_get_type(cd);

	if (!ARG_SET(OPT_KEYSLOT_KEY_SIZE_ID) && !ARG_SET(OPT_KEYSLOT_CIPHER_ID))
		return 0;

	if (!isLUKS2(type)) {
		log_err(_("Keyslot encryption parameters can be set only for LUKS2 device."));
		return -EINVAL;
	}

	return crypt_keyslot_set_encryption(cd, ARG_STR(OPT_KEYSLOT_CIPHER_ID), ARG_UINT32(OPT_KEYSLOT_KEY_SIZE_ID) / 8);
}

static int _set_tries_tty(void)
{
	return (tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID)) && isatty(STDIN_FILENO)) ? ARG_UINT32(OPT_TRIES_ID) : 1;
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
		.size = ARG_UINT64(OPT_SIZE_ID),
		.sector_size = ARG_UINT32(OPT_SECTOR_SIZE_ID) ?: SECTOR_SIZE
	};
	char *password = NULL;
	const char *activated_name = NULL;
	size_t passwordLen, key_size_max, signatures = 0,
	       key_size = (ARG_UINT32(OPT_KEY_SIZE_ID) ?: DEFAULT_PLAIN_KEYBITS) / 8;
	uint32_t activate_flags = 0;
	int r;

	r = crypt_parse_name_and_mode(ARG_STR(OPT_CIPHER_ID) ?: DEFAULT_CIPHER(PLAIN),
				      cipher, NULL, cipher_mode);
	if (r < 0) {
		log_err(_("No known cipher specification pattern detected."));
		goto out;
	}

	/* FIXME: temporary hack, no hashing for keyfiles in plain mode */
	if (ARG_SET(OPT_KEY_FILE_ID) && !tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID))) {
		params.hash = NULL;
		if (!ARG_SET(OPT_BATCH_MODE_ID) && ARG_SET(OPT_HASH_ID))
			log_std(_("WARNING: The --hash parameter is being ignored "
				 "in plain mode with keyfile specified.\n"));
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
		if (!ARG_UINT64(OPT_OFFSET_ID)) {
			/* Print all present signatures in read-only mode */
			r = tools_detect_signatures(action_argv[0], 0, &signatures, ARG_SET(OPT_BATCH_MODE_ID));
			if (r < 0)
				goto out;
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

	_set_activation_flags(&activate_flags);

	if (!tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID))) {
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
				  _verify_passphrase(0), 0, cd);
		if (r < 0)
			goto out;

		r = crypt_activate_by_passphrase(cd, activated_name,
			CRYPT_ANY_SLOT, password, passwordLen, activate_flags);
	}
out:
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

	_set_activation_flags(&activate_flags);

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

	tries = _set_tries_tty();
	do {
		/* TCRYPT header is encrypted, get passphrase now */
		r = tools_get_key(NULL, CONST_CAST(char**)&params->passphrase,
				  &params->passphrase_size, 0, 0, keyfile_stdin, ARG_UINT32(OPT_TIMEOUT_ID),
				 _verify_passphrase(0), 0, cd);
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
					_verify_passphrase(0), 0, cd);
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
			 (ARG_SET(OPT_VERACRYPT_ID) ? CRYPT_TCRYPT_VERA_MODES : 0),
		.veracrypt_pim = ARG_UINT32(OPT_VERACRYPT_PIM_ID),
		.hash_name = ARG_STR(OPT_HASH_ID),
		.cipher = ARG_STR(OPT_CIPHER_ID),
	};
	const char *activated_name;
	uint32_t activate_flags = 0;
	int r;

	activated_name = ARG_SET(OPT_TEST_PASSPHRASE_ID) ? NULL : action_argv[1];

	r = crypt_init_data_device(&cd, ARG_STR(OPT_HEADER_ID) ?: action_argv[0], action_argv[0]);
	if (r < 0)
		goto out;

	r = tcrypt_load(cd, &params);
	if (r < 0)
		goto out;

	_set_activation_flags(&activate_flags);

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

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	r = crypt_load(cd, CRYPT_BITLK, NULL);
	if (r < 0) {
		log_err(_("Device %s is not a valid BITLK device."), action_argv[0]);
		goto out;
	}
	_set_activation_flags(&activate_flags);

	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		keysize = crypt_get_volume_key_size(cd);
		if (!keysize && !ARG_SET(OPT_KEY_SIZE_ID)) {
			log_err(_("Cannot determine volume key size for BITLK, please use --key-size option."));
			r = -EINVAL;
			goto out;
		} else if (!keysize)
			keysize = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;

		r = tools_read_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), &key, keysize);
		if (r < 0)
			goto out;
		r = crypt_activate_by_volume_key(cd, activated_name,
						 key, keysize, activate_flags);
	} else {
		tries = _set_tries_tty();
		do {
			r = tools_get_key(NULL, &password, &passwordLen,
					ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
					ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);
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
	unsigned i;
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

	for(i = 0; i < vk_size; i++) {
		if (i && !(i % 16))
			log_std("\n\t\t");
		log_std("%02hhx ", (char)vk[i]);
	}
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
			 (ARG_SET(OPT_VERACRYPT_ID) ? CRYPT_TCRYPT_VERA_MODES : 0),
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

	if (ARG_SET(OPT_DUMP_MASTER_KEY_ID))
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
	unsigned i;
	int r;

	if (!yesDialog(
	    _("The header dump with volume key is sensitive information\n"
	      "that allows access to encrypted partition without a passphrase.\n"
	      "This dump should be stored encrypted in a safe place."),
	      NULL))
		return -EPERM;

	vk_size = crypt_get_volume_key_size(cd);
	vk = crypt_safe_alloc(vk_size);
	if (!vk)
		return -ENOMEM;

	r = tools_get_key(NULL, &password, &passwordLen,
			  ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			  ARG_UINT32(OPT_TIMEOUT_ID), 0, 0, cd);
	if (r < 0)
		goto out;

	r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, vk, &vk_size,
				 password, passwordLen);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		r = tools_write_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), vk, vk_size);
		if (r < 0)
			goto out;
	}

	log_std("BITLK header information for %s\n", crypt_get_device_name(cd));
	log_std("Cipher name:   \t%s\n", crypt_get_cipher(cd));
	log_std("Cipher mode:   \t%s\n", crypt_get_cipher_mode(cd));
	log_std("UUID:          \t%s\n", crypt_get_uuid(cd));
	log_std("MK bits:       \t%d\n", (int)vk_size * 8);
	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		log_std("Key stored to file %s.\n", ARG_STR(OPT_MASTER_KEY_FILE_ID));
		goto out;
	}
	log_std("MK dump:\t");

	for(i = 0; i < vk_size; i++) {
		if (i && !(i % 16))
			log_std("\n\t\t");
		log_std("%02hhx ", (char)vk[i]);
	}
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
	if (r < 0)
		goto out;

	if (ARG_SET(OPT_DUMP_MASTER_KEY_ID))
		r = bitlkDump_with_volume_key(cd);
	else
		r = crypt_dump(cd);
out:
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

	r = crypt_init_by_name(&cd, action_argv[0]);
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
	size_t passwordLen;
	struct crypt_active_device cad;
	uint64_t dev_size = 0;
	char *password = NULL;
	struct crypt_device *cd = NULL;

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

	if (cad.flags & CRYPT_ACTIVATE_KEYRING_KEY) {
		if (ARG_SET(OPT_DISABLE_KEYRING_ID)) {
			r = -EINVAL;
			log_err(_("Resize of active device requires volume key "
				  "in keyring but --disable-keyring option is set."));
				goto out;
		}

		/* try load VK in kernel keyring using token */
		r = crypt_activate_by_token(cd, NULL, ARG_INT32(OPT_TOKEN_ID_ID), NULL,
					    CRYPT_ACTIVATE_KEYRING_KEY);
		tools_keyslot_msg(r, UNLOCKED);

		if (r >= 0 || ARG_SET(OPT_TOKEN_ONLY_ID))
			goto out;

		r = tools_get_key(NULL, &password, &passwordLen,
				  ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
				  ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);
		if (r < 0)
			goto out;

		r = crypt_activate_by_passphrase(cd, NULL, ARG_INT32(OPT_KEY_SLOT_ID),
						 password, passwordLen,
						 CRYPT_ACTIVATE_KEYRING_KEY);
		tools_passphrase_msg(r);
		tools_keyslot_msg(r, UNLOCKED);
	}

out:
	if (r >= 0)
		r = crypt_resize(cd, action_argv[0], dev_size);

	crypt_safe_free(password);
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
	int path = 0, r = 0;

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

		log_std("  cipher:  %s-%s\n", crypt_get_cipher(cd), crypt_get_cipher_mode(cd));
		log_std("  keysize: %d bits\n", crypt_get_volume_key_size(cd) * 8);
		log_std("  key location: %s\n", (cad.flags & CRYPT_ACTIVATE_KEYRING_KEY) ? "keyring" : "dm-crypt");
		if (ip.integrity)
			log_std("  integrity: %s\n", ip.integrity);
		if (ip.integrity_key_size)
			log_std("  integrity keysize: %d bits\n", ip.integrity_key_size * 8);
		device = crypt_get_device_name(cd);
		log_std("  device:  %s\n", device);
		if ((backing_file = crypt_loop_backing_file(device))) {
			log_std("  loop:    %s\n", backing_file);
			free(backing_file);
		}
		log_std("  sector size:  %d\n", crypt_get_sector_size(cd));
		log_std("  offset:  %" PRIu64 " sectors\n", cad.offset);
		log_std("  size:    %" PRIu64 " sectors\n", cad.size);
		if (cad.iv_offset)
			log_std("  skipped: %" PRIu64 " sectors\n", cad.iv_offset);
		log_std("  mode:    %s%s\n", cad.flags & CRYPT_ACTIVATE_READONLY ?
					   "readonly" : "read/write",
					   (cad.flags & CRYPT_ACTIVATE_SUSPENDED) ? " (suspended)" : "");
		if (cad.flags & (CRYPT_ACTIVATE_ALLOW_DISCARDS|
				 CRYPT_ACTIVATE_SAME_CPU_CRYPT|
				 CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS|
				 CRYPT_ACTIVATE_NO_READ_WORKQUEUE|
				 CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE))
			log_std("  flags:   %s%s%s%s%s\n",
				(cad.flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) ? "discards " : "",
				(cad.flags & CRYPT_ACTIVATE_SAME_CPU_CRYPT) ? "same_cpu_crypt " : "",
				(cad.flags & CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS) ? "submit_from_crypt_cpus " : "",
				(cad.flags & CRYPT_ACTIVATE_NO_READ_WORKQUEUE) ? "no_read_workqueue " : "",
				(cad.flags & CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE) ? "no_write_workqueue" : "");
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

		r = crypt_benchmark_pbkdf(NULL, &pbkdf, "foo", 3, "bar", 3, key_size,
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

		r = crypt_benchmark_pbkdf(NULL, &pbkdf, "foo", 3,
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
	int skipped = 0, width;
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
			width = strlen(cipher) + strlen(cipher_mode) + 1;
			if (width < 11)
				width = 11;
			/* TRANSLATORS: The string is header of a table and must be exactly (right side) aligned. */
			log_std(_("#%*s Algorithm |       Key |      Encryption |      Decryption\n"), width - 11, "");
			log_std("%*s-%s  %9db  %10.1f MiB/s  %10.1f MiB/s\n", width - (int)strlen(cipher_mode) - 1,
				cipher, cipher_mode, key_size*8, enc_mbr, dec_mbr);
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
#ifdef ENABLE_AF_ALG
		log_err( _("Ensure you have algif_skcipher kernel module loaded."));
#endif
	}
	return r;
}

static int set_pbkdf_params(struct crypt_device *cd, const char *dev_type)
{
	const struct crypt_pbkdf_type *pbkdf_default;
	struct crypt_pbkdf_type pbkdf = {};

	pbkdf_default = crypt_get_pbkdf_default(dev_type);
	if (!pbkdf_default)
		return -EINVAL;

	pbkdf.type = set_pbkdf ?: pbkdf_default->type;
	pbkdf.hash = ARG_STR(OPT_HASH_ID) ?: pbkdf_default->hash;
	pbkdf.time_ms = ARG_UINT32(OPT_ITER_TIME_ID) ?: pbkdf_default->time_ms;
	if (strcmp(pbkdf.type, CRYPT_KDF_PBKDF2)) {
		pbkdf.max_memory_kb = ARG_UINT32(OPT_PBKDF_MEMORY_ID) ?: pbkdf_default->max_memory_kb;
		pbkdf.parallel_threads = ARG_UINT32(OPT_PBKDF_PARALLEL_ID) ?: pbkdf_default->parallel_threads;
	}

	if (ARG_SET(OPT_PBKDF_FORCE_ITERATIONS_ID)) {
		pbkdf.iterations = ARG_UINT32(OPT_PBKDF_FORCE_ITERATIONS_ID);
		pbkdf.time_ms = 0;
		pbkdf.flags |= CRYPT_PBKDF_NO_BENCHMARK;
	}

	return crypt_set_pbkdf_type(cd, &pbkdf);
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

static int _do_luks2_reencrypt_recovery(struct crypt_device *cd)
{
	int r;
	size_t passwordLen;
	char *password = NULL;
	struct crypt_params_reencrypt recovery_params = {
		.flags = CRYPT_REENCRYPT_RECOVERY
	};

	crypt_reencrypt_info ri = crypt_reencrypt_status(cd, NULL);
	switch (ri) {
	case CRYPT_REENCRYPT_NONE:
		/* fall through */
	case CRYPT_REENCRYPT_CLEAN:
		if (ARG_SET(OPT_BATCH_MODE_ID) ||
		    !noDialog(_("Seems device does not require reencryption recovery.\n"
				"Do you want to proceed anyway?"), NULL))
			return 0;
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

	r = tools_get_key(_("Enter passphrase for reencryption recovery: "),
			  &password, &passwordLen, ARG_UINT64(OPT_KEYFILE_OFFSET_ID),
			  ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_TIMEOUT_ID),
			  _verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	r = crypt_activate_by_passphrase(cd, NULL, ARG_INT32(OPT_KEY_SLOT_ID),
					 password, passwordLen, 0);
	if (r < 0)
		goto out;

	r = crypt_reencrypt_init_by_passphrase(cd, NULL, password, passwordLen,
			ARG_INT32(OPT_KEY_SLOT_ID), ARG_INT32(OPT_KEY_SLOT_ID), NULL, NULL, &recovery_params);
	if (r > 0)
		r = 0;
out:
	crypt_safe_free(password);

	return r;
}

static int action_luksRepair(void)
{
	struct crypt_device *cd = NULL;
	int r;

	if ((r = crypt_init_data_device(&cd, ARG_STR(OPT_HEADER_ID) ?: action_argv[0],
					action_argv[0])))
		goto out;

	crypt_set_log_callback(cd, quiet_log, &log_parms);
	r = crypt_load(cd, luksType(device_type), NULL);
	crypt_set_log_callback(cd, tool_log, &log_parms);
	if (r == 0) {
		log_verbose(_("No known problems detected for LUKS header."));
		goto out;
	}

	r = tools_detect_signatures(action_argv[0], 1, NULL, ARG_SET(OPT_BATCH_MODE_ID));
	if (r < 0)
		goto out;

	if (!ARG_SET(OPT_BATCH_MODE_ID) &&
	    !yesDialog(_("Really try to repair LUKS device header?"),
		       _("Operation aborted.\n")))
		r = -EINVAL;
	else
		r = crypt_repair(cd, luksType(device_type), NULL);
out:
	/* Header is ok, check if possible interrupted reencryption need repairs. */
	if (!r && isLUKS2(crypt_get_type(cd)))
		r = _do_luks2_reencrypt_recovery(cd);

	crypt_free(cd);
	return r;
}

static int _wipe_data_device(struct crypt_device *cd)
{
	char tmp_name[64], tmp_path[128], tmp_uuid[40];
	uuid_t tmp_uuid_bin;
	int r;
	struct tools_progress_params prog_parms = {
		.frequency = ARG_UINT32(OPT_PROGRESS_FREQUENCY_ID),
		.batch_mode = ARG_SET(OPT_BATCH_MODE_ID)
	};

	if (!ARG_SET(OPT_BATCH_MODE_ID))
		log_std(_("Wiping device to initialize integrity checksum.\n"
			"You can interrupt this by pressing CTRL+c "
			"(rest of not wiped device will contain invalid checksum).\n"));

	/* Activate the device a temporary one */
	uuid_generate(tmp_uuid_bin);
	uuid_unparse(tmp_uuid_bin, tmp_uuid);
	if (snprintf(tmp_name, sizeof(tmp_name), "temporary-cryptsetup-%s", tmp_uuid) < 0)
		return -EINVAL;
	if (snprintf(tmp_path, sizeof(tmp_path), "%s/%s", crypt_get_dir(), tmp_name) < 0)
		return -EINVAL;

	r = crypt_activate_by_volume_key(cd, tmp_name, NULL, 0,
		CRYPT_ACTIVATE_PRIVATE | CRYPT_ACTIVATE_NO_JOURNAL);
	if (r < 0)
		return r;

	/* Wipe the device */
	set_int_handler(0);
	r = crypt_wipe(cd, tmp_path, CRYPT_WIPE_ZERO, 0, 0, DEFAULT_WIPE_BLOCK,
		       0, &tools_wipe_progress, &prog_parms);
	if (crypt_deactivate(cd, tmp_name))
		log_err(_("Cannot deactivate temporary device %s."), tmp_path);
	set_int_block(0);

	return r;
}

static int strcmp_or_null(const char *str, const char *expected)
{
	return !str ? 0 : strcmp(str, expected);
}

static int get_adjusted_key_size(const char *cipher_mode, uint32_t default_size_bits, int integrity_keysize)
{
	uint32_t keysize_bits = ARG_UINT32(OPT_KEY_SIZE_ID);

#ifdef ENABLE_LUKS_ADJUST_XTS_KEYSIZE
	if (!ARG_SET(OPT_KEY_SIZE_ID) && !strncmp(cipher_mode, "xts-", 4)) {
		if (default_size_bits == 128)
			keysize_bits = 256;
		else if (default_size_bits == 256)
			keysize_bits = 512;
	}
#endif
	return (keysize_bits ?: default_size_bits) / 8 + integrity_keysize;
}

static int _luksFormat(struct crypt_device **r_cd, char **r_password, size_t *r_passwordLen)
{
	int r = -EINVAL, keysize, integrity_keysize = 0, fd, created = 0;
	struct stat st;
	const char *header_device, *type;
	char *msg = NULL, *key = NULL, *password = NULL;
	char cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN], integrity[MAX_CIPHER_LEN];
	size_t passwordLen, signatures;
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
	void *params;

	type = luksType(device_type);
	if (!type)
		type = crypt_get_default_type();

	if (isLUKS2(type)) {
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
		r = crypt_parse_integrity_mode(ARG_STR(OPT_INTEGRITY_ID), integrity, &integrity_keysize);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			goto out;
		}
		params2.integrity = integrity;
		/* FIXME: we use default integrity_params (set to NULL) */
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
	r = tools_detect_signatures(header_device, 0, &signatures, ARG_SET(OPT_BATCH_MODE_ID));
	if (r < 0)
		goto out;

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

	keysize = get_adjusted_key_size(cipher_mode, DEFAULT_LUKS1_KEYBITS, integrity_keysize);

	if (ARG_SET(OPT_USE_RANDOM_ID))
		crypt_set_rng_type(cd, CRYPT_RNG_RANDOM);
	else if (ARG_SET(OPT_USE_URANDOM_ID))
		crypt_set_rng_type(cd, CRYPT_RNG_URANDOM);

	r = tools_get_key(NULL, &password, &passwordLen,
			  ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			  ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(1), !ARG_SET(OPT_FORCE_PASSWORD_ID), cd);
	if (r < 0)
		goto out;

	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		r = tools_read_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), &key, keysize);
		if (r < 0)
			goto out;
	}

	r = set_pbkdf_params(cd, type);
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	/* Signature candidates found */
	if (signatures && ((r =	tools_wipe_all_signatures(header_device)) < 0))
		goto out;

	if (ARG_SET(OPT_INTEGRITY_LEGACY_PADDING_ID))
		crypt_set_compatibility(cd, CRYPT_COMPAT_LEGACY_INTEGRITY_PADDING);

	r = crypt_format(cd, type, cipher, cipher_mode,
			 ARG_STR(OPT_UUID_ID), key, keysize, params);
	check_signal(&r);
	if (r < 0)
		goto out;

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	r = crypt_keyslot_add_by_volume_key(cd, ARG_INT32(OPT_KEY_SLOT_ID),
					    key, keysize,
					    password, passwordLen);
	if (r < 0) {
		(void) tools_wipe_all_signatures(header_device);
		goto out;
	}
	tools_keyslot_msg(r, CREATED);

	if (ARG_SET(OPT_INTEGRITY_ID) && !ARG_SET(OPT_INTEGRITY_NO_WIPE_ID) &&
	    strcmp_or_null(params2.integrity, "none"))
		r = _wipe_data_device(cd);
out:
	if (r >= 0 && r_cd && r_password && r_passwordLen) {
		*r_cd = cd;
		*r_password = password;
		*r_passwordLen = passwordLen;
	} else {
		crypt_free(cd);
		crypt_safe_free(password);
	}

	crypt_safe_free(key);

	return r;
}

static int action_luksFormat(void)
{
	return _luksFormat(NULL, NULL, NULL);
}

static int action_open_luks(void)
{
	struct crypt_active_device cad;
	struct crypt_device *cd = NULL;
	const char *data_device, *header_device, *activated_name;
	char *key = NULL;
	uint32_t activate_flags = 0;
	int r, keysize, tries;
	char *password = NULL;
	size_t passwordLen;

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
	}

	_set_activation_flags(&activate_flags);

	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		keysize = crypt_get_volume_key_size(cd);
		if (!keysize && !ARG_SET(OPT_KEY_SIZE_ID)) {
			log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --key-size option."));
			r = -EINVAL;
			goto out;
		} else if (!keysize)
			keysize = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;

		r = tools_read_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), &key, keysize);
		if (r < 0)
			goto out;
		r = crypt_activate_by_volume_key(cd, activated_name,
						 key, keysize, activate_flags);
	} else {
		r = crypt_activate_by_token(cd, activated_name, ARG_INT32(OPT_TOKEN_ID_ID), NULL, activate_flags);
		tools_keyslot_msg(r, UNLOCKED);

		/* Token requires PIN, but ask only there will be no password query later */
		if (ARG_SET(OPT_TOKEN_ONLY_ID) && r == -EAGAIN) {
			r = tools_get_key(_("Enter token PIN:"), &password, &passwordLen, 0, 0, NULL,
					ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);
			if (r < 0)
				goto out;
			r = crypt_activate_by_token_pin(cd, activated_name, NULL, ARG_INT32(OPT_TOKEN_ID_ID),
							password, passwordLen, NULL, activate_flags);
			tools_keyslot_msg(r, UNLOCKED);
		}

		if (r >= 0 || ARG_SET(OPT_TOKEN_ONLY_ID))
			goto out;

		tries = _set_tries_tty();
		do {
			r = tools_get_key(NULL, &password, &passwordLen,
					ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
					ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);
			if (r < 0)
				goto out;

			r = crypt_activate_by_passphrase(cd, activated_name,
				ARG_INT32(OPT_KEY_SLOT_ID), password, passwordLen, activate_flags);
			tools_keyslot_msg(r, UNLOCKED);
			tools_passphrase_msg(r);
			check_signal(&r);
			crypt_safe_free(password);
			password = NULL;
		} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
	}
out:
	if (r >= 0 && ARG_SET(OPT_PERSISTENT_ID) &&
	    (crypt_get_active_device(cd, activated_name, &cad) ||
	     crypt_persistent_flags_set(cd, CRYPT_FLAGS_ACTIVATION, cad.flags & activate_flags)))
		log_err(_("Device activated but cannot make flags persistent."));

	crypt_safe_free(key);
	crypt_safe_free(password);
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
			  _verify_passphrase(0), 0, cd);
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
		      _verify_passphrase(0), 0,
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

	keysize = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;
	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		r = tools_read_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), &key, keysize);
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
			  _verify_passphrase(1), !ARG_SET(OPT_FORCE_PASSWORD_ID), cd);
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

static int action_luksAddKey(void)
{
	int r = -EINVAL, keysize = 0;
	char *key = NULL;
	const char *new_key_file = (action_argc > 1 ? action_argv[1] : NULL);
	char *password = NULL, *password_new = NULL;
	size_t password_size = 0, password_new_size = 0;
	struct crypt_device *cd = NULL;

	/* Unbound keyslot (no assigned data segment) is special case */
	if (ARG_SET(OPT_UNBOUND_ID))
		return luksAddUnboundKey();

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

	keysize = crypt_get_volume_key_size(cd);
	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		if (!keysize && !ARG_SET(OPT_KEY_SIZE_ID)) {
			log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --key-size option."));
			r = -EINVAL;
			goto out;
		} else if (!keysize)
			keysize = ARG_UINT32(OPT_KEY_SIZE_ID) / 8;

		r = tools_read_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), &key, keysize);
		if (r < 0)
			goto out;

		r = crypt_volume_key_verify(cd, key, keysize);
		check_signal(&r);
		if (r < 0)
			goto out;

		r = tools_get_key(_("Enter new passphrase for key slot: "),
				  &password_new, &password_new_size,
				  ARG_UINT64(OPT_NEW_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_NEW_KEYFILE_SIZE_ID),
				  new_key_file, ARG_UINT32(OPT_TIMEOUT_ID),
				  _verify_passphrase(1), !ARG_SET(OPT_FORCE_PASSWORD_ID), cd);
		if (r < 0)
			goto out;

		r = crypt_keyslot_add_by_volume_key(cd, ARG_INT32(OPT_KEY_SLOT_ID), key, keysize,
						    password_new, password_new_size);
	} else if (ARG_SET(OPT_KEY_FILE_ID) && !tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID)) &&
		   new_key_file && !tools_is_stdin(new_key_file)) {
		r = crypt_keyslot_add_by_keyfile_device_offset(cd, ARG_INT32(OPT_KEY_SLOT_ID),
			ARG_STR(OPT_KEY_FILE_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_UINT64(OPT_KEYFILE_OFFSET_ID),
			new_key_file, ARG_UINT32(OPT_NEW_KEYFILE_SIZE_ID), ARG_UINT64(OPT_NEW_KEYFILE_OFFSET_ID));
		tools_passphrase_msg(r);
	} else {
		r = tools_get_key(_("Enter any existing passphrase: "),
			      &password, &password_size,
			      ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			      ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);

		if (r < 0)
			goto out;

		/* Check password before asking for new one */
		r = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT,
						 password, password_size, 0);
		check_signal(&r);
		tools_passphrase_msg(r);
		if (r < 0)
			goto out;
		tools_keyslot_msg(r, UNLOCKED);

		r = tools_get_key(_("Enter new passphrase for key slot: "),
				  &password_new, &password_new_size,
				  ARG_UINT64(OPT_NEW_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_NEW_KEYFILE_SIZE_ID), new_key_file,
				  ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(1), !ARG_SET(OPT_FORCE_PASSWORD_ID), cd);
		if (r < 0)
			goto out;

		r = crypt_keyslot_add_by_passphrase(cd, ARG_INT32(OPT_KEY_SLOT_ID),
						    password, password_size,
						    password_new, password_new_size);
	}
out:
	tools_keyslot_msg(r, CREATED);
	crypt_safe_free(password);
	crypt_safe_free(password_new);
	crypt_safe_free(key);
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
		      ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);
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
			  ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(1), !ARG_SET(OPT_FORCE_PASSWORD_ID), cd);
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
		log_err(_("Device %s is not a valid LUKS device."),
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
		      ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);
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
	char *vk = NULL, *password = NULL;
	size_t passwordLen = 0;
	size_t vk_size;
	unsigned i;
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

	r = tools_get_key(NULL, &password, &passwordLen,
			  ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			  ARG_UINT32(OPT_TIMEOUT_ID), 0, 0, cd);
	if (r < 0)
		goto out;

	r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, vk, &vk_size,
				 password, passwordLen);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		r = tools_write_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), vk, vk_size);
		if (r < 0)
			goto out;
	}

	log_std("LUKS header information for %s\n", crypt_get_device_name(cd));
	log_std("Cipher name:   \t%s\n", crypt_get_cipher(cd));
	log_std("Cipher mode:   \t%s\n", crypt_get_cipher_mode(cd));
	log_std("Payload offset:\t%d\n", (int)crypt_get_data_offset(cd));
	log_std("UUID:          \t%s\n", crypt_get_uuid(cd));
	log_std("MK bits:       \t%d\n", (int)vk_size * 8);
	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		log_std("Key stored to file %s.\n", ARG_STR(OPT_MASTER_KEY_FILE_ID));
		goto out;
	}
	log_std("MK dump:\t");

	for(i = 0; i < vk_size; i++) {
		if (i && !(i % 16))
			log_std("\n\t\t");
		log_std("%02hhx ", (char)vk[i]);
	}
	log_std("\n");

out:
	crypt_safe_free(password);
	crypt_safe_free(vk);
	return r;
}

static int luksDump_with_unbound_key(struct crypt_device *cd)
{
	crypt_keyslot_info ki;
	char *uk = NULL, *password = NULL;
	size_t uk_size, passwordLen = 0;
	int i, r;

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

	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		r = tools_write_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), uk, uk_size);
		if (r < 0)
			goto out;
	}

	log_std("LUKS header information for %s\n", crypt_get_device_name(cd));
	log_std("UUID:    \t%s\n", crypt_get_uuid(cd));
	log_std("Keyslot: \t%d\n", ARG_INT32(OPT_KEY_SLOT_ID));
	log_std("Key bits:\t%d\n", (int)uk_size * 8);
	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		log_std("Key stored to file %s.\n", ARG_STR(OPT_MASTER_KEY_FILE_ID));
		goto out;
	}
	log_std("Unbound Key:\t");

	for(i = 0; i < (int)uk_size; i++) {
		if (i && !(i % 16))
			log_std("\n\t\t");
		log_std("%02hhx ", (char)uk[i]);
	}
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

	if (ARG_SET(OPT_DUMP_MASTER_KEY_ID))
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
	char *password = NULL;
	size_t passwordLen;
	int r, tries;
	const char *req_type = luksType(device_type);

	if (req_type && !isLUKS(req_type))
		return -EINVAL;

	if ((r = crypt_init_by_name_and_header(&cd, action_argv[0], uuid_or_device(ARG_STR(OPT_HEADER_ID)))))
		return r;

	r = -EINVAL;
	if (!isLUKS(crypt_get_type(cd))) {
		log_err(_("%s is not active LUKS device name or header is missing."), action_argv[0]);
		goto out;
	}

	if (req_type && strcmp(req_type, crypt_get_type(cd))) {
		log_err(_("%s is not active %s device name."), action_argv[0], req_type);
		goto out;
	}

	tries = _set_tries_tty();
	do {
		r = tools_get_key(NULL, &password, &passwordLen,
			ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);
		if (r < 0)
			goto out;

		r = crypt_resume_by_passphrase(cd, action_argv[0], CRYPT_ANY_SLOT,
					       password, passwordLen);
		tools_passphrase_msg(r);
		check_signal(&r);
		tools_keyslot_msg(r, UNLOCKED);

		crypt_safe_free(password);
		password = NULL;
	} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
out:
	crypt_safe_free(password);
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
	} else
		r = -ENOENT;
out:
	if (r == -ENOENT)
		log_err(_("Unrecognized metadata device type %s."), device_type);
	else
		log_err(_("Command requires device and mapped name as arguments."));

	return r;
}

static int action_luksErase(void)
{
	struct crypt_device *cd = NULL;
	crypt_keyslot_info ki;
	char *msg = NULL;
	int i, max, r;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if ((r = crypt_load(cd, luksType(device_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	if(asprintf(&msg, _("This operation will erase all keyslots on device %s.\n"
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
		log_err(_("Device %s is not a valid LUKS device."),
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
		} else if (token_info > CRYPT_TOKEN_INACTIVE) {
			log_err(_("Token %d in use."), ARG_INT32(OPT_TOKEN_ID_ID));
			return -EINVAL;
		}
	}

	r = crypt_token_luks2_keyring_set(cd, ARG_INT32(OPT_TOKEN_ID_ID), &params);
	if (r < 0) {
		log_err(_("Failed to add luks2-keyring token %d."), ARG_INT32(OPT_TOKEN_ID_ID));
		return r;
	}

	token = r;

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
		} else if (token_info > CRYPT_TOKEN_INACTIVE) {
			log_err(_("Token %d in use."), ARG_INT32(OPT_TOKEN_ID_ID));
			return -EINVAL;
		}
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

static int action_token(void)
{
	int r;
	struct crypt_device *cd = NULL;

	if ((r = crypt_init(&cd, uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[1]))))
		return r;

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device(ARG_STR(OPT_HEADER_ID) ?: action_argv[1]));
		crypt_free(cd);
		return r;
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

	crypt_free(cd);

	return r;
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

	r = auto_detect_active_name(cd, action_argv[0], buffer, buffer_size);
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

static int action_reencrypt_load(struct crypt_device *cd)
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
			ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	if (!ARG_SET(OPT_ACTIVE_NAME_ID)) {
		r = _get_device_active_name(cd, action_argv[0], dm_name, sizeof(dm_name));
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

static int action_encrypt_luks2(struct crypt_device **cd)
{
	char *tmp;
	const char *type, *activated_name = NULL;
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
	if ((r = crypt_init(cd, action_argv[0])))
		return r;
	r = crypt_load(*cd, CRYPT_LUKS, NULL);
	crypt_free(*cd);
	*cd = NULL;
	if (!r && !ARG_SET(OPT_BATCH_MODE_ID)) {
		r = asprintf(&msg, _("Detected LUKS device on %s. Do you want to encrypt that LUKS device again?"), action_argv[0]);
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
			log_err("LUKS2 metadata size is larger than data shift value.");
			return -EINVAL;
		}
	}

	r = _luksFormat(cd, &password, &passwordLen);
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

		r = crypt_init(cd, action_argv[0]);
		if (!r)
			r = crypt_header_restore(*cd, CRYPT_LUKS2, header_file);

		if (r) {
			log_err("Failed to place new header at head of device %s.", action_argv[0]);
			goto out;
		}
	}

	/* activate device */
	if (action_argc > 1) {
		activated_name = action_argv[1];
		_set_activation_flags(&activate_flags);
		r = crypt_activate_by_passphrase(*cd, activated_name, ARG_INT32(OPT_KEY_SLOT_ID), password, passwordLen, activate_flags);
		if (r >= 0)
			log_std(_("%s/%s is now active and ready for online encryption.\n"), crypt_get_dir(), activated_name);
	}

	if (r < 0)
		goto out;

	/* just load reencryption context to continue reencryption */
	if (!ARG_SET(OPT_INIT_ONLY_ID)) {
		params.flags &= ~CRYPT_REENCRYPT_INITIALIZE_ONLY;
		r = crypt_reencrypt_init_by_passphrase(*cd, activated_name, password, passwordLen,
				CRYPT_ANY_SLOT, keyslot, NULL, NULL, &params);
	}
out:
	crypt_safe_free(password);
	if (*header_file)
		unlink(header_file);
	return r;
}

static int action_decrypt_luks2(struct crypt_device *cd)
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

	if (!crypt_get_metadata_device_name(cd) || crypt_header_is_detached(cd) <= 0) {
		log_err(_("LUKS2 decryption is supported with detached header device only."));
		return -ENOTSUP;
	}

	_set_reencryption_flags(&params.flags);

	r = tools_get_key(NULL, &password, &passwordLen,
			ARG_UINT64(OPT_KEYFILE_OFFSET_ID), ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
			ARG_UINT32(OPT_TIMEOUT_ID), _verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	if (!ARG_SET(OPT_ACTIVE_NAME_ID)) {
		r = _get_device_active_name(cd, action_argv[0], dm_name, sizeof(dm_name));
		if (r > 0)
			active_name = dm_name;
		if (r < 0)
			goto out;
	} else
		active_name = ARG_STR(OPT_ACTIVE_NAME_ID);

	if (!active_name)
		log_dbg("Device %s seems unused. Proceeding with offline operation.", action_argv[0]);

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

	retry_count = _set_tries_tty();

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

static int _check_luks2_keyslots(struct crypt_device *cd)
{
	int i, max = crypt_keyslot_max(CRYPT_LUKS2), active = 0, unbound = 0;

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

	/* at least one keyslot for reencryption plus new volume key */
	if (active + unbound > max - 2) {
		log_err(_("Not enough free keyslots for reencryption."));
		return -EINVAL;
	}

	if ((ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT) &&
            (2 * active + unbound > max - 1)) {
		log_err(_("Not enough free keyslots for reencryption."));
		return -EINVAL;
	}

	return 0;
}

static int fill_keyslot_passwords(struct crypt_device *cd,
		struct keyslot_passwords *kp, size_t kp_size)
{
	char msg[128];
	crypt_keyslot_info ki;
	int i, r = 0;

	if (ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT && ARG_SET(OPT_KEY_FILE_ID)) {
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

static int action_reencrypt_luks2(struct crypt_device *cd)
{
	size_t i, vk_size, kp_size;
	int r, keyslot_old = CRYPT_ANY_SLOT, keyslot_new = CRYPT_ANY_SLOT, key_size;
	char dm_name[PATH_MAX], cipher [MAX_CIPHER_LEN], mode[MAX_CIPHER_LEN], *vk = NULL;
	const char *active_name = NULL;
	struct keyslot_passwords *kp;
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

	if (!ARG_SET(OPT_CIPHER_ID) && crypt_is_cipher_null(crypt_get_cipher(cd))) {
		log_std(_("Switching data encryption cipher to %s.\n"), DEFAULT_CIPHER(LUKS1));
		ARG_SET_STR(OPT_CIPHER_ID, strdup(DEFAULT_CIPHER(LUKS1)));
	}

	if (!ARG_SET(OPT_CIPHER_ID)) {
		strncpy(cipher, crypt_get_cipher(cd), MAX_CIPHER_LEN - 1);
		strncpy(mode, crypt_get_cipher_mode(cd), MAX_CIPHER_LEN - 1);
		cipher[MAX_CIPHER_LEN-1] = '\0';
		mode[MAX_CIPHER_LEN-1] = '\0';
	} else if ((r = crypt_parse_name_and_mode(ARG_STR(OPT_CIPHER_ID), cipher, NULL, mode))) {
		log_err(_("No known cipher specification pattern detected."));
		return r;
	}

	luks2_params.sector_size = ARG_UINT32(OPT_SECTOR_SIZE_ID) ?: (uint32_t)crypt_get_sector_size(cd);

	r = _check_luks2_keyslots(cd);
	if (r)
		return r;

	if (ARG_SET(OPT_KEY_SIZE_ID) || ARG_SET(OPT_CIPHER_ID))
		key_size = get_adjusted_key_size(mode, DEFAULT_LUKS1_KEYBITS, 0);
	else
		key_size = crypt_get_volume_key_size(cd);

	if (!key_size)
		return -EINVAL;
	vk_size = key_size;

	r = crypt_keyslot_max(CRYPT_LUKS2);
	if (r < 0)
		return r;
	kp_size = r;
	kp = init_keyslot_passwords(kp_size);

	if (!kp)
		return -ENOMEM;

	r = fill_keyslot_passwords(cd, kp, kp_size);
	if (r)
		goto out;

	if (ARG_SET(OPT_MASTER_KEY_FILE_ID)) {
		r = tools_read_mk(ARG_STR(OPT_MASTER_KEY_FILE_ID), &vk, key_size);
		if (r < 0)
			goto out;
	}

	r = -ENOENT;

	for (i = 0; i < kp_size; i++) {
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
		r = _get_device_active_name(cd, action_argv[0], dm_name, sizeof(dm_name));
		if (r > 0)
			active_name = dm_name;
		if (r < 0)
			goto out;
	} else if (ARG_SET(OPT_ACTIVE_NAME_ID))
		active_name = ARG_STR(OPT_ACTIVE_NAME_ID);

	if (!active_name && !ARG_SET(OPT_INIT_ONLY_ID))
		log_dbg("Device %s seems unused. Proceeding with offline operation.", action_argv[0]);

	r = crypt_reencrypt_init_by_passphrase(cd, active_name, kp[keyslot_old].password,
			kp[keyslot_old].passwordLen, keyslot_old, kp[keyslot_old].new,
			cipher, mode, &params);
out:
	crypt_safe_free(vk);
	for (i = 0; i < kp_size; i++) {
		crypt_safe_free(kp[i].password);
		if (r < 0 && kp[i].new >= 0 &&
		    crypt_reencrypt_status(cd, NULL) == CRYPT_REENCRYPT_NONE &&
		    crypt_keyslot_destroy(cd, kp[i].new))
			log_dbg("Failed to remove keyslot %d with unbound key.", kp[i].new);
	}
	free(kp);
	return r;
}

static int action_reencrypt(void)
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
			r = action_reencrypt_load(cd);
	} else if (!r && ARG_SET(OPT_RESUME_ONLY_ID)) {
		log_err(_("LUKS2 device is not in reencryption."));
		r = -EINVAL;
	} else if (ARG_SET(OPT_DECRYPT_ID))
		r = action_decrypt_luks2(cd);
	else if (ARG_SET(OPT_ENCRYPT_ID) && !ARG_SET(OPT_RESUME_ONLY_ID))
		r = action_encrypt_luks2(&cd);
	else
		r = action_reencrypt_luks2(cd);

	if (r >= 0 && !ARG_SET(OPT_INIT_ONLY_ID)) {
		set_int_handler(0);
		r = crypt_reencrypt(cd, tools_reencrypt_progress, &prog_parms);
	}
out:
	crypt_free(cd);

	return r;
}

static struct action_type {
	const char *type;
	int (*handler)(void);
	int required_action_argc;
	int required_memlock;
	const char *arg_desc;
	const char *desc;
} action_types[] = {
	{ OPEN_ACTION,		action_open,		1, 1, N_("<device> [--type <type>] [<name>]"),N_("open device as <name>") },
	{ CLOSE_ACTION,		action_close,		1, 1, N_("<name>"), N_("close device (remove mapping)") },
	{ RESIZE_ACTION,	action_resize,		1, 1, N_("<name>"), N_("resize active device") },
	{ STATUS_ACTION,	action_status,		1, 0, N_("<name>"), N_("show device status") },
	{ BENCHMARK_ACTION,	action_benchmark,	0, 0, N_("[--cipher <cipher>]"), N_("benchmark cipher") },
	{ REPAIR_ACTION,	action_luksRepair,	1, 1, N_("<device>"), N_("try to repair on-disk metadata") },
	{ REENCRYPT_ACTION,	action_reencrypt,	0, 0, N_("<device>"), N_("reencrypt LUKS2 device") },
	{ ERASE_ACTION,		action_luksErase,	1, 1, N_("<device>"), N_("erase all keyslots (remove encryption key)") },
	{ CONVERT_ACTION,	action_luksConvert,	1, 1, N_("<device>"), N_("convert LUKS from/to LUKS2 format") },
	{ CONFIG_ACTION,	action_luksConfig,	1, 1, N_("<device>"), N_("set permanent configuration options for LUKS2") },
	{ FORMAT_ACTION,	action_luksFormat,	1, 1, N_("<device> [<new key file>]"), N_("formats a LUKS device") },
	{ ADDKEY_ACTION,	action_luksAddKey,	1, 1, N_("<device> [<new key file>]"), N_("add key to LUKS device") },
	{ REMOVEKEY_ACTION,	action_luksRemoveKey,	1, 1, N_("<device> [<key file>]"), N_("removes supplied key or key file from LUKS device") },
	{ CHANGEKEY_ACTION,	action_luksChangeKey,	1, 1, N_("<device> [<key file>]"), N_("changes supplied key or key file of LUKS device") },
	{ CONVERTKEY_ACTION,	action_luksConvertKey,	1, 1, N_("<device> [<key file>]"), N_("converts a key to new pbkdf parameters") },
	{ KILLKEY_ACTION,	action_luksKillSlot,	2, 1, N_("<device> <key slot>"), N_("wipes key with number <key slot> from LUKS device") },
	{ UUID_ACTION,		action_luksUUID,	1, 0, N_("<device>"), N_("print UUID of LUKS device") },
	{ ISLUKS_ACTION,	action_isLuks,		1, 0, N_("<device>"), N_("tests <device> for LUKS partition header") },
	{ LUKSDUMP_ACTION,	action_luksDump,	1, 1, N_("<device>"), N_("dump LUKS partition information") },
	{ TCRYPTDUMP_ACTION,	action_tcryptDump,	1, 1, N_("<device>"), N_("dump TCRYPT device information") },
	{ BITLKDUMP_ACTION,	action_bitlkDump,	1, 1, N_("<device>"), N_("dump BITLK device information") },
	{ SUSPEND_ACTION,	action_luksSuspend,	1, 1, N_("<device>"), N_("Suspend LUKS device and wipe key (all IOs are frozen)") },
	{ RESUME_ACTION,	action_luksResume,	1, 1, N_("<device>"), N_("Resume suspended LUKS device") },
	{ HEADERBACKUP_ACTION,	action_luksBackup,	1, 1, N_("<device>"), N_("Backup LUKS device header and keyslots") },
	{ HEADERRESTORE_ACTION,	action_luksRestore,	1, 1, N_("<device>"), N_("Restore LUKS device header and keyslots") },
	{ TOKEN_ACTION,		action_token,		2, 0, N_("<add|remove|import|export> <device>"), N_("Manipulate LUKS2 tokens") },
	{}
};

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	if (key->shortName == '?') {
		struct action_type *action;
		const struct crypt_pbkdf_type *pbkdf_luks1, *pbkdf_luks2;

		log_std("%s\n",PACKAGE_STRING);

		poptPrintHelp(popt_context, stdout, 0);

		log_std(_("\n"
			 "<action> is one of:\n"));

		for(action = action_types; action->type; action++)
			log_std("\t%s %s - %s\n", action->type, _(action->arg_desc), _(action->desc));

		log_std(_("\n"
			  "You can also use old <action> syntax aliases:\n"
			  "\topen: create (plainOpen), luksOpen, loopaesOpen, tcryptOpen, bitlkOpen\n"
			  "\tclose: remove (plainClose), luksClose, loopaesClose, tcryptClose, bitlkClose\n"));
		log_std(_("\n"
			 "<name> is the device to create under %s\n"
			 "<device> is the encrypted device\n"
			 "<key slot> is the LUKS key slot number to modify\n"
			 "<key file> optional key file for the new key for luksAddKey action\n"),
			crypt_get_dir());

		log_std(_("\nDefault compiled-in metadata format is %s (for luksFormat action).\n"),
			  crypt_get_default_type());

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
#if defined(ENABLE_LUKS_ADJUST_XTS_KEYSIZE) && DEFAULT_LUKS1_KEYBITS != 512
		log_std(_("\tLUKS: Default keysize with XTS mode (two internal keys) will be doubled.\n"));
#endif
		tools_cleanup();
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else if (key->shortName == 'V') {
		log_std("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
		tools_cleanup();
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else
		usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

static void help_args(struct action_type *action, poptContext popt_context)
{
	char buf[128];

	snprintf(buf, sizeof(buf), _("%s: requires %s as arguments"), action->type, action->arg_desc);
	usage(popt_context, EXIT_FAILURE, buf, poptGetInvocationName(popt_context));
}

static int run_action(struct action_type *action)
{
	int r;

	log_dbg("Running command %s.", action->type);

	if (action->required_memlock)
		crypt_memory_lock(NULL, 1);

	set_int_handler(0);
	r = action->handler();

	if (action->required_memlock)
		crypt_memory_lock(NULL, 0);

	/* Some functions returns keyslot # */
	if (r > 0)
		r = 0;
	check_signal(&r);

	show_status(r);
	return translate_errno(r);
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
#undef arg
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options,  0, N_("Help options:"), NULL },
		{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, popt_basic_options, 0, NULL, NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;
	struct action_type *action;
	const char *aname;
	int r;

	crypt_set_log_callback(NULL, tool_log, &log_parms);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext(PACKAGE, argc, argv, popt_options, 0);
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
	} else if (!strcmp(aname, "tcryptDump")) {
		device_type = "tcrypt";
	} else if (!strcmp(aname, "bitlkDump")) {
		device_type = "bitlk";
	} else if (!strcmp(aname, "remove") ||
		   !strcmp(aname, "plainClose") ||
		   !strcmp(aname, "luksClose") ||
		   !strcmp(aname, "loopaesClose") ||
		   !strcmp(aname, "tcryptClose") ||
		   !strcmp(aname, "bitlkClose")) {
		aname = CLOSE_ACTION;
	} else if (!strcmp(aname, "luksErase")) {
		aname = ERASE_ACTION;
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

	if (ARG_SET(OPT_REFRESH_ID) && ARG_SET(OPT_TEST_PASSPHRASE_ID))
		usage(popt_context, EXIT_FAILURE,
		      _("Options --refresh and --test-passphrase are mutually exclusive."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_CANCEL_DEFERRED_ID) && ARG_SET(OPT_DEFERRED_ID))
		usage(popt_context, EXIT_FAILURE,
		      _("Options --cancel-deferred and --deferred cannot be used at the same time."),
		      poptGetInvocationName(popt_context));

	/* open action specific check */
	if (ARG_SET(OPT_SHARED_ID) && strcmp_or_null(device_type, "plain"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --shared is allowed only for open of plain device."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_PERSISTENT_ID) && ARG_SET(OPT_TEST_PASSPHRASE_ID))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --persistent is not allowed with --test-passphrase."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_INTEGRITY_NO_WIPE_ID) && !ARG_SET(OPT_INTEGRITY_ID))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --integrity-no-wipe"
		        " can be used only for format action with integrity extension."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_TEST_PASSPHRASE_ID) && (strcmp(aname, OPEN_ACTION) || !device_type ||
	    (strncmp(device_type, "luks", 4) && strcmp(device_type, "tcrypt") && strcmp(device_type, "bitlk"))))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --test-passphrase is allowed only for open of LUKS, TCRYPT and BITLK devices."),
		      poptGetInvocationName(popt_context));

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

	if (ARG_SET(OPT_USE_RANDOM_ID) && ARG_SET(OPT_USE_URANDOM_ID))
		usage(popt_context, EXIT_FAILURE, _("Only one of --use-[u]random options is allowed."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_ALIGN_PAYLOAD_ID) && ARG_SET(OPT_OFFSET_ID))
		usage(popt_context, EXIT_FAILURE, _("Options --align-payload and --offset cannot be combined."),
		      poptGetInvocationName(popt_context));

	/* open action specific check */
	if (ARG_SET(OPT_SKIP_ID) && strcmp_or_null(device_type, "plain") && strcmp(device_type, "loopaes"))
		usage(popt_context, EXIT_FAILURE,
		_("Option --skip is supported only for open of plain and loopaes devices."),
		poptGetInvocationName(popt_context));

	/* open action specific check */
	if (ARG_SET(OPT_OFFSET_ID) && !strcmp(aname, OPEN_ACTION) && strcmp_or_null(device_type, "plain") && strcmp(device_type, "loopaes"))
		usage(popt_context, EXIT_FAILURE,
		_("Option --offset with open action is only supported for plain and loopaes devices."),
		poptGetInvocationName(popt_context));

	/* open action specific check */
	if ((ARG_SET(OPT_TCRYPT_HIDDEN_ID) || ARG_SET(OPT_TCRYPT_SYSTEM_ID) || ARG_SET(OPT_TCRYPT_BACKUP_ID)) && !strcmp(aname, OPEN_ACTION) && (!device_type || strcmp(device_type, "tcrypt")))
		usage(popt_context, EXIT_FAILURE,
		_("Option --tcrypt-hidden, --tcrypt-system or --tcrypt-backup is supported only for TCRYPT device."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_TCRYPT_HIDDEN_ID) && ARG_SET(OPT_ALLOW_DISCARDS_ID))
		usage(popt_context, EXIT_FAILURE,
		_("Option --tcrypt-hidden cannot be combined with --allow-discards."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_VERACRYPT_ID) && (!device_type || strcmp(device_type, "tcrypt")))
		usage(popt_context, EXIT_FAILURE,
		_("Option --veracrypt is supported only for TCRYPT device type."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_VERACRYPT_PIM_ID) && !ARG_SET(OPT_VERACRYPT_ID))
		usage(popt_context, EXIT_FAILURE,
		_("Option --veracrypt-pim is supported only for VeraCrypt compatible devices."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_VERACRYPT_QUERY_PIM_ID)) {
		if (!ARG_SET(OPT_VERACRYPT_ID)) {
			usage(popt_context, EXIT_FAILURE,
			_("Option --veracrypt-query-pim is supported only for VeraCrypt compatible devices."),
			poptGetInvocationName(popt_context));
		} else if (ARG_SET(OPT_VERACRYPT_PIM_ID)) {
			usage(popt_context, EXIT_FAILURE,
			_("The options --veracrypt-pim and --veracrypt-query-pim are mutually exclusive."),
			poptGetInvocationName(popt_context));
		}
	}

	/* config action specific check */
	if (!strcmp(aname, CONFIG_ACTION) && ARG_SET(OPT_PRIORITY_ID) && ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT)
		usage(popt_context, EXIT_FAILURE,
		_("Keyslot specification is required."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_PBKDF_ID) && crypt_parse_pbkdf(ARG_STR(OPT_PBKDF_ID), &set_pbkdf))
		usage(popt_context, EXIT_FAILURE,
		_("Password-based key derivation function (PBKDF) can be only pbkdf2 or argon2i/argon2id."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_PBKDF_FORCE_ITERATIONS_ID) && ARG_SET(OPT_ITER_TIME_ID))
		usage(popt_context, EXIT_FAILURE,
		_("PBKDF forced iterations cannot be combined with iteration time option."),
		poptGetInvocationName(popt_context));

	/* open action specific check */
	if (ARG_SET(OPT_SECTOR_SIZE_ID) && !strcmp(aname, OPEN_ACTION) &&
	    (!device_type || strcmp(device_type, "plain")))
		usage(popt_context, EXIT_FAILURE,
		      _("Sector size option with open action is supported only for plain devices."),
		      poptGetInvocationName(popt_context));

	/* open action specific check */
	if (ARG_SET(OPT_IV_LARGE_SECTORS_ID) && (!device_type || strcmp(device_type, "plain") ||
	    ARG_UINT32(OPT_SECTOR_SIZE_ID) <= SECTOR_SIZE))
		usage(popt_context, EXIT_FAILURE,
		      _("Large IV sectors option is supported only for opening plain type device with sector size larger than 512 bytes."),
		      poptGetInvocationName(popt_context));

	/* luksAddKey action specific check */
	if (ARG_SET(OPT_UNBOUND_ID) && !ARG_UINT32(OPT_KEY_SIZE_ID) && !strcmp(aname, ADDKEY_ACTION))
		usage(popt_context, EXIT_FAILURE,
		      _("Key size is required with --unbound option."),
		      poptGetInvocationName(popt_context));

	/* luksDump action specific check */
	if (ARG_SET(OPT_UNBOUND_ID) && ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT && !strcmp(aname, LUKSDUMP_ACTION))
		usage(popt_context, EXIT_FAILURE,
		      _("Keyslot specification is required."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_DEBUG_ID) || ARG_SET(OPT_DEBUG_JSON_ID)) {
		crypt_set_debug_level(ARG_SET(OPT_DEBUG_JSON_ID)? CRYPT_DEBUG_JSON : CRYPT_DEBUG_ALL);
		dbg_version_and_cmd(argc, argv);
	}

	/* reencrypt action specific check */
	if (ARG_SET(OPT_DECRYPT_ID) && !ARG_SET(OPT_HEADER_ID))
		usage(popt_context, EXIT_FAILURE, _("LUKS2 decryption requires option --header."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_REDUCE_DEVICE_SIZE_ID) && ARG_SET(OPT_DEVICE_SIZE_ID))
		usage(popt_context, EXIT_FAILURE, _("Options --reduce-device-size and --data-size cannot be combined."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_DEVICE_SIZE_ID) && ARG_SET(OPT_SIZE_ID))
		usage(popt_context, EXIT_FAILURE, _("Options --device-size and --size cannot be combined."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_KEYSLOT_CIPHER_ID) != ARG_SET(OPT_KEYSLOT_KEY_SIZE_ID))
		usage(popt_context, EXIT_FAILURE, _("Options --keyslot-cipher and --keyslot-key-size must be used together."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_TEST_ARGS_ID)) {
		log_std(_("No action taken. Invoked with --test-args option.\n"));
		tools_cleanup();
		poptFreeContext(popt_context);
		return 0;
	}

	/* token action specific check */
	if (!strcmp(aname, TOKEN_ACTION)) {
		if (strcmp(action_argv[0], "add") &&
		    strcmp(action_argv[0], "remove") &&
		    strcmp(action_argv[0], "import") &&
		    strcmp(action_argv[0], "export"))
			usage(popt_context, EXIT_FAILURE, _("Invalid token action."),
			      poptGetInvocationName(popt_context));

		if (!ARG_SET(OPT_KEY_DESCRIPTION_ID) && !strcmp(action_argv[0], "add"))
			usage(popt_context, EXIT_FAILURE,
			      _("--key-description parameter is mandatory for token add action."),
			      poptGetInvocationName(popt_context));

		if (ARG_INT32(OPT_TOKEN_ID_ID) == CRYPT_ANY_TOKEN &&
		    (!strcmp(action_argv[0], "remove") || !strcmp(action_argv[0], "export")))
			usage(popt_context, EXIT_FAILURE,
			      _("Action requires specific token. Use --token-id parameter."),
			      poptGetInvocationName(popt_context));
	}

	if (ARG_SET(OPT_DISABLE_KEYRING_ID))
		(void) crypt_volume_key_keyring(NULL, 0);

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
