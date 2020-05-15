/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2020 Milan Broz
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

#include "cryptsetup.h"
#include <uuid/uuid.h>

static const char *opt_cipher = NULL;
static const char *opt_keyslot_cipher = NULL;
static const char *opt_hash = NULL;
static int opt_verify_passphrase = 0;

static const char *opt_json_file = NULL;
static const char *opt_key_file = NULL;
static const char *opt_keyfile_stdin = NULL;
static int opt_keyfiles_count = 0;
static const char *opt_keyfiles[MAX_KEYFILES];

static const char *opt_master_key_file = NULL;
static const char *opt_header_backup_file = NULL;
static const char *opt_uuid = NULL;
static const char *opt_header_device = NULL;
static const char *opt_type = "luks";
static int opt_key_size = 0;
static int opt_keyslot_key_size = 0;
static long opt_keyfile_size = 0;
static long opt_new_keyfile_size = 0;
static uint64_t opt_keyfile_offset = 0;
static uint64_t opt_new_keyfile_offset = 0;
static int opt_key_slot = CRYPT_ANY_SLOT;
static int opt_token = CRYPT_ANY_TOKEN;
static int opt_token_only = 0;
static uint64_t opt_size = 0;
static uint64_t opt_offset = 0;
static uint64_t opt_skip = 0;
static int opt_skip_valid = 0;
static int opt_readonly = 0;
static int opt_timeout = 0;
static int opt_tries = 3;
static int opt_align_payload = 0;
static int opt_random = 0;
static int opt_urandom = 0;
static int opt_dump_master_key = 0;
static int opt_shared = 0;
static int opt_allow_discards = 0;
static int opt_perf_same_cpu_crypt = 0;
static int opt_perf_submit_from_crypt_cpus = 0;
static int opt_test_passphrase = 0;
static int opt_tcrypt_hidden = 0;
static int opt_tcrypt_system = 0;
static int opt_tcrypt_backup = 0;
static int opt_veracrypt = 0;
static int opt_veracrypt_pim = -1;
static int opt_veracrypt_query_pim = 0;
static int opt_deferred_remove = 0;
static int opt_serialize_memory_hard_pbkdf = 0;
//FIXME: check uint32 overflow for long type
static const char *opt_pbkdf = NULL;
static long opt_pbkdf_memory = DEFAULT_LUKS2_MEMORY_KB;
static long opt_pbkdf_parallel = DEFAULT_LUKS2_PARALLEL_THREADS;
static long opt_pbkdf_iterations = 0;
static int opt_iteration_time = 0;
static int opt_disable_locks = 0;
static int opt_disable_keyring = 0;
static const char *opt_priority = NULL; /* normal */
static const char *opt_integrity = NULL; /* none */
static int opt_integrity_nojournal = 0;
static int opt_integrity_no_wipe = 0;
static int opt_integrity_legacy_padding = 0;
static const char *opt_key_description = NULL;
static int opt_sector_size = 0;
static int opt_iv_large_sectors = 0;
static int opt_persistent = 0;
static const char *opt_label = NULL;
static const char *opt_subsystem = NULL;
static int opt_unbound = 0;
static int opt_refresh = 0;

/* LUKS2 reencryption parameters */
static const char *opt_active_name = NULL;
static const char *opt_resilience_mode = "checksum"; // TODO: default resilience
static const char *opt_resilience_hash = "sha256"; // TODO: default checksum hash
static int opt_encrypt = 0;
static int opt_reencrypt_init_only = 0;
static int opt_reencrypt_resume_only = 0;
static int opt_decrypt = 0;

static const char *opt_reduce_size_str = NULL;
static uint64_t opt_reduce_size = 0;

static const char *opt_hotzone_size_str = NULL;
static uint64_t opt_hotzone_size = 0;

static const char *opt_device_size_str = NULL;
static uint64_t opt_device_size = 0;

/* do not set from command line, use helpers above */
static int64_t opt_data_shift;

static const char *opt_luks2_metadata_size_str = NULL;
static uint64_t opt_luks2_metadata_size = 0;
static const char *opt_luks2_keyslots_size_str = NULL;
static uint64_t opt_luks2_keyslots_size = 0;

static const char **action_argv;
static int action_argc;
static const char *null_action_argv[] = {NULL, NULL};

static const char *uuid_or_device_header(const char **data_device)
{
	if (data_device)
		*data_device = opt_header_device ? action_argv[0] : NULL;

	return uuid_or_device(opt_header_device ?: action_argv[0]);
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

static int _verify_passphrase(int def)
{
	/* Batch mode switch off verify - if not overridden by -y */
	if (opt_verify_passphrase)
		def = 1;
	else if (opt_batch_mode)
		def = 0;

	/* Non-tty input doesn't allow verify */
	if (def && !isatty(STDIN_FILENO)) {
		if (opt_verify_passphrase)
			log_err(_("Can't do passphrase verification on non-tty inputs."));
		def = 0;
	}

	return def;
}

static void _set_activation_flags(uint32_t *flags)
{
	if (opt_readonly)
		*flags |= CRYPT_ACTIVATE_READONLY;

	if (opt_allow_discards)
		*flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

	if (opt_perf_same_cpu_crypt)
		*flags |= CRYPT_ACTIVATE_SAME_CPU_CRYPT;

	if (opt_perf_submit_from_crypt_cpus)
		*flags |= CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS;

	if (opt_integrity_nojournal)
		*flags |= CRYPT_ACTIVATE_NO_JOURNAL;

	/* In persistent mode, we use what is set on command line */
	if (opt_persistent)
		*flags |= CRYPT_ACTIVATE_IGNORE_PERSISTENT;

	/* Only for LUKS2 but ignored elsewhere */
	if (opt_test_passphrase)
		*flags |= CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY;

	if (opt_serialize_memory_hard_pbkdf)
		*flags |= CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF;

	/* Only for plain */
	if (opt_iv_large_sectors)
		*flags |= CRYPT_ACTIVATE_IV_LARGE_SECTORS;
}

static void _set_reencryption_flags(uint32_t *flags)
{
	if (opt_reencrypt_init_only)
		*flags |= CRYPT_REENCRYPT_INITIALIZE_ONLY;

	if (opt_reencrypt_resume_only)
		*flags |= CRYPT_REENCRYPT_RESUME_ONLY;
}

static int _set_keyslot_encryption_params(struct crypt_device *cd)
{
	const char *type = crypt_get_type(cd);

	if (!opt_keyslot_key_size && !opt_keyslot_cipher)
		return 0;

	if (!type || strcmp(type, CRYPT_LUKS2)) {
		log_err(_("Keyslot encryption parameters can be set only for LUKS2 device."));
		return -EINVAL;
	}

	return crypt_keyslot_set_encryption(cd, opt_keyslot_cipher, opt_keyslot_key_size / 8);
}

static int action_open_plain(void)
{
	struct crypt_device *cd = NULL, *cd1 = NULL;
	const char *pcipher, *pmode;
	char *msg, cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	struct crypt_active_device cad;
	struct crypt_params_plain params = {
		.hash = opt_hash ?: DEFAULT_PLAIN_HASH,
		.skip = opt_skip,
		.offset = opt_offset,
		.size = opt_size,
		.sector_size = opt_sector_size ?: SECTOR_SIZE
	};
	char *password = NULL;
	const char *activated_name = NULL;
	size_t passwordLen, key_size_max, signatures = 0,
	       key_size = (opt_key_size ?: DEFAULT_PLAIN_KEYBITS) / 8;
	uint32_t activate_flags = 0;
	int r;

	r = crypt_parse_name_and_mode(opt_cipher ?: DEFAULT_CIPHER(PLAIN),
				      cipher, NULL, cipher_mode);
	if (r < 0) {
		log_err(_("No known cipher specification pattern detected."));
		goto out;
	}

	/* FIXME: temporary hack, no hashing for keyfiles in plain mode */
	if (opt_key_file && !tools_is_stdin(opt_key_file)) {
		params.hash = NULL;
		if (!opt_batch_mode && opt_hash)
			log_std(_("WARNING: The --hash parameter is being ignored "
				 "in plain mode with keyfile specified.\n"));
	}

	if (params.hash && !strcmp(params.hash, "plain"))
		params.hash = NULL;

	if (!opt_batch_mode && !params.hash && opt_key_file && !tools_is_stdin(opt_key_file) && opt_keyfile_size)
		log_std(_("WARNING: The --keyfile-size option is being ignored, "
			 "the read size is the same as the encryption key size.\n"));

	if (opt_refresh) {
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
		if (!opt_offset) {
			/* Print all present signatures in read-only mode */
			r = tools_detect_signatures(action_argv[0], 0, &signatures);
			if (r < 0)
				goto out;
		}

		if (signatures) {
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

	if (opt_shared)
		activate_flags |= CRYPT_ACTIVATE_SHARED;

	_set_activation_flags(&activate_flags);

	if (!tools_is_stdin(opt_key_file)) {
		/* If no hash, key is read directly, read size is always key_size
		 * (possible opt_keyfile_size is ignored.
		 * If hash is specified, opt_keyfile_size is applied.
		 * The opt_keyfile_offset is applied always.
		 */
		key_size_max = params.hash ? (size_t)opt_keyfile_size : key_size;
		r = crypt_activate_by_keyfile_device_offset(cd, action_argv[1],
			CRYPT_ANY_SLOT, opt_key_file, key_size_max,
			opt_keyfile_offset, activate_flags);
	} else {
		key_size_max = (opt_key_file && !params.hash) ? key_size : (size_t)opt_keyfile_size;
		r = tools_get_key(NULL, &password, &passwordLen,
				  opt_keyfile_offset, key_size_max,
				  opt_key_file, opt_timeout,
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
		.hash = opt_hash ?: NULL,
		.offset = opt_offset,
		.skip = opt_skip_valid ? opt_skip : opt_offset,
	};
	unsigned int key_size = (opt_key_size ?: DEFAULT_LOOPAES_KEYBITS) / 8;
	uint32_t activate_flags = 0;
	const char *activated_name = NULL;
	int r;

	if (!opt_key_file) {
		log_err(_("Option --key-file is required."));
		return -EINVAL;
	}

	if (opt_refresh) {
		activated_name = action_argc > 1 ? action_argv[1] : action_argv[0];
		if ((r = crypt_init_by_name(&cd, activated_name)))
			goto out;
		activate_flags |= CRYPT_ACTIVATE_REFRESH;
	} else {
		activated_name = action_argv[1];
		if ((r = crypt_init(&cd, action_argv[0])))
			goto out;

		r = crypt_format(cd, CRYPT_LOOPAES, opt_cipher ?: DEFAULT_LOOPAES_CIPHER,
				 NULL, NULL, NULL, key_size, &params);
		check_signal(&r);
		if (r < 0)
			goto out;
	}

	_set_activation_flags(&activate_flags);

	r = crypt_activate_by_keyfile_device_offset(cd, activated_name, CRYPT_ANY_SLOT,
		tools_is_stdin(opt_key_file) ? "/dev/stdin" : opt_key_file, opt_keyfile_size,
		opt_keyfile_offset, activate_flags);
out:
	crypt_free(cd);

	return r;
}

static int tcrypt_load(struct crypt_device *cd, struct crypt_params_tcrypt *params)
{
	int r, tries = opt_tries, eperm = 0;

	if (opt_keyfile_stdin)
		tries = 1;

	do {
		/* TCRYPT header is encrypted, get passphrase now */
		r = tools_get_key(NULL, CONST_CAST(char**)&params->passphrase,
				  &params->passphrase_size, 0, 0, opt_keyfile_stdin, opt_timeout,
				 _verify_passphrase(0), 0, cd);
		if (r < 0)
			continue;

		if (opt_veracrypt_query_pim) {
			char *tmp_pim_nptr = NULL;
			char *tmp_pim_end = NULL;
			size_t tmp_pim_size = 0;
			unsigned long long tmp_pim_ull = 0;

			r = tools_get_key(_("Enter VeraCrypt PIM: "),
					CONST_CAST(char**)&tmp_pim_nptr,
					&tmp_pim_size, 0, 0, opt_keyfile_stdin, opt_timeout,
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
			crypt_safe_free(CONST_CAST(char*)tmp_pim_nptr);
			if (r < 0)
				continue;

			params->veracrypt_pim = (uint32_t)tmp_pim_ull;
			crypt_safe_memzero(&tmp_pim_ull, sizeof(tmp_pim_ull));
		}

		if (opt_tcrypt_hidden)
			params->flags |= CRYPT_TCRYPT_HIDDEN_HEADER;

		if (opt_tcrypt_system)
			params->flags |= CRYPT_TCRYPT_SYSTEM_HEADER;

		if (opt_tcrypt_backup)
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
		.keyfiles = opt_keyfiles,
		.keyfiles_count = opt_keyfiles_count,
		.flags = CRYPT_TCRYPT_LEGACY_MODES |
			 (opt_veracrypt ? CRYPT_TCRYPT_VERA_MODES : 0),
		.veracrypt_pim = (opt_veracrypt_pim > 0) ? opt_veracrypt_pim : 0,
	};
	const char *activated_name;
	uint32_t activate_flags = 0;
	int r;

	activated_name = opt_test_passphrase ? NULL : action_argv[1];

	if ((r = crypt_init(&cd, action_argv[0])))
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
	int r, tries;
	char *password = NULL;
	size_t passwordLen;

	activated_name = opt_test_passphrase ? NULL : action_argv[1];

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	r = crypt_load(cd, CRYPT_BITLK, NULL);
	if (r < 0) {
		log_err(_("Device %s is not a valid BITLK device."), action_argv[0]);
		goto out;
	}
	_set_activation_flags(&activate_flags);

	tries = (tools_is_stdin(opt_key_file) && isatty(STDIN_FILENO)) ? opt_tries : 1;
	do {
		r = tools_get_key(NULL, &password, &passwordLen,
				opt_keyfile_offset, opt_keyfile_size, opt_key_file,
				opt_timeout, _verify_passphrase(0), 0, cd);
		if (r < 0)
			goto out;

		r = crypt_activate_by_passphrase(cd, activated_name, CRYPT_ANY_SLOT,
						 password, passwordLen, activate_flags);
		tools_passphrase_msg(r);
		check_signal(&r);
		crypt_safe_free(password);
		password = NULL;
	} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
out:
	crypt_safe_free(password);
	crypt_free(cd);
	return r;
}

static int tcryptDump_with_volume_key(struct crypt_device *cd)
{
	char *vk = NULL;
	size_t vk_size;
	unsigned i;
	int r;

	crypt_set_confirm_callback(cd, yesDialog, NULL);
	if (!yesDialog(
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
		.keyfiles = opt_keyfiles,
		.keyfiles_count = opt_keyfiles_count,
		.flags = CRYPT_TCRYPT_LEGACY_MODES |
			 (opt_veracrypt ? CRYPT_TCRYPT_VERA_MODES : 0),
		.veracrypt_pim = (opt_veracrypt_pim > 0) ? opt_veracrypt_pim : 0,
	};
	int r;

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	r = tcrypt_load(cd, &params);
	if (r < 0)
		goto out;

	if (opt_dump_master_key)
		r = tcryptDump_with_volume_key(cd);
	else
		r = crypt_dump(cd);
out:
	crypt_free(cd);
	crypt_safe_free(CONST_CAST(char*)params.passphrase);
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

	if (opt_deferred_remove)
		flags |= CRYPT_DEACTIVATE_DEFERRED;

	r = crypt_init_by_name(&cd, action_argv[0]);
	if (r == 0)
		r = crypt_deactivate_by_name(cd, action_argv[0], flags);

	if (!r && opt_deferred_remove) {
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
	char *password = NULL;
	struct crypt_device *cd = NULL;

	r = crypt_init_by_name_and_header(&cd, action_argv[0], opt_header_device);
	if (r)
		goto out;

	/* FIXME: LUKS2 may enforce fixed size and it must not be changed */
	r = crypt_get_active_device(cd, action_argv[0], &cad);
	if (r)
		goto out;

	if (cad.flags & CRYPT_ACTIVATE_KEYRING_KEY) {
		if (opt_disable_keyring) {
			r = -EINVAL;
			log_err(_("Resize of active device requires volume key "
				  "in keyring but --disable-keyring option is set."));
				goto out;
		}

		/* try load VK in kernel keyring using token */
		r = crypt_activate_by_token(cd, NULL, opt_token, NULL,
					    CRYPT_ACTIVATE_KEYRING_KEY);
		tools_keyslot_msg(r, UNLOCKED);
		if (r < 0 && opt_token_only)
			goto out;

		r = tools_get_key(NULL, &password, &passwordLen,
				  opt_keyfile_offset, opt_keyfile_size, opt_key_file,
				  opt_timeout, _verify_passphrase(0), 0, cd);
		if (r < 0)
			goto out;

		r = crypt_activate_by_passphrase(cd, NULL, opt_key_slot,
						 password, passwordLen,
						 CRYPT_ACTIVATE_KEYRING_KEY);
		tools_passphrase_msg(r);
		tools_keyslot_msg(r, UNLOCKED);
		crypt_safe_free(password);
	}

	if (opt_device_size)
		opt_size = opt_device_size / SECTOR_SIZE;

	if (r >= 0)
		r = crypt_resize(cd, action_argv[0], opt_size);
out:
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

		r = crypt_init_by_name_and_header(&cd, action_argv[0], opt_header_device);
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
				 CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS))
			log_std("  flags:   %s%s%s\n",
				(cad.flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) ? "discards " : "",
				(cad.flags & CRYPT_ACTIVATE_SAME_CPU_CRYPT) ? "same_cpu_crypt " : "",
				(cad.flags & CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS) ? "submit_from_crypt_cpus" : "");
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
			.time_ms = opt_iteration_time ?: DEFAULT_LUKS2_ITER_TIME,
			.max_memory_kb = opt_pbkdf_memory,
			.parallel_threads = opt_pbkdf_parallel,
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
	int key_size = (opt_key_size ?: DEFAULT_PLAIN_KEYBITS) / 8;
	int skipped = 0, width;
	char *c;
	int i, r;

	log_std(_("# Tests are approximate using memory only (no storage IO).\n"));
	if (opt_pbkdf || opt_hash) {
		if (!opt_pbkdf && opt_hash)
			opt_pbkdf = CRYPT_KDF_PBKDF2;
		r = action_benchmark_kdf(opt_pbkdf, opt_hash, key_size);
	} else if (opt_cipher) {
		r = crypt_parse_name_and_mode(opt_cipher, cipher, NULL, cipher_mode);
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
			log_err(_("Cipher %s (with %i bits key) is not available."), opt_cipher, key_size * 8);
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

			snprintf(cipher, MAX_CIPHER_LEN, "%s-%s",
				 bciphers[i].cipher, bciphers[i].mode);
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

	pbkdf.type = opt_pbkdf ?: pbkdf_default->type;
	pbkdf.hash = opt_hash ?: pbkdf_default->hash;
	pbkdf.time_ms = (uint32_t)opt_iteration_time ?: pbkdf_default->time_ms;
	if (strcmp(pbkdf.type, CRYPT_KDF_PBKDF2)) {
		pbkdf.max_memory_kb = (uint32_t)opt_pbkdf_memory ?: pbkdf_default->max_memory_kb;
		pbkdf.parallel_threads = (uint32_t)opt_pbkdf_parallel ?: pbkdf_default->parallel_threads;
	}

	if (opt_pbkdf_iterations) {
		pbkdf.iterations = opt_pbkdf_iterations;
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

	if (crypt_keyslot_set_encryption(cd, cipher, key_size))
		return -EINVAL;

	/* if requested any of those just reinitialize context pbkdf */
	if (opt_pbkdf || opt_hash || opt_pbkdf_iterations || opt_iteration_time)
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
		r = noDialog(_("Seems device does not require reencryption recovery.\n"
				"Do you want to proceed anyway?"), NULL);
		if (!r)
			return 0;
		break;
	case CRYPT_REENCRYPT_CRASH:
		r = yesDialog(_("Really proceed with LUKS2 reencryption recovery?"),
			      _("Operation aborted.\n"));
		if (!r)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	r = tools_get_key(_("Enter passphrase for reencryption recovery: "),
			  &password, &passwordLen, opt_keyfile_offset,
			  opt_keyfile_size, opt_key_file, opt_timeout,
			  _verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	r = crypt_activate_by_passphrase(cd, NULL, opt_key_slot,
					 password, passwordLen, 0);
	if (r < 0)
		goto out;

	r = crypt_reencrypt_init_by_passphrase(cd, NULL, password, passwordLen,
			opt_key_slot, opt_key_slot, NULL, NULL, &recovery_params);
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

	if ((r = crypt_init_data_device(&cd, opt_header_device ?: action_argv[0],
					action_argv[0])))
		goto out;

	crypt_set_log_callback(cd, quiet_log, NULL);
	r = crypt_load(cd, luksType(opt_type), NULL);
	crypt_set_log_callback(cd, tool_log, NULL);
	if (r == 0) {
		log_verbose(_("No known problems detected for LUKS header."));
		goto skip_repair;
	}

	r = tools_detect_signatures(action_argv[0], 1, NULL);
	if (r < 0)
		goto out;

	r = yesDialog(_("Really try to repair LUKS device header?"),
		       _("Operation aborted.\n")) ? 0 : -EINVAL;
	if (r == 0)
		r = crypt_repair(cd, luksType(opt_type), NULL);
skip_repair:
	if (!r && crypt_get_type(cd) && !strcmp(crypt_get_type(cd), CRYPT_LUKS2))
		r = _do_luks2_reencrypt_recovery(cd);
out:
	crypt_free(cd);
	return r;
}

static int _wipe_data_device(struct crypt_device *cd)
{
	char tmp_name[64], tmp_path[128], tmp_uuid[40];
	uuid_t tmp_uuid_bin;
	int r;

	if (!opt_batch_mode)
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
		       0, &tools_wipe_progress, NULL);
	if (crypt_deactivate(cd, tmp_name))
		log_err(_("Cannot deactivate temporary device %s."), tmp_path);
	set_int_block(0);

	return r;
}

static int strcmp_or_null(const char *str, const char *expected)
{
	return !str ? 0 : strcmp(str, expected);
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
		.hash = opt_hash ?: DEFAULT_LUKS1_HASH,
		.data_alignment = opt_align_payload,
		.data_device = opt_header_device ? action_argv[0] : NULL,
	};
	struct crypt_params_luks2 params2 = {
		.data_alignment = params1.data_alignment,
		.data_device = params1.data_device,
		.sector_size = opt_sector_size ?: SECTOR_SIZE,
		.label = opt_label,
		.subsystem = opt_subsystem
	};
	void *params;

	type = luksType(opt_type);
	if (!type)
		type = crypt_get_default_type();

	if (!strcmp(type, CRYPT_LUKS2)) {
		params = &params2;
	} else if (!strcmp(type, CRYPT_LUKS1)) {
		params = &params1;

		if (opt_sector_size > SECTOR_SIZE) {
			log_err(_("Unsupported encryption sector size."));
			return -EINVAL;
		}

		if (opt_integrity) {
			log_err(_("Integrity option can be used only for LUKS2 format."));
			return -EINVAL;
		}

		if (opt_luks2_keyslots_size || opt_luks2_metadata_size) {
			log_err(_("Unsupported LUKS2 metadata size options."));
			return -EINVAL;
		}
	} else
		return -EINVAL;

	/* Create header file (must contain at least one sector)? */
	if (opt_header_device && stat(opt_header_device, &st) < 0 && errno == ENOENT) {
		if (!opt_batch_mode &&
		    !yesDialog("Header file does not exist, do you want to create it?",
			    _("Operation aborted.\n")))
		    return -EPERM;

		log_dbg("Creating header file.");
		/* coverity[toctou] */
		fd = open(opt_header_device, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
		if (fd == -1 || posix_fallocate(fd, 0, 4096))
			log_err(_("Cannot create header file %s."), opt_header_device);
		else {
			r = 0;
			created = 1;
		}
		if (fd != -1)
			close(fd);
		if (r < 0)
			return r;
	}

	header_device = opt_header_device ?: action_argv[0];

	r = crypt_parse_name_and_mode(opt_cipher ?: DEFAULT_CIPHER(LUKS1),
				      cipher, NULL, cipher_mode);
	if (r < 0) {
		log_err(_("No known cipher specification pattern detected."));
		goto out;
	}

	if (opt_integrity) {
		r = crypt_parse_integrity_mode(opt_integrity, integrity, &integrity_keysize);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			goto out;
		}
		params2.integrity = integrity;
		/* FIXME: we use default integrity_params (set to NULL) */
	}

	/* Never call pwquality if using null cipher */
	if (tools_is_cipher_null(cipher))
		opt_force_password = 1;

	if ((r = crypt_init(&cd, header_device))) {
		if (opt_header_device)
			log_err(_("Cannot use %s as on-disk header."), header_device);
		return r;
	}

	if (opt_luks2_keyslots_size || opt_luks2_metadata_size) {
		r = crypt_set_metadata_size(cd, opt_luks2_metadata_size, opt_luks2_keyslots_size);
		if (r < 0) {
			log_err(_("Unsupported LUKS2 metadata size options."));
			goto out;
		}
	}

	if (opt_offset) {
		r = crypt_set_data_offset(cd, opt_offset);
		if (r < 0)
			goto out;
	}

	/* Print all present signatures in read-only mode */
	r = tools_detect_signatures(header_device, 0, &signatures);
	if (r < 0)
		goto out;

	if (!created) {
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

#ifdef ENABLE_LUKS_ADJUST_XTS_KEYSIZE
	if (!opt_key_size && !strncmp(cipher_mode, "xts-", 4)) {
		if (DEFAULT_LUKS1_KEYBITS == 128)
			opt_key_size = 256;
		else if (DEFAULT_LUKS1_KEYBITS == 256)
			opt_key_size = 512;
	}
#endif
	keysize = (opt_key_size ?: DEFAULT_LUKS1_KEYBITS) / 8 + integrity_keysize;

	if (opt_random)
		crypt_set_rng_type(cd, CRYPT_RNG_RANDOM);
	else if (opt_urandom)
		crypt_set_rng_type(cd, CRYPT_RNG_URANDOM);

	r = tools_get_key(NULL, &password, &passwordLen,
			  opt_keyfile_offset, opt_keyfile_size, opt_key_file,
			  opt_timeout, _verify_passphrase(1), 1, cd);
	if (r < 0)
		goto out;

	if (opt_master_key_file) {
		r = tools_read_mk(opt_master_key_file, &key, keysize);
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

	if (opt_integrity_legacy_padding)
		crypt_set_compatibility(cd, CRYPT_COMPAT_LEGACY_INTEGRITY_PADDING);

	r = crypt_format(cd, type, cipher, cipher_mode,
			 opt_uuid, key, keysize, params);
	check_signal(&r);
	if (r < 0)
		goto out;

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	r = crypt_keyslot_add_by_volume_key(cd, opt_key_slot,
					    key, keysize,
					    password, passwordLen);
	if (r < 0) {
		(void) tools_wipe_all_signatures(header_device);
		goto out;
	}
	tools_keyslot_msg(r, CREATED);

	if (opt_integrity && !opt_integrity_no_wipe &&
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

	if (opt_refresh) {
		activated_name = action_argc > 1 ? action_argv[1] : action_argv[0];
		r = crypt_init_by_name_and_header(&cd, activated_name, opt_header_device);
		if (r)
			goto out;
		activate_flags |= CRYPT_ACTIVATE_REFRESH;
	} else {
		header_device = uuid_or_device_header(&data_device);

		activated_name = opt_test_passphrase ? NULL : action_argv[1];

		if ((r = crypt_init_data_device(&cd, header_device, data_device)))
			goto out;

		if ((r = crypt_load(cd, luksType(opt_type), NULL))) {
			log_err(_("Device %s is not a valid LUKS device."),
				header_device);
			goto out;
		}

		if (!data_device && (crypt_get_data_offset(cd) < 8) && !opt_test_passphrase) {
			log_err(_("Reduced data offset is allowed only for detached LUKS header."));
			r = -EINVAL;
			goto out;
		}
	}

	_set_activation_flags(&activate_flags);

	if (opt_master_key_file) {
		keysize = crypt_get_volume_key_size(cd);
		if (!keysize && !opt_key_size) {
			log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --key-size option."));
			r = -EINVAL;
			goto out;
		} else if (!keysize)
			keysize = opt_key_size / 8;

		r = tools_read_mk(opt_master_key_file, &key, keysize);
		if (r < 0)
			goto out;
		r = crypt_activate_by_volume_key(cd, activated_name,
						 key, keysize, activate_flags);
	} else {
		r = crypt_activate_by_token(cd, activated_name, opt_token, NULL, activate_flags);
		tools_keyslot_msg(r, UNLOCKED);
		if (r >= 0 || opt_token_only)
			goto out;

		tries = (tools_is_stdin(opt_key_file) && isatty(STDIN_FILENO)) ? opt_tries : 1;
		do {
			r = tools_get_key(NULL, &password, &passwordLen,
					opt_keyfile_offset, opt_keyfile_size, opt_key_file,
					opt_timeout, _verify_passphrase(0), 0, cd);
			if (r < 0)
				goto out;

			r = crypt_activate_by_passphrase(cd, activated_name,
				opt_key_slot, password, passwordLen, activate_flags);
			tools_keyslot_msg(r, UNLOCKED);
			tools_passphrase_msg(r);
			check_signal(&r);
			crypt_safe_free(password);
			password = NULL;
		} while ((r == -EPERM || r == -ERANGE) && (--tries > 0));
	}
out:
	if (r >= 0 && opt_persistent &&
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

	if (ki == CRYPT_SLOT_ACTIVE_LAST && !opt_batch_mode && !key_file &&
	    msg_last && !yesDialog(msg_last, msg_fail))
		return -EPERM;

	r = tools_get_key(msg_pass, &password, &passwordLen,
			  keyfile_offset, keyfile_size, key_file, opt_timeout,
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

	crypt_set_confirm_callback(cd, yesDialog, NULL);

	if ((r = crypt_load(cd, luksType(opt_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	ki = crypt_keyslot_status(cd, opt_key_slot);
	switch (ki) {
	case CRYPT_SLOT_ACTIVE_LAST:
	case CRYPT_SLOT_ACTIVE:
	case CRYPT_SLOT_UNBOUND:
		log_verbose(_("Keyslot %d is selected for deletion."), opt_key_slot);
		break;
	case CRYPT_SLOT_INACTIVE:
		log_err(_("Keyslot %d is not active."), opt_key_slot);
		/* fall through */
	case CRYPT_SLOT_INVALID:
		r = -EINVAL;
		goto out;
	}

	if (!opt_batch_mode || opt_key_file || !isatty(STDIN_FILENO)) {
		r = verify_keyslot(cd, opt_key_slot, ki,
			_("This is the last keyslot. Device will become unusable after purging this key."),
			_("Enter any remaining passphrase: "),
			_("Operation aborted, the keyslot was NOT wiped.\n"),
			opt_key_file, opt_keyfile_offset, opt_keyfile_size);
		tools_keyslot_msg(r, UNLOCKED);

		if (r == -EPIPE && (!opt_key_file || tools_is_stdin(opt_key_file))) {
			log_dbg("Failed read from input, ignoring passphrase.");
			r = 0;
		}

		if (r < 0)
			goto out;
	}

	r = crypt_keyslot_destroy(cd, opt_key_slot);
	tools_keyslot_msg(opt_key_slot, REMOVED);
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

	crypt_set_confirm_callback(cd, yesDialog, NULL);

	if ((r = crypt_load(cd, luksType(opt_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	r = tools_get_key(_("Enter passphrase to be deleted: "),
		      &password, &passwordLen,
		      opt_keyfile_offset, opt_keyfile_size, opt_key_file,
		      opt_timeout,
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

	opt_key_slot = r;
	log_verbose(_("Keyslot %d is selected for deletion."), opt_key_slot);

	if (crypt_keyslot_status(cd, opt_key_slot) == CRYPT_SLOT_ACTIVE_LAST &&
	    !yesDialog(_("This is the last keyslot. "
			  "Device will become unusable after purging this key."),
			_("Operation aborted, the keyslot was NOT wiped.\n"))) {
		r = -EPERM;
		goto out;
	}

	r = crypt_keyslot_destroy(cd, opt_key_slot);
	tools_keyslot_msg(opt_key_slot, REMOVED);
out:
	crypt_safe_free(password);
	crypt_free(cd);
	return r;
}

static int luksAddUnboundKey(void)
{
	int r = -EINVAL, keysize = 0;
	char *key = NULL;
	const char *opt_new_key_file = (action_argc > 1 ? action_argv[1] : NULL);
	char *password_new = NULL;
	size_t password_new_size = 0;
	struct crypt_device *cd = NULL;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	crypt_set_confirm_callback(cd, yesDialog, NULL);

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	/* Never call pwquality if using null cipher */
	if (tools_is_cipher_null(crypt_get_cipher(cd)))
		opt_force_password = 1;

	keysize = opt_key_size / 8;
	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	if (opt_master_key_file) {
		r = tools_read_mk(opt_master_key_file, &key, keysize);
		if (r < 0)
			goto out;

		check_signal(&r);
		if (r < 0)
			goto out;
	}

	r = tools_get_key(_("Enter new passphrase for key slot: "),
			  &password_new, &password_new_size,
			  opt_new_keyfile_offset, opt_new_keyfile_size,
			  opt_new_key_file, opt_timeout,
			  _verify_passphrase(1), 1, cd);
	if (r < 0)
		goto out;

	r = crypt_keyslot_add_by_key(cd, opt_key_slot, key, keysize,
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
	const char *opt_new_key_file = (action_argc > 1 ? action_argv[1] : NULL);
	char *password = NULL, *password_new = NULL;
	size_t password_size = 0, password_new_size = 0;
	struct crypt_device *cd = NULL;

	/* Unbound keyslot (no assigned data segment) is special case */
	if (opt_unbound)
		return luksAddUnboundKey();

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	crypt_set_confirm_callback(cd, yesDialog, NULL);

	if ((r = crypt_load(cd, luksType(opt_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	/* Never call pwquality if using null cipher */
	if (tools_is_cipher_null(crypt_get_cipher(cd)))
		opt_force_password = 1;

	keysize = crypt_get_volume_key_size(cd);
	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	if (opt_master_key_file) {
		if (!keysize && !opt_key_size) {
			log_err(_("Cannot determine volume key size for LUKS without keyslots, please use --key-size option."));
			r = -EINVAL;
			goto out;
		} else if (!keysize)
			keysize = opt_key_size / 8;

		r = tools_read_mk(opt_master_key_file, &key, keysize);
		if (r < 0)
			goto out;

		r = crypt_volume_key_verify(cd, key, keysize);
		check_signal(&r);
		if (r < 0)
			goto out;

		r = tools_get_key(_("Enter new passphrase for key slot: "),
				  &password_new, &password_new_size,
				  opt_new_keyfile_offset, opt_new_keyfile_size,
				  opt_new_key_file, opt_timeout,
				  _verify_passphrase(1), 1, cd);
		if (r < 0)
			goto out;

		r = crypt_keyslot_add_by_volume_key(cd, opt_key_slot, key, keysize,
						    password_new, password_new_size);
	} else if (opt_key_file && !tools_is_stdin(opt_key_file) &&
		   opt_new_key_file && !tools_is_stdin(opt_new_key_file)) {
		r = crypt_keyslot_add_by_keyfile_device_offset(cd, opt_key_slot,
			opt_key_file, opt_keyfile_size, opt_keyfile_offset,
			opt_new_key_file, opt_new_keyfile_size, opt_new_keyfile_offset);
		tools_passphrase_msg(r);
	} else {
		r = tools_get_key(_("Enter any existing passphrase: "),
			      &password, &password_size,
			      opt_keyfile_offset, opt_keyfile_size, opt_key_file,
			      opt_timeout, _verify_passphrase(0), 0, cd);

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
				  opt_new_keyfile_offset, opt_new_keyfile_size, opt_new_key_file,
				  opt_timeout, _verify_passphrase(1), 1, cd);
		if (r < 0)
			goto out;

		r = crypt_keyslot_add_by_passphrase(cd, opt_key_slot,
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
	const char *opt_new_key_file = (action_argc > 1 ? action_argv[1] : NULL);
	struct crypt_device *cd = NULL;
	char *password = NULL, *password_new = NULL;
	size_t password_size = 0, password_new_size = 0;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	if ((r = crypt_load(cd, luksType(opt_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	r = _set_keyslot_encryption_params(cd);
	if (r < 0)
		goto out;

	/* Never call pwquality if using null cipher */
	if (tools_is_cipher_null(crypt_get_cipher(cd)))
		opt_force_password = 1;

	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	r = tools_get_key(_("Enter passphrase to be changed: "),
		      &password, &password_size,
		      opt_keyfile_offset, opt_keyfile_size, opt_key_file,
		      opt_timeout, _verify_passphrase(0), 0, cd);
	if (r < 0)
		goto out;

	/* Check password before asking for new one */
	r = crypt_activate_by_passphrase(cd, NULL, opt_key_slot,
					 password, password_size, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	r = tools_get_key(_("Enter new passphrase: "),
			  &password_new, &password_new_size,
			  opt_new_keyfile_offset, opt_new_keyfile_size,
			  opt_new_key_file,
			  opt_timeout, _verify_passphrase(1), 1, cd);
	if (r < 0)
		goto out;

	r = crypt_keyslot_change_by_passphrase(cd, opt_key_slot, opt_key_slot,
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

	if (crypt_keyslot_status(cd, opt_key_slot) == CRYPT_SLOT_INACTIVE) {
		r = -EINVAL;
		log_err(_("Keyslot %d is not active."), opt_key_slot);
		goto out;
	}

	r = set_pbkdf_params(cd, crypt_get_type(cd));
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	r = tools_get_key(_("Enter passphrase for keyslot to be converted: "),
		      &password, &password_size,
		      opt_keyfile_offset, opt_keyfile_size, opt_key_file,
		      opt_timeout, _verify_passphrase(0), 0, cd);
	if (r < 0)
		goto out;

	r = crypt_keyslot_change_by_passphrase(cd, opt_key_slot, opt_key_slot,
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

	crypt_set_log_callback(cd, quiet_log, NULL);
	r = crypt_load(cd, luksType(opt_type), NULL);
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

	crypt_set_confirm_callback(cd, yesDialog, _("Operation aborted.\n"));

	if ((r = crypt_load(cd, luksType(opt_type), NULL)))
		goto out;

	if (opt_uuid)
		r = crypt_set_uuid(cd, opt_uuid);
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

	crypt_set_confirm_callback(cd, yesDialog, NULL);
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
			  opt_keyfile_offset, opt_keyfile_size, opt_key_file,
			  opt_timeout, 0, 0, cd);
	if (r < 0)
		goto out;

	r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, vk, &vk_size,
				 password, passwordLen);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	if (opt_master_key_file) {
		r = tools_write_mk(opt_master_key_file, vk, vk_size);
		if (r < 0)
			goto out;
	}

	log_std("LUKS header information for %s\n", crypt_get_device_name(cd));
	log_std("Cipher name:   \t%s\n", crypt_get_cipher(cd));
	log_std("Cipher mode:   \t%s\n", crypt_get_cipher_mode(cd));
	log_std("Payload offset:\t%d\n", (int)crypt_get_data_offset(cd));
	log_std("UUID:          \t%s\n", crypt_get_uuid(cd));
	log_std("MK bits:       \t%d\n", (int)vk_size * 8);
	if (opt_master_key_file) {
		log_std("Key stored to file %s.\n", opt_master_key_file);
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

	ki = crypt_keyslot_status(cd, opt_key_slot);
	if (ki != CRYPT_SLOT_UNBOUND) {
		log_err(_("Keyslot %d does not contain unbound key."), opt_key_slot);
		return -EINVAL;
	}

	crypt_set_confirm_callback(cd, yesDialog, NULL);
	if (!yesDialog(
	    _("The header dump with unbound key is sensitive information.\n"
	      "This dump should be stored encrypted in a safe place."),
	      NULL))
		return -EPERM;

	r = crypt_keyslot_get_key_size(cd, opt_key_slot);
	if (r < 0)
		return -EINVAL;
	uk_size = r;
	uk = crypt_safe_alloc(uk_size);
	if (!uk)
		return -ENOMEM;

	r = tools_get_key(NULL, &password, &passwordLen,
			  opt_keyfile_offset, opt_keyfile_size, opt_key_file,
			  opt_timeout, 0, 0, cd);
	if (r < 0)
		goto out;

	r = crypt_volume_key_get(cd, opt_key_slot, uk, &uk_size,
				 password, passwordLen);
	tools_passphrase_msg(r);
	check_signal(&r);
	if (r < 0)
		goto out;
	tools_keyslot_msg(r, UNLOCKED);

	if (opt_master_key_file) {
		r = tools_write_mk(opt_master_key_file, uk, uk_size);
		if (r < 0)
			goto out;
	}

	log_std("LUKS header information for %s\n", crypt_get_device_name(cd));
	log_std("UUID:    \t%s\n", crypt_get_uuid(cd));
	log_std("Keyslot: \t%d\n", opt_key_slot);
	log_std("Key bits:\t%d\n", (int)uk_size * 8);
	if (opt_master_key_file) {
		log_std("Key stored to file %s.\n", opt_master_key_file);
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

	if ((r = crypt_load(cd, luksType(opt_type), NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device_header(NULL));
		goto out;
	}

	if (opt_dump_master_key)
		r = luksDump_with_volume_key(cd);
	else if (opt_unbound)
		r = luksDump_with_unbound_key(cd);
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

	r = crypt_init_by_name_and_header(&cd, action_argv[0], uuid_or_device(opt_header_device));
	if (!r)
		r = crypt_suspend(cd, action_argv[0]);

	crypt_free(cd);
	return r;
}

static int action_luksResume(void)
{
	struct crypt_device *cd = NULL;
	char *password = NULL;
	size_t passwordLen;
	int r, tries;

	if ((r = crypt_init_by_name_and_header(&cd, action_argv[0], uuid_or_device(opt_header_device))))
		goto out;

	if ((r = crypt_load(cd, luksType(opt_type), NULL)))
		goto out;

	tries = (tools_is_stdin(opt_key_file) && isatty(STDIN_FILENO)) ? opt_tries : 1;
	do {
		r = tools_get_key(NULL, &password, &passwordLen,
			opt_keyfile_offset, opt_keyfile_size, opt_key_file,
			opt_timeout, _verify_passphrase(0), 0, cd);
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

	if (!opt_header_backup_file) {
		log_err(_("Option --header-backup-file is required."));
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	crypt_set_confirm_callback(cd, yesDialog, NULL);

	r = crypt_header_backup(cd, NULL, opt_header_backup_file);
out:
	crypt_free(cd);
	return r;
}

static int action_luksRestore(void)
{
	struct crypt_device *cd = NULL;
	int r = 0;

	if (!opt_header_backup_file) {
		log_err(_("Option --header-backup-file is required."));
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	crypt_set_confirm_callback(cd, yesDialog, NULL);
	r = crypt_header_restore(cd, NULL, opt_header_backup_file);
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

	if (crypt_init_by_name_and_header(&cd, name, opt_header_device))
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
	if (opt_refresh && !opt_type)
		/* read device type from active mapping */
		opt_type = _get_device_type();

	if (!opt_type)
		return -EINVAL;

	if (!strcmp(opt_type, "luks") ||
	    !strcmp(opt_type, "luks1") ||
	    !strcmp(opt_type, "luks2")) {
		if (action_argc < 2 && (!opt_test_passphrase && !opt_refresh))
			goto args;
		return action_open_luks();
	} else if (!strcmp(opt_type, "plain")) {
		if (action_argc < 2 && !opt_refresh)
			goto args;
		return action_open_plain();
	} else if (!strcmp(opt_type, "loopaes")) {
		if (action_argc < 2 && !opt_refresh)
			goto args;
		return action_open_loopaes();
	} else if (!strcmp(opt_type, "tcrypt")) {
		if (action_argc < 2 && !opt_test_passphrase)
			goto args;
		return action_open_tcrypt();
	} else if (!strcmp(opt_type, "bitlk")) {
		if (action_argc < 2 && !opt_test_passphrase)
			goto args;
		return action_open_bitlk();
	}

	log_err(_("Unrecognized metadata device type %s."), opt_type);
	return -EINVAL;
args:
	log_err(_("Command requires device and mapped name as arguments."));
	return -EINVAL;
}

static int action_luksErase(void)
{
	struct crypt_device *cd = NULL;
	crypt_keyslot_info ki;
	char *msg = NULL;
	int i, max, r;

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		goto out;

	crypt_set_confirm_callback(cd, yesDialog, NULL);

	if ((r = crypt_load(cd, luksType(opt_type), NULL))) {
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

	if (!yesDialog(msg, _("Operation aborted, keyslots were NOT wiped.\n"))) {
		r = -EPERM;
		goto out;
	}

	/* Safety check */
	max = crypt_keyslot_max(crypt_get_type(cd));
	if (max <= 0)
		return -EINVAL;

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

	if (!strcmp(opt_type, "luks2")) {
		to_type = CRYPT_LUKS2;
	} else if (!strcmp(opt_type, "luks1")) {
		to_type = CRYPT_LUKS1;
	} else {
		log_err(_("Invalid LUKS type, only luks1 and luks2 are supported."));
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, uuid_or_device_header(NULL))))
		return r;

	crypt_set_confirm_callback(cd, yesDialog, NULL);

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

	if (asprintf(&msg, _("This operation will convert %s to %s format.\n"),
			    uuid_or_device_header(NULL), to_type) == -1) {
		crypt_free(cd);
		return -ENOMEM;
	}

	if (yesDialog(msg, _("Operation aborted, device was NOT converted.\n")))
		r = crypt_convert(cd, to_type, NULL);
	else
		r = -EPERM;

	free(msg);
	crypt_free(cd);
	return r;
}

static int _config_priority(struct crypt_device *cd)
{
	crypt_keyslot_info cs;
	crypt_keyslot_priority priority = CRYPT_SLOT_PRIORITY_INVALID;

	if (!strcmp("normal", opt_priority))
		priority = CRYPT_SLOT_PRIORITY_NORMAL;
	else if (!strcmp("prefer", opt_priority))
		priority = CRYPT_SLOT_PRIORITY_PREFER;
	else if (!strcmp("ignore", opt_priority))
		priority = CRYPT_SLOT_PRIORITY_IGNORE;

	cs = crypt_keyslot_status(cd, opt_key_slot);
	if (cs != CRYPT_SLOT_INVALID)
		return crypt_keyslot_set_priority(cd, opt_key_slot, priority);

	return -EINVAL;
}

static int _config_labels(struct crypt_device *cd)
{
	return crypt_set_label(cd, opt_label, opt_subsystem);
}

static int action_luksConfig(void)
{
	struct crypt_device *cd = NULL;
	int r;

	if (!opt_priority && !opt_label && !opt_subsystem) {
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

	if (opt_priority && (r = _config_priority(cd)))
		goto out;

	if ((opt_label || opt_subsystem) && (r = _config_labels(cd)))
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
		.key_description = opt_key_description
	};

	if (opt_token != CRYPT_ANY_TOKEN) {
		token_info = crypt_token_status(cd, opt_token, NULL);
		if (token_info < CRYPT_TOKEN_INACTIVE) {
			log_err(_("Token %d is invalid."), opt_token);
			return -EINVAL;
		} else if (token_info > CRYPT_TOKEN_INACTIVE) {
			log_err(_("Token %d in use."), opt_token);
			return -EINVAL;
		}
	}

	r = crypt_token_luks2_keyring_set(cd, opt_token, &params);
	if (r < 0) {
		log_err(_("Failed to add luks2-keyring token %d."), opt_token);
		return r;
	}

	token = r;
	tools_token_msg(token, CREATED);

	r = crypt_token_assign_keyslot(cd, token, opt_key_slot);
	if (r < 0) {
		log_err(_("Failed to assign token %d to keyslot %d."), token, opt_key_slot);
		(void) crypt_token_json_set(cd, token, NULL);
	}

	return r;
}

static int _token_remove(struct crypt_device *cd)
{
	crypt_token_info token_info;
	int r;

	token_info = crypt_token_status(cd, opt_token, NULL);
	if (token_info < CRYPT_TOKEN_INACTIVE) {
		log_err(_("Token %d is invalid."), opt_token);
		return -EINVAL;
	} else if (token_info == CRYPT_TOKEN_INACTIVE) {
		log_err(_("Token %d is not in use."), opt_token);
		return -EINVAL;
	}

	r = crypt_token_json_set(cd, opt_token, NULL);
	tools_token_msg(r, REMOVED);

	return r;
}

static int _token_import(struct crypt_device *cd)
{
	char *json;
	size_t json_length;
	crypt_token_info token_info;
	int r, token;

	if (opt_token != CRYPT_ANY_TOKEN) {
		token_info = crypt_token_status(cd, opt_token, NULL);
		if (token_info < CRYPT_TOKEN_INACTIVE) {
			log_err(_("Token %d is invalid."), opt_token);
			return -EINVAL;
		} else if (token_info > CRYPT_TOKEN_INACTIVE) {
			log_err(_("Token %d in use."), opt_token);
			return -EINVAL;
		}
	}

	r = tools_read_json_file(cd, opt_json_file, &json, &json_length);
	if (r)
		return r;

	r = crypt_token_json_set(cd, opt_token, json);
	free(json);
	if (r < 0) {
		log_err(_("Failed to import token from file."));
		return r;
	}

	token = r;
	tools_token_msg(token, CREATED);

	if (opt_key_slot != CRYPT_ANY_SLOT) {
		r = crypt_token_assign_keyslot(cd, token, opt_key_slot);
		if (r < 0) {
			log_err(_("Failed to assign token %d to keyslot %d."), token, opt_key_slot);
			(void) crypt_token_json_set(cd, token, NULL);
		}
	}

	return r;
}

static int _token_export(struct crypt_device *cd)
{
	const char *json;
	int r;

	r = crypt_token_json_get(cd, opt_token, &json);
	if (r < 0) {
		log_err(_("Failed to get token %d for export."), opt_token);
		return r;
	}

	return tools_write_json_file(cd, opt_json_file, json);
}

static int action_token(void)
{
	int r;
	struct crypt_device *cd = NULL;
	enum { ADD = 0, REMOVE, IMPORT, EXPORT } action;

	if (!strcmp(action_argv[0], "add")) {
		if (!opt_key_description) {
			log_err(_("--key-description parameter is mandatory for token add action."));
			return -EINVAL;
		}
		action = ADD;
	} else if (!strcmp(action_argv[0], "remove")) {
		if (opt_token == CRYPT_ANY_TOKEN) {
			log_err(_("Action requires specific token. Use --token-id parameter."));
			return -EINVAL;
		}
		action = REMOVE;
	} else if (!strcmp(action_argv[0], "import")) {
		action = IMPORT;
	} else if (!strcmp(action_argv[0], "export")) {
		if (opt_token == CRYPT_ANY_TOKEN) {
			log_err(_("Action requires specific token. Use --token-id parameter."));
			return -EINVAL;
		}
		action = EXPORT;
	} else {
		log_err(_("Invalid token operation %s."), action_argv[0]);
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, uuid_or_device(opt_header_device ?: action_argv[1]))))
		return r;

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL))) {
		log_err(_("Device %s is not a valid LUKS device."),
			uuid_or_device(opt_header_device ?: action_argv[1]));
		crypt_free(cd);
		return r;
	}

	if (action == ADD)
		r = _token_add(cd); /* adds only luks2-keyring type */
	else if (action == REMOVE)
		r = _token_remove(cd);
	else if (action == IMPORT)
		r = _token_import(cd);
	else if (action == EXPORT)
		r = _token_export(cd);
	else {
		log_dbg("Internal token action error.");
		r = -EINVAL;
	}

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
		if (!opt_batch_mode)
			log_std(_("Auto-detected active dm device '%s' for data device %s.\n"), buffer, data_device);
	}
	if (r < 0) {
		if (r == -ENOTBLK)
			log_std(_("Device %s is not a block device.\n"), data_device);
		else
			log_err(_("Failed to auto-detect device %s holders."), data_device);

		r = asprintf(&msg, _("Unable to decide if device %s is activated or not.\n"
				     "Are you sure you want to proceed with reencryption in offline mode?\n"
				     "It may lead to data corruption if the device is actually activated.\n"
				     "To run reencryption in online mode, use --active-name parameter instead.\n"), data_device);
		if (r < 0)
			return -ENOMEM;
		r = noDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
		free(msg);
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
		.resilience = opt_resilience_mode,
		.hash = opt_resilience_hash,
		.max_hotzone_size = opt_hotzone_size / SECTOR_SIZE,
		.device_size = opt_device_size / SECTOR_SIZE,
		.flags = CRYPT_REENCRYPT_RESUME_ONLY
	};

	r = tools_get_key(NULL, &password, &passwordLen,
			opt_keyfile_offset, opt_keyfile_size, opt_key_file,
			opt_timeout, _verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	if (!opt_active_name) {
		r = _get_device_active_name(cd, action_argv[0], dm_name, sizeof(dm_name));
		if (r > 0)
			active_name = dm_name;
		if (r < 0) {
			crypt_safe_free(password);
			return -EINVAL;
		}
	} else
		active_name = opt_active_name;

	r = crypt_reencrypt_init_by_passphrase(cd, active_name, password, passwordLen, opt_key_slot, opt_key_slot, NULL, NULL, &params);

	crypt_safe_free(password);

	return r;
}

static int action_encrypt_luks2(struct crypt_device **cd)
{
	const char *type, *activated_name = NULL;
	int keyslot, r, fd;
	uuid_t uuid;
	size_t passwordLen;
	char *msg, uuid_str[37], header_file[PATH_MAX] = { 0 }, *password = NULL;
	uint32_t activate_flags = 0;
	const struct crypt_params_luks2 luks2_params = {
		.sector_size = opt_sector_size ?: SECTOR_SIZE
	};
	struct crypt_params_reencrypt params = {
		.mode = CRYPT_REENCRYPT_ENCRYPT,
		.direction = opt_data_shift < 0 ? CRYPT_REENCRYPT_BACKWARD : CRYPT_REENCRYPT_FORWARD,
		.resilience = opt_resilience_mode,
		.hash = opt_resilience_hash,
		.max_hotzone_size = opt_hotzone_size / SECTOR_SIZE,
		.device_size = opt_device_size / SECTOR_SIZE,
		.luks2 = &luks2_params,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY
	};

	_set_reencryption_flags(&params.flags);

	type = luksType(opt_type);
	if (!type)
		type = crypt_get_default_type();

	if (strcmp(type, CRYPT_LUKS2)) {
		log_err(_("Invalid LUKS device type."));
		return -EINVAL;
	}

	if (!opt_data_shift && !opt_header_device) {
		log_err(_("Encryption without detached header (--header) is not possible without data device size reduction (--reduce-device-size)."));
		return -ENOTSUP;
	}

	if (!opt_header_device && opt_offset && opt_data_shift && (opt_offset > (imaxabs(opt_data_shift) / (2 * SECTOR_SIZE)))) {
		log_err(_("Requested data offset must be less than or equal to half of --reduce-device-size parameter."));
		return -EINVAL;
	}

	/* TODO: ask user to confirm. It's useless to do data device reduction and than use smaller value */
	if (!opt_header_device && opt_offset && opt_data_shift && (opt_offset < (imaxabs(opt_data_shift) / (2 * SECTOR_SIZE)))) {
		opt_data_shift = -(opt_offset * 2 * SECTOR_SIZE);
		if (opt_data_shift >= 0)
			return -EINVAL;
		log_std(_("Adjusting --reduce-device-size value to twice the --offset %" PRIu64 " (sectors).\n"), opt_offset * 2);
	}

	if (strncmp(type, CRYPT_LUKS2, strlen(CRYPT_LUKS2))) {
		log_err(_("Encryption is supported only for LUKS2 format."));
		return -EINVAL;
	}

	if (opt_uuid && uuid_parse(opt_uuid, uuid) == -1) {
		log_err(_("Wrong LUKS UUID format provided."));
		return -EINVAL;
	}

	if (!opt_uuid) {
		uuid_generate(uuid);
		uuid_unparse(uuid, uuid_str);
		opt_uuid = uuid_str;
	}

	/* Check the data device is not LUKS device already */
	if ((r = crypt_init(cd, action_argv[0])))
		return r;
	r = crypt_load(*cd, CRYPT_LUKS, NULL);
	crypt_free(*cd);
	*cd = NULL;
	if (!r) {
		r = asprintf(&msg, _("Detected LUKS device on %s. Do you want to encrypt that LUKS device again?"), action_argv[0]);
		if (r == -1)
			return -ENOMEM;

		r = yesDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
		free(msg);
		if (r < 0)
			return r;
	}

	if (!opt_header_device) {
		snprintf(header_file, sizeof(header_file), "LUKS2-temp-%s.new", opt_uuid);
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
			goto err;
		}

		opt_header_device = header_file;
		/*
		 * FIXME: just override offset here, but we should support both.
		 * offset and implicit offset via data shift (lvprepend?)
		 */
		if (!opt_offset)
			opt_offset = imaxabs(opt_data_shift) / (2 * SECTOR_SIZE);
		opt_data_shift >>= 1;
		params.flags |= CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT;
	} else if (opt_data_shift < 0) {
		if (!opt_luks2_metadata_size)
			opt_luks2_metadata_size = 0x4000; /* missing default here */
		if (!opt_luks2_keyslots_size)
			opt_luks2_keyslots_size = -opt_data_shift - 2 * opt_luks2_metadata_size;

		if (2 * opt_luks2_metadata_size + opt_luks2_keyslots_size > (uint64_t)-opt_data_shift) {
			log_err("LUKS2 metadata size is larger than data shift value.");
			return -EINVAL;
		}
	}

	r = _luksFormat(cd, &password, &passwordLen);
	if (r < 0)
		goto err;

	if (opt_data_shift) {
		params.data_shift = imaxabs(opt_data_shift) / SECTOR_SIZE,
		params.resilience = "datashift";
	}
	keyslot = opt_key_slot < 0 ? 0 : opt_key_slot;
	r = crypt_reencrypt_init_by_passphrase(*cd, NULL, password, passwordLen,
			CRYPT_ANY_SLOT, keyslot, crypt_get_cipher(*cd),
			crypt_get_cipher_mode(*cd), &params);
	if (r < 0) {
		crypt_keyslot_destroy(*cd, keyslot);
		goto err;
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
			goto err;
		}
	}

	/* activate device */
	if (action_argc > 1) {
		activated_name = action_argv[1];
		_set_activation_flags(&activate_flags);
		r = crypt_activate_by_passphrase(*cd, activated_name, opt_key_slot, password, passwordLen, activate_flags);
		if (r >= 0)
			log_std(_("%s/%s is now active and ready for online encryption.\n"), crypt_get_dir(), activated_name);
	}

	if (r < 0)
		goto err;

	/* just load reencryption context to continue reencryption */
	if (!opt_reencrypt_init_only) {
		params.flags &= ~CRYPT_REENCRYPT_INITIALIZE_ONLY;
		r = crypt_reencrypt_init_by_passphrase(*cd, activated_name, password, passwordLen,
				CRYPT_ANY_SLOT, keyslot, NULL, NULL, &params);
	}
err:
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
		.direction = opt_data_shift > 0 ? CRYPT_REENCRYPT_FORWARD : CRYPT_REENCRYPT_BACKWARD,
		.resilience = opt_data_shift ? "datashift" : opt_resilience_mode,
		.hash = opt_resilience_hash,
		.data_shift = imaxabs(opt_data_shift) / SECTOR_SIZE,
		.device_size = opt_device_size / SECTOR_SIZE,
		.max_hotzone_size = opt_hotzone_size / SECTOR_SIZE,
	};
	size_t passwordLen;

	_set_reencryption_flags(&params.flags);

	r = tools_get_key(NULL, &password, &passwordLen,
			opt_keyfile_offset, opt_keyfile_size, opt_key_file,
			opt_timeout, _verify_passphrase(0), 0, cd);
	if (r < 0)
		return r;

	if (!opt_active_name) {
		r = _get_device_active_name(cd, action_argv[0], dm_name, sizeof(dm_name));
		if (r > 0)
			active_name = dm_name;
		if (r < 0)
			goto err;
	} else
		active_name = opt_active_name;

	if (!active_name)
		log_dbg("Device %s seems unused. Proceeding with offline operation.", action_argv[0]);

	r = crypt_reencrypt_init_by_passphrase(cd, active_name, password,
			passwordLen, opt_key_slot, CRYPT_ANY_SLOT, NULL, NULL, &params);
err:
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

	retry_count = (opt_tries && !opt_key_file) ? opt_tries : 1;
	while (retry_count--) {
		r = tools_get_key(msg,  &password, &passwordLen, 0, 0,
				  opt_key_file, 0, 0, 0 /*pwquality*/, cd);
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

	if ((opt_key_slot == CRYPT_ANY_SLOT) &&
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

	if (opt_key_slot == CRYPT_ANY_SLOT && opt_key_file) {
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

	if (opt_key_slot == CRYPT_ANY_SLOT) {
		for (i = 0; (size_t)i < kp_size; i++) {
			snprintf(msg, sizeof(msg), _("Enter passphrase for key slot %d: "), i);
			r = init_passphrase(kp, kp_size, cd, msg, i);
			if (r == -ENOENT)
				r = 0;
			if (r < 0)
				break;
		}
	} else {
		snprintf(msg, sizeof(msg), _("Enter passphrase for key slot %u: "), opt_key_slot);
		r = init_passphrase(kp, kp_size, cd, msg, opt_key_slot);
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
	char dm_name[PATH_MAX], cipher [MAX_CIPHER_LEN], mode[MAX_CIPHER_LEN], *vk;
	const char *active_name = NULL;
	struct keyslot_passwords *kp;
	struct crypt_params_luks2 luks2_params = {};
	struct crypt_params_reencrypt params = {
		.mode = CRYPT_REENCRYPT_REENCRYPT,
		.direction = opt_data_shift < 0 ? CRYPT_REENCRYPT_BACKWARD : CRYPT_REENCRYPT_FORWARD,
		.resilience = opt_data_shift ? "datashift" : opt_resilience_mode,
		.hash = opt_resilience_hash,
		.data_shift = imaxabs(opt_data_shift) / SECTOR_SIZE,
		.max_hotzone_size = opt_hotzone_size / SECTOR_SIZE,
		.device_size = opt_device_size / SECTOR_SIZE,
		.luks2 = &luks2_params,
	};

	_set_reencryption_flags(&params.flags);

	if (!opt_cipher) {
		strncpy(cipher, crypt_get_cipher(cd), MAX_CIPHER_LEN - 1);
		strncpy(mode, crypt_get_cipher_mode(cd), MAX_CIPHER_LEN - 1);
		cipher[MAX_CIPHER_LEN-1] = '\0';
		mode[MAX_CIPHER_LEN-1] = '\0';
	} else if ((r = crypt_parse_name_and_mode(opt_cipher, cipher, NULL, mode))) {
		log_err(_("No known cipher specification pattern detected."));
		return r;
	}

	luks2_params.sector_size = opt_sector_size ?: crypt_get_sector_size(cd);

	r = _check_luks2_keyslots(cd);
	if (r)
		return r;

	if (opt_key_size)
		key_size = opt_key_size / 8;
	else if (opt_cipher)
		key_size = DEFAULT_LUKS1_KEYBITS / 8;
	else
		key_size = crypt_get_volume_key_size(cd);

	if (!key_size)
		return -EINVAL;

	r = crypt_keyslot_max(CRYPT_LUKS2);
	if (r < 0)
		return r;
	kp_size = r;
	kp = init_keyslot_passwords(kp_size);

	if (!kp)
		return -ENOMEM;

	r = fill_keyslot_passwords(cd, kp, kp_size);
	if (r)
		goto err;

	vk_size = key_size;
	vk = crypt_safe_alloc(vk_size);
	if (!vk) {
		r = -ENOMEM;
		goto err;
	}

	r = -ENOENT;

	for (i = 0; i < kp_size; i++) {
		if (kp[i].password && keyslot_new < 0) {
			r = set_keyslot_params(cd, i);
			if (r < 0)
				break;
			r = crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, NULL, key_size,
					kp[i].password, kp[i].passwordLen, CRYPT_VOLUME_KEY_NO_SEGMENT);
			tools_keyslot_msg(r, CREATED);
			if (r < 0)
				break;

			kp[i].new = r;
			keyslot_new = r;
			keyslot_old = i;
			r = crypt_volume_key_get(cd, keyslot_new, vk, &vk_size, kp[i].password, kp[i].passwordLen);
			if (r < 0)
				break;
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

	crypt_safe_free(vk);

	if (r < 0)
		goto err;

	if (!opt_active_name && !opt_reencrypt_init_only) {
		r = _get_device_active_name(cd, action_argv[0], dm_name, sizeof(dm_name));
		if (r > 0)
			active_name = dm_name;
		if (r < 0)
			goto err;
	} else if (opt_active_name)
		active_name = opt_active_name;

	if (!active_name && !opt_reencrypt_init_only)
		log_dbg("Device %s seems unused. Proceeding with offline operation.", action_argv[0]);

	r = crypt_reencrypt_init_by_passphrase(cd, active_name, kp[keyslot_old].password,
			kp[keyslot_old].passwordLen, keyslot_old, kp[keyslot_old].new,
			cipher, mode, &params);
err:
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

	if (action_argc < 1 && (!opt_active_name || opt_encrypt)) {
		log_err(_("Command requires device as argument."));
		return -EINVAL;
	}

	if (!opt_encrypt || opt_reencrypt_resume_only) {
		if (opt_active_name) {
			r = crypt_init_by_name_and_header(&cd, opt_active_name, opt_header_device);
			if (r || !crypt_get_type(cd) || strcmp(crypt_get_type(cd), CRYPT_LUKS2)) {
				log_err(_("Device %s is not a valid LUKS device."), opt_active_name);
				r = -EINVAL;
				goto out;
			}
		} else {
			if ((r = crypt_init_data_device(&cd, uuid_or_device(opt_header_device ?: action_argv[0]), action_argv[0])))
				return r;

			if ((r = crypt_load(cd, CRYPT_LUKS, NULL))) {
				log_err(_("Device %s is not a valid LUKS device."),
					uuid_or_device(opt_header_device ?: action_argv[0]));
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
		if (opt_reencrypt_init_only)
			log_err(_("LUKS2 reencryption already initialized. Aborting operation."));
		else
			r = action_reencrypt_load(cd);
	} else if (!r && opt_reencrypt_resume_only) {
		log_err(_("LUKS2 device is not in reencryption."));
		r = -EINVAL;
	} else if (opt_decrypt)
		r = action_decrypt_luks2(cd);
	else if (opt_encrypt && !opt_reencrypt_resume_only)
		r = action_encrypt_luks2(&cd);
	else
		r = action_reencrypt_luks2(cd);

	if (r >= 0 && !opt_reencrypt_init_only) {
		set_int_handler(0);
		r = crypt_reencrypt(cd, tools_reencrypt_progress);
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
	{ "open",         action_open,         1, 1, N_("<device> [--type <type>] [<name>]"),N_("open device as <name>") },
	{ "close",        action_close,        1, 1, N_("<name>"), N_("close device (remove mapping)") },
	{ "resize",       action_resize,       1, 1, N_("<name>"), N_("resize active device") },
	{ "status",       action_status,       1, 0, N_("<name>"), N_("show device status") },
	{ "benchmark",    action_benchmark,    0, 0, N_("[--cipher <cipher>]"), N_("benchmark cipher") },
	{ "repair",       action_luksRepair,   1, 1, N_("<device>"), N_("try to repair on-disk metadata") },
	{ "reencrypt",    action_reencrypt,    0, 0, N_("<device>"), N_("reencrypt LUKS2 device") },
	{ "erase",        action_luksErase ,   1, 1, N_("<device>"), N_("erase all keyslots (remove encryption key)") },
	{ "convert",      action_luksConvert,  1, 1, N_("<device>"), N_("convert LUKS from/to LUKS2 format") },
	{ "config",       action_luksConfig,   1, 1, N_("<device>"), N_("set permanent configuration options for LUKS2") },
	{ "luksFormat",   action_luksFormat,   1, 1, N_("<device> [<new key file>]"), N_("formats a LUKS device") },
	{ "luksAddKey",   action_luksAddKey,   1, 1, N_("<device> [<new key file>]"), N_("add key to LUKS device") },
	{ "luksRemoveKey",action_luksRemoveKey,1, 1, N_("<device> [<key file>]"), N_("removes supplied key or key file from LUKS device") },
	{ "luksChangeKey",action_luksChangeKey,1, 1, N_("<device> [<key file>]"), N_("changes supplied key or key file of LUKS device") },
	{ "luksConvertKey",action_luksConvertKey,1, 1, N_("<device> [<key file>]"), N_("converts a key to new pbkdf parameters") },
	{ "luksKillSlot", action_luksKillSlot, 2, 1, N_("<device> <key slot>"), N_("wipes key with number <key slot> from LUKS device") },
	{ "luksUUID",     action_luksUUID,     1, 0, N_("<device>"), N_("print UUID of LUKS device") },
	{ "isLuks",       action_isLuks,       1, 0, N_("<device>"), N_("tests <device> for LUKS partition header") },
	{ "luksDump",     action_luksDump,     1, 1, N_("<device>"), N_("dump LUKS partition information") },
	{ "tcryptDump",   action_tcryptDump,   1, 1, N_("<device>"), N_("dump TCRYPT device information") },
	{ "bitlkDump",    action_bitlkDump,    1, 1, N_("<device>"), N_("dump BITLK device information") },
	{ "luksSuspend",  action_luksSuspend,  1, 1, N_("<device>"), N_("Suspend LUKS device and wipe key (all IOs are frozen)") },
	{ "luksResume",   action_luksResume,   1, 1, N_("<device>"), N_("Resume suspended LUKS device") },
	{ "luksHeaderBackup", action_luksBackup,1,1, N_("<device>"), N_("Backup LUKS device header and keyslots") },
	{ "luksHeaderRestore",action_luksRestore,1,1,N_("<device>"), N_("Restore LUKS device header and keyslots") },
	{ "token",	  action_token,	       2, 0, N_("<add|remove|import|export> <device>"), N_("Manipulate LUKS2 tokens") },
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
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else if (key->shortName == 'V') {
		log_std("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
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

int main(int argc, const char **argv)
{
	static char *popt_tmp;
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		{ "version",'V', POPT_ARG_NONE,     NULL, 0, N_("Print package version"),  NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,                '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ "verbose",           'v',  POPT_ARG_NONE, &opt_verbose,               0, N_("Shows more detailed error messages"), NULL },
		{ "debug",             '\0', POPT_ARG_NONE, &opt_debug,                 0, N_("Show debug messages"), NULL },
		{ "debug-json",        '\0', POPT_ARG_NONE, &opt_debug_json,            0, N_("Show debug messages including JSON metadata"), NULL },
		{ "cipher",            'c',  POPT_ARG_STRING, &opt_cipher,              0, N_("The cipher used to encrypt the disk (see /proc/crypto)"), NULL },
		{ "hash",              'h',  POPT_ARG_STRING, &opt_hash,                0, N_("The hash used to create the encryption key from the passphrase"), NULL },
		{ "verify-passphrase", 'y',  POPT_ARG_NONE, &opt_verify_passphrase,     0, N_("Verifies the passphrase by asking for it twice"), NULL },
		{ "key-file",          'd',  POPT_ARG_STRING, &opt_key_file,            6, N_("Read the key from a file"), NULL },
		{ "master-key-file",  '\0',  POPT_ARG_STRING, &opt_master_key_file,     0, N_("Read the volume (master) key from file."), NULL },
		{ "dump-master-key",  '\0',  POPT_ARG_NONE, &opt_dump_master_key,       0, N_("Dump volume (master) key instead of keyslots info"), NULL },
		{ "key-size",          's',  POPT_ARG_INT, &opt_key_size,               0, N_("The size of the encryption key"), N_("BITS") },
		{ "keyfile-size",      'l',  POPT_ARG_LONG, &opt_keyfile_size,          0, N_("Limits the read from keyfile"), N_("bytes") },
		{ "keyfile-offset",   '\0',  POPT_ARG_STRING, &popt_tmp,                4, N_("Number of bytes to skip in keyfile"), N_("bytes") },
		{ "new-keyfile-size", '\0',  POPT_ARG_LONG, &opt_new_keyfile_size,      0, N_("Limits the read from newly added keyfile"), N_("bytes") },
		{ "new-keyfile-offset",'\0', POPT_ARG_STRING, &popt_tmp,                5, N_("Number of bytes to skip in newly added keyfile"), N_("bytes") },
		{ "key-slot",          'S',  POPT_ARG_INT, &opt_key_slot,               0, N_("Slot number for new key (default is first free)"), NULL },
		{ "size",              'b',  POPT_ARG_STRING, &popt_tmp,                1, N_("The size of the device"), N_("SECTORS") },
		{ "device-size",      '\0',  POPT_ARG_STRING, &opt_device_size_str,     0, N_("Use only specified device size (ignore rest of device). DANGEROUS!"), N_("bytes") },
		{ "offset",            'o',  POPT_ARG_STRING, &popt_tmp,                2, N_("The start offset in the backend device"), N_("SECTORS") },
		{ "skip",              'p',  POPT_ARG_STRING, &popt_tmp,                3, N_("How many sectors of the encrypted data to skip at the beginning"), N_("SECTORS") },
		{ "readonly",          'r',  POPT_ARG_NONE, &opt_readonly,              0, N_("Create a readonly mapping"), NULL },
		{ "batch-mode",        'q',  POPT_ARG_NONE, &opt_batch_mode,            0, N_("Do not ask for confirmation"), NULL },
		{ "timeout",           't',  POPT_ARG_INT, &opt_timeout,                0, N_("Timeout for interactive passphrase prompt (in seconds)"), N_("secs") },
		{ "progress-frequency",'\0', POPT_ARG_INT, &opt_progress_frequency,     0, N_("Progress line update (in seconds)"), N_("secs") },
		{ "tries",             'T',  POPT_ARG_INT, &opt_tries,                  0, N_("How often the input of the passphrase can be retried"), NULL },
		{ "align-payload",     '\0', POPT_ARG_INT, &opt_align_payload,          0, N_("Align payload at <n> sector boundaries - for luksFormat"), N_("SECTORS") },
		{ "header-backup-file",'\0', POPT_ARG_STRING, &opt_header_backup_file,  0, N_("File with LUKS header and keyslots backup"), NULL },
		{ "use-random",        '\0', POPT_ARG_NONE, &opt_random,                0, N_("Use /dev/random for generating volume key"), NULL },
		{ "use-urandom",       '\0', POPT_ARG_NONE, &opt_urandom,               0, N_("Use /dev/urandom for generating volume key"), NULL },
		{ "shared",            '\0', POPT_ARG_NONE, &opt_shared,                0, N_("Share device with another non-overlapping crypt segment"), NULL },
		{ "uuid",              '\0', POPT_ARG_STRING, &opt_uuid,                0, N_("UUID for device to use"), NULL },
		{ "allow-discards",    '\0', POPT_ARG_NONE, &opt_allow_discards,        0, N_("Allow discards (aka TRIM) requests for device"), NULL },
		{ "header",            '\0', POPT_ARG_STRING, &opt_header_device,       0, N_("Device or file with separated LUKS header"), NULL },
		{ "test-passphrase",   '\0', POPT_ARG_NONE, &opt_test_passphrase,       0, N_("Do not activate device, just check passphrase"), NULL },
		{ "tcrypt-hidden",     '\0', POPT_ARG_NONE, &opt_tcrypt_hidden,         0, N_("Use hidden header (hidden TCRYPT device)"), NULL },
		{ "tcrypt-system",     '\0', POPT_ARG_NONE, &opt_tcrypt_system,         0, N_("Device is system TCRYPT drive (with bootloader)"), NULL },
		{ "tcrypt-backup",     '\0', POPT_ARG_NONE, &opt_tcrypt_backup,         0, N_("Use backup (secondary) TCRYPT header"), NULL },
		{ "veracrypt",         '\0', POPT_ARG_NONE, &opt_veracrypt,             0, N_("Scan also for VeraCrypt compatible device"), NULL },
		{ "veracrypt-pim",     '\0', POPT_ARG_INT, &opt_veracrypt_pim,          0, N_("Personal Iteration Multiplier for VeraCrypt compatible device"), NULL },
		{ "veracrypt-query-pim", '\0', POPT_ARG_NONE, &opt_veracrypt_query_pim, 0, N_("Query Personal Iteration Multiplier for VeraCrypt compatible device"), NULL },
		{ "type",               'M', POPT_ARG_STRING, &opt_type,                0, N_("Type of device metadata: luks, luks1, luks2, plain, loopaes, tcrypt, bitlk"), NULL },
		{ "force-password",    '\0', POPT_ARG_NONE, &opt_force_password,        0, N_("Disable password quality check (if enabled)"), NULL },
		{ "perf-same_cpu_crypt",'\0', POPT_ARG_NONE, &opt_perf_same_cpu_crypt,  0, N_("Use dm-crypt same_cpu_crypt performance compatibility option"), NULL },
		{ "perf-submit_from_crypt_cpus",'\0', POPT_ARG_NONE, &opt_perf_submit_from_crypt_cpus,0,N_("Use dm-crypt submit_from_crypt_cpus performance compatibility option"), NULL },
		{ "deferred",          '\0', POPT_ARG_NONE, &opt_deferred_remove,       0, N_("Device removal is deferred until the last user closes it"), NULL },
		{ "serialize-memory-hard-pbkdf", '\0', POPT_ARG_NONE, &opt_serialize_memory_hard_pbkdf, 0, N_("Use global lock to serialize memory hard PBKDF (OOM workaround)"), NULL },
		{ "iter-time",         'i',  POPT_ARG_INT, &opt_iteration_time,         0, N_("PBKDF iteration time for LUKS (in ms)"), N_("msecs") },
		{ "pbkdf",             '\0', POPT_ARG_STRING, &opt_pbkdf,               0, N_("PBKDF algorithm (for LUKS2): argon2i, argon2id, pbkdf2"), NULL },
		{ "pbkdf-memory",      '\0', POPT_ARG_LONG, &opt_pbkdf_memory,          0, N_("PBKDF memory cost limit"), N_("kilobytes") },
		{ "pbkdf-parallel",    '\0', POPT_ARG_LONG, &opt_pbkdf_parallel,        0, N_("PBKDF parallel cost"), N_("threads") },
		{ "pbkdf-force-iterations",'\0',POPT_ARG_LONG, &opt_pbkdf_iterations,   0, N_("PBKDF iterations cost (forced, disables benchmark)"), NULL },
		{ "priority",          '\0', POPT_ARG_STRING, &opt_priority,            0, N_("Keyslot priority: ignore, normal, prefer"), NULL },
		{ "disable-locks",     '\0', POPT_ARG_NONE, &opt_disable_locks,         0, N_("Disable locking of on-disk metadata"), NULL },
		{ "disable-keyring",   '\0', POPT_ARG_NONE, &opt_disable_keyring,       0, N_("Disable loading volume keys via kernel keyring"), NULL },
		{ "integrity",          'I', POPT_ARG_STRING, &opt_integrity,           0, N_("Data integrity algorithm (LUKS2 only)"), NULL },
		{ "integrity-no-journal",'\0',POPT_ARG_NONE, &opt_integrity_nojournal,  0, N_("Disable journal for integrity device"), NULL },
		{ "integrity-no-wipe", '\0', POPT_ARG_NONE, &opt_integrity_no_wipe,     0, N_("Do not wipe device after format"), NULL },
		{ "integrity-legacy-padding",'\0', POPT_ARG_NONE, &opt_integrity_legacy_padding,0, N_("Use inefficient legacy padding (old kernels)"), NULL },
		{ "token-only",        '\0', POPT_ARG_NONE, &opt_token_only,            0, N_("Do not ask for passphrase if activation by token fails"), NULL },
		{ "token-id",          '\0', POPT_ARG_INT, &opt_token,                  0, N_("Token number (default: any)"), NULL },
		{ "key-description",   '\0', POPT_ARG_STRING, &opt_key_description,     0, N_("Key description"), NULL },
		{ "sector-size",       '\0', POPT_ARG_INT, &opt_sector_size,            0, N_("Encryption sector size (default: 512 bytes)"), NULL },
		{ "iv-large-sectors",  '\0', POPT_ARG_NONE, &opt_iv_large_sectors,      0, N_("Use IV counted in sector size (not in 512 bytes)"), NULL },
		{ "persistent",	       '\0', POPT_ARG_NONE, &opt_persistent,            0, N_("Set activation flags persistent for device"), NULL },
		{ "label",	       '\0', POPT_ARG_STRING, &opt_label,               0, N_("Set label for the LUKS2 device"), NULL },
		{ "subsystem",	       '\0', POPT_ARG_STRING, &opt_subsystem,           0, N_("Set subsystem label for the LUKS2 device"), NULL },
		{ "unbound",           '\0', POPT_ARG_NONE, &opt_unbound,               0, N_("Create or dump unbound (no assigned data segment) LUKS2 keyslot"), NULL },
		{ "json-file",	       '\0', POPT_ARG_STRING, &opt_json_file,           0, N_("Read or write the json from or to a file"), NULL },
		{ "luks2-metadata-size",'\0',POPT_ARG_STRING,&opt_luks2_metadata_size_str,0,N_("LUKS2 header metadata area size"), N_("bytes") },
		{ "luks2-keyslots-size",'\0',POPT_ARG_STRING,&opt_luks2_keyslots_size_str,0,N_("LUKS2 header keyslots area size"), N_("bytes") },
		{ "refresh",           '\0', POPT_ARG_NONE, &opt_refresh,               0, N_("Refresh (reactivate) device with new parameters"), NULL },
		{ "keyslot-key-size",  '\0', POPT_ARG_INT, &opt_keyslot_key_size,       0, N_("LUKS2 keyslot: The size of the encryption key"), N_("BITS") },
		{ "keyslot-cipher",    '\0', POPT_ARG_STRING, &opt_keyslot_cipher,      0, N_("LUKS2 keyslot: The cipher used for keyslot encryption"), NULL },
		{ "encrypt",           '\0', POPT_ARG_NONE, &opt_encrypt,               0, N_("Encrypt LUKS2 device (in-place encryption)."), NULL },
		{ "decrypt",	       '\0', POPT_ARG_NONE, &opt_decrypt,		0, N_("Decrypt LUKS2 device (remove encryption)."), NULL },
		{ "init-only",         '\0', POPT_ARG_NONE, &opt_reencrypt_init_only,	0, N_("Initialize LUKS2 reencryption in metadata only."), NULL },
		{ "resume-only",       '\0', POPT_ARG_NONE, &opt_reencrypt_resume_only,	0, N_("Resume initialized LUKS2 reencryption only."), NULL },
		{ "reduce-device-size",'\0', POPT_ARG_STRING, &opt_reduce_size_str,     0, N_("Reduce data device size (move data offset). DANGEROUS!"), N_("bytes") },
		{ "hotzone-size",      '\0', POPT_ARG_STRING, &opt_hotzone_size_str,    0, N_("Maximal reencryption hotzone size."), N_("bytes") },
		{ "resilience",	       '\0', POPT_ARG_STRING, &opt_resilience_mode,     0, N_("Reencryption hotzone resilience type (checksum,journal,none)"), NULL },
		{ "resilience-hash",   '\0', POPT_ARG_STRING, &opt_resilience_hash,     0, N_("Reencryption hotzone checksums hash"), NULL },
		{ "active-name",       '\0', POPT_ARG_STRING, &opt_active_name,		0, N_("Override device autodetection of dm device to be reencrypted"), NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;
	struct action_type *action;
	const char *aname;
	int r, total_keyfiles = 0;

	crypt_set_log_callback(NULL, tool_log, NULL);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext(PACKAGE, argc, argv, popt_options, 0);
	poptSetOtherOptionHelp(popt_context,
	                       _("[OPTION...] <action> <action-specific>"));

	while((r = poptGetNextOpt(popt_context)) > 0) {
		unsigned long long ull_value;
		char *endp;

		if (r == 6) {
			const char *kf = poptGetOptArg(popt_context);
			if (tools_is_stdin(kf))
				opt_keyfile_stdin = kf;
			else if (opt_keyfiles_count < MAX_KEYFILES)
				opt_keyfiles[opt_keyfiles_count++] = kf;
			total_keyfiles++;
			continue;
		}

		errno = 0;
		ull_value = strtoull(popt_tmp, &endp, 0);
		if (*endp || !*popt_tmp || !isdigit(*popt_tmp) ||
		    (errno == ERANGE && ull_value == ULLONG_MAX) ||
		    (errno != 0 && ull_value == 0))
			r = POPT_ERROR_BADNUMBER;

		switch(r) {
			case 1:
				opt_size = ull_value;
				break;
			case 2:
				opt_offset = ull_value;
				break;
			case 3:
				opt_skip = ull_value;
				opt_skip_valid = 1;
				break;
			case 4:
				opt_keyfile_offset = ull_value;
				break;
			case 5:
				opt_new_keyfile_offset = ull_value;
				break;
		}

		if (r < 0)
			break;
	}

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
		aname = "open";
		opt_type = "plain";
	} else if (!strcmp(aname, "plainOpen")) {
		aname = "open";
		opt_type = "plain";
	} else if (!strcmp(aname, "luksOpen")) {
		aname = "open";
		opt_type = "luks";
	} else if (!strcmp(aname, "loopaesOpen")) {
		aname = "open";
		opt_type = "loopaes";
	} else if (!strcmp(aname, "tcryptOpen")) {
		aname = "open";
		opt_type = "tcrypt";
	} else if (!strcmp(aname, "bitlkOpen")) {
		aname = "open";
		opt_type = "bitlk";
	} else if (!strcmp(aname, "tcryptDump")) {
		opt_type = "tcrypt";
	} else if (!strcmp(aname, "bitlkDump")) {
		opt_type = "bitlk";
	} else if (!strcmp(aname, "remove") ||
		   !strcmp(aname, "plainClose") ||
		   !strcmp(aname, "luksClose") ||
		   !strcmp(aname, "loopaesClose") ||
		   !strcmp(aname, "tcryptClose") ||
		   !strcmp(aname, "bitlkClose")) {
		aname = "close";
	} else if (!strcmp(aname, "luksErase")) {
		aname = "erase";
		opt_type = "luks";
	} else if (!strcmp(aname, "luksConfig")) {
		aname = "config";
		opt_type = "luks2";
	} else if (!strcmp(aname, "refresh")) {
		aname = "open";
		opt_refresh = 1;
	}

	/* ignore user supplied type and query device type instead */
	if (opt_refresh)
		opt_type = NULL;

	for(action = action_types; action->type; action++)
		if (strcmp(action->type, aname) == 0)
			break;

	if (!action->type)
		usage(popt_context, EXIT_FAILURE, _("Unknown action."),
		      poptGetInvocationName(popt_context));

	if (action_argc < action->required_action_argc)
		help_args(action, popt_context);

	/* FIXME: rewrite this from scratch */

	if (opt_refresh && opt_test_passphrase)
		usage(popt_context, EXIT_FAILURE,
		      _("Options --refresh and --test-passphrase are mutually exclusive."),
		      poptGetInvocationName(popt_context));

	if (opt_deferred_remove && strcmp(aname, "close"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --deferred is allowed only for close command."),
		      poptGetInvocationName(popt_context));

	if (opt_shared && (strcmp(aname, "open") || strcmp_or_null(opt_type, "plain")))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --shared is allowed only for open of plain device."),
		      poptGetInvocationName(popt_context));

	if (opt_allow_discards && strcmp(aname, "open"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --allow-discards is allowed only for open operation."),
		      poptGetInvocationName(popt_context));

	if (opt_persistent && strcmp(aname, "open"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --persistent is allowed only for open operation."),
		      poptGetInvocationName(popt_context));

	if (opt_serialize_memory_hard_pbkdf && strcmp(aname, "open"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --serialize-memory-hard-pbkdf is allowed only for open operation."),
		      poptGetInvocationName(popt_context));

	if (opt_persistent && opt_test_passphrase)
		usage(popt_context, EXIT_FAILURE,
		      _("Option --persistent is not allowed with --test-passphrase."),
		      poptGetInvocationName(popt_context));

	if (opt_key_size &&
	   strcmp(aname, "reencrypt") &&
	   strcmp(aname, "luksFormat") &&
	   strcmp(aname, "open") &&
	   strcmp(aname, "benchmark") &&
	   strcmp(aname, "luksAddKey"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --key-size is allowed only for luksFormat, luksAddKey,\n"
			"open and benchmark actions. To limit read from keyfile use --keyfile-size=(bytes)."),
		      poptGetInvocationName(popt_context));

	if (opt_integrity && strcmp(aname, "luksFormat"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --integrity is allowed only for luksFormat (LUKS2)."),
		      poptGetInvocationName(popt_context));

	if (opt_integrity_no_wipe && !opt_integrity)
		usage(popt_context, EXIT_FAILURE,
		      _("Option --integrity-no-wipe"
		        " can be used only for format action with integrity extension."),
		      poptGetInvocationName(popt_context));

	if ((opt_label || opt_subsystem) && strcmp(aname, "luksFormat") && strcmp(aname, "config"))
		usage(popt_context, EXIT_FAILURE,
		      _("Options --label and --subsystem are allowed only for luksFormat and config LUKS2 operations."),
		      poptGetInvocationName(popt_context));

	if (opt_test_passphrase && (strcmp(aname, "open") || !opt_type ||
	    (strncmp(opt_type, "luks", 4) && strcmp(opt_type, "tcrypt") && strcmp(opt_type, "bitlk"))))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --test-passphrase is allowed only for open of LUKS, TCRYPT and BITLK devices."),
		      poptGetInvocationName(popt_context));

	if (opt_key_size % 8 || opt_keyslot_key_size % 8)
		usage(popt_context, EXIT_FAILURE,
		      _("Key size must be a multiple of 8 bits"),
		      poptGetInvocationName(popt_context));

	if (!strcmp(aname, "luksKillSlot") && action_argc > 1)
		opt_key_slot = atoi(action_argv[1]);
	if (opt_key_slot != CRYPT_ANY_SLOT && opt_key_slot < 0)
		usage(popt_context, EXIT_FAILURE, _("Key slot is invalid."),
		      poptGetInvocationName(popt_context));

	if ((!strcmp(aname, "luksRemoveKey") ||
	     !strcmp(aname, "luksFormat")) &&
	     action_argc > 1) {
		if (opt_key_file)
			log_err(_("Option --key-file takes precedence over specified key file argument."));
		else
			opt_key_file = action_argv[1];
	}

	if (opt_keyfile_size < 0 || opt_new_keyfile_size < 0 || opt_key_size < 0)
		usage(popt_context, EXIT_FAILURE,
		      _("Negative number for option not permitted."),
		      poptGetInvocationName(popt_context));

	if (total_keyfiles > 1 && (strcmp_or_null(opt_type, "tcrypt")))
		usage(popt_context, EXIT_FAILURE, _("Only one --key-file argument is allowed."),
		      poptGetInvocationName(popt_context));

	if (opt_random && opt_urandom)
		usage(popt_context, EXIT_FAILURE, _("Only one of --use-[u]random options is allowed."),
		      poptGetInvocationName(popt_context));

	if ((opt_random || opt_urandom) && strcmp(aname, "luksFormat"))
		usage(popt_context, EXIT_FAILURE, _("Option --use-[u]random is allowed only for luksFormat."),
		      poptGetInvocationName(popt_context));

	if (opt_uuid && strcmp(aname, "luksFormat") && strcmp(aname, "luksUUID"))
		usage(popt_context, EXIT_FAILURE, _("Option --uuid is allowed only for luksFormat and luksUUID."),
		      poptGetInvocationName(popt_context));

	if (opt_align_payload && strcmp(aname, "luksFormat"))
		usage(popt_context, EXIT_FAILURE, _("Option --align-payload is allowed only for luksFormat."),
		      poptGetInvocationName(popt_context));

	if ((opt_luks2_metadata_size_str || opt_luks2_keyslots_size_str) && strcmp(aname, "luksFormat") && strcmp(aname, "reencrypt"))
		usage(popt_context, EXIT_FAILURE, _("Options --luks2-metadata-size and --opt-luks2-keyslots-size "
		"are allowed only for luksFormat with LUKS2."),
		      poptGetInvocationName(popt_context));
	if (opt_luks2_metadata_size_str &&
	    tools_string_to_size(NULL, opt_luks2_metadata_size_str, &opt_luks2_metadata_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid LUKS2 metadata size specification."),
		      poptGetInvocationName(popt_context));
	if (opt_luks2_keyslots_size_str &&
	    tools_string_to_size(NULL, opt_luks2_keyslots_size_str, &opt_luks2_keyslots_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid LUKS2 keyslots size specification."),
		      poptGetInvocationName(popt_context));

	if (opt_align_payload && opt_offset)
		usage(popt_context, EXIT_FAILURE, _("Options --align-payload and --offset cannot be combined."),
		      poptGetInvocationName(popt_context));

	if (opt_skip && (strcmp(aname, "open") ||
	    (strcmp_or_null(opt_type, "plain") && strcmp(opt_type, "loopaes"))))
		usage(popt_context, EXIT_FAILURE,
		_("Option --skip is supported only for open of plain and loopaes devices."),
		poptGetInvocationName(popt_context));

	if (opt_offset && ((strcmp(aname, "reencrypt") && strcmp(aname, "open") && strcmp(aname, "luksFormat")) ||
	    (!strcmp(aname, "open") && strcmp_or_null(opt_type, "plain") && strcmp(opt_type, "loopaes")) ||
	    (!strcmp(aname, "luksFormat") && opt_type && strncmp(opt_type, "luks", 4))))
		usage(popt_context, EXIT_FAILURE,
		_("Option --offset is supported only for open of plain and loopaes devices, luksFormat and device reencryption."),
		poptGetInvocationName(popt_context));

	if ((opt_tcrypt_hidden || opt_tcrypt_system || opt_tcrypt_backup) && strcmp(aname, "tcryptDump") &&
	    (strcmp(aname, "open") || !opt_type || strcmp(opt_type, "tcrypt")))
		usage(popt_context, EXIT_FAILURE,
		_("Option --tcrypt-hidden, --tcrypt-system or --tcrypt-backup is supported only for TCRYPT device."),
		poptGetInvocationName(popt_context));

	if (opt_tcrypt_hidden && opt_allow_discards)
		usage(popt_context, EXIT_FAILURE,
		_("Option --tcrypt-hidden cannot be combined with --allow-discards."),
		poptGetInvocationName(popt_context));

	if (opt_veracrypt && (!opt_type || strcmp(opt_type, "tcrypt")))
		usage(popt_context, EXIT_FAILURE,
		_("Option --veracrypt is supported only for TCRYPT device type."),
		poptGetInvocationName(popt_context));

	if (opt_veracrypt_pim != -1) {
		if (opt_veracrypt_pim < -1) {
			usage(popt_context, EXIT_FAILURE,
			_("Invalid argument for parameter --veracrypt-pim supplied."),
			poptGetInvocationName(popt_context));
		} else if (!opt_veracrypt) {
			usage(popt_context, EXIT_FAILURE,
			_("Option --veracrypt-pim is supported only for VeraCrypt compatible devices."),
			poptGetInvocationName(popt_context));
		}
	}

	if (opt_veracrypt_query_pim) {
		if (!opt_veracrypt) {
			usage(popt_context, EXIT_FAILURE,
			_("Option --veracrypt-query-pim is supported only for VeraCrypt compatible devices."),
			poptGetInvocationName(popt_context));
		} else if (opt_veracrypt_pim != -1) {
			usage(popt_context, EXIT_FAILURE,
			_("The options --veracrypt-pim and --veracrypt-query-pim are mutually exclusive."),
			poptGetInvocationName(popt_context));
		}
	}

	if (opt_priority && strcmp(opt_priority, "normal") && strcmp(opt_priority, "prefer") && strcmp(opt_priority, "ignore"))
		usage(popt_context, EXIT_FAILURE,
		_("Option --priority can be only ignore/normal/prefer."),
		poptGetInvocationName(popt_context));

	if (!strcmp(aname, "config") && opt_priority && opt_key_slot == CRYPT_ANY_SLOT)
		usage(popt_context, EXIT_FAILURE,
		_("Keyslot specification is required."),
		poptGetInvocationName(popt_context));

	if (opt_pbkdf && crypt_parse_pbkdf(opt_pbkdf, &opt_pbkdf))
		usage(popt_context, EXIT_FAILURE,
		_("Password-based key derivation function (PBKDF) can be only pbkdf2 or argon2i/argon2id."),
		poptGetInvocationName(popt_context));

	if (opt_pbkdf_iterations && opt_iteration_time)
		usage(popt_context, EXIT_FAILURE,
		_("PBKDF forced iterations cannot be combined with iteration time option."),
		poptGetInvocationName(popt_context));

	if (opt_sector_size && strcmp(aname, "reencrypt") && strcmp(aname, "luksFormat") &&
	    (strcmp(aname, "open") || strcmp_or_null(opt_type, "plain")))
		usage(popt_context, EXIT_FAILURE,
		      _("Sector size option is not supported for this command."),
		      poptGetInvocationName(popt_context));

	if (opt_sector_size && (opt_sector_size < SECTOR_SIZE || opt_sector_size > MAX_SECTOR_SIZE ||
	    (opt_sector_size & (opt_sector_size - 1))))
		usage(popt_context, EXIT_FAILURE,
		      _("Unsupported encryption sector size."),
		      poptGetInvocationName(popt_context));

	if (opt_iv_large_sectors && (strcmp(aname, "open") || strcmp_or_null(opt_type, "plain") ||
	    opt_sector_size <= SECTOR_SIZE))
		usage(popt_context, EXIT_FAILURE,
		      _("Large IV sectors option is supported only for opening plain type device with sector size larger than 512 bytes."),
		      poptGetInvocationName(popt_context));

	if (opt_unbound && !opt_key_size && !strcmp(aname, "luksAddKey"))
		usage(popt_context, EXIT_FAILURE,
		      _("Key size is required with --unbound option."),
		      poptGetInvocationName(popt_context));

	if (opt_unbound && !strcmp(aname, "luksDump") && opt_key_slot == CRYPT_ANY_SLOT)
		usage(popt_context, EXIT_FAILURE,
		      _("Keyslot specification is required."),
		      poptGetInvocationName(popt_context));

	if (opt_unbound && strcmp(aname, "luksAddKey") && strcmp(aname, "luksDump"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --unbound may be used only with luksAddKey and luksDump actions."),
		      poptGetInvocationName(popt_context));

	if (opt_refresh && strcmp(aname, "open"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --refresh may be used only with open action."),
		      poptGetInvocationName(popt_context));

	if (opt_debug || opt_debug_json) {
		opt_debug = 1;
		opt_verbose = 1;
		crypt_set_debug_level(opt_debug_json? CRYPT_DEBUG_JSON : CRYPT_DEBUG_ALL);
		dbg_version_and_cmd(argc, argv);
	}

	if (opt_disable_locks && crypt_metadata_locking(NULL, 0)) {
		log_std(_("Cannot disable metadata locking."));
		poptFreeContext(popt_context);
		exit(EXIT_FAILURE);
	}

	if (opt_disable_keyring)
		(void) crypt_volume_key_keyring(NULL, 0);

	if (opt_hotzone_size_str &&
	    (tools_string_to_size(NULL, opt_hotzone_size_str, &opt_hotzone_size) || !opt_hotzone_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid max reencryption hotzone size specification."),
		      poptGetInvocationName(popt_context));

	if (!opt_hotzone_size && opt_resilience_mode && !strcmp(opt_resilience_mode, "none"))
		opt_hotzone_size = 50 * 1024 * 1024;

	if (opt_reduce_size_str &&
	    tools_string_to_size(NULL, opt_reduce_size_str, &opt_reduce_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid device size specification."),
		      poptGetInvocationName(popt_context));
	if (opt_reduce_size > 1024 * 1024 * 1024)
		usage(popt_context, EXIT_FAILURE, _("Maximum device reduce size is 1 GiB."),
		      poptGetInvocationName(popt_context));
	if (opt_reduce_size % SECTOR_SIZE)
		usage(popt_context, EXIT_FAILURE, _("Reduce size must be multiple of 512 bytes sector."),
		      poptGetInvocationName(popt_context));

	if (opt_device_size_str &&
	    tools_string_to_size(NULL, opt_device_size_str, &opt_device_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid data size specification."),
		      poptGetInvocationName(popt_context));

	opt_data_shift = -(int64_t)opt_reduce_size;
	if (opt_data_shift > 0)
		usage(popt_context, EXIT_FAILURE, _("Reduce size overflow."),
		      poptGetInvocationName(popt_context));

	if (opt_decrypt && !opt_header_device)
		usage(popt_context, EXIT_FAILURE, _("LUKS2 decryption requires option --header."),
		      poptGetInvocationName(popt_context));

	if (opt_device_size % SECTOR_SIZE)
		usage(popt_context, EXIT_FAILURE, _("Device size must be multiple of 512 bytes sector."),
		      poptGetInvocationName(popt_context));

	if (opt_data_shift && opt_device_size)
		usage(popt_context, EXIT_FAILURE, _("Options --reduce-device-size and --data-size cannot be combined."),
		      poptGetInvocationName(popt_context));

	if (opt_device_size && opt_size)
		usage(popt_context, EXIT_FAILURE, _("Options --device-size and --size cannot be combined."),
		      poptGetInvocationName(popt_context));

	if ((opt_keyslot_cipher && !opt_keyslot_key_size) || (!opt_keyslot_cipher && opt_keyslot_key_size))
		usage(popt_context, EXIT_FAILURE, _("Options --keyslot-cipher and --keyslot-key-size must be used together."),
		      poptGetInvocationName(popt_context));

	r = run_action(action);
	poptFreeContext(popt_context);
	return r;
}
