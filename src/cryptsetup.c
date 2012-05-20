/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004, Christophe Saout <christophe@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <limits.h>
#include <libcryptsetup.h>
#include <popt.h>

#include "cryptsetup.h"

static int opt_verbose = 0;
static int opt_debug = 0;
static const char *opt_cipher = NULL;
static const char *opt_hash = NULL;
static int opt_verify_passphrase = 0;
static const char *opt_key_file = NULL;
static const char *opt_master_key_file = NULL;
static const char *opt_header_backup_file = NULL;
static const char *opt_uuid = NULL;
static const char *opt_header_device = NULL;
static int opt_key_size = 0;
static long opt_keyfile_size = 0;
static long opt_new_keyfile_size = 0;
static long opt_keyfile_offset = 0;
static long opt_new_keyfile_offset = 0;
static int opt_key_slot = CRYPT_ANY_SLOT;
static uint64_t opt_size = 0;
static uint64_t opt_offset = 0;
static uint64_t opt_skip = 0;
static int opt_skip_valid = 0;
static int opt_readonly = 0;
static int opt_iteration_time = 1000;
static int opt_batch_mode = 0;
static int opt_version_mode = 0;
static int opt_timeout = 0;
static int opt_tries = 3;
static int opt_align_payload = 0;
static int opt_random = 0;
static int opt_urandom = 0;
static int opt_dump_master_key = 0;
static int opt_shared = 0;
static int opt_allow_discards = 0;

static const char **action_argv;
static int action_argc;

static int action_create(int arg);
static int action_remove(int arg);
static int action_resize(int arg);
static int action_status(int arg);
static int action_luksFormat(int arg);
static int action_luksOpen(int arg);
static int action_luksAddKey(int arg);
static int action_luksKillSlot(int arg);
static int action_luksRemoveKey(int arg);
static int action_luksChangeKey(int arg);
static int action_isLuks(int arg);
static int action_luksUUID(int arg);
static int action_luksDump(int arg);
static int action_luksSuspend(int arg);
static int action_luksResume(int arg);
static int action_luksBackup(int arg);
static int action_luksRestore(int arg);
static int action_loopaesOpen(int arg);
static int action_luksRepair(int arg);

static struct action_type {
	const char *type;
	int (*handler)(int);
	int arg;
	int required_action_argc;
	int required_memlock;
	const char *arg_desc;
	const char *desc;
} action_types[] = {
	{ "create",	action_create,		0, 2, 1, N_("<name> <device>"),N_("create device") },
	{ "remove",	action_remove,		0, 1, 1, N_("<name>"), N_("remove device") },
	{ "resize",	action_resize,		0, 1, 1, N_("<name>"), N_("resize active device") },
	{ "status",	action_status,		0, 1, 0, N_("<name>"), N_("show device status") },
	{ "repair",	action_luksRepair,	0, 1, 1, N_("<device>"), N_("try to repair on-disk metadata") },
	{ "luksFormat", action_luksFormat,	0, 1, 1, N_("<device> [<new key file>]"), N_("formats a LUKS device") },
	{ "luksOpen",	action_luksOpen,	0, 2, 1, N_("<device> <name> "), N_("open LUKS device as mapping <name>") },
	{ "luksAddKey",	action_luksAddKey,	0, 1, 1, N_("<device> [<new key file>]"), N_("add key to LUKS device") },
	{ "luksRemoveKey",action_luksRemoveKey,	0, 1, 1, N_("<device> [<key file>]"), N_("removes supplied key or key file from LUKS device") },
	{ "luksChangeKey",action_luksChangeKey,	0, 1, 1, N_("<device> [<key file>]"), N_("changes supplied key or key file of LUKS device") },
	{ "luksKillSlot",  action_luksKillSlot, 0, 2, 1, N_("<device> <key slot>"), N_("wipes key with number <key slot> from LUKS device") },
	{ "luksUUID",	action_luksUUID,	0, 1, 0, N_("<device>"), N_("print UUID of LUKS device") },
	{ "isLuks",	action_isLuks,		0, 1, 0, N_("<device>"), N_("tests <device> for LUKS partition header") },
	{ "luksClose",	action_remove,		0, 1, 1, N_("<name>"), N_("remove LUKS mapping") },
	{ "luksDump",	action_luksDump,	0, 1, 1, N_("<device>"), N_("dump LUKS partition information") },
	{ "luksSuspend",action_luksSuspend,	0, 1, 1, N_("<device>"), N_("Suspend LUKS device and wipe key (all IOs are frozen).") },
	{ "luksResume",	action_luksResume,	0, 1, 1, N_("<device>"), N_("Resume suspended LUKS device.") },
	{ "luksHeaderBackup",action_luksBackup,	0, 1, 1, N_("<device>"), N_("Backup LUKS device header and keyslots") },
	{ "luksHeaderRestore",action_luksRestore,0,1, 1, N_("<device>"), N_("Restore LUKS device header and keyslots") },
	{ "loopaesOpen",action_loopaesOpen,	0, 2, 1, N_("<device> <name> "), N_("open loop-AES device as mapping <name>") },
	{ "loopaesClose",action_remove,		0, 1, 1, N_("<name>"), N_("remove loop-AES mapping") },
	{ NULL, NULL, 0, 0, 0, NULL, NULL }
};

__attribute__((format(printf, 5, 6)))
static void clogger(struct crypt_device *cd, int level, const char *file,
		   int line, const char *format, ...)
{
	va_list argp;
	char *target = NULL;

	va_start(argp, format);

	if (vasprintf(&target, format, argp) > 0) {
		if (level >= 0) {
			crypt_log(cd, level, target);
#ifdef CRYPT_DEBUG
		} else if (opt_debug)
			printf("# %s:%d %s\n", file ?: "?", line, target);
#else
		} else if (opt_debug)
			printf("# %s\n", target);
#endif
	}

	va_end(argp);
	free(target);
}

static int _yesDialog(const char *msg, void *usrptr __attribute__((unused)))
{
	char *answer = NULL;
	size_t size = 0;
	int r = 1;

	if(isatty(STDIN_FILENO) && !opt_batch_mode) {
		log_std("\nWARNING!\n========\n");
		log_std("%s\n\nAre you sure? (Type uppercase yes): ", msg);
		if(getline(&answer, &size, stdin) == -1) {
			perror("getline");
			free(answer);
			return 0;
		}
		if(strcmp(answer, "YES\n"))
			r = 0;
		free(answer);
	}

	return r;
}

static void _log(int level, const char *msg, void *usrptr __attribute__((unused)))
{
	switch(level) {

	case CRYPT_LOG_NORMAL:
		fputs(msg, stdout);
		break;
	case CRYPT_LOG_VERBOSE:
		if (opt_verbose)
			fputs(msg, stdout);
		break;
	case CRYPT_LOG_ERROR:
		fputs(msg, stderr);
		break;
	case CRYPT_LOG_DEBUG:
		if (opt_debug)
			printf("# %s\n", msg);
		break;
	default:
		fprintf(stderr, "Internal error on logging class for msg: %s", msg);
		break;
	}
}

static void _quiet_log(int level, const char *msg, void *usrptr)
{
	if (!opt_verbose && (level == CRYPT_LOG_ERROR || level == CRYPT_LOG_NORMAL))
		level = CRYPT_LOG_VERBOSE;
	_log(level, msg, usrptr);
}

static int _verify_passphrase(int def)
{
	/* Batch mode switch off verify - if not overrided by -y */
	if (opt_verify_passphrase)
		def = 1;
	else if (opt_batch_mode)
		def = 0;

	/* Non-tty input doesn't allow verify */
	if (def && !isatty(STDIN_FILENO)) {
		if (opt_verify_passphrase)
			log_err(_("Can't do passphrase verification on non-tty inputs.\n"));
		def = 0;
	}

	return def;
}

static void show_status(int errcode)
{
	char error[256], *error_;

	if(!opt_verbose)
		return;

	if(!errcode) {
		log_std(_("Command successful.\n"));
		return;
	}

	crypt_get_error(error, sizeof(error));

	if (!error[0]) {
		error_ = strerror_r(-errcode, error, sizeof(error));
		if (error_ != error) {
			strncpy(error, error_, sizeof(error));
			error[sizeof(error) - 1] = '\0';
		}
	}

	log_err(_("Command failed with code %i"), -errcode);
	if (*error)
		log_err(": %s\n", error);
	else
		log_err(".\n");
}

static const char *uuid_or_device(const char *spec)
{
	static char device[PATH_MAX];
	char s, *ptr;
	int i = 0, uuid_len = 5;

	/* Check if it is correct UUID=<LUKS_UUID> format */
	if (spec && !strncmp(spec, "UUID=", uuid_len)) {
		strcpy(device, "/dev/disk/by-uuid/");
		ptr = &device[strlen(device)];
		i = uuid_len;
		while ((s = spec[i++]) && i < PATH_MAX) {
			if (!isxdigit(s) && s != '-')
				return spec; /* Bail it out */
			if (isalpha(s))
				s = tolower(s);
			*ptr++ = s;
		}
		*ptr = '\0';
		return device;
	}

	return spec;
}

static int action_create(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	struct crypt_params_plain params = {
		.hash = opt_hash ?: DEFAULT_PLAIN_HASH,
		.skip = opt_skip,
		.offset = opt_offset,
		.size = opt_size,
	};
	char *password = NULL;
	size_t passwordLen;
	size_t key_size = (opt_key_size ?: DEFAULT_PLAIN_KEYBITS) / 8;
	uint32_t activate_flags = 0;
	int r;

	if (params.hash && !strcmp(params.hash, "plain"))
		params.hash = NULL;

	/* FIXME: temporary hack */
	if (opt_key_file && strcmp(opt_key_file, "-"))
		params.hash = NULL;

	if ((opt_keyfile_offset || opt_keyfile_size) && opt_key_file)
		log_std(("Ignoring keyfile offset and size options, keyfile read "
			 "size is always the same as encryption key size.\n"));

	r = crypt_parse_name_and_mode(opt_cipher ?: DEFAULT_CIPHER(PLAIN),
				      cipher, NULL, cipher_mode);
	if (r < 0) {
		log_err("No known cipher specification pattern detected.\n");
		goto out;
	}

	if ((r = crypt_init(&cd, action_argv[1])))
		goto out;

	crypt_set_timeout(cd, opt_timeout);
	crypt_set_password_retry(cd, opt_tries);

	r = crypt_format(cd, CRYPT_PLAIN,
			 cipher, cipher_mode,
			 NULL, NULL,
			 key_size,
			 &params);
	if (r < 0)
		goto out;

	if (opt_readonly)
		activate_flags |= CRYPT_ACTIVATE_READONLY;

	if (opt_shared)
		activate_flags |= CRYPT_ACTIVATE_SHARED;

	if (opt_allow_discards)
		activate_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

	if (opt_key_file)
		/* With hashing, read the whole keyfile */
		r = crypt_activate_by_keyfile_offset(cd, action_argv[0],
			CRYPT_ANY_SLOT, opt_key_file,
			params.hash ? 0 : key_size, 0,
			activate_flags);
	else {
		r = crypt_get_key(_("Enter passphrase: "),
				  &password, &passwordLen,
				  opt_keyfile_offset, opt_keyfile_size,
				  NULL, opt_timeout,
				  _verify_passphrase(0),
				  cd);
		if (r < 0)
			goto out;

		r = crypt_activate_by_passphrase(cd, action_argv[0],
			CRYPT_ANY_SLOT, password, passwordLen, activate_flags);
	}
out:
	crypt_free(cd);
	crypt_safe_free(password);

	return r;
}

static int action_loopaesOpen(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	struct crypt_params_loopaes params = {
		.hash = opt_hash ?: NULL,
		.offset = opt_offset,
		.skip = opt_skip_valid ? opt_skip : opt_offset,
	};
	unsigned int key_size = (opt_key_size ?: DEFAULT_LOOPAES_KEYBITS) / 8;
	uint32_t activate_flags = 0;
	int r;

	if (!opt_key_file) {
		log_err(_("Option --key-file is required.\n"));
		return -EINVAL;
	}

	if (opt_readonly)
		activate_flags |= CRYPT_ACTIVATE_READONLY;

	if (opt_allow_discards)
		activate_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	r = crypt_format(cd, CRYPT_LOOPAES, opt_cipher ?: DEFAULT_LOOPAES_CIPHER,
			 NULL, NULL, NULL, key_size, &params);
	if (r < 0)
		goto out;

	r = crypt_activate_by_keyfile_offset(cd, action_argv[1], CRYPT_ANY_SLOT,
				      opt_key_file, opt_keyfile_size,
				      opt_keyfile_size, activate_flags);
out:
	crypt_free(cd);

	return r;
}

static int action_remove(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_init_by_name(&cd, action_argv[0]);
	if (r == 0)
		r = crypt_deactivate(cd, action_argv[0]);

	crypt_free(cd);
	return r;
}

static int action_resize(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_init_by_name_and_header(&cd, action_argv[0], opt_header_device);
	if (r == 0)
		r = crypt_resize(cd, action_argv[0], opt_size);

	crypt_free(cd);
	return r;
}

static int action_status(int arg __attribute__((unused)))
{
	crypt_status_info ci;
	struct crypt_active_device cad;
	struct crypt_device *cd = NULL;
	struct stat st;
	char *backing_file;
	const char *device;
	int path = 0, r = 0;

	/* perhaps a path, not a dm device name */
	if (strchr(action_argv[0], '/') && !stat(action_argv[0], &st))
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
		if (r < 0 || !crypt_get_type(cd))
			goto out;

		log_std("  type:    %s\n", crypt_get_type(cd));

		r = crypt_get_active_device(cd, action_argv[0], &cad);
		if (r < 0)
			goto out;

		log_std("  cipher:  %s-%s\n", crypt_get_cipher(cd), crypt_get_cipher_mode(cd));
		log_std("  keysize: %d bits\n", crypt_get_volume_key_size(cd) * 8);
		device = crypt_get_device_name(cd);
		log_std("  device:  %s\n", device);
		if (crypt_loop_device(device)) {
			backing_file = crypt_loop_backing_file(device);
			log_std("  loop:    %s\n", backing_file);
			free(backing_file);
		}
		log_std("  offset:  %" PRIu64 " sectors\n", cad.offset);
		log_std("  size:    %" PRIu64 " sectors\n", cad.size);
		if (cad.iv_offset)
			log_std("  skipped: %" PRIu64 " sectors\n", cad.iv_offset);
		log_std("  mode:    %s\n", cad.flags & CRYPT_ACTIVATE_READONLY ?
					   "readonly" : "read/write");
		if (cad.flags & CRYPT_ACTIVATE_ALLOW_DISCARDS)
			log_std("  flags:   discards\n");
	}
out:
	crypt_free(cd);
	return r;
}

static int _read_mk(const char *file, char **key, int keysize)
{
	int fd;

	*key = crypt_safe_alloc(keysize);
	if (!*key)
		return -ENOMEM;

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		log_err("Cannot read keyfile %s.\n", file);
		goto fail;
	}
	if ((read(fd, *key, keysize) != keysize)) {
		log_err("Cannot read %d bytes from keyfile %s.\n", keysize, file);
		close(fd);
		goto fail;
	}
	close(fd);
	return 0;
fail:
	crypt_safe_free(*key);
	*key = NULL;
	return -EINVAL;
}

static int action_luksRepair(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r;

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	/* Currently only LUKS1 allows repair */
	crypt_set_log_callback(cd, _quiet_log, NULL);
	r = crypt_load(cd, CRYPT_LUKS1, NULL);
	crypt_set_log_callback(cd, _log, NULL);
	if (r == 0) {
		log_verbose( _("No known problems detected for LUKS header.\n"));
		goto out;
	}

	r = _yesDialog(_("Really try to repair LUKS device header?"),
		       NULL) ? 0 : -EINVAL;
	if (r == 0)
		r = crypt_repair(cd, CRYPT_LUKS1, NULL);
out:
	crypt_free(cd);
	return r;
}

static int action_luksFormat(int arg __attribute__((unused)))
{
	int r = -EINVAL, keysize;
	const char *header_device;
	char *msg = NULL, *key = NULL, cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	char *password = NULL;
	size_t passwordLen;
	struct crypt_device *cd = NULL;
	struct crypt_params_luks1 params = {
		.hash = opt_hash ?: DEFAULT_LUKS1_HASH,
		.data_alignment = opt_align_payload,
		.data_device = opt_header_device ? action_argv[0] : NULL,
	};

	header_device = opt_header_device ?: action_argv[0];

	if(asprintf(&msg, _("This will overwrite data on %s irrevocably."),
		    header_device) == -1) {
		log_err(_("memory allocation error in action_luksFormat"));
		r = -ENOMEM;
		goto out;
	}
	r = _yesDialog(msg, NULL) ? 0 : -EINVAL;
	free(msg);
	if (r < 0)
		goto out;

	r = crypt_parse_name_and_mode(opt_cipher ?: DEFAULT_CIPHER(LUKS1),
				      cipher, NULL, cipher_mode);
	if (r < 0) {
		log_err(_("No known cipher specification pattern detected.\n"));
		goto out;
	}

	if ((r = crypt_init(&cd, header_device))) {
		if (opt_header_device)
			log_err(_("Cannot use %s as on-disk header.\n"), header_device);
		goto out;
	}

	keysize = (opt_key_size ?: DEFAULT_LUKS1_KEYBITS) / 8;

	crypt_set_timeout(cd, opt_timeout);
	if (opt_iteration_time)
		crypt_set_iteration_time(cd, opt_iteration_time);

	if (opt_random)
		crypt_set_rng_type(cd, CRYPT_RNG_RANDOM);
	else if (opt_urandom)
		crypt_set_rng_type(cd, CRYPT_RNG_URANDOM);

	r = crypt_get_key(_("Enter LUKS passphrase: "), &password, &passwordLen,
			  opt_keyfile_offset, opt_keyfile_size, opt_key_file,
			  opt_timeout, _verify_passphrase(1), cd);
	if (r < 0)
		goto out;

	if (opt_master_key_file) {
		r = _read_mk(opt_master_key_file, &key, keysize);
		if (r < 0)
			goto out;
	}

	r = crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode,
			 opt_uuid, key, keysize, &params);
	if (r < 0)
		goto out;

	r = crypt_keyslot_add_by_volume_key(cd, opt_key_slot,
					    key, keysize,
					    password, passwordLen);
out:
	crypt_free(cd);
	crypt_safe_free(key);
	crypt_safe_free(password);

	return r;
}

static int action_luksOpen(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	const char *data_device, *header_device;
	char *key = NULL;
	uint32_t flags = 0;
	int r, keysize;

	if (opt_header_device) {
		header_device = uuid_or_device(opt_header_device);
		data_device = action_argv[0];
	} else {
		header_device = uuid_or_device(action_argv[0]);
		data_device = NULL;
	}

	if ((r = crypt_init(&cd, header_device)))
		goto out;

	if ((r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	if (data_device &&
	    (r = crypt_set_data_device(cd, data_device)))
		goto out;

	if (!data_device && (crypt_get_data_offset(cd) < 8)) {
		log_err(_("Reduced data offset is allowed only for detached LUKS header.\n"));
		r = -EINVAL;
		goto out;
	}

	crypt_set_timeout(cd, opt_timeout);
	crypt_set_password_retry(cd, opt_tries);
	crypt_set_password_verify(cd, _verify_passphrase(0));

	if (opt_iteration_time)
		crypt_set_iteration_time(cd, opt_iteration_time);

	if (opt_readonly)
		flags |= CRYPT_ACTIVATE_READONLY;

	if (opt_allow_discards)
		flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

	if (opt_master_key_file) {
		keysize = crypt_get_volume_key_size(cd);
		r = _read_mk(opt_master_key_file, &key, keysize);
		if (r < 0)
			goto out;
		r = crypt_activate_by_volume_key(cd, action_argv[1],
						 key, keysize, flags);
	} else if (opt_key_file) {
		crypt_set_password_retry(cd, 1);
		r = crypt_activate_by_keyfile_offset(cd, action_argv[1],
			opt_key_slot, opt_key_file, opt_keyfile_size,
			opt_keyfile_offset, flags);
	} else
		r = crypt_activate_by_passphrase(cd, action_argv[1],
			opt_key_slot, NULL, 0, flags);
out:
	crypt_safe_free(key);
	crypt_free(cd);
	return r;
}

static int verify_keyslot(struct crypt_device *cd, int key_slot,
			  char *msg_last, char *msg_pass,
			  const char *key_file, int keyfile_offset,
			  int keyfile_size)
{
	crypt_keyslot_info ki;
	char *password = NULL;
	size_t passwordLen;
	int i, r;

	ki = crypt_keyslot_status(cd, key_slot);
	if (ki == CRYPT_SLOT_ACTIVE_LAST && msg_last && !_yesDialog(msg_last, NULL))
		return -EPERM;

	r = crypt_get_key(msg_pass, &password, &passwordLen,
			  keyfile_offset, keyfile_size, key_file, opt_timeout,
			  _verify_passphrase(0), cd);
	if(r < 0)
		goto out;

	if (ki == CRYPT_SLOT_ACTIVE_LAST) {
		/* check the last keyslot */
		r = crypt_activate_by_passphrase(cd, NULL, key_slot,
						 password, passwordLen, 0);
	} else {
		/* try all other keyslots */
		for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS1); i++) {
			if (i == key_slot)
				continue;
			ki = crypt_keyslot_status(cd, key_slot);
			if (ki == CRYPT_SLOT_ACTIVE)
			r = crypt_activate_by_passphrase(cd, NULL, i,
							 password, passwordLen, 0);
			if (r == i)
				break;
		}
	}

	if (r < 0)
		log_err(_("No key available with this passphrase.\n"));
out:
	crypt_safe_free(password);
	return r;
}

static int action_luksKillSlot(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device(action_argv[0]))))
		goto out;

	crypt_set_confirm_callback(cd, _yesDialog, NULL);
	crypt_set_timeout(cd, opt_timeout);

	if ((r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	switch (crypt_keyslot_status(cd, opt_key_slot)) {
	case CRYPT_SLOT_ACTIVE_LAST:
	case CRYPT_SLOT_ACTIVE:
		log_verbose(_("Key slot %d selected for deletion.\n"), opt_key_slot);
		break;
	case CRYPT_SLOT_INACTIVE:
		log_err(_("Key %d not active. Can't wipe.\n"), opt_key_slot);
	case CRYPT_SLOT_INVALID:
		r = -EINVAL;
		goto out;
	}

	if (!opt_batch_mode) {
		r = verify_keyslot(cd, opt_key_slot,
			_("This is the last keyslot. Device will become unusable after purging this key."),
			_("Enter any remaining LUKS passphrase: "),
			opt_key_file, opt_keyfile_offset, opt_keyfile_size);
		if (r < 0)
			goto out;
	}

	r = crypt_keyslot_destroy(cd, opt_key_slot);
out:
	crypt_free(cd);
	return r;
}

static int action_luksRemoveKey(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	char *password = NULL;
	size_t passwordLen;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device(action_argv[0]))))
		goto out;

	crypt_set_confirm_callback(cd, _yesDialog, NULL);
	crypt_set_timeout(cd, opt_timeout);

	if ((r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	r = crypt_get_key(_("Enter LUKS passphrase to be deleted: "),
		      &password, &passwordLen,
		      opt_keyfile_offset, opt_keyfile_size, opt_key_file,
		      opt_timeout,
		      _verify_passphrase(0),
		      cd);
	if(r < 0)
		goto out;

	r = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT,
					 password, passwordLen, 0);
	if (r < 0)
		goto out;

	opt_key_slot = r;
	log_verbose(_("Key slot %d selected for deletion.\n"), opt_key_slot);

	if (crypt_keyslot_status(cd, opt_key_slot) == CRYPT_SLOT_ACTIVE_LAST &&
	    !_yesDialog(_("This is the last keyslot. "
			  "Device will become unusable after purging this key."),
			NULL)) {
		r = -EPERM;
		goto out;
	}

	r = crypt_keyslot_destroy(cd, opt_key_slot);
out:
	crypt_safe_free(password);
	crypt_free(cd);
	return r;
}

static int action_luksAddKey(int arg __attribute__((unused)))
{
	int r = -EINVAL, keysize = 0;
	char *key = NULL;
	const char *opt_new_key_file = (action_argc > 1 ? action_argv[1] : NULL);
	struct crypt_device *cd = NULL;

	if ((r = crypt_init(&cd, uuid_or_device(action_argv[0]))))
		goto out;

	crypt_set_confirm_callback(cd, _yesDialog, NULL);

	if ((r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	keysize = crypt_get_volume_key_size(cd);
	/* FIXME: lib cannot properly set verification for new/old passphrase */
	crypt_set_password_verify(cd, _verify_passphrase(0));
	crypt_set_timeout(cd, opt_timeout);
	if (opt_iteration_time)
		crypt_set_iteration_time(cd, opt_iteration_time);

	if (opt_master_key_file) {
		r = _read_mk(opt_master_key_file, &key, keysize);
		if (r < 0)
			goto out;
		//FIXME: process keyfile arg
		r = crypt_keyslot_add_by_volume_key(cd, opt_key_slot,
						    key, keysize, NULL, 0);
	} else if (opt_key_file || opt_new_key_file) {
		r = crypt_keyslot_add_by_keyfile_offset(cd, opt_key_slot,
			opt_key_file, opt_keyfile_size, opt_keyfile_offset,
			opt_new_key_file, opt_new_keyfile_size, opt_new_keyfile_offset);
	} else {
		r = crypt_keyslot_add_by_passphrase(cd, opt_key_slot,
						    NULL, 0, NULL, 0);
	}
out:
	crypt_free(cd);
	crypt_safe_free(key);
	return r;
}

static int _slots_full(struct crypt_device *cd)
{
	int i;

	for (i = 0; i < crypt_keyslot_max(crypt_get_type(cd)); i++)
		if (crypt_keyslot_status(cd, i) == CRYPT_SLOT_INACTIVE)
			return 0;
	return 1;
}

static int action_luksChangeKey(int arg __attribute__((unused)))
{
	const char *opt_new_key_file = (action_argc > 1 ? action_argv[1] : NULL);
	struct crypt_device *cd = NULL;
	char *vk = NULL, *password = NULL;
	size_t passwordLen = 0;
	size_t vk_size;
	int new_key_slot, old_key_slot, r;

	if ((r = crypt_init(&cd, uuid_or_device(action_argv[0]))))
		goto out;

	if ((r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	if (opt_iteration_time)
		crypt_set_iteration_time(cd, opt_iteration_time);

	r = crypt_get_key(_("Enter LUKS passphrase to be changed: "),
		      &password, &passwordLen,
		      opt_keyfile_offset, opt_keyfile_size, opt_key_file,
		      opt_timeout, _verify_passphrase(0), cd);
	if (r < 0)
		goto out;

	vk_size = crypt_get_volume_key_size(cd);
	vk = crypt_safe_alloc(vk_size);
	if (!vk) {
		r = -ENOMEM;
		goto out;
	}

	r = crypt_volume_key_get(cd, opt_key_slot, vk, &vk_size,
				 password, passwordLen);
	if (r < 0) {
		if (opt_key_slot != CRYPT_ANY_SLOT)
			log_err(_("No key available with this passphrase.\n"));
		goto out;
	}

	if (opt_key_slot != CRYPT_ANY_SLOT || _slots_full(cd)) {
		log_dbg("Key slot %d is going to be overwritten (%s).",
			r, opt_key_slot != CRYPT_ANY_SLOT ?
			"explicit key slot specified" : "no free key slot");
		old_key_slot = r;
		new_key_slot = r;
	} else {
		log_dbg("Allocating new key slot.");
		old_key_slot = r;
		new_key_slot = CRYPT_ANY_SLOT;
	}

	crypt_safe_free(password);
	password = NULL;
	passwordLen = 0;
	r = crypt_get_key(_("Enter new LUKS passphrase: "),
			  &password, &passwordLen,
			  opt_new_keyfile_offset, opt_new_keyfile_size,
			  opt_new_key_file,
			  opt_timeout, _verify_passphrase(0), cd);
	if (r < 0)
		goto out;

	if (new_key_slot == old_key_slot) {
		(void)crypt_keyslot_destroy(cd, old_key_slot);
		r = crypt_keyslot_add_by_volume_key(cd, new_key_slot,
						    vk, vk_size,
						    password, passwordLen);
		if (r >= 0)
			log_verbose(_("Key slot %d changed.\n"), r);
	} else {
		r = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT,
						    vk, vk_size,
						    password, passwordLen);
		if (r >= 0) {
			log_verbose(_("Replaced with key slot %d.\n"), r);
			r = crypt_keyslot_destroy(cd, old_key_slot);
		}
	}
	if (r < 0)
		log_err(_("Failed to swap new key slot.\n"));
out:
	crypt_safe_free(vk);
	crypt_safe_free(password);
	crypt_free(cd);
	return r;
}

static int action_isLuks(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r;

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	crypt_set_log_callback(cd, _quiet_log, NULL);
	r = crypt_load(cd, CRYPT_LUKS1, NULL);
out:
	crypt_free(cd);
	return r;
}

static int action_luksUUID(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	const char *existing_uuid = NULL;
	int r;

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	crypt_set_confirm_callback(cd, _yesDialog, NULL);

	if ((r = crypt_load(cd, CRYPT_LUKS1, NULL)))
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

	crypt_set_confirm_callback(cd, _yesDialog, NULL);
	if (!_yesDialog(
	    _("LUKS header dump with volume key is sensitive information\n"
	      "which allows access to encrypted partition without passphrase.\n"
	      "This dump should be always stored encrypted on safe place."),
	      NULL))
		return -EPERM;

	vk_size = crypt_get_volume_key_size(cd);
	vk = crypt_safe_alloc(vk_size);
	if (!vk)
		return -ENOMEM;

	r = crypt_get_key(_("Enter LUKS passphrase: "), &password, &passwordLen,
			  opt_keyfile_offset, opt_keyfile_size, opt_key_file,
			  opt_timeout, 0, cd);
	if (r < 0)
		goto out;

	r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, vk, &vk_size,
				 password, passwordLen);
	if (r < 0)
		goto out;

	log_std("LUKS header information for %s\n", crypt_get_device_name(cd));
	log_std("Cipher name:   \t%s\n", crypt_get_cipher(cd));
	log_std("Cipher mode:   \t%s\n", crypt_get_cipher_mode(cd));
	log_std("Payload offset:\t%d\n", (int)crypt_get_data_offset(cd));
	log_std("UUID:          \t%s\n", crypt_get_uuid(cd));
	log_std("MK bits:       \t%d\n", (int)vk_size * 8);
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

static int action_luksDump(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r;

	if ((r = crypt_init(&cd, uuid_or_device(action_argv[0]))))
		goto out;

	if ((r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	if (opt_dump_master_key)
		r = luksDump_with_volume_key(cd);
	else
		r = crypt_dump(cd);
out:
	crypt_free(cd);
	return r;
}

static int action_luksSuspend(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_init_by_name_and_header(&cd, action_argv[0], opt_header_device);
	if (!r)
		r = crypt_suspend(cd, action_argv[0]);

	crypt_free(cd);
	return r;
}

static int action_luksResume(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r;

	if ((r = crypt_init_by_name_and_header(&cd, action_argv[0], opt_header_device)))
		goto out;

	crypt_set_timeout(cd, opt_timeout);
	crypt_set_password_retry(cd, opt_tries);
	crypt_set_password_verify(cd, _verify_passphrase(0));

	if (opt_key_file)
		r = crypt_resume_by_keyfile_offset(cd, action_argv[0], CRYPT_ANY_SLOT,
			opt_key_file, opt_keyfile_size, opt_keyfile_offset);
	else
		r = crypt_resume_by_passphrase(cd, action_argv[0], CRYPT_ANY_SLOT,
					       NULL, 0);
out:
	crypt_free(cd);
	return r;
}

static int action_luksBackup(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r;

	if (!opt_header_backup_file) {
		log_err(_("Option --header-backup-file is required.\n"));
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, uuid_or_device(action_argv[0]))))
		goto out;

	crypt_set_confirm_callback(cd, _yesDialog, NULL);

	r = crypt_header_backup(cd, CRYPT_LUKS1, opt_header_backup_file);
out:
	crypt_free(cd);
	return r;
}

static int action_luksRestore(int arg __attribute__((unused)))
{
	struct crypt_device *cd = NULL;
	int r = 0;

	if (!opt_header_backup_file) {
		log_err(_("Option --header-backup-file is required.\n"));
		return -EINVAL;
	}

	if ((r = crypt_init(&cd, action_argv[0])))
		goto out;

	crypt_set_confirm_callback(cd, _yesDialog, NULL);
	r = crypt_header_restore(cd, CRYPT_LUKS1, opt_header_backup_file);
out:
	crypt_free(cd);
	return r;
}

static __attribute__ ((noreturn)) void usage(poptContext popt_context,
					     int exitcode, const char *error,
					     const char *more)
{
	poptPrintUsage(popt_context, stderr, 0);
	if (error)
		log_err("%s: %s\n", more, error);
	poptFreeContext(popt_context);
	exit(exitcode);
}

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	if (key->shortName == '?') {
		struct action_type *action;

		log_std("%s\n",PACKAGE_STRING);

		poptPrintHelp(popt_context, stdout, 0);

		log_std(_("\n"
			 "<action> is one of:\n"));

		for(action = action_types; action->type; action++)
			log_std("\t%s %s - %s\n", action->type, _(action->arg_desc), _(action->desc));

		log_std(_("\n"
			 "<name> is the device to create under %s\n"
			 "<device> is the encrypted device\n"
			 "<key slot> is the LUKS key slot number to modify\n"
			 "<key file> optional key file for the new key for luksAddKey action\n"),
			crypt_get_dir());

		log_std(_("\nDefault compiled-in keyfile parameters:\n"
			 "\tMaximum keyfile size: %dkB, "
			 "Maximum interactive passphrase length %d (characters)\n"),
			 DEFAULT_KEYFILE_SIZE_MAXKB, DEFAULT_PASSPHRASE_SIZE_MAX);

		log_std(_("\nDefault compiled-in device cipher parameters:\n"
			 "\tloop-AES: %s, Key %d bits\n"
			 "\tplain: %s, Key: %d bits, Password hashing: %s\n"
			 "\tLUKS1: %s, Key: %d bits, LUKS header hashing: %s, RNG: %s\n"),
			 DEFAULT_LOOPAES_CIPHER, DEFAULT_LOOPAES_KEYBITS,
			 DEFAULT_CIPHER(PLAIN), DEFAULT_PLAIN_KEYBITS, DEFAULT_PLAIN_HASH,
			 DEFAULT_CIPHER(LUKS1), DEFAULT_LUKS1_KEYBITS, DEFAULT_LUKS1_HASH,
			 DEFAULT_RNG);
		exit(EXIT_SUCCESS);
	} else
		usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

static void _dbg_version_and_cmd(int argc, const char **argv)
{
	int i;

	log_std("# %s %s processing \"", PACKAGE_NAME, PACKAGE_VERSION);
	for (i = 0; i < argc; i++) {
		if (i)
			log_std(" ");
		log_std("%s", argv[i]);
	}
	log_std("\"\n");
}

static int run_action(struct action_type *action)
{
	int r;

	log_dbg("Running command %s.", action->type);

	if (action->required_memlock)
		crypt_memory_lock(NULL, 1);

	r = action->handler(action->arg);

	if (action->required_memlock)
		crypt_memory_lock(NULL, 0);

	/* Some functions returns keyslot # */
	if (r > 0)
		r = 0;

	show_status(r);

	/* Translate exit code to simple codes */
	switch (r) {
	case 0: 	r = EXIT_SUCCESS; break;
	case -EEXIST:
	case -EBUSY:	r = 5; break;
	case -ENOTBLK:
	case -ENODEV:	r = 4; break;
	case -ENOMEM:	r = 3; break;
	case -EPERM:	r = 2; break;
	case -EINVAL:
	case -ENOENT:
	case -ENOSYS:
	default:	r = EXIT_FAILURE;
	}
	return r;
}

int main(int argc, const char **argv)
{
	static char *popt_tmp;
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,                '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ "version",           '\0', POPT_ARG_NONE, &opt_version_mode,          0, N_("Print package version"), NULL },
		{ "verbose",           'v',  POPT_ARG_NONE, &opt_verbose,               0, N_("Shows more detailed error messages"), NULL },
		{ "debug",             '\0', POPT_ARG_NONE, &opt_debug,                 0, N_("Show debug messages"), NULL },
		{ "cipher",            'c',  POPT_ARG_STRING, &opt_cipher,              0, N_("The cipher used to encrypt the disk (see /proc/crypto)"), NULL },
		{ "hash",              'h',  POPT_ARG_STRING, &opt_hash,                0, N_("The hash used to create the encryption key from the passphrase"), NULL },
		{ "verify-passphrase", 'y',  POPT_ARG_NONE, &opt_verify_passphrase,     0, N_("Verifies the passphrase by asking for it twice"), NULL },
		{ "key-file",          'd',  POPT_ARG_STRING, &opt_key_file,            0, N_("Read the key from a file."), NULL },
		{ "master-key-file",  '\0',  POPT_ARG_STRING, &opt_master_key_file,     0, N_("Read the volume (master) key from file."), NULL },
		{ "dump-master-key",  '\0',  POPT_ARG_NONE, &opt_dump_master_key,       0, N_("Dump volume (master) key instead of keyslots info."), NULL },
		{ "key-size",          's',  POPT_ARG_INT, &opt_key_size,               0, N_("The size of the encryption key"), N_("BITS") },
		{ "keyfile-size",      'l',  POPT_ARG_LONG, &opt_keyfile_size,          0, N_("Limits the read from keyfile"), N_("bytes") },
		{ "keyfile-offset",   '\0',  POPT_ARG_LONG, &opt_keyfile_offset,        0, N_("Number of bytes to skip in keyfile"), N_("bytes") },
		{ "new-keyfile-size", '\0',  POPT_ARG_LONG, &opt_new_keyfile_size,      0, N_("Limits the read from newly added keyfile"), N_("bytes") },
		{ "new-keyfile-offset",'\0', POPT_ARG_LONG, &opt_new_keyfile_offset,    0, N_("Number of bytes to skip in newly added keyfile"), N_("bytes") },
		{ "key-slot",          'S',  POPT_ARG_INT, &opt_key_slot,               0, N_("Slot number for new key (default is first free)"), NULL },
		{ "size",              'b',  POPT_ARG_STRING, &popt_tmp,                1, N_("The size of the device"), N_("SECTORS") },
		{ "offset",            'o',  POPT_ARG_STRING, &popt_tmp,                2, N_("The start offset in the backend device"), N_("SECTORS") },
		{ "skip",              'p',  POPT_ARG_STRING, &popt_tmp,                3, N_("How many sectors of the encrypted data to skip at the beginning"), N_("SECTORS") },
		{ "readonly",          'r',  POPT_ARG_NONE, &opt_readonly,              0, N_("Create a readonly mapping"), NULL },
		{ "iter-time",         'i',  POPT_ARG_INT, &opt_iteration_time,         0, N_("PBKDF2 iteration time for LUKS (in ms)"), N_("msecs") },
		{ "batch-mode",        'q',  POPT_ARG_NONE, &opt_batch_mode,            0, N_("Do not ask for confirmation"), NULL },
		{ "timeout",           't',  POPT_ARG_INT, &opt_timeout,                0, N_("Timeout for interactive passphrase prompt (in seconds)"), N_("secs") },
		{ "tries",             'T',  POPT_ARG_INT, &opt_tries,                  0, N_("How often the input of the passphrase can be retried"), NULL },
		{ "align-payload",     '\0', POPT_ARG_INT, &opt_align_payload,          0, N_("Align payload at <n> sector boundaries - for luksFormat"), N_("SECTORS") },
		{ "header-backup-file",'\0', POPT_ARG_STRING, &opt_header_backup_file,  0, N_("File with LUKS header and keyslots backup."), NULL },
		{ "use-random",        '\0', POPT_ARG_NONE, &opt_random,                0, N_("Use /dev/random for generating volume key."), NULL },
		{ "use-urandom",       '\0', POPT_ARG_NONE, &opt_urandom,               0, N_("Use /dev/urandom for generating volume key."), NULL },
		{ "shared",            '\0', POPT_ARG_NONE, &opt_shared,                0, N_("Share device with another non-overlapping crypt segment."), NULL },
		{ "uuid",              '\0', POPT_ARG_STRING, &opt_uuid,                0, N_("UUID for device to use."), NULL },
		{ "allow-discards",    '\0', POPT_ARG_NONE, &opt_allow_discards,        0, N_("Allow discards (aka TRIM) requests for device."), NULL },
		{ "header",            '\0', POPT_ARG_STRING, &opt_header_device,       0, N_("Device or file with separated LUKS header."), NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;
	struct action_type *action;
	const char *aname;
	int r;
	const char *null_action_argv[] = {NULL};

	crypt_set_log_callback(NULL, _log, NULL);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	crypt_fips_self_check(NULL);

	popt_context = poptGetContext(PACKAGE, argc, argv, popt_options, 0);
	poptSetOtherOptionHelp(popt_context,
	                       N_("[OPTION...] <action> <action-specific>]"));

	while((r = poptGetNextOpt(popt_context)) > 0) {
		unsigned long long ull_value;
		char *endp;

		errno = 0;
		ull_value = strtoull(popt_tmp, &endp, 0);
		if (*endp || !*popt_tmp ||
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
		}

		if (r < 0)
			break;
	}

	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));
	if (opt_version_mode) {
		log_std("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	}

	if (!(aname = poptGetArg(popt_context)))
		usage(popt_context, EXIT_FAILURE, _("Argument <action> missing."),
		      poptGetInvocationName(popt_context));
	for(action = action_types; action->type; action++)
		if (strcmp(action->type, aname) == 0)
			break;
	if (!action->type)
		usage(popt_context, EXIT_FAILURE, _("Unknown action."),
		      poptGetInvocationName(popt_context));

	action_argc = 0;
	action_argv = poptGetArgs(popt_context);
	/* Make return values of poptGetArgs more consistent in case of remaining argc = 0 */
	if(!action_argv)
		action_argv = null_action_argv;

	/* Count args, somewhat unnice, change? */
	while(action_argv[action_argc] != NULL)
		action_argc++;

	if(action_argc < action->required_action_argc) {
		char buf[128];
		snprintf(buf, 128,_("%s: requires %s as arguments"), action->type, action->arg_desc);
		usage(popt_context, EXIT_FAILURE, buf,
		      poptGetInvocationName(popt_context));
	}

	/* FIXME: rewrite this from scratch */

	if (opt_shared && strcmp(aname, "create")) {
		usage(popt_context, EXIT_FAILURE,
		      _("Option --shared is allowed only for create operation.\n"),
		      poptGetInvocationName(popt_context));
	}

	if (opt_allow_discards &&
	    strcmp(aname, "luksOpen") &&
	    strcmp(aname, "create") &&
	    strcmp(aname, "loopaesOpen")) {
		usage(popt_context, EXIT_FAILURE,
		      _("Option --allow-discards is allowed only for luksOpen, loopaesOpen and create operation.\n"),
		      poptGetInvocationName(popt_context));
	}

	if (opt_key_size &&
	   strcmp(aname, "luksFormat") &&
	   strcmp(aname, "create") &&
	   strcmp(aname, "loopaesOpen")) {
		usage(popt_context, EXIT_FAILURE,
		      _("Option --key-size is allowed only for luksFormat, create and loopaesOpen.\n"
		        "To limit read from keyfile use --keyfile-size=(bytes)."),
		      poptGetInvocationName(popt_context));
	}

	if (opt_key_size % 8)
		usage(popt_context, EXIT_FAILURE,
		      _("Key size must be a multiple of 8 bits"),
		      poptGetInvocationName(popt_context));

	if (!strcmp(aname, "luksKillSlot") && action_argc > 1)
		opt_key_slot = atoi(action_argv[1]);
	if (opt_key_slot != CRYPT_ANY_SLOT &&
	    (opt_key_slot < 0 || opt_key_slot >= crypt_keyslot_max(CRYPT_LUKS1)))
		usage(popt_context, EXIT_FAILURE, _("Key slot is invalid."),
		      poptGetInvocationName(popt_context));

	if ((!strcmp(aname, "luksRemoveKey") ||
	     !strcmp(aname, "luksFormat")) &&
	     action_argc > 1) {
		if (opt_key_file)
			log_err(_("Option --key-file takes precedence over specified key file argument.\n"));
		else
			opt_key_file = action_argv[1];
	}

	if (opt_keyfile_size < 0 || opt_new_keyfile_size < 0 || opt_key_size < 0 ||
	    opt_keyfile_offset < 0 || opt_new_keyfile_offset < 0) {
		usage(popt_context, EXIT_FAILURE,
		      _("Negative number for option not permitted."),
		      poptGetInvocationName(popt_context));
	}

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

	if (opt_skip && strcmp(aname, "create") && strcmp(aname, "loopaesOpen"))
		usage(popt_context, EXIT_FAILURE,
		_("Option --skip is supported only for create and loopaesOpen commands.\n"),
		poptGetInvocationName(popt_context));

	if (opt_offset && strcmp(aname, "create") && strcmp(aname, "loopaesOpen"))
		usage(popt_context, EXIT_FAILURE,
		_("Option --offset is supported only for create and loopaesOpen commands.\n"),
		poptGetInvocationName(popt_context));

	if (opt_debug) {
		opt_verbose = 1;
		crypt_set_debug_level(-1);
		_dbg_version_and_cmd(argc, argv);
	}

	r = run_action(action);
	poptFreeContext(popt_context);
	return r;
}
