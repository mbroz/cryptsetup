/*
 * libcryptsetup - cryptsetup library
 *
 * Copyright (C) 2004, Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2014, Milan Broz
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>

#include "libcryptsetup.h"
#include "luks.h"
#include "loopaes.h"
#include "verity.h"
#include "tcrypt.h"
#include "internal.h"

struct crypt_device {
	char *type;

	struct device *device;
	struct device *metadata_device;

	struct volume_key *volume_key;
	uint64_t timeout;
	uint64_t iteration_time;
	int tries;
	int password_verify;
	int rng_type;

	// FIXME: private binary headers and access it properly
	// through sub-library (LUKS1, TCRYPT)

	union {
	struct { /* used in CRYPT_LUKS1 */
		struct luks_phdr hdr;
		uint64_t PBKDF2_per_sec;
	} luks1;
	struct { /* used in CRYPT_PLAIN */
		struct crypt_params_plain hdr;
		char *cipher;
		char *cipher_mode;
		unsigned int key_size;
	} plain;
	struct { /* used in CRYPT_LOOPAES */
		struct crypt_params_loopaes hdr;
		char *cipher;
		char *cipher_mode;
		unsigned int key_size;
	} loopaes;
	struct { /* used in CRYPT_VERITY */
		struct crypt_params_verity hdr;
		char *root_hash;
		unsigned int root_hash_size;
		char *uuid;
	} verity;
	struct { /* used in CRYPT_TCRYPT */
		struct crypt_params_tcrypt params;
		struct tcrypt_phdr hdr;
	} tcrypt;
	struct { /* used if initialized without header by name */
		char *active_name;
		/* buffers, must refresh from kernel on every query */
		char cipher[MAX_CIPHER_LEN];
		char cipher_mode[MAX_CIPHER_LEN];
		unsigned int key_size;
	} none;
	} u;

	/* callbacks definitions */
	void (*log)(int level, const char *msg, void *usrptr);
	void *log_usrptr;
	int (*confirm)(const char *msg, void *usrptr);
	void *confirm_usrptr;
	int (*password)(const char *msg, char *buf, size_t length, void *usrptr);
	void *password_usrptr;

	/* last error message */
	char error[MAX_ERROR_LENGTH];
};

/* Just to suppress redundant messages about crypto backend */
static int _crypto_logged = 0;

/* Global error */
/* FIXME: not thread safe, remove this later */
static char global_error[MAX_ERROR_LENGTH] = {0};

/* Log helper */
static void (*_default_log)(int level, const char *msg, void *usrptr) = NULL;
static int _debug_level = 0;

void crypt_set_debug_level(int level)
{
	_debug_level = level;
}

int crypt_get_debug_level(void)
{
	return _debug_level;
}

static void crypt_set_error(struct crypt_device *cd, const char *error)
{
	size_t size = strlen(error);

	/* Set global error, ugly hack... */
	strncpy(global_error, error, MAX_ERROR_LENGTH - 2);
	if (size < MAX_ERROR_LENGTH && global_error[size - 1] == '\n')
		global_error[size - 1] = '\0';

	/* Set error string per context */
	if (cd) {
		strncpy(cd->error, error, MAX_ERROR_LENGTH - 2);
		if (size < MAX_ERROR_LENGTH && cd->error[size - 1] == '\n')
			cd->error[size - 1] = '\0';
	}
}

void crypt_log(struct crypt_device *cd, int level, const char *msg)
{
	if (cd && cd->log)
		cd->log(level, msg, cd->log_usrptr);
	else if (_default_log)
		_default_log(level, msg, NULL);

	if (level == CRYPT_LOG_ERROR)
		crypt_set_error(cd, msg);
}

__attribute__((format(printf, 5, 6)))
void logger(struct crypt_device *cd, int level, const char *file,
	    int line, const char *format, ...)
{
	va_list argp;
	char *target = NULL;

	va_start(argp, format);

	if (vasprintf(&target, format, argp) > 0 ) {
		if (level >= 0) {
			crypt_log(cd, level, target);
#ifdef CRYPT_DEBUG
		} else if (_debug_level)
			printf("# %s:%d %s\n", file ?: "?", line, target);
#else
		} else if (_debug_level)
			printf("# %s\n", target);
#endif
	}

	va_end(argp);
	free(target);
}

static const char *mdata_device_path(struct crypt_device *cd)
{
	return device_path(cd->metadata_device ?: cd->device);
}

/* internal only */
struct device *crypt_metadata_device(struct crypt_device *cd)
{
	return cd->metadata_device ?: cd->device;
}

struct device *crypt_data_device(struct crypt_device *cd)
{
	return cd->device;
}

int init_crypto(struct crypt_device *ctx)
{
	struct utsname uts;
	int r;

	r = crypt_random_init(ctx);
	if (r < 0) {
		log_err(ctx, _("Cannot initialize crypto RNG backend.\n"));
		return r;
	}

	r = crypt_backend_init(ctx);
	if (r < 0)
		log_err(ctx, _("Cannot initialize crypto backend.\n"));

	if (!r && !_crypto_logged) {
		log_dbg("Crypto backend (%s) initialized.", crypt_backend_version());
		if (!uname(&uts))
			log_dbg("Detected kernel %s %s %s.",
				uts.sysname, uts.release, uts.machine);
		_crypto_logged = 1;
	}

	return r;
}

static int process_key(struct crypt_device *cd, const char *hash_name,
		       size_t key_size, const char *pass, size_t passLen,
		       struct volume_key **vk)
{
	int r;

	if (!key_size)
		return -EINVAL;

	*vk = crypt_alloc_volume_key(key_size, NULL);
	if (!*vk)
		return -ENOMEM;

	if (hash_name) {
		r = crypt_plain_hash(cd, hash_name, (*vk)->key, key_size, pass, passLen);
		if (r < 0) {
			if (r == -ENOENT)
				log_err(cd, _("Hash algorithm %s not supported.\n"),
					hash_name);
			else
				log_err(cd, _("Key processing error (using hash %s).\n"),
					hash_name);
			crypt_free_volume_key(*vk);
			*vk = NULL;
			return -EINVAL;
		}
	} else if (passLen > key_size) {
		memcpy((*vk)->key, pass, key_size);
	} else {
		memcpy((*vk)->key, pass, passLen);
	}

	return 0;
}

static int isPLAIN(const char *type)
{
	return (type && !strcmp(CRYPT_PLAIN, type));
}

static int isLUKS(const char *type)
{
	return (type && !strcmp(CRYPT_LUKS1, type));
}

static int isLOOPAES(const char *type)
{
	return (type && !strcmp(CRYPT_LOOPAES, type));
}

static int isVERITY(const char *type)
{
	return (type && !strcmp(CRYPT_VERITY, type));
}

static int isTCRYPT(const char *type)
{
	return (type && !strcmp(CRYPT_TCRYPT, type));
}

static int onlyLUKS(struct crypt_device *cd)
{
	int r = 0;

	if (cd && !cd->type) {
		log_err(cd, _("Cannot determine device type. Incompatible activation of device?\n"));
		r = -EINVAL;
	}
	if (!cd || !isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		r = -EINVAL;
	}

	return r;
}

static void crypt_set_null_type(struct crypt_device *cd)
{
	if (!cd->type)
		return;

	free(cd->type);
	cd->type = NULL;
	cd->u.none.active_name = NULL;
}

static void crypt_reset_null_type(struct crypt_device *cd)
{
	if (cd->type)
		return;

	free(cd->u.none.active_name);
	cd->u.none.active_name = NULL;
}

/* keyslot helpers */
static int keyslot_verify_or_find_empty(struct crypt_device *cd, int *keyslot)
{
	if (*keyslot == CRYPT_ANY_SLOT) {
		*keyslot = LUKS_keyslot_find_empty(&cd->u.luks1.hdr);
		if (*keyslot < 0) {
			log_err(cd, _("All key slots full.\n"));
			return -EINVAL;
		}
	}

	switch (LUKS_keyslot_info(&cd->u.luks1.hdr, *keyslot)) {
		case CRYPT_SLOT_INVALID:
			log_err(cd, _("Key slot %d is invalid, please select between 0 and %d.\n"),
				*keyslot, LUKS_NUMKEYS - 1);
			return -EINVAL;
		case CRYPT_SLOT_INACTIVE:
			break;
		default:
			log_err(cd, _("Key slot %d is full, please select another one.\n"),
				*keyslot);
			return -EINVAL;
	}

	return 0;
}

/*
 * compares UUIDs returned by device-mapper (striped by cryptsetup) and uuid in header
 */
static int crypt_uuid_cmp(const char *dm_uuid, const char *hdr_uuid)
{
	int i, j;
	char *str;

	if (!dm_uuid || !hdr_uuid)
		return -EINVAL;

	str = strchr(dm_uuid, '-');
	if (!str)
		return -EINVAL;

	for (i = 0, j = 1; hdr_uuid[i]; i++) {
		if (hdr_uuid[i] == '-')
			continue;

		if (!str[j] || str[j] == '-')
			return -EINVAL;

		if (str[j] != hdr_uuid[i])
			return -EINVAL;
		j++;
	}

	return 0;
}

int PLAIN_activate(struct crypt_device *cd,
		     const char *name,
		     struct volume_key *vk,
		     uint64_t size,
		     uint32_t flags)
{
	int r;
	char *dm_cipher = NULL;
	enum devcheck device_check;
	struct crypt_dm_active_device dmd = {
		.target = DM_CRYPT,
		.size   = size,
		.flags  = flags,
		.data_device = crypt_data_device(cd),
		.u.crypt  = {
			.cipher = NULL,
			.vk     = vk,
			.offset = crypt_get_data_offset(cd),
			.iv_offset = crypt_get_iv_offset(cd),
		}
	};

	if (dmd.flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_SHARED;
	else
		device_check = DEV_EXCL;

	r = device_block_adjust(cd, dmd.data_device, device_check,
				dmd.u.crypt.offset, &dmd.size, &dmd.flags);
	if (r)
		return r;

	if (crypt_get_cipher_mode(cd))
		r = asprintf(&dm_cipher, "%s-%s", crypt_get_cipher(cd), crypt_get_cipher_mode(cd));
	else
		r = asprintf(&dm_cipher, "%s", crypt_get_cipher(cd));
	if (r < 0)
		return -ENOMEM;

	dmd.u.crypt.cipher = dm_cipher;
	log_dbg("Trying to activate PLAIN device %s using cipher %s.",
		name, dmd.u.crypt.cipher);

	r = dm_create_device(cd, name, CRYPT_PLAIN, &dmd, 0);

	free(dm_cipher);
	return r;
}

int crypt_confirm(struct crypt_device *cd, const char *msg)
{
	if (!cd || !cd->confirm)
		return 1;
	else
		return cd->confirm(msg, cd->confirm_usrptr);
}

static int key_from_terminal(struct crypt_device *cd, char *msg, char **key,
			      size_t *key_len, int force_verify)
{
	char *prompt = NULL, *device_name;
	int r;

	*key = NULL;
	if(!msg) {
		if (crypt_loop_device(crypt_get_device_name(cd)))
			device_name = crypt_loop_backing_file(crypt_get_device_name(cd));
		else
			device_name = strdup(crypt_get_device_name(cd));
		if (!device_name)
			return -ENOMEM;
		r = asprintf(&prompt, _("Enter passphrase for %s: "), device_name);
		free(device_name);
		if (r < 0)
			return -ENOMEM;
		msg = prompt;
	}

	if (cd->password) {
		*key = crypt_safe_alloc(DEFAULT_PASSPHRASE_SIZE_MAX);
		if (!*key) {
			r = -ENOMEM;
			goto out;
		}
		r = cd->password(msg, *key, DEFAULT_PASSPHRASE_SIZE_MAX,
				 cd->password_usrptr);
		if (r < 0) {
			crypt_safe_free(*key);
			*key = NULL;
		} else
			*key_len = r;
	} else
		r = crypt_get_key(msg, key, key_len, 0, 0, NULL, cd->timeout,
				  (force_verify || cd->password_verify), cd);
out:
	free(prompt);
	return (r < 0) ? r: 0;
}

static int volume_key_by_terminal_passphrase(struct crypt_device *cd, int keyslot,
					     struct volume_key **vk)
{
	char *passphrase_read = NULL;
	size_t passphrase_size_read;
	int r = -EINVAL, eperm = 0, tries = cd->tries;

	*vk = NULL;
	do {
		crypt_free_volume_key(*vk);
		*vk = NULL;

		r = key_from_terminal(cd, NULL, &passphrase_read,
				      &passphrase_size_read, 0);
		/* Continue if it is just passphrase verify mismatch */
		if (r == -EPERM)
			continue;
		if(r < 0)
			goto out;

		r = LUKS_open_key_with_hdr(keyslot, passphrase_read,
					   passphrase_size_read, &cd->u.luks1.hdr, vk, cd);
		if (r == -EPERM)
			eperm = 1;
		crypt_safe_free(passphrase_read);
		passphrase_read = NULL;
	} while (r == -EPERM && (--tries > 0));
out:
	if (r < 0) {
		crypt_free_volume_key(*vk);
		*vk = NULL;

		/* Report wrong passphrase if at least one try failed */
		if (eperm && r == -EPIPE)
			r = -EPERM;
	}

	crypt_safe_free(passphrase_read);
	return r;
}

static int key_from_file(struct crypt_device *cd, char *msg,
			  char **key, size_t *key_len,
			  const char *key_file, size_t key_offset,
			  size_t key_size)
{
	return crypt_get_key(msg, key, key_len, key_offset, key_size, key_file,
			     cd->timeout, 0, cd);
}

void crypt_set_log_callback(struct crypt_device *cd,
	void (*log)(int level, const char *msg, void *usrptr),
	void *usrptr)
{
	if (!cd)
		_default_log = log;
	else {
		cd->log = log;
		cd->log_usrptr = usrptr;
	}
}

void crypt_set_confirm_callback(struct crypt_device *cd,
	int (*confirm)(const char *msg, void *usrptr),
	void *usrptr)
{
	cd->confirm = confirm;
	cd->confirm_usrptr = usrptr;
}

void crypt_set_password_callback(struct crypt_device *cd,
	int (*password)(const char *msg, char *buf, size_t length, void *usrptr),
	void *usrptr)
{
	cd->password = password;
	cd->password_usrptr = usrptr;
}

static void _get_error(char *error, char *buf, size_t size)
{
	if (!buf || size < 1)
		error[0] = '\0';
	else if (*error) {
		strncpy(buf, error, size - 1);
		buf[size - 1] = '\0';
		error[0] = '\0';
	} else
		buf[0] = '\0';
}

void crypt_last_error(struct crypt_device *cd, char *buf, size_t size)
{
	if (cd)
		return _get_error(cd->error, buf, size);
}

/* Deprecated global error interface */
void crypt_get_error(char *buf, size_t size)
{
	return _get_error(global_error, buf, size);
}

const char *crypt_get_dir(void)
{
	return dm_get_dir();
}

int crypt_init(struct crypt_device **cd, const char *device)
{
	struct crypt_device *h = NULL;
	int r;

	if (!cd)
		return -EINVAL;

	log_dbg("Allocating crypt device %s context.", device);

	if (!(h = malloc(sizeof(struct crypt_device))))
		return -ENOMEM;

	memset(h, 0, sizeof(*h));

	r = device_alloc(&h->device, device);
	if (r < 0)
		goto bad;

	dm_backend_init();

	h->iteration_time = 1000;
	h->password_verify = 0;
	h->tries = 3;
	h->rng_type = crypt_random_default_key_rng();
	*cd = h;
	return 0;
bad:
	device_free(h->device);
	free(h);
	return r;
}

static int crypt_check_data_device_size(struct crypt_device *cd)
{
	int r;
	uint64_t size, size_min;

	/* Check data device size, require at least one sector */
	size_min = crypt_get_data_offset(cd) << SECTOR_SHIFT ?: SECTOR_SIZE;

	r = device_size(cd->device, &size);
	if (r < 0)
		return r;

	if (size < size_min) {
		log_err(cd, _("Header detected but device %s is too small.\n"),
			device_path(cd->device));
		return -EINVAL;
	}

	return r;
}

int crypt_set_data_device(struct crypt_device *cd, const char *device)
{
	struct device *dev = NULL;
	int r;

	log_dbg("Setting ciphertext data device to %s.", device ?: "(none)");

	if (!isLUKS(cd->type) && !isVERITY(cd->type)) {
		log_err(cd, _("This operation is not supported for this device type.\n"));
		return  -EINVAL;
	}

	/* metadata device must be set */
	if (!cd->device || !device)
		return -EINVAL;

	r = device_alloc(&dev, device);
	if (r < 0)
		return r;

	if (!cd->metadata_device) {
		cd->metadata_device = cd->device;
	} else
		device_free(cd->device);

	cd->device = dev;

	return crypt_check_data_device_size(cd);
}

static int _crypt_load_luks1(struct crypt_device *cd, int require_header, int repair)
{
	struct luks_phdr hdr;
	int r;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = LUKS_read_phdr(&hdr, require_header, repair, cd);
	if (r < 0)
		return r;

	if (!cd->type && !(cd->type = strdup(CRYPT_LUKS1)))
		return -ENOMEM;

	memcpy(&cd->u.luks1.hdr, &hdr, sizeof(hdr));

	return r;
}

static int _crypt_load_tcrypt(struct crypt_device *cd, struct crypt_params_tcrypt *params)
{
	int r;

	if (!params)
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	memcpy(&cd->u.tcrypt.params, params, sizeof(*params));

	r = TCRYPT_read_phdr(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);

	cd->u.tcrypt.params.passphrase = NULL;
	cd->u.tcrypt.params.passphrase_size = 0;
	cd->u.tcrypt.params.keyfiles = NULL;
	cd->u.tcrypt.params.keyfiles_count = 0;

	if (r < 0)
		return r;

	if (!cd->type && !(cd->type = strdup(CRYPT_TCRYPT)))
		return -ENOMEM;

	return r;
}

static int _crypt_load_verity(struct crypt_device *cd, struct crypt_params_verity *params)
{
	int r;
	size_t sb_offset = 0;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	if (params && params->flags & CRYPT_VERITY_NO_HEADER)
		return -EINVAL;

	if (params)
		sb_offset = params->hash_area_offset;

	r = VERITY_read_sb(cd, sb_offset, &cd->u.verity.uuid, &cd->u.verity.hdr);
	if (r < 0)
		return r;

	if (params)
		cd->u.verity.hdr.flags = params->flags;

	/* Hash availability checked in sb load */
	cd->u.verity.root_hash_size = crypt_hash_size(cd->u.verity.hdr.hash_name);
	if (cd->u.verity.root_hash_size > 4096)
		return -EINVAL;

	if (!cd->type && !(cd->type = strdup(CRYPT_VERITY)))
		return -ENOMEM;

	if (params && params->data_device &&
	    (r = crypt_set_data_device(cd, params->data_device)) < 0)
		return r;

	return r;
}

static int _init_by_name_crypt(struct crypt_device *cd, const char *name)
{
	struct crypt_dm_active_device dmd = {};
	char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	int key_nums, r;

	r = dm_query_device(cd, name,
			DM_ACTIVE_DEVICE |
			DM_ACTIVE_UUID |
			DM_ACTIVE_CRYPT_CIPHER |
			DM_ACTIVE_CRYPT_KEYSIZE, &dmd);
	if (r < 0)
		goto out;
	if (r > 0)
		r = 0;

	if (isPLAIN(cd->type)) {
		cd->u.plain.hdr.hash = NULL; /* no way to get this */
		cd->u.plain.hdr.offset = dmd.u.crypt.offset;
		cd->u.plain.hdr.skip = dmd.u.crypt.iv_offset;
		cd->u.plain.key_size = dmd.u.crypt.vk->keylength;

		r = crypt_parse_name_and_mode(dmd.u.crypt.cipher, cipher, NULL, cipher_mode);
		if (!r) {
			cd->u.plain.cipher = strdup(cipher);
			cd->u.plain.cipher_mode = strdup(cipher_mode);
		}
	} else if (isLOOPAES(cd->type)) {
		cd->u.loopaes.hdr.offset = dmd.u.crypt.offset;

		r = crypt_parse_name_and_mode(dmd.u.crypt.cipher, cipher,
					      &key_nums, cipher_mode);
		if (!r) {
			cd->u.loopaes.cipher = strdup(cipher);
			cd->u.loopaes.cipher_mode = strdup(cipher_mode);
			/* version 3 uses last key for IV */
			if (dmd.u.crypt.vk->keylength % key_nums)
				key_nums++;
			cd->u.loopaes.key_size = dmd.u.crypt.vk->keylength / key_nums;
		}
	} else if (isLUKS(cd->type)) {
		if (crypt_metadata_device(cd)) {
			r = _crypt_load_luks1(cd, 0, 0);
			if (r < 0) {
				log_dbg("LUKS device header does not match active device.");
				crypt_set_null_type(cd);
				r = 0;
				goto out;
			}
			/* check whether UUIDs match each other */
			r = crypt_uuid_cmp(dmd.uuid, cd->u.luks1.hdr.uuid);
			if (r < 0) {
				log_dbg("LUKS device header uuid: %s mismatches DM returned uuid %s",
					cd->u.luks1.hdr.uuid, dmd.uuid);
				crypt_set_null_type(cd);
				r = 0;
			}
		} else {
			log_dbg("LUKS device header not available.");
			crypt_set_null_type(cd);
			r = 0;
		}
	} else if (isTCRYPT(cd->type)) {
		r = TCRYPT_init_by_name(cd, name, &dmd, &cd->device,
					&cd->u.tcrypt.params, &cd->u.tcrypt.hdr);
	}
out:
	crypt_free_volume_key(dmd.u.crypt.vk);
	device_free(dmd.data_device);
	free(CONST_CAST(void*)dmd.u.crypt.cipher);
	free(CONST_CAST(void*)dmd.uuid);
	return r;
}

static int _init_by_name_verity(struct crypt_device *cd, const char *name)
{
	struct crypt_params_verity params = {};
	struct crypt_dm_active_device dmd = {
		.target = DM_VERITY,
		.u.verity.vp = &params,
	};
	int r;

	r = dm_query_device(cd, name,
				DM_ACTIVE_DEVICE |
				DM_ACTIVE_VERITY_HASH_DEVICE |
				DM_ACTIVE_VERITY_PARAMS, &dmd);
	if (r < 0)
		goto out;
	if (r > 0)
		r = 0;

	if (isVERITY(cd->type)) {
		cd->u.verity.uuid = NULL; // FIXME
		cd->u.verity.hdr.flags = CRYPT_VERITY_NO_HEADER; //FIXME
		cd->u.verity.hdr.data_size = params.data_size;
		cd->u.verity.root_hash_size = dmd.u.verity.root_hash_size;
		cd->u.verity.root_hash = NULL;
		cd->u.verity.hdr.hash_name = params.hash_name;
		cd->u.verity.hdr.data_device = NULL;
		cd->u.verity.hdr.hash_device = NULL;
		cd->u.verity.hdr.data_block_size = params.data_block_size;
		cd->u.verity.hdr.hash_block_size = params.hash_block_size;
		cd->u.verity.hdr.hash_area_offset = dmd.u.verity.hash_offset;
		cd->u.verity.hdr.hash_type = params.hash_type;
		cd->u.verity.hdr.flags = params.flags;
		cd->u.verity.hdr.salt_size = params.salt_size;
		cd->u.verity.hdr.salt = params.salt;
		cd->metadata_device = dmd.u.verity.hash_device;
	}
out:
	device_free(dmd.data_device);
	return r;
}

int crypt_init_by_name_and_header(struct crypt_device **cd,
				  const char *name,
				  const char *header_device)
{
	crypt_status_info ci;
	struct crypt_dm_active_device dmd;
	int r;

	log_dbg("Allocating crypt device context by device %s.", name);

	ci = crypt_status(NULL, name);
	if (ci == CRYPT_INVALID)
		return -ENODEV;

	if (ci < CRYPT_ACTIVE) {
		log_err(NULL, _("Device %s is not active.\n"), name);
		return -ENODEV;
	}

	r = dm_query_device(NULL, name, DM_ACTIVE_DEVICE | DM_ACTIVE_UUID, &dmd);
	if (r < 0)
		goto out;

	*cd = NULL;

	if (header_device) {
		r = crypt_init(cd, header_device);
	} else {
		r = crypt_init(cd, device_path(dmd.data_device));

		/* Underlying device disappeared but mapping still active */
		if (!dmd.data_device || r == -ENOTBLK)
			log_verbose(NULL, _("Underlying device for crypt device %s disappeared.\n"),
				    name);

		/* Underlying device is not readable but crypt mapping exists */
		if (r == -ENOTBLK) {
			device_free(dmd.data_device);
			dmd.data_device = NULL;
			r = crypt_init(cd, NULL);
		}
	}

	if (r < 0)
		goto out;

	if (dmd.uuid) {
		if (!strncmp(CRYPT_PLAIN, dmd.uuid, sizeof(CRYPT_PLAIN)-1))
			(*cd)->type = strdup(CRYPT_PLAIN);
		else if (!strncmp(CRYPT_LOOPAES, dmd.uuid, sizeof(CRYPT_LOOPAES)-1))
			(*cd)->type = strdup(CRYPT_LOOPAES);
		else if (!strncmp(CRYPT_LUKS1, dmd.uuid, sizeof(CRYPT_LUKS1)-1))
			(*cd)->type = strdup(CRYPT_LUKS1);
		else if (!strncmp(CRYPT_VERITY, dmd.uuid, sizeof(CRYPT_VERITY)-1))
			(*cd)->type = strdup(CRYPT_VERITY);
		else if (!strncmp(CRYPT_TCRYPT, dmd.uuid, sizeof(CRYPT_TCRYPT)-1))
			(*cd)->type = strdup(CRYPT_TCRYPT);
		else
			log_dbg("Unknown UUID set, some parameters are not set.");
	} else
		log_dbg("Active device has no UUID set, some parameters are not set.");

	if (header_device) {
		r = crypt_set_data_device(*cd, device_path(dmd.data_device));
		if (r < 0)
			goto out;
	}

	/* Try to initialise basic parameters from active device */

	if (dmd.target == DM_CRYPT)
		r = _init_by_name_crypt(*cd, name);
	else if (dmd.target == DM_VERITY)
		r = _init_by_name_verity(*cd, name);
out:
	if (r < 0) {
		crypt_free(*cd);
		*cd = NULL;
	} else if (!(*cd)->type && name) {
		/* For anonymous device (no header found) remember initialized name */
		(*cd)->u.none.active_name = strdup(name);
	}

	device_free(dmd.data_device);
	free(CONST_CAST(void*)dmd.uuid);
	return r;
}

int crypt_init_by_name(struct crypt_device **cd, const char *name)
{
	return crypt_init_by_name_and_header(cd, name, NULL);
}

static int _crypt_format_plain(struct crypt_device *cd,
			       const char *cipher,
			       const char *cipher_mode,
			       const char *uuid,
			       size_t volume_key_size,
			       struct crypt_params_plain *params)
{
	if (!cipher || !cipher_mode) {
		log_err(cd, _("Invalid plain crypt parameters.\n"));
		return -EINVAL;
	}

	if (volume_key_size > 1024) {
		log_err(cd, _("Invalid key size.\n"));
		return -EINVAL;
	}

	if (uuid) {
		log_err(cd, _("UUID is not supported for this crypt type.\n"));
		return -EINVAL;
	}

	if (!(cd->type = strdup(CRYPT_PLAIN)))
		return -ENOMEM;

	cd->u.plain.key_size = volume_key_size;
	cd->volume_key = crypt_alloc_volume_key(volume_key_size, NULL);
	if (!cd->volume_key)
		return -ENOMEM;

	cd->u.plain.cipher = strdup(cipher);
	cd->u.plain.cipher_mode = strdup(cipher_mode);


	if (params && params->hash)
		cd->u.plain.hdr.hash = strdup(params->hash);

	cd->u.plain.hdr.offset = params ? params->offset : 0;
	cd->u.plain.hdr.skip = params ? params->skip : 0;
	cd->u.plain.hdr.size = params ? params->size : 0;

	if (!cd->u.plain.cipher || !cd->u.plain.cipher_mode)
		return -ENOMEM;

	return 0;
}

static int _crypt_format_luks1(struct crypt_device *cd,
			       const char *cipher,
			       const char *cipher_mode,
			       const char *uuid,
			       const char *volume_key,
			       size_t volume_key_size,
			       struct crypt_params_luks1 *params)
{
	int r;
	unsigned long required_alignment = DEFAULT_DISK_ALIGNMENT;
	unsigned long alignment_offset = 0;

	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format LUKS without device.\n"));
		return -EINVAL;
	}

	if (!(cd->type = strdup(CRYPT_LUKS1)))
		return -ENOMEM;

	if (volume_key)
		cd->volume_key = crypt_alloc_volume_key(volume_key_size,
						      volume_key);
	else
		cd->volume_key = crypt_generate_volume_key(cd, volume_key_size);

	if(!cd->volume_key)
		return -ENOMEM;

	if (params && params->data_device) {
		cd->metadata_device = cd->device;
		cd->device = NULL;
		if (device_alloc(&cd->device, params->data_device) < 0)
			return -ENOMEM;
		required_alignment = params->data_alignment * SECTOR_SIZE;
	} else if (params && params->data_alignment) {
		required_alignment = params->data_alignment * SECTOR_SIZE;
	} else
		device_topology_alignment(cd->device,
				       &required_alignment,
				       &alignment_offset, DEFAULT_DISK_ALIGNMENT);

	r = LUKS_generate_phdr(&cd->u.luks1.hdr, cd->volume_key, cipher, cipher_mode,
			       (params && params->hash) ? params->hash : "sha1",
			       uuid, LUKS_STRIPES,
			       required_alignment / SECTOR_SIZE,
			       alignment_offset / SECTOR_SIZE,
			       cd->iteration_time, &cd->u.luks1.PBKDF2_per_sec,
			       cd->metadata_device ? 1 : 0, cd);
	if(r < 0)
		return r;

	/* Wipe first 8 sectors - fs magic numbers etc. */
	r = crypt_wipe(crypt_metadata_device(cd), 0, 8 * SECTOR_SIZE, CRYPT_WIPE_ZERO, 1);
	if(r < 0) {
		if (r == -EBUSY)
			log_err(cd, _("Cannot format device %s which is still in use.\n"),
				mdata_device_path(cd));
		else if (r == -EACCES) {
			log_err(cd, _("Cannot format device %s, permission denied.\n"),
				mdata_device_path(cd));
			r = -EINVAL;
		} else
			log_err(cd, _("Cannot wipe header on device %s.\n"),
				mdata_device_path(cd));

		return r;
	}

	r = LUKS_write_phdr(&cd->u.luks1.hdr, cd);

	return r;
}

static int _crypt_format_loopaes(struct crypt_device *cd,
				 const char *cipher,
				 const char *uuid,
				 size_t volume_key_size,
				 struct crypt_params_loopaes *params)
{
	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format LOOPAES without device.\n"));
		return -EINVAL;
	}

	if (volume_key_size > 1024) {
		log_err(cd, _("Invalid key size.\n"));
		return -EINVAL;
	}

	if (uuid) {
		log_err(cd, _("UUID is not supported for this crypt type.\n"));
		return -EINVAL;
	}

	if (!(cd->type = strdup(CRYPT_LOOPAES)))
		return -ENOMEM;

	cd->u.loopaes.key_size = volume_key_size;

	cd->u.loopaes.cipher = strdup(cipher ?: DEFAULT_LOOPAES_CIPHER);

	if (params && params->hash)
		cd->u.loopaes.hdr.hash = strdup(params->hash);

	cd->u.loopaes.hdr.offset = params ? params->offset : 0;
	cd->u.loopaes.hdr.skip = params ? params->skip : 0;

	return 0;
}

static int _crypt_format_verity(struct crypt_device *cd,
				 const char *uuid,
				 struct crypt_params_verity *params)
{
	int r = 0, hash_size;
	uint64_t data_device_size;

	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format VERITY without device.\n"));
		return -EINVAL;
	}

	if (!params || !params->data_device)
		return -EINVAL;

	if (params->hash_type > VERITY_MAX_HASH_TYPE) {
		log_err(cd, _("Unsupported VERITY hash type %d.\n"), params->hash_type);
		return -EINVAL;
	}

	if (VERITY_BLOCK_SIZE_OK(params->data_block_size) ||
	    VERITY_BLOCK_SIZE_OK(params->hash_block_size)) {
		log_err(cd, _("Unsupported VERITY block size.\n"));
		return -EINVAL;
	}

	if (params->hash_area_offset % 512) {
		log_err(cd, _("Unsupported VERITY hash offset.\n"));
		return -EINVAL;
	}

	if (!(cd->type = strdup(CRYPT_VERITY)))
		return -ENOMEM;

	r = crypt_set_data_device(cd, params->data_device);
	if (r)
		return r;
	if (!params->data_size) {
		r = device_size(cd->device, &data_device_size);
		if (r < 0)
			return r;

		cd->u.verity.hdr.data_size = data_device_size / params->data_block_size;
	} else
		cd->u.verity.hdr.data_size = params->data_size;

	hash_size = crypt_hash_size(params->hash_name);
	if (hash_size <= 0) {
		log_err(cd, _("Hash algorithm %s not supported.\n"),
			params->hash_name);
		return -EINVAL;
	}
	cd->u.verity.root_hash_size = hash_size;

	cd->u.verity.root_hash = malloc(cd->u.verity.root_hash_size);
	if (!cd->u.verity.root_hash)
		return -ENOMEM;

	cd->u.verity.hdr.flags = params->flags;
	if (!(cd->u.verity.hdr.hash_name = strdup(params->hash_name)))
		return -ENOMEM;
	cd->u.verity.hdr.data_device = NULL;
	cd->u.verity.hdr.data_block_size = params->data_block_size;
	cd->u.verity.hdr.hash_block_size = params->hash_block_size;
	cd->u.verity.hdr.hash_area_offset = params->hash_area_offset;
	cd->u.verity.hdr.hash_type = params->hash_type;
	cd->u.verity.hdr.flags = params->flags;
	cd->u.verity.hdr.salt_size = params->salt_size;
	if (!(cd->u.verity.hdr.salt = malloc(params->salt_size)))
		return -ENOMEM;

	if (params->salt)
		memcpy(CONST_CAST(char*)cd->u.verity.hdr.salt, params->salt,
		       params->salt_size);
	else
		r = crypt_random_get(cd, CONST_CAST(char*)cd->u.verity.hdr.salt,
				     params->salt_size, CRYPT_RND_SALT);
	if (r)
		return r;

	if (params->flags & CRYPT_VERITY_CREATE_HASH) {
		r = VERITY_create(cd, &cd->u.verity.hdr,
				  cd->u.verity.root_hash, cd->u.verity.root_hash_size);
		if (r)
			return r;
	}

	if (!(params->flags & CRYPT_VERITY_NO_HEADER)) {
		if (uuid)
			cd->u.verity.uuid = strdup(uuid);
		else {
			r = VERITY_UUID_generate(cd, &cd->u.verity.uuid);
			if (r)
				return r;
		}

		r = VERITY_write_sb(cd, cd->u.verity.hdr.hash_area_offset,
				    cd->u.verity.uuid,
				    &cd->u.verity.hdr);
	}
	return r;
}

int crypt_format(struct crypt_device *cd,
	const char *type,
	const char *cipher,
	const char *cipher_mode,
	const char *uuid,
	const char *volume_key,
	size_t volume_key_size,
	void *params)
{
	int r;

	if (!type)
		return -EINVAL;

	if (cd->type) {
		log_dbg("Context already formatted as %s.", cd->type);
		return -EINVAL;
	}

	log_dbg("Formatting device %s as type %s.", mdata_device_path(cd) ?: "(none)", type);

	crypt_reset_null_type(cd);

	r = init_crypto(cd);
	if (r < 0)
		return r;

	if (isPLAIN(type))
		r = _crypt_format_plain(cd, cipher, cipher_mode,
					uuid, volume_key_size, params);
	else if (isLUKS(type))
		r = _crypt_format_luks1(cd, cipher, cipher_mode,
					uuid, volume_key, volume_key_size, params);
	else if (isLOOPAES(type))
		r = _crypt_format_loopaes(cd, cipher, uuid, volume_key_size, params);
	else if (isVERITY(type))
		r = _crypt_format_verity(cd, uuid, params);
	else {
		log_err(cd, _("Unknown crypt device type %s requested.\n"), type);
		r = -EINVAL;
	}

	if (r < 0) {
		crypt_set_null_type(cd);
		crypt_free_volume_key(cd->volume_key);
		cd->volume_key = NULL;
	}

	return r;
}

int crypt_load(struct crypt_device *cd,
	       const char *requested_type,
	       void *params)
{
	int r;

	log_dbg("Trying to load %s crypt type from device %s.",
		requested_type ?: "any", mdata_device_path(cd) ?: "(none)");

	if (!crypt_metadata_device(cd))
		return -EINVAL;

	crypt_reset_null_type(cd);

	if (!requested_type || isLUKS(requested_type)) {
		if (cd->type && !isLUKS(cd->type)) {
			log_dbg("Context is already initialised to type %s", cd->type);
			return -EINVAL;
		}

		r = _crypt_load_luks1(cd, 1, 0);
	} else if (isVERITY(requested_type)) {
		if (cd->type && !isVERITY(cd->type)) {
			log_dbg("Context is already initialised to type %s", cd->type);
			return -EINVAL;
		}
		r = _crypt_load_verity(cd, params);
	} else if (isTCRYPT(requested_type)) {
		if (cd->type && !isTCRYPT(cd->type)) {
			log_dbg("Context is already initialised to type %s", cd->type);
			return -EINVAL;
		}
		r = _crypt_load_tcrypt(cd, params);
	} else
		return -EINVAL;

	return r;
}

int crypt_repair(struct crypt_device *cd,
		 const char *requested_type,
		 void *params __attribute__((unused)))
{
	int r;

	log_dbg("Trying to repair %s crypt type from device %s.",
		requested_type ?: "any", mdata_device_path(cd) ?: "(none)");

	if (!crypt_metadata_device(cd))
		return -EINVAL;

	if (requested_type && !isLUKS(requested_type))
		return -EINVAL;


	/* Load with repair */
	r = _crypt_load_luks1(cd, 1, 1);
	if (r < 0)
		return r;

	/* cd->type and header must be set in context */
	r = crypt_check_data_device_size(cd);
	if (r < 0)
		crypt_set_null_type(cd);

	return r;
}

int crypt_resize(struct crypt_device *cd, const char *name, uint64_t new_size)
{
	struct crypt_dm_active_device dmd;
	int r;

	/* Device context type must be initialised */
	if (!cd->type)
		return -EINVAL;

	log_dbg("Resizing device %s to %" PRIu64 " sectors.", name, new_size);

	r = dm_query_device(cd, name, DM_ACTIVE_DEVICE | DM_ACTIVE_CRYPT_CIPHER |
				  DM_ACTIVE_UUID | DM_ACTIVE_CRYPT_KEYSIZE |
				  DM_ACTIVE_CRYPT_KEY, &dmd);
	if (r < 0) {
		log_err(NULL, _("Device %s is not active.\n"), name);
		return -EINVAL;
	}

	if (!dmd.uuid || dmd.target != DM_CRYPT) {
		r = -EINVAL;
		goto out;
	}

	r = device_block_adjust(cd, dmd.data_device, DEV_OK,
				dmd.u.crypt.offset, &new_size, &dmd.flags);
	if (r)
		goto out;

	if (new_size == dmd.size) {
		log_dbg("Device has already requested size %" PRIu64
			" sectors.", dmd.size);
		r = 0;
	} else {
		dmd.size = new_size;
		if (isTCRYPT(cd->type))
			r = -ENOTSUP;
		else
			r = dm_create_device(cd, name, cd->type, &dmd, 1);
	}
out:
	if (dmd.target == DM_CRYPT) {
		crypt_free_volume_key(dmd.u.crypt.vk);
		free(CONST_CAST(void*)dmd.u.crypt.cipher);
	}
	free(CONST_CAST(void*)dmd.data_device);
	free(CONST_CAST(void*)dmd.uuid);

	return r;
}

int crypt_set_uuid(struct crypt_device *cd, const char *uuid)
{
	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is not supported for this device type.\n"));
		return  -EINVAL;
	}

	if (uuid && !strncmp(uuid, cd->u.luks1.hdr.uuid, sizeof(cd->u.luks1.hdr.uuid))) {
		log_dbg("UUID is the same as requested (%s) for device %s.",
			uuid, mdata_device_path(cd));
		return 0;
	}

	if (uuid)
		log_dbg("Requested new UUID change to %s for %s.", uuid, mdata_device_path(cd));
	else
		log_dbg("Requested new UUID refresh for %s.", mdata_device_path(cd));

	if (!crypt_confirm(cd, _("Do you really want to change UUID of device?")))
		return -EPERM;

	return LUKS_hdr_uuid_set(&cd->u.luks1.hdr, uuid, cd);
}

int crypt_header_backup(struct crypt_device *cd,
			const char *requested_type,
			const char *backup_file)
{
	int r;

	if ((requested_type && !isLUKS(requested_type)) || !backup_file)
		return -EINVAL;

	if (cd->type && !isLUKS(cd->type))
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	log_dbg("Requested header backup of device %s (%s) to "
		"file %s.", mdata_device_path(cd), requested_type, backup_file);

	r = LUKS_hdr_backup(backup_file, cd);
	return r;
}

int crypt_header_restore(struct crypt_device *cd,
			 const char *requested_type,
			 const char *backup_file)
{
	struct luks_phdr hdr;
	int r;

	if (requested_type && !isLUKS(requested_type))
		return -EINVAL;

	if (cd->type && !isLUKS(cd->type))
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	log_dbg("Requested header restore to device %s (%s) from "
		"file %s.", mdata_device_path(cd), requested_type, backup_file);

	r = LUKS_hdr_restore(backup_file, isLUKS(cd->type) ? &cd->u.luks1.hdr : &hdr, cd);

	memset(&hdr, 0, sizeof(hdr));
	return r;
}

void crypt_free(struct crypt_device *cd)
{
	if (cd) {
		log_dbg("Releasing crypt device %s context.", mdata_device_path(cd));

		dm_backend_exit();
		crypt_free_volume_key(cd->volume_key);

		device_free(cd->device);
		device_free(cd->metadata_device);

		if (isPLAIN(cd->type)) {
			free(CONST_CAST(void*)cd->u.plain.hdr.hash);
			free(cd->u.plain.cipher);
			free(cd->u.plain.cipher_mode);
		} else if (isLOOPAES(cd->type)) {
			free(CONST_CAST(void*)cd->u.loopaes.hdr.hash);
			free(cd->u.loopaes.cipher);
		} else if (isVERITY(cd->type)) {
			free(CONST_CAST(void*)cd->u.verity.hdr.hash_name);
			free(CONST_CAST(void*)cd->u.verity.hdr.salt);
			free(cd->u.verity.root_hash);
			free(cd->u.verity.uuid);
		} else if (!cd->type) {
			free(cd->u.none.active_name);
		}

		free(cd->type);
		/* Some structures can contain keys (TCRYPT), wipe it */
		memset(cd, 0, sizeof(*cd));
		free(cd);
	}
}

int crypt_suspend(struct crypt_device *cd,
		  const char *name)
{
	crypt_status_info ci;
	int r;

	log_dbg("Suspending volume %s.", name);

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	ci = crypt_status(NULL, name);
	if (ci < CRYPT_ACTIVE) {
		log_err(cd, _("Volume %s is not active.\n"), name);
		return -EINVAL;
	}

	dm_backend_init();

	r = dm_status_suspended(cd, name);
	if (r < 0)
		goto out;

	if (r) {
		log_err(cd, _("Volume %s is already suspended.\n"), name);
		r = -EINVAL;
		goto out;
	}

	r = dm_suspend_and_wipe_key(cd, name);
	if (r == -ENOTSUP)
		log_err(cd, _("Suspend is not supported for device %s.\n"), name);
	else if (r)
		log_err(cd, _("Error during suspending device %s.\n"), name);
out:
	dm_backend_exit();
	return r;
}

int crypt_resume_by_passphrase(struct crypt_device *cd,
			       const char *name,
			       int keyslot,
			       const char *passphrase,
			       size_t passphrase_size)
{
	struct volume_key *vk = NULL;
	int r;

	log_dbg("Resuming volume %s.", name);

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	r = dm_status_suspended(cd, name);
	if (r < 0)
		return r;

	if (!r) {
		log_err(cd, _("Volume %s is not suspended.\n"), name);
		return -EINVAL;
	}

	if (passphrase) {
		r = LUKS_open_key_with_hdr(keyslot, passphrase, passphrase_size,
					   &cd->u.luks1.hdr, &vk, cd);
	} else
		r = volume_key_by_terminal_passphrase(cd, keyslot, &vk);

	if (r >= 0) {
		keyslot = r;
		r = dm_resume_and_reinstate_key(cd, name, vk->keylength, vk->key);
		if (r == -ENOTSUP)
			log_err(cd, _("Resume is not supported for device %s.\n"), name);
		else if (r)
			log_err(cd, _("Error during resuming device %s.\n"), name);
	} else
		r = keyslot;

	crypt_free_volume_key(vk);
	return r < 0 ? r : keyslot;
}

int crypt_resume_by_keyfile_offset(struct crypt_device *cd,
				   const char *name,
				   int keyslot,
				   const char *keyfile,
				   size_t keyfile_size,
				   size_t keyfile_offset)
{
	struct volume_key *vk = NULL;
	char *passphrase_read = NULL;
	size_t passphrase_size_read;
	int r;

	log_dbg("Resuming volume %s.", name);

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	r = dm_status_suspended(cd, name);
	if (r < 0)
		return r;

	if (!r) {
		log_err(cd, _("Volume %s is not suspended.\n"), name);
		return -EINVAL;
	}

	if (!keyfile)
		return -EINVAL;

	r = key_from_file(cd, _("Enter passphrase: "), &passphrase_read,
			  &passphrase_size_read, keyfile, keyfile_offset,
			  keyfile_size);
	if (r < 0)
		goto out;

	r = LUKS_open_key_with_hdr(keyslot, passphrase_read,
				   passphrase_size_read, &cd->u.luks1.hdr, &vk, cd);
	if (r < 0)
		goto out;

	keyslot = r;
	r = dm_resume_and_reinstate_key(cd, name, vk->keylength, vk->key);
	if (r)
		log_err(cd, _("Error during resuming device %s.\n"), name);
out:
	crypt_safe_free(passphrase_read);
	crypt_free_volume_key(vk);
	return r < 0 ? r : keyslot;
}

int crypt_resume_by_keyfile(struct crypt_device *cd,
			    const char *name,
			    int keyslot,
			    const char *keyfile,
			    size_t keyfile_size)
{
	return crypt_resume_by_keyfile_offset(cd, name, keyslot,
					      keyfile, keyfile_size, 0);
}

// slot manipulation
int crypt_keyslot_add_by_passphrase(struct crypt_device *cd,
	int keyslot, // -1 any
	const char *passphrase, // NULL -> terminal
	size_t passphrase_size,
	const char *new_passphrase, // NULL -> terminal
	size_t new_passphrase_size)
{
	struct volume_key *vk = NULL;
	char *password = NULL, *new_password = NULL;
	size_t passwordLen, new_passwordLen;
	int r;

	log_dbg("Adding new keyslot, existing passphrase %sprovided,"
		"new passphrase %sprovided.",
		passphrase ? "" : "not ", new_passphrase  ? "" : "not ");

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r)
		return r;

	if (!LUKS_keyslot_active_count(&cd->u.luks1.hdr)) {
		/* No slots used, try to use pre-generated key in header */
		if (cd->volume_key) {
			vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);
			r = vk ? 0 : -ENOMEM;
		} else {
			log_err(cd, _("Cannot add key slot, all slots disabled and no volume key provided.\n"));
			return -EINVAL;
		}
	} else if (passphrase) {
		/* Passphrase provided, use it to unlock existing keyslot */
		r = LUKS_open_key_with_hdr(CRYPT_ANY_SLOT, passphrase,
					   passphrase_size, &cd->u.luks1.hdr, &vk, cd);
	} else {
		/* Passphrase not provided, ask first and use it to unlock existing keyslot */
		r = key_from_terminal(cd, _("Enter any passphrase: "),
				      &password, &passwordLen, 0);
		if (r < 0)
			goto out;

		r = LUKS_open_key_with_hdr(CRYPT_ANY_SLOT, password,
					   passwordLen, &cd->u.luks1.hdr, &vk, cd);
		crypt_safe_free(password);
	}

	if(r < 0)
		goto out;

	if (new_passphrase) {
		new_password = CONST_CAST(char*)new_passphrase;
		new_passwordLen = new_passphrase_size;
	} else {
		r = key_from_terminal(cd, _("Enter new passphrase for key slot: "),
				      &new_password, &new_passwordLen, 1);
		if(r < 0)
			goto out;
	}

	r = LUKS_set_key(keyslot, new_password, new_passwordLen,
			 &cd->u.luks1.hdr, vk, cd->iteration_time, &cd->u.luks1.PBKDF2_per_sec, cd);
	if(r < 0)
		goto out;

	r = 0;
out:
	if (!new_passphrase)
		crypt_safe_free(new_password);
	crypt_free_volume_key(vk);
	return r < 0 ? r : keyslot;
}

int crypt_keyslot_change_by_passphrase(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	const char *passphrase,
	size_t passphrase_size,
	const char *new_passphrase,
	size_t new_passphrase_size)
{
	struct volume_key *vk = NULL;
	int r;

	log_dbg("Changing passphrase from old keyslot %d to new %d.",
		keyslot_old, keyslot_new);

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	r = LUKS_open_key_with_hdr(keyslot_old, passphrase, passphrase_size,
				   &cd->u.luks1.hdr, &vk, cd);
	if (r < 0)
		goto out;

	if (keyslot_old != CRYPT_ANY_SLOT && keyslot_old != r) {
		log_dbg("Keyslot mismatch.");
		goto out;
	}
	keyslot_old = r;

	if (keyslot_new == CRYPT_ANY_SLOT) {
		keyslot_new = LUKS_keyslot_find_empty(&cd->u.luks1.hdr);
		if (keyslot_new < 0)
			keyslot_new = keyslot_old;
	}

	if (keyslot_old == keyslot_new) {
		log_dbg("Key slot %d is going to be overwritten.", keyslot_old);
		(void)crypt_keyslot_destroy(cd, keyslot_old);
	}

	r = LUKS_set_key(keyslot_new, new_passphrase, new_passphrase_size,
			 &cd->u.luks1.hdr, vk, cd->iteration_time,
			 &cd->u.luks1.PBKDF2_per_sec, cd);

	if (keyslot_old == keyslot_new) {
		if (r >= 0)
			log_verbose(cd, _("Key slot %d changed.\n"), keyslot_new);
	} else {
		if (r >= 0) {
			log_verbose(cd, _("Replaced with key slot %d.\n"), keyslot_new);
			r = crypt_keyslot_destroy(cd, keyslot_old);
		}
	}
	if (r < 0)
		log_err(cd, _("Failed to swap new key slot.\n"));
out:
	crypt_free_volume_key(vk);
	return r < 0 ? r : keyslot_new;
}

int crypt_keyslot_add_by_keyfile_offset(struct crypt_device *cd,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	size_t keyfile_offset,
	const char *new_keyfile,
	size_t new_keyfile_size,
	size_t new_keyfile_offset)
{
	struct volume_key *vk = NULL;
	char *password = NULL; size_t passwordLen;
	char *new_password = NULL; size_t new_passwordLen;
	int r;

	log_dbg("Adding new keyslot, existing keyfile %s, new keyfile %s.",
		keyfile ?: "[none]", new_keyfile ?: "[none]");

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r)
		return r;

	if (!LUKS_keyslot_active_count(&cd->u.luks1.hdr)) {
		/* No slots used, try to use pre-generated key in header */
		if (cd->volume_key) {
			vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);
			r = vk ? 0 : -ENOMEM;
		} else {
			log_err(cd, _("Cannot add key slot, all slots disabled and no volume key provided.\n"));
			return -EINVAL;
		}
	} else {
		/* Read password from file of (if NULL) from terminal */
		if (keyfile)
			r = key_from_file(cd, _("Enter any passphrase: "),
					  &password, &passwordLen,
					  keyfile, keyfile_offset, keyfile_size);
		else
			r = key_from_terminal(cd, _("Enter any passphrase: "),
					      &password, &passwordLen, 0);
		if (r < 0)
			goto out;

		r = LUKS_open_key_with_hdr(CRYPT_ANY_SLOT, password, passwordLen,
					   &cd->u.luks1.hdr, &vk, cd);
	}

	if(r < 0)
		goto out;

	if (new_keyfile)
		r = key_from_file(cd, _("Enter new passphrase for key slot: "),
				  &new_password, &new_passwordLen, new_keyfile,
				  new_keyfile_offset, new_keyfile_size);
	else
		r = key_from_terminal(cd, _("Enter new passphrase for key slot: "),
				      &new_password, &new_passwordLen, 1);
	if (r < 0)
		goto out;

	r = LUKS_set_key(keyslot, new_password, new_passwordLen,
			 &cd->u.luks1.hdr, vk, cd->iteration_time, &cd->u.luks1.PBKDF2_per_sec, cd);
out:
	crypt_safe_free(password);
	crypt_safe_free(new_password);
	crypt_free_volume_key(vk);
	return r < 0 ? r : keyslot;
}

int crypt_keyslot_add_by_keyfile(struct crypt_device *cd,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	const char *new_keyfile,
	size_t new_keyfile_size)
{
	return crypt_keyslot_add_by_keyfile_offset(cd, keyslot,
				keyfile, keyfile_size, 0,
				new_keyfile, new_keyfile_size, 0);
}

int crypt_keyslot_add_by_volume_key(struct crypt_device *cd,
	int keyslot,
	const char *volume_key,
	size_t volume_key_size,
	const char *passphrase,
	size_t passphrase_size)
{
	struct volume_key *vk = NULL;
	int r;
	char *new_password = NULL; size_t new_passwordLen;

	log_dbg("Adding new keyslot %d using volume key.", keyslot);

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	if (volume_key)
		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	else if (cd->volume_key)
		vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);

	if (!vk)
		return -ENOMEM;

	r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);
	if (r < 0) {
		log_err(cd, _("Volume key does not match the volume.\n"));
		goto out;
	}

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r)
		goto out;

	if (!passphrase) {
		r = key_from_terminal(cd, _("Enter new passphrase for key slot: "),
				      &new_password, &new_passwordLen, 1);
		if (r < 0)
			goto out;
		passphrase = new_password;
		passphrase_size = new_passwordLen;
	}

	r = LUKS_set_key(keyslot, passphrase, passphrase_size,
			 &cd->u.luks1.hdr, vk, cd->iteration_time, &cd->u.luks1.PBKDF2_per_sec, cd);
out:
	crypt_safe_free(new_password);
	crypt_free_volume_key(vk);
	return (r < 0) ? r : keyslot;
}

int crypt_keyslot_destroy(struct crypt_device *cd, int keyslot)
{
	crypt_keyslot_info ki;
	int r;

	log_dbg("Destroying keyslot %d.", keyslot);

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	ki = crypt_keyslot_status(cd, keyslot);
	if (ki == CRYPT_SLOT_INVALID) {
		log_err(cd, _("Key slot %d is invalid.\n"), keyslot);
		return -EINVAL;
	}

	if (ki == CRYPT_SLOT_INACTIVE) {
		log_err(cd, _("Key slot %d is not used.\n"), keyslot);
		return -EINVAL;
	}

	return LUKS_del_key(keyslot, &cd->u.luks1.hdr, cd);
}

// activation/deactivation of device mapping
int crypt_activate_by_passphrase(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	crypt_status_info ci;
	struct volume_key *vk = NULL;
	char *read_passphrase = NULL;
	size_t passphraseLen = 0;
	int r;

	log_dbg("%s volume %s [keyslot %d] using %spassphrase.",
		name ? "Activating" : "Checking", name ?: "",
		keyslot, passphrase ? "" : "[none] ");

	if (name) {
		ci = crypt_status(NULL, name);
		if (ci == CRYPT_INVALID)
			return -EINVAL;
		else if (ci >= CRYPT_ACTIVE) {
			log_err(cd, _("Device %s already exists.\n"), name);
			return -EEXIST;
		}
	}

	/* plain, use hashed passphrase */
	if (isPLAIN(cd->type)) {
		if (!name)
			return -EINVAL;

		if (!passphrase) {
			r = key_from_terminal(cd, NULL, &read_passphrase,
					      &passphraseLen, 0);
			if (r < 0)
				goto out;
			passphrase = read_passphrase;
			passphrase_size = passphraseLen;
		}

		r = process_key(cd, cd->u.plain.hdr.hash,
				cd->u.plain.key_size,
				passphrase, passphrase_size, &vk);
		if (r < 0)
			goto out;

		r = PLAIN_activate(cd, name, vk, cd->u.plain.hdr.size, flags);
		keyslot = 0;
	} else if (isLUKS(cd->type)) {
		/* provided passphrase, do not retry */
		if (passphrase) {
			r = LUKS_open_key_with_hdr(keyslot, passphrase,
						   passphrase_size, &cd->u.luks1.hdr, &vk, cd);
		} else
			r = volume_key_by_terminal_passphrase(cd, keyslot, &vk);

		if (r >= 0) {
			keyslot = r;
			if (name)
				r = LUKS1_activate(cd, name, vk, flags);
		}
	} else
		r = -EINVAL;
out:
	crypt_safe_free(read_passphrase);
	crypt_free_volume_key(vk);

	return r < 0  ? r : keyslot;
}

int crypt_activate_by_keyfile_offset(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	size_t keyfile_offset,
	uint32_t flags)
{
	crypt_status_info ci;
	struct volume_key *vk = NULL;
	char *passphrase_read = NULL;
	size_t passphrase_size_read;
	unsigned int key_count = 0;
	int r;

	log_dbg("Activating volume %s [keyslot %d] using keyfile %s.",
		name ?: "", keyslot, keyfile ?: "[none]");

	if (name) {
		ci = crypt_status(NULL, name);
		if (ci == CRYPT_INVALID)
			return -EINVAL;
		else if (ci >= CRYPT_ACTIVE) {
			log_err(cd, _("Device %s already exists.\n"), name);
			return -EEXIST;
		}
	}

	if (!keyfile)
		return -EINVAL;

	if (isPLAIN(cd->type)) {
		if (!name)
			return -EINVAL;

		r = key_from_file(cd, _("Enter passphrase: "),
				  &passphrase_read, &passphrase_size_read,
				  keyfile, keyfile_offset, keyfile_size);
		if (r < 0)
			goto out;

		r = process_key(cd, cd->u.plain.hdr.hash,
				cd->u.plain.key_size,
				passphrase_read, passphrase_size_read, &vk);
		if (r < 0)
			goto out;

		r = PLAIN_activate(cd, name, vk, cd->u.plain.hdr.size, flags);
	} else if (isLUKS(cd->type)) {
		r = key_from_file(cd, _("Enter passphrase: "), &passphrase_read,
			  &passphrase_size_read, keyfile, keyfile_offset, keyfile_size);
		if (r < 0)
			goto out;
		r = LUKS_open_key_with_hdr(keyslot, passphrase_read,
					   passphrase_size_read, &cd->u.luks1.hdr, &vk, cd);
		if (r < 0)
			goto out;
		keyslot = r;

		if (name) {
			r = LUKS1_activate(cd, name, vk, flags);
			if (r < 0)
				goto out;
		}
		r = keyslot;
	} else if (isLOOPAES(cd->type)) {
		r = key_from_file(cd, NULL, &passphrase_read, &passphrase_size_read,
				  keyfile, keyfile_offset, keyfile_size);
		if (r < 0)
			goto out;
		r = LOOPAES_parse_keyfile(cd, &vk, cd->u.loopaes.hdr.hash, &key_count,
					  passphrase_read, passphrase_size_read);
		if (r < 0)
			goto out;
		if (name)
			r = LOOPAES_activate(cd, name, cd->u.loopaes.cipher,
					     key_count, vk, flags);
	} else
		r = -EINVAL;

out:
	crypt_safe_free(passphrase_read);
	crypt_free_volume_key(vk);

	return r;
}

int crypt_activate_by_keyfile(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	uint32_t flags)
{
	return crypt_activate_by_keyfile_offset(cd, name, keyslot, keyfile,
						keyfile_size, 0, flags);
}

int crypt_activate_by_volume_key(struct crypt_device *cd,
	const char *name,
	const char *volume_key,
	size_t volume_key_size,
	uint32_t flags)
{
	crypt_status_info ci;
	struct volume_key *vk = NULL;
	int r = -EINVAL;

	log_dbg("Activating volume %s by volume key.", name ?: "[none]");

	if (name) {
		ci = crypt_status(NULL, name);
		if (ci == CRYPT_INVALID)
			return -EINVAL;
		else if (ci >= CRYPT_ACTIVE) {
			log_err(cd, _("Device %s already exists.\n"), name);
			return -EEXIST;
		}
	}

	/* use key directly, no hash */
	if (isPLAIN(cd->type)) {
		if (!name)
			return -EINVAL;

		if (!volume_key || !volume_key_size || volume_key_size != cd->u.plain.key_size) {
			log_err(cd, _("Incorrect volume key specified for plain device.\n"));
			return -EINVAL;
		}

		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
		if (!vk)
			return -ENOMEM;

		r = PLAIN_activate(cd, name, vk, cd->u.plain.hdr.size, flags);
	} else if (isLUKS(cd->type)) {
		/* If key is not provided, try to use internal key */
		if (!volume_key) {
			if (!cd->volume_key) {
				log_err(cd, _("Volume key does not match the volume.\n"));
				return -EINVAL;
			}
			volume_key_size = cd->volume_key->keylength;
			volume_key = cd->volume_key->key;
		}

		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
		if (!vk)
			return -ENOMEM;
		r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);

		if (r == -EPERM)
			log_err(cd, _("Volume key does not match the volume.\n"));

		if (!r && name)
			r = LUKS1_activate(cd, name, vk, flags);
	} else if (isVERITY(cd->type)) {
		/* volume_key == root hash */
		if (!volume_key || !volume_key_size) {
			log_err(cd, _("Incorrect root hash specified for verity device.\n"));
			return -EINVAL;
		}

		r = VERITY_activate(cd, name, volume_key, volume_key_size,
				    &cd->u.verity.hdr, CRYPT_ACTIVATE_READONLY);

		if (r == -EPERM) {
			free(cd->u.verity.root_hash);
			cd->u.verity.root_hash = NULL;
		} if (!r) {
			cd->u.verity.root_hash_size = volume_key_size;
			if (!cd->u.verity.root_hash)
				cd->u.verity.root_hash = malloc(volume_key_size);
			if (cd->u.verity.root_hash)
				memcpy(cd->u.verity.root_hash, volume_key, volume_key_size);
		}
	} else if (isTCRYPT(cd->type)) {
		if (!name)
			return 0;
		r = TCRYPT_activate(cd, name, &cd->u.tcrypt.hdr,
				    &cd->u.tcrypt.params, flags);
	} else
		log_err(cd, _("Device type is not properly initialised.\n"));

	crypt_free_volume_key(vk);

	return r;
}

int crypt_deactivate(struct crypt_device *cd, const char *name)
{
	struct crypt_device *fake_cd = NULL;
	int r;

	if (!name)
		return -EINVAL;

	log_dbg("Deactivating volume %s.", name);

	if (!cd) {
		r = crypt_init_by_name(&fake_cd, name);
		if (r < 0)
			return r;
		cd = fake_cd;
	}

	switch (crypt_status(cd, name)) {
		case CRYPT_ACTIVE:
		case CRYPT_BUSY:
			if (isTCRYPT(cd->type))
				r = TCRYPT_deactivate(cd, name);
			else
				r = dm_remove_device(cd, name, 0, 0);
			if (r < 0 && crypt_status(cd, name) == CRYPT_BUSY) {
				log_err(cd, _("Device %s is still in use.\n"), name);
				r = -EBUSY;
			}
			break;
		case CRYPT_INACTIVE:
			log_err(cd, _("Device %s is not active.\n"), name);
			r = -ENODEV;
			break;
		default:
			log_err(cd, _("Invalid device %s.\n"), name);
			r = -EINVAL;
	}

	crypt_free(fake_cd);

	return r;
}

int crypt_volume_key_get(struct crypt_device *cd,
	int keyslot,
	char *volume_key,
	size_t *volume_key_size,
	const char *passphrase,
	size_t passphrase_size)
{
	struct volume_key *vk = NULL;
	unsigned key_len;
	int r = -EINVAL;

	if (crypt_fips_mode()) {
		log_err(cd, _("Function not available in FIPS mode.\n"));
		return -EACCES;
	}

	key_len = crypt_get_volume_key_size(cd);
	if (key_len > *volume_key_size) {
		log_err(cd, _("Volume key buffer too small.\n"));
		return -ENOMEM;
	}

	if (isPLAIN(cd->type) && cd->u.plain.hdr.hash) {
		r = process_key(cd, cd->u.plain.hdr.hash, key_len,
				passphrase, passphrase_size, &vk);
		if (r < 0)
			log_err(cd, _("Cannot retrieve volume key for plain device.\n"));
	} else if (isLUKS(cd->type)) {
		r = LUKS_open_key_with_hdr(keyslot, passphrase,
					passphrase_size, &cd->u.luks1.hdr, &vk, cd);
	} else if (isTCRYPT(cd->type)) {
		r = TCRYPT_get_volume_key(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params, &vk);
	} else
		log_err(cd, _("This operation is not supported for %s crypt device.\n"), cd->type ?: "(none)");

	if (r >= 0) {
		memcpy(volume_key, vk->key, vk->keylength);
		*volume_key_size = vk->keylength;
	}

	crypt_free_volume_key(vk);
	return r;
}

int crypt_volume_key_verify(struct crypt_device *cd,
	const char *volume_key,
	size_t volume_key_size)
{
	struct volume_key *vk;
	int r;

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	if (!vk)
		return -ENOMEM;

	r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);

	if (r == -EPERM)
		log_err(cd, _("Volume key does not match the volume.\n"));

	crypt_free_volume_key(vk);

	return r;
}

void crypt_set_timeout(struct crypt_device *cd, uint64_t timeout_sec)
{
	log_dbg("Timeout set to %" PRIu64 " miliseconds.", timeout_sec);
	cd->timeout = timeout_sec;
}

void crypt_set_password_retry(struct crypt_device *cd, int tries)
{
	log_dbg("Password retry count set to %d.", tries);
	cd->tries = tries;
}

void crypt_set_iteration_time(struct crypt_device *cd, uint64_t iteration_time_ms)
{
	log_dbg("Iteration time set to %" PRIu64 " miliseconds.", iteration_time_ms);
	cd->iteration_time = iteration_time_ms;
}
void crypt_set_iterarion_time(struct crypt_device *cd, uint64_t iteration_time_ms)
{
	crypt_set_iteration_time(cd, iteration_time_ms);
}

void crypt_set_password_verify(struct crypt_device *cd, int password_verify)
{
	log_dbg("Password verification %s.", password_verify ? "enabled" : "disabled");
	cd->password_verify = password_verify ? 1 : 0;
}

void crypt_set_rng_type(struct crypt_device *cd, int rng_type)
{
	switch (rng_type) {
	case CRYPT_RNG_URANDOM:
	case CRYPT_RNG_RANDOM:
		log_dbg("RNG set to %d (%s).", rng_type, rng_type ? "random" : "urandom");
		cd->rng_type = rng_type;
	}
}

int crypt_get_rng_type(struct crypt_device *cd)
{
	if (!cd)
		return -EINVAL;

	return cd->rng_type;
}

int crypt_memory_lock(struct crypt_device *cd, int lock)
{
	return lock ? crypt_memlock_inc(cd) : crypt_memlock_dec(cd);
}

// reporting
crypt_status_info crypt_status(struct crypt_device *cd, const char *name)
{
	int r;

	if (!cd)
		dm_backend_init();

	r = dm_status_device(cd, name);

	if (!cd)
		dm_backend_exit();

	if (r < 0 && r != -ENODEV)
		return CRYPT_INVALID;

	if (r == 0)
		return CRYPT_ACTIVE;

	if (r > 0)
		return CRYPT_BUSY;

	return CRYPT_INACTIVE;
}

static void hexprint(struct crypt_device *cd, const char *d, int n, const char *sep)
{
	int i;
	for(i = 0; i < n; i++)
		log_std(cd, "%02hhx%s", (const char)d[i], sep);
}

static int _luks_dump(struct crypt_device *cd)
{
	int i;

	log_std(cd, "LUKS header information for %s\n\n", mdata_device_path(cd));
	log_std(cd, "Version:       \t%d\n", cd->u.luks1.hdr.version);
	log_std(cd, "Cipher name:   \t%s\n", cd->u.luks1.hdr.cipherName);
	log_std(cd, "Cipher mode:   \t%s\n", cd->u.luks1.hdr.cipherMode);
	log_std(cd, "Hash spec:     \t%s\n", cd->u.luks1.hdr.hashSpec);
	log_std(cd, "Payload offset:\t%d\n", cd->u.luks1.hdr.payloadOffset);
	log_std(cd, "MK bits:       \t%d\n", cd->u.luks1.hdr.keyBytes * 8);
	log_std(cd, "MK digest:     \t");
	hexprint(cd, cd->u.luks1.hdr.mkDigest, LUKS_DIGESTSIZE, " ");
	log_std(cd, "\n");
	log_std(cd, "MK salt:       \t");
	hexprint(cd, cd->u.luks1.hdr.mkDigestSalt, LUKS_SALTSIZE/2, " ");
	log_std(cd, "\n               \t");
	hexprint(cd, cd->u.luks1.hdr.mkDigestSalt+LUKS_SALTSIZE/2, LUKS_SALTSIZE/2, " ");
	log_std(cd, "\n");
	log_std(cd, "MK iterations: \t%d\n", cd->u.luks1.hdr.mkDigestIterations);
	log_std(cd, "UUID:          \t%s\n\n", cd->u.luks1.hdr.uuid);
	for(i = 0; i < LUKS_NUMKEYS; i++) {
		if(cd->u.luks1.hdr.keyblock[i].active == LUKS_KEY_ENABLED) {
			log_std(cd, "Key Slot %d: ENABLED\n",i);
			log_std(cd, "\tIterations:         \t%d\n",
				cd->u.luks1.hdr.keyblock[i].passwordIterations);
			log_std(cd, "\tSalt:               \t");
			hexprint(cd, cd->u.luks1.hdr.keyblock[i].passwordSalt,
				 LUKS_SALTSIZE/2, " ");
			log_std(cd, "\n\t                      \t");
			hexprint(cd, cd->u.luks1.hdr.keyblock[i].passwordSalt +
				 LUKS_SALTSIZE/2, LUKS_SALTSIZE/2, " ");
			log_std(cd, "\n");

			log_std(cd, "\tKey material offset:\t%d\n",
				cd->u.luks1.hdr.keyblock[i].keyMaterialOffset);
			log_std(cd, "\tAF stripes:            \t%d\n",
				cd->u.luks1.hdr.keyblock[i].stripes);
		}
		else 
			log_std(cd, "Key Slot %d: DISABLED\n", i);
	}
	return 0;
}

static int _verity_dump(struct crypt_device *cd)
{
	log_std(cd, "VERITY header information for %s\n", mdata_device_path(cd));
	log_std(cd, "UUID:            \t%s\n", cd->u.verity.uuid ?: "");
	log_std(cd, "Hash type:       \t%u\n", cd->u.verity.hdr.hash_type);
	log_std(cd, "Data blocks:     \t%" PRIu64 "\n", cd->u.verity.hdr.data_size);
	log_std(cd, "Data block size: \t%u\n", cd->u.verity.hdr.data_block_size);
	log_std(cd, "Hash block size: \t%u\n", cd->u.verity.hdr.hash_block_size);
	log_std(cd, "Hash algorithm:  \t%s\n", cd->u.verity.hdr.hash_name);
	log_std(cd, "Salt:            \t");
	if (cd->u.verity.hdr.salt_size)
		hexprint(cd, cd->u.verity.hdr.salt, cd->u.verity.hdr.salt_size, "");
	else
		log_std(cd, "-");
	log_std(cd, "\n");
	if (cd->u.verity.root_hash) {
		log_std(cd, "Root hash:      \t");
		hexprint(cd, cd->u.verity.root_hash, cd->u.verity.root_hash_size, "");
		log_std(cd, "\n");
	}
	return 0;
}

int crypt_dump(struct crypt_device *cd)
{
	if (isLUKS(cd->type))
		return _luks_dump(cd);
	else if (isVERITY(cd->type))
		return _verity_dump(cd);
	else if (isTCRYPT(cd->type))
		return TCRYPT_dump(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);

	log_err(cd, _("Dump operation is not supported for this device type.\n"));
	return -EINVAL;
}


static int _init_by_name_crypt_none(struct crypt_device *cd)
{
	struct crypt_dm_active_device dmd = {};
	int r;

	if (cd->type || !cd->u.none.active_name)
		return -EINVAL;

	r = dm_query_device(cd, cd->u.none.active_name,
			DM_ACTIVE_CRYPT_CIPHER |
			DM_ACTIVE_CRYPT_KEYSIZE, &dmd);
	if (r >= 0)
		r = crypt_parse_name_and_mode(dmd.u.crypt.cipher,
					      cd->u.none.cipher, NULL,
					      cd->u.none.cipher_mode);

	if (!r)
		cd->u.none.key_size = dmd.u.crypt.vk->keylength;

	crypt_free_volume_key(dmd.u.crypt.vk);
	free(CONST_CAST(void*)dmd.u.crypt.cipher);
	return r;
}

const char *crypt_get_cipher(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->u.plain.cipher;

	if (isLUKS(cd->type))
		return cd->u.luks1.hdr.cipherName;

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.cipher;

	if (isTCRYPT(cd->type))
		return cd->u.tcrypt.params.cipher;

	if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.cipher;

	return NULL;
}

const char *crypt_get_cipher_mode(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->u.plain.cipher_mode;

	if (isLUKS(cd->type))
		return cd->u.luks1.hdr.cipherMode;

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.cipher_mode;

	if (isTCRYPT(cd->type))
		return cd->u.tcrypt.params.mode;

	if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.cipher_mode;

	return NULL;
}

const char *crypt_get_uuid(struct crypt_device *cd)
{
	if (isLUKS(cd->type))
		return cd->u.luks1.hdr.uuid;

	if (isVERITY(cd->type))
		return cd->u.verity.uuid;

	return NULL;
}

const char *crypt_get_device_name(struct crypt_device *cd)
{
	const char *path = device_block_path(cd->device);

	if (!path)
		path = device_path(cd->device);

	return path;
}

int crypt_get_volume_key_size(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->u.plain.key_size;

	if (isLUKS(cd->type))
		return cd->u.luks1.hdr.keyBytes;

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.key_size;

	if (isVERITY(cd->type))
		return cd->u.verity.root_hash_size;

	if (isTCRYPT(cd->type))
		return cd->u.tcrypt.params.key_size;

	if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.key_size;

	return 0;
}

uint64_t crypt_get_data_offset(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->u.plain.hdr.offset;

	if (isLUKS(cd->type))
		return cd->u.luks1.hdr.payloadOffset;

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.hdr.offset;

	if (isTCRYPT(cd->type))
		return TCRYPT_get_data_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);

	return 0;
}

uint64_t crypt_get_iv_offset(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->u.plain.hdr.skip;

	if (isLUKS(cd->type))
		return 0;

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.hdr.skip;

	if (isTCRYPT(cd->type))
		return TCRYPT_get_iv_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);

	return 0;
}

crypt_keyslot_info crypt_keyslot_status(struct crypt_device *cd, int keyslot)
{
	if (onlyLUKS(cd) < 0)
		return CRYPT_SLOT_INVALID;

	return LUKS_keyslot_info(&cd->u.luks1.hdr, keyslot);
}

int crypt_keyslot_max(const char *type)
{
	if (type && isLUKS(type))
		return LUKS_NUMKEYS;

	return -EINVAL;
}

int crypt_keyslot_area(struct crypt_device *cd,
	int keyslot,
	uint64_t *offset,
	uint64_t *length)
{
	if (!isLUKS(cd->type))
		return -EINVAL;

	return LUKS_keyslot_area(&cd->u.luks1.hdr, keyslot, offset, length);
}

const char *crypt_get_type(struct crypt_device *cd)
{
	return cd->type;
}

int crypt_get_verity_info(struct crypt_device *cd,
	struct crypt_params_verity *vp)
{
	if (!isVERITY(cd->type) || !vp)
		return -EINVAL;

	vp->data_device = device_path(cd->device);
	vp->hash_device = mdata_device_path(cd);
	vp->hash_name = cd->u.verity.hdr.hash_name;
	vp->salt = cd->u.verity.hdr.salt;
	vp->salt_size = cd->u.verity.hdr.salt_size;
	vp->data_block_size = cd->u.verity.hdr.data_block_size;
	vp->hash_block_size = cd->u.verity.hdr.hash_block_size;
	vp->data_size = cd->u.verity.hdr.data_size;
	vp->hash_area_offset = cd->u.verity.hdr.hash_area_offset;
	vp->hash_type = cd->u.verity.hdr.hash_type;
	vp->flags = cd->u.verity.hdr.flags & CRYPT_VERITY_NO_HEADER;
	return 0;
}

int crypt_get_active_device(struct crypt_device *cd, const char *name,
			    struct crypt_active_device *cad)
{
	struct crypt_dm_active_device dmd;
	int r;

	r = dm_query_device(cd, name, 0, &dmd);
	if (r < 0)
		return r;

	if (dmd.target != DM_CRYPT && dmd.target != DM_VERITY)
		return -ENOTSUP;

	if (cd && isTCRYPT(cd->type)) {
		cad->offset	= TCRYPT_get_data_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);
		cad->iv_offset	= TCRYPT_get_iv_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);
	} else {
		cad->offset	= dmd.u.crypt.offset;
		cad->iv_offset	= dmd.u.crypt.iv_offset;
	}
	cad->size	= dmd.size;
	cad->flags	= dmd.flags;

	return 0;
}

static void __attribute__((constructor)) libcryptsetup_ctor(void)
{
	crypt_fips_libcryptsetup_check();
}
