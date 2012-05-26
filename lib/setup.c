/*
 * libcryptsetup - cryptsetup library
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
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>

#include "libcryptsetup.h"
#include "luks.h"
#include "loopaes.h"
#include "internal.h"

struct crypt_device {
	char *type;

	char *device;
	char *metadata_device;

	char *backing_file;
	int loop_fd;
	struct volume_key *volume_key;
	uint64_t timeout;
	uint64_t iteration_time;
	int tries;
	int password_verify;
	int rng_type;

	/* used in CRYPT_LUKS1 */
	struct luks_phdr hdr;
	uint64_t PBKDF2_per_sec;

	/* used in CRYPT_PLAIN */
	struct crypt_params_plain plain_hdr;
	char *plain_cipher;
	char *plain_cipher_mode;
	char *plain_uuid;
	unsigned int plain_key_size;

	/* used in CRYPT_LOOPAES */
	struct crypt_params_loopaes loopaes_hdr;
	char *loopaes_cipher;
	char *loopaes_cipher_mode;
	char *loopaes_uuid;
	unsigned int loopaes_key_size;

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

static const char *mdata_device(struct crypt_device *cd)
{
	return cd->metadata_device ?: cd->device;
}

static int init_crypto(struct crypt_device *ctx)
{
	int r;

	crypt_fips_libcryptsetup_check(ctx);

	r = crypt_random_init(ctx);
	if (r < 0) {
		log_err(ctx, _("Cannot initialize crypto RNG backend.\n"));
		return r;
	}

	r = crypt_backend_init(ctx);
	if (r < 0)
		log_err(ctx, _("Cannot initialize crypto backend.\n"));

	log_dbg("Crypto backend (%s) initialized.", crypt_backend_version());
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

/* keyslot helpers */
static int keyslot_verify_or_find_empty(struct crypt_device *cd, int *keyslot)
{
	if (*keyslot == CRYPT_ANY_SLOT) {
		*keyslot = LUKS_keyslot_find_empty(&cd->hdr);
		if (*keyslot < 0) {
			log_err(cd, _("All key slots full.\n"));
			return -EINVAL;
		}
	}

	switch (LUKS_keyslot_info(&cd->hdr, *keyslot)) {
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
		.device = crypt_get_device_name(cd),
		.cipher = NULL,
		.uuid   = crypt_get_uuid(cd),
		.vk    = vk,
		.offset = crypt_get_data_offset(cd),
		.iv_offset = crypt_get_iv_offset(cd),
		.size   = size,
		.flags  = flags
	};

	if (dmd.flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_SHARED;
	else
		device_check = DEV_EXCL;

	r = device_check_and_adjust(cd, dmd.device, device_check,
				    &dmd.size, &dmd.offset, &flags);
	if (r)
		return r;

	if (crypt_get_cipher_mode(cd))
		r = asprintf(&dm_cipher, "%s-%s", crypt_get_cipher(cd), crypt_get_cipher_mode(cd));
	else
		r = asprintf(&dm_cipher, "%s", crypt_get_cipher(cd));
	if (r < 0)
		return -ENOMEM;

	dmd.cipher = dm_cipher;
	log_dbg("Trying to activate PLAIN device %s using cipher %s.", name, dmd.cipher);

	r = dm_create_device(name, CRYPT_PLAIN, &dmd, 0);

	// FIXME
	if (!cd->plain_uuid && dm_query_device(name, DM_ACTIVE_UUID, &dmd) >= 0)
		cd->plain_uuid = CONST_CAST(char*)dmd.uuid;

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
	char *prompt = NULL;
	int r;

	*key = NULL;
	if(!msg && asprintf(&prompt, _("Enter passphrase for %s: "),
			    cd->backing_file ?: crypt_get_device_name(cd)) < 0)
		return -ENOMEM;

	if (!msg)
		msg = prompt;

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

		r = LUKS_open_key_with_hdr(mdata_device(cd), keyslot, passphrase_read,
					   passphrase_size_read, &cd->hdr, vk, cd);
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
	int r, readonly = 0;

	if (!cd)
		return -EINVAL;

	log_dbg("Allocating crypt device %s context.", device);

	if (!(h = malloc(sizeof(struct crypt_device))))
		return -ENOMEM;

	memset(h, 0, sizeof(*h));
	h->loop_fd = -1;

	if (device) {
		r = device_ready(NULL, device, O_RDONLY);
		if (r == -ENOTBLK) {
			h->device = crypt_loop_get_device();
			log_dbg("Not a block device, %s%s.",
				h->device ? "using free loop device " :
					 "no free loop device found",
				h->device ?: "");
			if (!h->device) {
				log_err(NULL, _("Cannot find a free loopback device.\n"));
				r = -ENOSYS;
				goto bad;
			}

			/* Keep the loop open, dettached on last close. */
			h->loop_fd = crypt_loop_attach(h->device, device, 0, 1, &readonly);
			if (h->loop_fd == -1) {
				log_err(NULL, _("Attaching loopback device failed "
					"(loop device with autoclear flag is required).\n"));
				r = -EINVAL;
				goto bad;
			}

			h->backing_file = crypt_loop_backing_file(h->device);
			r = device_ready(NULL, h->device, O_RDONLY);
		}
		if (r < 0) {
			r = -ENOTBLK;
			goto bad;
		}
	}

	if (!h->device && device && !(h->device = strdup(device))) {
		r = -ENOMEM;
		goto bad;
	}

	if (dm_init(h, 1) < 0) {
		r = -ENOSYS;
		goto bad;
	}

	h->iteration_time = 1000;
	h->password_verify = 0;
	h->tries = 3;
	h->rng_type = crypt_random_default_key_rng();
	*cd = h;
	return 0;
bad:

	if (h) {
		if (h->loop_fd != -1)
			close(h->loop_fd);
		free(h->device);
		free(h->backing_file);
	}
	free(h);
	return r;
}

static int crypt_check_data_device_size(struct crypt_device *cd)
{
	int r;
	uint64_t size, size_min;

	/* Check data device size, require at least one sector */
	size_min = crypt_get_data_offset(cd) << SECTOR_SHIFT ?: SECTOR_SIZE;

	r = device_size(crypt_get_device_name(cd), &size);
	if (r < 0)
		return r;

	if (size < size_min) {
		log_err(cd, _("LUKS header detected but device %s is too small.\n"),
			crypt_get_device_name(cd));
		return -EINVAL;
	}

	return r;
}

int crypt_set_data_device(struct crypt_device *cd, const char *device)
{
	char *data_device;
	int r;

	log_dbg("Setting ciphertext data device to %s.", device ?: "(none)");

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is not supported for this device type.\n"));
		return  -EINVAL;
	}

	/* metadata device must be set */
	if (!cd->device || !device)
		return -EINVAL;

	r = device_ready(NULL, device, O_RDONLY);
	if (r < 0)
		return r;

	if (!(data_device = strdup(device)))
		return -ENOMEM;

	if (!cd->metadata_device)
		cd->metadata_device = cd->device;
	else
		free(cd->device);

	cd->device = data_device;

	return crypt_check_data_device_size(cd);
}

static int _crypt_load_luks1(struct crypt_device *cd, int require_header, int repair)
{
	struct luks_phdr hdr;
	int r;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = LUKS_read_phdr(mdata_device(cd), &hdr, require_header, repair, cd);
	if (r < 0)
		return r;

	if (!cd->type && !(cd->type = strdup(CRYPT_LUKS1)))
		return -ENOMEM;

	memcpy(&cd->hdr, &hdr, sizeof(hdr));

	return r;
}

int crypt_init_by_name_and_header(struct crypt_device **cd,
				  const char *name,
				  const char *header_device)
{
	crypt_status_info ci;
	struct crypt_dm_active_device dmd;
	char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	int key_nums, r;


	log_dbg("Allocating crypt device context by device %s.", name);

	ci = crypt_status(NULL, name);
	if (ci == CRYPT_INVALID)
		return -ENODEV;

	if (ci < CRYPT_ACTIVE) {
		log_err(NULL, _("Device %s is not active.\n"), name);
		return -ENODEV;
	}

	r = dm_query_device(name, DM_ACTIVE_DEVICE | DM_ACTIVE_CIPHER |
				  DM_ACTIVE_UUID | DM_ACTIVE_KEYSIZE, &dmd);
	if (r < 0)
		goto out;

	*cd = NULL;

	if (header_device) {
		r = crypt_init(cd, header_device);
	} else {
		r = crypt_init(cd, dmd.device);

		/* Underlying device disappeared but mapping still active */
		if (!dmd.device || r == -ENOTBLK)
			log_verbose(NULL, _("Underlying device for crypt device %s disappeared.\n"),
				    name);

		/* Underlying device is not readable but crypt mapping exists */
		if (r == -ENOTBLK) {
			free(CONST_CAST(void*)dmd.device);
			dmd.device = NULL;
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
		else
			log_dbg("Unknown UUID set, some parameters are not set.");
	} else
		log_dbg("Active device has no UUID set, some parameters are not set.");

	if (header_device) {
		r = crypt_set_data_device(*cd, dmd.device);
		if (r < 0)
			goto out;
	}

	/* Try to initialise basic parameters from active device */

	if (!(*cd)->backing_file && dmd.device && crypt_loop_device(dmd.device) &&
	    !((*cd)->backing_file = crypt_loop_backing_file(dmd.device))) {
		r = -ENOMEM;
		goto out;
	}

	if (isPLAIN((*cd)->type)) {
		(*cd)->plain_uuid = dmd.uuid ? strdup(dmd.uuid) : NULL;
		(*cd)->plain_hdr.hash = NULL; /* no way to get this */
		(*cd)->plain_hdr.offset = dmd.offset;
		(*cd)->plain_hdr.skip = dmd.iv_offset;
		(*cd)->plain_key_size = dmd.vk->keylength;

		r = crypt_parse_name_and_mode(dmd.cipher, cipher, NULL, cipher_mode);
		if (!r) {
			(*cd)->plain_cipher = strdup(cipher);
			(*cd)->plain_cipher_mode = strdup(cipher_mode);
		}
	} else if (isLOOPAES((*cd)->type)) {
		(*cd)->loopaes_uuid = dmd.uuid ? strdup(dmd.uuid) : NULL;
		(*cd)->loopaes_hdr.offset = dmd.offset;

		r = crypt_parse_name_and_mode(dmd.cipher, cipher,
					      &key_nums, cipher_mode);
		if (!r) {
			(*cd)->loopaes_cipher = strdup(cipher);
			(*cd)->loopaes_cipher_mode = strdup(cipher_mode);
			/* version 3 uses last key for IV */
			if (dmd.vk->keylength % key_nums)
				key_nums++;
			(*cd)->loopaes_key_size = dmd.vk->keylength / key_nums;
		}
	} else if (isLUKS((*cd)->type)) {
		if (mdata_device(*cd)) {
			r = _crypt_load_luks1(*cd, 0, 0);
			if (r < 0) {
				log_dbg("LUKS device header does not match active device.");
				free((*cd)->type);
				(*cd)->type = NULL;
				r = 0;
				goto out;
			}
			/* checks whether UUIDs match each other */
			r = crypt_uuid_cmp(dmd.uuid, (*cd)->hdr.uuid);
			if (r < 0) {
				log_dbg("LUKS device header uuid: %s mismatches DM returned uuid %s",
					(*cd)->hdr.uuid, dmd.uuid);
				free((*cd)->type);
				(*cd)->type = NULL;
				r = 0;
				goto out;
			}
		}
	}

out:
	if (r < 0) {
		crypt_free(*cd);
		*cd = NULL;
	}
	crypt_free_volume_key(dmd.vk);
	free(CONST_CAST(void*)dmd.device);
	free(CONST_CAST(void*)dmd.cipher);
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

	cd->plain_key_size = volume_key_size;
	cd->volume_key = crypt_alloc_volume_key(volume_key_size, NULL);
	if (!cd->volume_key)
		return -ENOMEM;

	cd->plain_cipher = strdup(cipher);
	cd->plain_cipher_mode = strdup(cipher_mode);

	if (uuid)
		cd->plain_uuid = strdup(uuid);

	if (params && params->hash)
		cd->plain_hdr.hash = strdup(params->hash);

	cd->plain_hdr.offset = params ? params->offset : 0;
	cd->plain_hdr.skip = params ? params->skip : 0;
	cd->plain_hdr.size = params ? params->size : 0;

	if (!cd->plain_cipher || !cd->plain_cipher_mode)
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

	if (!mdata_device(cd)) {
		log_err(cd, _("Can't format LUKS without device.\n"));
		return -EINVAL;
	}

	if (volume_key)
		cd->volume_key = crypt_alloc_volume_key(volume_key_size,
						      volume_key);
	else
		cd->volume_key = crypt_generate_volume_key(cd, volume_key_size);

	if(!cd->volume_key)
		return -ENOMEM;

	if (params && params->data_device) {
		cd->metadata_device = cd->device;
		if (!(cd->device = strdup(params->data_device)))
			return -ENOMEM;
		required_alignment = params->data_alignment * SECTOR_SIZE;
	} else if (params && params->data_alignment) {
		required_alignment = params->data_alignment * SECTOR_SIZE;
	} else
		get_topology_alignment(cd->device, &required_alignment,
				       &alignment_offset, DEFAULT_DISK_ALIGNMENT);

	r = LUKS_generate_phdr(&cd->hdr, cd->volume_key, cipher, cipher_mode,
			       (params && params->hash) ? params->hash : "sha1",
			       uuid, LUKS_STRIPES,
			       required_alignment / SECTOR_SIZE,
			       alignment_offset / SECTOR_SIZE,
			       cd->iteration_time, &cd->PBKDF2_per_sec,
			       cd->metadata_device, cd);
	if(r < 0)
		return r;

	/* Wipe first 8 sectors - fs magic numbers etc. */
	r = crypt_wipe(mdata_device(cd), 0, 8 * SECTOR_SIZE, CRYPT_WIPE_ZERO, 1);
	if(r < 0) {
		if (r == -EBUSY)
			log_err(cd, _("Cannot format device %s which is still in use.\n"),
				mdata_device(cd));
		else
			log_err(cd, _("Cannot wipe header on device %s.\n"),
				mdata_device(cd));

		return r;
	}

	r = LUKS_write_phdr(mdata_device(cd), &cd->hdr, cd);

	return r;
}

static int _crypt_format_loopaes(struct crypt_device *cd,
				 const char *cipher,
				 const char *uuid,
				 size_t volume_key_size,
				 struct crypt_params_loopaes *params)
{
	if (!mdata_device(cd)) {
		log_err(cd, _("Can't format LOOPAES without device.\n"));
		return -EINVAL;
	}

	if (volume_key_size > 1024) {
		log_err(cd, _("Invalid key size.\n"));
		return -EINVAL;
	}

	cd->loopaes_key_size = volume_key_size;

	cd->loopaes_cipher = strdup(cipher ?: DEFAULT_LOOPAES_CIPHER);

	if (uuid)
		cd->loopaes_uuid = strdup(uuid);

	if (params && params->hash)
		cd->loopaes_hdr.hash = strdup(params->hash);

	cd->loopaes_hdr.offset = params ? params->offset : 0;
	cd->loopaes_hdr.skip = params ? params->skip : 0;

	return 0;
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

	log_dbg("Formatting device %s as type %s.", mdata_device(cd) ?: "(none)", type);

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
	else {
		/* FIXME: allow plugins here? */
		log_err(cd, _("Unknown crypt device type %s requested.\n"), type);
		r = -EINVAL;
	}

	if (!r && !(cd->type = strdup(type)))
		r = -ENOMEM;

	if (r < 0) {
		crypt_free_volume_key(cd->volume_key);
		cd->volume_key = NULL;
	}

	return r;
}

int crypt_load(struct crypt_device *cd,
	       const char *requested_type,
	       void *params __attribute__((unused)))
{
	int r;

	log_dbg("Trying to load %s crypt type from device %s.",
		requested_type ?: "any", mdata_device(cd) ?: "(none)");

	if (!mdata_device(cd))
		return -EINVAL;

	if (requested_type && !isLUKS(requested_type))
		return -EINVAL;

	if (cd->type && !isLUKS(cd->type)) {
		log_dbg("Context is already initialised to type %s", cd->type);
		return -EINVAL;
	}

	r = _crypt_load_luks1(cd, 1, 0);
	if (r < 0)
		return r;

	/* cd->type and header must be set in context */
	r = crypt_check_data_device_size(cd);
	if (r < 0) {
		free(cd->type);
		cd->type = NULL;
	}

	return r;
}

int crypt_repair(struct crypt_device *cd,
		 const char *requested_type,
		 void *params __attribute__((unused)))
{
	int r;

	log_dbg("Trying to repair %s crypt type from device %s.",
		requested_type ?: "any", mdata_device(cd) ?: "(none)");

	if (!mdata_device(cd))
		return -EINVAL;

	if (requested_type && !isLUKS(requested_type))
		return -EINVAL;


	/* Load with repair */
	r = _crypt_load_luks1(cd, 1, 1);
	if (r < 0)
		return r;

	/* cd->type and header must be set in context */
	r = crypt_check_data_device_size(cd);
	if (r < 0) {
		free(cd->type);
		cd->type = NULL;
	}

	return r;
}

int crypt_resize(struct crypt_device *cd, const char *name, uint64_t new_size)
{
	struct crypt_dm_active_device dmd;
	int r;

	/* Device context type must be initialised */
	if (!cd->type || !crypt_get_uuid(cd))
		return -EINVAL;

	log_dbg("Resizing device %s to %" PRIu64 " sectors.", name, new_size);

	r = dm_query_device(name, DM_ACTIVE_DEVICE | DM_ACTIVE_CIPHER |
				  DM_ACTIVE_UUID | DM_ACTIVE_KEYSIZE |
				  DM_ACTIVE_KEY, &dmd);
	if (r < 0) {
		log_err(NULL, _("Device %s is not active.\n"), name);
		goto out;
	}

	if (!dmd.uuid) {
		r = -EINVAL;
		goto out;
	}

	r = device_check_and_adjust(cd, dmd.device, DEV_OK, &new_size, &dmd.offset, &dmd.flags);
	if (r)
		goto out;

	if (new_size == dmd.size) {
		log_dbg("Device has already requested size %" PRIu64
			" sectors.", dmd.size);
		r = 0;
	} else {
		dmd.size = new_size;
		r = dm_create_device(name, cd->type, &dmd, 1);
	}
out:
	crypt_free_volume_key(dmd.vk);
	free(CONST_CAST(void*)dmd.cipher);
	free(CONST_CAST(void*)dmd.device);
	free(CONST_CAST(void*)dmd.uuid);

	return r;
}

int crypt_set_uuid(struct crypt_device *cd, const char *uuid)
{
	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is not supported for this device type.\n"));
		return  -EINVAL;
	}

	if (uuid && !strncmp(uuid, cd->hdr.uuid, sizeof(cd->hdr.uuid))) {
		log_dbg("UUID is the same as requested (%s) for device %s.",
			uuid, mdata_device(cd));
		return 0;
	}

	if (uuid)
		log_dbg("Requested new UUID change to %s for %s.", uuid, mdata_device(cd));
	else
		log_dbg("Requested new UUID refresh for %s.", mdata_device(cd));

	if (!crypt_confirm(cd, _("Do you really want to change UUID of device?")))
		return -EPERM;

	return LUKS_hdr_uuid_set(mdata_device(cd), &cd->hdr, uuid, cd);
}

int crypt_header_backup(struct crypt_device *cd,
			const char *requested_type,
			const char *backup_file)
{
	int r;

	if ((requested_type && !isLUKS(requested_type)) || !backup_file)
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	log_dbg("Requested header backup of device %s (%s) to "
		"file %s.", mdata_device(cd), requested_type, backup_file);

	return LUKS_hdr_backup(backup_file, mdata_device(cd), &cd->hdr, cd);
}

int crypt_header_restore(struct crypt_device *cd,
			 const char *requested_type,
			 const char *backup_file)
{
	int r;

	if (requested_type && !isLUKS(requested_type))
		return -EINVAL;

	/* Some hash functions need initialized gcrypt library */
	r = init_crypto(cd);
	if (r < 0)
		return r;

	log_dbg("Requested header restore to device %s (%s) from "
		"file %s.", mdata_device(cd), requested_type, backup_file);

	return LUKS_hdr_restore(backup_file, mdata_device(cd), &cd->hdr, cd);
}

void crypt_free(struct crypt_device *cd)
{
	if (cd) {
		log_dbg("Releasing crypt device %s context.", mdata_device(cd));

		if (cd->loop_fd != -1)
			close(cd->loop_fd);

		dm_exit();
		crypt_free_volume_key(cd->volume_key);

		free(cd->device);
		free(cd->metadata_device);
		free(cd->backing_file);
		free(cd->type);

		/* used in plain device only */
		free(CONST_CAST(void*)cd->plain_hdr.hash);
		free(cd->plain_cipher);
		free(cd->plain_cipher_mode);
		free(cd->plain_uuid);

		/* used in loop-AES device only */
		free(CONST_CAST(void*)cd->loopaes_hdr.hash);
		free(cd->loopaes_cipher);
		free(cd->loopaes_uuid);

		free(cd);
	}
}

int crypt_suspend(struct crypt_device *cd,
		  const char *name)
{
	crypt_status_info ci;
	int r;

	log_dbg("Suspending volume %s.", name);

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		r = -EINVAL;
		goto out;
	}

	ci = crypt_status(NULL, name);
	if (ci < CRYPT_ACTIVE) {
		log_err(cd, _("Volume %s is not active.\n"), name);
		return -EINVAL;
	}

	if (!cd && dm_init(NULL, 1) < 0)
		return -ENOSYS;

	r = dm_status_suspended(name);
	if (r < 0)
		goto out;

	if (r) {
		log_err(cd, _("Volume %s is already suspended.\n"), name);
		r = -EINVAL;
		goto out;
	}

	r = dm_suspend_and_wipe_key(name);
	if (r == -ENOTSUP)
		log_err(cd, "Suspend is not supported for device %s.\n", name);
	else if (r)
		log_err(cd, "Error during suspending device %s.\n", name);
out:
	if (!cd)
		dm_exit();
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

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		r = -EINVAL;
		goto out;
	}

	r = dm_status_suspended(name);
	if (r < 0)
		return r;

	if (!r) {
		log_err(cd, _("Volume %s is not suspended.\n"), name);
		return -EINVAL;
	}

	if (passphrase) {
		r = LUKS_open_key_with_hdr(mdata_device(cd), keyslot, passphrase,
					   passphrase_size, &cd->hdr, &vk, cd);
	} else
		r = volume_key_by_terminal_passphrase(cd, keyslot, &vk);

	if (r >= 0) {
		keyslot = r;
		r = dm_resume_and_reinstate_key(name, vk->keylength, vk->key);
		if (r == -ENOTSUP)
			log_err(cd, "Resume is not supported for device %s.\n", name);
		else if (r)
			log_err(cd, "Error during resuming device %s.\n", name);
	} else
		r = keyslot;
out:
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

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		r = -EINVAL;
		goto out;
	}

	r = dm_status_suspended(name);
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

	r = LUKS_open_key_with_hdr(mdata_device(cd), keyslot, passphrase_read,
				   passphrase_size_read, &cd->hdr, &vk, cd);
	if (r < 0)
		goto out;

	keyslot = r;
	r = dm_resume_and_reinstate_key(name, vk->keylength, vk->key);
	if (r)
		log_err(cd, "Error during resuming device %s.\n", name);
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

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		return -EINVAL;
	}

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r)
		return r;

	if (!LUKS_keyslot_active_count(&cd->hdr)) {
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
		r = LUKS_open_key_with_hdr(mdata_device(cd), CRYPT_ANY_SLOT, passphrase,
					   passphrase_size, &cd->hdr, &vk, cd);
	} else {
		/* Passphrase not provided, ask first and use it to unlock existing keyslot */
		r = key_from_terminal(cd, _("Enter any passphrase: "),
				      &password, &passwordLen, 0);
		if (r < 0)
			goto out;

		r = LUKS_open_key_with_hdr(mdata_device(cd), CRYPT_ANY_SLOT, password,
					   passwordLen, &cd->hdr, &vk, cd);
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

	r = LUKS_set_key(mdata_device(cd), keyslot, new_password, new_passwordLen,
			 &cd->hdr, vk, cd->iteration_time, &cd->PBKDF2_per_sec, cd);
	if(r < 0) goto out;

	r = 0;
out:
	if (!new_passphrase)
		crypt_safe_free(new_password);
	crypt_free_volume_key(vk);
	return r ?: keyslot;
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

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		return -EINVAL;
	}

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r)
		return r;

	if (!LUKS_keyslot_active_count(&cd->hdr)) {
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

		r = LUKS_open_key_with_hdr(mdata_device(cd), CRYPT_ANY_SLOT, password, passwordLen,
					   &cd->hdr, &vk, cd);
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

	r = LUKS_set_key(mdata_device(cd), keyslot, new_password, new_passwordLen,
			 &cd->hdr, vk, cd->iteration_time, &cd->PBKDF2_per_sec, cd);
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
	int r = -EINVAL;
	char *new_password = NULL; size_t new_passwordLen;

	log_dbg("Adding new keyslot %d using volume key.", keyslot);

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		return -EINVAL;
	}

	if (volume_key)
		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	else if (cd->volume_key)
		vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);

	if (!vk)
		return -ENOMEM;

	r = LUKS_verify_volume_key(&cd->hdr, vk);
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

	r = LUKS_set_key(mdata_device(cd), keyslot, passphrase, passphrase_size,
			 &cd->hdr, vk, cd->iteration_time, &cd->PBKDF2_per_sec, cd);
out:
	crypt_safe_free(new_password);
	crypt_free_volume_key(vk);
	return (r < 0) ? r : keyslot;
}

int crypt_keyslot_destroy(struct crypt_device *cd, int keyslot)
{
	crypt_keyslot_info ki;

	log_dbg("Destroying keyslot %d.", keyslot);

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		return -EINVAL;
	}

	ki = crypt_keyslot_status(cd, keyslot);
	if (ki == CRYPT_SLOT_INVALID) {
		log_err(cd, _("Key slot %d is invalid.\n"), keyslot);
		return -EINVAL;
	}

	if (ki == CRYPT_SLOT_INACTIVE) {
		log_err(cd, _("Key slot %d is not used.\n"), keyslot);
		return -EINVAL;
	}

	return LUKS_del_key(mdata_device(cd), keyslot, &cd->hdr, cd);
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

		r = process_key(cd, cd->plain_hdr.hash,
				cd->plain_key_size,
				passphrase, passphrase_size, &vk);
		if (r < 0)
			goto out;

		r = PLAIN_activate(cd, name, vk, cd->plain_hdr.size, flags);
		keyslot = 0;
	} else if (isLUKS(cd->type)) {
		/* provided passphrase, do not retry */
		if (passphrase) {
			r = LUKS_open_key_with_hdr(mdata_device(cd), keyslot, passphrase,
						   passphrase_size, &cd->hdr, &vk, cd);
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

		r = process_key(cd, cd->plain_hdr.hash,
				cd->plain_key_size,
				passphrase_read, passphrase_size_read, &vk);
		if (r < 0)
			goto out;

		r = PLAIN_activate(cd, name, vk, cd->plain_hdr.size, flags);
	} else if (isLUKS(cd->type)) {
		r = key_from_file(cd, _("Enter passphrase: "), &passphrase_read,
			  &passphrase_size_read, keyfile, keyfile_offset, keyfile_size);
		if (r < 0)
			goto out;
		r = LUKS_open_key_with_hdr(mdata_device(cd), keyslot, passphrase_read,
					   passphrase_size_read, &cd->hdr, &vk, cd);
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
		r = LOOPAES_parse_keyfile(cd, &vk, cd->loopaes_hdr.hash, &key_count,
					  passphrase_read, passphrase_size_read);
		if (r < 0)
			goto out;
		if (name)
			r = LOOPAES_activate(cd, name, cd->loopaes_cipher,
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

	log_dbg("Activating volume %s by volume key.", name);

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

		if (!volume_key || !volume_key_size || volume_key_size != cd->plain_key_size) {
			log_err(cd, _("Incorrect volume key specified for plain device.\n"));
			return -EINVAL;
		}

		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
		if (!vk)
			return -ENOMEM;

		r = PLAIN_activate(cd, name, vk, cd->plain_hdr.size, flags);
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
		r = LUKS_verify_volume_key(&cd->hdr, vk);

		if (r == -EPERM)
			log_err(cd, _("Volume key does not match the volume.\n"));

		if (!r && name)
			r = LUKS1_activate(cd, name, vk, flags);
	} else
		log_err(cd, _("Device type is not properly initialised.\n"));

	crypt_free_volume_key(vk);

	return r;
}

int crypt_deactivate(struct crypt_device *cd, const char *name)
{
	int r;

	if (!name)
		return -EINVAL;

	log_dbg("Deactivating volume %s.", name);

	if (!cd && dm_init(NULL, 1) < 0)
		return -ENOSYS;

	switch (crypt_status(cd, name)) {
		case CRYPT_ACTIVE:
		case CRYPT_BUSY:
			r = dm_remove_device(name, 0, 0);
			break;
		case CRYPT_INACTIVE:
			log_err(cd, _("Device %s is not active.\n"), name);
			r = -ENODEV;
			break;
		default:
			log_err(cd, _("Invalid device %s.\n"), name);
			r = -EINVAL;
	}

	if (!cd)
		dm_exit();

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
		log_err(cd, "Function not available in FIPS mode.\n");
		return -EACCES;
	}

	key_len = crypt_get_volume_key_size(cd);
	if (key_len > *volume_key_size) {
		log_err(cd, _("Volume key buffer too small.\n"));
		return -ENOMEM;
	}

	if (isPLAIN(cd->type) && cd->plain_hdr.hash) {
		r = process_key(cd, cd->plain_hdr.hash, key_len,
				passphrase, passphrase_size, &vk);
		if (r < 0)
			log_err(cd, _("Cannot retrieve volume key for plain device.\n"));
	} else if (isLUKS(cd->type)) {
		r = LUKS_open_key_with_hdr(mdata_device(cd), keyslot, passphrase,
					passphrase_size, &cd->hdr, &vk, cd);

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

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		return -EINVAL;
	}

	vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	if (!vk)
		return -ENOMEM;

	r = LUKS_verify_volume_key(&cd->hdr, vk);

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

	if (!cd && dm_init(NULL, 1) < 0)
		return CRYPT_INVALID;

	r = dm_status_device(name);

	if (!cd)
		dm_exit();

	if (r < 0 && r != -ENODEV)
		return CRYPT_INVALID;

	if (r == 0)
		return CRYPT_ACTIVE;

	if (r > 0)
		return CRYPT_BUSY;

	return CRYPT_INACTIVE;
}

static void hexprintICB(struct crypt_device *cd, char *d, int n)
{
	int i;
	for(i = 0; i < n; i++)
		log_std(cd, "%02hhx ", (char)d[i]);
}

int crypt_dump(struct crypt_device *cd)
{
	int i;
	if (!isLUKS(cd->type)) { //FIXME
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		return -EINVAL;
	}

	log_std(cd, "LUKS header information for %s\n\n", mdata_device(cd));
	log_std(cd, "Version:       \t%d\n", cd->hdr.version);
	log_std(cd, "Cipher name:   \t%s\n", cd->hdr.cipherName);
	log_std(cd, "Cipher mode:   \t%s\n", cd->hdr.cipherMode);
	log_std(cd, "Hash spec:     \t%s\n", cd->hdr.hashSpec);
	log_std(cd, "Payload offset:\t%d\n", cd->hdr.payloadOffset);
	log_std(cd, "MK bits:       \t%d\n", cd->hdr.keyBytes * 8);
	log_std(cd, "MK digest:     \t");
	hexprintICB(cd, cd->hdr.mkDigest, LUKS_DIGESTSIZE);
	log_std(cd, "\n");
	log_std(cd, "MK salt:       \t");
	hexprintICB(cd, cd->hdr.mkDigestSalt, LUKS_SALTSIZE/2);
	log_std(cd, "\n               \t");
	hexprintICB(cd, cd->hdr.mkDigestSalt+LUKS_SALTSIZE/2, LUKS_SALTSIZE/2);
	log_std(cd, "\n");
	log_std(cd, "MK iterations: \t%d\n", cd->hdr.mkDigestIterations);
	log_std(cd, "UUID:          \t%s\n\n", cd->hdr.uuid);
	for(i = 0; i < LUKS_NUMKEYS; i++) {
		if(cd->hdr.keyblock[i].active == LUKS_KEY_ENABLED) {
			log_std(cd, "Key Slot %d: ENABLED\n",i);
			log_std(cd, "\tIterations:         \t%d\n",
				cd->hdr.keyblock[i].passwordIterations);
			log_std(cd, "\tSalt:               \t");
			hexprintICB(cd, cd->hdr.keyblock[i].passwordSalt,
				    LUKS_SALTSIZE/2);
			log_std(cd, "\n\t                      \t");
			hexprintICB(cd, cd->hdr.keyblock[i].passwordSalt +
				    LUKS_SALTSIZE/2, LUKS_SALTSIZE/2);
			log_std(cd, "\n");

			log_std(cd, "\tKey material offset:\t%d\n",
				cd->hdr.keyblock[i].keyMaterialOffset);
			log_std(cd, "\tAF stripes:            \t%d\n",
				cd->hdr.keyblock[i].stripes);
		}
		else 
			log_std(cd, "Key Slot %d: DISABLED\n", i);
	}

	return 0;
}

const char *crypt_get_cipher(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->plain_cipher;

	if (isLUKS(cd->type))
		return cd->hdr.cipherName;

	if (isLOOPAES(cd->type))
		return cd->loopaes_cipher;

	return NULL;
}

const char *crypt_get_cipher_mode(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->plain_cipher_mode;

	if (isLUKS(cd->type))
		return cd->hdr.cipherMode;

	if (isLOOPAES(cd->type))
		return cd->loopaes_cipher_mode;

	return NULL;
}

const char *crypt_get_uuid(struct crypt_device *cd)
{
	if (isLUKS(cd->type))
		return cd->hdr.uuid;

	if (isPLAIN(cd->type))
		return cd->plain_uuid;

	if (isLOOPAES(cd->type))
		return cd->loopaes_uuid;

	return NULL;
}

const char *crypt_get_device_name(struct crypt_device *cd)
{
	return cd->device;
}


int crypt_get_volume_key_size(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->plain_key_size;

	if (isLUKS(cd->type))
		return cd->hdr.keyBytes;

	if (isLOOPAES(cd->type))
		return cd->loopaes_key_size;

	return 0;
}

uint64_t crypt_get_data_offset(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->plain_hdr.offset;

	if (isLUKS(cd->type))
		return cd->hdr.payloadOffset;

	if (isLOOPAES(cd->type))
		return cd->loopaes_hdr.offset;

	return 0;
}

uint64_t crypt_get_iv_offset(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->plain_hdr.skip;

	if (isLUKS(cd->type))
		return 0;

	if (isLOOPAES(cd->type))
		return cd->loopaes_hdr.skip;

	return 0;
}

crypt_keyslot_info crypt_keyslot_status(struct crypt_device *cd, int keyslot)
{
	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		return CRYPT_SLOT_INVALID;
	}

	return LUKS_keyslot_info(&cd->hdr, keyslot);
}

int crypt_keyslot_max(const char *type)
{
	if (type && isLUKS(type))
		return LUKS_NUMKEYS;

	return -EINVAL;
}

const char *crypt_get_type(struct crypt_device *cd)
{
	return cd->type;
}

int crypt_get_active_device(struct crypt_device *cd __attribute__((unused)),
			    const char *name,
			    struct crypt_active_device *cad)
{
	struct crypt_dm_active_device dmd;
	int r;

	r = dm_query_device(name, 0, &dmd);
	if (r < 0)
		return r;

	cad->offset	= dmd.offset;
	cad->iv_offset	= dmd.iv_offset;
	cad->size	= dmd.size;
	cad->flags	= dmd.flags;

	return 0;
}
