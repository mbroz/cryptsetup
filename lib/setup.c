/*
 * libcryptsetup - cryptsetup library
 *
 * Copyright (C) 2004, Christophe Saout <christophe@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2011, Red Hat, Inc. All rights reserved.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
#include "crypto_backend.h"

struct crypt_device {
	char *type;

	char *device;
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
};

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

void crypt_log(struct crypt_device *cd, int level, const char *msg)
{
	if (cd && cd->log)
		cd->log(level, msg, cd->log_usrptr);
	else if (_default_log)
		_default_log(level, msg, NULL);
}

__attribute__((format(printf, 5, 6)))
void logger(struct crypt_device *cd, int level, const char *file,
	    int line, const char *format, ...)
{
	va_list argp;
	char *target = NULL;

	va_start(argp, format);

	if (vasprintf(&target, format, argp) > 0) {
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

static int init_crypto(struct crypt_device *ctx)
{
	int r;

	r = crypt_random_init(ctx);
	if (r < 0) {
		log_err(ctx, _("Cannot initialize crypto RNG backend.\n"));
		return r;
	}

	r = crypt_backend_init(ctx);
	if (r < 0)
		log_err(ctx, _("Cannot initialize crypto backend.\n"));

	return r;
}

/*
 * Password processing behaviour matrix of process_key
 *
 * from binary file: check if there is sufficently large key material
 * interactive & from fd: hash if requested, otherwise crop or pad with '0'
 */
static char *process_key(struct crypt_device *cd, const char *hash_name,
			 const char *key_file, size_t key_size,
			 const char *pass, size_t passLen)
{
	char *key;
	int r;

	if (!key_size)
		return NULL;

	key = crypt_safe_alloc(key_size);
	if (!key)
		return NULL;
	memset(key, 0, key_size);

	/* key is coming from binary file */
	if (key_file && strcmp(key_file, "-")) {
		if(passLen < key_size) {
			log_err(cd, ngettext("Cannot read %d byte from key file %s.\n",
				"Cannot read %d bytes from key file %s.\n", key_size),
				(int)key_size, key_file);
			crypt_safe_free(key);
			return NULL;
		}
		memcpy(key, pass, key_size);
		return key;
	}

	/* key is coming from tty, fd or binary stdin */
	if (hash_name) {
		r = crypt_plain_hash(cd, hash_name, key, key_size, pass, passLen);
		if (r < 0) {
			if (r == -ENOENT)
				log_err(cd, _("Hash algorithm %s not supported.\n"),
					hash_name);
			else
				log_err(cd, _("Key processing error (using hash %s).\n"),
					hash_name);
			crypt_safe_free(key);
			return NULL;
		}
	} else if (passLen > key_size) {
		memcpy(key, pass, key_size);
	} else {
		memcpy(key, pass, passLen);
	}

	return key;
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

static int verify_other_keyslot(struct crypt_device *cd,
				const char *key_file,
				int keyIndex)
{
	struct volume_key *vk = NULL;
	crypt_keyslot_info ki;
	int openedIndex, r;
	char *password = NULL;
	size_t passwordLen;

	r = crypt_get_key(_("Enter any remaining LUKS passphrase: "),
			  &password, &passwordLen, 0, key_file, cd->timeout,
			  cd->password_verify, cd);
	if(r < 0)
		goto out;

	ki = crypt_keyslot_status(cd, keyIndex);
	if (ki == CRYPT_SLOT_ACTIVE) /* Not last slot */
		LUKS_keyslot_set(&cd->hdr, keyIndex, 0);

	openedIndex = LUKS_open_key_with_hdr(cd->device, CRYPT_ANY_SLOT,
					     password, passwordLen,
					     &cd->hdr, &vk, cd);

	if (ki == CRYPT_SLOT_ACTIVE)
		LUKS_keyslot_set(&cd->hdr, keyIndex, 1);

	if (openedIndex < 0)
		r = -EPERM;
	else
		log_verbose(cd, _("Key slot %d verified.\n"), openedIndex);
out:
	crypt_free_volume_key(vk);
	crypt_safe_free(password);
	return r;
}

static int find_keyslot_by_passphrase(struct crypt_device *cd,
				      const char *key_file,
				      char *message)
{
	struct volume_key *vk = NULL;
	char *password = NULL;
	size_t passwordLen;
	int r;

	r = crypt_get_key(message,&password,&passwordLen, 0, key_file,
			  cd->timeout, cd->password_verify, cd);
	if (r < 0)
		goto out;

	r = LUKS_open_key_with_hdr(cd->device, CRYPT_ANY_SLOT, password,
				   passwordLen, &cd->hdr, &vk, cd);
out:
	crypt_free_volume_key(vk);
	crypt_safe_free(password);
	return r;
}

static int luks_remove_helper(struct crypt_device *cd,
			      int key_slot,
			      const char *other_key_file,
			      const char *key_file,
			      int verify)
{
	crypt_keyslot_info ki;
	int r = -EINVAL;

	if (key_slot == CRYPT_ANY_SLOT) {
		key_slot = find_keyslot_by_passphrase(cd, key_file,
				_("Enter LUKS passphrase to be deleted: "));
		if(key_slot < 0) {
			r = -EPERM;
			goto out;
		}

		log_std(cd, _("Key slot %d selected for deletion.\n"), key_slot);
	}

	ki = crypt_keyslot_status(cd, key_slot);
	if (ki == CRYPT_SLOT_INVALID) {
		log_err(cd, _("Key slot %d is invalid, please select between 0 and %d.\n"),
			key_slot, LUKS_NUMKEYS - 1);
		r = -EINVAL;
		goto out;
	}
	if (ki <= CRYPT_SLOT_INACTIVE) {
		log_err(cd, _("Key %d not active. Can't wipe.\n"), key_slot);
		r = -EINVAL;
		goto out;
	}

	if (ki == CRYPT_SLOT_ACTIVE_LAST && cd->confirm &&
	    !(cd->confirm(_("This is the last keyslot."
			    " Device will become unusable after purging this key."),
			 cd->confirm_usrptr))) {
		r = -EINVAL;
		goto out;
	}

	if(verify)
		r = verify_other_keyslot(cd, other_key_file, key_slot);
	else
		r = 0;

	if (!r)
		r = crypt_keyslot_destroy(cd, key_slot);
out:
	return (r < 0) ? r : 0;
}

static int create_device_helper(struct crypt_device *cd,
				const char *name,
				const char *hash,
				const char *cipher,
				const char *cipher_mode,
				const char *key_file,
				const char *passphrase,
				size_t passphrase_size,
				size_t key_size,
				uint64_t size,
				uint64_t skip,
				uint64_t offset,
				const char *uuid,
				int read_only,
				int reload)
{
	crypt_status_info ci;
	char *dm_cipher = NULL;
	char *processed_key = NULL;
	int r;

	if (!name)
		return -EINVAL;

	ci = crypt_status(cd, name);
	if (ci == CRYPT_INVALID)
		return -EINVAL;

	if (reload && ci < CRYPT_ACTIVE)
		return -EINVAL;

	if (!reload && ci >= CRYPT_ACTIVE) {
		log_err(cd, _("Device %s already exists.\n"), name);
		return -EEXIST;
	}

	if (key_size > 1024) {
		log_err(cd, _("Invalid key size %d.\n"), (int)key_size);
		return -EINVAL;
	}

	r = device_check_and_adjust(cd, cd->device, !reload, &size, &offset, &read_only);
	if (r)
		return r;

	if (cipher_mode && asprintf(&dm_cipher, "%s-%s", cipher, cipher_mode) < 0)
		return -ENOMEM;

	processed_key = process_key(cd, hash, key_file, key_size, passphrase, passphrase_size);
	if (!processed_key) {
		r = -ENOENT;
		goto out;
	}

	r = dm_create_device(name, cd->device, dm_cipher ?: cipher, cd->type, uuid, size, skip, offset,
			     key_size, processed_key, read_only, reload);

	if (isPLAIN(cd->type) && !uuid)
		(void)dm_query_device(name, NULL, NULL, NULL, NULL, NULL, NULL,
				      NULL, NULL, NULL, &cd->plain_uuid);
out:
	free(dm_cipher);
	crypt_safe_free(processed_key);
	return r;
}

static int open_from_hdr_and_vk(struct crypt_device *cd,
				struct volume_key *vk,
				const char *name,
				uint32_t flags)
{
	uint64_t size, offset;
	char *cipher;
	int read_only, no_uuid, r;

	size = 0;
	offset = crypt_get_data_offset(cd);
	read_only = flags & CRYPT_ACTIVATE_READONLY;
	no_uuid = flags & CRYPT_ACTIVATE_NO_UUID;

	r = device_check_and_adjust(cd, cd->device, 1, &size, &offset, &read_only);
	if (r)
		return r;

	if (asprintf(&cipher, "%s-%s", crypt_get_cipher(cd),
		     crypt_get_cipher_mode(cd)) < 0)
		r = -ENOMEM;
	else
		r = dm_create_device(name, cd->device, cipher, cd->type,
				     no_uuid ? NULL : crypt_get_uuid(cd),
				     size, 0, offset, vk->keylength, vk->key,
				     read_only, 0);
	free(cipher);
	return r;
}

static void log_wrapper(int level, const char *msg, void *usrptr)
{
	void (*xlog)(int level, char *msg) = usrptr;
	xlog(level, (char *)msg);
}

static int yesDialog_wrapper(const char *msg, void *usrptr)
{
	int (*xyesDialog)(char *msg) = usrptr;
	return xyesDialog((char*)msg);
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
			    cd->backing_file ?: cd->device) < 0)
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
		r = crypt_get_key(msg, key, key_len, 0, NULL, cd->timeout,
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
		if(r < 0)
			goto out;

		r = LUKS_open_key_with_hdr(cd->device, keyslot, passphrase_read,
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
			  const char *key_file, size_t key_size)
{
	return crypt_get_key(msg, key, key_len, key_size, key_file,
			     cd->timeout, 0, cd);
}

static int _crypt_init(struct crypt_device **cd,
		       const char *type,
		       struct crypt_options *options,
		       int load, int need_dm)
{
	int init_by_name, r;

	/* if it is plain device and mapping table is being reloaded
	initialize it by name*/
	init_by_name = (type && !strcmp(type, CRYPT_PLAIN) && load);

	/* Some of old API calls do not require DM in kernel,
	   fake initialisation by initialise it with kernel_check disabled */
	if (!need_dm)
		(void)dm_init(NULL, 0);
	if (init_by_name)
		r = crypt_init_by_name(cd, options->name);
	else
		r = crypt_init(cd, options->device);
	if (!need_dm)
		dm_exit();

	if (r)
		return -EINVAL;

	crypt_set_log_callback(*cd, log_wrapper, options->icb->log);
	crypt_set_confirm_callback(*cd, yesDialog_wrapper, options->icb->yesDialog);

	crypt_set_timeout(*cd, options->timeout);
	crypt_set_password_retry(*cd, options->tries);
	crypt_set_iterarion_time(*cd, options->iteration_time ?: 1000);
	crypt_set_password_verify(*cd, options->flags & CRYPT_FLAG_VERIFY);

	if (load && !init_by_name)
		r = crypt_load(*cd, type, NULL);

	if (!r && type && !(*cd)->type) {
		(*cd)->type = strdup(type);
		if (!(*cd)->type)
			r = -ENOMEM;
	}

	if (r)
		crypt_free(*cd);

	return r;
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

/* OPTIONS: name, cipher, device, hash, key_file, key_size, key_slot,
 *          offset, size, skip, timeout, tries, passphrase_fd (ignored),
 *          flags, icb */
static int crypt_create_and_update_device(struct crypt_options *options, int update)
{
	struct crypt_device *cd = NULL;
	char *passphrase = NULL;
	size_t passphrase_size = 0;
	int r;

	r = _crypt_init(&cd, CRYPT_PLAIN, options, 0, 1);
	if (r)
		return r;

	r = crypt_get_key(_("Enter passphrase: "), &passphrase, &passphrase_size,
			  options->key_size, options->key_file,
			  cd->timeout, cd->password_verify, cd);
	if (!r)
		r = create_device_helper(cd, options->name, options->hash,
			options->cipher, NULL, options->key_file,
			passphrase, passphrase_size,
			options->key_size, options->size, options->skip,
			options->offset, NULL, options->flags & CRYPT_FLAG_READONLY,
			update);

	crypt_safe_free(passphrase);
	crypt_free(cd);
	return r;
}

int crypt_create_device(struct crypt_options *options)
{
	return crypt_create_and_update_device(options, 0);
}

int crypt_update_device(struct crypt_options *options)
{
	return crypt_create_and_update_device(options, 1);
}

/* OPTIONS: name, size, icb */
int crypt_resize_device(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	char *device = NULL, *cipher = NULL, *uuid = NULL, *key = NULL;
	const char *type = NULL;
	uint64_t size, skip, offset;
	int key_size, read_only, r;

	log_dbg("Resizing device %s to %" PRIu64 " sectors.", options->name, options->size);

	if (dm_init(NULL, 1) < 0)
		return -ENOSYS;

	r = dm_query_device(options->name, &device, &size, &skip, &offset,
			    &cipher, &key_size, &key, &read_only, NULL, &uuid);
	if (r < 0) {
		log_err(NULL, _("Device %s is not active.\n"), options->name);
		goto out;
	}

	/* Try to determine type of device from UUID */
	type = CRYPT_PLAIN;
	if (uuid) {
		if (!strncmp(uuid, CRYPT_PLAIN, strlen(CRYPT_PLAIN))) {
			type = CRYPT_PLAIN;
			free (uuid);
			uuid = NULL;
		} else if (!strncmp(uuid, CRYPT_LUKS1, strlen(CRYPT_LUKS1)))
			type = CRYPT_LUKS1;
	}

	if (!options->device)
		options->device = device;

	r = _crypt_init(&cd, type, options, 1, 1);
	if (r)
		goto out;

	size = options->size;
	r = device_check_and_adjust(cd, device, 0, &size, &offset, &read_only);
	if (r)
		goto out;

	r = dm_create_device(options->name, device, cipher, type,
			     crypt_get_uuid(cd), size, skip, offset,
			     key_size, key, read_only, 1);
out:
	crypt_safe_free(key);
	free(cipher);
	if (options->device == device)
		options->device = NULL;
	free(device);
	free(uuid);
	crypt_free(cd);
	dm_exit();
	return r;
}

/* OPTIONS: name, icb */
int crypt_query_device(struct crypt_options *options)
{
	int read_only, r;

	log_dbg("Query device %s.", options->name);

	if (dm_init(NULL, 1) < 0)
		return -ENOSYS;

	r = dm_status_device(options->name);
	if (r < 0)
		goto out;

	r = dm_query_device(options->name, (char **)&options->device, &options->size,
			    &options->skip, &options->offset, (char **)&options->cipher,
			    &options->key_size, NULL, &read_only, NULL, NULL);
	if (r >= 0) {
		if (read_only)
			options->flags |= CRYPT_FLAG_READONLY;

		options->flags |= CRYPT_FLAG_FREE_DEVICE;
		options->flags |= CRYPT_FLAG_FREE_CIPHER;

		r = 1;
	}
out:
	if (r == -ENODEV)
		r = 0;

	dm_exit();
	return r;
}

/* OPTIONS: name, icb */
int crypt_remove_device(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_init_by_name(&cd, options->name);
	if (r == 0)
		r = crypt_deactivate(cd, options->name);

	crypt_free(cd);
	return r;

}

/* OPTIONS: device, cipher, hash, align_payload, key_size (master key), key_slot
 *          new_key_file, iteration_time, timeout, flags, icb */
int crypt_luksFormat(struct crypt_options *options)
{
	char cipherName[LUKS_CIPHERNAME_L];
	char cipherMode[LUKS_CIPHERMODE_L];
	char *password=NULL;
	size_t passwordLen;
	struct crypt_device *cd = NULL;
	struct crypt_params_luks1 cp = {
		.hash = options->hash,
		.data_alignment = options->align_payload
	};
	int r;

	r = crypt_parse_name_and_mode(options->cipher, cipherName, NULL, cipherMode);
	if(r < 0) {
		log_err(cd, _("No known cipher specification pattern detected.\n"));
		return r;
	}

	if ((r = _crypt_init(&cd, CRYPT_LUKS1, options, 0, 1)))
		return r;

	if (options->key_slot >= LUKS_NUMKEYS && options->key_slot != CRYPT_ANY_SLOT) {
		log_err(cd, _("Key slot %d is invalid, please select between 0 and %d.\n"),
			options->key_slot, LUKS_NUMKEYS - 1);
		r = -EINVAL;
		goto out;
	}

	r = crypt_get_key(_("Enter LUKS passphrase: "), &password, &passwordLen, 0,
			  options->new_key_file, cd->timeout, cd->password_verify, cd);

	if(r < 0)
		goto out;

	r = crypt_format(cd, CRYPT_LUKS1, cipherName, cipherMode,
			 NULL, NULL, options->key_size, &cp);
	if (r < 0)
		goto out;

	/* Add keyslot using internally stored volume key generated during format */
	r = crypt_keyslot_add_by_volume_key(cd, options->key_slot, NULL, 0,
					    password, passwordLen);
out:
	crypt_free(cd);
	crypt_safe_free(password);
	return (r < 0) ? r : 0;
}

/* OPTIONS: name, device, key_size, key_file, timeout, tries, flags, icb */
int crypt_luksOpen(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	uint32_t flags = 0;
	int r;

	if (!options->name)
		return -EINVAL;

	r = _crypt_init(&cd, CRYPT_LUKS1, options, 1, 1);
	if (r)
		return r;

	if (options->flags & CRYPT_FLAG_READONLY)
		flags |= CRYPT_ACTIVATE_READONLY;

	if (options->flags & CRYPT_FLAG_NON_EXCLUSIVE_ACCESS)
		flags |= CRYPT_ACTIVATE_NO_UUID;

	if (options->key_file)
		r = crypt_activate_by_keyfile(cd, options->name,
			CRYPT_ANY_SLOT, options->key_file, 0,
			flags);
	else
		r = crypt_activate_by_passphrase(cd, options->name,
			CRYPT_ANY_SLOT, options->passphrase,
			options->passphrase ? strlen(options->passphrase) : 0,
			flags);

	crypt_free(cd);
	return (r < 0) ? r : 0;
}

/* OPTIONS: device, keys_slot, key_file, timeout, flags, icb */
int crypt_luksKillSlot(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	int r;

	r = _crypt_init(&cd, CRYPT_LUKS1, options, 1, 1);
	if (r)
		return r;

	r = luks_remove_helper(cd, options->key_slot, options->key_file, NULL,
			       options->flags & CRYPT_FLAG_VERIFY_ON_DELKEY);

	crypt_free(cd);
	return (r < 0) ? r : 0;
}

/* OPTIONS: device, new_key_file, key_file, timeout, flags, icb */
int crypt_luksRemoveKey(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	int r;

	r = _crypt_init(&cd, CRYPT_LUKS1, options, 1, 1);
	if (r)
		return r;

	r = luks_remove_helper(cd, CRYPT_ANY_SLOT, options->key_file, options->new_key_file,
			       options->flags & CRYPT_FLAG_VERIFY_ON_DELKEY);

	crypt_free(cd);
	return (r < 0) ? r : 0;
}


/* OPTIONS: device, new_key_file, key_file, key_slot, flags,
            iteration_time, timeout, icb */
int crypt_luksAddKey(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	int r = -EINVAL;

	r = _crypt_init(&cd, CRYPT_LUKS1, options, 1, 1);
	if (r)
		return r;

	if (options->key_file || options->new_key_file)
		r = crypt_keyslot_add_by_keyfile(cd, options->key_slot,
						 options->key_file, 0,
						 options->new_key_file, 0);
	else
		r = crypt_keyslot_add_by_passphrase(cd, options->key_slot,
						    NULL, 0, NULL, 0);

	crypt_free(cd);
	return (r < 0) ? r : 0;
}

/* OPTIONS: device, icb */
int crypt_luksUUID(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	const char *uuid;
	int r;

	r = _crypt_init(&cd, CRYPT_LUKS1, options, 1, 0);
	if (r)
		return r;

	uuid = crypt_get_uuid(cd);
	log_std(cd, "%s\n", uuid ?: "");
	crypt_free(cd);
	return 0;
}

/* OPTIONS: device, icb */
int crypt_isLuks(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	int r;

	log_dbg("Check device %s for LUKS header.", options->device);

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = crypt_init(&cd, options->device);
	if (r < 0)
		return -EINVAL;

	/* Do print fail here, no need to crypt_load() */
	r = LUKS_read_phdr(cd->device, &cd->hdr, 0, cd) ? -EINVAL : 0;

	crypt_free(cd);
	return r;
}

/* OPTIONS: device, icb */
int crypt_luksDump(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	int r;

	r = _crypt_init(&cd, CRYPT_LUKS1, options, 1, 0);
	if(r < 0)
		return r;

	r = crypt_dump(cd);

	crypt_free(cd);
	return r;
}

void crypt_get_error(char *buf, size_t size)
{
	const char *error = get_error();

	if (!buf || size < 1)
		set_error(NULL);
	else if (error) {
		strncpy(buf, error, size - 1);
		buf[size - 1] = '\0';
		set_error(NULL);
	} else
		buf[0] = '\0';
}

void crypt_put_options(struct crypt_options *options)
{
	if (options->flags & CRYPT_FLAG_FREE_DEVICE) {
		free((char *)options->device);
		options->device = NULL;
		options->flags &= ~CRYPT_FLAG_FREE_DEVICE;
	}
	if (options->flags & CRYPT_FLAG_FREE_CIPHER) {
		free((char *)options->cipher);
		options->cipher = NULL;
		options->flags &= ~CRYPT_FLAG_FREE_CIPHER;
	}
}

const char *crypt_get_dir(void)
{
	return dm_get_dir();
}

/////////////////////////////////
//
// New API
//

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

int crypt_init_by_name(struct crypt_device **cd, const char *name)
{
	crypt_status_info ci;
	struct crypt_active_device cad;
	char *device = NULL, *cipher_full = NULL, *device_uuid = NULL;
	char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	char *key = NULL;
	int key_size = 0, key_nums, r;


	log_dbg("Allocating crypt device context by device %s.", name);

	ci = crypt_status(NULL, name);
	if (ci == CRYPT_INVALID)
		return -ENODEV;

	if (ci < CRYPT_ACTIVE) {
		log_err(NULL, _("Device %s is not active.\n"), name);
		return -ENODEV;
	}

	r = dm_query_device(name, &device, &cad.size, &cad.iv_offset, &cad.offset,
			    &cipher_full, &key_size, &key, NULL, NULL,
			    &device_uuid);
	if (r < 0)
		goto out;

	*cd = NULL;
	r = crypt_init(cd, device);

	/* Underlying device disappeared but mapping still active */
	if (!device || r == -ENOTBLK)
		log_verbose(NULL, _("Underlying device for crypt device %s disappeared.\n"),
			    name);

	/* Underlying device is not readable but crypt mapping exists */
	if (r == -ENOTBLK) {
		free(device);
		device = NULL;
		r = crypt_init(cd, NULL);
	}

	if (r < 0)
		goto out;

	/* Try to initialise basic parameters from active device */

	if (!(*cd)->backing_file && device && crypt_loop_device(device) &&
	    !((*cd)->backing_file = crypt_loop_backing_file(device))) {
		r = -ENOMEM;
		goto out;
	}

	if (device_uuid) {
		if (!strncmp(CRYPT_PLAIN, device_uuid, sizeof(CRYPT_PLAIN)-1)) {
			(*cd)->type = strdup(CRYPT_PLAIN);
			(*cd)->plain_uuid = strdup(device_uuid);
			(*cd)->plain_hdr.hash = NULL; /* no way to get this */
			(*cd)->plain_hdr.offset = cad.offset;
			(*cd)->plain_hdr.skip = cad.iv_offset;
			(*cd)->volume_key = crypt_alloc_volume_key(key_size, key);
			if (!(*cd)->volume_key) {
				r = -ENOMEM;
				goto out;
			}

			r = crypt_parse_name_and_mode(cipher_full, cipher, NULL, cipher_mode);
			if (!r) {
				(*cd)->plain_cipher = strdup(cipher);
				(*cd)->plain_cipher_mode = strdup(cipher_mode);
			}
		} else if (!strncmp(CRYPT_LOOPAES, device_uuid, sizeof(CRYPT_LOOPAES)-1)) {
			(*cd)->type = strdup(CRYPT_LOOPAES);
			(*cd)->loopaes_uuid = strdup(device_uuid);
			(*cd)->loopaes_hdr.offset = cad.offset;

			r = crypt_parse_name_and_mode(cipher_full, cipher,
						      &key_nums, cipher_mode);
			if (!r) {
				(*cd)->loopaes_cipher = strdup(cipher);
				(*cd)->loopaes_cipher_mode = strdup(cipher_mode);
				/* version 3 uses last key for IV */
				if (key_size % key_nums)
					key_nums++;
				(*cd)->loopaes_key_size = key_size / key_nums;
			}
		} else if (!strncmp(CRYPT_LUKS1, device_uuid, sizeof(CRYPT_LUKS1)-1)) {
			if (device) {
				if (crypt_load(*cd, CRYPT_LUKS1, NULL) < 0 ||
				    crypt_volume_key_verify(*cd, key, key_size) < 0) {
					log_dbg("LUKS device header does not match active device.");
					goto out;
				}

				(*cd)->volume_key = crypt_alloc_volume_key(key_size, key);
				if (!(*cd)->volume_key) {
					r = -ENOMEM;
					goto out;
				}
			}
		}
	} else
		log_dbg("Active device has no UUID set, some parameters are not set.");

out:
	if (r < 0) {
		crypt_free(*cd);
		*cd = NULL;
	}
	crypt_safe_free(key);
	free(device);
	free(cipher_full);
	free(device_uuid);
	return r;
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

	if (!cd->device) {
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

	if (params && params->data_alignment)
		required_alignment = params->data_alignment * SECTOR_SIZE;
	else
		get_topology_alignment(cd->device, &required_alignment,
				       &alignment_offset, DEFAULT_DISK_ALIGNMENT);

	r = LUKS_generate_phdr(&cd->hdr, cd->volume_key, cipher, cipher_mode,
			       (params && params->hash) ? params->hash : "sha1",
			       uuid, LUKS_STRIPES,
			       required_alignment / SECTOR_SIZE,
			       alignment_offset / SECTOR_SIZE,
			       cd->iteration_time, &cd->PBKDF2_per_sec, cd);
	if(r < 0)
		return r;

	/* Wipe first 8 sectors - fs magic numbers etc. */
	r = wipe_device_header(cd->device, 8);
	if(r < 0) {
		if (r == -EBUSY)
			log_err(cd, _("Cannot format device %s which is still in use.\n"),
				cd->device);
		else
			log_err(cd, _("Cannot wipe header on device %s.\n"),
				cd->device);

		return r;
	}

	r = LUKS_write_phdr(cd->device, &cd->hdr, cd);

	return r;
}

static int _crypt_format_loopaes(struct crypt_device *cd,
				 const char *cipher,
				 const char *uuid,
				 size_t volume_key_size,
				 struct crypt_params_loopaes *params)
{
	if (!cd->device) {
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

	log_dbg("Formatting device %s as type %s.", cd->device ?: "(none)", type);

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
	struct luks_phdr hdr;
	int r;

	log_dbg("Trying to load %s crypt type from device %s.",
		requested_type ?: "any", cd->device ?: "(none)");

	if (!cd->device)
		return -EINVAL;

	if (requested_type && !isLUKS(requested_type))
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = LUKS_read_phdr(cd->device, &hdr, 1, cd);

	if (!r) {
		memcpy(&cd->hdr, &hdr, sizeof(hdr));
		cd->type = strdup(CRYPT_LUKS1);
		if (!cd->type)
			r = -ENOMEM;
	}

	return r;
}

int crypt_resize(struct crypt_device *cd, const char *name, uint64_t new_size)
{
	char *device = NULL, *cipher = NULL, *uuid = NULL, *key = NULL;
	uint64_t size, skip, offset;
	int key_size, read_only, r;

	/* Device context type must be initialised */
	if (!cd->type || !crypt_get_uuid(cd))
		return -EINVAL;

	log_dbg("Resizing device %s to %" PRIu64 " sectors.", name, new_size);

	r = dm_query_device(name, &device, &size, &skip, &offset,
			    &cipher, &key_size, &key, &read_only, NULL, &uuid);
	if (r < 0) {
		log_err(NULL, _("Device %s is not active.\n"), name);
		goto out;
	}

	if (!uuid) {
		r = -EINVAL;
		goto out;
	}

	r = device_check_and_adjust(cd, device, 0, &new_size, &offset, &read_only);
	if (r)
		goto out;

	if (new_size == size) {
		log_dbg("Device has already requested size %" PRIu64
			" sectors.", size);
		r = 0;
		goto out;
	}

	r = dm_create_device(name, device, cipher, cd->type,
			     crypt_get_uuid(cd), new_size, skip, offset,
			     key_size, key, read_only, 1);
out:
	crypt_safe_free(key);
	free(cipher);
	free(device);
	free(uuid);

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
			uuid, cd->device);
		return 0;
	}

	if (uuid)
		log_dbg("Requested new UUID change to %s for %s.", uuid, cd->device);
	else
		log_dbg("Requested new UUID refresh for %s.", cd->device);

	if (!crypt_confirm(cd, _("Do you really want to change UUID of device?")))
		return -EPERM;

	return LUKS_hdr_uuid_set(cd->device, &cd->hdr, uuid, cd);
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
		"file %s.", cd->device, requested_type, backup_file);

	return LUKS_hdr_backup(backup_file, cd->device, &cd->hdr, cd);
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
		"file %s.", cd->device, requested_type, backup_file);

	return LUKS_hdr_restore(backup_file, cd->device, &cd->hdr, cd);
}

void crypt_free(struct crypt_device *cd)
{
	if (cd) {
		log_dbg("Releasing crypt device %s context.", cd->device);

		if (cd->loop_fd != -1)
			close(cd->loop_fd);

		dm_exit();
		crypt_free_volume_key(cd->volume_key);

		free(cd->device);
		free(cd->backing_file);
		free(cd->type);

		/* used in plain device only */
		free((char*)cd->plain_hdr.hash);
		free(cd->plain_cipher);
		free(cd->plain_cipher_mode);
		free(cd->plain_uuid);

		/* used in loop-AES device only */
		free((char*)cd->loopaes_hdr.hash);
		free(cd->loopaes_cipher);
		free(cd->loopaes_uuid);

		free(cd);
	}
}

int crypt_suspend(struct crypt_device *cd,
		  const char *name)
{
	crypt_status_info ci;
	int r, suspended = 0;

	log_dbg("Suspending volume %s.", name);

	ci = crypt_status(NULL, name);
	if (ci < CRYPT_ACTIVE) {
		log_err(cd, _("Volume %s is not active.\n"), name);
		return -EINVAL;
	}

	if (!cd && dm_init(NULL, 1) < 0)
		return -ENOSYS;

	r = dm_query_device(name, NULL, NULL, NULL, NULL,
			    NULL, NULL, NULL, NULL, &suspended, NULL);
	if (r < 0)
		goto out;

	if (suspended) {
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
	int r, suspended = 0;

	log_dbg("Resuming volume %s.", name);

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		r = -EINVAL;
		goto out;
	}

	r = dm_query_device(name, NULL, NULL, NULL, NULL,
			    NULL, NULL, NULL, NULL, &suspended, NULL);
	if (r < 0)
		return r;

	if (!suspended) {
		log_err(cd, _("Volume %s is not suspended.\n"), name);
		return -EINVAL;
	}

	if (passphrase) {
		r = LUKS_open_key_with_hdr(cd->device, keyslot, passphrase,
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

int crypt_resume_by_keyfile(struct crypt_device *cd,
			    const char *name,
			    int keyslot,
			    const char *keyfile,
			    size_t keyfile_size)
{
	struct volume_key *vk = NULL;
	char *passphrase_read = NULL;
	size_t passphrase_size_read;
	int r, suspended = 0;

	log_dbg("Resuming volume %s.", name);

	if (!isLUKS(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		r = -EINVAL;
		goto out;
	}

	r = dm_query_device(name, NULL, NULL, NULL, NULL,
			    NULL, NULL, NULL, NULL, &suspended, NULL);
	if (r < 0)
		return r;

	if (!suspended) {
		log_err(cd, _("Volume %s is not suspended.\n"), name);
		return -EINVAL;
	}

	if (!keyfile)
		return -EINVAL;

	r = key_from_file(cd, _("Enter passphrase: "), &passphrase_read,
			  &passphrase_size_read, keyfile, keyfile_size);
	if (r < 0)
		goto out;

	r = LUKS_open_key_with_hdr(cd->device, keyslot, passphrase_read,
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
		r = LUKS_open_key_with_hdr(cd->device, CRYPT_ANY_SLOT, passphrase,
					   passphrase_size, &cd->hdr, &vk, cd);
	} else {
		/* Passphrase not provided, ask first and use it to unlock existing keyslot */
		r = key_from_terminal(cd, _("Enter any passphrase: "),
				      &password, &passwordLen, 0);
		if (r < 0)
			goto out;

		r = LUKS_open_key_with_hdr(cd->device, CRYPT_ANY_SLOT, password,
					   passwordLen, &cd->hdr, &vk, cd);
		crypt_safe_free(password);
	}

	if(r < 0)
		goto out;

	if (new_passphrase) {
		new_password = (char *)new_passphrase;
		new_passwordLen = new_passphrase_size;
	} else {
		r = key_from_terminal(cd, _("Enter new passphrase for key slot: "),
				      &new_password, &new_passwordLen, 1);
		if(r < 0)
			goto out;
	}

	r = LUKS_set_key(cd->device, keyslot, new_password, new_passwordLen,
			 &cd->hdr, vk, cd->iteration_time, &cd->PBKDF2_per_sec, cd);
	if(r < 0) goto out;

	r = 0;
out:
	if (!new_passphrase)
		crypt_safe_free(new_password);
	crypt_free_volume_key(vk);
	return r ?: keyslot;
}

int crypt_keyslot_add_by_keyfile(struct crypt_device *cd,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	const char *new_keyfile,
	size_t new_keyfile_size)
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
					  keyfile, keyfile_size);
		else
			r = key_from_terminal(cd, _("Enter any passphrase: "),
					      &password, &passwordLen, 0);
		if (r < 0)
			goto out;

		r = LUKS_open_key_with_hdr(cd->device, CRYPT_ANY_SLOT, password, passwordLen,
					   &cd->hdr, &vk, cd);
	}

	if(r < 0)
		goto out;

	if (new_keyfile)
		r = key_from_file(cd, _("Enter new passphrase for key slot: "),
				  &new_password, &new_passwordLen, new_keyfile,
				  new_keyfile_size);
	else
		r = key_from_terminal(cd, _("Enter new passphrase for key slot: "),
				      &new_password, &new_passwordLen, 1);
	if (r < 0)
		goto out;

	r = LUKS_set_key(cd->device, keyslot, new_password, new_passwordLen,
			 &cd->hdr, vk, cd->iteration_time, &cd->PBKDF2_per_sec, cd);
out:
	crypt_safe_free(password);
	crypt_safe_free(new_password);
	crypt_free_volume_key(vk);
	return r < 0 ? r : keyslot;
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

	r = LUKS_set_key(cd->device, keyslot, passphrase, passphrase_size,
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

	return LUKS_del_key(cd->device, keyslot, &cd->hdr, cd);
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
		if (!passphrase) {
			r = key_from_terminal(cd, NULL, &read_passphrase,
					      &passphraseLen, 0);
			if (r < 0)
				goto out;
			passphrase = read_passphrase;
			passphrase_size = passphraseLen;
		}
		r = create_device_helper(cd, name, cd->plain_hdr.hash,
					 cd->plain_cipher, cd->plain_cipher_mode,
					 NULL, passphrase, passphrase_size,
					 cd->volume_key->keylength, 0,
					 cd->plain_hdr.skip, cd->plain_hdr.offset,
					 cd->plain_uuid,
					 flags & CRYPT_ACTIVATE_READONLY, 0);
		keyslot = 0;
	} else if (isLUKS(cd->type)) {
		/* provided passphrase, do not retry */
		if (passphrase) {
			r = LUKS_open_key_with_hdr(cd->device, keyslot, passphrase,
						   passphrase_size, &cd->hdr, &vk, cd);
		} else
			r = volume_key_by_terminal_passphrase(cd, keyslot, &vk);

		if (r >= 0) {
			keyslot = r;
			if (name)
				r = open_from_hdr_and_vk(cd, vk, name, flags);
		}
	} else
		r = -EINVAL;
out:
	crypt_safe_free(read_passphrase);
	crypt_free_volume_key(vk);

	return r < 0  ? r : keyslot;
}

int crypt_activate_by_keyfile(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
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
		r = key_from_file(cd, _("Enter passphrase: "),
				  &passphrase_read, &passphrase_size_read,
				  keyfile, keyfile_size);
		if (r < 0)
			goto out;
		r = create_device_helper(cd, name, cd->plain_hdr.hash,
					 cd->plain_cipher, cd->plain_cipher_mode,
					 NULL, passphrase_read, passphrase_size_read,
					 cd->volume_key->keylength, 0,
					 cd->plain_hdr.skip, cd->plain_hdr.offset,
					 cd->plain_uuid,
					 flags & CRYPT_ACTIVATE_READONLY, 0);
	} else if (isLUKS(cd->type)) {
		r = key_from_file(cd, _("Enter passphrase: "), &passphrase_read,
			  &passphrase_size_read, keyfile, keyfile_size);
		if (r < 0)
			goto out;
		r = LUKS_open_key_with_hdr(cd->device, keyslot, passphrase_read,
					   passphrase_size_read, &cd->hdr, &vk, cd);
		if (r < 0)
			goto out;
		keyslot = r;

		if (name) {
			r = open_from_hdr_and_vk(cd, vk, name, flags);
			if (r < 0)
				goto out;
		}
		r = keyslot;
	} else if (isLOOPAES(cd->type)) {
		r = key_from_file(cd, NULL, &passphrase_read, &passphrase_size_read,
				  keyfile, keyfile_size);
		if (r < 0)
			goto out;
		r = LOOPAES_parse_keyfile(cd, &vk, cd->loopaes_hdr.hash, &key_count,
					  passphrase_read, passphrase_size_read);
		if (r < 0)
			goto out;
		if (name)
			r = LOOPAES_activate(cd, name, cd->loopaes_cipher,
					     key_count, vk,
					     cd->loopaes_hdr.offset,
					     cd->loopaes_hdr.skip,
					     flags);
	} else
		r = -EINVAL;

out:
	crypt_safe_free(passphrase_read);
	crypt_free_volume_key(vk);

	return r;
}

int crypt_activate_by_volume_key(struct crypt_device *cd,
	const char *name,
	const char *volume_key,
	size_t volume_key_size,
	uint32_t flags)
{
	crypt_status_info ci;
	struct volume_key *vk;
	int r;

	log_dbg("Activating volume %s by volume key.", name);

	/* use key directly, no hash */
	if (isPLAIN(cd->type)) {
		if (!volume_key || !volume_key_size || !cd->volume_key ||
			volume_key_size != cd->volume_key->keylength) {
			log_err(cd, _("Incorrect volume key specified for plain device.\n"));
			return -EINVAL;
		}

		return create_device_helper(cd, name, NULL,
			cd->plain_cipher, cd->plain_cipher_mode, NULL, volume_key, volume_key_size,
			cd->volume_key->keylength, 0, cd->plain_hdr.skip,
			cd->plain_hdr.offset, cd->plain_uuid, flags & CRYPT_ACTIVATE_READONLY, 0);
	}

	if (!isLUKS(cd->type)) {
		log_err(cd, _("Device type is not properly initialised.\n"));
		return -EINVAL;
	}

	if (name) {
		ci = crypt_status(NULL, name);
		if (ci == CRYPT_INVALID)
			return -EINVAL;
		else if (ci >= CRYPT_ACTIVE) {
			log_err(cd, _("Device %s already exists.\n"), name);
			return -EEXIST;
		}
	}

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
		r = open_from_hdr_and_vk(cd, vk, name, flags);

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
			r = dm_remove_device(name, 0, 0);
			break;
		case CRYPT_BUSY:
			log_err(cd, _("Device %s is busy.\n"), name);
			r = -EBUSY;
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
	struct volume_key *vk;
	char *processed_key = NULL;
	unsigned key_len;
	int r;

	key_len = crypt_get_volume_key_size(cd);
	if (key_len > *volume_key_size) {
		log_err(cd, _("Volume key buffer too small.\n"));
		return -ENOMEM;
	}

	if (isPLAIN(cd->type) && cd->plain_hdr.hash) {
		processed_key = process_key(cd, cd->plain_hdr.hash, NULL, key_len,
					    passphrase, passphrase_size);
		if (!processed_key) {
			log_err(cd, _("Cannot retrieve volume key for plain device.\n"));
			return -EINVAL;
		}
		memcpy(volume_key, processed_key, key_len);
		*volume_key_size = key_len;
		crypt_safe_free(processed_key);
		return 0;
	}

	if (isLUKS(cd->type)) {
		r = LUKS_open_key_with_hdr(cd->device, keyslot, passphrase,
					passphrase_size, &cd->hdr, &vk, cd);

		if (r >= 0) {
			memcpy(volume_key, vk->key, vk->keylength);
			*volume_key_size = vk->keylength;
		}

		crypt_free_volume_key(vk);
		return r;
	}

	log_err(cd, _("This operation is not supported for %s crypt device.\n"), cd->type ?: "(none)");
	return -EINVAL;
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

void crypt_set_iterarion_time(struct crypt_device *cd, uint64_t iteration_time_ms)
{
	log_dbg("Iteration time set to %" PRIu64 " miliseconds.", iteration_time_ms);
	cd->iteration_time = iteration_time_ms;
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

	log_std(cd, "LUKS header information for %s\n\n", cd->device);
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
	if (isPLAIN(cd->type) && cd->volume_key)
		return cd->volume_key->keylength;

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
	int r, readonly;

	r = dm_query_device(name, NULL, &cad->size, &cad->iv_offset, &cad->offset,
			    NULL, NULL, NULL, &readonly, NULL, NULL);
	if (r < 0)
		return r;

	cad->flags = readonly ? CRYPT_ACTIVATE_READONLY : 0;

	return 0;
}
