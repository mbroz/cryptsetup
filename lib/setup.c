/*
 * libcryptsetup - cryptsetup library
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/utsname.h>
#include <errno.h>

#include "libcryptsetup.h"
#include "luks.h"
#include "luks2.h"
#include "loopaes.h"
#include "verity.h"
#include "tcrypt.h"
#include "integrity.h"
#include "bitlk.h"
#include "utils_device_locking.h"
#include "internal.h"

#define CRYPT_CD_UNRESTRICTED	(1 << 0)
#define CRYPT_CD_QUIET		(1 << 1)

struct crypt_device {
	char *type;

	struct device *device;
	struct device *metadata_device;

	struct volume_key *volume_key;
	int rng_type;
	uint32_t compatibility;
	struct crypt_pbkdf_type pbkdf;

	/* global context scope settings */
	unsigned key_in_keyring:1;

	uint64_t data_offset;
	uint64_t metadata_size; /* Used in LUKS2 format */
	uint64_t keyslots_size; /* Used in LUKS2 format */

	/* Workaround for OOM during parallel activation (like in systemd) */
	bool memory_hard_pbkdf_lock_enabled;
	struct crypt_lock_handle *pbkdf_memory_hard_lock;

	// FIXME: private binary headers and access it properly
	// through sub-library (LUKS1, TCRYPT)

	union {
	struct { /* used in CRYPT_LUKS1 */
		struct luks_phdr hdr;
		char *cipher_spec;
	} luks1;
	struct { /* used in CRYPT_LUKS2 */
		struct luks2_hdr hdr;
		char cipher[MAX_CIPHER_LEN];	  /* only for compatibility */
		char cipher_mode[MAX_CIPHER_LEN]; /* only for compatibility */
		char *keyslot_cipher;
		unsigned int keyslot_key_size;
		struct luks2_reenc_context *rh;
	} luks2;
	struct { /* used in CRYPT_PLAIN */
		struct crypt_params_plain hdr;
		char *cipher_spec;
		char *cipher;
		const char *cipher_mode;
		unsigned int key_size;
	} plain;
	struct { /* used in CRYPT_LOOPAES */
		struct crypt_params_loopaes hdr;
		char *cipher_spec;
		char *cipher;
		const char *cipher_mode;
		unsigned int key_size;
	} loopaes;
	struct { /* used in CRYPT_VERITY */
		struct crypt_params_verity hdr;
		const char *root_hash;
		unsigned int root_hash_size;
		char *uuid;
		struct device *fec_device;
	} verity;
	struct { /* used in CRYPT_TCRYPT */
		struct crypt_params_tcrypt params;
		struct tcrypt_phdr hdr;
	} tcrypt;
	struct { /* used in CRYPT_INTEGRITY */
		struct crypt_params_integrity params;
		struct volume_key *journal_mac_key;
		struct volume_key *journal_crypt_key;
		uint32_t sb_flags;
	} integrity;
	struct { /* used in CRYPT_BITLK */
		struct bitlk_metadata params;
		char *cipher_spec;
	} bitlk;
	struct { /* used if initialized without header by name */
		char *active_name;
		/* buffers, must refresh from kernel on every query */
		char cipher_spec[MAX_CIPHER_LEN*2+1];
		char cipher[MAX_CIPHER_LEN];
		const char *cipher_mode;
		unsigned int key_size;
	} none;
	} u;

	/* callbacks definitions */
	void (*log)(int level, const char *msg, void *usrptr);
	void *log_usrptr;
	int (*confirm)(const char *msg, void *usrptr);
	void *confirm_usrptr;
};

/* Just to suppress redundant messages about crypto backend */
static int _crypto_logged = 0;

/* Log helper */
static void (*_default_log)(int level, const char *msg, void *usrptr) = NULL;
static int _debug_level = 0;

/* Library can do metadata locking  */
static int _metadata_locking = 1;

/* Library scope detection for kernel keyring support */
static int _kernel_keyring_supported;

/* Library allowed to use kernel keyring for loading VK in kernel crypto layer */
static int _vk_via_keyring = 1;

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
	if (!msg)
		return;

	if (level < _debug_level)
		return;

	if (cd && cd->log)
		cd->log(level, msg, cd->log_usrptr);
	else if (_default_log)
		_default_log(level, msg, NULL);
	/* Default to stdout/stderr if there is no callback. */
	else
		fprintf(level == CRYPT_LOG_ERROR ? stderr : stdout, "%s", msg);
}

__attribute__((format(printf, 5, 6)))
void logger(struct crypt_device *cd, int level, const char *file,
	    int line, const char *format, ...)
{
	va_list argp;
	char target[LOG_MAX_LEN + 2];
	int len;

	va_start(argp, format);

	len = vsnprintf(&target[0], LOG_MAX_LEN, format, argp);
	if (len > 0 && len < LOG_MAX_LEN) {
		/* All verbose and error messages in tools end with EOL. */
		if (level == CRYPT_LOG_VERBOSE || level == CRYPT_LOG_ERROR ||
		    level == CRYPT_LOG_DEBUG || level == CRYPT_LOG_DEBUG_JSON)
			strncat(target, "\n", LOG_MAX_LEN);

		crypt_log(cd, level, target);
	}

	va_end(argp);
}

static const char *mdata_device_path(struct crypt_device *cd)
{
	return device_path(cd->metadata_device ?: cd->device);
}

static const char *data_device_path(struct crypt_device *cd)
{
	return device_path(cd->device);
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
		log_err(ctx, _("Cannot initialize crypto RNG backend."));
		return r;
	}

	r = crypt_backend_init();
	if (r < 0)
		log_err(ctx, _("Cannot initialize crypto backend."));

	if (!r && !_crypto_logged) {
		log_dbg(ctx, "Crypto backend (%s) initialized in cryptsetup library version %s.",
			crypt_backend_version(), PACKAGE_VERSION);
		if (!uname(&uts))
			log_dbg(ctx, "Detected kernel %s %s %s.",
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
				log_err(cd, _("Hash algorithm %s not supported."),
					hash_name);
			else
				log_err(cd, _("Key processing error (using hash %s)."),
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

static int isLUKS1(const char *type)
{
	return (type && !strcmp(CRYPT_LUKS1, type));
}

static int isLUKS2(const char *type)
{
	return (type && !strcmp(CRYPT_LUKS2, type));
}

static int isLUKS(const char *type)
{
	return (isLUKS2(type) || isLUKS1(type));
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

static int isINTEGRITY(const char *type)
{
	return (type && !strcmp(CRYPT_INTEGRITY, type));
}

static int isBITLK(const char *type)
{
	return (type && !strcmp(CRYPT_BITLK, type));
}

static int _onlyLUKS(struct crypt_device *cd, uint32_t cdflags)
{
	int r = 0;

	if (cd && !cd->type) {
		if (!(cdflags & CRYPT_CD_QUIET))
			log_err(cd, _("Cannot determine device type. Incompatible activation of device?"));
		r = -EINVAL;
	}

	if (!cd || !isLUKS(cd->type)) {
		if (!(cdflags & CRYPT_CD_QUIET))
			log_err(cd, _("This operation is supported only for LUKS device."));
		r = -EINVAL;
	}

	if (r || (cdflags & CRYPT_CD_UNRESTRICTED) || isLUKS1(cd->type))
		return r;

	return LUKS2_unmet_requirements(cd, &cd->u.luks2.hdr, 0, cdflags & CRYPT_CD_QUIET);
}

static int onlyLUKS(struct crypt_device *cd)
{
	return _onlyLUKS(cd, 0);
}

static int _onlyLUKS2(struct crypt_device *cd, uint32_t cdflags, uint32_t mask)
{
	int r = 0;

	if (cd && !cd->type) {
		if (!(cdflags & CRYPT_CD_QUIET))
			log_err(cd, _("Cannot determine device type. Incompatible activation of device?"));
		r = -EINVAL;
	}

	if (!cd || !isLUKS2(cd->type)) {
		if (!(cdflags & CRYPT_CD_QUIET))
			log_err(cd, _("This operation is supported only for LUKS2 device."));
		r = -EINVAL;
	}

	if (r || (cdflags & CRYPT_CD_UNRESTRICTED))
		return r;

	return LUKS2_unmet_requirements(cd, &cd->u.luks2.hdr, mask, cdflags & CRYPT_CD_QUIET);
}

/* Internal only */
int onlyLUKS2(struct crypt_device *cd)
{
	return _onlyLUKS2(cd, 0, 0);
}

/* Internal only */
int onlyLUKS2mask(struct crypt_device *cd, uint32_t mask)
{
	return _onlyLUKS2(cd, 0, mask);
}

static void crypt_set_null_type(struct crypt_device *cd)
{
	if (!cd->type)
		return;

	free(cd->type);
	cd->type = NULL;
	cd->u.none.active_name = NULL;
	cd->data_offset = 0;
	cd->metadata_size = 0;
	cd->keyslots_size = 0;
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
	crypt_keyslot_info ki;

	if (*keyslot == CRYPT_ANY_SLOT) {
		if (isLUKS1(cd->type))
			*keyslot = LUKS_keyslot_find_empty(&cd->u.luks1.hdr);
		else
			*keyslot = LUKS2_keyslot_find_empty(&cd->u.luks2.hdr);
		if (*keyslot < 0) {
			log_err(cd, _("All key slots full."));
			return -EINVAL;
		}
	}

	if (isLUKS1(cd->type))
		ki = LUKS_keyslot_info(&cd->u.luks1.hdr, *keyslot);
	else
		ki = LUKS2_keyslot_info(&cd->u.luks2.hdr, *keyslot);
	switch (ki) {
		case CRYPT_SLOT_INVALID:
			log_err(cd, _("Key slot %d is invalid, please select between 0 and %d."),
				*keyslot, LUKS_NUMKEYS - 1);
			return -EINVAL;
		case CRYPT_SLOT_INACTIVE:
			break;
		default:
			log_err(cd, _("Key slot %d is full, please select another one."),
				*keyslot);
			return -EINVAL;
	}

	log_dbg(cd, "Selected keyslot %d.", *keyslot);
	return 0;
}

/*
 * compares UUIDs returned by device-mapper (striped by cryptsetup) and uuid in header
 */
int crypt_uuid_cmp(const char *dm_uuid, const char *hdr_uuid)
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

/*
 * compares type of active device to provided string (only if there is no explicit type)
 */
static int crypt_uuid_type_cmp(struct crypt_device *cd, const char *type)
{
	struct crypt_dm_active_device dmd;
	size_t len;
	int r;

	/* Must user header-on-disk if we know type here */
	if (cd->type || !cd->u.none.active_name)
		return -EINVAL;

	log_dbg(cd, "Checking if active device %s without header has UUID type %s.",
		cd->u.none.active_name, type);

	r = dm_query_device(cd, cd->u.none.active_name, DM_ACTIVE_UUID, &dmd);
	if (r < 0)
		return r;

	r = -ENODEV;
	len = strlen(type);
	if (dmd.uuid && strlen(dmd.uuid) > len &&
	    !strncmp(dmd.uuid, type, len) && dmd.uuid[len] == '-')
		r = 0;

	free(CONST_CAST(void*)dmd.uuid);
	return r;
}

int PLAIN_activate(struct crypt_device *cd,
		     const char *name,
		     struct volume_key *vk,
		     uint64_t size,
		     uint32_t flags)
{
	int r;
	struct crypt_dm_active_device dmd = {
		.flags = flags,
		.size = size,
	};

	log_dbg(cd, "Trying to activate PLAIN device %s using cipher %s.",
		name, crypt_get_cipher_spec(cd));

	if (MISALIGNED(size, device_block_size(cd, crypt_data_device(cd)) >> SECTOR_SHIFT)) {
		log_err(cd, _("Device size is not aligned to device logical block size."));
		return -EINVAL;
	}

	r = dm_crypt_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd),
			vk, crypt_get_cipher_spec(cd), crypt_get_iv_offset(cd),
			crypt_get_data_offset(cd), crypt_get_integrity(cd),
			crypt_get_integrity_tag_size(cd), crypt_get_sector_size(cd));
	if (r < 0)
		return r;

	r = create_or_reload_device(cd, name, CRYPT_PLAIN, &dmd);

	dm_targets_free(cd, &dmd);
	return r;
}

int crypt_confirm(struct crypt_device *cd, const char *msg)
{
	if (!cd || !cd->confirm)
		return 1;
	else
		return cd->confirm(msg, cd->confirm_usrptr);
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
	if (cd) {
		cd->confirm = confirm;
		cd->confirm_usrptr = usrptr;
	}
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

	log_dbg(NULL, "Allocating context for crypt device %s.", device ?: "(none)");
#if !HAVE_DECL_O_CLOEXEC
	log_dbg(NULL, "Running without O_CLOEXEC.");
#endif

	if (!(h = malloc(sizeof(struct crypt_device))))
		return -ENOMEM;

	memset(h, 0, sizeof(*h));

	r = device_alloc(NULL, &h->device, device);
	if (r < 0)
		goto bad;

	dm_backend_init(NULL);

	h->rng_type = crypt_random_default_key_rng();

	*cd = h;
	return 0;
bad:
	device_free(NULL, h->device);
	free(h);
	return r;
}

static int crypt_check_data_device_size(struct crypt_device *cd)
{
	int r;
	uint64_t size, size_min;

	/* Check data device size, require at least header or one sector */
	size_min = crypt_get_data_offset(cd) << SECTOR_SHIFT ?: SECTOR_SIZE;

	r = device_size(cd->device, &size);
	if (r < 0)
		return r;

	if (size < size_min) {
		log_err(cd, _("Header detected but device %s is too small."),
			device_path(cd->device));
		return -EINVAL;
	}

	return r;
}

static int _crypt_set_data_device(struct crypt_device *cd, const char *device)
{
	struct device *dev = NULL;
	int r;

	r = device_alloc(cd, &dev, device);
	if (r < 0)
		return r;

	if (!cd->metadata_device) {
		cd->metadata_device = cd->device;
	} else
		device_free(cd, cd->device);

	cd->device = dev;

	return crypt_check_data_device_size(cd);
}

int crypt_set_data_device(struct crypt_device *cd, const char *device)
{
	/* metadata device must be set */
	if (!cd || !cd->device || !device)
		return -EINVAL;

	log_dbg(cd, "Setting ciphertext data device to %s.", device ?: "(none)");

	if (!isLUKS1(cd->type) && !isLUKS2(cd->type) && !isVERITY(cd->type) &&
	    !isINTEGRITY(cd->type)) {
		log_err(cd, _("This operation is not supported for this device type."));
		return -EINVAL;
	}

	if (isLUKS2(cd->type) && crypt_get_reenc_context(cd)) {
		log_err(cd, _("Illegal operation with reencryption in-progress."));
		return -EINVAL;
	}

	return _crypt_set_data_device(cd, device);
}

int crypt_init_data_device(struct crypt_device **cd, const char *device, const char *data_device)
{
	int r;

	if (!cd)
		return -EINVAL;

	r = crypt_init(cd, device);
	if (r || !data_device || !strcmp(device, data_device))
		return r;

	log_dbg(NULL, "Setting ciphertext data device to %s.", data_device);
	r = _crypt_set_data_device(*cd, data_device);
	if (r) {
		crypt_free(*cd);
		*cd = NULL;
	}

	return r;
}


/* internal only */
struct crypt_pbkdf_type *crypt_get_pbkdf(struct crypt_device *cd)
{
	return &cd->pbkdf;
}

/*
 * crypt_load() helpers
 */
static int _crypt_load_luks2(struct crypt_device *cd, int reload, int repair)
{
	int r;
	char *type = NULL;
	struct luks2_hdr hdr2 = {};

	log_dbg(cd, "%soading LUKS2 header (repair %sabled).", reload ? "Rel" : "L", repair ? "en" : "dis");

	r = LUKS2_hdr_read(cd, &hdr2, repair);
	if (r)
		return r;

	if (!reload && !(type = strdup(CRYPT_LUKS2))) {
		r = -ENOMEM;
		goto out;
	}

	if (verify_pbkdf_params(cd, &cd->pbkdf)) {
		r = init_pbkdf_type(cd, NULL, CRYPT_LUKS2);
		if (r)
			goto out;
	}

	if (reload) {
		LUKS2_hdr_free(cd, &cd->u.luks2.hdr);
		free(cd->u.luks2.keyslot_cipher);
	} else
		cd->type = type;

	r = 0;
	memcpy(&cd->u.luks2.hdr, &hdr2, sizeof(hdr2));
	cd->u.luks2.keyslot_cipher = NULL;
	cd->u.luks2.rh = NULL;

out:
	if (r) {
		free(type);
		LUKS2_hdr_free(cd, &hdr2);
	}
	return r;
}

static void _luks2_reload(struct crypt_device *cd)
{
	if (!cd || !isLUKS2(cd->type))
		return;

	(void) _crypt_load_luks2(cd, 1, 0);
}

static int _crypt_load_luks(struct crypt_device *cd, const char *requested_type,
			    int require_header, int repair)
{
	char *cipher_spec;
	struct luks_phdr hdr = {};
	int r, version;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	/* This will return 0 if primary LUKS2 header is damaged */
	version = LUKS2_hdr_version_unlocked(cd, NULL);

	if ((isLUKS1(requested_type) && version == 2) ||
	    (isLUKS2(requested_type) && version == 1))
		return -EINVAL;

	if (requested_type)
		version = 0;

	if (isLUKS1(requested_type) || version == 1) {
		if (cd->type && isLUKS2(cd->type)) {
			log_dbg(cd, "Context is already initialized to type %s", cd->type);
			return -EINVAL;
		}

		if (verify_pbkdf_params(cd, &cd->pbkdf)) {
			r = init_pbkdf_type(cd, NULL, CRYPT_LUKS1);
			if (r)
				return r;
		}

		r = LUKS_read_phdr(&hdr, require_header, repair, cd);
		if (r)
			goto out;

		if (!cd->type && !(cd->type = strdup(CRYPT_LUKS1))) {
			r = -ENOMEM;
			goto out;
		}

		/* Set hash to the same as in the loaded header */
		if (!cd->pbkdf.hash || strcmp(cd->pbkdf.hash, hdr.hashSpec)) {
			free(CONST_CAST(void*)cd->pbkdf.hash);
			cd->pbkdf.hash = strdup(hdr.hashSpec);
			if (!cd->pbkdf.hash) {
				r = -ENOMEM;
				goto out;
			}
		}

		if (asprintf(&cipher_spec, "%s-%s", hdr.cipherName, hdr.cipherMode) < 0) {
			r = -ENOMEM;
			goto out;
		}

		free(cd->u.luks1.cipher_spec);
		cd->u.luks1.cipher_spec = cipher_spec;

		memcpy(&cd->u.luks1.hdr, &hdr, sizeof(hdr));
	} else if (isLUKS2(requested_type) || version == 2 || version == 0) {
		if (cd->type && isLUKS1(cd->type)) {
			log_dbg(cd, "Context is already initialized to type %s", cd->type);
			return -EINVAL;
		}

		/*
		 * Current LUKS2 repair just overrides blkid probes
		 * and perform auto-recovery if possible. This is safe
		 * unless future LUKS2 repair code do something more
		 * sophisticated. In such case we would need to check
		 * for LUKS2 requirements and decide if it's safe to
		 * perform repair.
		 */
		r =  _crypt_load_luks2(cd, cd->type != NULL, repair);
	} else {
		if (version > 2)
			log_err(cd, _("Unsupported LUKS version %d."), version);
		r = -EINVAL;
	}
out:
	crypt_safe_memzero(&hdr, sizeof(hdr));

	return r;
}

static int _crypt_load_tcrypt(struct crypt_device *cd, struct crypt_params_tcrypt *params)
{
	int r;

	if (!params)
		return -EINVAL;

	if (cd->metadata_device) {
		log_err(cd, _("Detached metadata device is not supported for this crypt type."));
		return -EINVAL;
	}

	r = init_crypto(cd);
	if (r < 0)
		return r;

	memcpy(&cd->u.tcrypt.params, params, sizeof(*params));

	r = TCRYPT_read_phdr(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);

	cd->u.tcrypt.params.passphrase = NULL;
	cd->u.tcrypt.params.passphrase_size = 0;
	cd->u.tcrypt.params.keyfiles = NULL;
	cd->u.tcrypt.params.keyfiles_count = 0;
	cd->u.tcrypt.params.veracrypt_pim = 0;

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

	//FIXME: use crypt_free
	if (!cd->type && !(cd->type = strdup(CRYPT_VERITY))) {
		free(CONST_CAST(void*)cd->u.verity.hdr.hash_name);
		free(CONST_CAST(void*)cd->u.verity.hdr.salt);
		free(cd->u.verity.uuid);
		crypt_safe_memzero(&cd->u.verity.hdr, sizeof(cd->u.verity.hdr));
		return -ENOMEM;
	}

	if (params)
		cd->u.verity.hdr.flags = params->flags;

	/* Hash availability checked in sb load */
	cd->u.verity.root_hash_size = crypt_hash_size(cd->u.verity.hdr.hash_name);
	if (cd->u.verity.root_hash_size > 4096)
		return -EINVAL;

	if (params && params->data_device &&
	    (r = crypt_set_data_device(cd, params->data_device)) < 0)
		return r;

	if (params && params->fec_device) {
		r = device_alloc(cd, &cd->u.verity.fec_device, params->fec_device);
		if (r < 0)
			return r;
		cd->u.verity.hdr.fec_area_offset = params->fec_area_offset;
		cd->u.verity.hdr.fec_roots = params->fec_roots;
	}

	return r;
}

static int _crypt_load_integrity(struct crypt_device *cd,
				 struct crypt_params_integrity *params)
{
	int r;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = INTEGRITY_read_sb(cd, &cd->u.integrity.params, &cd->u.integrity.sb_flags);
	if (r < 0)
		return r;

	// FIXME: add checks for fields in integrity sb vs params

	if (params) {
		cd->u.integrity.params.journal_watermark = params->journal_watermark;
		cd->u.integrity.params.journal_commit_time = params->journal_commit_time;
		cd->u.integrity.params.buffer_sectors = params->buffer_sectors;
		// FIXME: check ENOMEM
		if (params->integrity)
			cd->u.integrity.params.integrity = strdup(params->integrity);
		cd->u.integrity.params.integrity_key_size = params->integrity_key_size;
		if (params->journal_integrity)
			cd->u.integrity.params.journal_integrity = strdup(params->journal_integrity);
		if (params->journal_crypt)
			cd->u.integrity.params.journal_crypt = strdup(params->journal_crypt);

		if (params->journal_crypt_key) {
			cd->u.integrity.journal_crypt_key =
				crypt_alloc_volume_key(params->journal_crypt_key_size,
						       params->journal_crypt_key);
			if (!cd->u.integrity.journal_crypt_key)
				return -ENOMEM;
		}
		if (params->journal_integrity_key) {
			cd->u.integrity.journal_mac_key =
				crypt_alloc_volume_key(params->journal_integrity_key_size,
						       params->journal_integrity_key);
			if (!cd->u.integrity.journal_mac_key)
				return -ENOMEM;
		}
	}

	if (!cd->type && !(cd->type = strdup(CRYPT_INTEGRITY))) {
		free(CONST_CAST(void*)cd->u.integrity.params.integrity);
		return -ENOMEM;
	}

	return 0;
}

static int _crypt_load_bitlk(struct crypt_device *cd,
			     struct bitlk_metadata *params)
{
	int r;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = BITLK_read_sb(cd, &cd->u.bitlk.params);
	if (r < 0)
		return r;

	if (asprintf(&cd->u.bitlk.cipher_spec, "%s-%s",
		     cd->u.bitlk.params.cipher, cd->u.bitlk.params.cipher_mode) < 0) {
		cd->u.bitlk.cipher_spec = NULL;
		return -ENOMEM;
	}

	if (!cd->type && !(cd->type = strdup(CRYPT_BITLK)))
		return -ENOMEM;

	return 0;
}

int crypt_load(struct crypt_device *cd,
	       const char *requested_type,
	       void *params)
{
	int r;

	if (!cd)
		return -EINVAL;

	log_dbg(cd, "Trying to load %s crypt type from device %s.",
		requested_type ?: "any", mdata_device_path(cd) ?: "(none)");

	if (!crypt_metadata_device(cd))
		return -EINVAL;

	crypt_reset_null_type(cd);
	cd->data_offset = 0;
	cd->metadata_size = 0;
	cd->keyslots_size = 0;

	if (!requested_type || isLUKS1(requested_type) || isLUKS2(requested_type)) {
		if (cd->type && !isLUKS1(cd->type) && !isLUKS2(cd->type)) {
			log_dbg(cd, "Context is already initialized to type %s", cd->type);
			return -EINVAL;
		}

		r = _crypt_load_luks(cd, requested_type, 1, 0);
	} else if (isVERITY(requested_type)) {
		if (cd->type && !isVERITY(cd->type)) {
			log_dbg(cd, "Context is already initialized to type %s", cd->type);
			return -EINVAL;
		}
		r = _crypt_load_verity(cd, params);
	} else if (isTCRYPT(requested_type)) {
		if (cd->type && !isTCRYPT(cd->type)) {
			log_dbg(cd, "Context is already initialized to type %s", cd->type);
			return -EINVAL;
		}
		r = _crypt_load_tcrypt(cd, params);
	} else if (isINTEGRITY(requested_type)) {
		if (cd->type && !isINTEGRITY(cd->type)) {
			log_dbg(cd, "Context is already initialized to type %s", cd->type);
			return -EINVAL;
		}
		r = _crypt_load_integrity(cd, params);
	} else if (isBITLK(requested_type)) {
		if (cd->type && !isBITLK(cd->type)) {
			log_dbg(cd, "Context is already initialized to type %s", cd->type);
			return -EINVAL;
		}
		r = _crypt_load_bitlk(cd, params);
	} else
		return -EINVAL;

	return r;
}

/*
 * crypt_init() helpers
 */
static int _init_by_name_crypt_none(struct crypt_device *cd)
{
	int r;
	char _mode[MAX_CIPHER_LEN];
	struct crypt_dm_active_device dmd;
	struct dm_target *tgt = &dmd.segment;

	if (cd->type || !cd->u.none.active_name)
		return -EINVAL;

	r = dm_query_device(cd, cd->u.none.active_name,
			DM_ACTIVE_CRYPT_CIPHER |
			DM_ACTIVE_CRYPT_KEYSIZE, &dmd);
	if (r < 0)
		return r;
	if (!single_segment(&dmd) || tgt->type != DM_CRYPT)
		r = -EINVAL;
	if (r >= 0)
		r = crypt_parse_name_and_mode(tgt->u.crypt.cipher,
					      cd->u.none.cipher, NULL,
					      _mode);

	if (!r) {
		snprintf(cd->u.none.cipher_spec, sizeof(cd->u.none.cipher_spec),
			 "%s-%s", cd->u.none.cipher, _mode);
		cd->u.none.cipher_mode = cd->u.none.cipher_spec + strlen(cd->u.none.cipher) + 1;
		cd->u.none.key_size = tgt->u.crypt.vk->keylength;
	}

	dm_targets_free(cd, &dmd);
	return r;
}

static const char *LUKS_UUID(struct crypt_device *cd)
{
	if (!cd)
		return NULL;
	else if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.uuid;
	else if (isLUKS2(cd->type))
		return cd->u.luks2.hdr.uuid;

	return NULL;
}

static void crypt_free_type(struct crypt_device *cd)
{
	if (isPLAIN(cd->type)) {
		free(CONST_CAST(void*)cd->u.plain.hdr.hash);
		free(cd->u.plain.cipher);
		free(cd->u.plain.cipher_spec);
	} else if (isLUKS2(cd->type)) {
		LUKS2_reenc_context_free(cd, cd->u.luks2.rh);
		LUKS2_hdr_free(cd, &cd->u.luks2.hdr);
		free(cd->u.luks2.keyslot_cipher);
	} else if (isLUKS1(cd->type)) {
		free(cd->u.luks1.cipher_spec);
	} else if (isLOOPAES(cd->type)) {
		free(CONST_CAST(void*)cd->u.loopaes.hdr.hash);
		free(cd->u.loopaes.cipher);
		free(cd->u.loopaes.cipher_spec);
	} else if (isVERITY(cd->type)) {
		free(CONST_CAST(void*)cd->u.verity.hdr.hash_name);
		free(CONST_CAST(void*)cd->u.verity.hdr.data_device);
		free(CONST_CAST(void*)cd->u.verity.hdr.hash_device);
		free(CONST_CAST(void*)cd->u.verity.hdr.fec_device);
		free(CONST_CAST(void*)cd->u.verity.hdr.salt);
		free(CONST_CAST(void*)cd->u.verity.root_hash);
		free(cd->u.verity.uuid);
		device_free(cd, cd->u.verity.fec_device);
	} else if (isINTEGRITY(cd->type)) {
		free(CONST_CAST(void*)cd->u.integrity.params.integrity);
		free(CONST_CAST(void*)cd->u.integrity.params.journal_integrity);
		free(CONST_CAST(void*)cd->u.integrity.params.journal_crypt);
		crypt_free_volume_key(cd->u.integrity.journal_crypt_key);
		crypt_free_volume_key(cd->u.integrity.journal_mac_key);
	} else if (isBITLK(cd->type)) {
		free(cd->u.bitlk.cipher_spec);
		BITLK_bitlk_metadata_free(&cd->u.bitlk.params);
	} else if (!cd->type) {
		free(cd->u.none.active_name);
		cd->u.none.active_name = NULL;
	}

	crypt_set_null_type(cd);
}

static int _init_by_name_crypt(struct crypt_device *cd, const char *name)
{
	bool found = false;
	char **dep, *cipher_spec = NULL, cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN], deps_uuid_prefix[40], *deps[MAX_DM_DEPS+1] = {};
	const char *dev, *namei;
	int key_nums, r;
	struct crypt_dm_active_device dmd, dmdi = {}, dmdep = {};
	struct dm_target *tgt = &dmd.segment, *tgti = &dmdi.segment;

	r = dm_query_device(cd, name,
			DM_ACTIVE_DEVICE |
			DM_ACTIVE_UUID |
			DM_ACTIVE_CRYPT_CIPHER |
			DM_ACTIVE_CRYPT_KEYSIZE, &dmd);
	if (r < 0)
		return r;

	if (tgt->type != DM_CRYPT && tgt->type != DM_LINEAR) {
		log_dbg(cd, "Unsupported device table detected in %s.", name);
		r = -EINVAL;
		goto out;
	}

	r = -EINVAL;

	if (dmd.uuid) {
		r = snprintf(deps_uuid_prefix, sizeof(deps_uuid_prefix), CRYPT_SUBDEV "-%.32s", dmd.uuid + 6);
		if (r < 0 || (size_t)r != (sizeof(deps_uuid_prefix) - 1))
			r = -EINVAL;
	}

	if (r >= 0) {
		r = dm_device_deps(cd, name, deps_uuid_prefix, deps, ARRAY_SIZE(deps));
		if (r)
			goto out;
	}

	r = crypt_parse_name_and_mode(tgt->type == DM_LINEAR ? "null" : tgt->u.crypt.cipher, cipher,
				      &key_nums, cipher_mode);
	if (r < 0) {
		log_dbg(cd, "Cannot parse cipher and mode from active device.");
		goto out;
	}

	dep = deps;

	if (tgt->type == DM_CRYPT && tgt->u.crypt.integrity && (namei = device_dm_name(tgt->data_device))) {
		r = dm_query_device(cd, namei, DM_ACTIVE_DEVICE, &dmdi);
		if (r < 0)
			goto out;
		if (!single_segment(&dmdi) || tgti->type != DM_INTEGRITY) {
			log_dbg(cd, "Unsupported device table detected in %s.", namei);
			r = -EINVAL;
			goto out;
		}
		if (!cd->metadata_device) {
			device_free(cd, cd->device);
			MOVE_REF(cd->device, tgti->data_device);
		}
	}

	/* do not try to lookup LUKS2 header in detached header mode */
	if (!cd->metadata_device && !found) {
		while (*dep && !found) {
			r = dm_query_device(cd, *dep, DM_ACTIVE_DEVICE, &dmdep);
			if (r < 0)
				goto out;

			tgt = &dmdep.segment;

			while (tgt && !found) {
				dev = device_path(tgt->data_device);
				if (!dev) {
					tgt = tgt->next;
					continue;
				}
				if (!strstr(dev, dm_get_dir()) ||
				    !crypt_string_in(dev + strlen(dm_get_dir()) + 1, deps, ARRAY_SIZE(deps))) {
					device_free(cd, cd->device);
					MOVE_REF(cd->device, tgt->data_device);
					found = true;
				}
				tgt = tgt->next;
			}
			dep++;
			dm_targets_free(cd, &dmdep);
		}
	}

	if (asprintf(&cipher_spec, "%s-%s", cipher, cipher_mode) < 0) {
		cipher_spec = NULL;
		r = -ENOMEM;
		goto out;
	}

	tgt = &dmd.segment;
	r = 0;

	if (isPLAIN(cd->type) && single_segment(&dmd) && tgt->type == DM_CRYPT) {
		cd->u.plain.hdr.hash = NULL; /* no way to get this */
		cd->u.plain.hdr.offset = tgt->u.crypt.offset;
		cd->u.plain.hdr.skip = tgt->u.crypt.iv_offset;
		cd->u.plain.hdr.sector_size = tgt->u.crypt.sector_size;
		cd->u.plain.key_size = tgt->u.crypt.vk->keylength;
		cd->u.plain.cipher = strdup(cipher);
		MOVE_REF(cd->u.plain.cipher_spec, cipher_spec);
		cd->u.plain.cipher_mode = cd->u.plain.cipher_spec + strlen(cipher) + 1;
	} else if (isLOOPAES(cd->type) && single_segment(&dmd) && tgt->type == DM_CRYPT) {
		cd->u.loopaes.hdr.offset = tgt->u.crypt.offset;
		cd->u.loopaes.cipher = strdup(cipher);
		MOVE_REF(cd->u.loopaes.cipher_spec, cipher_spec);
		cd->u.loopaes.cipher_mode = cd->u.loopaes.cipher_spec + strlen(cipher) + 1;
		/* version 3 uses last key for IV */
		if (tgt->u.crypt.vk->keylength % key_nums)
			key_nums++;
		cd->u.loopaes.key_size = tgt->u.crypt.vk->keylength / key_nums;
	} else if (isLUKS1(cd->type) || isLUKS2(cd->type)) {
		if (crypt_metadata_device(cd)) {
			r = _crypt_load_luks(cd, cd->type, 0, 0);
			if (r < 0) {
				log_dbg(cd, "LUKS device header does not match active device.");
				crypt_set_null_type(cd);
				device_close(cd, cd->metadata_device);
				device_close(cd, cd->device);
				r = 0;
				goto out;
			}
			/* check whether UUIDs match each other */
			r = crypt_uuid_cmp(dmd.uuid, LUKS_UUID(cd));
			if (r < 0) {
				log_dbg(cd, "LUKS device header uuid: %s mismatches DM returned uuid %s",
					LUKS_UUID(cd), dmd.uuid);
				crypt_free_type(cd);
				r = 0;
				goto out;
			}
		} else {
			log_dbg(cd, "LUKS device header not available.");
			crypt_set_null_type(cd);
			r = 0;
		}
	} else if (isTCRYPT(cd->type) && single_segment(&dmd) && tgt->type == DM_CRYPT) {
		r = TCRYPT_init_by_name(cd, name, dmd.uuid, tgt, &cd->device,
					&cd->u.tcrypt.params, &cd->u.tcrypt.hdr);
	} else if (isBITLK(cd->type)) {
		r = _crypt_load_bitlk(cd, NULL);
		if (r < 0) {
			log_dbg(cd, "BITLK device header not available.");
			crypt_set_null_type(cd);
			r = 0;
		}
	}
out:
	dm_targets_free(cd, &dmd);
	dm_targets_free(cd, &dmdi);
	dm_targets_free(cd, &dmdep);
	free(CONST_CAST(void*)dmd.uuid);
	free(cipher_spec);
	dep = deps;
	while (*dep)
		free(*dep++);
	return r;
}

static int _init_by_name_verity(struct crypt_device *cd, const char *name)
{
	struct crypt_dm_active_device dmd;
	struct dm_target *tgt = &dmd.segment;
	int r;

	r = dm_query_device(cd, name,
				DM_ACTIVE_DEVICE |
				DM_ACTIVE_VERITY_HASH_DEVICE |
				DM_ACTIVE_VERITY_ROOT_HASH |
				DM_ACTIVE_VERITY_PARAMS, &dmd);
	if (r < 0)
		return r;
	if (!single_segment(&dmd) || tgt->type != DM_VERITY) {
		log_dbg(cd, "Unsupported device table detected in %s.", name);
		r = -EINVAL;
		goto out;
	}
	if (r > 0)
		r = 0;

	if (isVERITY(cd->type)) {
		cd->u.verity.uuid = NULL; // FIXME
		cd->u.verity.hdr.flags = CRYPT_VERITY_NO_HEADER; //FIXME
		cd->u.verity.hdr.data_size = tgt->u.verity.vp->data_size;
		cd->u.verity.root_hash_size = tgt->u.verity.root_hash_size;
		MOVE_REF(cd->u.verity.hdr.hash_name, tgt->u.verity.vp->hash_name);
		cd->u.verity.hdr.data_device = NULL;
		cd->u.verity.hdr.hash_device = NULL;
		cd->u.verity.hdr.data_block_size = tgt->u.verity.vp->data_block_size;
		cd->u.verity.hdr.hash_block_size = tgt->u.verity.vp->hash_block_size;
		cd->u.verity.hdr.hash_area_offset = tgt->u.verity.hash_offset;
		cd->u.verity.hdr.fec_area_offset = tgt->u.verity.fec_offset;
		cd->u.verity.hdr.hash_type = tgt->u.verity.vp->hash_type;
		cd->u.verity.hdr.flags = tgt->u.verity.vp->flags;
		cd->u.verity.hdr.salt_size = tgt->u.verity.vp->salt_size;
		MOVE_REF(cd->u.verity.hdr.salt, tgt->u.verity.vp->salt);
		MOVE_REF(cd->u.verity.hdr.fec_device, tgt->u.verity.vp->fec_device);
		cd->u.verity.hdr.fec_roots = tgt->u.verity.vp->fec_roots;
		MOVE_REF(cd->u.verity.fec_device, tgt->u.verity.fec_device);
		MOVE_REF(cd->metadata_device, tgt->u.verity.hash_device);
		MOVE_REF(cd->u.verity.root_hash, tgt->u.verity.root_hash);
	}
out:
	dm_targets_free(cd, &dmd);
	return r;
}

static int _init_by_name_integrity(struct crypt_device *cd, const char *name)
{
	struct crypt_dm_active_device dmd;
	struct dm_target *tgt = &dmd.segment;
	int r;

	r = dm_query_device(cd, name, DM_ACTIVE_DEVICE |
				      DM_ACTIVE_CRYPT_KEY |
				      DM_ACTIVE_CRYPT_KEYSIZE |
				      DM_ACTIVE_INTEGRITY_PARAMS, &dmd);
	if (r < 0)
		return r;
	if (!single_segment(&dmd) || tgt->type != DM_INTEGRITY) {
		log_dbg(cd, "Unsupported device table detected in %s.", name);
		r = -EINVAL;
		goto out;
	}
	if (r > 0)
		r = 0;

	if (isINTEGRITY(cd->type)) {
		cd->u.integrity.params.tag_size = tgt->u.integrity.tag_size;
		cd->u.integrity.params.sector_size = tgt->u.integrity.sector_size;
		cd->u.integrity.params.journal_size = tgt->u.integrity.journal_size;
		cd->u.integrity.params.journal_watermark = tgt->u.integrity.journal_watermark;
		cd->u.integrity.params.journal_commit_time = tgt->u.integrity.journal_commit_time;
		cd->u.integrity.params.interleave_sectors = tgt->u.integrity.interleave_sectors;
		cd->u.integrity.params.buffer_sectors = tgt->u.integrity.buffer_sectors;
		MOVE_REF(cd->u.integrity.params.integrity, tgt->u.integrity.integrity);
		MOVE_REF(cd->u.integrity.params.journal_integrity, tgt->u.integrity.journal_integrity);
		MOVE_REF(cd->u.integrity.params.journal_crypt, tgt->u.integrity.journal_crypt);

		if (tgt->u.integrity.vk)
			cd->u.integrity.params.integrity_key_size = tgt->u.integrity.vk->keylength;
		if (tgt->u.integrity.journal_integrity_key)
			cd->u.integrity.params.journal_integrity_key_size = tgt->u.integrity.journal_integrity_key->keylength;
		if (tgt->u.integrity.journal_crypt_key)
			cd->u.integrity.params.integrity_key_size = tgt->u.integrity.journal_crypt_key->keylength;
		MOVE_REF(cd->metadata_device, tgt->u.integrity.meta_device);
	}
out:
	dm_targets_free(cd, &dmd);
	return r;
}

int crypt_init_by_name_and_header(struct crypt_device **cd,
				  const char *name,
				  const char *header_device)
{
	crypt_status_info ci;
	struct crypt_dm_active_device dmd;
	struct dm_target *tgt = &dmd.segment;
	int r;

	if (!cd || !name)
		return -EINVAL;

	log_dbg(NULL, "Allocating crypt device context by device %s.", name);

	ci = crypt_status(NULL, name);
	if (ci == CRYPT_INVALID)
		return -ENODEV;

	if (ci < CRYPT_ACTIVE) {
		log_err(NULL, _("Device %s is not active."), name);
		return -ENODEV;
	}

	r = dm_query_device(NULL, name, DM_ACTIVE_DEVICE | DM_ACTIVE_UUID, &dmd);
	if (r < 0)
		return r;

	*cd = NULL;

	if (header_device) {
		r = crypt_init(cd, header_device);
	} else {
		r = crypt_init(cd, device_path(tgt->data_device));

		/* Underlying device disappeared but mapping still active */
		if (!tgt->data_device || r == -ENOTBLK)
			log_verbose(NULL, _("Underlying device for crypt device %s disappeared."),
				    name);

		/* Underlying device is not readable but crypt mapping exists */
		if (r == -ENOTBLK)
			r = crypt_init(cd, NULL);
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
		else if (!strncmp(CRYPT_LUKS2, dmd.uuid, sizeof(CRYPT_LUKS2)-1))
			(*cd)->type = strdup(CRYPT_LUKS2);
		else if (!strncmp(CRYPT_VERITY, dmd.uuid, sizeof(CRYPT_VERITY)-1))
			(*cd)->type = strdup(CRYPT_VERITY);
		else if (!strncmp(CRYPT_TCRYPT, dmd.uuid, sizeof(CRYPT_TCRYPT)-1))
			(*cd)->type = strdup(CRYPT_TCRYPT);
		else if (!strncmp(CRYPT_INTEGRITY, dmd.uuid, sizeof(CRYPT_INTEGRITY)-1))
			(*cd)->type = strdup(CRYPT_INTEGRITY);
		else if (!strncmp(CRYPT_BITLK, dmd.uuid, sizeof(CRYPT_BITLK)-1))
			(*cd)->type = strdup(CRYPT_BITLK);
		else
			log_dbg(NULL, "Unknown UUID set, some parameters are not set.");
	} else
		log_dbg(NULL, "Active device has no UUID set, some parameters are not set.");

	if (header_device) {
		r = crypt_set_data_device(*cd, device_path(tgt->data_device));
		if (r < 0)
			goto out;
	}

	/* Try to initialize basic parameters from active device */

	if (tgt->type == DM_CRYPT || tgt->type == DM_LINEAR)
		r = _init_by_name_crypt(*cd, name);
	else if (tgt->type == DM_VERITY)
		r = _init_by_name_verity(*cd, name);
	else if (tgt->type == DM_INTEGRITY)
		r = _init_by_name_integrity(*cd, name);
out:
	if (r < 0) {
		crypt_free(*cd);
		*cd = NULL;
	} else if (!(*cd)->type) {
		/* For anonymous device (no header found) remember initialized name */
		(*cd)->u.none.active_name = strdup(name);
	}

	free(CONST_CAST(void*)dmd.uuid);
	dm_targets_free(NULL, &dmd);
	return r;
}

int crypt_init_by_name(struct crypt_device **cd, const char *name)
{
	return crypt_init_by_name_and_header(cd, name, NULL);
}

/*
 * crypt_format() helpers
 */
static int _crypt_format_plain(struct crypt_device *cd,
			       const char *cipher,
			       const char *cipher_mode,
			       const char *uuid,
			       size_t volume_key_size,
			       struct crypt_params_plain *params)
{
	unsigned int sector_size = params ? params->sector_size : SECTOR_SIZE;
	uint64_t dev_size;

	if (!cipher || !cipher_mode) {
		log_err(cd, _("Invalid plain crypt parameters."));
		return -EINVAL;
	}

	if (volume_key_size > 1024) {
		log_err(cd, _("Invalid key size."));
		return -EINVAL;
	}

	if (uuid) {
		log_err(cd, _("UUID is not supported for this crypt type."));
		return -EINVAL;
	}

	if (cd->metadata_device) {
		log_err(cd, _("Detached metadata device is not supported for this crypt type."));
		return -EINVAL;
	}

	/* For compatibility with old params structure */
	if (!sector_size)
		sector_size = SECTOR_SIZE;

	if (sector_size < SECTOR_SIZE || sector_size > MAX_SECTOR_SIZE ||
	    NOTPOW2(sector_size)) {
		log_err(cd, _("Unsupported encryption sector size."));
		return -EINVAL;
	}

	if (sector_size > SECTOR_SIZE && !device_size(cd->device, &dev_size)) {
		if (params && params->offset)
			dev_size -= (params->offset * SECTOR_SIZE);
		if (dev_size % sector_size) {
			log_err(cd, _("Device size is not aligned to requested sector size."));
			return -EINVAL;
		}
	}

	if (!(cd->type = strdup(CRYPT_PLAIN)))
		return -ENOMEM;

	cd->u.plain.key_size = volume_key_size;
	cd->volume_key = crypt_alloc_volume_key(volume_key_size, NULL);
	if (!cd->volume_key)
		return -ENOMEM;

	if (asprintf(&cd->u.plain.cipher_spec, "%s-%s", cipher, cipher_mode) < 0) {
		cd->u.plain.cipher_spec = NULL;
		return -ENOMEM;
	}
	cd->u.plain.cipher = strdup(cipher);
	cd->u.plain.cipher_mode = cd->u.plain.cipher_spec + strlen(cipher) + 1;

	if (params && params->hash)
		cd->u.plain.hdr.hash = strdup(params->hash);

	cd->u.plain.hdr.offset = params ? params->offset : 0;
	cd->u.plain.hdr.skip = params ? params->skip : 0;
	cd->u.plain.hdr.size = params ? params->size : 0;
	cd->u.plain.hdr.sector_size = sector_size;

	if (!cd->u.plain.cipher)
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
	uint64_t dev_size;

	if (!cipher || !cipher_mode)
		return -EINVAL;

	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format LUKS without device."));
		return -EINVAL;
	}

	if (params && cd->data_offset && params->data_alignment &&
	   (cd->data_offset % params->data_alignment)) {
		log_err(cd, _("Requested data alignment is not compatible with data offset."));
		return -EINVAL;
	}

	if (!(cd->type = strdup(CRYPT_LUKS1)))
		return -ENOMEM;

	if (volume_key)
		cd->volume_key = crypt_alloc_volume_key(volume_key_size,
						      volume_key);
	else
		cd->volume_key = crypt_generate_volume_key(cd, volume_key_size);

	if (!cd->volume_key)
		return -ENOMEM;

	if (verify_pbkdf_params(cd, &cd->pbkdf)) {
		r = init_pbkdf_type(cd, NULL, CRYPT_LUKS1);
		if (r)
			return r;
	}

	if (params && params->hash && strcmp(params->hash, cd->pbkdf.hash)) {
		free(CONST_CAST(void*)cd->pbkdf.hash);
		cd->pbkdf.hash = strdup(params->hash);
		if (!cd->pbkdf.hash)
			return -ENOMEM;
	}

	if (params && params->data_device) {
		if (!cd->metadata_device)
			cd->metadata_device = cd->device;
		else
			device_free(cd, cd->device);
		cd->device = NULL;
		if (device_alloc(cd, &cd->device, params->data_device) < 0)
			return -ENOMEM;
	}

	if (params && cd->metadata_device) {
		/* For detached header the alignment is used directly as data offset */
		if (!cd->data_offset)
			cd->data_offset = params->data_alignment;
		required_alignment = params->data_alignment * SECTOR_SIZE;
	} else if (params && params->data_alignment) {
		required_alignment = params->data_alignment * SECTOR_SIZE;
	} else
		device_topology_alignment(cd, cd->device,
				       &required_alignment,
				       &alignment_offset, DEFAULT_DISK_ALIGNMENT);

	r = LUKS_check_cipher(cd, volume_key_size, cipher, cipher_mode);
	if (r < 0)
		return r;

	r = LUKS_generate_phdr(&cd->u.luks1.hdr, cd->volume_key, cipher, cipher_mode,
			       cd->pbkdf.hash, uuid,
			       cd->data_offset * SECTOR_SIZE,
			       alignment_offset, required_alignment, cd);
	if (r < 0)
		return r;

	r = device_check_access(cd, crypt_metadata_device(cd), DEV_EXCL);
	if (r < 0)
		return r;

	if (!device_size(crypt_data_device(cd), &dev_size) &&
	    dev_size < (crypt_get_data_offset(cd) * SECTOR_SIZE))
		log_std(cd, _("WARNING: Data offset is outside of currently available data device.\n"));

	if (asprintf(&cd->u.luks1.cipher_spec, "%s-%s", cipher, cipher_mode) < 0) {
		cd->u.luks1.cipher_spec = NULL;
		return -ENOMEM;
	}

	r = LUKS_wipe_header_areas(&cd->u.luks1.hdr, cd);
	if (r < 0) {
		free(cd->u.luks1.cipher_spec);
		log_err(cd, _("Cannot wipe header on device %s."),
			mdata_device_path(cd));
		return r;
	}

	r = LUKS_write_phdr(&cd->u.luks1.hdr, cd);
	if (r)
		free(cd->u.luks1.cipher_spec);

	return r;
}

static int _crypt_format_luks2(struct crypt_device *cd,
			       const char *cipher,
			       const char *cipher_mode,
			       const char *uuid,
			       const char *volume_key,
			       size_t volume_key_size,
			       struct crypt_params_luks2 *params)
{
	int r, integrity_key_size = 0;
	unsigned long required_alignment = DEFAULT_DISK_ALIGNMENT;
	unsigned long alignment_offset = 0;
	unsigned int sector_size = params ? params->sector_size : SECTOR_SIZE;
	const char *integrity = params ? params->integrity : NULL;
	uint64_t dev_size;
	uint32_t dmc_flags;

	cd->u.luks2.hdr.jobj = NULL;
	cd->u.luks2.keyslot_cipher = NULL;

	if (!cipher || !cipher_mode)
		return -EINVAL;

	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format LUKS without device."));
		return -EINVAL;
	}

	if (params && cd->data_offset && params->data_alignment &&
	   (cd->data_offset % params->data_alignment)) {
		log_err(cd, _("Requested data alignment is not compatible with data offset."));
		return -EINVAL;
	}

	if (sector_size < SECTOR_SIZE || sector_size > MAX_SECTOR_SIZE ||
	    NOTPOW2(sector_size)) {
		log_err(cd, _("Unsupported encryption sector size."));
		return -EINVAL;
	}
	if (sector_size != SECTOR_SIZE && !dm_flags(cd, DM_CRYPT, &dmc_flags) &&
	    !(dmc_flags & DM_SECTOR_SIZE_SUPPORTED))
		log_std(cd, _("WARNING: The device activation will fail, dm-crypt is missing "
			      "support for requested encryption sector size.\n"));

	if (integrity) {
		if (params->integrity_params) {
			/* Standalone dm-integrity must not be used */
			if (params->integrity_params->integrity ||
			    params->integrity_params->integrity_key_size)
				return -EINVAL;
			/* FIXME: journal encryption and MAC is here not yet supported */
			if (params->integrity_params->journal_crypt ||
			params->integrity_params->journal_integrity)
				return -ENOTSUP;
		}
		if (!INTEGRITY_tag_size(cd, integrity, cipher, cipher_mode)) {
			if (!strcmp(integrity, "none"))
				integrity = NULL;
			else
				return -EINVAL;
		}
		integrity_key_size = INTEGRITY_key_size(cd, integrity);
		if ((integrity_key_size < 0) || (integrity_key_size >= (int)volume_key_size)) {
			log_err(cd, _("Volume key is too small for encryption with integrity extensions."));
			return -EINVAL;
		}
	}

	r = device_check_access(cd, crypt_metadata_device(cd), DEV_EXCL);
	if (r < 0)
		return r;

	if (!(cd->type = strdup(CRYPT_LUKS2)))
		return -ENOMEM;

	if (volume_key)
		cd->volume_key = crypt_alloc_volume_key(volume_key_size,
						      volume_key);
	else
		cd->volume_key = crypt_generate_volume_key(cd, volume_key_size);

	if (!cd->volume_key)
		return -ENOMEM;

	if (params && params->pbkdf)
		r = crypt_set_pbkdf_type(cd, params->pbkdf);
	else if (verify_pbkdf_params(cd, &cd->pbkdf))
		r = init_pbkdf_type(cd, NULL, CRYPT_LUKS2);

	if (r < 0)
		return r;

	if (params && params->data_device) {
		if (!cd->metadata_device)
			cd->metadata_device = cd->device;
		else
			device_free(cd, cd->device);
		cd->device = NULL;
		if (device_alloc(cd, &cd->device, params->data_device) < 0)
			return -ENOMEM;
	}

	if (params && cd->metadata_device) {
		/* For detached header the alignment is used directly as data offset */
		if (!cd->data_offset)
			cd->data_offset = params->data_alignment;
		required_alignment = params->data_alignment * SECTOR_SIZE;
	} else if (params && params->data_alignment) {
		required_alignment = params->data_alignment * SECTOR_SIZE;
	} else
		device_topology_alignment(cd, cd->device,
				       &required_alignment,
				       &alignment_offset, DEFAULT_DISK_ALIGNMENT);

	/* FIXME: allow this later also for normal ciphers (check AF_ALG availability. */
	if (integrity && !integrity_key_size) {
		r = crypt_cipher_check_kernel(cipher, cipher_mode, integrity, volume_key_size);
		if (r < 0) {
			log_err(cd, _("Cipher %s-%s (key size %zd bits) is not available."),
				cipher, cipher_mode, volume_key_size * 8);
			goto out;
		}
	}

	if ((!integrity || integrity_key_size) && !crypt_cipher_wrapped_key(cipher, cipher_mode) &&
	    !INTEGRITY_tag_size(cd, NULL, cipher, cipher_mode)) {
		r = LUKS_check_cipher(cd, volume_key_size - integrity_key_size,
				      cipher, cipher_mode);
		if (r < 0)
			goto out;
	}

	r = LUKS2_generate_hdr(cd, &cd->u.luks2.hdr, cd->volume_key,
			       cipher, cipher_mode,
			       integrity, uuid,
			       sector_size,
			       cd->data_offset * SECTOR_SIZE,
			       alignment_offset,
			       required_alignment,
			       cd->metadata_size, cd->keyslots_size);
	if (r < 0)
		goto out;

	r = device_size(crypt_data_device(cd), &dev_size);
	if (r < 0)
		goto out;

	if (dev_size < (crypt_get_data_offset(cd) * SECTOR_SIZE))
		log_std(cd, _("WARNING: Data offset is outside of currently available data device.\n"));

	if (cd->metadata_size && (cd->metadata_size != LUKS2_metadata_size(cd->u.luks2.hdr.jobj)))
		log_std(cd, _("WARNING: LUKS2 metadata size changed to %" PRIu64 " bytes.\n"),
			LUKS2_metadata_size(cd->u.luks2.hdr.jobj));

	if (cd->keyslots_size && (cd->keyslots_size != LUKS2_keyslots_size(cd->u.luks2.hdr.jobj)))
		log_std(cd, _("WARNING: LUKS2 keyslots area size changed to %" PRIu64 " bytes.\n"),
			LUKS2_keyslots_size(cd->u.luks2.hdr.jobj));

	if (!integrity && sector_size > SECTOR_SIZE) {
		dev_size -= (crypt_get_data_offset(cd) * SECTOR_SIZE);
		if (dev_size % sector_size) {
			log_err(cd, _("Device size is not aligned to requested sector size."));
			r = -EINVAL;
			goto out;
		}
	}

	if (params && (params->label || params->subsystem)) {
		r = LUKS2_hdr_labels(cd, &cd->u.luks2.hdr,
				     params->label, params->subsystem, 0);
		if (r < 0)
			goto out;
	}

	r = LUKS2_wipe_header_areas(cd, &cd->u.luks2.hdr);
	if (r < 0) {
		log_err(cd, _("Cannot wipe header on device %s."),
			mdata_device_path(cd));
		if (dev_size < LUKS2_hdr_and_areas_size(cd->u.luks2.hdr.jobj))
			log_err(cd, _("Device %s is too small."), device_path(crypt_metadata_device(cd)));
		goto out;
	}

	/* Wipe integrity superblock and create integrity superblock */
	if (crypt_get_integrity_tag_size(cd)) {
		r = crypt_wipe_device(cd, crypt_data_device(cd), CRYPT_WIPE_ZERO,
				      crypt_get_data_offset(cd) * SECTOR_SIZE,
				      8 * SECTOR_SIZE, 8 * SECTOR_SIZE, NULL, NULL);
		if (r < 0) {
			if (r == -EBUSY)
				log_err(cd, _("Cannot format device %s in use."),
					data_device_path(cd));
			else if (r == -EACCES) {
				log_err(cd, _("Cannot format device %s, permission denied."),
					data_device_path(cd));
				r = -EINVAL;
			} else
				log_err(cd, _("Cannot wipe header on device %s."),
					data_device_path(cd));

			goto out;
		}

		r = INTEGRITY_format(cd, params ? params->integrity_params : NULL, NULL, NULL);
		if (r)
			log_err(cd, _("Cannot format integrity for device %s."),
				data_device_path(cd));
	}

	if (r < 0)
		goto out;

	/* override sequence id check with format */
	r = LUKS2_hdr_write_force(cd, &cd->u.luks2.hdr);
	if (r < 0) {
		if (r == -EBUSY)
			log_err(cd, _("Cannot format device %s in use."),
				mdata_device_path(cd));
		else if (r == -EACCES) {
			log_err(cd, _("Cannot format device %s, permission denied."),
				mdata_device_path(cd));
			r = -EINVAL;
		} else
			log_err(cd, _("Cannot format device %s."),
				mdata_device_path(cd));
	}

out:
	if (r)
		LUKS2_hdr_free(cd, &cd->u.luks2.hdr);

	return r;
}

static int _crypt_format_loopaes(struct crypt_device *cd,
				 const char *cipher,
				 const char *uuid,
				 size_t volume_key_size,
				 struct crypt_params_loopaes *params)
{
	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format LOOPAES without device."));
		return -EINVAL;
	}

	if (volume_key_size > 1024) {
		log_err(cd, _("Invalid key size."));
		return -EINVAL;
	}

	if (uuid) {
		log_err(cd, _("UUID is not supported for this crypt type."));
		return -EINVAL;
	}

	if (cd->metadata_device) {
		log_err(cd, _("Detached metadata device is not supported for this crypt type."));
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
	uint64_t data_device_size, hash_blocks_size;
	struct device *fec_device = NULL;
	char *fec_device_path = NULL, *hash_name = NULL, *root_hash = NULL, *salt = NULL;

	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format VERITY without device."));
		return -EINVAL;
	}

	if (!params)
		return -EINVAL;

	if (!params->data_device && !cd->metadata_device)
		return -EINVAL;

	if (params->hash_type > VERITY_MAX_HASH_TYPE) {
		log_err(cd, _("Unsupported VERITY hash type %d."), params->hash_type);
		return -EINVAL;
	}

	if (VERITY_BLOCK_SIZE_OK(params->data_block_size) ||
	    VERITY_BLOCK_SIZE_OK(params->hash_block_size)) {
		log_err(cd, _("Unsupported VERITY block size."));
		return -EINVAL;
	}

	if (MISALIGNED_512(params->hash_area_offset)) {
		log_err(cd, _("Unsupported VERITY hash offset."));
		return -EINVAL;
	}

	if (MISALIGNED_512(params->fec_area_offset)) {
		log_err(cd, _("Unsupported VERITY FEC offset."));
		return -EINVAL;
	}

	if (!(cd->type = strdup(CRYPT_VERITY)))
		return -ENOMEM;

	if (params->data_device) {
		r = crypt_set_data_device(cd, params->data_device);
		if (r)
			return r;
	}

	if (!params->data_size) {
		r = device_size(cd->device, &data_device_size);
		if (r < 0)
			return r;

		cd->u.verity.hdr.data_size = data_device_size / params->data_block_size;
	} else
		cd->u.verity.hdr.data_size = params->data_size;

	if (device_is_identical(crypt_metadata_device(cd), crypt_data_device(cd)) &&
	   (cd->u.verity.hdr.data_size * params->data_block_size) > params->hash_area_offset) {
		log_err(cd, _("Data area overlaps with hash area."));
		return -EINVAL;
	}

	hash_size = crypt_hash_size(params->hash_name);
	if (hash_size <= 0) {
		log_err(cd, _("Hash algorithm %s not supported."),
			params->hash_name);
		return -EINVAL;
	}
	cd->u.verity.root_hash_size = hash_size;

	if (params->fec_device) {
		fec_device_path = strdup(params->fec_device);
		if (!fec_device_path)
			return -ENOMEM;
		r = device_alloc(cd, &fec_device, params->fec_device);
		if (r < 0) {
			r = -ENOMEM;
			goto err;
		}

		hash_blocks_size = VERITY_hash_blocks(cd, params) * params->hash_block_size;
		if (device_is_identical(crypt_metadata_device(cd), fec_device) &&
		    (params->hash_area_offset + hash_blocks_size) > params->fec_area_offset) {
			log_err(cd, _("Hash area overlaps with FEC area."));
			r = -EINVAL;
			goto err;
		}

		if (device_is_identical(crypt_data_device(cd), fec_device) &&
		    (cd->u.verity.hdr.data_size * params->data_block_size) > params->fec_area_offset) {
			log_err(cd, _("Data area overlaps with FEC area."));
			r = -EINVAL;
			goto err;
		}
	}

	root_hash = malloc(cd->u.verity.root_hash_size);
	hash_name = strdup(params->hash_name);
	salt = malloc(params->salt_size);

	if (!root_hash || !hash_name || !salt) {
		r = -ENOMEM;
		goto err;
	}

	cd->u.verity.hdr.flags = params->flags;
	cd->u.verity.root_hash = root_hash;
	cd->u.verity.hdr.hash_name = hash_name;
	cd->u.verity.hdr.data_device = NULL;
	cd->u.verity.fec_device = fec_device;
	cd->u.verity.hdr.fec_device = fec_device_path;
	cd->u.verity.hdr.fec_roots = params->fec_roots;
	cd->u.verity.hdr.data_block_size = params->data_block_size;
	cd->u.verity.hdr.hash_block_size = params->hash_block_size;
	cd->u.verity.hdr.hash_area_offset = params->hash_area_offset;
	cd->u.verity.hdr.fec_area_offset = params->fec_area_offset;
	cd->u.verity.hdr.hash_type = params->hash_type;
	cd->u.verity.hdr.flags = params->flags;
	cd->u.verity.hdr.salt_size = params->salt_size;
	cd->u.verity.hdr.salt = salt;

	if (params->salt)
		memcpy(salt, params->salt, params->salt_size);
	else
		r = crypt_random_get(cd, salt, params->salt_size, CRYPT_RND_SALT);
	if (r)
		goto err;

	if (params->flags & CRYPT_VERITY_CREATE_HASH) {
		r = VERITY_create(cd, &cd->u.verity.hdr,
				  cd->u.verity.root_hash, cd->u.verity.root_hash_size);
		if (!r && params->fec_device)
			r = VERITY_FEC_process(cd, &cd->u.verity.hdr, cd->u.verity.fec_device, 0, NULL);
		if (r)
			goto err;
	}

	if (!(params->flags & CRYPT_VERITY_NO_HEADER)) {
		if (uuid) {
			if (!(cd->u.verity.uuid = strdup(uuid)))
				r = -ENOMEM;
		} else
			r = VERITY_UUID_generate(cd, &cd->u.verity.uuid);

		if (!r)
			r = VERITY_write_sb(cd, cd->u.verity.hdr.hash_area_offset,
					    cd->u.verity.uuid,
					    &cd->u.verity.hdr);
	}

err:
	if (r) {
		device_free(cd, fec_device);
		free(root_hash);
		free(hash_name);
		free(fec_device_path);
		free(salt);
	}

	return r;
}

static int _crypt_format_integrity(struct crypt_device *cd,
				   const char *uuid,
				   struct crypt_params_integrity *params)
{
	int r;
	uint32_t integrity_tag_size;
	char *integrity = NULL, *journal_integrity = NULL, *journal_crypt = NULL;
	struct volume_key *journal_crypt_key = NULL, *journal_mac_key = NULL;

	if (!params)
		return -EINVAL;

	if (uuid) {
		log_err(cd, _("UUID is not supported for this crypt type."));
		return -EINVAL;
	}

	r = device_check_access(cd, crypt_metadata_device(cd), DEV_EXCL);
	if (r < 0)
		return r;

	/* Wipe first 8 sectors - fs magic numbers etc. */
	r = crypt_wipe_device(cd, crypt_metadata_device(cd), CRYPT_WIPE_ZERO, 0,
			      8 * SECTOR_SIZE, 8 * SECTOR_SIZE, NULL, NULL);
	if (r < 0) {
		log_err(cd, _("Cannot wipe header on device %s."),
			mdata_device_path(cd));
		return r;
	}

	if (!(cd->type = strdup(CRYPT_INTEGRITY)))
		return -ENOMEM;

	if (params->journal_crypt_key) {
		journal_crypt_key = crypt_alloc_volume_key(params->journal_crypt_key_size,
							   params->journal_crypt_key);
		if (!journal_crypt_key)
			return -ENOMEM;
	}

	if (params->journal_integrity_key) {
		journal_mac_key = crypt_alloc_volume_key(params->journal_integrity_key_size,
							 params->journal_integrity_key);
		if (!journal_mac_key) {
			r = -ENOMEM;
			goto err;
		}
	}

	if (params->integrity && !(integrity = strdup(params->integrity))) {
		r = -ENOMEM;
		goto err;
	}
	if (params->journal_integrity && !(journal_integrity = strdup(params->journal_integrity))) {
		r = -ENOMEM;
		goto err;
	}
	if (params->journal_crypt && !(journal_crypt = strdup(params->journal_crypt))) {
		r = -ENOMEM;
		goto err;
	}

	integrity_tag_size = INTEGRITY_hash_tag_size(integrity);
	if (integrity_tag_size > 0 && params->tag_size && integrity_tag_size != params->tag_size)
		log_std(cd, _("WARNING: Requested tag size %d bytes differs from %s size output (%d bytes).\n"),
			params->tag_size, integrity, integrity_tag_size);

	if (params->tag_size)
		integrity_tag_size = params->tag_size;

	cd->u.integrity.journal_crypt_key = journal_crypt_key;
	cd->u.integrity.journal_mac_key = journal_mac_key;
	cd->u.integrity.params.journal_size = params->journal_size;
	cd->u.integrity.params.journal_watermark = params->journal_watermark;
	cd->u.integrity.params.journal_commit_time = params->journal_commit_time;
	cd->u.integrity.params.interleave_sectors = params->interleave_sectors;
	cd->u.integrity.params.buffer_sectors = params->buffer_sectors;
	cd->u.integrity.params.sector_size = params->sector_size;
	cd->u.integrity.params.tag_size = integrity_tag_size;
	cd->u.integrity.params.integrity = integrity;
	cd->u.integrity.params.journal_integrity = journal_integrity;
	cd->u.integrity.params.journal_crypt = journal_crypt;

	r = INTEGRITY_format(cd, params, cd->u.integrity.journal_crypt_key, cd->u.integrity.journal_mac_key);
	if (r)
		log_err(cd, _("Cannot format integrity for device %s."),
			mdata_device_path(cd));
err:
	if (r) {
		crypt_free_volume_key(journal_crypt_key);
		crypt_free_volume_key(journal_mac_key);
		free(integrity);
		free(journal_integrity);
		free(journal_crypt);
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

	if (!cd || !type)
		return -EINVAL;

	if (cd->type) {
		log_dbg(cd, "Context already formatted as %s.", cd->type);
		return -EINVAL;
	}

	log_dbg(cd, "Formatting device %s as type %s.", mdata_device_path(cd) ?: "(none)", type);

	crypt_reset_null_type(cd);

	r = init_crypto(cd);
	if (r < 0)
		return r;

	if (isPLAIN(type))
		r = _crypt_format_plain(cd, cipher, cipher_mode,
					uuid, volume_key_size, params);
	else if (isLUKS1(type))
		r = _crypt_format_luks1(cd, cipher, cipher_mode,
					uuid, volume_key, volume_key_size, params);
	else if (isLUKS2(type))
		r = _crypt_format_luks2(cd, cipher, cipher_mode,
					uuid, volume_key, volume_key_size, params);
	else if (isLOOPAES(type))
		r = _crypt_format_loopaes(cd, cipher, uuid, volume_key_size, params);
	else if (isVERITY(type))
		r = _crypt_format_verity(cd, uuid, params);
	else if (isINTEGRITY(type))
		r = _crypt_format_integrity(cd, uuid, params);
	else {
		log_err(cd, _("Unknown crypt device type %s requested."), type);
		r = -EINVAL;
	}

	if (r < 0) {
		crypt_set_null_type(cd);
		crypt_free_volume_key(cd->volume_key);
		cd->volume_key = NULL;
	}

	return r;
}

int crypt_repair(struct crypt_device *cd,
		 const char *requested_type,
		 void *params __attribute__((unused)))
{
	int r;

	if (!cd)
		return -EINVAL;

	log_dbg(cd, "Trying to repair %s crypt type from device %s.",
		requested_type ?: "any", mdata_device_path(cd) ?: "(none)");

	if (!crypt_metadata_device(cd))
		return -EINVAL;

	if (requested_type && !isLUKS(requested_type))
		return -EINVAL;

	/* Load with repair */
	r = _crypt_load_luks(cd, requested_type, 1, 1);
	if (r < 0)
		return r;

	/* cd->type and header must be set in context */
	r = crypt_check_data_device_size(cd);
	if (r < 0)
		crypt_set_null_type(cd);

	return r;
}

/* compare volume keys */
static int _compare_volume_keys(struct volume_key *svk, unsigned skeyring_only, struct volume_key *tvk, unsigned tkeyring_only)
{
	if (!svk && !tvk)
		return 0;
	else if (!svk || !tvk)
		return 1;

	if (svk->keylength != tvk->keylength)
		return 1;

	if (!skeyring_only && !tkeyring_only)
		return memcmp(svk->key, tvk->key, svk->keylength);

	if (svk->key_description && tvk->key_description)
		return strcmp(svk->key_description, tvk->key_description);

	return 0;
}

static int _compare_device_types(struct crypt_device *cd,
			       const struct crypt_dm_active_device *src,
			       const struct crypt_dm_active_device *tgt)
{
	if (!tgt->uuid) {
		log_dbg(cd, "Missing device uuid in target device.");
		return -EINVAL;
	}

	if (isLUKS2(cd->type) && !strncmp("INTEGRITY-", tgt->uuid, strlen("INTEGRITY-"))) {
		if (crypt_uuid_cmp(tgt->uuid, src->uuid)) {
			log_dbg(cd, "LUKS UUID mismatch.");
			return -EINVAL;
		}
	} else if (isLUKS(cd->type)) {
		if (!src->uuid || strncmp(cd->type, tgt->uuid, strlen(cd->type)) ||
		    crypt_uuid_cmp(tgt->uuid, src->uuid)) {
			log_dbg(cd, "LUKS UUID mismatch.");
			return -EINVAL;
		}
	} else if (isPLAIN(cd->type) || isLOOPAES(cd->type)) {
		if (strncmp(cd->type, tgt->uuid, strlen(cd->type))) {
			log_dbg(cd, "Unexpected uuid prefix %s in target device.", tgt->uuid);
			return -EINVAL;
		}
	} else {
		log_dbg(cd, "Unsupported device type %s for reload.", cd->type ?: "<empty>");
		return -ENOTSUP;
	}

	return 0;
}

static int _compare_crypt_devices(struct crypt_device *cd,
			       const struct dm_target *src,
			       const struct dm_target *tgt)
{
	/* for crypt devices keys are mandatory */
	if (!src->u.crypt.vk || !tgt->u.crypt.vk)
		return -EINVAL;

	if (_compare_volume_keys(src->u.crypt.vk, 0, tgt->u.crypt.vk, tgt->u.crypt.vk->key_description != NULL)) {
		log_dbg(cd, "Keys in context and target device do not match.");
		return -EINVAL;
	}

	/* CIPHER checks */
	if (!src->u.crypt.cipher || !tgt->u.crypt.cipher)
		return -EINVAL;
	if (strcmp(src->u.crypt.cipher, tgt->u.crypt.cipher)) {
		log_dbg(cd, "Cipher specs do not match.");
		return -EINVAL;
	}
	if (crypt_strcmp(src->u.crypt.integrity, tgt->u.crypt.integrity)) {
		log_dbg(cd, "Integrity parameters do not match.");
		return -EINVAL;
	}

	if (src->u.crypt.offset      != tgt->u.crypt.offset ||
	    src->u.crypt.sector_size != tgt->u.crypt.sector_size ||
	    src->u.crypt.iv_offset   != tgt->u.crypt.iv_offset ||
	    src->u.crypt.tag_size    != tgt->u.crypt.tag_size) {
		log_dbg(cd, "Integer parameters do not match.");
		return -EINVAL;
	}

	if (!device_is_identical(src->data_device, tgt->data_device)) {
		log_dbg(cd, "Data devices do not match.");
		return -EINVAL;
	}

	return 0;
}

static int _compare_integrity_devices(struct crypt_device *cd,
			       const struct dm_target *src,
			       const struct dm_target *tgt)
{
	/*
	 * some parameters may be implicit (and set in dm-integrity ctor)
	 *
	 *	journal_size
	 *	journal_watermark
	 *	journal_commit_time
	 *	buffer_sectors
	 *	interleave_sectors
	 */

	/* check remaining integer values that makes sense */
	if (src->u.integrity.tag_size	  != tgt->u.integrity.tag_size ||
	    src->u.integrity.offset	  != tgt->u.integrity.offset   ||
	    src->u.integrity.sector_size  != tgt->u.integrity.sector_size) {
		log_dbg(cd, "Integer parameters do not match.");
		return -EINVAL;
	}

	if (crypt_strcmp(src->u.integrity.integrity,	     tgt->u.integrity.integrity) ||
	    crypt_strcmp(src->u.integrity.journal_integrity, tgt->u.integrity.journal_integrity) ||
	    crypt_strcmp(src->u.integrity.journal_crypt,     tgt->u.integrity.journal_crypt)) {
		log_dbg(cd, "Journal parameters do not match.");
		return -EINVAL;
	}

	/* unfortunately dm-integrity doesn't support keyring */
	if (_compare_volume_keys(src->u.integrity.vk, 0, tgt->u.integrity.vk, 0) ||
	    _compare_volume_keys(src->u.integrity.journal_integrity_key, 0, tgt->u.integrity.journal_integrity_key, 0) ||
	    _compare_volume_keys(src->u.integrity.journal_crypt_key, 0, tgt->u.integrity.journal_crypt_key, 0)) {
		log_dbg(cd, "Journal keys do not match.");
		return -EINVAL;
	}

	/* unsupported underneath dm-crypt with auth. encryption */
	if (src->u.integrity.meta_device || tgt->u.integrity.meta_device)
		return -ENOTSUP;

	if (src->size != tgt->size) {
		log_dbg(cd, "Device size parameters do not match.");
		return -EINVAL;
	}

	if (!device_is_identical(src->data_device, tgt->data_device)) {
		log_dbg(cd, "Data devices do not match.");
		return -EINVAL;
	}

	return 0;
}

int crypt_compare_dm_devices(struct crypt_device *cd,
			       const struct crypt_dm_active_device *src,
			       const struct crypt_dm_active_device *tgt)
{
	int r;
	const struct dm_target *s, *t;

	if (!src || !tgt)
		return -EINVAL;

	r = _compare_device_types(cd, src, tgt);
	if (r)
		return r;

	s = &src->segment;
	t = &tgt->segment;

	while (s || t) {
		if (!s || !t) {
			log_dbg(cd, "segments count mismatch.");
			return -EINVAL;
		}
		if (s->type != t->type) {
			log_dbg(cd, "segment type mismatch.");
			r = -EINVAL;
			break;
		}

		switch (s->type) {
		case DM_CRYPT:
			r = _compare_crypt_devices(cd, s, t);
			break;
		case DM_INTEGRITY:
			r = _compare_integrity_devices(cd, s, t);
			break;
		case DM_LINEAR:
			r = (s->u.linear.offset == t->u.linear.offset) ? 0 : -EINVAL;
			break;
		default:
			r = -ENOTSUP;
		}

		if (r)
			break;

		s = s->next;
		t = t->next;
	}

	return r;
}

static int _reload_device(struct crypt_device *cd, const char *name,
			  struct crypt_dm_active_device *sdmd)
{
	int r;
	struct crypt_dm_active_device tdmd;
	struct dm_target *src, *tgt = &tdmd.segment;

	if (!cd || !cd->type || !name || !(sdmd->flags & CRYPT_ACTIVATE_REFRESH))
		return -EINVAL;

	r = dm_query_device(cd, name, DM_ACTIVE_DEVICE | DM_ACTIVE_CRYPT_CIPHER |
				  DM_ACTIVE_UUID | DM_ACTIVE_CRYPT_KEYSIZE |
				  DM_ACTIVE_CRYPT_KEY, &tdmd);
	if (r < 0) {
		log_err(cd, _("Device %s is not active."), name);
		return -EINVAL;
	}

	if (!single_segment(&tdmd) || tgt->type != DM_CRYPT || tgt->u.crypt.tag_size) {
		r = -ENOTSUP;
		log_err(cd, _("Unsupported parameters on device %s."), name);
		goto out;
	}

	r = crypt_compare_dm_devices(cd, sdmd, &tdmd);
	if (r) {
		log_err(cd, _("Mismatching parameters on device %s."), name);
		goto out;
	}

	src = &sdmd->segment;

	/* Changing read only flag for active device makes no sense */
	if (tdmd.flags & CRYPT_ACTIVATE_READONLY)
		sdmd->flags |= CRYPT_ACTIVATE_READONLY;
	else
		sdmd->flags &= ~CRYPT_ACTIVATE_READONLY;

	if (sdmd->flags & CRYPT_ACTIVATE_KEYRING_KEY) {
		r = crypt_volume_key_set_description(tgt->u.crypt.vk, src->u.crypt.vk->key_description);
		if (r)
			goto out;
	} else {
		crypt_free_volume_key(tgt->u.crypt.vk);
		tgt->u.crypt.vk = crypt_alloc_volume_key(src->u.crypt.vk->keylength, src->u.crypt.vk->key);
		if (!tgt->u.crypt.vk) {
			r = -ENOMEM;
			goto out;
		}
	}

	r = device_block_adjust(cd, src->data_device, DEV_OK,
				src->u.crypt.offset, &sdmd->size, NULL);
	if (r)
		goto out;

	tdmd.flags = sdmd->flags;
	tgt->size = tdmd.size = sdmd->size;

	r = dm_reload_device(cd, name, &tdmd, 0, 1);
out:
	dm_targets_free(cd, &tdmd);
	free(CONST_CAST(void*)tdmd.uuid);

	return r;
}

static int _reload_device_with_integrity(struct crypt_device *cd,
	const char *name,
	const char *iname,
	const char *ipath,
	struct crypt_dm_active_device *sdmd,
	struct crypt_dm_active_device *sdmdi)
{
	int r;
	struct crypt_dm_active_device tdmd, tdmdi = {};
	struct dm_target *src, *srci, *tgt = &tdmd.segment, *tgti = &tdmdi.segment;
	struct device *data_device = NULL;

	if (!cd || !cd->type || !name || !iname || !(sdmd->flags & CRYPT_ACTIVATE_REFRESH))
		return -EINVAL;

	r = dm_query_device(cd, name, DM_ACTIVE_DEVICE | DM_ACTIVE_CRYPT_CIPHER |
				  DM_ACTIVE_UUID | DM_ACTIVE_CRYPT_KEYSIZE |
				  DM_ACTIVE_CRYPT_KEY, &tdmd);
	if (r < 0) {
		log_err(cd, _("Device %s is not active."), name);
		return -EINVAL;
	}

	if (!single_segment(&tdmd) || tgt->type != DM_CRYPT || !tgt->u.crypt.tag_size) {
		r = -ENOTSUP;
		log_err(cd, _("Unsupported parameters on device %s."), name);
		goto out;
	}

	r = dm_query_device(cd, iname, DM_ACTIVE_DEVICE | DM_ACTIVE_UUID, &tdmdi);
	if (r < 0) {
		log_err(cd, _("Device %s is not active."), iname);
		r = -EINVAL;
		goto out;
	}

	if (!single_segment(&tdmdi) || tgti->type != DM_INTEGRITY) {
		r = -ENOTSUP;
		log_err(cd, _("Unsupported parameters on device %s."), iname);
		goto out;
	}

	r = crypt_compare_dm_devices(cd, sdmdi, &tdmdi);
	if (r) {
		log_err(cd, _("Mismatching parameters on device %s."), iname);
		goto out;
	}

	src = &sdmd->segment;
	srci = &sdmdi->segment;

	r = device_alloc(cd, &data_device, ipath);
	if (r < 0)
		goto out;

	r = device_block_adjust(cd, srci->data_device, DEV_OK,
				srci->u.integrity.offset, &sdmdi->size, NULL);
	if (r)
		goto out;

	src->data_device = data_device;

	r = crypt_compare_dm_devices(cd, sdmd, &tdmd);
	if (r) {
		log_err(cd, _("Crypt devices mismatch."));
		goto out;
	}

	/* Changing read only flag for active device makes no sense */
	if (tdmd.flags & CRYPT_ACTIVATE_READONLY)
		sdmd->flags |= CRYPT_ACTIVATE_READONLY;
	else
		sdmd->flags &= ~CRYPT_ACTIVATE_READONLY;

	if (tdmdi.flags & CRYPT_ACTIVATE_READONLY)
		sdmdi->flags |= CRYPT_ACTIVATE_READONLY;
	else
		sdmdi->flags &= ~CRYPT_ACTIVATE_READONLY;

	if (sdmd->flags & CRYPT_ACTIVATE_KEYRING_KEY) {
		r = crypt_volume_key_set_description(tgt->u.crypt.vk, src->u.crypt.vk->key_description);
		if (r)
			goto out;
	} else {
		crypt_free_volume_key(tgt->u.crypt.vk);
		tgt->u.crypt.vk = crypt_alloc_volume_key(src->u.crypt.vk->keylength, src->u.crypt.vk->key);
		if (!tgt->u.crypt.vk) {
			r = -ENOMEM;
			goto out;
		}
	}

	r = device_block_adjust(cd, src->data_device, DEV_OK,
				src->u.crypt.offset, &sdmd->size, NULL);
	if (r)
		goto out;

	tdmd.flags = sdmd->flags;
	tdmd.size = sdmd->size;

	if ((r = dm_reload_device(cd, iname, sdmdi, 0, 0))) {
		log_err(cd, _("Failed to reload device %s."), iname);
		goto out;
	}

	if ((r = dm_reload_device(cd, name, &tdmd, 0, 0))) {
		log_err(cd, _("Failed to reload device %s."), name);
		goto err_clear;
	}

	if ((r = dm_suspend_device(cd, name, 0))) {
		log_err(cd, _("Failed to suspend device %s."), name);
		goto err_clear;
	}

	if ((r = dm_suspend_device(cd, iname, 0))) {
		log_err(cd, _("Failed to suspend device %s."), iname);
		goto err_clear;
	}

	if ((r = dm_resume_device(cd, iname, act2dmflags(sdmdi->flags)))) {
		log_err(cd, _("Failed to resume device %s."), iname);
		goto err_clear;
	}

	r = dm_resume_device(cd, name, act2dmflags(tdmd.flags));
	if (!r)
		goto out;

	/*
	 * This is worst case scenario. We have active underlying dm-integrity device with
	 * new table but dm-crypt resume failed for some reason. Tear everything down and
	 * burn it for good.
	 */

	log_err(cd, _("Fatal error while reloading device %s (on top of device %s)."), name, iname);

	if (dm_error_device(cd, name))
		log_err(cd, _("Failed to switch device %s to dm-error."), name);
	if (dm_error_device(cd, iname))
		log_err(cd, _("Failed to switch device %s to dm-error."), iname);
	goto out;

err_clear:
	dm_clear_device(cd, name);
	dm_clear_device(cd, iname);

	if (dm_status_suspended(cd, name) > 0)
		dm_resume_device(cd, name, 0);
	if (dm_status_suspended(cd, iname) > 0)
		dm_resume_device(cd, iname, 0);
out:
	dm_targets_free(cd, &tdmd);
	dm_targets_free(cd, &tdmdi);
	free(CONST_CAST(void*)tdmdi.uuid);
	free(CONST_CAST(void*)tdmd.uuid);
	device_free(cd, data_device);

	return r;
}

int crypt_resize(struct crypt_device *cd, const char *name, uint64_t new_size)
{
	struct crypt_dm_active_device dmdq, dmd = {};
	struct dm_target *tgt = &dmdq.segment;
	int r;

	/*
	 * FIXME: Also with LUKS2 we must not allow resize when there's
	 *	  explicit size stored in metadata (length != "dynamic")
	 */

	/* Device context type must be initialized */
	if (!cd || !cd->type || !name)
		return -EINVAL;

	log_dbg(cd, "Resizing device %s to %" PRIu64 " sectors.", name, new_size);

	r = dm_query_device(cd, name, DM_ACTIVE_CRYPT_KEYSIZE | DM_ACTIVE_CRYPT_KEY, &dmdq);
	if (r < 0) {
		log_err(cd, _("Device %s is not active."), name);
		return -EINVAL;
	}
	if (!single_segment(&dmdq) || tgt->type != DM_CRYPT) {
		log_dbg(cd, "Unsupported device table detected in %s.", name);
		r = -EINVAL;
		goto out;
	}

	if ((dmdq.flags & CRYPT_ACTIVATE_KEYRING_KEY) && !crypt_key_in_keyring(cd)) {
		r = -EPERM;
		goto out;
	}

	if (crypt_key_in_keyring(cd)) {
		if (!isLUKS2(cd->type)) {
			r = -EINVAL;
			goto out;
		}
		r = LUKS2_key_description_by_segment(cd, &cd->u.luks2.hdr,
					tgt->u.crypt.vk, CRYPT_DEFAULT_SEGMENT);
		if (r)
			goto out;

		dmdq.flags |= CRYPT_ACTIVATE_KEYRING_KEY;
	}

	if (crypt_loop_device(crypt_get_device_name(cd))) {
		log_dbg(cd, "Trying to resize underlying loop device %s.",
			crypt_get_device_name(cd));
		/* Here we always use default size not new_size */
		if (crypt_loop_resize(crypt_get_device_name(cd)))
			log_err(cd, _("Cannot resize loop device."));
	}

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				crypt_get_data_offset(cd), &new_size, &dmdq.flags);
	if (r)
		goto out;

	if (MISALIGNED(new_size, tgt->u.crypt.sector_size >> SECTOR_SHIFT)) {
		log_err(cd, _("Device size is not aligned to requested sector size."));
		r = -EINVAL;
		goto out;
	}

	if (MISALIGNED(new_size, device_block_size(cd, crypt_data_device(cd)) >> SECTOR_SHIFT)) {
		log_err(cd, _("Device size is not aligned to device logical block size."));
		r = -EINVAL;
		goto out;
	}

	dmd.uuid = crypt_get_uuid(cd);
	dmd.size = new_size;
	dmd.flags = dmdq.flags | CRYPT_ACTIVATE_REFRESH;
	r = dm_crypt_target_set(&dmd.segment, 0, new_size, crypt_data_device(cd),
			tgt->u.crypt.vk, crypt_get_cipher_spec(cd),
			crypt_get_iv_offset(cd), crypt_get_data_offset(cd),
			crypt_get_integrity(cd), crypt_get_integrity_tag_size(cd),
			crypt_get_sector_size(cd));
	if (r < 0)
		goto out;

	if (new_size == dmdq.size) {
		log_dbg(cd, "Device has already requested size %" PRIu64
			" sectors.", dmdq.size);
		r = 0;
	} else {
		if (isTCRYPT(cd->type))
			r = -ENOTSUP;
		else if (isLUKS2(cd->type))
			r = LUKS2_unmet_requirements(cd, &cd->u.luks2.hdr, 0, 0);
		if (!r)
			r = _reload_device(cd, name, &dmd);
	}
out:
	dm_targets_free(cd, &dmd);
	dm_targets_free(cd, &dmdq);

	return r;
}

int crypt_set_uuid(struct crypt_device *cd, const char *uuid)
{
	const char *active_uuid;
	int r;

	log_dbg(cd, "%s device uuid.", uuid ? "Setting new" : "Refreshing");

	if ((r = onlyLUKS(cd)))
		return r;

	active_uuid = crypt_get_uuid(cd);

	if (uuid && active_uuid && !strncmp(uuid, active_uuid, UUID_STRING_L)) {
		log_dbg(cd, "UUID is the same as requested (%s) for device %s.",
			uuid, mdata_device_path(cd));
		return 0;
	}

	if (uuid)
		log_dbg(cd, "Requested new UUID change to %s for %s.", uuid, mdata_device_path(cd));
	else
		log_dbg(cd, "Requested new UUID refresh for %s.", mdata_device_path(cd));

	if (!crypt_confirm(cd, _("Do you really want to change UUID of device?")))
		return -EPERM;

	if (isLUKS1(cd->type))
		return LUKS_hdr_uuid_set(&cd->u.luks1.hdr, uuid, cd);
	else
		return LUKS2_hdr_uuid(cd, &cd->u.luks2.hdr, uuid);
}

int crypt_set_label(struct crypt_device *cd, const char *label, const char *subsystem)
{
	int r;

	log_dbg(cd, "Setting new labels.");

	if ((r = onlyLUKS2(cd)))
		return r;

	return LUKS2_hdr_labels(cd, &cd->u.luks2.hdr, label, subsystem, 1);
}

int crypt_header_backup(struct crypt_device *cd,
			const char *requested_type,
			const char *backup_file)
{
	int r;

	if (requested_type && !isLUKS(requested_type))
		return -EINVAL;

	if (!backup_file)
		return -EINVAL;

	/* Load with repair */
	r = _crypt_load_luks(cd, requested_type, 1, 0);
	if (r < 0)
		return r;

	log_dbg(cd, "Requested header backup of device %s (%s) to "
		"file %s.", mdata_device_path(cd), requested_type ?: "any type", backup_file);

	if (isLUKS1(cd->type) && (!requested_type || isLUKS1(requested_type)))
		r = LUKS_hdr_backup(backup_file, cd);
	else if (isLUKS2(cd->type) && (!requested_type || isLUKS2(requested_type)))
		r = LUKS2_hdr_backup(cd, &cd->u.luks2.hdr, backup_file);
	else
		r = -EINVAL;

	return r;
}

int crypt_header_restore(struct crypt_device *cd,
			 const char *requested_type,
			 const char *backup_file)
{
	struct luks_phdr hdr1;
	struct luks2_hdr hdr2;
	int r, version;

	if (requested_type && !isLUKS(requested_type))
		return -EINVAL;

	if (!cd || (cd->type && !isLUKS(cd->type)) || !backup_file)
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	log_dbg(cd, "Requested header restore to device %s (%s) from "
		"file %s.", mdata_device_path(cd), requested_type ?: "any type", backup_file);

	version = LUKS2_hdr_version_unlocked(cd, backup_file);
	if (!version ||
	   (requested_type && version == 1 && !isLUKS1(requested_type)) ||
	   (requested_type && version == 2 && !isLUKS2(requested_type))) {
		log_err(cd, _("Header backup file does not contain compatible LUKS header."));
		return -EINVAL;
	}

	memset(&hdr2, 0, sizeof(hdr2));

	if (!cd->type) {
		if (version == 1)
			r = LUKS_hdr_restore(backup_file, &hdr1, cd);
		else
			r = LUKS2_hdr_restore(cd, &hdr2, backup_file);

		crypt_safe_memzero(&hdr1, sizeof(hdr1));
		crypt_safe_memzero(&hdr2, sizeof(hdr2));
	} else if (isLUKS2(cd->type) && (!requested_type || isLUKS2(requested_type))) {
		r = LUKS2_hdr_restore(cd, &cd->u.luks2.hdr, backup_file);
		if (r)
			_luks2_reload(cd);
	} else if (isLUKS1(cd->type) && (!requested_type || isLUKS1(requested_type)))
		r = LUKS_hdr_restore(backup_file, &cd->u.luks1.hdr, cd);
	else
		r = -EINVAL;

	if (!r)
		r = _crypt_load_luks(cd, version == 1 ? CRYPT_LUKS1 : CRYPT_LUKS2, 1, 1);

	return r;
}

void crypt_free(struct crypt_device *cd)
{
	if (!cd)
		return;

	log_dbg(cd, "Releasing crypt device %s context.", mdata_device_path(cd));

	dm_backend_exit(cd);
	crypt_free_volume_key(cd->volume_key);

	crypt_free_type(cd);

	device_free(cd, cd->device);
	device_free(cd, cd->metadata_device);

	free(CONST_CAST(void*)cd->pbkdf.type);
	free(CONST_CAST(void*)cd->pbkdf.hash);

	/* Some structures can contain keys (TCRYPT), wipe it */
	crypt_safe_memzero(cd, sizeof(*cd));
	free(cd);
}

static char *crypt_get_device_key_description(struct crypt_device *cd, const char *name)
{
	char *desc = NULL;
	struct crypt_dm_active_device dmd;
	struct dm_target *tgt = &dmd.segment;

	if (dm_query_device(cd, name, DM_ACTIVE_CRYPT_KEY | DM_ACTIVE_CRYPT_KEYSIZE, &dmd) < 0)
		return NULL;

	if (single_segment(&dmd) && tgt->type == DM_CRYPT &&
	    (dmd.flags & CRYPT_ACTIVATE_KEYRING_KEY) && tgt->u.crypt.vk->key_description)
		desc = strdup(tgt->u.crypt.vk->key_description);

	dm_targets_free(cd, &dmd);

	return desc;
}

int crypt_suspend(struct crypt_device *cd,
		  const char *name)
{
	char *key_desc;
	crypt_status_info ci;
	int r;
	uint32_t dmflags = DM_SUSPEND_WIPE_KEY;

	/* FIXME: check context uuid matches the dm-crypt device uuid (onlyLUKS branching) */

	if (!cd || !name)
		return -EINVAL;

	log_dbg(cd, "Suspending volume %s.", name);

	if (cd->type)
		r = onlyLUKS(cd);
	else {
		r = crypt_uuid_type_cmp(cd, CRYPT_LUKS1);
		if (r < 0)
			r = crypt_uuid_type_cmp(cd, CRYPT_LUKS2);
		if (r < 0)
			log_err(cd, _("This operation is supported only for LUKS device."));
	}

	if (r < 0)
		return r;

	ci = crypt_status(NULL, name);
	if (ci < CRYPT_ACTIVE) {
		log_err(cd, _("Volume %s is not active."), name);
		return -EINVAL;
	}

	dm_backend_init(cd);

	r = dm_status_suspended(cd, name);
	if (r < 0)
		goto out;

	if (r) {
		log_err(cd, _("Volume %s is already suspended."), name);
		r = -EINVAL;
		goto out;
	}

	key_desc = crypt_get_device_key_description(cd, name);

	/* we can't simply wipe wrapped keys */
	if (crypt_cipher_wrapped_key(crypt_get_cipher(cd), crypt_get_cipher_mode(cd)))
		dmflags &= ~DM_SUSPEND_WIPE_KEY;

	r = dm_suspend_device(cd, name, dmflags);
	if (r == -ENOTSUP)
		log_err(cd, _("Suspend is not supported for device %s."), name);
	else if (r)
		log_err(cd, _("Error during suspending device %s."), name);
	else
		crypt_drop_keyring_key_by_description(cd, key_desc, LOGON_KEY);
	free(key_desc);
out:
	dm_backend_exit(cd);
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

	/* FIXME: check context uuid matches the dm-crypt device uuid */

	if (!passphrase || !name)
		return -EINVAL;

	log_dbg(cd, "Resuming volume %s.", name);

	if ((r = onlyLUKS(cd)))
		return r;

	r = dm_status_suspended(cd, name);
	if (r < 0)
		return r;

	if (!r) {
		log_err(cd, _("Volume %s is not suspended."), name);
		return -EINVAL;
	}

	if (isLUKS1(cd->type))
		r = LUKS_open_key_with_hdr(keyslot, passphrase, passphrase_size,
					   &cd->u.luks1.hdr, &vk, cd);
	else
		r = LUKS2_keyslot_open(cd, keyslot, CRYPT_DEFAULT_SEGMENT, passphrase, passphrase_size, &vk);

	if  (r < 0)
		goto out;

	keyslot = r;

	if (crypt_use_keyring_for_vk(cd)) {
		if (!isLUKS2(cd->type)) {
			r = -EINVAL;
			goto out;
		}
		r = LUKS2_volume_key_load_in_keyring_by_keyslot(cd,
					&cd->u.luks2.hdr, vk, keyslot);
		if (r < 0)
			goto out;
	}

	r = dm_resume_and_reinstate_key(cd, name, vk);

	if (r == -ENOTSUP)
		log_err(cd, _("Resume is not supported for device %s."), name);
	else if (r)
		log_err(cd, _("Error during resuming device %s."), name);
out:
	if (r < 0)
		crypt_drop_keyring_key(cd, vk);
	crypt_free_volume_key(vk);

	return r < 0 ? r : keyslot;
}

int crypt_resume_by_keyfile_device_offset(struct crypt_device *cd,
					  const char *name,
					  int keyslot,
					  const char *keyfile,
					  size_t keyfile_size,
					  uint64_t keyfile_offset)
{
	struct volume_key *vk = NULL;
	char *passphrase_read = NULL;
	size_t passphrase_size_read;
	int r;

	/* FIXME: check context uuid matches the dm-crypt device uuid */

	if (!name || !keyfile)
		return -EINVAL;

	log_dbg(cd, "Resuming volume %s.", name);

	if ((r = onlyLUKS(cd)))
		return r;

	r = dm_status_suspended(cd, name);
	if (r < 0)
		return r;

	if (!r) {
		log_err(cd, _("Volume %s is not suspended."), name);
		return -EINVAL;
	}

	r = crypt_keyfile_device_read(cd, keyfile,
				      &passphrase_read, &passphrase_size_read,
				      keyfile_offset, keyfile_size, 0);
	if (r < 0)
		goto out;

	if (isLUKS1(cd->type))
		r = LUKS_open_key_with_hdr(keyslot, passphrase_read, passphrase_size_read,
					   &cd->u.luks1.hdr, &vk, cd);
	else
		r = LUKS2_keyslot_open(cd, keyslot, CRYPT_DEFAULT_SEGMENT, passphrase_read, passphrase_size_read, &vk);
	if (r < 0)
		goto out;
	keyslot = r;

	if (crypt_use_keyring_for_vk(cd)) {
		if (!isLUKS2(cd->type)) {
			r = -EINVAL;
			goto out;
		}
		r = LUKS2_volume_key_load_in_keyring_by_keyslot(cd,
					&cd->u.luks2.hdr, vk, keyslot);
		if (r < 0)
			goto out;
	}

	r = dm_resume_and_reinstate_key(cd, name, vk);
	if (r < 0)
		log_err(cd, _("Error during resuming device %s."), name);
out:
	crypt_safe_free(passphrase_read);
	if (r < 0)
		crypt_drop_keyring_key(cd, vk);
	crypt_free_volume_key(vk);
	return r < 0 ? r : keyslot;
}

int crypt_resume_by_keyfile(struct crypt_device *cd,
			    const char *name,
			    int keyslot,
			    const char *keyfile,
			    size_t keyfile_size)
{
	return crypt_resume_by_keyfile_device_offset(cd, name, keyslot,
					      keyfile, keyfile_size, 0);
}

int crypt_resume_by_keyfile_offset(struct crypt_device *cd,
				   const char *name,
				   int keyslot,
				   const char *keyfile,
				   size_t keyfile_size,
				   size_t keyfile_offset)
{
	return crypt_resume_by_keyfile_device_offset(cd, name, keyslot,
				      keyfile, keyfile_size, keyfile_offset);
}

int crypt_resume_by_volume_key(struct crypt_device *cd,
	const char *name,
	const char *volume_key,
	size_t volume_key_size)
{
	struct volume_key *vk = NULL;
	int r;

	if (!name || !volume_key)
		return -EINVAL;

	log_dbg(cd, "Resuming volume %s by volume key.", name);

	if ((r = onlyLUKS(cd)))
		return r;

	r = dm_status_suspended(cd, name);
	if (r < 0)
		return r;

	if (!r) {
		log_err(cd, _("Volume %s is not suspended."), name);
		return -EINVAL;
	}

	vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	if (!vk)
		return -ENOMEM;

	if (isLUKS1(cd->type))
		r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);
	else if (isLUKS2(cd->type))
		r = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
	else
		r = -EINVAL;
	if (r == -EPERM || r == -ENOENT)
		log_err(cd, _("Volume key does not match the volume."));
	if  (r < 0)
		goto out;
	r = 0;

	if (crypt_use_keyring_for_vk(cd)) {
		r = LUKS2_key_description_by_segment(cd, &cd->u.luks2.hdr, vk, CRYPT_DEFAULT_SEGMENT);
		if (!r)
			r = crypt_volume_key_load_in_keyring(cd, vk);
	}
	if  (r < 0)
		goto out;

	r = dm_resume_and_reinstate_key(cd, name, vk);
	if (r < 0)
		log_err(cd, _("Error during resuming device %s."), name);
out:
	if (r < 0)
		crypt_drop_keyring_key(cd, vk);
	crypt_free_volume_key(vk);
	return r;
}

/*
 * Keyslot manipulation
 */
int crypt_keyslot_add_by_passphrase(struct crypt_device *cd,
	int keyslot, // -1 any
	const char *passphrase,
	size_t passphrase_size,
	const char *new_passphrase,
	size_t new_passphrase_size)
{
	int digest, r, active_slots;
	struct luks2_keyslot_params params;
	struct volume_key *vk = NULL;

	log_dbg(cd, "Adding new keyslot, existing passphrase %sprovided,"
		"new passphrase %sprovided.",
		passphrase ? "" : "not ", new_passphrase  ? "" : "not ");

	if ((r = onlyLUKS(cd)))
		return r;

	if (!passphrase || !new_passphrase)
		return -EINVAL;

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r)
		return r;

	if (isLUKS1(cd->type))
		active_slots = LUKS_keyslot_active_count(&cd->u.luks1.hdr);
	else
		active_slots = LUKS2_keyslot_active_count(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);
	if (active_slots == 0) {
		/* No slots used, try to use pre-generated key in header */
		if (cd->volume_key) {
			vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);
			r = vk ? 0 : -ENOMEM;
		} else {
			log_err(cd, _("Cannot add key slot, all slots disabled and no volume key provided."));
			return -EINVAL;
		}
	} else if (active_slots < 0)
		return -EINVAL;
	else {
		/* Passphrase provided, use it to unlock existing keyslot */
		if (isLUKS1(cd->type))
			r = LUKS_open_key_with_hdr(CRYPT_ANY_SLOT, passphrase,
						   passphrase_size, &cd->u.luks1.hdr, &vk, cd);
		else
			r = LUKS2_keyslot_open(cd, CRYPT_ANY_SLOT, CRYPT_DEFAULT_SEGMENT, passphrase,
						passphrase_size, &vk);
	}

	if (r < 0)
		goto out;

	if (isLUKS1(cd->type))
		r = LUKS_set_key(keyslot, CONST_CAST(char*)new_passphrase,
				 new_passphrase_size, &cd->u.luks1.hdr, vk, cd);
	else {
		r = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
		digest = r;

		if (r >= 0)
			r = LUKS2_keyslot_params_default(cd, &cd->u.luks2.hdr, &params);

		if (r >= 0)
			r = LUKS2_digest_assign(cd, &cd->u.luks2.hdr, keyslot, digest, 1, 0);

		if (r >= 0)
			r = LUKS2_keyslot_store(cd,  &cd->u.luks2.hdr, keyslot,
						CONST_CAST(char*)new_passphrase,
						new_passphrase_size, vk, &params);
	}

	if (r < 0)
		goto out;

	r = 0;
out:
	crypt_free_volume_key(vk);
	if (r < 0) {
		_luks2_reload(cd);
		return r;
	}
	return keyslot;
}

int crypt_keyslot_change_by_passphrase(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	const char *passphrase,
	size_t passphrase_size,
	const char *new_passphrase,
	size_t new_passphrase_size)
{
	int digest = -1, r;
	struct luks2_keyslot_params params;
	struct volume_key *vk = NULL;

	if (!passphrase || !new_passphrase)
		return -EINVAL;

	log_dbg(cd, "Changing passphrase from old keyslot %d to new %d.",
		keyslot_old, keyslot_new);

	if ((r = onlyLUKS(cd)))
		return r;

	if (isLUKS1(cd->type))
		r = LUKS_open_key_with_hdr(keyslot_old, passphrase, passphrase_size,
					   &cd->u.luks1.hdr, &vk, cd);
	else if (isLUKS2(cd->type)) {
		r = LUKS2_keyslot_open(cd, keyslot_old, CRYPT_ANY_SEGMENT, passphrase, passphrase_size, &vk);
		/* will fail for keyslots w/o digest. fix if supported in a future */
		if (r >= 0) {
			digest = LUKS2_digest_by_keyslot(&cd->u.luks2.hdr, r);
			if (digest < 0)
				r = -EINVAL;
		}
	} else
		r = -EINVAL;
	if (r < 0)
		goto out;

	if (keyslot_old != CRYPT_ANY_SLOT && keyslot_old != r) {
		log_dbg(cd, "Keyslot mismatch.");
		goto out;
	}
	keyslot_old = r;

	if (keyslot_new == CRYPT_ANY_SLOT) {
		if (isLUKS1(cd->type))
			keyslot_new = LUKS_keyslot_find_empty(&cd->u.luks1.hdr);
		else if (isLUKS2(cd->type))
			keyslot_new = LUKS2_keyslot_find_empty(&cd->u.luks2.hdr);
		if (keyslot_new < 0)
			keyslot_new = keyslot_old;
	}
	log_dbg(cd, "Key change, old slot %d, new slot %d.", keyslot_old, keyslot_new);

	if (isLUKS1(cd->type)) {
		if (keyslot_old == keyslot_new) {
			log_dbg(cd, "Key slot %d is going to be overwritten.", keyslot_old);
			(void)crypt_keyslot_destroy(cd, keyslot_old);
		}
		r = LUKS_set_key(keyslot_new, new_passphrase, new_passphrase_size,
				 &cd->u.luks1.hdr, vk, cd);
	} else if (isLUKS2(cd->type)) {
		r = LUKS2_keyslot_params_default(cd, &cd->u.luks2.hdr, &params);
		if (r)
			goto out;

		if (keyslot_old != keyslot_new) {
			r = LUKS2_digest_assign(cd, &cd->u.luks2.hdr, keyslot_new, digest, 1, 0);
			if (r < 0)
				goto out;
		} else {
			log_dbg(cd, "Key slot %d is going to be overwritten.", keyslot_old);
			/* FIXME: improve return code so that we can detect area is damaged */
			r = LUKS2_keyslot_wipe(cd, &cd->u.luks2.hdr, keyslot_old, 1);
			if (r) {
				/* (void)crypt_keyslot_destroy(cd, keyslot_old); */
				r = -EINVAL;
				goto out;
			}
		}

		r = LUKS2_keyslot_store(cd,  &cd->u.luks2.hdr,
					keyslot_new, new_passphrase,
					new_passphrase_size, vk, &params);
	} else
		r = -EINVAL;

	if (r >= 0 && keyslot_old != keyslot_new)
		r = crypt_keyslot_destroy(cd, keyslot_old);

	if (r < 0)
		log_err(cd, _("Failed to swap new key slot."));
out:
	crypt_free_volume_key(vk);
	if (r < 0) {
		_luks2_reload(cd);
		return r;
	}
	return keyslot_new;
}

int crypt_keyslot_add_by_keyfile_device_offset(struct crypt_device *cd,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	const char *new_keyfile,
	size_t new_keyfile_size,
	uint64_t new_keyfile_offset)
{
	int digest, r, active_slots;
	size_t passwordLen, new_passwordLen;
	struct luks2_keyslot_params params;
	char *password = NULL, *new_password = NULL;
	struct volume_key *vk = NULL;

	if (!keyfile || !new_keyfile)
		return -EINVAL;

	log_dbg(cd, "Adding new keyslot, existing keyfile %s, new keyfile %s.",
		keyfile, new_keyfile);

	if ((r = onlyLUKS(cd)))
		return r;

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r)
		return r;

	if (isLUKS1(cd->type))
		active_slots = LUKS_keyslot_active_count(&cd->u.luks1.hdr);
	else
		active_slots = LUKS2_keyslot_active_count(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);
	if (active_slots == 0) {
		/* No slots used, try to use pre-generated key in header */
		if (cd->volume_key) {
			vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);
			r = vk ? 0 : -ENOMEM;
		} else {
			log_err(cd, _("Cannot add key slot, all slots disabled and no volume key provided."));
			return -EINVAL;
		}
	} else {
		r = crypt_keyfile_device_read(cd, keyfile,
				       &password, &passwordLen,
				       keyfile_offset, keyfile_size, 0);
		if (r < 0)
			goto out;

		if (isLUKS1(cd->type))
			r = LUKS_open_key_with_hdr(CRYPT_ANY_SLOT, password, passwordLen,
						   &cd->u.luks1.hdr, &vk, cd);
		else
			r = LUKS2_keyslot_open(cd, CRYPT_ANY_SLOT, CRYPT_DEFAULT_SEGMENT, password, passwordLen, &vk);
	}

	if (r < 0)
		goto out;

	r = crypt_keyfile_device_read(cd, new_keyfile,
			       &new_password, &new_passwordLen,
			       new_keyfile_offset, new_keyfile_size, 0);
	if (r < 0)
		goto out;

	if (isLUKS1(cd->type))
		r = LUKS_set_key(keyslot, new_password, new_passwordLen,
				 &cd->u.luks1.hdr, vk, cd);
	else {
		r = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
		digest = r;

		if (r >= 0)
			r = LUKS2_keyslot_params_default(cd, &cd->u.luks2.hdr, &params);

		if (r >= 0)
			r = LUKS2_digest_assign(cd, &cd->u.luks2.hdr, keyslot, digest, 1, 0);

		if (r >= 0)
			r = LUKS2_keyslot_store(cd,  &cd->u.luks2.hdr, keyslot,
						new_password, new_passwordLen, vk, &params);
	}
out:
	crypt_safe_free(password);
	crypt_safe_free(new_password);
	crypt_free_volume_key(vk);
	if (r < 0) {
		_luks2_reload(cd);
		return r;
	}
	return keyslot;
}

int crypt_keyslot_add_by_keyfile(struct crypt_device *cd,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	const char *new_keyfile,
	size_t new_keyfile_size)
{
	return crypt_keyslot_add_by_keyfile_device_offset(cd, keyslot,
				keyfile, keyfile_size, 0,
				new_keyfile, new_keyfile_size, 0);
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
	return crypt_keyslot_add_by_keyfile_device_offset(cd, keyslot,
				keyfile, keyfile_size, keyfile_offset,
				new_keyfile, new_keyfile_size, new_keyfile_offset);
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

	if (!passphrase)
		return -EINVAL;

	log_dbg(cd, "Adding new keyslot %d using volume key.", keyslot);

	if ((r = onlyLUKS(cd)))
		return r;

	if (isLUKS2(cd->type))
		return crypt_keyslot_add_by_key(cd, keyslot,
				volume_key, volume_key_size, passphrase,
				passphrase_size, 0);

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r < 0)
		return r;

	if (volume_key)
		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	else if (cd->volume_key)
		vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);

	if (!vk)
		return -ENOMEM;

	r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);
	if (r < 0)
		log_err(cd, _("Volume key does not match the volume."));
	else
		r = LUKS_set_key(keyslot, passphrase, passphrase_size,
			&cd->u.luks1.hdr, vk, cd);

	crypt_free_volume_key(vk);
	return (r < 0) ? r : keyslot;
}

int crypt_keyslot_destroy(struct crypt_device *cd, int keyslot)
{
	crypt_keyslot_info ki;
	int r;

	log_dbg(cd, "Destroying keyslot %d.", keyslot);

	if ((r = _onlyLUKS(cd, CRYPT_CD_UNRESTRICTED)))
		return r;

	ki = crypt_keyslot_status(cd, keyslot);
	if (ki == CRYPT_SLOT_INVALID) {
		log_err(cd, _("Key slot %d is invalid."), keyslot);
		return -EINVAL;
	}

	if (isLUKS1(cd->type)) {
		if (ki == CRYPT_SLOT_INACTIVE) {
			log_err(cd, _("Keyslot %d is not active."), keyslot);
			return -EINVAL;
		}
		return LUKS_del_key(keyslot, &cd->u.luks1.hdr, cd);
	}

	return LUKS2_keyslot_wipe(cd, &cd->u.luks2.hdr, keyslot, 0);
}

static int _check_header_data_overlap(struct crypt_device *cd, const char *name)
{
	if (!name || !isLUKS(cd->type))
		return 0;

	if (!device_is_identical(crypt_data_device(cd), crypt_metadata_device(cd)))
		return 0;

	/* FIXME: check real header size */
	if (crypt_get_data_offset(cd) == 0) {
		log_err(cd, _("Device header overlaps with data area."));
		return -EINVAL;
	}

	return 0;
}

static int check_devices(struct crypt_device *cd, const char *name, const char *iname, uint32_t *flags)
{
	int r;

	if (!flags || !name)
		return -EINVAL;

	if (iname) {
		r = dm_status_device(cd, iname);
		if (r >= 0 && !(*flags & CRYPT_ACTIVATE_REFRESH))
			return -EBUSY;
		if (r < 0 && r != -ENODEV)
			return r;
		if (r == -ENODEV)
			*flags &= ~CRYPT_ACTIVATE_REFRESH;
	}

	r = dm_status_device(cd, name);
	if (r >= 0 && !(*flags & CRYPT_ACTIVATE_REFRESH))
		return -EBUSY;
	if (r < 0 && r != -ENODEV)
		return r;
	if (r == -ENODEV)
		*flags &= ~CRYPT_ACTIVATE_REFRESH;

	return 0;
}

static int _create_device_with_integrity(struct crypt_device *cd,
	const char *type, const char *name, const char *iname,
	const char *ipath, struct crypt_dm_active_device *dmd,
	struct crypt_dm_active_device *dmdi)
{
	int r;
	enum devcheck device_check;
	struct dm_target *tgt;
	struct device *device = NULL;

	if (!single_segment(dmd))
		return -EINVAL;

	tgt = &dmd->segment;
	if (tgt->type != DM_CRYPT)
		return -EINVAL;

	device_check = dmd->flags & CRYPT_ACTIVATE_SHARED ? DEV_OK : DEV_EXCL;

	r = INTEGRITY_activate_dmd_device(cd, iname, CRYPT_INTEGRITY, dmdi, 0);
	if (r)
		return r;

	r = device_alloc(cd, &device, ipath);
	if (r < 0)
		goto out;
	tgt->data_device = device;

	r = device_block_adjust(cd, tgt->data_device, device_check,
				tgt->u.crypt.offset, &dmd->size, &dmd->flags);

	if (!r)
		r = dm_create_device(cd, name, type, dmd);
out:
	if (r < 0)
		dm_remove_device(cd, iname, 0);

	device_free(cd, device);
	return r;
}

static int kernel_keyring_support(void)
{
	static unsigned _checked = 0;

	if (!_checked) {
		_kernel_keyring_supported = keyring_check();
		_checked = 1;
	}

	return _kernel_keyring_supported;
}

static int dmcrypt_keyring_bug(void)
{
	uint64_t kversion;

	if (kernel_version(&kversion))
		return 1;
	return kversion < version(4,15,0,0);
}

int create_or_reload_device(struct crypt_device *cd, const char *name,
		     const char *type, struct crypt_dm_active_device *dmd)
{
	int r;
	enum devcheck device_check;
	struct dm_target *tgt;

	if (!type || !name || !single_segment(dmd))
		return -EINVAL;

	tgt = &dmd->segment;
	if (tgt->type != DM_CRYPT)
		return -EINVAL;

	/* drop CRYPT_ACTIVATE_REFRESH flag if any device is inactive */
	r = check_devices(cd, name, NULL, &dmd->flags);
	if (r)
		return r;

	if (dmd->flags & CRYPT_ACTIVATE_REFRESH)
		r = _reload_device(cd, name, dmd);
	else {
		device_check = dmd->flags & CRYPT_ACTIVATE_SHARED ? DEV_OK : DEV_EXCL;

		r = device_block_adjust(cd, tgt->data_device, device_check,
					tgt->u.crypt.offset, &dmd->size, &dmd->flags);
		if (!r) {
			tgt->size = dmd->size;
			r = dm_create_device(cd, name, type, dmd);
		}
	}

	return r;
}

int create_or_reload_device_with_integrity(struct crypt_device *cd, const char *name,
		     const char *type, struct crypt_dm_active_device *dmd,
		     struct crypt_dm_active_device *dmdi)
{
	int r;
	const char *iname = NULL;
	char *ipath = NULL;

	if (!type || !name || !dmd || !dmdi)
		return -EINVAL;

	if (asprintf(&ipath, "%s/%s_dif", dm_get_dir(), name) < 0)
		return -ENOMEM;
	iname = ipath + strlen(dm_get_dir()) + 1;

	/* drop CRYPT_ACTIVATE_REFRESH flag if any device is inactive */
	r = check_devices(cd, name, iname, &dmd->flags);
	if (r)
		goto out;

	if (dmd->flags & CRYPT_ACTIVATE_REFRESH)
		r = _reload_device_with_integrity(cd, name, iname, ipath, dmd, dmdi);
	else
		r = _create_device_with_integrity(cd, type, name, iname, ipath, dmd, dmdi);
out:
	free(ipath);

	return r;
}

static int load_all_keys(struct crypt_device *cd, struct luks2_hdr *hdr, struct volume_key *vks)
{
	int r;
	struct volume_key *vk = vks;

	while (vk) {
		r = LUKS2_volume_key_load_in_keyring_by_digest(cd, hdr, vk, crypt_volume_key_get_id(vk));
		if (r < 0)
			return r;
		vk = crypt_volume_key_next(vk);
	}

	return 0;
}

/* See fixmes in _open_and_activate_luks2 */
int update_reencryption_flag(struct crypt_device *cd, int enable, bool commit);

/* TODO: This function should 1:1 with pre-reencryption code */
static int _open_and_activate(struct crypt_device *cd,
	int keyslot,
	const char *name,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	int r;
	struct volume_key *vk = NULL;

	r = LUKS2_keyslot_open(cd, keyslot,
			       (flags & CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY) ?
			       CRYPT_ANY_SEGMENT : CRYPT_DEFAULT_SEGMENT,
			       passphrase, passphrase_size, &vk);
	if (r < 0)
		return r;
	keyslot = r;

	if ((name || (flags & CRYPT_ACTIVATE_KEYRING_KEY)) &&
	    crypt_use_keyring_for_vk(cd)) {
		r = LUKS2_volume_key_load_in_keyring_by_keyslot(cd,
				&cd->u.luks2.hdr, vk, keyslot);
		if (r < 0)
			goto out;
		flags |= CRYPT_ACTIVATE_KEYRING_KEY;
	}

	if (name)
		r = LUKS2_activate(cd, name, vk, flags);
out:
	if (r < 0)
		crypt_drop_keyring_key(cd, vk);
	crypt_free_volume_key(vk);

	return r < 0 ? r : keyslot;
}

static int _open_all_keys(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags,
	struct volume_key **vks)
{
	int r, segment;
	struct volume_key *_vks = NULL;
	crypt_reencrypt_info ri = LUKS2_reenc_status(hdr);

	segment = (flags & CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY) ? CRYPT_ANY_SEGMENT : CRYPT_DEFAULT_SEGMENT;

	switch (ri) {
	case CRYPT_REENCRYPT_NONE:
		r = LUKS2_keyslot_open(cd, keyslot, segment, passphrase, passphrase_size, &_vks);
		break;
	case CRYPT_REENCRYPT_CLEAN:
	case CRYPT_REENCRYPT_CRASH:
		if (segment == CRYPT_ANY_SEGMENT)
			r = LUKS2_keyslot_open(cd, keyslot, segment, passphrase,
					       passphrase_size, &_vks);
		else
			r = LUKS2_keyslot_open_all_segments(cd, keyslot,
					keyslot, passphrase, passphrase_size,
					&_vks);
		break;
	default:
		r = -EINVAL;
	}

	if (keyslot == CRYPT_ANY_SLOT)
		keyslot = r;

	if (r >= 0 && (flags & CRYPT_ACTIVATE_KEYRING_KEY))
		r = load_all_keys(cd, hdr, _vks);

	if (r >= 0 && vks)
		MOVE_REF(*vks, _vks);

	if (r < 0)
		crypt_drop_keyring_key(cd, _vks);
	crypt_free_volume_key(_vks);

	return r < 0 ? r : keyslot;
}

static int _open_and_activate_reencrypt_device(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *name,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	bool dynamic_size;
	crypt_reencrypt_info ri;
	uint64_t minimal_size, device_size;
	struct volume_key *vks = NULL;
	int r = 0;
	struct crypt_lock_handle *reencrypt_lock = NULL;

	if (crypt_use_keyring_for_vk(cd))
		flags |= CRYPT_ACTIVATE_KEYRING_KEY;

	r = crypt_reencrypt_lock(cd, &reencrypt_lock);
	if (r) {
		if (r == -EBUSY)
			log_err(cd, _("Reencryption in-progress. Cannot activate device."));
		else
			log_err(cd, _("Failed to get reencryption lock."));
		return r;
	}

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL)))
		goto err;

	ri = LUKS2_reenc_status(hdr);

	if (ri == CRYPT_REENCRYPT_CRASH) {
		r = LUKS2_reencrypt_locked_recovery_by_passphrase(cd, keyslot,
				keyslot, passphrase, passphrase_size, flags, &vks);
		if (r < 0) {
			log_err(cd, _("LUKS2 reencryption recovery failed."));
			goto err;
		}
		keyslot = r;

		ri = LUKS2_reenc_status(hdr);
	}

	/* recovery finished reencryption or it's already finished */
	if (ri == CRYPT_REENCRYPT_NONE) {
		crypt_drop_keyring_key(cd, vks);
		crypt_free_volume_key(vks);
		crypt_reencrypt_unlock(cd, reencrypt_lock);
		return _open_and_activate(cd, keyslot, name, passphrase, passphrase_size, flags);
	}

	if (ri > CRYPT_REENCRYPT_CLEAN) {
		r = -EINVAL;
		goto err;
	}

	if (LUKS2_get_data_size(hdr, &minimal_size, &dynamic_size))
		goto err;

	if (!vks) {
		r = _open_all_keys(cd, hdr, keyslot, passphrase, passphrase_size, flags, &vks);
		if (r >= 0)
			keyslot = r;
	}

	log_dbg(cd, "Entering clean reencryption state mode.");

	if (r >= 0)
		r = luks2_check_device_size(cd, hdr, minimal_size, &device_size, true, dynamic_size);

	if (r >= 0)
		r = LUKS2_activate_multi(cd, name, vks, device_size >> SECTOR_SHIFT, flags);
err:
	crypt_reencrypt_unlock(cd, reencrypt_lock);
	if (r < 0)
		crypt_drop_keyring_key(cd, vks);
	crypt_free_volume_key(vks);

	return r < 0 ? r : keyslot;
}

/*
 * Activation/deactivation of a device
 */
static int _open_and_activate_luks2(struct crypt_device *cd,
	int keyslot,
	const char *name,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	crypt_reencrypt_info ri;
	int r;
	struct luks2_hdr *hdr = &cd->u.luks2.hdr;

	ri = LUKS2_reenc_status(hdr);
	if (ri == CRYPT_REENCRYPT_INVALID)
		return -EINVAL;

	if (ri > CRYPT_REENCRYPT_NONE) {
		if (name)
			r = _open_and_activate_reencrypt_device(cd, hdr, keyslot, name, passphrase,
					passphrase_size, flags);
		else
			r = _open_all_keys(cd, hdr, keyslot, passphrase,
					   passphrase_size, flags, NULL);
	} else
		r = _open_and_activate(cd, keyslot, name, passphrase,
				passphrase_size, flags);

	return r;
}

static int _activate_by_passphrase(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	int r;
	struct volume_key *vk = NULL;

	if ((flags & CRYPT_ACTIVATE_KEYRING_KEY) && !crypt_use_keyring_for_vk(cd))
		return -EINVAL;

	if ((flags & CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY) && name)
		return -EINVAL;

	r = _check_header_data_overlap(cd, name);
	if (r < 0)
		return r;

	if (flags & CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF)
		cd->memory_hard_pbkdf_lock_enabled = true;

	/* plain, use hashed passphrase */
	if (isPLAIN(cd->type)) {
		r = -EINVAL;
		if (!name)
			goto out;

		r = process_key(cd, cd->u.plain.hdr.hash,
				cd->u.plain.key_size,
				passphrase, passphrase_size, &vk);
		if (r < 0)
			goto out;

		r = PLAIN_activate(cd, name, vk, cd->u.plain.hdr.size, flags);
		keyslot = 0;
	} else if (isLUKS1(cd->type)) {
		r = LUKS_open_key_with_hdr(keyslot, passphrase,
					   passphrase_size, &cd->u.luks1.hdr, &vk, cd);
		if (r >= 0) {
			keyslot = r;
			if (name)
				r = LUKS1_activate(cd, name, vk, flags);
		}
	} else if (isLUKS2(cd->type)) {
		r = _open_and_activate_luks2(cd, keyslot, name, passphrase, passphrase_size, flags);
		keyslot = r;
	} else if (isBITLK(cd->type)) {
		r = BITLK_activate(cd, name, passphrase, passphrase_size,
				   &cd->u.bitlk.params, flags);
		keyslot = 0;
	} else {
		log_err(cd, _("Device type is not properly initialized."));
		r = -EINVAL;
	}
out:
	if (r < 0)
		crypt_drop_keyring_key(cd, vk);
	crypt_free_volume_key(vk);

	cd->memory_hard_pbkdf_lock_enabled = false;

	return r < 0 ? r : keyslot;
}

static int _activate_loopaes(struct crypt_device *cd,
	const char *name,
	char *buffer,
	size_t buffer_size,
	uint32_t flags)
{
	int r;
	unsigned int key_count = 0;
	struct volume_key *vk = NULL;

	r = LOOPAES_parse_keyfile(cd, &vk, cd->u.loopaes.hdr.hash, &key_count,
				  buffer, buffer_size);

	if (!r && name)
		r = LOOPAES_activate(cd, name, cd->u.loopaes.cipher, key_count,
				     vk, flags);

	crypt_free_volume_key(vk);

	return r;
}

static int _activate_check_status(struct crypt_device *cd, const char *name, unsigned reload)
{
	crypt_status_info ci;

	if (!name)
		return 0;

	ci = crypt_status(cd, name);
	if (ci == CRYPT_INVALID) {
		log_err(cd, _("Cannot use device %s, name is invalid or still in use."), name);
		return -EINVAL;
	} else if (ci >= CRYPT_ACTIVE && !reload) {
		log_err(cd, _("Device %s already exists."), name);
		return -EEXIST;
	}

	return 0;
}

// activation/deactivation of device mapping
int crypt_activate_by_passphrase(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	int r;

	if (!cd || !passphrase || (!name && (flags & CRYPT_ACTIVATE_REFRESH)))
		return -EINVAL;

	log_dbg(cd, "%s volume %s [keyslot %d] using passphrase.",
		name ? "Activating" : "Checking", name ?: "passphrase",
		keyslot);

	r = _activate_check_status(cd, name, flags & CRYPT_ACTIVATE_REFRESH);
	if (r < 0)
		return r;

	return _activate_by_passphrase(cd, name, keyslot, passphrase, passphrase_size, flags);
}

int crypt_activate_by_keyfile_device_offset(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	uint32_t flags)
{
	char *passphrase_read = NULL;
	size_t passphrase_size_read;
	int r;

	if (!cd || !keyfile ||
	    ((flags & CRYPT_ACTIVATE_KEYRING_KEY) && !crypt_use_keyring_for_vk(cd)))
		return -EINVAL;

	log_dbg(cd, "%s volume %s [keyslot %d] using keyfile %s.",
		name ? "Activating" : "Checking", name ?: "passphrase", keyslot, keyfile);

	r = _activate_check_status(cd, name, flags & CRYPT_ACTIVATE_REFRESH);
	if (r < 0)
		return r;

	r = crypt_keyfile_device_read(cd, keyfile,
				&passphrase_read, &passphrase_size_read,
				keyfile_offset, keyfile_size, 0);
	if (r < 0)
		goto out;

	if (isLOOPAES(cd->type))
		r = _activate_loopaes(cd, name, passphrase_read, passphrase_size_read, flags);
	else
		r = _activate_by_passphrase(cd, name, keyslot, passphrase_read, passphrase_size_read, flags);

out:
	crypt_safe_free(passphrase_read);
	return r;
}

int crypt_activate_by_keyfile(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	uint32_t flags)
{
	return crypt_activate_by_keyfile_device_offset(cd, name, keyslot, keyfile,
					keyfile_size, 0, flags);
}

int crypt_activate_by_keyfile_offset(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	size_t keyfile_offset,
	uint32_t flags)
{
	return crypt_activate_by_keyfile_device_offset(cd, name, keyslot, keyfile,
					keyfile_size, keyfile_offset, flags);
}
int crypt_activate_by_volume_key(struct crypt_device *cd,
	const char *name,
	const char *volume_key,
	size_t volume_key_size,
	uint32_t flags)
{
	struct volume_key *vk = NULL;
	int r;

	if (!cd ||
	    ((flags & CRYPT_ACTIVATE_KEYRING_KEY) && !crypt_use_keyring_for_vk(cd)))
		return -EINVAL;

	log_dbg(cd, "%s volume %s by volume key.", name ? "Activating" : "Checking",
		name ?: "");

	r = _activate_check_status(cd, name, flags & CRYPT_ACTIVATE_REFRESH);
	if (r < 0)
		return r;

	r = _check_header_data_overlap(cd, name);
	if (r < 0)
		return r;

	/* use key directly, no hash */
	if (isPLAIN(cd->type)) {
		if (!name)
			return -EINVAL;

		if (!volume_key || !volume_key_size || volume_key_size != cd->u.plain.key_size) {
			log_err(cd, _("Incorrect volume key specified for plain device."));
			return -EINVAL;
		}

		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
		if (!vk)
			return -ENOMEM;

		r = PLAIN_activate(cd, name, vk, cd->u.plain.hdr.size, flags);
	} else if (isLUKS1(cd->type)) {
		/* If key is not provided, try to use internal key */
		if (!volume_key) {
			if (!cd->volume_key) {
				log_err(cd, _("Volume key does not match the volume."));
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
			log_err(cd, _("Volume key does not match the volume."));

		if (!r && name)
			r = LUKS1_activate(cd, name, vk, flags);
	} else if (isLUKS2(cd->type)) {
		/* If key is not provided, try to use internal key */
		if (!volume_key) {
			if (!cd->volume_key) {
				log_err(cd, _("Volume key does not match the volume."));
				return -EINVAL;
			}
			volume_key_size = cd->volume_key->keylength;
			volume_key = cd->volume_key->key;
		}

		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
		if (!vk)
			return -ENOMEM;

		r = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
		if (r == -EPERM || r == -ENOENT)
			log_err(cd, _("Volume key does not match the volume."));
		if (r > 0)
			r = 0;

		if (!r && (name || (flags & CRYPT_ACTIVATE_KEYRING_KEY)) &&
		    crypt_use_keyring_for_vk(cd)) {
			r = LUKS2_key_description_by_segment(cd,
				&cd->u.luks2.hdr, vk, CRYPT_DEFAULT_SEGMENT);
			if (!r)
				r = crypt_volume_key_load_in_keyring(cd, vk);
			if (!r)
				flags |= CRYPT_ACTIVATE_KEYRING_KEY;
		}

		if (!r && name)
			r = LUKS2_activate(cd, name, vk, flags);
	} else if (isVERITY(cd->type)) {
		r = crypt_activate_by_signed_key(cd, name, volume_key, volume_key_size, NULL, 0, flags);
	} else if (isTCRYPT(cd->type)) {
		if (!name)
			return 0;
		r = TCRYPT_activate(cd, name, &cd->u.tcrypt.hdr,
				    &cd->u.tcrypt.params, flags);
	} else if (isINTEGRITY(cd->type)) {
		if (!name)
			return 0;
		if (volume_key) {
			vk = crypt_alloc_volume_key(volume_key_size, volume_key);
			if (!vk)
				return -ENOMEM;
		}
		r = INTEGRITY_activate(cd, name, &cd->u.integrity.params, vk,
				       cd->u.integrity.journal_crypt_key,
				       cd->u.integrity.journal_mac_key, flags,
				       cd->u.integrity.sb_flags);
	} else {
		log_err(cd, _("Device type is not properly initialized."));
		r = -EINVAL;
	}

	if (r < 0)
		crypt_drop_keyring_key(cd, vk);
	crypt_free_volume_key(vk);

	return r;
}

int crypt_activate_by_signed_key(struct crypt_device *cd,
	const char *name,
	const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size,
	uint32_t flags)
{
	char description[512];
	int r;

	if (!cd || !isVERITY(cd->type))
		return -EINVAL;

	if (!volume_key || !volume_key_size || (!name && signature)) {
		log_err(cd, _("Incorrect root hash specified for verity device."));
		return -EINVAL;
	}

	log_dbg(cd, "%s volume %s by signed key.", name ? "Activating" : "Checking", name ?: "");

	if (cd->u.verity.hdr.flags & CRYPT_VERITY_ROOT_HASH_SIGNATURE && !signature) {
		log_err(cd, _("Root hash signature required."));
		return -EINVAL;
	}

	r = _activate_check_status(cd, name, flags & CRYPT_ACTIVATE_REFRESH);
	if (r < 0)
		return r;

	if (signature && !kernel_keyring_support()) {
		log_err(cd, _("Kernel keyring missing: required for passing signature to kernel."));
		return -EINVAL;
	}

	/* volume_key == root hash */
	free(CONST_CAST(void*)cd->u.verity.root_hash);
	cd->u.verity.root_hash = NULL;

	if (signature) {
		r = snprintf(description, sizeof(description)-1, "cryptsetup:%s%s%s",
			     crypt_get_uuid(cd) ?: "", crypt_get_uuid(cd) ? "-" : "", name);
		if (r < 0)
			return -EINVAL;

		log_dbg(cd, "Adding signature into keyring %s", description);
		r = keyring_add_key_in_thread_keyring(USER_KEY, description, signature, signature_size);
		if (r) {
			log_err(cd, _("Failed to load key in kernel keyring."));
			return r;
		}
	}

	r = VERITY_activate(cd, name, volume_key, volume_key_size,
			    signature ? description : NULL,
			    cd->u.verity.fec_device,
			    &cd->u.verity.hdr, flags | CRYPT_ACTIVATE_READONLY);

	if (!r) {
		cd->u.verity.root_hash_size = volume_key_size;
		cd->u.verity.root_hash = malloc(volume_key_size);
		if (cd->u.verity.root_hash)
			memcpy(CONST_CAST(void*)cd->u.verity.root_hash, volume_key, volume_key_size);
	}

	if (signature)
		crypt_drop_keyring_key_by_description(cd, description, USER_KEY);

	return r;
}

int crypt_deactivate_by_name(struct crypt_device *cd, const char *name, uint32_t flags)
{
	struct crypt_device *fake_cd = NULL;
	struct luks2_hdr *hdr2 = NULL;
	struct crypt_dm_active_device dmd = {};
	int r;
	uint32_t get_flags = DM_ACTIVE_DEVICE | DM_ACTIVE_UUID | DM_ACTIVE_HOLDERS;

	if (!name)
		return -EINVAL;

	log_dbg(cd, "Deactivating volume %s.", name);

	if (!cd) {
		r = crypt_init_by_name(&fake_cd, name);
		if (r < 0)
			return r;
		cd = fake_cd;
	}

	/* skip holders detection and early abort when some flags raised */
	if (flags & (CRYPT_DEACTIVATE_FORCE | CRYPT_DEACTIVATE_DEFERRED))
		get_flags &= ~DM_ACTIVE_HOLDERS;

	switch (crypt_status(cd, name)) {
		case CRYPT_ACTIVE:
		case CRYPT_BUSY:
			r = dm_query_device(cd, name, get_flags, &dmd);
			if (r >= 0) {
				if (dmd.holders) {
					log_err(cd, _("Device %s is still in use."), name);
					r = -EBUSY;
					break;
				}
			}

			if (isLUKS2(cd->type))
				hdr2 = crypt_get_hdr(cd, CRYPT_LUKS2);

			if ((dmd.uuid && !strncmp(CRYPT_LUKS2, dmd.uuid, sizeof(CRYPT_LUKS2)-1)) || hdr2)
				r = LUKS2_deactivate(cd, name, hdr2, &dmd, flags);
			else if (isTCRYPT(cd->type))
				r = TCRYPT_deactivate(cd, name, flags);
			else
				r = dm_remove_device(cd, name, flags);
			if (r < 0 && crypt_status(cd, name) == CRYPT_BUSY) {
				log_err(cd, _("Device %s is still in use."), name);
				r = -EBUSY;
			}
			break;
		case CRYPT_INACTIVE:
			log_err(cd, _("Device %s is not active."), name);
			r = -ENODEV;
			break;
		default:
			log_err(cd, _("Invalid device %s."), name);
			r = -EINVAL;
	}

	dm_targets_free(cd, &dmd);
	free(CONST_CAST(void*)dmd.uuid);
	crypt_free(fake_cd);

	return r;
}

int crypt_deactivate(struct crypt_device *cd, const char *name)
{
	return crypt_deactivate_by_name(cd, name, 0);
}

int crypt_get_active_device(struct crypt_device *cd, const char *name,
			    struct crypt_active_device *cad)
{
	int r;
	struct crypt_dm_active_device dmd, dmdi = {};
	const char *namei = NULL;
	struct dm_target *tgt = &dmd.segment;
	uint64_t min_offset = UINT64_MAX;

	if (!cd || !name || !cad)
		return -EINVAL;

	r = dm_query_device(cd, name, DM_ACTIVE_DEVICE, &dmd);
	if (r < 0)
		return r;

	/* For LUKS2 with integrity we need flags from underlying dm-integrity */
	if (isLUKS2(cd->type) && crypt_get_integrity_tag_size(cd) && single_segment(&dmd)) {
		namei = device_dm_name(tgt->data_device);
		if (namei && dm_query_device(cd, namei, 0, &dmdi) >= 0)
			dmd.flags |= dmdi.flags;
	}

	if (cd && isTCRYPT(cd->type)) {
		cad->offset	= TCRYPT_get_data_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);
		cad->iv_offset	= TCRYPT_get_iv_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);
	} else {
		while (tgt) {
			if (tgt->type == DM_CRYPT && (min_offset > tgt->u.crypt.offset)) {
				min_offset = tgt->u.crypt.offset;
				cad->iv_offset = tgt->u.crypt.iv_offset;
			} else if (tgt->type == DM_INTEGRITY && (min_offset > tgt->u.integrity.offset)) {
				min_offset = tgt->u.integrity.offset;
				cad->iv_offset = 0;
			} else if (tgt->type == DM_LINEAR && (min_offset > tgt->u.linear.offset)) {
				min_offset = tgt->u.linear.offset;
				cad->iv_offset = 0;
			}
			tgt = tgt->next;
		}
	}

	if (min_offset != UINT64_MAX)
		cad->offset = min_offset;

	cad->size	= dmd.size;
	cad->flags	= dmd.flags;

	r = 0;
	dm_targets_free(cd, &dmd);
	dm_targets_free(cd, &dmdi);

	return r;
}

uint64_t crypt_get_active_integrity_failures(struct crypt_device *cd, const char *name)
{
	struct crypt_dm_active_device dmd;
	uint64_t failures = 0;

	if (!name)
		return 0;

	/* FIXME: LUKS2 / dm-crypt does not provide this count. */
	if (dm_query_device(cd, name, 0, &dmd) < 0)
		return 0;

	if (single_segment(&dmd) && dmd.segment.type == DM_INTEGRITY)
		(void)dm_status_integrity_failures(cd, name, &failures);

	dm_targets_free(cd, &dmd);

	return failures;
}

/*
 * Volume key handling
 */
int crypt_volume_key_get(struct crypt_device *cd,
	int keyslot,
	char *volume_key,
	size_t *volume_key_size,
	const char *passphrase,
	size_t passphrase_size)
{
	struct volume_key *vk = NULL;
	int key_len, r = -EINVAL;

	if (!cd || !volume_key || !volume_key_size || (!isTCRYPT(cd->type) && !isVERITY(cd->type) && !passphrase))
		return -EINVAL;

	if (isLUKS2(cd->type) && keyslot != CRYPT_ANY_SLOT)
		key_len = LUKS2_get_keyslot_stored_key_size(&cd->u.luks2.hdr, keyslot);
	else
		key_len = crypt_get_volume_key_size(cd);

	if (key_len < 0)
		return -EINVAL;

	if (key_len > (int)*volume_key_size) {
		log_err(cd, _("Volume key buffer too small."));
		return -ENOMEM;
	}

	if (isPLAIN(cd->type) && cd->u.plain.hdr.hash) {
		r = process_key(cd, cd->u.plain.hdr.hash, key_len,
				passphrase, passphrase_size, &vk);
		if (r < 0)
			log_err(cd, _("Cannot retrieve volume key for plain device."));
	} else if (isLUKS1(cd->type)) {
		r = LUKS_open_key_with_hdr(keyslot, passphrase,
					passphrase_size, &cd->u.luks1.hdr, &vk, cd);
	} else if (isLUKS2(cd->type)) {
		r = LUKS2_keyslot_open(cd, keyslot,
				keyslot == CRYPT_ANY_SLOT ? CRYPT_DEFAULT_SEGMENT : CRYPT_ANY_SEGMENT,
				passphrase, passphrase_size, &vk);
	} else if (isTCRYPT(cd->type)) {
		r = TCRYPT_get_volume_key(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params, &vk);
	} else if (isVERITY(cd->type)) {
		/* volume_key == root hash */
		if (cd->u.verity.root_hash) {
			memcpy(volume_key, cd->u.verity.root_hash, cd->u.verity.root_hash_size);
			*volume_key_size = cd->u.verity.root_hash_size;
			r = 0;
		} else
			log_err(cd, _("Cannot retrieve root hash for verity device."));
	} else
		log_err(cd, _("This operation is not supported for %s crypt device."), cd->type ?: "(none)");

	if (r >= 0 && vk) {
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

	if ((r = _onlyLUKS(cd, CRYPT_CD_UNRESTRICTED)))
		return r;

	vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	if (!vk)
		return -ENOMEM;

	if (isLUKS1(cd->type))
		r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);
	else if (isLUKS2(cd->type))
		r = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
	else
		r = -EINVAL;


	if (r == -EPERM)
		log_err(cd, _("Volume key does not match the volume."));

	crypt_free_volume_key(vk);

	return r >= 0 ? 0 : r;
}

/*
 * RNG and memory locking
 */
void crypt_set_rng_type(struct crypt_device *cd, int rng_type)
{
	if (!cd)
		return;

	switch (rng_type) {
	case CRYPT_RNG_URANDOM:
	case CRYPT_RNG_RANDOM:
		log_dbg(cd, "RNG set to %d (%s).", rng_type, rng_type ? "random" : "urandom");
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

void crypt_set_compatibility(struct crypt_device *cd, uint32_t flags)
{
	if (cd)
		cd->compatibility = flags;
}

uint32_t crypt_get_compatibility(struct crypt_device *cd)
{
	if (cd)
		return cd->compatibility;

	return 0;
}

/*
 * Reporting
 */
crypt_status_info crypt_status(struct crypt_device *cd, const char *name)
{
	int r;

	if (!name)
		return CRYPT_INVALID;

	if (!cd)
		dm_backend_init(cd);

	r = dm_status_device(cd, name);

	if (!cd)
		dm_backend_exit(cd);

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
	log_std(cd, "Version:       \t%" PRIu16 "\n", cd->u.luks1.hdr.version);
	log_std(cd, "Cipher name:   \t%s\n", cd->u.luks1.hdr.cipherName);
	log_std(cd, "Cipher mode:   \t%s\n", cd->u.luks1.hdr.cipherMode);
	log_std(cd, "Hash spec:     \t%s\n", cd->u.luks1.hdr.hashSpec);
	log_std(cd, "Payload offset:\t%" PRIu32 "\n", cd->u.luks1.hdr.payloadOffset);
	log_std(cd, "MK bits:       \t%" PRIu32 "\n", cd->u.luks1.hdr.keyBytes * 8);
	log_std(cd, "MK digest:     \t");
	hexprint(cd, cd->u.luks1.hdr.mkDigest, LUKS_DIGESTSIZE, " ");
	log_std(cd, "\n");
	log_std(cd, "MK salt:       \t");
	hexprint(cd, cd->u.luks1.hdr.mkDigestSalt, LUKS_SALTSIZE/2, " ");
	log_std(cd, "\n               \t");
	hexprint(cd, cd->u.luks1.hdr.mkDigestSalt+LUKS_SALTSIZE/2, LUKS_SALTSIZE/2, " ");
	log_std(cd, "\n");
	log_std(cd, "MK iterations: \t%" PRIu32 "\n", cd->u.luks1.hdr.mkDigestIterations);
	log_std(cd, "UUID:          \t%s\n\n", cd->u.luks1.hdr.uuid);
	for(i = 0; i < LUKS_NUMKEYS; i++) {
		if(cd->u.luks1.hdr.keyblock[i].active == LUKS_KEY_ENABLED) {
			log_std(cd, "Key Slot %d: ENABLED\n",i);
			log_std(cd, "\tIterations:         \t%" PRIu32 "\n",
				cd->u.luks1.hdr.keyblock[i].passwordIterations);
			log_std(cd, "\tSalt:               \t");
			hexprint(cd, cd->u.luks1.hdr.keyblock[i].passwordSalt,
				 LUKS_SALTSIZE/2, " ");
			log_std(cd, "\n\t                      \t");
			hexprint(cd, cd->u.luks1.hdr.keyblock[i].passwordSalt +
				 LUKS_SALTSIZE/2, LUKS_SALTSIZE/2, " ");
			log_std(cd, "\n");

			log_std(cd, "\tKey material offset:\t%" PRIu32 "\n",
				cd->u.luks1.hdr.keyblock[i].keyMaterialOffset);
			log_std(cd, "\tAF stripes:            \t%" PRIu32 "\n",
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
	if (!cd)
		return -EINVAL;
	if (isLUKS1(cd->type))
		return _luks_dump(cd);
	else if (isLUKS2(cd->type))
		return LUKS2_hdr_dump(cd, &cd->u.luks2.hdr);
	else if (isVERITY(cd->type))
		return _verity_dump(cd);
	else if (isTCRYPT(cd->type))
		return TCRYPT_dump(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);
	else if (isINTEGRITY(cd->type))
		return INTEGRITY_dump(cd, crypt_data_device(cd), 0);
	else if (isBITLK(cd->type))
		return BITLK_dump(cd, crypt_data_device(cd), &cd->u.bitlk.params);

	log_err(cd, _("Dump operation is not supported for this device type."));
	return -EINVAL;
}

/* internal only */
const char *crypt_get_cipher_spec(struct crypt_device *cd)
{
	if (!cd)
		return NULL;
	else if (isLUKS2(cd->type))
		return LUKS2_get_cipher(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);
	else if (isLUKS1(cd->type))
		return cd->u.luks1.cipher_spec;
	else if (isPLAIN(cd->type))
		return cd->u.plain.cipher_spec;
	else if (isLOOPAES(cd->type))
		return cd->u.loopaes.cipher_spec;
	else if (isBITLK(cd->type))
		return cd->u.bitlk.cipher_spec;
	else if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.cipher_spec;

	return NULL;
}

const char *crypt_get_cipher(struct crypt_device *cd)
{
	if (!cd)
		return NULL;

	if (isPLAIN(cd->type))
		return cd->u.plain.cipher;

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.cipherName;

	if (isLUKS2(cd->type)) {
		if (crypt_parse_name_and_mode(LUKS2_get_cipher(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT),
					      cd->u.luks2.cipher, NULL, cd->u.luks2.cipher_mode))
			return NULL;
		return cd->u.luks2.cipher;
	}

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.cipher;

	if (isTCRYPT(cd->type))
		return cd->u.tcrypt.params.cipher;

	if (isBITLK(cd->type))
		return cd->u.bitlk.params.cipher;

	if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.cipher;

	return NULL;
}

const char *crypt_get_cipher_mode(struct crypt_device *cd)
{
	if (!cd)
		return NULL;

	if (isPLAIN(cd->type))
		return cd->u.plain.cipher_mode;

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.cipherMode;

	if (isLUKS2(cd->type)) {
		if (crypt_parse_name_and_mode(LUKS2_get_cipher(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT),
					      cd->u.luks2.cipher, NULL, cd->u.luks2.cipher_mode))
			return NULL;
		return cd->u.luks2.cipher_mode;
	}

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.cipher_mode;

	if (isTCRYPT(cd->type))
		return cd->u.tcrypt.params.mode;

	if (isBITLK(cd->type))
		return cd->u.bitlk.params.cipher_mode;

	if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.cipher_mode;

	return NULL;
}

/* INTERNAL only */
const char *crypt_get_integrity(struct crypt_device *cd)
{
	if (isINTEGRITY(cd->type))
		return cd->u.integrity.params.integrity;

	if (isLUKS2(cd->type))
		return LUKS2_get_integrity(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);

	return NULL;
}

/* INTERNAL only */
int crypt_get_integrity_key_size(struct crypt_device *cd)
{
	if (isINTEGRITY(cd->type))
		return INTEGRITY_key_size(cd, crypt_get_integrity(cd));

	if (isLUKS2(cd->type))
		return INTEGRITY_key_size(cd, crypt_get_integrity(cd));

	return 0;
}

/* INTERNAL only */
int crypt_get_integrity_tag_size(struct crypt_device *cd)
{
	if (isINTEGRITY(cd->type))
		return cd->u.integrity.params.tag_size;

	if (isLUKS2(cd->type))
		return INTEGRITY_tag_size(cd, crypt_get_integrity(cd),
					  crypt_get_cipher(cd),
					  crypt_get_cipher_mode(cd));
	return 0;
}

int crypt_get_sector_size(struct crypt_device *cd)
{
	if (!cd)
		return SECTOR_SIZE;

	if (isPLAIN(cd->type))
		return cd->u.plain.hdr.sector_size;

	if (isINTEGRITY(cd->type))
		return cd->u.integrity.params.sector_size;

	if (isLUKS2(cd->type))
		return LUKS2_get_sector_size(&cd->u.luks2.hdr);

	return SECTOR_SIZE;
}

const char *crypt_get_uuid(struct crypt_device *cd)
{
	if (!cd)
		return NULL;

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.uuid;

	if (isLUKS2(cd->type))
		return cd->u.luks2.hdr.uuid;

	if (isVERITY(cd->type))
		return cd->u.verity.uuid;

	if (isBITLK(cd->type))
		return cd->u.bitlk.params.guid;

	return NULL;
}

const char *crypt_get_device_name(struct crypt_device *cd)
{
	const char *path;

	if (!cd)
		return NULL;

	path = device_block_path(cd->device);
	if (!path)
		path = device_path(cd->device);

	return path;
}

const char *crypt_get_metadata_device_name(struct crypt_device *cd)
{
	const char *path;

	if (!cd || !cd->metadata_device)
		return NULL;

	path = device_block_path(cd->metadata_device);
	if (!path)
		path = device_path(cd->metadata_device);

	return path;
}

int crypt_get_volume_key_size(struct crypt_device *cd)
{
	int r;

	if (!cd)
		return 0;

	if (isPLAIN(cd->type))
		return cd->u.plain.key_size;

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.keyBytes;

	if (isLUKS2(cd->type)) {
		r = LUKS2_get_volume_key_size(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);
		if (r < 0 && cd->volume_key)
			r = cd->volume_key->keylength;
		return r < 0 ? 0 : r;
	}

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.key_size;

	if (isVERITY(cd->type))
		return cd->u.verity.root_hash_size;

	if (isTCRYPT(cd->type))
		return cd->u.tcrypt.params.key_size;

	if (isBITLK(cd->type))
		return cd->u.bitlk.params.key_size / 8;

	if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.key_size;

	return 0;
}

int crypt_keyslot_get_key_size(struct crypt_device *cd, int keyslot)
{
	if (!cd || !isLUKS(cd->type))
		return -EINVAL;

	if (keyslot < 0 || keyslot >= crypt_keyslot_max(cd->type))
		return -EINVAL;

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.keyBytes;

	if (isLUKS2(cd->type))
		return LUKS2_get_keyslot_stored_key_size(&cd->u.luks2.hdr, keyslot);

	return -EINVAL;
}

int crypt_keyslot_set_encryption(struct crypt_device *cd,
	const char *cipher,
	size_t key_size)
{
	char *tmp;

	if (!cd || !cipher || ! key_size || !isLUKS2(cd->type))
		return -EINVAL;

	if (LUKS2_keyslot_cipher_incompatible(cd, cipher))
		return -EINVAL;

	tmp = strdup(cipher);
	free(cd->u.luks2.keyslot_cipher);
	cd->u.luks2.keyslot_cipher = tmp;
	if (!cd->u.luks2.keyslot_cipher)
		return -ENOMEM;
	cd->u.luks2.keyslot_key_size = key_size;

	return 0;
}

const char *crypt_keyslot_get_encryption(struct crypt_device *cd, int keyslot, size_t *key_size)
{
	const char *cipher;

	if (!cd || !isLUKS(cd->type) || !key_size)
		return NULL;

	if (isLUKS1(cd->type)) {
		if (keyslot != CRYPT_ANY_SLOT &&
		    LUKS_keyslot_info(&cd->u.luks1.hdr, keyslot) < CRYPT_SLOT_ACTIVE)
			return NULL;
		*key_size = crypt_get_volume_key_size(cd);
		return cd->u.luks1.cipher_spec;
	}

	if (keyslot != CRYPT_ANY_SLOT)
		return LUKS2_get_keyslot_cipher(&cd->u.luks2.hdr, keyslot, key_size);

	/* Keyslot encryption was set through crypt_keyslot_set_encryption() */
	if (cd->u.luks2.keyslot_cipher) {
		*key_size = cd->u.luks2.keyslot_key_size;
		return cd->u.luks2.keyslot_cipher;
	}

	/* Try to reuse volume encryption parameters */
	cipher =  LUKS2_get_cipher(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);
	if (!LUKS2_keyslot_cipher_incompatible(cd, cipher)) {
		*key_size = crypt_get_volume_key_size(cd);
		if (*key_size)
			return cipher;
	}

	/* Fallback to default LUKS2 keyslot encryption */
	*key_size = DEFAULT_LUKS2_KEYSLOT_KEYBITS / 8;
	return DEFAULT_LUKS2_KEYSLOT_CIPHER;
}

int crypt_keyslot_get_pbkdf(struct crypt_device *cd, int keyslot, struct crypt_pbkdf_type *pbkdf)
{
	if (!cd || !pbkdf || keyslot == CRYPT_ANY_SLOT)
		return -EINVAL;

	if (isLUKS1(cd->type))
		return LUKS_keyslot_pbkdf(&cd->u.luks1.hdr, keyslot, pbkdf);
	else if (isLUKS2(cd->type))
		return LUKS2_keyslot_pbkdf(&cd->u.luks2.hdr, keyslot, pbkdf);

	return -EINVAL;
}

int crypt_set_data_offset(struct crypt_device *cd, uint64_t data_offset)
{
	if (!cd)
		return -EINVAL;
	if (data_offset % (MAX_SECTOR_SIZE >> SECTOR_SHIFT)) {
		log_err(cd, _("Data offset is not multiple of %u bytes."), MAX_SECTOR_SIZE);
		return -EINVAL;
	}

	cd->data_offset = data_offset;
	log_dbg(cd, "Data offset set to %" PRIu64 " (512-byte) sectors.", data_offset);

	return 0;
}

int crypt_set_metadata_size(struct crypt_device *cd,
	uint64_t metadata_size,
	uint64_t keyslots_size)
{
	if (!cd)
		return -EINVAL;

	if (cd->type && !isLUKS2(cd->type))
		return -EINVAL;

	if (metadata_size && LUKS2_check_metadata_area_size(metadata_size))
		return -EINVAL;

	if (keyslots_size && LUKS2_check_keyslots_area_size(keyslots_size))
		return -EINVAL;

	cd->metadata_size = metadata_size;
	cd->keyslots_size = keyslots_size;

	return 0;
}

int crypt_get_metadata_size(struct crypt_device *cd,
	uint64_t *metadata_size,
	uint64_t *keyslots_size)
{
	uint64_t msize, ksize;

	if (!cd)
		return -EINVAL;

	if (!cd->type) {
		msize = cd->metadata_size;
		ksize = cd->keyslots_size;
	} else if (isLUKS1(cd->type)) {
		msize = LUKS_ALIGN_KEYSLOTS;
		ksize = LUKS_device_sectors(&cd->u.luks1.hdr) * SECTOR_SIZE - msize;
	} else if (isLUKS2(cd->type)) {
		msize = LUKS2_metadata_size(cd->u.luks2.hdr.jobj);
		ksize = LUKS2_keyslots_size(cd->u.luks2.hdr.jobj);
	} else
		return -EINVAL;

	if (metadata_size)
		*metadata_size = msize;
	if (keyslots_size)
		*keyslots_size = ksize;

	return 0;
}

uint64_t crypt_get_data_offset(struct crypt_device *cd)
{
	if (!cd)
		return 0;

	if (isPLAIN(cd->type))
		return cd->u.plain.hdr.offset;

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.payloadOffset;

	if (isLUKS2(cd->type))
		return LUKS2_get_data_offset(&cd->u.luks2.hdr);

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.hdr.offset;

	if (isTCRYPT(cd->type))
		return TCRYPT_get_data_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);

	if (isBITLK(cd->type))
		return cd->u.bitlk.params.volume_header_size / SECTOR_SIZE;

	return cd->data_offset;
}

uint64_t crypt_get_iv_offset(struct crypt_device *cd)
{
	if (!cd)
		return 0;

	if (isPLAIN(cd->type))
		return cd->u.plain.hdr.skip;

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.hdr.skip;

	if (isTCRYPT(cd->type))
		return TCRYPT_get_iv_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);

	return 0;
}

crypt_keyslot_info crypt_keyslot_status(struct crypt_device *cd, int keyslot)
{
	if (_onlyLUKS(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED) < 0)
		return CRYPT_SLOT_INVALID;

	if (isLUKS1(cd->type))
		return LUKS_keyslot_info(&cd->u.luks1.hdr, keyslot);
	else if(isLUKS2(cd->type))
		return LUKS2_keyslot_info(&cd->u.luks2.hdr, keyslot);

	return CRYPT_SLOT_INVALID;
}

int crypt_keyslot_max(const char *type)
{
	if (type && isLUKS1(type))
		return LUKS_NUMKEYS;

	if (type && isLUKS2(type))
		return LUKS2_KEYSLOTS_MAX;

	return -EINVAL;
}

int crypt_keyslot_area(struct crypt_device *cd,
	int keyslot,
	uint64_t *offset,
	uint64_t *length)
{
	if (_onlyLUKS(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED) || !offset || !length)
		return -EINVAL;

	if (isLUKS2(cd->type))
		return LUKS2_keyslot_area(&cd->u.luks2.hdr, keyslot, offset, length);

	return LUKS_keyslot_area(&cd->u.luks1.hdr, keyslot, offset, length);
}

crypt_keyslot_priority crypt_keyslot_get_priority(struct crypt_device *cd, int keyslot)
{
	if (_onlyLUKS(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED))
		return CRYPT_SLOT_PRIORITY_INVALID;

	if (keyslot < 0 || keyslot >= crypt_keyslot_max(cd->type))
		return CRYPT_SLOT_PRIORITY_INVALID;

	if (isLUKS2(cd->type))
		return LUKS2_keyslot_priority_get(cd, &cd->u.luks2.hdr, keyslot);

	return CRYPT_SLOT_PRIORITY_NORMAL;
}

int crypt_keyslot_set_priority(struct crypt_device *cd, int keyslot, crypt_keyslot_priority priority)
{
	int r;

	log_dbg(cd, "Setting keyslot %d to priority %d.", keyslot, priority);

	if (priority == CRYPT_SLOT_PRIORITY_INVALID)
		return -EINVAL;

	if (keyslot < 0 || keyslot >= crypt_keyslot_max(cd->type))
		return -EINVAL;

	if ((r = onlyLUKS2(cd)))
		return r;

	return LUKS2_keyslot_priority_set(cd, &cd->u.luks2.hdr, keyslot, priority, 1);
}

const char *crypt_get_type(struct crypt_device *cd)
{
	return cd ? cd->type : NULL;
}

const char *crypt_get_default_type(void)
{
	return DEFAULT_LUKS_FORMAT;
}

int crypt_get_verity_info(struct crypt_device *cd,
	struct crypt_params_verity *vp)
{
	if (!cd || !isVERITY(cd->type) || !vp)
		return -EINVAL;

	vp->data_device = device_path(cd->device);
	vp->hash_device = mdata_device_path(cd);
	vp->fec_device  = device_path(cd->u.verity.fec_device);
	vp->fec_area_offset = cd->u.verity.hdr.fec_area_offset;
	vp->fec_roots = cd->u.verity.hdr.fec_roots;
	vp->hash_name = cd->u.verity.hdr.hash_name;
	vp->salt = cd->u.verity.hdr.salt;
	vp->salt_size = cd->u.verity.hdr.salt_size;
	vp->data_block_size = cd->u.verity.hdr.data_block_size;
	vp->hash_block_size = cd->u.verity.hdr.hash_block_size;
	vp->data_size = cd->u.verity.hdr.data_size;
	vp->hash_area_offset = cd->u.verity.hdr.hash_area_offset;
	vp->hash_type = cd->u.verity.hdr.hash_type;
	vp->flags = cd->u.verity.hdr.flags & (CRYPT_VERITY_NO_HEADER | CRYPT_VERITY_ROOT_HASH_SIGNATURE);
	return 0;
}

int crypt_get_integrity_info(struct crypt_device *cd,
	struct crypt_params_integrity *ip)
{
	if (!cd || !ip)
		return -EINVAL;

	if (isINTEGRITY(cd->type)) {
		ip->journal_size = cd->u.integrity.params.journal_size;
		ip->journal_watermark = cd->u.integrity.params.journal_watermark;
		ip->journal_commit_time = cd->u.integrity.params.journal_commit_time;
		ip->interleave_sectors = cd->u.integrity.params.interleave_sectors;
		ip->tag_size = cd->u.integrity.params.tag_size;
		ip->sector_size = cd->u.integrity.params.sector_size;
		ip->buffer_sectors = cd->u.integrity.params.buffer_sectors;

		ip->integrity = cd->u.integrity.params.integrity;
		ip->integrity_key_size = crypt_get_integrity_key_size(cd);

		ip->journal_integrity = cd->u.integrity.params.journal_integrity;
		ip->journal_integrity_key_size = cd->u.integrity.params.journal_integrity_key_size;
		ip->journal_integrity_key = NULL;

		ip->journal_crypt = cd->u.integrity.params.journal_crypt;
		ip->journal_crypt_key_size = cd->u.integrity.params.journal_crypt_key_size;
		ip->journal_crypt_key = NULL;
		return 0;
	} else if (isLUKS2(cd->type)) {
		ip->journal_size = 0; // FIXME
		ip->journal_watermark = 0; // FIXME
		ip->journal_commit_time = 0; // FIXME
		ip->interleave_sectors = 0; // FIXME
		ip->sector_size = crypt_get_sector_size(cd);
		ip->buffer_sectors = 0; // FIXME

		ip->integrity = LUKS2_get_integrity(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);
		ip->integrity_key_size = crypt_get_integrity_key_size(cd);
		ip->tag_size = INTEGRITY_tag_size(cd, ip->integrity, crypt_get_cipher(cd), crypt_get_cipher_mode(cd));

		ip->journal_integrity = NULL;
		ip->journal_integrity_key_size = 0;
		ip->journal_integrity_key = NULL;

		ip->journal_crypt = NULL;
		ip->journal_crypt_key_size = 0;
		ip->journal_crypt_key = NULL;
		return 0;
	}

	return -ENOTSUP;
}

int crypt_convert(struct crypt_device *cd,
		  const char *type,
		  void *params)
{
	struct luks_phdr hdr1;
	struct luks2_hdr hdr2;
	int r;

	if (!type)
		return -EINVAL;

	log_dbg(cd, "Converting LUKS device to type %s", type);

	if ((r = onlyLUKS(cd)))
		return r;

	if (isLUKS1(cd->type) && isLUKS2(type))
		r = LUKS2_luks1_to_luks2(cd, &cd->u.luks1.hdr, &hdr2);
	else if (isLUKS2(cd->type) && isLUKS1(type))
		r = LUKS2_luks2_to_luks1(cd, &cd->u.luks2.hdr, &hdr1);
	else
		return -EINVAL;

	if (r < 0) {
		/* in-memory header may be invalid after failed conversion */
		_luks2_reload(cd);
		if (r == -EBUSY)
			log_err(cd, _("Cannot convert device %s which is still in use."), mdata_device_path(cd));
		return r;
	}

	crypt_free_type(cd);

	return crypt_load(cd, type, params);
}

/* Internal access function to header pointer */
void *crypt_get_hdr(struct crypt_device *cd, const char *type)
{
	/* If requested type differs, ignore it */
	if (strcmp(cd->type, type))
		return NULL;

	if (isPLAIN(cd->type))
		return &cd->u.plain;

	if (isLUKS1(cd->type))
		return &cd->u.luks1.hdr;

	if (isLUKS2(cd->type))
		return &cd->u.luks2.hdr;

	if (isLOOPAES(cd->type))
		return &cd->u.loopaes;

	if (isVERITY(cd->type))
		return &cd->u.verity;

	if (isTCRYPT(cd->type))
		return &cd->u.tcrypt;

	return NULL;
}

/* internal only */
struct luks2_reenc_context *crypt_get_reenc_context(struct crypt_device *cd)
{
	return cd->u.luks2.rh;
}

/* internal only */
void crypt_set_reenc_context(struct crypt_device *cd, struct luks2_reenc_context *rh)
{
	cd->u.luks2.rh = rh;
}

/*
 * Token handling
 */
int crypt_activate_by_token(struct crypt_device *cd,
	const char *name, int token, void *usrptr, uint32_t flags)
{
	int r;

	log_dbg(cd, "%s volume %s using token %d.",
		name ? "Activating" : "Checking", name ?: "passphrase", token);

	if ((r = _onlyLUKS2(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED, 0)))
		return r;

	if ((flags & CRYPT_ACTIVATE_KEYRING_KEY) && !crypt_use_keyring_for_vk(cd))
		return -EINVAL;

	if ((flags & CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY) && name)
		return -EINVAL;

	if (token == CRYPT_ANY_TOKEN)
		return LUKS2_token_open_and_activate_any(cd, &cd->u.luks2.hdr, name, flags);

	return LUKS2_token_open_and_activate(cd, &cd->u.luks2.hdr, token, name, flags, usrptr);
}

int crypt_token_json_get(struct crypt_device *cd, int token, const char **json)
{
	int r;

	if (!json)
		return -EINVAL;

	log_dbg(cd, "Requesting JSON for token %d.", token);

	if ((r = _onlyLUKS2(cd, CRYPT_CD_UNRESTRICTED, 0)))
		return r;

	return LUKS2_token_json_get(cd, &cd->u.luks2.hdr, token, json) ?: token;
}

int crypt_token_json_set(struct crypt_device *cd, int token, const char *json)
{
	int r;

	log_dbg(cd, "Updating JSON for token %d.", token);

	if ((r = onlyLUKS2(cd)))
		return r;

	return LUKS2_token_create(cd, &cd->u.luks2.hdr, token, json, 1);
}

crypt_token_info crypt_token_status(struct crypt_device *cd, int token, const char **type)
{
	if (_onlyLUKS2(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED, 0))
		return CRYPT_TOKEN_INVALID;

	return LUKS2_token_status(cd, &cd->u.luks2.hdr, token, type);
}

int crypt_token_luks2_keyring_get(struct crypt_device *cd,
	int token,
	struct crypt_token_params_luks2_keyring *params)
{
	crypt_token_info token_info;
	const char *type;
	int r;

	if (!params)
		return -EINVAL;

	log_dbg(cd, "Requesting LUKS2 keyring token %d.", token);

	if ((r = _onlyLUKS2(cd, CRYPT_CD_UNRESTRICTED, 0)))
		return r;

	token_info = LUKS2_token_status(cd, &cd->u.luks2.hdr, token, &type);
	switch (token_info) {
	case CRYPT_TOKEN_INVALID:
		log_dbg(cd, "Token %d is invalid.", token);
		return -EINVAL;
	case CRYPT_TOKEN_INACTIVE:
		log_dbg(cd, "Token %d is inactive.", token);
		return -EINVAL;
	case CRYPT_TOKEN_INTERNAL:
		if (!strcmp(type, LUKS2_TOKEN_KEYRING))
			break;
		/* Fall through */
	case CRYPT_TOKEN_INTERNAL_UNKNOWN:
	case CRYPT_TOKEN_EXTERNAL:
	case CRYPT_TOKEN_EXTERNAL_UNKNOWN:
		log_dbg(cd, "Token %d has unexpected type %s.", token, type);
		return -EINVAL;
	}

	return LUKS2_builtin_token_get(cd, &cd->u.luks2.hdr, token, LUKS2_TOKEN_KEYRING, params);
}

int crypt_token_luks2_keyring_set(struct crypt_device *cd,
	int token,
	const struct crypt_token_params_luks2_keyring *params)
{
	int r;

	if (!params)
		return -EINVAL;

	log_dbg(cd, "Creating new LUKS2 keyring token (%d).", token);

	if ((r = onlyLUKS2(cd)))
		return r;

	return LUKS2_builtin_token_create(cd, &cd->u.luks2.hdr, token, LUKS2_TOKEN_KEYRING, params, 1);
}

int crypt_token_assign_keyslot(struct crypt_device *cd, int token, int keyslot)
{
	int r;

	if ((r = onlyLUKS2(cd)))
		return r;

	return LUKS2_token_assign(cd, &cd->u.luks2.hdr, keyslot, token, 1, 1);
}

int crypt_token_unassign_keyslot(struct crypt_device *cd, int token, int keyslot)
{
	int r;

	if ((r = onlyLUKS2(cd)))
		return r;

	return LUKS2_token_assign(cd, &cd->u.luks2.hdr, keyslot, token, 0, 1);
}

int crypt_token_is_assigned(struct crypt_device *cd, int token, int keyslot)
{
	int r;

	if ((r = _onlyLUKS2(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED, 0)))
		return r;

	return LUKS2_token_is_assigned(cd, &cd->u.luks2.hdr, keyslot, token);
}

/* Internal only */
int crypt_metadata_locking_enabled(void)
{
	return _metadata_locking;
}

int crypt_metadata_locking(struct crypt_device *cd, int enable)
{
	if (enable && !_metadata_locking)
		return -EPERM;

	_metadata_locking = enable ? 1 : 0;
	return 0;
}

int crypt_persistent_flags_set(struct crypt_device *cd, crypt_flags_type type, uint32_t flags)
{
	int r;

	if ((r = onlyLUKS2(cd)))
		return r;

	if (type == CRYPT_FLAGS_ACTIVATION)
		return LUKS2_config_set_flags(cd, &cd->u.luks2.hdr, flags);

	if (type == CRYPT_FLAGS_REQUIREMENTS)
		return LUKS2_config_set_requirements(cd, &cd->u.luks2.hdr, flags, true);

	return -EINVAL;
}

int crypt_persistent_flags_get(struct crypt_device *cd, crypt_flags_type type, uint32_t *flags)
{
	int r;

	if (!flags)
		return -EINVAL;

	if ((r = _onlyLUKS2(cd, CRYPT_CD_UNRESTRICTED, 0)))
		return r;

	if (type == CRYPT_FLAGS_ACTIVATION)
		return LUKS2_config_get_flags(cd, &cd->u.luks2.hdr, flags);

	if (type == CRYPT_FLAGS_REQUIREMENTS)
		return LUKS2_config_get_requirements(cd, &cd->u.luks2.hdr, flags);

	return -EINVAL;
}

static int update_volume_key_segment_digest(struct crypt_device *cd, struct luks2_hdr *hdr, int digest, int commit)
{
	int r;

	/* Remove any assignments in memory */
	r = LUKS2_digest_segment_assign(cd, hdr, CRYPT_DEFAULT_SEGMENT, CRYPT_ANY_DIGEST, 0, 0);
	if (r)
		return r;

	/* Assign it to the specific digest */
	return LUKS2_digest_segment_assign(cd, hdr, CRYPT_DEFAULT_SEGMENT, digest, 1, commit);
}

static int verify_and_update_segment_digest(struct crypt_device *cd,
		struct luks2_hdr *hdr, int keyslot,
		const char *volume_key, size_t volume_key_size,
		const char *password, size_t password_size)
{
	int digest, r;
	struct volume_key *vk = NULL;

	if (keyslot < 0 || (volume_key && !volume_key_size))
		return -EINVAL;

	if (volume_key)
		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	else {
		r = LUKS2_keyslot_open(cd, keyslot, CRYPT_ANY_SEGMENT, password, password_size, &vk);
		if (r != keyslot) {
			r = -EINVAL;
			goto out;
		}
	}

	if (!vk)
		return -ENOMEM;

	/* check volume_key (param) digest matches keyslot digest */
	r = LUKS2_digest_verify(cd, hdr, vk, keyslot);
	if (r < 0)
		goto out;
	digest = r;

	/* nothing to do, volume key in keyslot is already assigned to default segment */
	r = LUKS2_digest_verify_by_segment(cd, hdr, CRYPT_DEFAULT_SEGMENT, vk);
	if (r >= 0)
		goto out;

	/* FIXME: check new volume key is usable with current default segment */

	r = update_volume_key_segment_digest(cd, &cd->u.luks2.hdr, digest, 1);
	if (r)
		log_err(cd, _("Failed to assign keyslot %u as the new volume key."), keyslot);
out:
	crypt_free_volume_key(vk);
	return r < 0 ? r : keyslot;
}


int crypt_keyslot_add_by_key(struct crypt_device *cd,
	int keyslot,
	const char *volume_key,
	size_t volume_key_size,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	int digest, r;
	struct luks2_keyslot_params params;
	struct volume_key *vk = NULL;

	if (!passphrase || ((flags & CRYPT_VOLUME_KEY_NO_SEGMENT) &&
			    (flags & CRYPT_VOLUME_KEY_SET)))
		return -EINVAL;

	log_dbg(cd, "Adding new keyslot %d with volume key %sassigned to a crypt segment.",
		keyslot, flags & CRYPT_VOLUME_KEY_NO_SEGMENT ? "un" : "");

	if ((r = onlyLUKS2(cd)))
		return r;

	/* new volume key assignment */
	if ((flags & CRYPT_VOLUME_KEY_SET) && crypt_keyslot_status(cd, keyslot) > CRYPT_SLOT_INACTIVE)
		return verify_and_update_segment_digest(cd, &cd->u.luks2.hdr,
			keyslot, volume_key, volume_key_size, passphrase, passphrase_size);

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r < 0)
		return r;

	if (volume_key)
		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	else if (flags & CRYPT_VOLUME_KEY_NO_SEGMENT)
		vk = crypt_generate_volume_key(cd, volume_key_size);
	else if (cd->volume_key)
		vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);
	else
		return -EINVAL;

	if (!vk)
		return -ENOMEM;

	/* if key matches volume key digest tear down new vk flag */
	digest = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
	if (digest >= 0)
		flags &= ~CRYPT_VOLUME_KEY_SET;

	/* if key matches any existing digest, do not create new digest */
	if (digest < 0 && (flags & CRYPT_VOLUME_KEY_DIGEST_REUSE))
		digest = LUKS2_digest_any_matching(cd, &cd->u.luks2.hdr, vk);

	/* no segment flag or new vk flag requires new key digest */
	if (flags & (CRYPT_VOLUME_KEY_NO_SEGMENT | CRYPT_VOLUME_KEY_SET)) {
		if (digest < 0 || !(flags & CRYPT_VOLUME_KEY_DIGEST_REUSE))
			digest = LUKS2_digest_create(cd, "pbkdf2", &cd->u.luks2.hdr, vk);
	}

	r = digest;
	if (r < 0) {
		log_err(cd, _("Volume key does not match the volume."));
		goto out;
	}

	r = LUKS2_keyslot_params_default(cd, &cd->u.luks2.hdr, &params);
	if (r < 0) {
		log_err(cd, _("Failed to initialize default LUKS2 keyslot parameters."));
		goto out;
	}

	r = LUKS2_digest_assign(cd, &cd->u.luks2.hdr, keyslot, digest, 1, 0);
	if (r < 0) {
		log_err(cd, _("Failed to assign keyslot %d to digest."), keyslot);
		goto out;
	}

	r = LUKS2_keyslot_store(cd, &cd->u.luks2.hdr, keyslot,
				passphrase, passphrase_size, vk, &params);

	if (r >= 0 && (flags & CRYPT_VOLUME_KEY_SET))
		r = update_volume_key_segment_digest(cd, &cd->u.luks2.hdr, digest, 1);
out:
	crypt_free_volume_key(vk);
	if (r < 0) {
		_luks2_reload(cd);
		return r;
	}
	return keyslot;
}

/*
 * Keyring handling
 */

int crypt_use_keyring_for_vk(struct crypt_device *cd)
{
	uint32_t dmc_flags;

	/* dm backend must be initialized */
	if (!cd || !isLUKS2(cd->type))
		return 0;

	if (!_vk_via_keyring || !kernel_keyring_support())
		return 0;

	if (dm_flags(cd, DM_CRYPT, &dmc_flags))
		return dmcrypt_keyring_bug() ? 0 : 1;

	return (dmc_flags & DM_KERNEL_KEYRING_SUPPORTED);
}

int crypt_volume_key_keyring(struct crypt_device *cd, int enable)
{
	_vk_via_keyring = enable ? 1 : 0;
	return 0;
}

/* internal only */
int crypt_volume_key_load_in_keyring(struct crypt_device *cd, struct volume_key *vk)
{
	int r;
	const char *type_name = key_type_name(LOGON_KEY);

	if (!vk || !cd || !type_name)
		return -EINVAL;

	if (!vk->key_description) {
		log_dbg(cd, "Invalid key description");
		return -EINVAL;
	}

	log_dbg(cd, "Loading key (%zu bytes, type %s) in thread keyring.", vk->keylength, type_name);

	r = keyring_add_key_in_thread_keyring(LOGON_KEY, vk->key_description, vk->key, vk->keylength);
	if (r) {
		log_dbg(cd, "keyring_add_key_in_thread_keyring failed (error %d)", r);
		log_err(cd, _("Failed to load key in kernel keyring."));
	} else
		crypt_set_key_in_keyring(cd, 1);

	return r;
}

/* internal only */
int crypt_key_in_keyring(struct crypt_device *cd)
{
	return cd ? cd->key_in_keyring : 0;
}

/* internal only */
void crypt_set_key_in_keyring(struct crypt_device *cd, unsigned key_in_keyring)
{
	if (!cd)
		return;

	cd->key_in_keyring = key_in_keyring;
}

/* internal only */
void crypt_drop_keyring_key_by_description(struct crypt_device *cd, const char *key_description, key_type_t ktype)
{
	int r;
	const char *type_name = key_type_name(ktype);

	if (!key_description || !type_name)
		return;

	log_dbg(cd, "Requesting keyring %s key for revoke and unlink.", type_name);

	r = keyring_revoke_and_unlink_key(ktype, key_description);
	if (r)
		log_dbg(cd, "keyring_revoke_and_unlink_key failed (error %d)", r);
	crypt_set_key_in_keyring(cd, 0);
}

/* internal only */
void crypt_drop_keyring_key(struct crypt_device *cd, struct volume_key *vks)
{
	struct volume_key *vk = vks;

	while (vk) {
		crypt_drop_keyring_key_by_description(cd, vk->key_description, LOGON_KEY);
		vk = crypt_volume_key_next(vk);
	}
}

int crypt_activate_by_keyring(struct crypt_device *cd,
			      const char *name,
			      const char *key_description,
			      int keyslot,
			      uint32_t flags)
{
	char *passphrase;
	size_t passphrase_size;
	int r;

	if (!cd || !key_description)
		return -EINVAL;

	log_dbg(cd, "%s volume %s [keyslot %d] using passphrase in keyring.",
		name ? "Activating" : "Checking", name ?: "passphrase", keyslot);

	if (!kernel_keyring_support()) {
		log_err(cd, _("Kernel keyring is not supported by the kernel."));
		return -EINVAL;
	}

	r = _activate_check_status(cd, name, flags & CRYPT_ACTIVATE_REFRESH);
	if (r < 0)
		return r;

	r = keyring_get_passphrase(key_description, &passphrase, &passphrase_size);
	if (r < 0) {
		log_err(cd, _("Failed to read passphrase from keyring (error %d)."), r);
		return -EINVAL;
	}

	r = _activate_by_passphrase(cd, name, keyslot, passphrase, passphrase_size, flags);

	crypt_safe_memzero(passphrase, passphrase_size);
	free(passphrase);

	return r;
}

/*
 * Workaround for serialization of parallel activation and memory-hard PBKDF
 * In specific situation (systemd activation) this causes OOM killer activation.
 * For now, let's provide this ugly way to serialize unlocking of devices.
 */
int crypt_serialize_lock(struct crypt_device *cd)
{
	if (!cd->memory_hard_pbkdf_lock_enabled)
		return 0;

	log_dbg(cd, "Taking global memory-hard access serialization lock.");
	if (crypt_write_lock(cd, "memory-hard-access", true, &cd->pbkdf_memory_hard_lock)) {
		log_err(cd, _("Failed to acquire global memory-hard access serialization lock."));
		cd->pbkdf_memory_hard_lock = NULL;
		return -EINVAL;
	}

	return 0;
}

void crypt_serialize_unlock(struct crypt_device *cd)
{
	if (!cd->memory_hard_pbkdf_lock_enabled)
		return;

	crypt_unlock_internal(cd, cd->pbkdf_memory_hard_lock);
	cd->pbkdf_memory_hard_lock = NULL;
}

crypt_reencrypt_info crypt_reencrypt_status(struct crypt_device *cd,
		struct crypt_params_reencrypt *params)
{
	if (!cd || !isLUKS2(cd->type))
		return CRYPT_REENCRYPT_NONE;

	if (_onlyLUKS2(cd, CRYPT_CD_QUIET, CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return CRYPT_REENCRYPT_INVALID;

	return LUKS2_reencrypt_status(cd, params);
}

static void __attribute__((destructor)) libcryptsetup_exit(void)
{
	crypt_backend_destroy();
	crypt_random_exit();
}
