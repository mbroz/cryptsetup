// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * libcryptsetup - cryptsetup library
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/utsname.h>
#include <errno.h>

#include "libcryptsetup.h"
#include "luks1/luks.h"
#include "luks2/luks2.h"
#include "loopaes/loopaes.h"
#include "verity/verity.h"
#include "tcrypt/tcrypt.h"
#include "integrity/integrity.h"
#include "bitlk/bitlk.h"
#include "fvault2/fvault2.h"
#include "utils_device_locking.h"
#include "internal.h"
#include "keyslot_context.h"
#include "luks2/hw_opal/hw_opal.h"

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

	bool link_vk_to_keyring;
	int32_t keyring_to_link_vk;
	const char *user_key_name1;
	const char *user_key_name2;
	key_type_t keyring_key_type;

	uint64_t data_offset;
	uint64_t metadata_size; /* Used in LUKS2 format */
	uint64_t keyslots_size; /* Used in LUKS2 format */

	/* Workaround for OOM during parallel activation (like in systemd) */
	bool memory_hard_pbkdf_lock_enabled;
	struct crypt_lock_handle *pbkdf_memory_hard_lock;

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
		struct luks2_reencrypt *rh;
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
	struct { /* used in CRYPT_FVAULT2 */
		struct fvault2_params params;
	} fvault2;
	struct { /* used if initialized without header by name */
		char *active_name;
		/* buffers, must refresh from kernel on every query */
		char cipher_spec[MAX_CIPHER_LEN*2+1];
		char cipher[MAX_CIPHER_LEN];
		char integrity_spec[MAX_INTEGRITY_LEN];
		const char *cipher_mode;
		unsigned int key_size;
		uint32_t sector_size;
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
static void *_default_log_usrptr = NULL;
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
		_default_log(level, msg, _default_log_usrptr);
	/* Default to stdout/stderr if there is no callback. */
	else
		fprintf(level == CRYPT_LOG_ERROR ? stderr : stdout, "%s", msg);
}

__attribute__((format(printf, 3, 4)))
void crypt_logf(struct crypt_device *cd, int level, const char *format, ...)
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

uint64_t crypt_get_metadata_size_bytes(struct crypt_device *cd)
{
	assert(cd);
	return cd->metadata_size;
}

uint64_t crypt_get_keyslots_size_bytes(struct crypt_device *cd)
{
	assert(cd);
	return cd->keyslots_size;
}

uint64_t crypt_get_data_offset_sectors(struct crypt_device *cd)
{
	assert(cd);
	return cd->data_offset;
}

int crypt_opal_supported(struct crypt_device *cd, struct device *opal_device)
{
	int r;

	assert(cd);
	assert(opal_device);

	r = opal_supported(cd, opal_device);
	if (r <= 0) {
		if (r == -ENOTSUP)
			log_err(cd, _("OPAL support is disabled in libcryptsetup."));
		else
			log_err(cd, _("Device %s or kernel does not support OPAL encryption."),
				    device_path(opal_device));
		r = -EINVAL;
	} else
		r = 0;

	return r;
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
		log_dbg(ctx, "Crypto backend (%s%s) initialized in cryptsetup library version %s.",
			crypt_backend_version(), crypt_argon2_version(), PACKAGE_VERSION);

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
	void *key = NULL;

	if (!key_size)
		return -EINVAL;

	if (hash_name) {
		key = crypt_safe_alloc(key_size);
		if (!key)
			return -ENOMEM;

		r = crypt_plain_hash(cd, hash_name, key, key_size, pass, passLen);
		if (r < 0) {
			if (r == -ENOENT)
				log_err(cd, _("Hash algorithm %s not supported."),
					hash_name);
			else
				log_err(cd, _("Key processing error (using hash %s)."),
					hash_name);
			crypt_safe_free(key);
			return -EINVAL;
		}
		*vk = crypt_alloc_volume_key_by_safe_alloc(&key);
	} else if (passLen >= key_size) {
		*vk = crypt_alloc_volume_key(key_size, pass);
	} else {
		key = crypt_safe_alloc(key_size);
		if (!key)
			return -ENOMEM;

		crypt_safe_memcpy(key, pass, passLen);

		*vk = crypt_alloc_volume_key_by_safe_alloc(&key);
	}

	r = *vk ? 0 : -ENOMEM;

	crypt_safe_free(key);

	return r;
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

static int isFVAULT2(const char *type)
{
	return (type && !strcmp(CRYPT_FVAULT2, type));
}

static int _onlyLUKS(struct crypt_device *cd, uint32_t cdflags, uint32_t mask)
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

	return LUKS2_unmet_requirements(cd, &cd->u.luks2.hdr, mask, cdflags & CRYPT_CD_QUIET);
}

static int onlyLUKSunrestricted(struct crypt_device *cd)
{
	return _onlyLUKS(cd, CRYPT_CD_UNRESTRICTED, 0);
}

static int onlyLUKSnoRequirements(struct crypt_device *cd)
{
	return _onlyLUKS(cd, 0, 0);
}

static int onlyLUKS(struct crypt_device *cd)
{
	return _onlyLUKS(cd, 0, CRYPT_REQUIREMENT_OPAL | CRYPT_REQUIREMENT_INLINE_HW_TAGS);
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

static int onlyLUKS2unrestricted(struct crypt_device *cd)
{
	return _onlyLUKS2(cd, CRYPT_CD_UNRESTRICTED, 0);
}

/* Internal only */
int onlyLUKS2(struct crypt_device *cd)
{
	return _onlyLUKS2(cd, 0, CRYPT_REQUIREMENT_OPAL | CRYPT_REQUIREMENT_INLINE_HW_TAGS);
}

/* Internal only */
int onlyLUKS2reencrypt(struct crypt_device *cd)
{
	return _onlyLUKS2(cd, 0, CRYPT_REQUIREMENT_ONLINE_REENCRYPT);
}

static void crypt_set_null_type(struct crypt_device *cd)
{
	free(cd->type);
	cd->type = NULL;
	cd->data_offset = 0;
	cd->metadata_size = 0;
	cd->keyslots_size = 0;
	crypt_safe_memzero(&cd->u, sizeof(cd->u));
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
			*keyslot = LUKS2_keyslot_find_empty(cd, &cd->u.luks2.hdr, 0);
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
				*keyslot, crypt_keyslot_max(cd->type) - 1);
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
			crypt_get_data_offset(cd), NULL, 0, 0, crypt_get_sector_size(cd));
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
	if (!cd) {
		_default_log = log;
		_default_log_usrptr = usrptr;
	} else {
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
	if (r < 0) {
		free(h);
		return r;
	}

	dm_backend_init(NULL);

	h->rng_type = crypt_random_default_key_rng();

	*cd = h;
	return 0;
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

	r = crypt_check_data_device_size(cd);
	if (!r && isLUKS2(cd->type))
		device_set_block_size(crypt_data_device(cd), LUKS2_get_sector_size(&cd->u.luks2.hdr));

	return r;
}

int crypt_set_data_device(struct crypt_device *cd, const char *device)
{
	/* metadata device must be set */
	if (!cd || !cd->device || !device)
		return -EINVAL;

	log_dbg(cd, "Setting ciphertext data device to %s.", device ?: "(none)");

	if (!isLUKS1(cd->type) && !isLUKS2(cd->type) && !isVERITY(cd->type) &&
	    !isINTEGRITY(cd->type) && !isTCRYPT(cd->type)) {
		log_err(cd, _("This operation is not supported for this device type."));
		return -EINVAL;
	}

	if (isLUKS2(cd->type) && crypt_get_luks2_reencrypt(cd)) {
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

static void crypt_free_type(struct crypt_device *cd, const char *force_type)
{
	const char *type = force_type ?: cd->type;

	if (isPLAIN(type)) {
		free(CONST_CAST(void*)cd->u.plain.hdr.hash);
		free(cd->u.plain.cipher);
		free(cd->u.plain.cipher_spec);
	} else if (isLUKS2(type)) {
		LUKS2_reencrypt_free(cd, cd->u.luks2.rh);
		LUKS2_hdr_free(cd, &cd->u.luks2.hdr);
		free(cd->u.luks2.keyslot_cipher);
	} else if (isLUKS1(type)) {
		free(cd->u.luks1.cipher_spec);
	} else if (isLOOPAES(type)) {
		free(CONST_CAST(void*)cd->u.loopaes.hdr.hash);
		free(cd->u.loopaes.cipher);
		free(cd->u.loopaes.cipher_spec);
	} else if (isVERITY(type)) {
		free(CONST_CAST(void*)cd->u.verity.hdr.hash_name);
		free(CONST_CAST(void*)cd->u.verity.hdr.data_device);
		free(CONST_CAST(void*)cd->u.verity.hdr.hash_device);
		free(CONST_CAST(void*)cd->u.verity.hdr.fec_device);
		free(CONST_CAST(void*)cd->u.verity.hdr.salt);
		free(CONST_CAST(void*)cd->u.verity.root_hash);
		free(cd->u.verity.uuid);
		device_free(cd, cd->u.verity.fec_device);
	} else if (isINTEGRITY(type)) {
		free(CONST_CAST(void*)cd->u.integrity.params.integrity);
		free(CONST_CAST(void*)cd->u.integrity.params.journal_integrity);
		free(CONST_CAST(void*)cd->u.integrity.params.journal_crypt);
		crypt_free_volume_key(cd->u.integrity.journal_crypt_key);
		crypt_free_volume_key(cd->u.integrity.journal_mac_key);
	} else if (isBITLK(type)) {
		free(cd->u.bitlk.cipher_spec);
		BITLK_bitlk_metadata_free(&cd->u.bitlk.params);
	} else if (!type) {
		free(cd->u.none.active_name);
		cd->u.none.active_name = NULL;
	}

	crypt_set_null_type(cd);
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

	if (!reload) {
		type = strdup(CRYPT_LUKS2);
		if (!type) {
			r = -ENOMEM;
			goto out;
		}
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

static void _luks2_rollback(struct crypt_device *cd)
{
	if (!cd || !isLUKS2(cd->type))
		return;

	if (LUKS2_hdr_rollback(cd, &cd->u.luks2.hdr)) {
		log_err(cd, _("Failed to rollback LUKS2 metadata in memory."));
		return;
	}

	free(cd->u.luks2.keyslot_cipher);
	cd->u.luks2.keyslot_cipher = NULL;
}

static int _crypt_load_luks(struct crypt_device *cd, const char *requested_type,
			    bool quiet, bool repair)
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
		if (isLUKS2(cd->type)) {
			log_dbg(cd, "Context is already initialized to type %s", cd->type);
			return -EINVAL;
		}

		if (verify_pbkdf_params(cd, &cd->pbkdf)) {
			r = init_pbkdf_type(cd, NULL, CRYPT_LUKS1);
			if (r)
				return r;
		}

		r = LUKS_read_phdr(&hdr, !quiet, repair, cd);
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
		if (isLUKS1(cd->type)) {
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
		if (!r)
			device_set_block_size(crypt_data_device(cd), LUKS2_get_sector_size(&cd->u.luks2.hdr));
		else if (!quiet)
			log_err(cd, _("Device %s is not a valid LUKS device."), mdata_device_path(cd));
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
		goto out;

	if (!cd->type && !(cd->type = strdup(CRYPT_TCRYPT)))
		r = -ENOMEM;
out:
	if (r < 0)
		crypt_free_type(cd, CRYPT_TCRYPT);
	return r;
}

static int _crypt_load_verity(struct crypt_device *cd, struct crypt_params_verity *params)
{
	int r;
	uint64_t sb_offset = 0;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	if (params && params->flags & CRYPT_VERITY_NO_HEADER)
		return -EINVAL;

	if (params)
		sb_offset = params->hash_area_offset;

	r = VERITY_read_sb(cd, sb_offset, &cd->u.verity.uuid, &cd->u.verity.hdr);
	if (r < 0)
		goto out;

	if (!cd->type && !(cd->type = strdup(CRYPT_VERITY))) {
		r = -ENOMEM;
		goto out;
	}

	if (params)
		cd->u.verity.hdr.flags = params->flags;

	/* Hash availability checked in sb load */
	cd->u.verity.root_hash_size = crypt_hash_size(cd->u.verity.hdr.hash_name);
	if (cd->u.verity.root_hash_size > 4096) {
		r = -EINVAL;
		goto out;
	}

	if (params && params->data_device &&
	    (r = crypt_set_data_device(cd, params->data_device)) < 0)
		goto out;

	if (params && params->fec_device) {
		r = device_alloc(cd, &cd->u.verity.fec_device, params->fec_device);
		if (r < 0)
			goto out;
		cd->u.verity.hdr.fec_area_offset = params->fec_area_offset;
		cd->u.verity.hdr.fec_roots = params->fec_roots;
	}
out:
	if (r < 0)
		crypt_free_type(cd, CRYPT_VERITY);
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
		goto out;

	// FIXME: add checks for fields in integrity sb vs params

	r = -ENOMEM;
	if (params) {
		cd->u.integrity.params.journal_watermark = params->journal_watermark;
		cd->u.integrity.params.journal_commit_time = params->journal_commit_time;
		cd->u.integrity.params.buffer_sectors = params->buffer_sectors;
		if (params->integrity &&
		    !(cd->u.integrity.params.integrity = strdup(params->integrity)))
			goto out;
		cd->u.integrity.params.integrity_key_size = params->integrity_key_size;
		if (params->journal_integrity &&
		    !(cd->u.integrity.params.journal_integrity = strdup(params->journal_integrity)))
			goto out;
		if (params->journal_crypt &&
		    !(cd->u.integrity.params.journal_crypt = strdup(params->journal_crypt)))
			goto out;

		if (params->journal_crypt_key) {
			cd->u.integrity.journal_crypt_key =
				crypt_alloc_volume_key(params->journal_crypt_key_size,
						       params->journal_crypt_key);
			if (!cd->u.integrity.journal_crypt_key)
				goto out;
		}
		if (params->journal_integrity_key) {
			cd->u.integrity.journal_mac_key =
				crypt_alloc_volume_key(params->journal_integrity_key_size,
						       params->journal_integrity_key);
			if (!cd->u.integrity.journal_mac_key)
				goto out;
		}
	}

	if (!cd->type && !(cd->type = strdup(CRYPT_INTEGRITY)))
		goto out;
	r = 0;
out:
	if (r < 0)
		crypt_free_type(cd, CRYPT_INTEGRITY);
	return r;
}

static int _crypt_load_bitlk(struct crypt_device *cd)
{
	int r;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = BITLK_read_sb(cd, &cd->u.bitlk.params);
	if (r < 0)
		goto out;

	if (asprintf(&cd->u.bitlk.cipher_spec, "%s-%s",
		     cd->u.bitlk.params.cipher, cd->u.bitlk.params.cipher_mode) < 0) {
		cd->u.bitlk.cipher_spec = NULL;
		r = -ENOMEM;
		goto out;
	}

	if (!cd->type && !(cd->type = strdup(CRYPT_BITLK))) {
		r = -ENOMEM;
		goto out;
	}

	device_set_block_size(crypt_data_device(cd), cd->u.bitlk.params.sector_size);
out:
	if (r < 0)
		crypt_free_type(cd, CRYPT_BITLK);
	return r;
}

static int _crypt_load_fvault2(struct crypt_device *cd)
{
	int r;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = FVAULT2_read_metadata(cd, &cd->u.fvault2.params);
	if (r < 0)
		goto out;

	if (!cd->type && !(cd->type = strdup(CRYPT_FVAULT2)))
		r = -ENOMEM;
out:
	if (r < 0)
		crypt_free_type(cd, CRYPT_FVAULT2);
	return r;
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

		r = _crypt_load_luks(cd, requested_type, true, false);
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
		r = _crypt_load_bitlk(cd);
	} else if (isFVAULT2(requested_type)) {
		if (cd->type && !isFVAULT2(cd->type)) {
			log_dbg(cd, "Context is already initialized to type %s", cd->type);
			return -EINVAL;
		}
		r = _crypt_load_fvault2(cd);
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
		r = snprintf(cd->u.none.cipher_spec, sizeof(cd->u.none.cipher_spec),
			 "%s-%s", cd->u.none.cipher, _mode);
		if (r < 0 || (size_t)r >= sizeof(cd->u.none.cipher_spec))
			r = -EINVAL;
		else {
			cd->u.none.cipher_mode = cd->u.none.cipher_spec + strlen(cd->u.none.cipher) + 1;
			cd->u.none.key_size = crypt_volume_key_length(tgt->u.crypt.vk);
			r = 0;
		}
	}

	if (!r && tgt->u.crypt.integrity) {
		r = snprintf(cd->u.none.integrity_spec, sizeof(cd->u.none.integrity_spec),
			 "%s", tgt->u.crypt.integrity);
		if (r < 0 || (size_t)r >= sizeof(cd->u.none.integrity_spec))
			r = -EINVAL;
		else
			r = 0;
	}

	cd->u.none.sector_size = tgt->u.crypt.sector_size;

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

static int _init_by_name_crypt(struct crypt_device *cd, const char *name)
{
	bool found = false;
	char **dep, *cipher_spec = NULL, cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	char deps_uuid_prefix[40], *deps[MAX_DM_DEPS+1] = {};
	const char *dev;
	char *iname = NULL;
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
		/* Allow crypt null context with unknown cipher string */
		if (tgt->type == DM_CRYPT && !tgt->u.crypt.integrity) {
			crypt_set_null_type(cd);
			r = 0;
			goto out;
		}
		log_err(cd, _("No known cipher specification pattern detected for active device %s."), name);
		goto out;
	}

	dep = deps;

	if (tgt->type == DM_CRYPT && tgt->u.crypt.tag_size &&
	     (iname = dm_get_active_iname(cd, name))) {

		r = dm_query_device(cd, iname, DM_ACTIVE_DEVICE, &dmdi);
		free(iname);
		if (r < 0)
			goto out;
		/*
		 * Data device for crypt with integrity is not dm-integrity device,
		 * but always the device underlying dm-integrity.
		 */
		device_free(cd, cd->device);
		MOVE_REF(cd->device, tgti->data_device);
	}

	/* do not try to lookup LUKS2 header in detached header mode */
	if (dmd.uuid && !cd->metadata_device && !found) {
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
		cd->u.plain.key_size = crypt_volume_key_length(tgt->u.crypt.vk);
		cd->u.plain.cipher = strdup(cipher);
		MOVE_REF(cd->u.plain.cipher_spec, cipher_spec);
		cd->u.plain.cipher_mode = cd->u.plain.cipher_spec + strlen(cipher) + 1;
		if (dmd.flags & CRYPT_ACTIVATE_KEYRING_KEY)
			crypt_set_key_in_keyring(cd, 1);
	} else if (isLOOPAES(cd->type) && single_segment(&dmd) && tgt->type == DM_CRYPT) {
		cd->u.loopaes.hdr.offset = tgt->u.crypt.offset;
		cd->u.loopaes.cipher = strdup(cipher);
		MOVE_REF(cd->u.loopaes.cipher_spec, cipher_spec);
		cd->u.loopaes.cipher_mode = cd->u.loopaes.cipher_spec + strlen(cipher) + 1;
		/* version 3 uses last key for IV */
		if (crypt_volume_key_length(tgt->u.crypt.vk) % key_nums)
			key_nums++;
		cd->u.loopaes.key_size = crypt_volume_key_length(tgt->u.crypt.vk) / key_nums;
	} else if (isLUKS1(cd->type) || isLUKS2(cd->type)) {
		if (crypt_metadata_device(cd)) {
			r = _crypt_load_luks(cd, cd->type, true, false);
			if (r < 0) {
				log_dbg(cd, "LUKS device header does not match active device.");
				crypt_set_null_type(cd);
				device_close(cd, cd->metadata_device);
				device_close(cd, cd->device);
				r = 0;
				goto out;
			}
			/* check whether UUIDs match each other */
			r = dm_uuid_cmp(dmd.uuid, LUKS_UUID(cd));
			if (r < 0) {
				log_dbg(cd, "LUKS device header uuid: %s mismatches DM returned uuid %s",
					LUKS_UUID(cd), dmd.uuid);
				crypt_free_type(cd, NULL);
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
		r = _crypt_load_bitlk(cd);
		if (r < 0) {
			log_dbg(cd, "BITLK device header not available.");
			crypt_set_null_type(cd);
			r = 0;
		}
	} else if (isFVAULT2(cd->type)) {
		r = _crypt_load_fvault2(cd);
		if (r < 0) {
			log_dbg(cd, "FVAULT2 device header not available.");
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
			cd->u.integrity.params.integrity_key_size = crypt_volume_key_length(tgt->u.integrity.vk);
		if (tgt->u.integrity.journal_integrity_key)
			cd->u.integrity.params.journal_integrity_key_size = crypt_volume_key_length(tgt->u.integrity.journal_integrity_key);
		if (tgt->u.integrity.journal_crypt_key)
			cd->u.integrity.params.journal_crypt_key_size = crypt_volume_key_length(tgt->u.integrity.journal_crypt_key);
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
		else if (!strncmp(CRYPT_FVAULT2, dmd.uuid, sizeof(CRYPT_FVAULT2)-1))
			(*cd)->type = strdup(CRYPT_FVAULT2);
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
		device_set_block_size(crypt_data_device(cd), sector_size);
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

	if (device_is_zoned(crypt_metadata_device(cd)) > 0) {
		log_err(cd, _("Zoned device %s cannot be used for LUKS header."),
			device_path(crypt_metadata_device(cd)));
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
		cd->volume_key = crypt_generate_volume_key(cd, volume_key_size, KEY_QUALITY_KEY);

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

	if (device_is_dax(crypt_data_device(cd)) > 0)
		log_std(cd, _("WARNING: DAX device can corrupt data as it does not guarantee atomic sector updates.\n"));

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
	if (r) {
		free(cd->u.luks1.cipher_spec);
		return r;
	}

	if (!device_size(crypt_data_device(cd), &dev_size) &&
	    dev_size <= (crypt_get_data_offset(cd) * SECTOR_SIZE))
		log_std(cd, _("Device %s is too small for activation, there is no remaining space for data.\n"),
			      device_path(crypt_data_device(cd)));

	return 0;
}

static int LUKS2_check_encryption_params(struct crypt_device *cd,
	const char *cipher,
	const char *cipher_mode,
	const char *integrity,
	size_t required_integrity_key_size,
	size_t volume_key_size,
	const struct crypt_params_luks2 *params,
	const char **ret_integrity,
	size_t *ret_integrity_key_size)
{
	int r, integrity_key_size = 0;

	assert(cipher);
	assert(cipher_mode);
	assert(ret_integrity);

	if (integrity) {
		if (params->integrity_params) {
			/* Standalone dm-integrity must not be used */
			if (params->integrity_params->integrity)
				return -EINVAL;
			/* FIXME: journal encryption and MAC is here not yet supported */
			if (params->integrity_params->journal_crypt ||
			params->integrity_params->journal_integrity)
				return -ENOTSUP;
		}
		if (!INTEGRITY_tag_size(integrity, cipher, cipher_mode)) {
			/* merge "none" string into NULL to make branching logic is easier */
			if (!strcmp(integrity, "none"))
				integrity = NULL;
			else
				return -EINVAL;
		}
		integrity_key_size = INTEGRITY_key_size(integrity, required_integrity_key_size);
		if ((integrity_key_size < 0) || (integrity_key_size >= (int)volume_key_size)) {
			log_err(cd, _("Volume key is too small for encryption with integrity extensions."));
			return -EINVAL;
		}
		if (integrity_key_size && integrity_key_size < LUKS2_MIN_INTEGRITY_KEY_BYTES) {
			log_err(cd, _("Integrity key size is too small."));
			return -EINVAL;
		}
	}

	/* FIXME: allow this later also for normal ciphers (check AF_ALG availability. */
	if (integrity && integrity_key_size == 0) {
		r = crypt_cipher_check_kernel(cipher, cipher_mode, integrity, volume_key_size);
		if (r < 0) {
			log_err(cd, _("Cipher %s-%s (key size %zd bits) is not available."),
				cipher, cipher_mode, volume_key_size * 8);
			return r;
		}
	}

	if ((!integrity || integrity_key_size) && !crypt_cipher_wrapped_key(cipher, cipher_mode) &&
	    !INTEGRITY_tag_size(NULL, cipher, cipher_mode)) {
		r = LUKS_check_cipher(cd, volume_key_size - integrity_key_size,
				      cipher, cipher_mode);
		if (r < 0)
			return r;
	}

	*ret_integrity = integrity;
	if (ret_integrity_key_size)
		*ret_integrity_key_size = required_integrity_key_size ? integrity_key_size : 0;

	return 0;
}

static int LUKS2_check_encryption_sector(struct crypt_device *cd, uint64_t device_size_bytes,
		uint64_t data_offset_bytes, uint32_t sector_size, bool modify_sector_size,
		bool verify_data_area_alignment, uint32_t *ret_sector_size)
{
	uint64_t dmc_flags;

	assert(ret_sector_size);

	if (sector_size < SECTOR_SIZE || sector_size > MAX_SECTOR_SIZE ||
	    NOTPOW2(sector_size)) {
		log_err(cd, _("Unsupported encryption sector size."));
		return -EINVAL;
	}

	if (sector_size != SECTOR_SIZE && !dm_flags(cd, DM_CRYPT, &dmc_flags) &&
	    !(dmc_flags & DM_SECTOR_SIZE_SUPPORTED)) {
		if (modify_sector_size) {
			log_dbg(cd, "dm-crypt does not support encryption sector size option. Reverting to 512 bytes.");
			sector_size = SECTOR_SIZE;
		} else
			log_std(cd, _("WARNING: The device activation will fail, dm-crypt is missing "
				      "support for requested encryption sector size.\n"));
	}

	if (modify_sector_size) {
		if (data_offset_bytes && MISALIGNED(data_offset_bytes, sector_size)) {
			log_dbg(cd, "Data offset not aligned to sector size. Reverting to 512 bytes.");
			sector_size = SECTOR_SIZE;
		} else if (MISALIGNED(device_size_bytes - data_offset_bytes, sector_size)) {
			/* underflow does not affect misalignment checks */
			log_dbg(cd, "Device size is not aligned to sector size. Reverting to 512 bytes.");
			sector_size = SECTOR_SIZE;
		}
	}

	/* underflow does not affect misalignment checks */
	if (verify_data_area_alignment &&
	    sector_size > SECTOR_SIZE &&
	    MISALIGNED(device_size_bytes - data_offset_bytes, sector_size)) {
	       log_err(cd, _("Device size is not aligned to requested sector size."));
	       return -EINVAL;
	}

	*ret_sector_size = sector_size;

	return 0;
}

static int _crypt_format_luks2(struct crypt_device *cd,
			       const char *cipher,
			       const char *cipher_mode,
			       const char *uuid,
			       const char *volume_key,
			       size_t volume_key_size,
			       struct crypt_params_luks2 *params,
			       bool sector_size_autodetect, bool integrity_inline)
{
	int r;
	unsigned long required_alignment = DEFAULT_DISK_ALIGNMENT;
	unsigned long alignment_offset = 0;
	unsigned int sector_size;
	char cipher_spec[2*MAX_CAPI_ONE_LEN];
	const char *integrity = params ? params->integrity : NULL;
	size_t integrity_key_size = 0; /* only for independent, separate key in HMAC */
	struct volume_key *integrity_key = NULL;
	uint64_t data_offset_bytes, dev_size, metadata_size_bytes, keyslots_size_bytes;

	cd->u.luks2.hdr.jobj = NULL;
	cd->u.luks2.keyslot_cipher = NULL;

	if (!cipher || !cipher_mode)
		return -EINVAL;

	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format LUKS without device."));
		return -EINVAL;
	}

	if (device_is_zoned(crypt_metadata_device(cd)) > 0) {
		log_err(cd, _("Zoned device %s cannot be used for LUKS header."),
			device_path(crypt_metadata_device(cd)));
		return -EINVAL;
	}

	if (params && cd->data_offset && params->data_alignment &&
	   (cd->data_offset % params->data_alignment)) {
		log_err(cd, _("Requested data alignment is not compatible with data offset."));
		return -EINVAL;
	}

	if (params && params->sector_size)
		sector_size_autodetect = false;

	if (params && params->data_device) {
		if (!cd->metadata_device)
			cd->metadata_device = cd->device;
		else
			device_free(cd, cd->device);
		cd->device = NULL;
		if (device_alloc(cd, &cd->device, params->data_device) < 0)
			return -ENOMEM;
	}

	if (device_is_dax(crypt_data_device(cd)) > 0)
		log_std(cd, _("WARNING: DAX device can corrupt data as it does not guarantee atomic sector updates.\n"));

	if (sector_size_autodetect) {
		sector_size = device_optimal_encryption_sector_size(cd, crypt_data_device(cd));
		log_dbg(cd, "Auto-detected optimal encryption sector size for device %s is %d bytes.",
			device_path(crypt_data_device(cd)), sector_size);
	} else
		sector_size = params ? params->sector_size : SECTOR_SIZE;

	r = device_check_access(cd, crypt_metadata_device(cd), DEV_EXCL);
	if (r < 0)
		return r;

	if (!(cd->type = strdup(CRYPT_LUKS2)))
		return -ENOMEM;

	if (volume_key)
		cd->volume_key = crypt_alloc_volume_key(volume_key_size,
						      volume_key);
	else
		cd->volume_key = crypt_generate_volume_key(cd, volume_key_size, KEY_QUALITY_KEY);

	if (!cd->volume_key)
		return -ENOMEM;

	if (params && params->pbkdf)
		r = crypt_set_pbkdf_type(cd, params->pbkdf);
	else if (verify_pbkdf_params(cd, &cd->pbkdf))
		r = init_pbkdf_type(cd, NULL, CRYPT_LUKS2);

	if (r < 0)
		return r;

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

	if (params && params->integrity_params && params->integrity_params->integrity_key_size)
		integrity_key_size = params->integrity_params->integrity_key_size;

	r = LUKS2_check_encryption_params(cd, cipher, cipher_mode, integrity, integrity_key_size,
					  volume_key_size, params, &integrity, &integrity_key_size);
	if (r < 0)
		goto out;

	r = device_size(crypt_data_device(cd), &dev_size);
	if (r < 0)
		goto out;

	r = LUKS2_hdr_get_storage_params(cd, alignment_offset, required_alignment,
					 &metadata_size_bytes, &keyslots_size_bytes, &data_offset_bytes);
	if (r < 0)
		goto out;

	r = LUKS2_check_encryption_sector(cd, dev_size, data_offset_bytes, sector_size,
					  sector_size_autodetect, integrity == NULL,
					  &sector_size);
	if (r < 0)
		goto out;

	if (*cipher_mode != '\0')
		r = snprintf(cipher_spec, sizeof(cipher_spec), "%s-%s", cipher, cipher_mode);
	else
		r = snprintf(cipher_spec, sizeof(cipher_spec), "%s", cipher);
	if (r < 0 || (size_t)r >= sizeof(cipher_spec)) {
		r = -EINVAL;
		goto out;
	}

	r = LUKS2_generate_hdr(cd, &cd->u.luks2.hdr, cd->volume_key,
			       cipher_spec,
			       integrity, integrity_key_size,
			       uuid,
			       sector_size,
			       data_offset_bytes,
			       metadata_size_bytes, keyslots_size_bytes,
			       0, 0, 0);
	if (r < 0)
		goto out;

	if (integrity_inline) {
		log_dbg(cd, "Adding LUKS2 inline HW tags requirement flag.");
		r = LUKS2_config_set_requirement_version(cd, &cd->u.luks2.hdr,
			CRYPT_REQUIREMENT_INLINE_HW_TAGS, 1, false);
		if (r < 0)
			goto out;
	}

	if (params && (params->label || params->subsystem)) {
		r = LUKS2_hdr_labels(cd, &cd->u.luks2.hdr,
				     params->label, params->subsystem, 0);
		if (r < 0)
			goto out;
	}

	device_set_block_size(crypt_data_device(cd), sector_size);

	r = LUKS2_wipe_header_areas(cd, &cd->u.luks2.hdr);
	if (r < 0) {
		log_err(cd, _("Cannot wipe header on device %s."),
			mdata_device_path(cd));
		if (dev_size < LUKS2_hdr_and_areas_size(&cd->u.luks2.hdr))
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
	}

	/* Format underlying virtual dm-integrity device */
	if (!integrity_inline && crypt_get_integrity_tag_size(cd)) {
		if (integrity_key_size) {
			integrity_key = crypt_alloc_volume_key(integrity_key_size,
					crypt_volume_key_get_key(cd->volume_key) + volume_key_size - integrity_key_size);
			if (!integrity_key) {
				r = -ENOMEM;
				goto out;
			}
		}
		r = INTEGRITY_format(cd, params ? params->integrity_params : NULL,
				     integrity_key, NULL, NULL, 0, NULL, false);
		if (r)
			log_err(cd, _("Cannot format integrity for device %s."),
				data_device_path(cd));
		crypt_free_volume_key(integrity_key);
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
	if (r) {
		LUKS2_hdr_free(cd, &cd->u.luks2.hdr);
		return r;
	}

	/* Device size can be larger now if it is a file container */
	if (!device_size(crypt_data_device(cd), &dev_size) &&
	    dev_size <= (crypt_get_data_offset(cd) * SECTOR_SIZE))
		log_std(cd, _("Device %s is too small for activation, there is no remaining space for data.\n"),
			      device_path(crypt_data_device(cd)));

	return 0;
}

static int opal_topology_alignment(struct crypt_device *cd,
				   uint64_t partition_offset_sectors,
				   uint64_t data_offset_sectors,
				   uint64_t required_alignment_sectors,
				   uint64_t default_alignment_bytes,
				   uint64_t *ret_alignment_offset_bytes,
				   uint64_t *ret_alignment_bytes,
				   uint32_t *ret_opal_block_bytes,
				   uint64_t *ret_opal_alignment_granularity_blocks)
{
	bool opal_align;
	int r;
	uint32_t opal_block_bytes, device_block_bytes;
	uint64_t opal_alignment_granularity_blocks, opal_lowest_lba_blocks;

	assert(cd);
	assert(ret_alignment_offset_bytes);
	assert(ret_alignment_bytes);
	assert(ret_opal_block_bytes);
	assert(ret_opal_alignment_granularity_blocks);

	r = opal_geometry(cd, crypt_data_device(cd), &opal_align, &opal_block_bytes,
			  &opal_alignment_granularity_blocks, &opal_lowest_lba_blocks);
	if (r) {
		log_err(cd, _("Cannot get OPAL alignment parameters."));
		return -EINVAL;
	}

	device_block_bytes = device_block_size(cd, crypt_data_device(cd));

	log_dbg(cd, "OPAL geometry: alignment: '%c', logical block size: %" PRIu32 "/%" PRIu32
		    ", alignment granularity: %" PRIu64 ", lowest aligned LBA: %" PRIu64,
		    opal_align ? 'y' : 'n', opal_block_bytes, device_block_bytes,
		    opal_alignment_granularity_blocks, opal_lowest_lba_blocks);

	if (opal_block_bytes < SECTOR_SIZE || NOTPOW2(opal_block_bytes)) {
		log_err(cd, _("Bogus OPAL logical block size."));
		return -EINVAL;
	}

	if (device_block_bytes != opal_block_bytes) {
		log_err(cd, _("Bogus OPAL logical block size differs from device block size."));
		return -EINVAL;
	}

	if (data_offset_sectors &&
	    MISALIGNED(data_offset_sectors + partition_offset_sectors, opal_block_bytes / SECTOR_SIZE)) {
		log_err(cd, _("Requested data offset is not compatible with OPAL block size."));
		return -EINVAL;
	}

	/* Data offset has priority over data alignment parameter */
	if (!data_offset_sectors &&
	    MISALIGNED(required_alignment_sectors, opal_block_bytes / SECTOR_SIZE)) {
		log_err(cd, _("Requested data alignment is not compatible with OPAL alignment."));
		return -EINVAL;
	}

	if (!opal_align) {
		/* For detached header the alignment is used directly as data offset */
		if (required_alignment_sectors || cd->metadata_device)
			*ret_alignment_bytes = required_alignment_sectors * SECTOR_SIZE;
		else
			*ret_alignment_bytes = default_alignment_bytes;
		*ret_alignment_offset_bytes = 0;
		*ret_opal_block_bytes = opal_block_bytes;
		*ret_opal_alignment_granularity_blocks = 1;
		return 0;
	}

	if (data_offset_sectors) {
		if (MISALIGNED((((data_offset_sectors + partition_offset_sectors) * SECTOR_SIZE) / opal_block_bytes) - opal_lowest_lba_blocks,
			       opal_alignment_granularity_blocks)) {
			// FIXME: Add hint to user on how to fix it
			log_err(cd, _("Data offset does not satisfy OPAL alignment requirements."));
			return -EINVAL;
		}

		*ret_alignment_offset_bytes = 0;
		*ret_alignment_bytes = 0;
		*ret_opal_block_bytes = opal_block_bytes;
		*ret_opal_alignment_granularity_blocks = opal_alignment_granularity_blocks;

		return 0;
	}

	if (MISALIGNED(required_alignment_sectors * SECTOR_SIZE, opal_block_bytes * opal_alignment_granularity_blocks)) {
		log_err(cd, _("Requested data alignment does not satisfy locking range alignment requirements."));
		return -EINVAL;
	}

	/* For detached header the alignment is used directly as data offset */
	if (required_alignment_sectors || cd->metadata_device)
		*ret_alignment_bytes = required_alignment_sectors * SECTOR_SIZE;
	else
		*ret_alignment_bytes = size_round_up(default_alignment_bytes, opal_block_bytes * opal_alignment_granularity_blocks);

	/* data offset is not set, calculate proper alignment */
	*ret_alignment_offset_bytes = (partition_offset_sectors * SECTOR_SIZE) % (opal_block_bytes * opal_alignment_granularity_blocks);
	if (*ret_alignment_offset_bytes)
		*ret_alignment_offset_bytes = opal_block_bytes * opal_alignment_granularity_blocks - *ret_alignment_offset_bytes;

	if (*ret_alignment_offset_bytes)
		log_dbg(cd, "Compensating misaligned partition offset by %" PRIu64 "bytes.",
			*ret_alignment_offset_bytes);

	*ret_alignment_offset_bytes += (opal_lowest_lba_blocks * opal_block_bytes);
	*ret_opal_block_bytes = opal_block_bytes;
	*ret_opal_alignment_granularity_blocks = opal_alignment_granularity_blocks;

	log_dbg(cd, "OPAL alignment (%" PRIu32 "/%" PRIu64 "), offset = %" PRIu64 ". Required alignment is %" PRIu64 ".",
		opal_block_bytes, opal_alignment_granularity_blocks, *ret_alignment_offset_bytes, *ret_alignment_bytes);

	return 0;
}

int crypt_format_luks2_opal(struct crypt_device *cd,
			      const char *cipher,
			      const char *cipher_mode,
			      const char *uuid,
			      const char *volume_keys,
			      size_t volume_keys_size,
			      struct crypt_params_luks2 *params,
			      struct crypt_params_hw_opal *opal_params)
{
	bool opal_range_reset = false, subsystem_overridden = false, sector_size_autodetect = cipher != NULL;
	int r;
	char cipher_spec[128];
	const char *integrity = params ? params->integrity : NULL;
	size_t integrity_key_size = 0; /* only for independent, separate key in HMAC */
	struct volume_key *integrity_key = NULL;
	uint32_t sector_size, opal_block_bytes, opal_segment_number = 1; /* We'll use the partition number if available later */
	uint64_t alignment_offset_bytes, data_offset_bytes, device_size_bytes, opal_alignment_granularity_blocks,
		 partition_offset_sectors, range_offset_blocks, range_size_bytes,
		 required_alignment_bytes, metadata_size_bytes, keyslots_size_bytes,
		 provided_data_sectors;
	struct volume_key *user_key = NULL;
	struct crypt_lock_handle *opal_lh = NULL;

	if (!cd || !params || !opal_params ||
	    !opal_params->admin_key || !opal_params->admin_key_size || !opal_params->user_key_size)
		return -EINVAL;

	if (cd->type) {
		log_dbg(cd, "Context already formatted as %s.", cd->type);
		return -EINVAL;
	}

	log_dbg(cd, "Formatting device %s as type LUKS2 with OPAL HW encryption.", mdata_device_path(cd) ?: "(none)");

	r = init_crypto(cd);
	if (r < 0)
		return r;

	if (volume_keys_size < opal_params->user_key_size)
		return -EINVAL;

	if (cipher && (volume_keys_size == opal_params->user_key_size))
		return -EINVAL;

	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format LUKS without device."));
		return -EINVAL;
	}

	if (params->data_alignment &&
	    MISALIGNED(cd->data_offset, params->data_alignment)) {
		log_err(cd, _("Requested data alignment is not compatible with data offset."));
		return -EINVAL;
	}

	if (params->data_device) {
		if (!cd->metadata_device)
			cd->metadata_device = cd->device;
		else
			device_free(cd, cd->device);
		cd->device = NULL;
		if (device_alloc(cd, &cd->device, params->data_device) < 0)
			return -ENOMEM;
	}

	r = crypt_opal_supported(cd, crypt_data_device(cd));
	if (r < 0)
		return r;

	if (params->sector_size)
		sector_size_autodetect = false;

	partition_offset_sectors = crypt_dev_partition_offset(device_path(crypt_data_device(cd)));

	r = device_check_access(cd, crypt_metadata_device(cd), DEV_EXCL);
	if (r < 0)
		return r;

	/*
	 * Check both data and metadata devices for exclusive access since
	 * we don't want to setup locking range on already used partition.
	 */
	if (crypt_metadata_device(cd) != crypt_data_device(cd)) {
		r = device_check_access(cd, crypt_data_device(cd), DEV_EXCL);
		if (r < 0)
			return r;
	}

	if (!(cd->type = strdup(CRYPT_LUKS2)))
		return -ENOMEM;

	if (volume_keys)
		cd->volume_key = crypt_alloc_volume_key(volume_keys_size, volume_keys);
	else
		cd->volume_key = crypt_generate_volume_key(cd, volume_keys_size, KEY_QUALITY_KEY);

	if (!cd->volume_key) {
		r = -ENOMEM;
		goto out;
	}

	if (cipher) {
		user_key = crypt_alloc_volume_key(opal_params->user_key_size, crypt_volume_key_get_key(cd->volume_key));
		if (!user_key) {
			r = -ENOMEM;
			goto out;
		}
	}

	r = 0;
	if (params->pbkdf)
		r = crypt_set_pbkdf_type(cd, params->pbkdf);
	else if (verify_pbkdf_params(cd, &cd->pbkdf))
		r = init_pbkdf_type(cd, NULL, CRYPT_LUKS2);

	if (r < 0)
		goto out;

	if (cd->metadata_device && !cd->data_offset)
		/* For detached header the alignment is used directly as data offset */
		cd->data_offset = params->data_alignment;

	r = opal_topology_alignment(cd, partition_offset_sectors,
				    cd->data_offset, params->data_alignment,
				    DEFAULT_DISK_ALIGNMENT, &alignment_offset_bytes, &required_alignment_bytes,
				    &opal_block_bytes, &opal_alignment_granularity_blocks);
	if (r < 0)
		goto out;

	if (sector_size_autodetect) {
		sector_size = device_optimal_encryption_sector_size(cd, crypt_data_device(cd));
		if ((opal_block_bytes * opal_alignment_granularity_blocks) > sector_size)
			sector_size = opal_block_bytes * opal_alignment_granularity_blocks;
		if (sector_size > MAX_SECTOR_SIZE)
			sector_size = MAX_SECTOR_SIZE;
		log_dbg(cd, "Auto-detected optimal encryption sector size for device %s is %d bytes.",
			device_path(crypt_data_device(cd)), sector_size);
	} else
		sector_size = params->sector_size;

	/* To ensure it is obvious and explicit that OPAL is being used, set the
	 * subsystem tag if the user hasn't passed one. */
	if (!params->subsystem) {
		params->subsystem = "HW-OPAL";
		subsystem_overridden = true;
	}

	/* We need to give the drive a segment number - use the partition number if there is
	 * one, otherwise the first valid (1) number if it's a single-volume setup */
	r = crypt_dev_get_partition_number(device_path(crypt_data_device(cd)));
	if (r > 0)
		opal_segment_number = r;

	if (cipher) {
		if (params->integrity_params && params->integrity_params->integrity_key_size)
			integrity_key_size = params->integrity_params->integrity_key_size;

		r = LUKS2_check_encryption_params(cd, cipher, cipher_mode, integrity, 0,
						  volume_keys_size - opal_params->user_key_size,
						  params, &integrity, &integrity_key_size);
		if (r < 0)
			goto out;
	}

	r = device_size(crypt_data_device(cd), &device_size_bytes);
	if (r < 0)
		goto out;

	r = LUKS2_hdr_get_storage_params(cd, alignment_offset_bytes, required_alignment_bytes,
			     &metadata_size_bytes, &keyslots_size_bytes, &data_offset_bytes);
	if (r < 0)
		goto out;

	r = -EINVAL;
	if (device_size_bytes < data_offset_bytes && !cd->metadata_device) {
		log_err(cd, _("Device %s is too small."), device_path(crypt_data_device(cd)));
		goto out;
	}

	device_size_bytes -= data_offset_bytes;
	range_size_bytes = device_size_bytes - (device_size_bytes % (opal_block_bytes * opal_alignment_granularity_blocks));
	if (!range_size_bytes)
		goto out;

	if (device_size_bytes != range_size_bytes)
		log_err(cd, _("Compensating device size by %" PRIu64 " sectors to align it with OPAL alignment granularity."),
			(device_size_bytes - range_size_bytes) / SECTOR_SIZE);

	if (cipher) {
		r = LUKS2_check_encryption_sector(cd, range_size_bytes, data_offset_bytes, sector_size,
						  sector_size_autodetect, integrity == NULL,
						  &sector_size);
		if (r < 0)
			goto out;

		if (*cipher_mode != '\0')
			r = snprintf(cipher_spec, sizeof(cipher_spec), "%s-%s", cipher, cipher_mode);
		else
			r = snprintf(cipher_spec, sizeof(cipher_spec), "%s", cipher);
		if (r < 0 || (size_t)r >= sizeof(cipher_spec)) {
			r = -EINVAL;
			goto out;
		}
	}

	r = LUKS2_generate_hdr(cd, &cd->u.luks2.hdr, cd->volume_key,
			       cipher ? cipher_spec : NULL,
			       integrity, integrity_key_size,
			       uuid,
			       sector_size,
			       data_offset_bytes,
			       metadata_size_bytes, keyslots_size_bytes,
			       range_size_bytes,
			       opal_segment_number,
			       opal_params->user_key_size);
	if (r < 0)
		goto out;

	log_dbg(cd, "Adding LUKS2 OPAL requirement flag.");
	r = LUKS2_config_set_requirement_version(cd, &cd->u.luks2.hdr, CRYPT_REQUIREMENT_OPAL, 1, false);
	if (r < 0)
		goto out;

	if (params->label || params->subsystem) {
		r = LUKS2_hdr_labels(cd, &cd->u.luks2.hdr,
				     params->label, params->subsystem, 0);
		if (r < 0)
			goto out;
	}

	device_set_block_size(crypt_data_device(cd), sector_size);

	r = LUKS2_wipe_header_areas(cd, &cd->u.luks2.hdr);
	if (r < 0) {
		log_err(cd, _("Cannot wipe header on device %s."),
			mdata_device_path(cd));
		if (device_size_bytes < LUKS2_hdr_and_areas_size(&cd->u.luks2.hdr))
			log_err(cd, _("Device %s is too small."), device_path(crypt_metadata_device(cd)));
		goto out;
	}

	range_offset_blocks = (data_offset_bytes + partition_offset_sectors * SECTOR_SIZE) / opal_block_bytes;

	r = opal_exclusive_lock(cd, crypt_data_device(cd), &opal_lh);
	if (r < 0) {
		log_err(cd, _("Failed to acquire OPAL lock on device %s."), device_path(crypt_data_device(cd)));
		goto out;
	}

	r = opal_setup_ranges(cd, crypt_data_device(cd), user_key ?: cd->volume_key,
					range_offset_blocks, range_size_bytes / opal_block_bytes,
					opal_block_bytes, opal_segment_number,
					opal_params->admin_key, opal_params->admin_key_size);
	if (r < 0) {
		if (r == -EPERM)
			log_err(cd, _("Incorrect OPAL Admin key."));
		else
			log_err(cd, _("Cannot setup OPAL segment."));
		goto out;
	}

	opal_range_reset = true;

	/* integrity metadata goes in unlocked OPAL locking range */
	if (crypt_get_integrity_tag_size(cd)) {
		r = opal_unlock(cd, crypt_data_device(cd), opal_segment_number, user_key ?: cd->volume_key);
		if (r < 0)
			goto out;

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

		if (integrity_key_size) {
			integrity_key = crypt_alloc_volume_key(integrity_key_size,
				crypt_volume_key_get_key(cd->volume_key) + volume_keys_size - integrity_key_size);

			if (!integrity_key) {
				r = -ENOMEM;
				goto out;
			}
		}

		r = INTEGRITY_format(cd, params->integrity_params, integrity_key, NULL, NULL,
				     /*
				      * Create reduced dm-integrity device only if locking range size does
				      * not match device size.
				      */
				     device_size_bytes != range_size_bytes ? range_size_bytes / SECTOR_SIZE : 0, NULL, false);
		if (r)
			log_err(cd, _("Cannot format integrity for device %s."),
				data_device_path(cd));

		crypt_free_volume_key(integrity_key);
		if (r < 0)
			goto out;

		r = INTEGRITY_data_sectors(cd, crypt_data_device(cd),
					   crypt_get_data_offset(cd) * SECTOR_SIZE,
					   &provided_data_sectors);
		if (r < 0)
			goto out;

		if (!LUKS2_segment_set_size(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT,
					    &(uint64_t) {provided_data_sectors * SECTOR_SIZE})) {
			r = -EINVAL;
			goto out;
		}

		r = opal_lock(cd, crypt_data_device(cd), opal_segment_number);
		if (r < 0)
			goto out;
	}

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
		} else if (r == -EIO) {
			log_err(cd, _("Cannot format device %s, OPAL device seems to be fully write-protected now."),
				mdata_device_path(cd));
			log_err(cd, _("This is perhaps a bug in firmware. Run OPAL PSID reset and reconnect for recovery."));
		} else
			log_err(cd, _("Cannot format device %s."),
				mdata_device_path(cd));
	}

out:
	crypt_free_volume_key(user_key);

	if (subsystem_overridden)
		params->subsystem = NULL;

	if (r >= 0) {
		opal_exclusive_unlock(cd, opal_lh);
		return 0;
	}

	if (opal_range_reset &&
	    (opal_reset_segment(cd, crypt_data_device(cd), opal_segment_number,
				opal_params->admin_key, opal_params->admin_key_size) < 0))
		log_err(cd, _("Locking range %d reset on device %s failed."),
			opal_segment_number, device_path(crypt_data_device(cd)));

	opal_exclusive_unlock(cd, opal_lh);
	LUKS2_hdr_free(cd, &cd->u.luks2.hdr);

	crypt_set_null_type(cd);
	crypt_free_volume_key(cd->volume_key);
	cd->volume_key = NULL;

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

	if (device_is_identical(crypt_metadata_device(cd), crypt_data_device(cd)) > 0 &&
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
			goto out;
		}

		hash_blocks_size = VERITY_hash_blocks(cd, params) * params->hash_block_size;
		if (device_is_identical(crypt_metadata_device(cd), fec_device) > 0 &&
		    (params->hash_area_offset + hash_blocks_size) > params->fec_area_offset) {
			log_err(cd, _("Hash area overlaps with FEC area."));
			r = -EINVAL;
			goto out;
		}

		if (device_is_identical(crypt_data_device(cd), fec_device) > 0 &&
		    (cd->u.verity.hdr.data_size * params->data_block_size) > params->fec_area_offset) {
			log_err(cd, _("Data area overlaps with FEC area."));
			r = -EINVAL;
			goto out;
		}
	}

	root_hash = malloc(cd->u.verity.root_hash_size);
	hash_name = strdup(params->hash_name);
	salt = malloc(params->salt_size);

	if (!root_hash || !hash_name || !salt) {
		r = -ENOMEM;
		goto out;
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
		goto out;

	if (params->flags & CRYPT_VERITY_CREATE_HASH) {
		r = VERITY_create(cd, &cd->u.verity.hdr,
				  cd->u.verity.root_hash, cd->u.verity.root_hash_size);
		if (!r && params->fec_device)
			r = VERITY_FEC_process(cd, &cd->u.verity.hdr, cd->u.verity.fec_device, 0, NULL);
		if (r)
			goto out;
	}

	if (!(params->flags & CRYPT_VERITY_NO_HEADER)) {
		if (uuid) {
			if (!(cd->u.verity.uuid = strdup(uuid)))
				r = -ENOMEM;
		} else
			r = VERITY_UUID_generate(&cd->u.verity.uuid);

		if (!r)
			r = VERITY_write_sb(cd, cd->u.verity.hdr.hash_area_offset,
					    cd->u.verity.uuid,
					    &cd->u.verity.hdr);
	}

out:
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
				   struct crypt_params_integrity *params,
				   const char *integrity_key, size_t integrity_key_size,
				   bool integrity_inline)
{
	int r;
	uint32_t integrity_tag_size;
	char *integrity = NULL, *journal_integrity = NULL, *journal_crypt = NULL;
	struct volume_key *journal_crypt_key = NULL, *journal_mac_key = NULL, *ik = NULL;

	if (!params)
		return -EINVAL;

	if (uuid) {
		log_err(cd, _("UUID is not supported for this crypt type."));
		return -EINVAL;
	}

	if (integrity_key_size && integrity_key_size != params->integrity_key_size) {
		log_err(cd, _("Integrity key size mismatch."));
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
			goto out;
		}
	}

	if (params->integrity && !(integrity = strdup(params->integrity))) {
		r = -ENOMEM;
		goto out;
	}
	if (params->journal_integrity && !(journal_integrity = strdup(params->journal_integrity))) {
		r = -ENOMEM;
		goto out;
	}
	if (params->journal_crypt && !(journal_crypt = strdup(params->journal_crypt))) {
		r = -ENOMEM;
		goto out;
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

	if (params->integrity_key_size) {
		if (!integrity_key)
			ik = crypt_generate_volume_key(cd, params->integrity_key_size, KEY_QUALITY_EMPTY);
		else
			ik = crypt_alloc_volume_key(params->integrity_key_size, integrity_key);
		if (!ik) {
			r = -ENOMEM;
			goto out;
		}
	}

	r = INTEGRITY_format(cd, params, ik, cd->u.integrity.journal_crypt_key,
			     cd->u.integrity.journal_mac_key, 0, &cd->u.integrity.sb_flags,
			     integrity_inline);
	if (r)
		log_err(cd, _("Cannot format integrity for device %s."), mdata_device_path(cd));

	crypt_free_volume_key(ik);
out:
	if (r) {
		crypt_free_volume_key(journal_crypt_key);
		crypt_free_volume_key(journal_mac_key);
		free(integrity);
		free(journal_integrity);
		free(journal_crypt);
	}

	return r;
}

int crypt_format_inline(struct crypt_device *cd,
	const char *type,
	const char *cipher,
	const char *cipher_mode,
	const char *uuid,
	const char *volume_key,
	size_t volume_key_size,
	void *params)
{
	struct crypt_params_luks2 *lparams;
	const struct crypt_params_integrity *iparams;
	uint32_t device_tag_size, required_tag_size;
	struct device *idevice;
	size_t sector_size, required_sector_size;
	int r;

	if (!cd || !params)
		return -EINVAL;

	if (cd->type) {
		log_dbg(cd, "Context already formatted as %s.", cd->type);
		return -EINVAL;
	}

	log_dbg(cd, "Formatting device %s as type %s with inline tags.", mdata_device_path(cd) ?: "(none)", type);

	crypt_reset_null_type(cd);

	r = init_crypto(cd);
	if (r < 0)
		return r;

	if (isINTEGRITY(type)) {
		lparams = NULL;
		iparams = params;
		idevice = crypt_metadata_device(cd);
		required_sector_size = iparams->sector_size;
		required_tag_size = iparams->tag_size;

		/* Unused in standalone integrity */
		if (cipher || cipher_mode)
			return -EINVAL;
	} else if (isLUKS2(type)) {
		lparams = params;
		iparams = lparams->integrity_params;
		idevice = crypt_data_device(cd);
		required_sector_size = lparams->sector_size;

		if (!lparams->integrity || !idevice)
			return -EINVAL;

		required_tag_size = INTEGRITY_tag_size(lparams->integrity, cipher, cipher_mode);
	} else {
		log_err(cd, _("Unknown or unsupported device type %s requested."), type);
		return -EINVAL;
	}

	/* In inline mode journal will be never used, check that params are not set */
	if (iparams && (iparams->journal_size || iparams->journal_watermark || iparams->journal_commit_time ||
	    iparams->interleave_sectors || iparams->journal_integrity || iparams->journal_integrity_key ||
	    iparams->journal_integrity_key_size || iparams->journal_crypt || iparams->journal_crypt_key ||
	    iparams->journal_integrity_key_size))
		return -EINVAL;

	r = device_is_nop_dif(idevice, &device_tag_size);
	if (r < 0)
		return r;

	if (!r) {
		log_err(cd, _("Device %s does not provide inline integrity data fields."), mdata_device_path(cd));
		return -EINVAL;
	}

	/* We can get device_tag_size = 0 as kernel provides this info only for some block devices */
	if (device_tag_size > 0 && device_tag_size < required_tag_size) {
		log_err(cd, _("Inline tag size %" PRIu32 " [bytes] is larger than %" PRIu32 " provided by device %s."),
			required_tag_size, device_tag_size, mdata_device_path(cd));
		return -EINVAL;
	}
	log_dbg(cd, "Inline integrity is supported (%" PRIu32 ").", device_tag_size);

	/* Inline must use sectors size as hardware device */
	sector_size = device_block_size(cd, idevice);
	if (!sector_size)
		return -EINVAL;

	/* No autodetection, use device sector size */
	if (isLUKS2(type) && lparams && !required_sector_size)
		lparams->sector_size = sector_size;
	else if (sector_size != required_sector_size) {
		log_err(cd, _("Sector must be the same as device hardware sector (%zu bytes)."), sector_size);
		return -EINVAL;
	}

	if (isINTEGRITY(type))
		r = _crypt_format_integrity(cd, uuid, params, volume_key, volume_key_size, true);
	else if (isLUKS2(type))
		r = _crypt_format_luks2(cd, cipher, cipher_mode,
					uuid, volume_key, volume_key_size, params, false, true);
	else
		r = -EINVAL;

	if (r < 0) {
		crypt_set_null_type(cd);
		crypt_free_volume_key(cd->volume_key);
		cd->volume_key = NULL;
	}

	return r;
}

static int _crypt_format(struct crypt_device *cd,
	const char *type,
	const char *cipher,
	const char *cipher_mode,
	const char *uuid,
	const char *volume_key,
	size_t volume_key_size,
	void *params,
	bool sector_size_autodetect)
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
					uuid, volume_key, volume_key_size, params, sector_size_autodetect, false);
	else if (isLOOPAES(type))
		r = _crypt_format_loopaes(cd, cipher, uuid, volume_key_size, params);
	else if (isVERITY(type))
		r = _crypt_format_verity(cd, uuid, params);
	else if (isINTEGRITY(type))
		r = _crypt_format_integrity(cd, uuid, params, volume_key, volume_key_size, false);
	else {
		log_err(cd, _("Unknown or unsupported device type %s requested."), type);
		r = -EINVAL;
	}

	if (r < 0) {
		crypt_set_null_type(cd);
		crypt_free_volume_key(cd->volume_key);
		cd->volume_key = NULL;
	}

	return r;
}

CRYPT_SYMBOL_EXPORT_NEW(int, crypt_format, 2, 4,
	/* crypt_format parameters follows */
	struct crypt_device *cd,
	const char *type,
	const char *cipher,
	const char *cipher_mode,
	const char *uuid,
	const char *volume_key,
	size_t volume_key_size,
	void *params)
{
	return _crypt_format(cd, type, cipher, cipher_mode, uuid, volume_key, volume_key_size, params, true);
}


CRYPT_SYMBOL_EXPORT_OLD(int, crypt_format, 2, 0,
	/* crypt_format parameters follows */
	struct crypt_device *cd,
	const char *type,
	const char *cipher,
	const char *cipher_mode,
	const char *uuid,
	const char *volume_key,
	size_t volume_key_size,
	void *params)
{
	return _crypt_format(cd, type, cipher, cipher_mode, uuid, volume_key, volume_key_size, params, false);
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
	r = _crypt_load_luks(cd, requested_type, false, true);
	if (r < 0)
		return r;

	/* cd->type and header must be set in context */
	r = crypt_check_data_device_size(cd);
	if (r < 0)
		crypt_set_null_type(cd);

	return r;
}

/* compare volume keys */
static int _compare_volume_keys(struct volume_key *svk, struct volume_key *tvk)
{
	if (svk == tvk)
		return 0;

	if (!svk || !tvk)
		return 1;

	if (crypt_volume_key_length(svk) != crypt_volume_key_length(tvk))
		return 1;

	/* No switch between keyring and direct key specification */
	if ((!crypt_volume_key_description(svk) && crypt_volume_key_description(tvk)) ||
	    (crypt_volume_key_description(svk) && !crypt_volume_key_description(tvk)) ||
	    (!crypt_volume_key_is_set(svk) && crypt_volume_key_is_set(tvk)) ||
	    (crypt_volume_key_is_set(svk) && !crypt_volume_key_is_set(tvk)))
		return 1;

	if (crypt_volume_key_description(svk) &&
	    (crypt_volume_key_kernel_key_type(svk) != crypt_volume_key_kernel_key_type(tvk) ||
	    strcmp(crypt_volume_key_description(svk), crypt_volume_key_description(tvk))))
		return 1;

	if (crypt_volume_key_is_set(svk) &&
	    crypt_backend_memeq(crypt_volume_key_get_key(svk),
				crypt_volume_key_get_key(tvk),
				crypt_volume_key_length(svk)))
		return 1;

	return 0;
}

static int _compare_volume_keys_luks2(struct volume_key *svk, struct volume_key *tvk)
{
	if (svk == tvk)
		return 0;

	if (!svk || !tvk)
		return 1;

	if (crypt_volume_key_length(svk) != crypt_volume_key_length(tvk))
		return 1;

	if ((!crypt_volume_key_is_set(svk) && !crypt_volume_key_description(svk)) ||
	    (!crypt_volume_key_is_set(tvk) && !crypt_volume_key_description(tvk)))
		return 1;

	if (crypt_volume_key_is_set(svk) && crypt_volume_key_is_set(tvk) &&
	    crypt_backend_memeq(crypt_volume_key_get_key(svk),
				crypt_volume_key_get_key(tvk),
				crypt_volume_key_length(svk)))
		return 1;

	if (crypt_volume_key_description(svk) && crypt_volume_key_description(tvk))
		return (crypt_volume_key_kernel_key_type(svk) != crypt_volume_key_kernel_key_type(tvk) ||
			strcmp(crypt_volume_key_description(svk), crypt_volume_key_description(tvk)));

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

	/*
	 * FIXME: The CRYPT_SUBDEV prefix should be enough but we need
	 * to keep INTEGRITY- for dm-integrity subdevices opened with
	 * cryptsetup version < 2.8.0. Drop the INTEGRITY condition
	 * in next Y release.
	 */
	if (isLUKS2(cd->type) &&
	    (!strncmp("INTEGRITY-", tgt->uuid, strlen("INTEGRITY-")) ||
	     !strncmp(CRYPT_SUBDEV, tgt->uuid, strlen(CRYPT_SUBDEV)))) {
		if (dm_uuid_cmp(tgt->uuid, src->uuid)) {
			log_dbg(cd, "LUKS UUID mismatch.");
			return -EINVAL;
		}
	} else if (isLUKS(cd->type)) {
		if (!src->uuid || strncmp(cd->type, tgt->uuid, strlen(cd->type)) ||
		    dm_uuid_cmp(tgt->uuid, src->uuid)) {
			log_dbg(cd, "LUKS UUID mismatch.");
			return -EINVAL;
		}
	} else if (isPLAIN(cd->type) || isLOOPAES(cd->type)) {
		if (strncmp(cd->type, tgt->uuid, strlen(cd->type))) {
			log_dbg(cd, "Unexpected uuid prefix %s in target device.", tgt->uuid);
			return -EINVAL;
		}
	} else if (!isINTEGRITY(cd->type)) {
		log_dbg(cd, "Unsupported device type %s for reload.", cd->type ?: "<empty>");
		return -ENOTSUP;
	}

	return 0;
}

static int _compare_crypt_devices(struct crypt_device *cd,
			       const struct dm_target *src,
			       const struct dm_target *tgt)
{
	char *src_cipher = NULL, *src_integrity = NULL;
	int r = -EINVAL;

	/* for crypt devices keys are mandatory */
	if (!src->u.crypt.vk || !tgt->u.crypt.vk)
		return -EINVAL;

	/* CIPHER checks */
	if (!src->u.crypt.cipher || !tgt->u.crypt.cipher)
		return -EINVAL;

	/*
	 * dm_query_target converts capi cipher specification to dm-crypt format.
	 * We need to do same for cipher specification requested in source
	 * device.
	 */
	if (crypt_capi_to_cipher(&src_cipher, &src_integrity, src->u.crypt.cipher, src->u.crypt.integrity))
		return -EINVAL;

	if (strcmp(src_cipher, tgt->u.crypt.cipher)) {
		log_dbg(cd, "Cipher specs do not match.");
		goto out;
	}

	if (crypt_volume_key_length(tgt->u.crypt.vk) == 0 && crypt_is_cipher_null(tgt->u.crypt.cipher))
		log_dbg(cd, "Existing device uses cipher null. Skipping key comparison.");
	else if (cd && isLUKS2(cd->type)) {
		if (_compare_volume_keys_luks2(src->u.crypt.vk, tgt->u.crypt.vk)) {
			log_dbg(cd, "Keys in LUKS2 context and target device do not match.");
			goto out;
		}
	} else if (_compare_volume_keys(src->u.crypt.vk, tgt->u.crypt.vk)) {
		log_dbg(cd, "Keys in context and target device do not match.");
		goto out;
	}

	if (crypt_strcmp(src_integrity, tgt->u.crypt.integrity)) {
		log_dbg(cd, "Integrity parameters do not match.");
		goto out;
	}

	if (src->u.crypt.offset      != tgt->u.crypt.offset ||
	    src->u.crypt.sector_size != tgt->u.crypt.sector_size ||
	    src->u.crypt.iv_offset   != tgt->u.crypt.iv_offset ||
	    src->u.crypt.tag_size    != tgt->u.crypt.tag_size) {
		log_dbg(cd, "Integer parameters do not match.");
		goto out;
	}

	if (device_is_identical(src->data_device, tgt->data_device) <= 0)
		log_dbg(cd, "Data devices do not match.");
	else
		r = 0;

out:
	free(src_cipher);
	free(src_integrity);

	return r;
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
	if (_compare_volume_keys(src->u.integrity.vk, tgt->u.integrity.vk) ||
	    _compare_volume_keys(src->u.integrity.journal_integrity_key, tgt->u.integrity.journal_integrity_key) ||
	    _compare_volume_keys(src->u.integrity.journal_crypt_key, tgt->u.integrity.journal_crypt_key)) {
		log_dbg(cd, "Journal keys do not match.");
		return -EINVAL;
	}

	if (device_is_identical(src->data_device, tgt->data_device) <= 0) {
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
			  struct crypt_dm_active_device *sdmd, uint64_t dmflags)
{
	int r;
	struct crypt_dm_active_device tdmd;
	struct dm_target *src, *tgt = &tdmd.segment;

	assert(cd);
	assert(sdmd);

	if (!cd->type || !name || !(sdmd->flags & CRYPT_ACTIVATE_REFRESH))
		return -EINVAL;

	src = &sdmd->segment;

	r = dm_query_device(cd, name, DM_ACTIVE_DEVICE | DM_ACTIVE_CRYPT_CIPHER |
				  DM_ACTIVE_UUID | DM_ACTIVE_CRYPT_KEYSIZE |
				  DM_ACTIVE_CRYPT_KEY | DM_ACTIVE_INTEGRITY_PARAMS |
				  DM_ACTIVE_JOURNAL_CRYPT_KEY | DM_ACTIVE_JOURNAL_MAC_KEY, &tdmd);
	if (r < 0) {
		log_err(cd, _("Device %s is not active."), name);
		return -EINVAL;
	}

	if (!single_segment(&tdmd) ||
	    (tgt->type != DM_CRYPT && tgt->type != DM_INTEGRITY) ||
	    (tgt->type == DM_CRYPT && tgt->u.crypt.tag_size)) {
		r = -ENOTSUP;
		log_err(cd, _("Unsupported parameters on device %s."), name);
		goto out;
	}

	r = crypt_compare_dm_devices(cd, sdmd, &tdmd);
	if (r) {
		log_err(cd, _("Mismatching parameters on device %s."), name);
		goto out;
	}

	/* Changing read only flag for active device makes no sense */
	if (tdmd.flags & CRYPT_ACTIVATE_READONLY)
		sdmd->flags |= CRYPT_ACTIVATE_READONLY;
	else
		sdmd->flags &= ~CRYPT_ACTIVATE_READONLY;

	/*
	 * Only LUKS2 allows altering between volume key
	 * passed by hexbyte representation and reference
	 * to kernel keyring service.
	 *
	 * To make it easier pass src key directly after
	 * it was properly verified in crypt_compare_dm_devices
	 * call above.
	 */
	if (isLUKS2(cd->type) && tgt->type == DM_CRYPT && src->u.crypt.vk) {
		crypt_free_volume_key(tgt->u.crypt.vk);
		tgt->u.crypt.vk = src->u.crypt.vk;
	}

	if (tgt->type == DM_CRYPT)
		r = device_block_adjust(cd, src->data_device, DEV_OK,
					src->u.crypt.offset, &sdmd->size, NULL);
	else if (tgt->type == DM_INTEGRITY)
		r = device_block_adjust(cd, src->data_device, DEV_OK,
					src->u.integrity.offset, &sdmd->size, NULL);
	else
		r = -EINVAL;

	if (r)
		goto out;

	tdmd.flags = sdmd->flags;
	tgt->size = tdmd.size = sdmd->size;

	r = dm_reload_device(cd, name, &tdmd, dmflags, 1);
out:
	/* otherwise dm_targets_free would free src key */
	if (src->u.crypt.vk == tgt->u.crypt.vk)
		tgt->u.crypt.vk = NULL;

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
	bool clear = false;

	assert(cd);
	assert(sdmd);
	assert(sdmdi);

	if (!cd->type || !name || !iname || !(sdmd->flags & CRYPT_ACTIVATE_REFRESH))
		return -EINVAL;

	src = &sdmd->segment;
	srci = &sdmdi->segment;

	r = dm_query_device(cd, name, DM_ACTIVE_DEVICE | DM_ACTIVE_CRYPT_CIPHER |
				  DM_ACTIVE_UUID | DM_ACTIVE_CRYPT_KEYSIZE |
				  DM_ACTIVE_CRYPT_KEY, &tdmd);
	if (r < 0) {
		log_err(cd, _("Device %s is not active."), name);
		return -EINVAL;
	}

	if (!single_segment(&tdmd) || tgt->type != DM_CRYPT || !tgt->u.crypt.tag_size) {
		log_err(cd, _("Unsupported parameters on device %s."), name);
		r = -ENOTSUP;
		goto out;
	}

	r = dm_query_device(cd, iname, DM_ACTIVE_DEVICE | DM_ACTIVE_UUID, &tdmdi);
	if (r < 0) {
		log_err(cd, _("Device %s is not active."), iname);
		r = -EINVAL;
		goto out;
	}

	if (!single_segment(&tdmdi) || tgti->type != DM_INTEGRITY) {
		log_err(cd, _("Unsupported parameters on device %s."), iname);
		r = -ENOTSUP;
		goto out;
	}

	r = crypt_compare_dm_devices(cd, sdmdi, &tdmdi);
	if (r) {
		log_err(cd, _("Mismatching parameters on device %s."), iname);
		goto out;
	}

	/* unsupported underneath dm-crypt with auth. encryption */
	if (sdmdi->segment.u.integrity.meta_device || tdmdi.segment.u.integrity.meta_device) {
		r = -ENOTSUP;
		goto out;
	}

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

	/*
	 * To make it easier pass src key directly after
	 * it was properly verified in crypt_compare_dm_devices
	 * call above.
	 */
	crypt_free_volume_key(tgt->u.crypt.vk);
	tgt->u.crypt.vk = src->u.crypt.vk;

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
		clear = true;
		goto out;
	}

	if ((r = dm_suspend_device(cd, name, 0))) {
		log_err(cd, _("Failed to suspend device %s."), name);
		clear = true;
		goto out;
	}

	if ((r = dm_suspend_device(cd, iname, 0))) {
		log_err(cd, _("Failed to suspend device %s."), iname);
		clear = true;
		goto out;
	}

	if ((r = dm_resume_device(cd, iname, act2dmflags(sdmdi->flags)))) {
		log_err(cd, _("Failed to resume device %s."), iname);
		clear = true;
		goto out;
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
out:
	if (clear) {
		dm_clear_device(cd, name);
		dm_clear_device(cd, iname);

		if (dm_status_suspended(cd, name) > 0)
			dm_resume_device(cd, name, 0);
		if (dm_status_suspended(cd, iname) > 0)
			dm_resume_device(cd, iname, 0);
	}

	/* otherwise dm_targets_free would free src key */
	if (tgt->u.crypt.vk == src->u.crypt.vk)
		tgt->u.crypt.vk = NULL;
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
	struct crypt_params_integrity params = {};
	uint64_t supported_flags = 0, dmflags = 0;
	uint64_t old_size;
	int r;

	/* Device context type must be initialized */
	if (!cd || !cd->type || !name)
		return -EINVAL;

	if (isTCRYPT(cd->type) || isBITLK(cd->type)) {
		log_err(cd, _("This operation is not supported for this device type."));
		return -ENOTSUP;
	}

	if (isLUKS2(cd->type) && !LUKS2_segments_dynamic_size(&cd->u.luks2.hdr)) {
		log_err(cd, _("Can not resize LUKS2 device with static size."));
		return -EINVAL;
	}

	if (isLUKS2(cd->type) && crypt_get_integrity_tag_size(cd)) {
		log_err(cd, _("Resize of LUKS2 device with integrity protection is not supported."));
		return -ENOTSUP;
	}

	if (new_size)
		log_dbg(cd, "Resizing device %s to %" PRIu64 " sectors.", name, new_size);
	else
		log_dbg(cd, "Resizing device %s to underlying device size.", name);

	r = dm_query_device(cd, name, DM_ACTIVE_CRYPT_KEYSIZE | DM_ACTIVE_CRYPT_KEY |
			    DM_ACTIVE_INTEGRITY_PARAMS | DM_ACTIVE_JOURNAL_CRYPT_KEY |
			    DM_ACTIVE_JOURNAL_MAC_KEY, &dmdq);
	if (r < 0) {
		log_err(cd, _("Device %s is not active."), name);
		return -EINVAL;
	}
	if (!single_segment(&dmdq) || (tgt->type != DM_CRYPT && tgt->type != DM_INTEGRITY)) {
		log_dbg(cd, "Unsupported device table detected in %s.", name);
		r = -EINVAL;
		goto out;
	}

	if ((dmdq.flags & CRYPT_ACTIVATE_KEYRING_KEY) && !crypt_key_in_keyring(cd)) {
		r = -EPERM;
		goto out;
	}

	if (crypt_key_in_keyring(cd)) {
		if (isLUKS2(cd->type))
			r = LUKS2_key_description_by_segment(cd, &cd->u.luks2.hdr,
						tgt->u.crypt.vk, CRYPT_DEFAULT_SEGMENT);
		else if (isPLAIN(cd->type))
			r = 0; /* key description was set on table load */
		else
			r = -EINVAL;
		if (r < 0)
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


	/*
	 * Integrity device metadata are maintained by the kernel. We need to
	 * reload the device (with the same parameters) and let the kernel
	 * calculate the maximum size of integrity device and store it in the
	 * superblock.
	 */
	if (!new_size && tgt->type == DM_INTEGRITY) {
		r = INTEGRITY_data_sectors(cd, crypt_metadata_device(cd),
					   crypt_get_data_offset(cd) * SECTOR_SIZE, &old_size);
		if (r < 0)
			return r;

		dmd.size = dmdq.size;
		dmd.flags = dmdq.flags | CRYPT_ACTIVATE_REFRESH | CRYPT_ACTIVATE_PRIVATE;

		r = crypt_get_integrity_info(cd, &params);
		if (r)
			goto out;

		r = dm_integrity_target_set(cd, &dmd.segment, 0, dmdq.segment.size,
				crypt_metadata_device(cd), crypt_data_device(cd),
				crypt_get_integrity_tag_size(cd), crypt_get_data_offset(cd),
				crypt_get_sector_size(cd), tgt->u.integrity.vk, tgt->u.integrity.journal_crypt_key,
				tgt->u.integrity.journal_integrity_key, &params);
		if (r)
			goto out;
		/* Backend device cannot be smaller here, device_block_adjust() will fail if so. */
		r = _reload_device(cd, name, &dmd, DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH);
		if (r)
			goto out;

		r = INTEGRITY_data_sectors(cd, crypt_metadata_device(cd),
				crypt_get_data_offset(cd) * SECTOR_SIZE, &new_size);
		if (r < 0)
			return r;
		log_dbg(cd, "Maximum integrity device size from kernel %" PRIu64, new_size);

		if (old_size == new_size && new_size == dmdq.size &&
		    !dm_flags(cd, tgt->type, &supported_flags) &&
		    !(supported_flags & DM_INTEGRITY_RESIZE_SUPPORTED))
			log_std(cd, _("WARNING: Maximum size already set or kernel doesn't support resize.\n"));
	}

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
			crypt_get_data_offset(cd), &new_size, &dmdq.flags);
	if (r)
		goto out;

	if (MISALIGNED(new_size, (tgt->type == DM_CRYPT ? tgt->u.crypt.sector_size : tgt->u.integrity.sector_size) >> SECTOR_SHIFT)) {
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

	if (tgt->type == DM_CRYPT) {
		r = dm_crypt_target_set(&dmd.segment, 0, new_size, crypt_data_device(cd),
				tgt->u.crypt.vk, crypt_get_cipher_spec(cd),
				crypt_get_iv_offset(cd), crypt_get_data_offset(cd),
				crypt_get_integrity(cd), crypt_get_integrity_key_size(cd, true), crypt_get_integrity_tag_size(cd),
				crypt_get_sector_size(cd));
		if (r < 0)
			goto out;
	} else if (tgt->type == DM_INTEGRITY) {
		r = crypt_get_integrity_info(cd, &params);
		if (r)
			goto out;

		r = dm_integrity_target_set(cd, &dmd.segment, 0, new_size,
				crypt_metadata_device(cd), crypt_data_device(cd),
				crypt_get_integrity_tag_size(cd), crypt_get_data_offset(cd),
				crypt_get_sector_size(cd), tgt->u.integrity.vk, tgt->u.integrity.journal_crypt_key,
				tgt->u.integrity.journal_integrity_key, &params);
		if (r)
			goto out;
	}

	if (new_size == dmdq.size) {
		log_dbg(cd, "Device has already requested size %" PRIu64
			" sectors.", dmdq.size);
		r = 0;
	} else {
		if (isTCRYPT(cd->type))
			r = -ENOTSUP;
		else if (isLUKS2(cd->type))
			r = LUKS2_unmet_requirements(cd, &cd->u.luks2.hdr, 0, 0);

		if (!r) {
			/* Skip flush and lockfs if extending device */
			if (new_size > dmdq.size)
				dmflags = DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH;
			r = _reload_device(cd, name, &dmd, dmflags);
		}

		if (r && tgt->type == DM_INTEGRITY &&
		    !dm_flags(cd, tgt->type, &supported_flags) &&
		    !(supported_flags & DM_INTEGRITY_RESIZE_SUPPORTED))
			log_err(cd, _("Resize failed, the kernel doesn't support it."));
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

const char *crypt_get_label(struct crypt_device *cd)
{
	if (_onlyLUKS2(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED, 0))
		return NULL;

	return cd->u.luks2.hdr.label;
}

const char *crypt_get_subsystem(struct crypt_device *cd)
{
	if (_onlyLUKS2(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED, 0))
		return NULL;

	return cd->u.luks2.hdr.subsystem;
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
	r = _crypt_load_luks(cd, requested_type, false, false);
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
			(void) _crypt_load_luks2(cd, 1, 0);
	} else if (isLUKS1(cd->type) && (!requested_type || isLUKS1(requested_type)))
		r = LUKS_hdr_restore(backup_file, &cd->u.luks1.hdr, cd);
	else
		r = -EINVAL;

	if (!r)
		r = _crypt_load_luks(cd, version == 1 ? CRYPT_LUKS1 : CRYPT_LUKS2, false, true);

	return r;
}

int crypt_header_is_detached(struct crypt_device *cd)
{
	int r;

	if (!cd || (cd->type && !isLUKS(cd->type)))
		return -EINVAL;

	r = device_is_identical(crypt_data_device(cd), crypt_metadata_device(cd));
	if (r < 0) {
		log_dbg(cd, "Failed to compare data and metadata devices path.");
		return r;
	}

	return r ? 0 : 1;
}

void crypt_free(struct crypt_device *cd)
{
	if (!cd)
		return;

	log_dbg(cd, "Releasing crypt device %s context.", mdata_device_path(cd) ?: "empty");

	dm_backend_exit(cd);
	crypt_free_volume_key(cd->volume_key);

	crypt_free_type(cd, NULL);

	device_free(cd, cd->device);
	device_free(cd, cd->metadata_device);

	free(CONST_CAST(void*)cd->pbkdf.type);
	free(CONST_CAST(void*)cd->pbkdf.hash);
	free(CONST_CAST(void*)cd->user_key_name1);
	free(CONST_CAST(void*)cd->user_key_name2);

	/* Some structures can contain keys (TCRYPT), wipe it */
	crypt_safe_memzero(cd, sizeof(*cd));
	free(cd);
}

int crypt_suspend(struct crypt_device *cd,
		  const char *name)
{
	bool dm_opal_uuid;
	crypt_status_info ci;
	int r;
	struct crypt_dm_active_device dmd, dmdi = {};
	uint32_t opal_segment_number = 1;
	uint64_t dmflags = DM_SUSPEND_WIPE_KEY;
	struct dm_target *tgt = &dmd.segment;
	char *iname = NULL;
	struct crypt_lock_handle *opal_lh = NULL;

	if (!cd || !name)
		return -EINVAL;

	log_dbg(cd, "Suspending volume %s.", name);

	if (cd->type && ((r = onlyLUKS(cd)) < 0))
		return r;

	ci = crypt_status(cd, name);
	if (ci < CRYPT_ACTIVE) {
		log_err(cd, _("Volume %s is not active."), name);
		return -EINVAL;
	}

	r = dm_query_device(cd, name,
			    DM_ACTIVE_UUID | DM_ACTIVE_CRYPT_KEY | DM_ACTIVE_CRYPT_KEYSIZE,
			    &dmd);
	if (r < 0)
		return r;

	log_dbg(cd, "Checking if active device %s has UUID type LUKS.", name);

	r = dm_uuid_type_cmp(dmd.uuid, CRYPT_LUKS2);
	if (r < 0)
		r = dm_uuid_type_cmp(dmd.uuid, CRYPT_LUKS1);

	if (r < 0) {
		log_err(cd, _("This operation is supported only for LUKS device."));
		goto out;
	}

	r = -EINVAL;

	if (isLUKS2(cd->type) && dm_uuid_type_cmp(dmd.uuid, CRYPT_LUKS2)) {
		log_dbg(cd, "LUKS device header type: %s mismatches DM device type.", cd->type);
		goto out;
	}

	if (isLUKS1(cd->type) && dm_uuid_type_cmp(dmd.uuid, CRYPT_LUKS1)) {
		log_dbg(cd, "LUKS device header type: %s mismatches DM device type.", cd->type);
		goto out;
	}

	/* check if active device has LUKS2-OPAL dm uuid prefix */
	dm_opal_uuid = !dm_uuid_type_cmp(dmd.uuid, CRYPT_LUKS2_HW_OPAL);

	if (!dm_opal_uuid && isLUKS2(cd->type) &&
	    LUKS2_segment_is_hw_opal(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT))
		goto out;

	if (cd->type && (r = dm_uuid_cmp(dmd.uuid, LUKS_UUID(cd))) < 0) {
		log_dbg(cd, "LUKS device header uuid: %s mismatches DM returned uuid %s",
			LUKS_UUID(cd), dmd.uuid);
		goto out;
	}

	/* check UUID of integrity device underneath crypt device */
	if (crypt_get_integrity_tag_size(cd))
	    iname = dm_get_active_iname(cd, name);

	r = dm_status_suspended(cd, name);
	if (r < 0)
		goto out;

	if (r) {
		log_err(cd, _("Volume %s is already suspended."), name);
		r = -EINVAL;
		goto out;
	}

	if (dm_opal_uuid && crypt_data_device(cd)) {
		if (isLUKS2(cd->type)) {
			r = LUKS2_get_opal_segment_number(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, &opal_segment_number);
			if (r < 0)
				goto out;
		} else {
			 /* Guess OPAL range number for LUKS2-OPAL device with missing header */
			r = crypt_dev_get_partition_number(device_path(crypt_data_device(cd)));
			if (r > 0)
				opal_segment_number = r;
		}
	}

	/* we can't simply wipe wrapped keys. HW OPAL only encryption does not use dm-crypt target */
	if (crypt_cipher_wrapped_key(crypt_get_cipher(cd), crypt_get_cipher_mode(cd)) ||
	    (dm_opal_uuid && tgt->type == DM_LINEAR))
		dmflags &= ~DM_SUSPEND_WIPE_KEY;

	r = dm_suspend_device(cd, name, dmflags);
	if (r) {
		if (r == -ENOTSUP)
			log_err(cd, _("Suspend is not supported for device %s."), name);
		else
			log_err(cd, _("Error during suspending device %s."), name);
		goto out;
	}

	/* Suspend integrity device underneath; keep crypt suspended if it fails */
	if (iname) {
		r = dm_suspend_device(cd, iname, 0);
		if (r)
			log_err(cd, _("Error during suspending device %s."), iname);
	}

	if (single_segment(&dmd) && tgt->type == DM_CRYPT)
		crypt_volume_key_drop_kernel_key(cd, tgt->u.crypt.vk);

	if (dm_opal_uuid && crypt_data_device(cd)) {
		r = opal_exclusive_lock(cd, crypt_data_device(cd), &opal_lh);
		if (r < 0) {
			log_err(cd, _("Failed to acquire OPAL lock on device %s."), device_path(crypt_data_device(cd)));
			goto out;
		}
	}

	if (dm_opal_uuid && (!crypt_data_device(cd) || opal_lock(cd, crypt_data_device(cd), opal_segment_number)))
		log_err(cd, _("Device %s was suspended but hardware OPAL device cannot be locked."), name);
out:
	opal_exclusive_unlock(cd, opal_lh);
	free(iname);
	dm_targets_free(cd, &dmd);
	dm_targets_free(cd, &dmdi);
	free(CONST_CAST(void*)dmd.uuid);
	free(CONST_CAST(void*)dmdi.uuid);
	return r;
}

static int resume_luks1_by_volume_key(struct crypt_device *cd,
		struct volume_key *vk,
		const char *name)
{
	int r;
	struct volume_key *zerokey = NULL;

	assert(vk && crypt_volume_key_get_id(vk) == 0);
	assert(name);

	if (crypt_is_cipher_null(crypt_get_cipher_spec(cd))) {
		zerokey = crypt_alloc_volume_key(0, NULL);
		if (!zerokey)
			return -ENOMEM;
		vk = zerokey;
	}

	r = dm_resume_and_reinstate_key(cd, name, vk);

	if (r == -ENOTSUP)
		log_err(cd, _("Resume is not supported for device %s."), name);
	else if (r)
		log_err(cd, _("Error during resuming device %s."), name);

	crypt_free_volume_key(zerokey);

	return r;
}

static void crypt_unlink_key_from_custom_keyring(struct crypt_device *cd, key_serial_t kid)
{
	assert(cd);
	assert(cd->keyring_to_link_vk);

	log_dbg(cd, "Unlinking volume key (id: %" PRIi32 ") from kernel keyring (id: %" PRIi32 ").",
		kid, cd->keyring_to_link_vk);

	if (!keyring_unlink_key_from_keyring(kid, cd->keyring_to_link_vk))
		return;

	log_dbg(cd, "keyring_unlink_key_from_keyring failed with errno %d.", errno);
	log_err(cd, _("Failed to unlink volume key from user specified keyring."));
}

static key_serial_t crypt_single_volume_key_load_in_custom_keyring(struct crypt_device *cd,
								   struct volume_key *vk,
								   const char *user_key_name)
{
	key_serial_t kid;
	const char *type_name;

	assert(cd);
	assert(cd->link_vk_to_keyring);

	if (!vk || !(type_name = key_type_name(cd->keyring_key_type)))
		return -EINVAL;

	log_dbg(cd, "Linking volume key (type %s, name %s) to the specified keyring",
		    type_name, user_key_name);

	kid = keyring_add_key_to_keyring(cd->keyring_key_type, user_key_name,
					 crypt_volume_key_get_key(vk),
					 crypt_volume_key_length(vk),
					 cd->keyring_to_link_vk);
	if (kid <= 0)
		log_dbg(cd, "The keyring_add_key_to_keyring function failed (error %d).", errno);

	return kid;
}

static int crypt_volume_key_load_in_custom_keyring(struct crypt_device *cd,
						   struct volume_key *vk,
						   key_serial_t *kid1_out,
						   key_serial_t *kid2_out)
{
	key_serial_t kid1, kid2 = 0;

	assert(cd);
	assert(cd->link_vk_to_keyring);
	assert(cd->user_key_name1);

	if (!vk || !key_type_name(cd->keyring_key_type))
		return -EINVAL;

	kid1 = crypt_single_volume_key_load_in_custom_keyring(cd, vk, cd->user_key_name1);
	if (kid1 <= 0)
		return -EINVAL;

	vk = crypt_volume_key_next(vk);
	if (vk) {
		assert(cd->user_key_name2);
		kid2 = crypt_single_volume_key_load_in_custom_keyring(cd, vk, cd->user_key_name2);
		if (kid2 <= 0) {
			crypt_unlink_key_from_custom_keyring(cd, kid1);
			return -EINVAL;
		}
	}

	*kid2_out = kid2;
	*kid1_out = kid1;
	return 0;
}

static int resume_luks2_by_volume_key(struct crypt_device *cd,
		int digest,
		struct volume_key *vk,
		const char *name)
{
	bool use_keyring;
	int r, enc_type;
	uint32_t opal_segment_number;
	struct volume_key *p_crypt = vk, *p_opal = NULL, *zerokey = NULL, *crypt_key = NULL, *opal_key = NULL;
	char *iname = NULL;
	struct crypt_lock_handle *opal_lh = NULL;
	key_serial_t kid1 = 0, kid2 = 0;

	assert(digest >= 0);
	assert(vk && crypt_volume_key_get_id(vk) == digest);
	assert(name);

	enc_type = crypt_get_hw_encryption_type(cd);
	if (enc_type < 0)
		return enc_type;

	use_keyring = crypt_use_keyring_for_vk(cd);

	if (enc_type == CRYPT_OPAL_HW_ONLY || enc_type == CRYPT_SW_AND_OPAL_HW) {
		r = LUKS2_get_opal_segment_number(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT,
						  &opal_segment_number);
		if (r < 0)
			return r;

		r = LUKS2_split_crypt_and_opal_keys(cd, &cd->u.luks2.hdr,
						    vk, &crypt_key,
						    &opal_key);
		if (r < 0)
			return r;

		p_crypt = crypt_key;
		p_opal = opal_key ?: vk;
	}

	if (enc_type != CRYPT_OPAL_HW_ONLY && crypt_is_cipher_null(crypt_get_cipher_spec(cd))) {
		zerokey = crypt_alloc_volume_key(0, NULL);
		if (!zerokey) {
			r = -ENOMEM;
			goto out;
		}
		p_crypt = zerokey;
		use_keyring = false;
	}

	if (use_keyring) {
		if (p_crypt) {
			r = LUKS2_volume_key_load_in_keyring_by_digest(cd, p_crypt, digest);
			if (r < 0)
				goto out;
		}

		/* upload volume key in custom keyring if requested */
		if (cd->link_vk_to_keyring) {
			r = crypt_volume_key_load_in_custom_keyring(cd, vk, &kid1, &kid2);
			if (r < 0) {
				log_err(cd, _("Failed to link volume key in user defined keyring."));
				goto out;
			}
		}
	}

	if (p_opal) {
		r = opal_exclusive_lock(cd, crypt_data_device(cd), &opal_lh);
		if (r < 0) {
			log_err(cd, _("Failed to acquire OPAL lock on device %s."), device_path(crypt_data_device(cd)));
			goto out;
		}

		r = opal_unlock(cd, crypt_data_device(cd), opal_segment_number, p_opal);
		if (r < 0) {
			p_opal = NULL; /* do not lock on error path */
			goto out;
		}
	}

	if (crypt_get_integrity_tag_size(cd) &&
	    (iname = dm_get_active_iname(cd, name))) {
		r = dm_resume_device(cd, iname, 0);
		if (r)
			log_err(cd, _("Error during resuming device %s."), iname);
		free(iname);
	}

	if (enc_type == CRYPT_OPAL_HW_ONLY)
		r = dm_resume_device(cd, name, 0);
	else
		r = dm_resume_and_reinstate_key(cd, name, p_crypt);

	if (r == -ENOTSUP)
		log_err(cd, _("Resume is not supported for device %s."), name);
	else if (r)
		log_err(cd, _("Error during resuming device %s."), name);

out:
	if (r < 0) {
		crypt_drop_uploaded_keyring_key(cd, p_crypt);
		if (cd->link_vk_to_keyring && kid1)
			crypt_unlink_key_from_custom_keyring(cd, kid1);
		if (cd->link_vk_to_keyring && kid2)
			crypt_unlink_key_from_custom_keyring(cd, kid2);
	}

	if (r < 0 && p_opal)
		opal_lock(cd, crypt_data_device(cd), opal_segment_number);

	opal_exclusive_unlock(cd, opal_lh);
	crypt_free_volume_key(zerokey);
	crypt_free_volume_key(opal_key);
	crypt_free_volume_key(crypt_key);

	return r;
}

/* key must be properly verified */
static int resume_by_volume_key(struct crypt_device *cd,
		struct volume_key *vk,
		const char *name)
{
	assert(cd);

	if (isLUKS2(cd->type))
		return resume_luks2_by_volume_key(cd,
				LUKS2_digest_by_segment(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT),
				vk, name);

	if (isLUKS1(cd->type))
		return resume_luks1_by_volume_key(cd, vk, name);

	return -EINVAL;
}

int crypt_resume_by_keyslot_context(struct crypt_device *cd,
			       const char *name,
			       int keyslot,
			       struct crypt_keyslot_context *kc)
{
	int r;
	struct volume_key *vk = NULL;
	int unlocked_keyslot = -EINVAL;

	if (!name)
		return -EINVAL;

	log_dbg(cd, "Resuming volume %s [keyslot %d] using %s.", name, keyslot, keyslot_context_type_string(kc));

	if ((r = onlyLUKS(cd)))
		return r;

	r = dm_status_suspended(cd, name);
	if (r < 0)
		return r;

	if (!r) {
		log_err(cd, _("Volume %s is not suspended."), name);
		return -EINVAL;
	}

	if (isLUKS1(cd->type) && kc->get_luks1_volume_key)
		r = kc->get_luks1_volume_key(cd, kc, keyslot, &vk);
	else if (isLUKS2(cd->type) && kc->get_luks2_volume_key)
		r = kc->get_luks2_volume_key(cd, kc, keyslot, &vk);
	else
		r = -EINVAL;
	if (r < 0)
		goto out;
	unlocked_keyslot = r;

	if (isLUKS1(cd->type)) {
		r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);
		crypt_volume_key_set_id(vk, 0);
	} else if (isLUKS2(cd->type)) {
		r = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
		crypt_volume_key_set_id(vk, r);
	} else
		r = -EINVAL;
	if (r < 0)
		goto out;

	r = resume_by_volume_key(cd, vk, name);

	crypt_free_volume_key(vk);
	return r < 0 ? r : unlocked_keyslot;
out:
	crypt_free_volume_key(vk);
	return r;
}

int crypt_resume_by_passphrase(struct crypt_device *cd,
			       const char *name,
			       int keyslot,
			       const char *passphrase,
			       size_t passphrase_size)
{
	int r;
	struct crypt_keyslot_context kc = {};

	crypt_keyslot_context_init_by_passphrase_internal(&kc, passphrase, passphrase_size);
	r = crypt_resume_by_keyslot_context(cd, name, keyslot, &kc);
	crypt_keyslot_context_destroy_internal(&kc);

	return r;
}

int crypt_resume_by_keyfile_device_offset(struct crypt_device *cd,
					  const char *name,
					  int keyslot,
					  const char *keyfile,
					  size_t keyfile_size,
					  uint64_t keyfile_offset)
{
	int r;
	struct crypt_keyslot_context kc = {};

	crypt_keyslot_context_init_by_keyfile_internal(&kc, keyfile, keyfile_size, keyfile_offset);
	r = crypt_resume_by_keyslot_context(cd, name, keyslot, &kc);
	crypt_keyslot_context_destroy_internal(&kc);

	return r;
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
	int r;
	struct crypt_keyslot_context kc = {};

	crypt_keyslot_context_init_by_key_internal(&kc, volume_key, volume_key_size);
	r = crypt_resume_by_keyslot_context(cd, name, CRYPT_ANY_SLOT /* unused */, &kc);
	crypt_keyslot_context_destroy_internal(&kc);

	if (r == -EPERM || r == -ENOENT)
		log_err(cd, _("Volume key does not match the volume."));

	return r;
}

int crypt_resume_by_token_pin(struct crypt_device *cd, const char *name,
	const char *type, int token, const char *pin, size_t pin_size,
	void *usrptr)
{
	int r;
	struct crypt_keyslot_context kc = {};

	crypt_keyslot_context_init_by_token_internal(&kc, token, type, pin, pin_size, usrptr);
	r = crypt_resume_by_keyslot_context(cd, name, CRYPT_ANY_SLOT, &kc);
	crypt_keyslot_context_destroy_internal(&kc);

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
	int r;
	struct crypt_keyslot_context kc = {}, new_kc = {};

	if (!passphrase || !new_passphrase)
		return -EINVAL;

	crypt_keyslot_context_init_by_passphrase_internal(&kc, passphrase, passphrase_size);
	crypt_keyslot_context_init_by_passphrase_internal(&new_kc, new_passphrase, new_passphrase_size);

	r = crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, &kc, keyslot, &new_kc, 0);

	crypt_keyslot_context_destroy_internal(&kc);
	crypt_keyslot_context_destroy_internal(&new_kc);

	return r;
}

int crypt_keyslot_change_by_passphrase(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	const char *passphrase,
	size_t passphrase_size,
	const char *new_passphrase,
	size_t new_passphrase_size)
{
	bool keyslot_swap = false;
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

	if (isLUKS1(cd->type)) {
		if (keyslot_new == CRYPT_ANY_SLOT) {
			keyslot_new = LUKS_keyslot_find_empty(&cd->u.luks1.hdr);
			if (keyslot_new < 0)
				keyslot_new = keyslot_old;
		}
	} else if (isLUKS2(cd->type)) {
		/* If there is a free keyslot (both id and binary area) avoid in-place keyslot area overwrite  */
		if (keyslot_new == CRYPT_ANY_SLOT || keyslot_new == keyslot_old) {
			keyslot_new = LUKS2_keyslot_find_empty(cd, &cd->u.luks2.hdr, crypt_volume_key_length(vk));
			if (keyslot_new < 0)
				keyslot_new = keyslot_old;
			else
				keyslot_swap = true;
		}
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
			r = LUKS2_token_assignment_copy(cd, &cd->u.luks2.hdr, keyslot_old, keyslot_new, 0);
			if (r < 0)
				goto out;
		} else
			log_dbg(cd, "Key slot %d is going to be overwritten.", keyslot_old);

		r = LUKS2_keyslot_store(cd,  &cd->u.luks2.hdr,
					keyslot_new, new_passphrase,
					new_passphrase_size, vk, &params);
		if (r < 0)
			goto out;

		/* Swap old & new so the final keyslot number remains */
		if (keyslot_swap && keyslot_old != keyslot_new) {
			r = LUKS2_keyslot_swap(cd, &cd->u.luks2.hdr, keyslot_old, keyslot_new);
			if (r < 0)
				goto out;

			/* Swap slot id */
			r = keyslot_old;
			keyslot_old = keyslot_new;
			keyslot_new = r;
		}
	} else
		r = -EINVAL;

	if (r >= 0 && keyslot_old != keyslot_new)
		r = crypt_keyslot_destroy(cd, keyslot_old);

	if (r < 0)
		log_err(cd, _("Failed to swap new key slot."));
out:
	crypt_free_volume_key(vk);
	if (r < 0) {
		_luks2_rollback(cd);
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
	int r;
	struct crypt_keyslot_context kc = {}, new_kc = {};

	if (!keyfile || !new_keyfile)
		return -EINVAL;

	crypt_keyslot_context_init_by_keyfile_internal(&kc, keyfile, keyfile_size, keyfile_offset);
	crypt_keyslot_context_init_by_keyfile_internal(&new_kc, new_keyfile, new_keyfile_size, new_keyfile_offset);

	r = crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, &kc, keyslot, &new_kc, 0);

	crypt_keyslot_context_destroy_internal(&kc);
	crypt_keyslot_context_destroy_internal(&new_kc);

	return r;
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
	int r;
	struct crypt_keyslot_context kc = {}, new_kc = {};

	if (!passphrase)
		return -EINVAL;

	crypt_keyslot_context_init_by_key_internal(&kc, volume_key, volume_key_size);
	crypt_keyslot_context_init_by_passphrase_internal(&new_kc, passphrase, passphrase_size);

	r = crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, &kc, keyslot, &new_kc, 0);

	crypt_keyslot_context_destroy_internal(&kc);
	crypt_keyslot_context_destroy_internal(&new_kc);

	return r;
}

int crypt_keyslot_destroy(struct crypt_device *cd, int keyslot)
{
	crypt_keyslot_info ki;
	int r;

	log_dbg(cd, "Destroying keyslot %d.", keyslot);

	if ((r = onlyLUKSunrestricted(cd)))
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

	return LUKS2_keyslot_wipe(cd, &cd->u.luks2.hdr, keyslot);
}

static int _check_header_data_overlap(struct crypt_device *cd, const char *name)
{
	if (!name || !isLUKS(cd->type))
		return 0;

	if (device_is_identical(crypt_data_device(cd), crypt_metadata_device(cd)) <= 0)
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

	r = INTEGRITY_activate_dmd_device(cd, iname, CRYPT_SUBDEV, dmdi, 0);
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
	return kversion < compact_version(4,15,0,0);
}

int create_or_reload_device(struct crypt_device *cd, const char *name,
		     const char *type, struct crypt_dm_active_device *dmd)
{
	int r;
	enum devcheck device_check;
	struct dm_target *tgt;
	uint64_t offset, dmflags = 0;

	if (!type || !name || !single_segment(dmd))
		return -EINVAL;

	tgt = &dmd->segment;
	if (tgt->type != DM_CRYPT && tgt->type != DM_INTEGRITY && tgt->type != DM_LINEAR)
		return -EINVAL;

	/* drop CRYPT_ACTIVATE_REFRESH flag if any device is inactive */
	r = check_devices(cd, name, NULL, &dmd->flags);
	if (r)
		return r;

	if (dmd->flags & CRYPT_ACTIVATE_REFRESH) {
		/* Refresh and recalculate means increasing dm-integrity device */
		if (tgt->type == DM_INTEGRITY && dmd->flags & CRYPT_ACTIVATE_RECALCULATE)
			dmflags = DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH;
		r = _reload_device(cd, name, dmd, dmflags);
	} else {
		if (tgt->type == DM_CRYPT || tgt->type == DM_LINEAR) {
			device_check = dmd->flags & CRYPT_ACTIVATE_SHARED ? DEV_OK : DEV_EXCL;
			offset = tgt->type == DM_CRYPT ? tgt->u.crypt.offset : tgt->u.linear.offset;

			r = device_block_adjust(cd, tgt->data_device, device_check,
					offset, &dmd->size, &dmd->flags);
			if (!r) {
				tgt->size = dmd->size;
				r = dm_create_device(cd, name, type, dmd);
			}
		} else if (tgt->type == DM_INTEGRITY) {
			r = device_block_adjust(cd, tgt->data_device, DEV_EXCL,
					tgt->u.integrity.offset, NULL, &dmd->flags);
			if (r)
				return r;

			if (tgt->u.integrity.meta_device) {
				r = device_block_adjust(cd, tgt->u.integrity.meta_device, DEV_EXCL, 0, NULL, NULL);
				if (r)
					return r;
			}

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
	char *iname = NULL, *ipath = NULL;

	if (!type || !name || !dmd || !dmdi)
		return -EINVAL;

	r = dm_get_iname(name, &iname, false);
	if (r)
		goto out;

	r = dm_get_iname(name, &ipath, true);
	if (r)
		goto out;

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
	free(iname);

	return r;
}

static int load_all_keys(struct crypt_device *cd, struct volume_key *vks)
{
	int r;
	struct volume_key *vk = vks;

	while (vk) {
		r = LUKS2_volume_key_load_in_keyring_by_digest(cd, vk, crypt_volume_key_get_id(vk));
		if (r < 0)
			return r;
		vk = crypt_volume_key_next(vk);
	}

	return 0;
}

#if USE_LUKS2_REENCRYPTION
static int _activate_reencrypt_device_by_vk(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *name,
	struct volume_key *vks,
	uint32_t flags)
{
	bool dynamic_size;
	crypt_reencrypt_info ri;
	uint64_t minimal_size, device_size;
	int r = 0;
	struct crypt_lock_handle *reencrypt_lock = NULL;
	struct volume_key *vk;

	assert(hdr);
	assert(vks);

	r = LUKS2_reencrypt_lock(cd, &reencrypt_lock);
	if (r) {
		if (r == -EBUSY)
			log_err(cd, _("Reencryption in-progress. Cannot activate device."));
		else
			log_err(cd, _("Failed to get reencryption lock."));
		return r;
	}

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL)))
		goto out;

	ri = LUKS2_reencrypt_status(hdr);
	if (ri == CRYPT_REENCRYPT_INVALID) {
		r = -EINVAL;
		goto out;
	}

	if (ri > CRYPT_REENCRYPT_NONE) {
		/* it's sufficient to force re-verify the reencrypt digest only */
		r = LUKS2_reencrypt_digest_verify(cd, &cd->u.luks2.hdr, vks);
		if (r < 0)
			goto out;

		if (ri == CRYPT_REENCRYPT_CRASH) {
			r = LUKS2_reencrypt_locked_recovery_by_vks(cd, vks);
			if (r < 0) {
				log_err(cd, _("LUKS2 reencryption recovery using volume key(s) failed."));
				goto out;
			}

			ri = LUKS2_reencrypt_status(hdr);
		}
	}

	/* recovery finished reencryption or it was already finished after metadata reload */
	if (ri == CRYPT_REENCRYPT_NONE) {
		vk = crypt_volume_key_by_id(vks, LUKS2_digest_by_segment(hdr, CRYPT_DEFAULT_SEGMENT));
		if (!vk) {
			r = -EPERM;
			goto out;
		}

		r = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
		if (r >= 0)
			r = LUKS2_activate(cd, name, vk, NULL, flags);
		goto out;
	}
	if (ri > CRYPT_REENCRYPT_CLEAN) {
		r = -EINVAL;
		goto out;
	}

	if ((r = LUKS2_get_data_size(hdr, &minimal_size, &dynamic_size)))
		goto out;

	log_dbg(cd, "Entering clean reencryption state mode.");

	r = LUKS2_reencrypt_check_device_size(cd, hdr, minimal_size, &device_size,
					      !(flags & CRYPT_ACTIVATE_SHARED),
					      dynamic_size);
	if (r < 0)
		goto out;
	r = LUKS2_activate_multi(cd, name, vks, device_size >> SECTOR_SHIFT, flags);
out:
	LUKS2_reencrypt_unlock(cd, reencrypt_lock);

	return r;
}

/*
 * Activation/deactivation of a device
 */
static int _activate_luks2_by_volume_key(struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	struct volume_key *external_key,
	uint32_t flags)
{
	int r;
	crypt_reencrypt_info ri;
	ri = LUKS2_reencrypt_status(&cd->u.luks2.hdr);
	if (ri == CRYPT_REENCRYPT_INVALID)
		return -EINVAL;

	if (ri > CRYPT_REENCRYPT_NONE) {
		/* reencryption must reverify keys after taking the reencryption lock and reloading metadata */
		r = _activate_reencrypt_device_by_vk(cd, &cd->u.luks2.hdr, name, vk, flags);
	} else {
		/* hw-opal data segment type does not require volume key for activation */
		assert(!vk || crypt_volume_key_get_id(vk) == LUKS2_digest_by_segment(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT));
		r = LUKS2_activate(cd, name, vk, external_key, flags);
	}

	return r;
}
#else
static int _activate_luks2_by_volume_key(struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	struct volume_key *external_key,
	uint32_t flags)
{
	int r;
	crypt_reencrypt_info ri;
	ri = LUKS2_reencrypt_status(&cd->u.luks2.hdr);
	if (ri == CRYPT_REENCRYPT_INVALID)
		return -EINVAL;

	if (ri > CRYPT_REENCRYPT_NONE) {
		log_err(cd, _("This operation is not supported for this device type."));
		r = -ENOTSUP;
	} else {
		assert(crypt_volume_key_get_id(vk) == LUKS2_digest_by_segment(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT));
		r = LUKS2_activate(cd, name, vk, external_key, flags);
	}

	return r;
}
#endif

static int _activate_loopaes(struct crypt_device *cd,
	const char *name,
	const char *buffer,
	size_t buffer_size,
	uint32_t flags)
{
	int r;
	unsigned int key_count = 0;
	struct volume_key *vk = NULL;
	char *buffer_copy;

	buffer_copy = crypt_safe_alloc(buffer_size);
	if (!buffer_copy)
		return -ENOMEM;
	crypt_safe_memcpy(buffer_copy, buffer, buffer_size);

	r = LOOPAES_parse_keyfile(cd, &vk, cd->u.loopaes.hdr.hash, &key_count,
				  buffer_copy, buffer_size);
	crypt_safe_free(buffer_copy);

	if (!r && name)
		r = LOOPAES_activate(cd, name, cd->u.loopaes.cipher, key_count,
				     vk, flags);

	crypt_free_volume_key(vk);

	return r;
}

static int _activate_check_status(struct crypt_device *cd, const char *name, unsigned reload)
{
	int r;

	if (!name)
		return 0;

	r = dm_status_device(cd, name);

	if (r >= 0 && reload)
		return 0;

	if (r >= 0 || r == -EEXIST) {
		log_err(cd, _("Device %s already exists."), name);
		return -EEXIST;
	}

	if (r == -ENODEV)
		return 0;

	log_err(cd, _("Cannot use device %s, name is invalid or still in use."), name);
	return r;
}

static int _verify_reencrypt_keys(struct crypt_device *cd, struct volume_key *vks)
{
	int r;

	assert(cd && (isLUKS2(cd->type)));

	r = LUKS2_reencrypt_digest_verify(cd, &cd->u.luks2.hdr, vks);
	if (r == -EPERM || r == -ENOENT || r == -EINVAL)
		log_err(cd, _("Reencryption volume keys do not match the volume."));

	return r;
}

static int _verify_key(struct crypt_device *cd,
	bool unbound_key,
	struct volume_key *vk)
{
	int r = -EINVAL;

	assert(cd);

	if (isPLAIN(cd->type)) {
		if (vk && crypt_volume_key_length(vk) == cd->u.plain.key_size) {
			r = KEY_VERIFIED;
		} else
			log_err(cd, _("Incorrect volume key specified for plain device."));
	} else if (isLUKS1(cd->type)) {
		if (!vk)
			return -EINVAL;

		r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);
	} else if (isLUKS2(cd->type)) {
		if (!vk)
			return -EINVAL;

		if (unbound_key)
			r = LUKS2_digest_verify_by_any_matching(cd, vk);
		else
			r = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
	} else if (isVERITY(cd->type))
		r = KEY_VERIFIED;
	else if (isTCRYPT(cd->type))
		r = KEY_VERIFIED;
	else if (isINTEGRITY(cd->type))
		r = KEY_VERIFIED;
	else if (isBITLK(cd->type))
		r = KEY_VERIFIED;
	else if (isFVAULT2(cd->type)) {
		if (vk && crypt_volume_key_length(vk) == FVAULT2_volume_key_size())
			r = KEY_VERIFIED;
	} else
		log_err(cd, _("Device type is not properly initialized."));

	if (r >= KEY_VERIFIED)
		crypt_volume_key_set_id(vk, r);

	return r > 0 ? 0 : r;
}

/* activation/deactivation of device mapping */
static int _activate_by_volume_key(struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	struct volume_key *external_key,
	uint32_t flags)
{
	int r;

	assert(cd);
	assert(name);

	r = _check_header_data_overlap(cd, name);
	if (r < 0)
		return r;

	/* use key directly, no hash */
	if (isPLAIN(cd->type)) {
		assert(!external_key);
		assert(crypt_volume_key_get_id(vk) == KEY_VERIFIED);

		r = PLAIN_activate(cd, name, vk, cd->u.plain.hdr.size, flags);
	} else if (isLUKS1(cd->type)) {
		assert(!external_key);
		assert(crypt_volume_key_get_id(vk) == KEY_VERIFIED);

		r = LUKS1_activate(cd, name, vk, flags);
	} else if (isLUKS2(cd->type)) {
		r = _activate_luks2_by_volume_key(cd, name, vk, external_key, flags);
	} else if (isVERITY(cd->type)) {
		assert(crypt_volume_key_get_id(vk) == KEY_VERIFIED);
		r = VERITY_activate(cd, name, vk, external_key, cd->u.verity.fec_device,
				    &cd->u.verity.hdr, flags);
	} else if (isTCRYPT(cd->type)) {
		assert(!external_key);
		r = TCRYPT_activate(cd, name, &cd->u.tcrypt.hdr,
				    &cd->u.tcrypt.params, flags);
	} else if (isINTEGRITY(cd->type)) {
		assert(!external_key);
		assert(!vk || crypt_volume_key_get_id(vk) == KEY_VERIFIED);
		r = INTEGRITY_activate(cd, name, &cd->u.integrity.params, vk,
				       cd->u.integrity.journal_crypt_key,
				       cd->u.integrity.journal_mac_key, flags,
				       cd->u.integrity.sb_flags);
	} else if (isBITLK(cd->type)) {
		assert(!external_key);
		assert(crypt_volume_key_get_id(vk) == KEY_VERIFIED);
		r = BITLK_activate_by_volume_key(cd, name, vk, &cd->u.bitlk.params, flags);
	} else if (isFVAULT2(cd->type)) {
		assert(!external_key);
		assert(crypt_volume_key_get_id(vk) == KEY_VERIFIED);
		r = FVAULT2_activate_by_volume_key(cd, name, vk, &cd->u.fvault2.params, flags);
	} else {
		log_err(cd, _("Device type is not properly initialized."));
		r = -EINVAL;
	}

	return r;
}

int crypt_activate_by_keyslot_context(struct crypt_device *cd,
	const char *name,
	int keyslot,
	struct crypt_keyslot_context *kc,
	int additional_keyslot,
	struct crypt_keyslot_context *additional_kc,
	uint32_t flags)
{
	bool use_keyring, luks2_reencryption = false;
	struct volume_key *p_ext_key, *crypt_key = NULL, *opal_key = NULL, *vk = NULL,
		*vk_sign = NULL, *p_crypt = NULL;
	size_t passphrase_size;
	const char *passphrase = NULL;
	int unlocked_keyslot, r = -EINVAL;
	key_serial_t kid1 = 0, kid2 = 0;
	struct luks2_hdr *hdr = &cd->u.luks2.hdr;

	if (!cd || !kc)
		return -EINVAL;

	log_dbg(cd, "%s volume %s [keyslot %d] using %s.",
		name ? "Activating" : "Checking", name ?: "passphrase", keyslot, keyslot_context_type_string(kc));
	if (!name && (flags & CRYPT_ACTIVATE_REFRESH))
		return -EINVAL;
	if ((flags & CRYPT_ACTIVATE_KEYRING_KEY) && !crypt_use_keyring_for_vk(cd))
		return -EINVAL;
	if ((flags & CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY) && name)
		return -EINVAL;
	if (!additional_kc && (additional_keyslot != CRYPT_ANY_SLOT))
		return -EINVAL;
	if ((kc->type == CRYPT_KC_TYPE_KEYRING) && !kernel_keyring_support()) {
		log_err(cd, _("Kernel keyring is not supported by the kernel."));
		return -EINVAL;
	}
	if ((kc->type == CRYPT_KC_TYPE_SIGNED_KEY) && !kernel_keyring_support()) {
		log_err(cd, _("Kernel keyring missing: required for passing signature to kernel."));
		return -EINVAL;
	}
	r = _check_header_data_overlap(cd, name);
	if (r < 0)
		return r;
	r = _activate_check_status(cd, name, flags & CRYPT_ACTIVATE_REFRESH);
	if (r < 0)
		return r;

	if (kc->get_passphrase && kc->type != CRYPT_KC_TYPE_TOKEN &&
	    isLOOPAES(cd->type)) {
		r = kc->get_passphrase(cd, kc, &passphrase, &passphrase_size);
		if (r < 0)
			return r;

		return _activate_loopaes(cd, name, passphrase, passphrase_size, flags);
	}

	/* acquire the volume key(s) */
	r = -EINVAL;
	if (isLUKS1(cd->type)) {
		if (kc->get_luks1_volume_key)
			r = kc->get_luks1_volume_key(cd, kc, keyslot, &vk);
	} else if (isLUKS2(cd->type)) {
		if (flags & CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY) {
			if (kc->get_luks2_key)
				r = kc->get_luks2_key(cd, kc, keyslot, CRYPT_ANY_SEGMENT, &vk);
		} else {
			switch (LUKS2_reencrypt_status(hdr)) {
			case CRYPT_REENCRYPT_NONE:
				if (kc->get_luks2_volume_key)
					r = kc->get_luks2_volume_key(cd, kc, keyslot, &vk);
				break;
			case CRYPT_REENCRYPT_CLEAN: /* fall-through */
			case CRYPT_REENCRYPT_CRASH:
				luks2_reencryption = true;
				r = LUKS2_keyslot_context_open_all_segments(cd, keyslot, additional_keyslot, kc, additional_kc, &vk);
				/* fall-through */
			default:
				break;
			}
		}
	} else if (isTCRYPT(cd->type)) {
		r = 0;
	} else if (name && isPLAIN(cd->type)) {
		if (kc->type == CRYPT_KC_TYPE_VK_KEYRING) {
			vk = crypt_alloc_volume_key(cd->u.plain.key_size, NULL);
			if (!vk)
				return -ENOMEM;
			r = crypt_volume_key_set_description_by_name(vk, kc->u.vk_kr.key_description);
			if (r < 0)
				log_err(cd, _("Cannot use keyring key %s."), kc->u.vk_kr.key_description);
		} else if (kc->get_passphrase && kc->type != CRYPT_KC_TYPE_TOKEN) {
			r = kc->get_passphrase(cd, kc, &passphrase, &passphrase_size);
			if (r < 0)
				return r;
			r = process_key(cd, cd->u.plain.hdr.hash,
					cd->u.plain.key_size,
					passphrase, passphrase_size, &vk);
		} else if (kc->get_plain_volume_key)
			r = kc->get_plain_volume_key(cd, kc, &vk);
	} else if (isBITLK(cd->type)) {
		if (kc->get_bitlk_volume_key && (name || kc->type != CRYPT_KC_TYPE_KEY))
			r = kc->get_bitlk_volume_key(cd, kc, &cd->u.bitlk.params, &vk);
	} else if (isFVAULT2(cd->type)) {
		if (kc->get_fvault2_volume_key)
			r = kc->get_fvault2_volume_key(cd, kc, &cd->u.fvault2.params, &vk);
	} else if (isVERITY(cd->type) && (name || kc->type != CRYPT_KC_TYPE_SIGNED_KEY)) {
		if (kc->get_verity_volume_key)
			r = kc->get_verity_volume_key(cd, kc, &vk, &vk_sign);
		if (r >= 0)
			r = VERITY_verify_params(cd, &cd->u.verity.hdr, vk_sign != NULL,
						 cd->u.verity.fec_device, vk);

		free(CONST_CAST(void*)cd->u.verity.root_hash);
		cd->u.verity.root_hash = NULL;
		flags |= CRYPT_ACTIVATE_READONLY;
	} else if (isINTEGRITY(cd->type)) {
		if (kc->get_integrity_volume_key)
			r = kc->get_integrity_volume_key(cd, kc, &vk);
	}
	if (r < 0 && (r != -ENOENT || kc->type == CRYPT_KC_TYPE_TOKEN))
		goto out;
	unlocked_keyslot = r;

	if (r == -ENOENT && isLUKS(cd->type) && cd->volume_key) {
		vk = crypt_alloc_volume_key(crypt_volume_key_length(cd->volume_key),
					    crypt_volume_key_get_key(cd->volume_key));
		r = vk ? 0 : -ENOMEM;
	}
	if (r == -ENOENT && isINTEGRITY(cd->type))
		r = 0;

	if (r < 0)
		goto out;

	if (luks2_reencryption)
		r = _verify_reencrypt_keys(cd, vk);
	else
		r = _verify_key(cd, flags & CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY, vk);

	if (r < 0)
		goto out;

	if (isLUKS2(cd->type)) {
		/* split the key only if we do activation */
		if (name && LUKS2_segment_is_hw_opal(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT)) {
			r = LUKS2_split_crypt_and_opal_keys(cd, &cd->u.luks2.hdr,
							    vk, &crypt_key,
							    &opal_key);
			if (r < 0)
				goto out;

			/* copy volume key digest id in crypt subkey */
			crypt_volume_key_set_id(crypt_key, crypt_volume_key_get_id(vk));

			p_crypt = crypt_key;
			p_ext_key = opal_key ?: vk;
		} else {
			p_crypt = vk;
			p_ext_key = NULL;
		}

		if (!crypt_use_keyring_for_vk(cd))
			use_keyring = false;
		else
			/* Force keyring use for activation of LUKS2 device in reencryption */
			use_keyring = (name && (luks2_reencryption || !crypt_is_cipher_null(crypt_get_cipher(cd)))) ||
				      (flags & CRYPT_ACTIVATE_KEYRING_KEY);

		if (use_keyring) {
			/* upload dm-crypt part of volume key in thread keyring if requested */
			if (p_crypt) {
				r = load_all_keys(cd, p_crypt);
				if (r < 0)
					goto out;
				flags |= CRYPT_ACTIVATE_KEYRING_KEY;
			}

			/* upload the volume key in custom user keyring if requested */
			if (cd->link_vk_to_keyring) {
				r = crypt_volume_key_load_in_custom_keyring(cd, vk, &kid1, &kid2);
				if (r < 0) {
					log_err(cd, _("Failed to link volume key in user defined keyring."));
					goto out;
				}
			}
		}
	} else {
		p_crypt = vk;
		p_ext_key = vk_sign;
	}

	if (name)
		r = _activate_by_volume_key(cd, name, p_crypt, p_ext_key, flags);

	if (r >= 0 && unlocked_keyslot >= 0)
		r = unlocked_keyslot;
out:
	if (r < 0) {
		crypt_drop_uploaded_keyring_key(cd, vk);
		crypt_drop_uploaded_keyring_key(cd, crypt_key);
		if (cd->link_vk_to_keyring && kid1)
			crypt_unlink_key_from_custom_keyring(cd, kid1);
		if (cd->link_vk_to_keyring && kid2)
			crypt_unlink_key_from_custom_keyring(cd, kid2);
	}

	crypt_free_volume_key(vk);
	crypt_free_volume_key(crypt_key);
	crypt_free_volume_key(opal_key);
	crypt_free_volume_key(vk_sign);
	return r;
}

int crypt_activate_by_passphrase(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	int r;
	struct crypt_keyslot_context kc = {};

	crypt_keyslot_context_init_by_passphrase_internal(&kc, passphrase, passphrase_size);
	r = crypt_activate_by_keyslot_context(cd, name, keyslot, &kc, CRYPT_ANY_SLOT, &kc, flags);
	crypt_keyslot_context_destroy_internal(&kc);

	return r;
}

int crypt_activate_by_keyfile_device_offset(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	uint32_t flags)
{
	int r;
	struct crypt_keyslot_context kc = {};

	crypt_keyslot_context_init_by_keyfile_internal(&kc, keyfile, keyfile_size, keyfile_offset);
	r = crypt_activate_by_keyslot_context(cd, name, keyslot, &kc, CRYPT_ANY_SLOT, &kc, flags);
	crypt_keyslot_context_destroy_internal(&kc);

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
	int r;
	struct crypt_keyslot_context kc = {};

	crypt_keyslot_context_init_by_key_internal(&kc, volume_key, volume_key_size);
	r = crypt_activate_by_keyslot_context(cd, name, CRYPT_ANY_SLOT /* unused */, &kc, CRYPT_ANY_SLOT, &kc, flags);
	crypt_keyslot_context_destroy_internal(&kc);

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
	int r;
	struct crypt_keyslot_context kc = {};

	if (!cd || !isVERITY(cd->type))
		return -EINVAL;

	if (!volume_key || !volume_key_size || (!name && signature)) {
		log_err(cd, _("Incorrect root hash specified for verity device."));
		return -EINVAL;
	}

	if (signature)
		crypt_keyslot_context_init_by_signed_key_internal(&kc, volume_key, volume_key_size,
			signature, signature_size);
	else
		crypt_keyslot_context_init_by_key_internal(&kc, volume_key, volume_key_size);
	r = crypt_activate_by_keyslot_context(cd, name, -2 /* unused */, &kc, CRYPT_ANY_SLOT, NULL, flags);
	crypt_keyslot_context_destroy_internal(&kc);

	return r;
}

int crypt_deactivate_by_name(struct crypt_device *cd, const char *name, uint32_t flags)
{
	struct crypt_device *fake_cd = NULL;
	struct luks2_hdr *hdr2 = NULL;
	struct crypt_dm_active_device dmd = {};
	int r;
	uint64_t get_flags = DM_ACTIVE_DEVICE | DM_ACTIVE_UUID | DM_ACTIVE_HOLDERS;

	if (!name)
		return -EINVAL;

	if ((flags & CRYPT_DEACTIVATE_DEFERRED) && (flags & CRYPT_DEACTIVATE_DEFERRED_CANCEL))
		return -EINVAL;

	log_dbg(cd, "Deactivating volume %s.", name);

	if (!cd) {
		r = crypt_init_by_name(&fake_cd, name);
		if (r < 0)
			return r;
		cd = fake_cd;
	}

	if (flags & (CRYPT_DEACTIVATE_DEFERRED | CRYPT_DEACTIVATE_DEFERRED_CANCEL)) {
		r = crypt_get_hw_encryption_type(cd);
		if (r == CRYPT_SW_AND_OPAL_HW || r == CRYPT_OPAL_HW_ONLY) {
			log_err(cd, _("OPAL does not support deferred deactivation."));
			return -EINVAL;
		}
	}

	/* skip holders detection and early abort when some flags raised */
	if (flags & (CRYPT_DEACTIVATE_FORCE | CRYPT_DEACTIVATE_DEFERRED | CRYPT_DEACTIVATE_DEFERRED_CANCEL))
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

			/* For detached header case or missing metadata we need to check for OPAL2 devices
			 * from DM UUID */
			if (dmd.uuid && (flags & (CRYPT_DEACTIVATE_DEFERRED | CRYPT_DEACTIVATE_DEFERRED_CANCEL)) &&
			    !strncmp(CRYPT_LUKS2_HW_OPAL, dmd.uuid, sizeof(CRYPT_LUKS2_HW_OPAL)-1)) {
				log_err(cd, _("OPAL does not support deferred deactivation."));
				r = -EINVAL;
				break;
			}

			if (flags & CRYPT_DEACTIVATE_DEFERRED_CANCEL) {
				r = dm_cancel_deferred_removal(name);
				if (r < 0)
					log_err(cd, _("Could not cancel deferred remove from device %s."), name);
				break;
			}

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
	char *iname = NULL;
	struct dm_target *tgt = &dmd.segment;
	uint64_t min_offset = UINT64_MAX;

	if (!cd || !name || !cad)
		return -EINVAL;

	r = dm_query_device(cd, name, DM_ACTIVE_DEVICE, &dmd);
	if (r < 0)
		return r;

	/* For LUKS2 with integrity we need flags from underlying dm-integrity */
	if (isLUKS2(cd->type) && crypt_get_integrity_tag_size(cd) &&
		(iname = dm_get_active_iname(cd, name))) {
		if (dm_query_device(cd, iname, 0, &dmdi) >= 0)
			dmd.flags |= dmdi.flags;
		free(iname);
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

	/* LUKS2 / dm-crypt does not provide this count. */
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
	int r;
	struct crypt_keyslot_context kc = {};

	if (!passphrase)
		return crypt_volume_key_get_by_keyslot_context(cd, keyslot, volume_key, volume_key_size, NULL);

	crypt_keyslot_context_init_by_passphrase_internal(&kc, passphrase, passphrase_size);

	r = crypt_volume_key_get_by_keyslot_context(cd, keyslot, volume_key, volume_key_size, &kc);

	crypt_keyslot_context_destroy_internal(&kc);

	return r;
}

int crypt_volume_key_get_by_keyslot_context(struct crypt_device *cd,
	int keyslot,
	char *volume_key,
	size_t *volume_key_size,
	struct crypt_keyslot_context *kc)
{
	size_t passphrase_size;
	int key_len, r;
	const char *passphrase = NULL;
	struct volume_key *vk = NULL;

	if (!cd || !volume_key || !volume_key_size ||
	    (!kc && !isLUKS(cd->type) && !isTCRYPT(cd->type) && !isVERITY(cd->type) && !isBITLK(cd->type)))
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

	if (kc && (!kc->get_passphrase || kc->type == CRYPT_KC_TYPE_KEY))
		return -EINVAL;

	r = -EINVAL;

	if (isLUKS2(cd->type)) {
		if (kc && !kc->get_luks2_key)
			log_err(cd, _("Cannot retrieve volume key for LUKS2 device."));
		else if (!kc)
			r = -ENOENT;
		else
			r = kc->get_luks2_key(cd, kc, keyslot,
					keyslot == CRYPT_ANY_SLOT ? CRYPT_DEFAULT_SEGMENT : CRYPT_ANY_SEGMENT,
					&vk);
	} else if (isLUKS1(cd->type)) {
		if (kc && !kc->get_luks1_volume_key)
			log_err(cd, _("Cannot retrieve volume key for LUKS1 device."));
		else if (!kc)
			r = -ENOENT;
		else
			r = kc->get_luks1_volume_key(cd, kc, keyslot, &vk);
	} else if (isPLAIN(cd->type) && cd->u.plain.hdr.hash) {
		if (kc && kc->get_passphrase && kc->type != CRYPT_KC_TYPE_TOKEN) {
			r = kc->get_passphrase(cd, kc, &passphrase, &passphrase_size);
			if (r < 0)
				return r;
			r = process_key(cd, cd->u.plain.hdr.hash, key_len,
					passphrase, passphrase_size, &vk);
		}
		if (r < 0)
			log_err(cd, _("Cannot retrieve volume key for plain device."));
	} else if (isVERITY(cd->type)) {
		/* volume_key == root hash */
		if (cd->u.verity.root_hash) {
			crypt_safe_memcpy(volume_key, cd->u.verity.root_hash, cd->u.verity.root_hash_size);
			*volume_key_size = cd->u.verity.root_hash_size;
			r = 0;
		} else
			log_err(cd, _("Cannot retrieve root hash for verity device."));
	} else if (isTCRYPT(cd->type)) {
		r = TCRYPT_get_volume_key(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params, &vk);
	} else if (isBITLK(cd->type)) {
		if (kc && kc->get_bitlk_volume_key)
			r = kc->get_bitlk_volume_key(cd, kc, &cd->u.bitlk.params, &vk);
		else if (!kc)
			r = BITLK_get_volume_key(cd, NULL, 0, &cd->u.bitlk.params, &vk);
		if (r < 0)
			log_err(cd, _("Cannot retrieve volume key for BITLK device."));
	} else if (isFVAULT2(cd->type)) {
		if (kc && kc->get_fvault2_volume_key)
			r = kc->get_fvault2_volume_key(cd, kc, &cd->u.fvault2.params, &vk);
		if (r < 0)
			log_err(cd, _("Cannot retrieve volume key for FVAULT2 device."));
	} else
		log_err(cd, _("This operation is not supported for %s crypt device."), cd->type ?: "(none)");

	if (r == -ENOENT && isLUKS(cd->type) && cd->volume_key) {
		vk = crypt_alloc_volume_key(crypt_volume_key_length(cd->volume_key),
					    crypt_volume_key_get_key(cd->volume_key));
		r = vk ? 0 : -ENOMEM;
	}

	if (r >= 0 && vk) {
		crypt_safe_memcpy(volume_key, crypt_volume_key_get_key(vk), crypt_volume_key_length(vk));
		*volume_key_size = crypt_volume_key_length(vk);
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

	if ((r = onlyLUKSunrestricted(cd)))
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
	UNUSED(cd);
	UNUSED(lock);

	return 0;
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
	crypt_log_hex(cd, cd->u.luks1.hdr.mkDigest, LUKS_DIGESTSIZE, " ", 0, NULL);
	log_std(cd, "\n");
	log_std(cd, "MK salt:       \t");
	crypt_log_hex(cd, cd->u.luks1.hdr.mkDigestSalt, LUKS_SALTSIZE/2, " ", 0, NULL);
	log_std(cd, "\n               \t");
	crypt_log_hex(cd, cd->u.luks1.hdr.mkDigestSalt+LUKS_SALTSIZE/2, LUKS_SALTSIZE/2, " ", 0, NULL);
	log_std(cd, "\n");
	log_std(cd, "MK iterations: \t%" PRIu32 "\n", cd->u.luks1.hdr.mkDigestIterations);
	log_std(cd, "UUID:          \t%s\n\n", cd->u.luks1.hdr.uuid);
	for(i = 0; i < LUKS_NUMKEYS; i++) {
		if(cd->u.luks1.hdr.keyblock[i].active == LUKS_KEY_ENABLED) {
			log_std(cd, "Key Slot %d: ENABLED\n",i);
			log_std(cd, "\tIterations:         \t%" PRIu32 "\n",
				cd->u.luks1.hdr.keyblock[i].passwordIterations);
			log_std(cd, "\tSalt:               \t");
			crypt_log_hex(cd, cd->u.luks1.hdr.keyblock[i].passwordSalt,
				 LUKS_SALTSIZE/2, " ", 0, NULL);
			log_std(cd, "\n\t                      \t");
			crypt_log_hex(cd, cd->u.luks1.hdr.keyblock[i].passwordSalt +
				 LUKS_SALTSIZE/2, LUKS_SALTSIZE/2, " ", 0, NULL);
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

int crypt_dump(struct crypt_device *cd)
{
	if (!cd)
		return -EINVAL;
	if (isLUKS1(cd->type))
		return _luks_dump(cd);
	else if (isLUKS2(cd->type))
		return LUKS2_hdr_dump(cd, &cd->u.luks2.hdr);
	else if (isVERITY(cd->type))
		return VERITY_dump(cd, &cd->u.verity.hdr,
				   cd->u.verity.root_hash, cd->u.verity.root_hash_size,
				   cd->u.verity.fec_device);
	else if (isTCRYPT(cd->type))
		return TCRYPT_dump(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);
	else if (isINTEGRITY(cd->type))
		return INTEGRITY_dump(cd, crypt_data_device(cd), 0);
	else if (isBITLK(cd->type))
		return BITLK_dump(cd, crypt_data_device(cd), &cd->u.bitlk.params);
	else if (isFVAULT2(cd->type))
		return FVAULT2_dump(cd, crypt_data_device(cd), &cd->u.fvault2.params);

	log_err(cd, _("Dump operation is not supported for this device type."));
	return -EINVAL;
}

int crypt_dump_json(struct crypt_device *cd, const char **json, uint32_t flags)
{
	if (!cd || flags)
		return -EINVAL;
	if (isLUKS2(cd->type))
		return LUKS2_hdr_dump_json(cd, &cd->u.luks2.hdr, json);

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

	if (isFVAULT2(cd->type))
		return cd->u.fvault2.params.cipher;

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

	if (isFVAULT2(cd->type))
		return cd->u.fvault2.params.cipher_mode;

	if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.cipher_mode;

	return NULL;
}

/* INTERNAL only */
const char *crypt_get_integrity(struct crypt_device *cd)
{
	if (!cd)
		return NULL;

	if (isINTEGRITY(cd->type))
		return cd->u.integrity.params.integrity;

	if (isLUKS2(cd->type))
		return LUKS2_get_integrity(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);

	if (!cd->type && *cd->u.none.integrity_spec)
		return cd->u.none.integrity_spec;

	return NULL;
}

/* INTERNAL only */
int crypt_get_integrity_key_size(struct crypt_device *cd, bool dm_compat)
{
	int key_size = 0;

	if (isLUKS2(cd->type)) {
		key_size = INTEGRITY_key_size(crypt_get_integrity(cd),
					      LUKS2_get_integrity_key_size(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT));
		if (dm_compat && key_size > 0 &&
		    key_size == INTEGRITY_key_size(crypt_get_integrity(cd), 0))
			return 0;
	}

	if (isINTEGRITY(cd->type) || !cd->type)
		key_size = INTEGRITY_key_size(crypt_get_integrity(cd),  0);

	return key_size > 0 ? key_size : 0;
}

/* INTERNAL only */
int crypt_get_integrity_tag_size(struct crypt_device *cd)
{
	if (isINTEGRITY(cd->type))
		return cd->u.integrity.params.tag_size;

	if (isLUKS2(cd->type) || !cd->type)
		return INTEGRITY_tag_size(crypt_get_integrity(cd),
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

	if (!cd->type && cd->u.none.sector_size)
		return cd->u.none.sector_size;

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

	if (isFVAULT2(cd->type))
		return cd->u.fvault2.params.family_uuid;

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
			r = crypt_volume_key_length(cd->volume_key);
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

	if (isFVAULT2(cd->type))
		return cd->u.fvault2.params.key_size;

	if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.key_size;

	return 0;
}

int crypt_get_old_volume_key_size(struct crypt_device *cd)
{
	int r = _onlyLUKS2(cd, CRYPT_CD_QUIET,
			   CRYPT_REQUIREMENT_ONLINE_REENCRYPT | CRYPT_REQUIREMENT_OPAL);

	if (r < 0)
		return 0;

	r = LUKS2_get_old_volume_key_size(&cd->u.luks2.hdr);

	return r < 0 ? 0 : r;
}

int crypt_get_hw_encryption_key_size(struct crypt_device *cd)
{
	if (!cd || !isLUKS2(cd->type))
		return 0;

	return LUKS2_get_opal_key_size(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);
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

	if (!cd || !cipher || !key_size || !isLUKS2(cd->type))
		return -EINVAL;

	if (LUKS2_keyslot_cipher_incompatible(cd, cipher))
		return -EINVAL;

	if (!(tmp = strdup(cipher)))
		return -ENOMEM;

	free(cd->u.luks2.keyslot_cipher);
	cd->u.luks2.keyslot_cipher = tmp;
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

	if (LUKS2_segment_is_hw_opal(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT)) {
		/* Fallback to default LUKS2 keyslot encryption */
		*key_size = DEFAULT_LUKS2_KEYSLOT_KEYBITS / 8;
		return DEFAULT_LUKS2_KEYSLOT_CIPHER;
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
		msize = LUKS2_metadata_size(&cd->u.luks2.hdr);
		ksize = LUKS2_keyslots_size(&cd->u.luks2.hdr);
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

	if (isFVAULT2(cd->type))
		return cd->u.fvault2.params.log_vol_off / SECTOR_SIZE;

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
	if (_onlyLUKS(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED, 0) < 0)
		return CRYPT_SLOT_INVALID;

	if (isLUKS1(cd->type))
		return LUKS_keyslot_info(&cd->u.luks1.hdr, keyslot);
	else if(isLUKS2(cd->type))
		return LUKS2_keyslot_info(&cd->u.luks2.hdr, keyslot);

	return CRYPT_SLOT_INVALID;
}

int crypt_keyslot_max(const char *type)
{
	if (isLUKS1(type))
		return LUKS_NUMKEYS;

	if (isLUKS2(type))
		return LUKS2_KEYSLOTS_MAX;

	return -EINVAL;
}

int crypt_keyslot_area(struct crypt_device *cd,
	int keyslot,
	uint64_t *offset,
	uint64_t *length)
{
	if (_onlyLUKS(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED, 0) || !offset || !length)
		return -EINVAL;

	if (isLUKS2(cd->type))
		return LUKS2_keyslot_area(&cd->u.luks2.hdr, keyslot, offset, length);

	return LUKS_keyslot_area(&cd->u.luks1.hdr, keyslot, offset, length);
}

crypt_keyslot_priority crypt_keyslot_get_priority(struct crypt_device *cd, int keyslot)
{
	if (_onlyLUKS(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED, 0))
		return CRYPT_SLOT_PRIORITY_INVALID;

	if (keyslot < 0 || keyslot >= crypt_keyslot_max(cd->type))
		return CRYPT_SLOT_PRIORITY_INVALID;

	if (isLUKS2(cd->type))
		return LUKS2_keyslot_priority_get(&cd->u.luks2.hdr, keyslot);

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

int crypt_get_hw_encryption_type(struct crypt_device *cd)
{
	if (!cd)
		return -EINVAL;

	if (isLUKS2(cd->type)) {
		if (LUKS2_segment_is_hw_opal_crypt(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT))
			return CRYPT_SW_AND_OPAL_HW;
		else if (LUKS2_segment_is_hw_opal_only(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT))
			return CRYPT_OPAL_HW_ONLY;
	}

	return CRYPT_SW_ONLY;
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

int crypt_get_verity_repaired(struct crypt_device *cd, const char *name,
			      uint64_t *repaired)

{
	if (!cd || !isVERITY(cd->type) || !name || !repaired)
		return -EINVAL;

	return dm_status_verity_repaired(cd, name, repaired);
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
		ip->integrity_key_size = crypt_get_integrity_key_size(cd, false);

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
		ip->integrity_key_size = crypt_get_integrity_key_size(cd, false);
		ip->tag_size = INTEGRITY_tag_size(ip->integrity, crypt_get_cipher(cd), crypt_get_cipher_mode(cd));

		ip->journal_integrity = NULL;
		ip->journal_integrity_key_size = 0;
		ip->journal_integrity_key = NULL;

		ip->journal_crypt = NULL;
		ip->journal_crypt_key_size = 0;
		ip->journal_crypt_key = NULL;
		return 0;
	} else if (!cd->type) {
		memset(ip, 0, sizeof(*ip));
		ip->integrity = crypt_get_integrity(cd);
		ip->integrity_key_size = crypt_get_integrity_key_size(cd, false);
		ip->tag_size = crypt_get_integrity_tag_size(cd);
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

	if ((r = onlyLUKSnoRequirements(cd)))
		return r;

	if (isLUKS1(cd->type) && isLUKS2(type))
		r = LUKS2_luks1_to_luks2(cd, &cd->u.luks1.hdr, &hdr2);
	else if (isLUKS2(cd->type) && isLUKS1(type))
		r = LUKS2_luks2_to_luks1(cd, &cd->u.luks2.hdr, &hdr1);
	else
		return -EINVAL;

	if (r < 0) {
		/* in-memory header may be invalid after failed conversion */
		_luks2_rollback(cd);
		if (r == -EBUSY)
			log_err(cd, _("Cannot convert device %s which is still in use."), mdata_device_path(cd));
		return r;
	}

	crypt_free_type(cd, NULL);

	return crypt_load(cd, type, params);
}

/* Internal access function to header pointer */
void *crypt_get_hdr(struct crypt_device *cd, const char *type)
{
	assert(cd);
	assert(type);

	/* If requested type differs, ignore it */
	if (!cd->type || strcmp(cd->type, type))
		return NULL;

	if (isPLAIN(cd->type))
		return &cd->u.plain;

	if (isLUKS1(cd->type))
		return &cd->u.luks1.hdr;

	if (isLUKS2(type))
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
struct luks2_reencrypt *crypt_get_luks2_reencrypt(struct crypt_device *cd)
{
	return cd->u.luks2.rh;
}

/* internal only */
void crypt_set_luks2_reencrypt(struct crypt_device *cd, struct luks2_reencrypt *rh)
{
	cd->u.luks2.rh = rh;
}

/*
 * Token handling
 */
int crypt_activate_by_token_pin(struct crypt_device *cd, const char *name,
	const char *type, int token, const char *pin, size_t pin_size,
	void *usrptr, uint32_t flags)
{
	int r;
	struct crypt_keyslot_context kc = {};

	crypt_keyslot_context_init_by_token_internal(&kc, token, type, pin, pin_size, usrptr);
	r = crypt_activate_by_keyslot_context(cd, name, CRYPT_ANY_SLOT, &kc, CRYPT_ANY_SLOT, &kc, flags);
	crypt_keyslot_context_destroy_internal(&kc);

	return r;
}

int crypt_activate_by_token(struct crypt_device *cd,
	const char *name, int token, void *usrptr, uint32_t flags)
{
	return crypt_activate_by_token_pin(cd, name, NULL, token, NULL, 0, usrptr, flags);
}

int crypt_token_json_get(struct crypt_device *cd, int token, const char **json)
{
	int r;

	if (!json)
		return -EINVAL;

	log_dbg(cd, "Requesting JSON for token %d.", token);

	if ((r = onlyLUKS2unrestricted(cd)))
		return r;

	return LUKS2_token_json_get(&cd->u.luks2.hdr, token, json) ?: token;
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

int crypt_token_max(const char *type)
{
	if (isLUKS2(type))
		return LUKS2_TOKENS_MAX;

	return -EINVAL;
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

	if ((r = onlyLUKS2unrestricted(cd)))
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

	return LUKS2_token_keyring_get(&cd->u.luks2.hdr, token, params);
}

int crypt_token_luks2_keyring_set(struct crypt_device *cd,
	int token,
	const struct crypt_token_params_luks2_keyring *params)
{
	int r;
	char json[4096];

	if (!params || !params->key_description)
		return -EINVAL;

	log_dbg(cd, "Creating new LUKS2 keyring token (%d).", token);

	if ((r = onlyLUKS2(cd)))
		return r;

	r = LUKS2_token_keyring_json(json, sizeof(json), params);
	if (r < 0)
		return r;

	return LUKS2_token_create(cd, &cd->u.luks2.hdr, token, json, 1);
}

int crypt_token_assign_keyslot(struct crypt_device *cd, int token, int keyslot)
{
	int r;

	if ((r = onlyLUKS2(cd)))
		return r;

	if (token == CRYPT_ANY_TOKEN)
		return -EINVAL;

	return LUKS2_token_assign(cd, &cd->u.luks2.hdr, keyslot, token, 1, 1);
}

int crypt_token_unassign_keyslot(struct crypt_device *cd, int token, int keyslot)
{
	int r;

	if ((r = onlyLUKS2(cd)))
		return r;

	if (token == CRYPT_ANY_TOKEN)
		return -EINVAL;

	return LUKS2_token_assign(cd, &cd->u.luks2.hdr, keyslot, token, 0, 1);
}

int crypt_token_is_assigned(struct crypt_device *cd, int token, int keyslot)
{
	int r;

	if ((r = _onlyLUKS2(cd, CRYPT_CD_QUIET | CRYPT_CD_UNRESTRICTED, 0)))
		return r;

	return LUKS2_token_is_assigned(&cd->u.luks2.hdr, keyslot, token);
}

/* Internal only */
int crypt_metadata_locking_enabled(void)
{
	return _metadata_locking;
}

int crypt_metadata_locking(struct crypt_device *cd __attribute__((unused)), int enable)
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

	if ((r = onlyLUKS2unrestricted(cd)))
		return r;

	if (type == CRYPT_FLAGS_ACTIVATION)
		return LUKS2_config_get_flags(cd, &cd->u.luks2.hdr, flags);

	if (type == CRYPT_FLAGS_REQUIREMENTS) {
		LUKS2_config_get_requirements(cd, &cd->u.luks2.hdr, flags);
		return 0;
	}

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
		struct luks2_hdr *hdr, int keyslot, struct crypt_keyslot_context *kc)
{
	int digest, r;
	struct volume_key *vk = NULL;

	assert(kc);
	assert(kc->get_luks2_key);
	assert(keyslot >= 0);

	r = kc->get_luks2_key(cd, kc, keyslot, CRYPT_ANY_SEGMENT, &vk);
	if (r < 0)
		return r;

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

static int luks2_keyslot_add_by_verified_volume_key(struct crypt_device *cd,
	int keyslot_new,
	const char *new_passphrase,
	size_t new_passphrase_size,
	struct volume_key *vk)
{
	int r;
	struct luks2_keyslot_params params;

	assert(cd);
	assert(keyslot_new >= 0);
	assert(new_passphrase);
	assert(vk);
	assert(crypt_volume_key_get_id(vk) >= 0);

	r = LUKS2_keyslot_params_default(cd, &cd->u.luks2.hdr, &params);
	if (r < 0) {
		log_err(cd, _("Failed to initialize default LUKS2 keyslot parameters."));
		return r;
	}

	r = LUKS2_digest_assign(cd, &cd->u.luks2.hdr, keyslot_new, crypt_volume_key_get_id(vk), 1, 0);
	if (r < 0) {
		log_err(cd, _("Failed to assign keyslot %d to digest."), keyslot_new);
		return r;
	}

	r = LUKS2_keyslot_store(cd,  &cd->u.luks2.hdr, keyslot_new,
				CONST_CAST(char*)new_passphrase,
				new_passphrase_size, vk, &params);

	return r < 0 ? r : keyslot_new;
}

static int luks2_keyslot_add_by_volume_key(struct crypt_device *cd,
	int keyslot_new,
	const char *new_passphrase,
	size_t new_passphrase_size,
	struct volume_key *vk)
{
	int r;

	assert(cd);
	assert(keyslot_new >= 0);
	assert(new_passphrase);
	assert(vk);

	r = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
	if (r >= 0)
		crypt_volume_key_set_id(vk, r);

	if (r < 0) {
		log_err(cd, _("Volume key does not match the volume."));
		return r;
	}

	return luks2_keyslot_add_by_verified_volume_key(cd, keyslot_new, new_passphrase, new_passphrase_size, vk);
}

static int luks1_keyslot_add_by_volume_key(struct crypt_device *cd,
	int keyslot_new,
	const char *new_passphrase,
	size_t new_passphrase_size,
	struct volume_key *vk)
{
	int r;

	assert(cd);
	assert(keyslot_new >= 0);
	assert(new_passphrase);
	assert(vk);

	r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);
	if (r < 0) {
		log_err(cd, _("Volume key does not match the volume."));
		return r;
	}

	r = LUKS_set_key(keyslot_new, CONST_CAST(char*)new_passphrase,
			 new_passphrase_size, &cd->u.luks1.hdr, vk, cd);

	return r < 0 ? r : keyslot_new;
}

static int keyslot_add_by_key(struct crypt_device *cd,
	bool is_luks1,
	int keyslot_new,
	const char *new_passphrase,
	size_t new_passphrase_size,
	struct volume_key *vk,
	uint32_t flags)
{
	int r, digest;

	assert(cd);
	assert(keyslot_new >= 0);
	assert(new_passphrase);
	assert(vk);

	if (!flags)
		return is_luks1 ? luks1_keyslot_add_by_volume_key(cd, keyslot_new, new_passphrase, new_passphrase_size, vk) :
				  luks2_keyslot_add_by_volume_key(cd, keyslot_new, new_passphrase, new_passphrase_size, vk);

	if (is_luks1)
		return -EINVAL;

	digest = LUKS2_digest_verify_by_segment(cd, &cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT, vk);
	if (digest >= 0) /* if key matches volume key digest tear down new vk flag */
		flags &= ~CRYPT_VOLUME_KEY_SET;
	else if (digest == -EPERM) {
		/* if key matches any existing digest, do not create new digest */
		if ((flags & CRYPT_VOLUME_KEY_DIGEST_REUSE))
			digest = LUKS2_digest_verify_by_any_matching(cd, vk);

		/* Anything other than -EPERM or -ENOENT suggests broken metadata. Abort */
		if (digest < 0 && digest != -ENOENT && digest != -EPERM)
			return digest;

		/* no segment flag or new vk flag requires new key digest */
		if (flags & (CRYPT_VOLUME_KEY_NO_SEGMENT | CRYPT_VOLUME_KEY_SET)) {
			if (digest < 0 || !(flags & CRYPT_VOLUME_KEY_DIGEST_REUSE))
				digest = LUKS2_digest_create(cd, "pbkdf2", &cd->u.luks2.hdr, vk);
		}
	} else /* Anything other than -EPERM suggests broken metadata. Abort */
		return digest;

	r = digest;
	if (r < 0) {
		log_err(cd, _("Volume key does not match the volume."));
		return r;
	}

	crypt_volume_key_set_id(vk, digest);

	if (flags & CRYPT_VOLUME_KEY_SET) {
		r = update_volume_key_segment_digest(cd, &cd->u.luks2.hdr, digest, 0);
		if (r < 0)
			log_err(cd, _("Failed to assign keyslot %u as the new volume key."), keyslot_new);
	}

	if (r >= 0)
		r = luks2_keyslot_add_by_verified_volume_key(cd, keyslot_new, new_passphrase, new_passphrase_size, vk);

	return r < 0 ? r : keyslot_new;
}

int crypt_keyslot_add_by_key(struct crypt_device *cd,
	int keyslot,
	const char *volume_key,
	size_t volume_key_size,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	int r;
	struct crypt_keyslot_context kc = {}, new_kc = {};

	if (!passphrase || ((flags & CRYPT_VOLUME_KEY_NO_SEGMENT) &&
			    (flags & CRYPT_VOLUME_KEY_SET)))
		return -EINVAL;

	if ((r = onlyLUKS(cd)) < 0)
		return r;

	if ((flags & CRYPT_VOLUME_KEY_SET) && crypt_keyslot_status(cd, keyslot) > CRYPT_SLOT_INACTIVE &&
	    isLUKS2(cd->type)) {
		if (volume_key)
			crypt_keyslot_context_init_by_key_internal(&kc, volume_key, volume_key_size);
		else
			crypt_keyslot_context_init_by_passphrase_internal(&kc, passphrase, passphrase_size);

		r = verify_and_update_segment_digest(cd, &cd->u.luks2.hdr, keyslot, &kc);

		crypt_keyslot_context_destroy_internal(&kc);

		return r;
	}

	crypt_keyslot_context_init_by_key_internal(&kc, volume_key, volume_key_size);
	crypt_keyslot_context_init_by_passphrase_internal(&new_kc, passphrase, passphrase_size);

	r = crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, &kc, keyslot, &new_kc, flags);

	crypt_keyslot_context_destroy_internal(&kc);
	crypt_keyslot_context_destroy_internal(&new_kc);

	return r;
}

int crypt_keyslot_add_by_keyslot_context(struct crypt_device *cd,
	int keyslot_existing,
	struct crypt_keyslot_context *kc,
	int keyslot_new,
	struct crypt_keyslot_context *new_kc,
	uint32_t flags)
{
	bool is_luks1;
	int active_slots, r;
	const char *new_passphrase;
	size_t new_passphrase_size;
	struct volume_key *vk = NULL;

	if (!kc || ((flags & CRYPT_VOLUME_KEY_NO_SEGMENT) &&
		    (flags & CRYPT_VOLUME_KEY_SET)))
		return -EINVAL;

	r = flags ? onlyLUKS2(cd) : onlyLUKS(cd);
	if (r)
		return r;

	if ((flags & CRYPT_VOLUME_KEY_SET) && crypt_keyslot_status(cd, keyslot_existing) > CRYPT_SLOT_INACTIVE)
		return verify_and_update_segment_digest(cd, &cd->u.luks2.hdr, keyslot_existing, kc);

	if (!new_kc || !new_kc->get_passphrase)
		return -EINVAL;

	log_dbg(cd, "Adding new keyslot %d by %s%s, volume key provided by %s (%d).",
		keyslot_new, keyslot_context_type_string(new_kc),
		(flags & CRYPT_VOLUME_KEY_NO_SEGMENT) ? " unassigned to a crypt segment" : "",
		keyslot_context_type_string(kc), keyslot_existing);

	r = keyslot_verify_or_find_empty(cd, &keyslot_new);
	if (r < 0)
		return r;

	is_luks1 = isLUKS1(cd->type);
	if (is_luks1)
		active_slots = LUKS_keyslot_active_count(&cd->u.luks1.hdr);
	else
		active_slots = LUKS2_keyslot_active_count(&cd->u.luks2.hdr, CRYPT_DEFAULT_SEGMENT);

	if (active_slots < 0)
		return -EINVAL;

	if (active_slots == 0 && kc->type != CRYPT_KC_TYPE_KEY)
		r = -ENOENT;
	else if (is_luks1 && kc->get_luks1_volume_key)
		r = kc->get_luks1_volume_key(cd, kc, keyslot_existing, &vk);
	else if (!is_luks1 && kc->get_luks2_volume_key)
		r = kc->get_luks2_volume_key(cd, kc, keyslot_existing, &vk);
	else
		return -EINVAL;

	if (r == -ENOENT) {
		if ((flags & CRYPT_VOLUME_KEY_NO_SEGMENT) && kc->type == CRYPT_KC_TYPE_KEY) {
			if (!(vk = crypt_generate_volume_key(cd, kc->u.k.volume_key_size, KEY_QUALITY_KEY)))
				return -ENOMEM;
			r = 0;
		} else if (cd->volume_key) {
			if (!(vk = crypt_alloc_volume_key(crypt_volume_key_length(cd->volume_key),
							  crypt_volume_key_get_key(cd->volume_key))))
				return -ENOMEM;
			r = 0;
		} else if (active_slots == 0) {
			log_err(cd, _("Cannot add key slot, all slots disabled and no volume key provided."));
			r = -EINVAL;
		}
	}

	if (r < 0)
		return r;

	r = new_kc->get_passphrase(cd, new_kc, &new_passphrase, &new_passphrase_size);
	/* If new keyslot context is token just assign it to new keyslot */
	if (r >= 0 && new_kc->type == CRYPT_KC_TYPE_TOKEN && !is_luks1)
		r = LUKS2_token_assign(cd, &cd->u.luks2.hdr, keyslot_new, new_kc->u.t.id, 1, 0);
	if (r >= 0)
		r = keyslot_add_by_key(cd, is_luks1, keyslot_new, new_passphrase, new_passphrase_size, vk, flags);

	crypt_free_volume_key(vk);

	if (r < 0) {
		_luks2_rollback(cd);
		return r;
	}

	return keyslot_new;
}

/*
 * Keyring handling
 */
int crypt_use_keyring_for_vk(struct crypt_device *cd)
{
	uint64_t dmc_flags;

	/* dm backend must be initialized */
	if (!cd)
		return 0;

	if (!isPLAIN(cd->type) && !isLUKS2(cd->type))
		return 0;

	if (!_vk_via_keyring || !kernel_keyring_support())
		return 0;

	if (dm_flags(cd, DM_CRYPT, &dmc_flags))
		return dmcrypt_keyring_bug() ? 0 : 1;

	return (dmc_flags & DM_KERNEL_KEYRING_SUPPORTED);
}

int crypt_volume_key_keyring(struct crypt_device *cd __attribute__((unused)), int enable)
{
	_vk_via_keyring = enable ? 1 : 0;
	return 0;
}

/* internal only */
int crypt_volume_key_load_in_keyring(struct crypt_device *cd, struct volume_key *vk)
{
	if (!vk || !cd)
		return -EINVAL;

	if (!crypt_volume_key_description(vk)) {
		log_dbg(cd, "Invalid key description");
		return -EINVAL;
	}

	log_dbg(cd, "Loading key (type logon, name %s) in thread keyring.",
		crypt_volume_key_description(vk));

	if (crypt_volume_key_upload_kernel_key(vk)) {
		crypt_set_key_in_keyring(cd, 1);
		return 0;
	} else {
		log_dbg(cd, "keyring_add_key_in_thread_keyring failed (error %d)", errno);
		log_err(cd, _("Failed to load key in kernel keyring."));
		return -EINVAL;
	}
}

/* internal only */
int crypt_keyring_get_user_key(struct crypt_device *cd,
		const char *key_description,
		char **key,
		size_t *key_size)
{
	int r;
	key_serial_t kid;

	if (!key_description || !key || !key_size)
		return -EINVAL;

	log_dbg(cd, "Requesting key %s (user type)", key_description);

	kid = keyring_request_key_id(USER_KEY, key_description);
	if (kid == -ENOTSUP) {
		log_dbg(cd, "Kernel keyring features disabled.");
		return -ENOTSUP;
	} else if (kid < 0) {
		log_dbg(cd, "keyring_request_key_id failed with errno %d.", errno);
		return -EINVAL;
	}

	log_dbg(cd, "Reading content of kernel key (id %" PRIi32 ").", kid);

	r = keyring_read_key(kid, key, key_size);
	if (r < 0)
		log_dbg(cd, "keyring_read_key failed with errno %d.", errno);

	return r;
}

/* internal only */
int crypt_keyring_get_key_by_name(struct crypt_device *cd,
		const char *key_description,
		char **key,
		size_t *key_size)
{
	int r;
	key_serial_t kid;

	if (!key_description || !key || !key_size)
		return -EINVAL;

	log_dbg(cd, "Searching for kernel key by name %s.", key_description);

	kid = keyring_find_key_id_by_name(key_description);
	if (kid == 0) {
		log_dbg(cd, "keyring_find_key_id_by_name failed with errno %d.", errno);
		return -ENOENT;
	}

	log_dbg(cd, "Reading content of kernel key (id %" PRIi32 ").", kid);

	r = keyring_read_key(kid, key, key_size);
	if (r < 0)
		log_dbg(cd, "keyring_read_key failed with errno %d.", errno);

	return r;
}

int crypt_keyring_get_keysize_by_name(struct crypt_device *cd,
		const char *key_description,
		size_t *r_key_size)
{
	int r;
	key_serial_t kid;

	if (!key_description || !r_key_size)
		return -EINVAL;

	log_dbg(cd, "Searching for kernel key by name %s.", key_description);

	kid = keyring_find_key_id_by_name(key_description);
	if (kid == -ENOTSUP) {
		log_dbg(cd, "Kernel keyring features disabled.");
		return -ENOTSUP;
	} else if (kid < 0) {
		log_dbg(cd, "keyring_find_key_id_by_name failed with errno %d.", errno);
		return -EINVAL;
	}
	else if (kid == 0) {
		log_dbg(cd, "keyring_find_key_id_by_name failed with errno %d.", ENOENT);
		return -ENOENT;
	}

	log_dbg(cd, "Reading content of kernel key (id %" PRIi32 ").", kid);

	r = keyring_read_keysize(kid, r_key_size);
	if (r < 0)
		log_dbg(cd, "keyring_read_keysize failed with errno %d.", errno);

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
void crypt_unlink_key_from_thread_keyring(struct crypt_device *cd,
		key_serial_t key_id)
{
	log_dbg(cd, "Unlinking volume key (id: %" PRIi32 ") from thread keyring.", key_id);

	if (keyring_unlink_key_from_thread_keyring(key_id))
		log_dbg(cd, "keyring_unlink_key_from_thread_keyring failed with errno %d.", errno);
}

void crypt_unlink_key_by_description_from_thread_keyring(struct crypt_device *cd,
		const char *key_description,
		key_type_t ktype)
{
	key_serial_t kid;
	const char *type_name = key_type_name(ktype);

	if (!key_description || !type_name)
		return;

	log_dbg(cd, "Requesting kernel key %s (type %s).", key_description, type_name);

	crypt_set_key_in_keyring(cd, 0);

	kid = keyring_request_key_id(ktype, key_description);
	if (kid == -ENOTSUP) {
		log_dbg(cd, "Kernel keyring features disabled.");
		return;
	} else if (kid < 0) {
		log_dbg(cd, "keyring_request_key_id failed with errno %d.", errno);
		return;
	}

	crypt_unlink_key_from_thread_keyring(cd, kid);
}

int crypt_set_keyring_to_link(struct crypt_device *cd, const char *key_description,
			      const char *old_key_description,
			      const char *key_type_desc, const char *keyring_to_link_vk)
{
	key_type_t key_type = USER_KEY;
	const char *name1 = NULL, *name2 = NULL;
	int32_t id = 0;
	int r, ri;
	struct luks2_hdr *hdr;
	unsigned user_descriptions_count, vks_count = 1;

	if (!cd || ((!key_description && !old_key_description) && (keyring_to_link_vk || key_type_desc)) ||
	    ((key_description || old_key_description) && !keyring_to_link_vk))
		return -EINVAL;

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	/* if only one key description is supplied, force it to be the first one */
	if (!key_description && old_key_description)
		return -EINVAL;

	if ((r = _onlyLUKS2(cd, 0, CRYPT_REQUIREMENT_OPAL | CRYPT_REQUIREMENT_ONLINE_REENCRYPT)))
		return r;

	if (key_type_desc)
		key_type = key_type_by_name(key_type_desc);
	if (key_type != LOGON_KEY && key_type != USER_KEY)
		return -EINVAL;

	ri = crypt_reencrypt_status(cd, NULL);
	if (ri > CRYPT_REENCRYPT_NONE && ri < CRYPT_REENCRYPT_INVALID)
		vks_count = LUKS2_reencrypt_vks_count(hdr);

	user_descriptions_count = (key_description ? 1 : 0) + (old_key_description ? 1 : 0);
	if (user_descriptions_count != 0 && vks_count > user_descriptions_count)
		return -ESRCH;

	if (keyring_to_link_vk) {
		id = keyring_find_keyring_id_by_name(keyring_to_link_vk);
		if (id == 0) {
			log_err(cd, _("Could not find keyring described by \"%s\"."), keyring_to_link_vk);
			return -EINVAL;
		}
		if (key_description && !(name1 = strdup(key_description)))
			return -ENOMEM;
		if (old_key_description && !(name2 = strdup(old_key_description))) {
			free(CONST_CAST(void*)name1);
			return -ENOMEM;
		}
	}

	cd->keyring_key_type = key_type;

	free(CONST_CAST(void*)cd->user_key_name1);
	free(CONST_CAST(void*)cd->user_key_name2);
	cd->user_key_name1 = name1;
	cd->user_key_name2 = name2;
	cd->keyring_to_link_vk = id;
	cd->link_vk_to_keyring = id != 0;

	return 0;
}

/* internal only */
void crypt_drop_uploaded_keyring_key(struct crypt_device *cd, struct volume_key *vks)
{
	struct volume_key *vk = vks;

	while (vk) {
		crypt_volume_key_drop_uploaded_kernel_key(cd, vk);
		vk = crypt_volume_key_next(vk);
	}
}

int crypt_activate_by_keyring(struct crypt_device *cd,
			      const char *name,
			      const char *key_description,
			      int keyslot,
			      uint32_t flags)
{
	int r;
	struct crypt_keyslot_context kc = {};

	if (!cd || !key_description)
		return -EINVAL;

	crypt_keyslot_context_init_by_keyring_internal(&kc, key_description);
	r = crypt_activate_by_keyslot_context(cd, name, keyslot, &kc, CRYPT_ANY_SLOT, &kc, flags);
	crypt_keyslot_context_destroy_internal(&kc);

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
	if (params)
		memset(params, 0, sizeof(*params));

	if (!cd || !isLUKS(cd->type))
		return CRYPT_REENCRYPT_INVALID;

	if (isLUKS1(cd->type))
		return CRYPT_REENCRYPT_NONE;

	if (_onlyLUKS2(cd, CRYPT_CD_QUIET, CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return CRYPT_REENCRYPT_INVALID;

	return LUKS2_reencrypt_get_params(&cd->u.luks2.hdr, params);
}

static void __attribute__((destructor)) libcryptsetup_exit(void)
{
	crypt_token_unload_external_all(NULL);

	crypt_backend_destroy();
	crypt_random_exit();
}
