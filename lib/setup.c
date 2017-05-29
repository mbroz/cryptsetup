/*
 * libcryptsetup - cryptsetup library
 *
 * Copyright (C) 2004, Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2017, Milan Broz
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
#include "luks2.h"
#include "loopaes.h"
#include "verity.h"
#include "tcrypt.h"
#include "integrity.h"
#include "internal.h"

struct crypt_device {
	char *type;

	struct device *device;
	struct device *metadata_device;

	struct volume_key *volume_key;
	int rng_type;
	struct crypt_pbkdf_type pbkdf;

	 /* global context scope settings */
	unsigned iter_time_set:1;
	unsigned key_in_keyring:1;

	// FIXME: private binary headers and access it properly
	// through sub-library (LUKS1, TCRYPT)

	union {
	struct { /* used in CRYPT_LUKS1 */
		struct luks_phdr hdr;
		uint32_t PBKDF2_per_sec;
	} luks1;
	struct { /* used in CRYPT_LUKS2 */
		struct luks2_hdr hdr;
		char *cipher;		/* only for compatibility, segment 0 */
		char *cipher_mode;	/* only for compatibility, segment 0 */
	} luks2;
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
	} integrity;
	struct { /* used if initialized without header by name */
		char *active_name;
		/* buffers, must refresh from kernel on every query */
		char cipher[MAX_CIPHER_LEN];
		char cipher_mode[MAX_CIPHER_LEN];
		unsigned int key_size;
		unsigned int veracrypt_pim;
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
	if (cd && cd->log)
		cd->log(level, msg, cd->log_usrptr);
	else if (_default_log)
		_default_log(level, msg, NULL);
	else if (_debug_level)
		printf("%s", msg);
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
		log_dbg("Crypto backend (%s) initialized in cryptsetup library version %s.",
			crypt_backend_version(), PACKAGE_VERSION);
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

static int isLUKS1(const char *type)
{
	return (type && !strcmp(CRYPT_LUKS1, type));
}

static int isLUKS2(const char *type)
{
	return (type && !strcmp(CRYPT_LUKS2, type));
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

static int onlyLUKS(struct crypt_device *cd)
{
	int r = 0;

	if (cd && !cd->type) {
		log_err(cd, _("Cannot determine device type. Incompatible activation of device?\n"));
		r = -EINVAL;
	}

	if (!cd || (!isLUKS1(cd->type) && !isLUKS2(cd->type))) {
		log_err(cd, _("This operation is supported only for LUKS device.\n"));
		return -EINVAL;
	}

	return r;
}
static int onlyLUKS2(struct crypt_device *cd)
{
	int r = 0;

	if (cd && !cd->type) {
		log_err(cd, _("Cannot determine device type. Incompatible activation of device?\n"));
		r = -EINVAL;
	}

	if (!cd || !isLUKS2(cd->type)) {
		log_err(cd, _("This operation is supported only for LUKS2 device.\n"));
		return -EINVAL;
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
	crypt_keyslot_info ki;

	if (*keyslot == CRYPT_ANY_SLOT) {
		if (isLUKS1(cd->type))
			*keyslot = LUKS_keyslot_find_empty(&cd->u.luks1.hdr);
		else
			*keyslot = LUKS2_keyslot_find_empty(&cd->u.luks2.hdr, "luks2"); // FIXME
		if (*keyslot < 0) {
			log_err(cd, _("All key slots full.\n"));
			return -EINVAL;
		}
	}

	if (isLUKS1(cd->type))
		ki = LUKS_keyslot_info(&cd->u.luks1.hdr, *keyslot);
	else
		ki = LUKS2_keyslot_info(&cd->u.luks2.hdr, *keyslot);
	switch (ki) {
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

	log_dbg("Selected keyslot %d.", *keyslot);
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

/*
 * compares type of active device to provided string (only if there is no explicit type)
 */
static int crypt_uuid_type_cmp(struct crypt_device *cd, const char *type)
{
	struct crypt_dm_active_device dmd = {};
	size_t len;
	int r;

	/* Must user header-on-disk if we know type here */
	if (cd->type || !cd->u.none.active_name)
		return -EINVAL;

	log_dbg("Checking if active device %s without header has UUID type %s.",
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
			.sector_size = crypt_get_sector_size(cd),
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

	if (!isLUKS1(cd->type) && !isLUKS2(cd->type) && !isVERITY(cd->type)) {
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

static int verify_pbkdf_params(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf)
{
	int r = 0;

	if (!pbkdf->type || !pbkdf->hash)
		return -EINVAL;

	/* TODO: initialise crypto and check the hash and pbkdf are both available */

	if (!strcmp(pbkdf->type, "argon2")) {
		if (pbkdf->max_memory_kb > MAX_PBKDF_MEMORY) {
			log_err(cd, _("Requested maximum PBKDF memory cost is too high (maximum is %d kilobytes).\n"),
				MAX_PBKDF_MEMORY);
			r = -EINVAL;
		}
		if (!pbkdf->max_memory_kb) {
			log_err(cd, _("Requested maximum PBKDF memory can not be zero.\n"));
			r = -EINVAL;
		}
		if (!pbkdf->parallel_threads) {
			log_err(cd, _("Requested PBKDF parallel threads can not be zero.\n"));
			r = -EINVAL;
		}
		if (!pbkdf->time_ms) {
			log_err(cd, _("Requested PBKDF target time can not be zero.\n"));
			r = -EINVAL;
		}
	} else if (!strcmp(pbkdf->type, "pbkdf2")) {
		if (pbkdf->max_memory_kb || pbkdf->parallel_threads) {
			log_err(cd, _("PBKDF max memory or parallel threads must not be set with pbkdf2.\n"));
			r = -EINVAL;
		}
	} else {
		log_err(cd, _("Unknown pbkdf type %s.\n"), pbkdf->type);
		r = -EINVAL;
	}

	return r;
}

static int init_pbkdf_type(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf)
{
	const char *hash, *type;
	int r;
	struct crypt_pbkdf_type default_luks2 = {
		.type = DEFAULT_LUKS2_PBKDF,
		.hash = DEFAULT_LUKS1_HASH,
		.time_ms = cd->iter_time_set ? cd->pbkdf.time_ms : DEFAULT_LUKS2_ITER_TIME,
		.max_memory_kb = DEFAULT_LUKS2_MEMORY_KB,
		.parallel_threads = DEFAULT_LUKS2_PARALLEL_THREADS
	}, default_luks1 = {
		.type = "pbkdf2",
		.hash = DEFAULT_LUKS1_HASH,
		.time_ms = cd->iter_time_set ? cd->pbkdf.time_ms : DEFAULT_LUKS1_ITER_TIME
	};
	unsigned cpus = crypt_cpusonline();

	if (!pbkdf) {
		pbkdf = isLUKS2(cd->type) ? &default_luks2 : &default_luks1;

		/*
		 * black magic due to crypt_set_iteration_time() but we don't
		 * want crypt_get_pbkdf_type() return invalid parameters
		 */
		r = verify_pbkdf_params(cd, pbkdf);
		if (r)
			return r;
	}

	/*
	 * Crypto backend may be not initialized here,
	 * cannot check if algorithms are really available.
	 * It will fail later anyway :-)
	 */
	type = strdup(pbkdf->type);
	hash = strdup(pbkdf->hash);

	if (!type || !hash) {
		free(CONST_CAST(void*)type);
		free(CONST_CAST(void*)hash);
		return -ENOMEM;
	}

	free(CONST_CAST(void*)cd->pbkdf.type);
	free(CONST_CAST(void*)cd->pbkdf.hash);
	cd->pbkdf.type = type;
	cd->pbkdf.hash = hash;

	cd->pbkdf.time_ms = pbkdf->time_ms;
	cd->pbkdf.max_memory_kb = pbkdf->max_memory_kb;

	if (pbkdf->parallel_threads > cpus) {
		cd->pbkdf.parallel_threads = cpus;
		log_dbg("Only %u active CPUs detected, PBKDF threads decreased from %d to %d.",
			cpus, pbkdf->parallel_threads, cpus);
	} else
		cd->pbkdf.parallel_threads = pbkdf->parallel_threads;

	return 0;
}

static int _crypt_load_luks(struct crypt_device *cd, const char *requested_type,
			    int require_header, int repair)
{
	char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	struct luks_phdr hdr = {};
	struct luks2_hdr hdr2 = {};
	struct crypt_pbkdf_type pbkdf = {};
	int r, version = 0;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	/* This will return 0 if primary LUKS2 header is damaged */
	if (!requested_type)
		version = LUKS2_hdr_version_unlocked(cd);

	if (isLUKS1(requested_type) || version == 1) {
		if (cd->type && isLUKS2(cd->type)) {
			log_dbg("Context is already initialised to type %s", cd->type);
			return -EINVAL;
		}

		r = LUKS_read_phdr(&hdr, require_header, repair, cd);
		if (r)
			goto out;

		if (!cd->type && !(cd->type = strdup(CRYPT_LUKS1))) {
			r = -ENOMEM;
			goto out;
		}

		pbkdf.type = "pbkdf2";
		pbkdf.hash = hdr.hashSpec;
		pbkdf.time_ms = cd->iter_time_set ? cd->pbkdf.time_ms : DEFAULT_LUKS1_ITER_TIME;

		r = init_pbkdf_type(cd, &pbkdf);
		if (r)
			goto out;

		memcpy(&cd->u.luks1.hdr, &hdr, sizeof(hdr));
	} else if (isLUKS2(requested_type) || version == 2 || version == 0) {
		if (cd->type && isLUKS1(cd->type)) {
			log_dbg("Context is already initialised to type %s", cd->type);
			return -EINVAL;
		}

		r = LUKS2_hdr_read(cd, &hdr2);
		if (r)
			goto out;

		if (!cd->type && !(cd->type = strdup(CRYPT_LUKS2))) {
			r = -ENOMEM;
			goto out;
		}

		r = crypt_parse_name_and_mode(LUKS2_get_cipher(&hdr2, 0),
					      cipher, NULL, cipher_mode);
		if (r < 0) {
			log_dbg("Cannot parse cipher and mode from loaded device.");
			goto out;
		}

		/* just load default values if no default pbkdf was set */
		if (!cd->pbkdf.type) {
			r = init_pbkdf_type(cd, NULL);
			if (r)
				goto out;
		}
		LUKS2_hdr_free(&cd->u.luks2.hdr);
		memcpy(&cd->u.luks2.hdr, &hdr2, sizeof(hdr2));

		/* Save cipher and mode, compatibility only. */
		free(cd->u.luks2.cipher);
		free(cd->u.luks2.cipher_mode);
		cd->u.luks2.cipher = strdup(cipher);
		cd->u.luks2.cipher_mode = strdup(cipher_mode);
	} else
		r = -EINVAL;
out:
	crypt_memzero(&hdr, sizeof(hdr));
	crypt_memzero(&hdr2, sizeof(hdr2));
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
		crypt_memzero(&cd->u.verity.hdr, sizeof(cd->u.verity.hdr));
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
		r = device_alloc(&cd->u.verity.fec_device, params->fec_device);
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

	r = INTEGRITY_read_sb(cd, &cd->u.integrity.params);
	if (r < 0)
		return r;

	if (params) {
		cd->u.integrity.params.journal_watermark = params->journal_watermark;
		cd->u.integrity.params.journal_commit_time = params->journal_commit_time;
		cd->u.integrity.params.buffer_sectors = params->buffer_sectors;
		// FIXME: check ENOMEM
		if (params->integrity)
			cd->u.integrity.params.integrity = strdup(params->integrity);
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

static const char *LUKS_UUID(struct crypt_device *cd)
{
	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.uuid;
	else if (isLUKS2(cd->type))
		return cd->u.luks2.hdr.uuid;

	return NULL;
}
static int _init_by_name_crypt(struct crypt_device *cd, const char *name)
{
	struct crypt_dm_active_device dmd = {}, dmdi = {};
	char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	const char *namei;
	int key_nums, r;

	r = dm_query_device(cd, name,
			DM_ACTIVE_DEVICE |
			DM_ACTIVE_UUID |
			DM_ACTIVE_CRYPT_CIPHER |
			DM_ACTIVE_CRYPT_KEYSIZE, &dmd);
	if (r < 0)
		goto out;

	r = crypt_parse_name_and_mode(dmd.u.crypt.cipher, cipher,
				      &key_nums, cipher_mode);
	if (r < 0) {
		log_dbg("Cannot parse cipher and mode from active device.");
		goto out;
	}

	if (dmd.u.crypt.integrity && (namei = device_dm_name(dmd.data_device))) {
		r = dm_query_device(cd, namei, DM_ACTIVE_DEVICE, &dmdi);
		if (r < 0)
			goto out;
		if (dmdi.target == DM_INTEGRITY && !cd->metadata_device) {
			device_free(cd->device);
			cd->device = dmdi.data_device;
		} else
			device_free(dmdi.data_device);
	}

	if (isPLAIN(cd->type)) {
		cd->u.plain.hdr.hash = NULL; /* no way to get this */
		cd->u.plain.hdr.offset = dmd.u.crypt.offset;
		cd->u.plain.hdr.skip = dmd.u.crypt.iv_offset;
		cd->u.plain.key_size = dmd.u.crypt.vk->keylength;
		cd->u.plain.cipher = strdup(cipher);
		cd->u.plain.cipher_mode = strdup(cipher_mode);
	} else if (isLOOPAES(cd->type)) {
		cd->u.loopaes.hdr.offset = dmd.u.crypt.offset;
		cd->u.loopaes.cipher = strdup(cipher);
		cd->u.loopaes.cipher_mode = strdup(cipher_mode);
		/* version 3 uses last key for IV */
		if (dmd.u.crypt.vk->keylength % key_nums)
			key_nums++;
		cd->u.loopaes.key_size = dmd.u.crypt.vk->keylength / key_nums;
	} else if (isLUKS1(cd->type) || isLUKS2(cd->type)) {
		if (crypt_metadata_device(cd)) {
			r = _crypt_load_luks(cd, cd->type, 0, 0);
			if (r < 0) {
				log_dbg("LUKS device header does not match active device.");
				crypt_set_null_type(cd);
				r = 0;
				goto out;
			}
			/* check whether UUIDs match each other */
			r = crypt_uuid_cmp(dmd.uuid, LUKS_UUID(cd));
			if (r < 0) {
				log_dbg("LUKS device header uuid: %s mismatches DM returned uuid %s",
					LUKS_UUID(cd), dmd.uuid);
				crypt_set_null_type(cd);
				r = 0;
				goto out;
			}
			if (isLUKS2(cd->type)) {
				/* Save cipher and mode, complatibility only. */
				cd->u.luks2.cipher = strdup(cipher);
				cd->u.luks2.cipher_mode = strdup(cipher_mode);
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
	free(CONST_CAST(void*)dmd.u.crypt.integrity);
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
		cd->u.verity.hdr.fec_area_offset = dmd.u.verity.fec_offset;
		cd->u.verity.hdr.hash_type = params.hash_type;
		cd->u.verity.hdr.flags = params.flags;
		cd->u.verity.hdr.salt_size = params.salt_size;
		cd->u.verity.hdr.salt = params.salt;
		cd->u.verity.hdr.fec_device = params.fec_device;
		cd->u.verity.hdr.fec_roots = params.fec_roots;
		cd->u.verity.fec_device = dmd.u.verity.fec_device;
		cd->metadata_device = dmd.u.verity.hash_device;
	}
out:
	device_free(dmd.data_device);
	return r;
}

static int _init_by_name_integrity(struct crypt_device *cd, const char *name)
{
	struct crypt_dm_active_device dmd = {
		.target = DM_INTEGRITY,
	};
	int r;

	r = dm_query_device(cd, name, DM_ACTIVE_DEVICE |
				      DM_ACTIVE_CRYPT_KEY |
				      DM_ACTIVE_CRYPT_KEYSIZE, &dmd);
	if (r < 0)
		goto out;
	if (r > 0)
		r = 0;

	if (isINTEGRITY(cd->type)) {
		cd->u.integrity.params.tag_size = dmd.u.integrity.tag_size;
		cd->u.integrity.params.sector_size = dmd.u.integrity.sector_size;
		cd->u.integrity.params.journal_size = dmd.u.integrity.journal_size;
		cd->u.integrity.params.journal_watermark = dmd.u.integrity.journal_watermark;
		cd->u.integrity.params.journal_commit_time = dmd.u.integrity.journal_commit_time;
		cd->u.integrity.params.interleave_sectors = dmd.u.integrity.interleave_sectors;
		cd->u.integrity.params.buffer_sectors = dmd.u.integrity.buffer_sectors;
		cd->u.integrity.params.integrity = dmd.u.integrity.integrity;
		//FIXME init keys?
	}
out:
	crypt_free_volume_key(dmd.u.integrity.vk);
	device_free(dmd.data_device);
	return r;
}

int crypt_init_by_name_and_header(struct crypt_device **cd,
				  const char *name,
				  const char *header_device)
{
	crypt_status_info ci;
	struct crypt_dm_active_device dmd = {};
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
		else if (!strncmp(CRYPT_LUKS2, dmd.uuid, sizeof(CRYPT_LUKS2)-1))
			(*cd)->type = strdup(CRYPT_LUKS2);
		else if (!strncmp(CRYPT_VERITY, dmd.uuid, sizeof(CRYPT_VERITY)-1))
			(*cd)->type = strdup(CRYPT_VERITY);
		else if (!strncmp(CRYPT_TCRYPT, dmd.uuid, sizeof(CRYPT_TCRYPT)-1))
			(*cd)->type = strdup(CRYPT_TCRYPT);
		else if (!strncmp(CRYPT_INTEGRITY, dmd.uuid, sizeof(CRYPT_INTEGRITY)-1))
			(*cd)->type = strdup(CRYPT_INTEGRITY);
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
	else if (dmd.target == DM_INTEGRITY)
		r = _init_by_name_integrity(*cd, name);
out:
	if (r < 0) {
		crypt_free(*cd);
		*cd = NULL;
	} else if (!(*cd)->type) {
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

	r = init_pbkdf_type(cd, NULL);
	if (r)
		return r;

	if (params && params->hash && strcmp(params->hash, DEFAULT_LUKS1_HASH)) {
		free(CONST_CAST(void*)cd->pbkdf.hash);
		cd->pbkdf.hash = strdup(params->hash);
		if (!cd->pbkdf.hash)
			return -ENOMEM;
	}

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
			       cd->pbkdf.hash, uuid, LUKS_STRIPES,
			       required_alignment / SECTOR_SIZE,
			       alignment_offset / SECTOR_SIZE,
			       cd->pbkdf.time_ms, &cd->u.luks1.PBKDF2_per_sec,
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

static int _crypt_format_luks2(struct crypt_device *cd,
			       const char *cipher,
			       const char *cipher_mode,
			       const char *uuid,
			       const char *volume_key,
			       size_t volume_key_size,
			       struct crypt_params_luks2 *params)
{
	int r;
	unsigned long required_alignment = DEFAULT_DISK_ALIGNMENT;
	unsigned long alignment_offset = 0;
	unsigned int sector_size = params ? params->sector_size : SECTOR_SIZE;
	const char *integrity = params ? params->integrity.type : NULL;

	if (!crypt_metadata_device(cd)) {
		log_err(cd, _("Can't format LUKS without device.\n"));
		return -EINVAL;
	}

	if (sector_size < 512 || sector_size > 4096 || (sector_size & (sector_size - 1))) {
		log_err(cd, _("Unsupported encryption sector size.\n"));
		return -EINVAL;
	}

	if (integrity && !INTEGRITY_tag_size(cd, integrity, cipher_mode)) {
		if (!strcmp(integrity, "none"))
			integrity = NULL;
		else
			return -EINVAL;
	}

	r = device_check(crypt_metadata_device(cd), DEV_EXCL);
	if (r < 0) {
		log_err(cd, _("Cannot use device %s which is in use "
			      "(already mapped or mounted).\n"),
			      device_path(crypt_metadata_device(cd)));
		return r;
	}

	if (!(cd->type = strdup(CRYPT_LUKS2)))
		return -ENOMEM;

	if (volume_key)
		cd->volume_key = crypt_alloc_volume_key(volume_key_size,
						      volume_key);
	else
		cd->volume_key = crypt_generate_volume_key(cd, volume_key_size);

	if (!cd->volume_key)
		return -ENOMEM;

	if (params)
		r = crypt_set_pbkdf_type(cd, &params->pbkdf);
	else
		r = init_pbkdf_type(cd, NULL);

	if (r < 0)
		return r;

	if (params && params->data_device) {
		cd->metadata_device = cd->device;
		cd->device = NULL;
		if (device_alloc(&cd->device, params->data_device) < 0)
			return -ENOMEM;
		required_alignment = params->data_alignment * sector_size;
	} else if (params && params->data_alignment) {
		required_alignment = params->data_alignment * sector_size;
	} else
		device_topology_alignment(cd->device,
				       &required_alignment,
				       &alignment_offset, DEFAULT_DISK_ALIGNMENT);

	/* Save cipher and mode, compatibility only. */
	cd->u.luks2.cipher = strdup(cipher);
	cd->u.luks2.cipher_mode = strdup(cipher_mode);

	r = LUKS2_generate_hdr(cd, &cd->u.luks2.hdr, cd->volume_key,
			       cipher, cipher_mode,
			       integrity, uuid,
			       sector_size,
			       required_alignment / sector_size,
			       alignment_offset / sector_size,
			       cd->metadata_device ? 1 : 0);
	if (r < 0)
		return r;

	/* Wipe integrity superblock and create integrity superblock */
	if (crypt_get_integrity_tag_size(cd)) {
		/* FIXME: this should be locked. */
		r = crypt_wipe(crypt_metadata_device(cd), crypt_get_data_offset(cd) * SECTOR_SIZE,
			       8 * SECTOR_SIZE, CRYPT_WIPE_ZERO, 1);
		if (r < 0) {
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

		r = device_write_lock(cd, crypt_metadata_device(cd));
		if (r) {
			log_err(cd, _("Failed to acquire write lock on device %s.\n"),
				mdata_device_path(cd));
			return -EINVAL;
		}

		r = INTEGRITY_format(cd, NULL, NULL, NULL);
		if (r)
			log_err(cd, _("Cannot format integrity for device %s.\n"),
				mdata_device_path(cd));

		device_write_unlock(crypt_metadata_device(cd));
	}

	if (r < 0)
		return r;

	r = LUKS2_hdr_write(cd, &cd->u.luks2.hdr);
	if (r < 0) {
		if (r == -EBUSY)
			log_err(cd, _("Cannot format device %s in use.\n"),
				mdata_device_path(cd));
		else if (r == -EACCES) {
			log_err(cd, _("Cannot format device %s, permission denied.\n"),
				mdata_device_path(cd));
			r = -EINVAL;
		} else
			log_err(cd, _("Cannot format device %s\n"),
				mdata_device_path(cd));
	}

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

	if (params->fec_area_offset % 512) {
		log_err(cd, _("Unsupported VERITY FEC offset.\n"));
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

	if (device_is_identical(crypt_metadata_device(cd), crypt_data_device(cd)) &&
	   (cd->u.verity.hdr.data_size * params->data_block_size) > params->hash_area_offset) {
		log_err(cd, _("Data area overlaps with hash area.\n"));
		return -EINVAL;
	}

	if (params->fec_device &&
	    (r = device_alloc(&cd->u.verity.fec_device, params->fec_device)) < 0)
		return r;

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
	cd->u.verity.hdr.fec_device = params->fec_device;
	cd->u.verity.hdr.fec_roots = params->fec_roots;
	cd->u.verity.hdr.data_block_size = params->data_block_size;
	cd->u.verity.hdr.hash_block_size = params->hash_block_size;
	cd->u.verity.hdr.hash_area_offset = params->hash_area_offset;
	cd->u.verity.hdr.fec_area_offset = params->fec_area_offset;
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
		if (!r && params->fec_device)
			r = VERITY_FEC_create(cd, &cd->u.verity.hdr, cd->u.verity.fec_device);
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

static int _crypt_format_integrity(struct crypt_device *cd,
				   const char *uuid,
				   struct crypt_params_integrity *params)
{
	int r;

	if (!params)
		return -EINVAL;

	if (uuid) {
		log_err(cd, _("UUID is not supported for this crypt type.\n"));
		return -EINVAL;
	}

	/* Wipe first 8 sectors - fs magic numbers etc. */
	r = crypt_wipe(crypt_metadata_device(cd), 0, 8 * SECTOR_SIZE, CRYPT_WIPE_ZERO, 1);
	if (r < 0) {
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

	if (!(cd->type = strdup(CRYPT_INTEGRITY)))
		return -ENOMEM;

	if (params->journal_crypt_key) {
		cd->u.integrity.journal_crypt_key =
			crypt_alloc_volume_key(params->journal_crypt_key_size,
					       params->journal_crypt_key);
		if (!cd->u.integrity.journal_crypt_key) {
			crypt_reset_null_type(cd);
			return -ENOMEM;
		}
	}
	if (params->journal_integrity_key) {
		cd->u.integrity.journal_mac_key =
			crypt_alloc_volume_key(params->journal_integrity_key_size,
					       params->journal_integrity_key);
		if (!cd->u.integrity.journal_mac_key) {
			crypt_reset_null_type(cd);
			return -ENOMEM;
		}
	}

	cd->u.integrity.params.journal_size = params->journal_size;
	cd->u.integrity.params.journal_watermark = params->journal_watermark;
	cd->u.integrity.params.journal_commit_time = params->journal_commit_time;
	cd->u.integrity.params.interleave_sectors = params->interleave_sectors;
	cd->u.integrity.params.buffer_sectors = params->buffer_sectors;
	cd->u.integrity.params.sector_size = params->sector_size;
	cd->u.integrity.params.tag_size = params->tag_size;
	cd->u.integrity.params.integrity = params->integrity;
	cd->u.integrity.params.journal_integrity = params->journal_integrity;
	cd->u.integrity.params.journal_crypt = params->journal_crypt;

	r = INTEGRITY_format(cd, params, cd->u.integrity.journal_crypt_key, cd->u.integrity.journal_mac_key);
	if (r)
		log_err(cd, _("Cannot format integrity for device %s.\n"),
			mdata_device_path(cd));

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

	if (!requested_type || isLUKS1(requested_type) || isLUKS2(requested_type)) {
		if (cd->type && !isLUKS1(cd->type) && !isLUKS2(cd->type)) {
			log_dbg("Context is already initialised to type %s", cd->type);
			return -EINVAL;
		}

		r = _crypt_load_luks(cd, requested_type, 1, 0);
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
	} else if (isINTEGRITY(requested_type)) {
		if (cd->type && !isINTEGRITY(cd->type)) {
			log_dbg("Context is already initialised to type %s", cd->type);
			return -EINVAL;
		}
		r = _crypt_load_integrity(cd, params);
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

	// FIXME LUKS2
	if (requested_type && !isLUKS1(requested_type))
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

static int crypt_get_segment_key_description(struct crypt_device *cd, char **segment_key_desc, unsigned segment)
{
	char *key_desc;
	int r;
	size_t len;

	if (!crypt_get_uuid(cd) || segment > 9)
		return -EINVAL;

	len = strlen(crypt_get_uuid(cd)) + 14;

	key_desc = malloc(len);
	if (!key_desc)
	       return -ENOMEM;

	r = snprintf(key_desc, len, "%s:%s-%u", "cryptsetup", crypt_get_uuid(cd), segment);
	if (r < 0 || (size_t)r >= len) {
	       free(key_desc);
	       return -EINVAL;
	}

	*segment_key_desc = key_desc;

	return 0;
}

int crypt_resize(struct crypt_device *cd, const char *name, uint64_t new_size)
{
	char *key_desc;
	struct crypt_dm_active_device dmd = {};
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

	if ((dmd.flags & CRYPT_ACTIVATE_KEYRING_KEY) && !crypt_key_in_keyring(cd)) {
		r = -EPERM;
		goto out;
	}

	if (crypt_key_in_keyring(cd)) {
		r = crypt_get_segment_key_description(cd, &key_desc, 0);
		if (r)
			goto out;

		crypt_volume_key_set_description(dmd.u.crypt.vk, key_desc);
		dmd.flags |= CRYPT_ACTIVATE_KEYRING_KEY;
	}

	if (crypt_loop_device(crypt_get_device_name(cd))) {
		log_dbg("Trying to resize underlying loop device %s.",
			crypt_get_device_name(cd));
		/* Here we always use default size not new_size */
		if (crypt_loop_resize(crypt_get_device_name(cd)))
			log_err(NULL, _("Cannot resize loop device.\n"));
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
		free(CONST_CAST(void*)dmd.u.crypt.integrity);
	}
	free(CONST_CAST(void*)dmd.data_device);
	free(CONST_CAST(void*)dmd.uuid);

	return r;
}

int crypt_set_uuid(struct crypt_device *cd, const char *uuid)
{
	const char *active_uuid;

	if (!isLUKS1(cd->type) && !isLUKS2(cd->type)) {
		log_err(cd, _("This operation is not supported for this device type.\n"));
		return  -EINVAL;
	}

	active_uuid = crypt_get_uuid(cd);

	if (uuid && active_uuid && !strncmp(uuid, active_uuid, UUID_STRING_L)) {
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

	if (isLUKS1(cd->type))
		return LUKS_hdr_uuid_set(&cd->u.luks1.hdr, uuid, cd);
	else
		return LUKS2_hdr_uuid(cd, &cd->u.luks2.hdr, uuid);
}

int crypt_header_backup(struct crypt_device *cd,
			const char *requested_type,
			const char *backup_file)
{
	int r;

	if (requested_type && !isLUKS1(requested_type) && !isLUKS2(requested_type))
		return -EINVAL;

	if (!backup_file)
		return -EINVAL;

	/* Load with repair */
	r = _crypt_load_luks(cd, requested_type, 1, 0);
	if (r < 0)
		return r;

	log_dbg("Requested header backup of device %s (%s) to "
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
	int r;

	if (requested_type && !isLUKS1(requested_type) && !isLUKS2(requested_type))
		return -EINVAL;

	if (cd->type && !isLUKS1(cd->type) && !isLUKS2(cd->type))
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	log_dbg("Requested header restore to device %s (%s) from "
		"file %s.", mdata_device_path(cd), requested_type ?: "any type", backup_file);

	memset(&hdr2, 0, sizeof(hdr2));
	if (!cd->type) {
		if (!requested_type || isLUKS2(requested_type)) {
			r = LUKS2_hdr_restore(cd, &hdr2, backup_file);
			LUKS2_hdr_free(&hdr2);
		} else
			r = -ENOENT;
 
		if (r && (!requested_type || isLUKS1(requested_type)))
			r = LUKS_hdr_restore(backup_file, &hdr1, cd);

		crypt_memzero(&hdr1, sizeof(hdr1));
		crypt_memzero(&hdr2, sizeof(hdr2));
	} else if (isLUKS2(cd->type) && (!requested_type || isLUKS2(requested_type))) {
		r = LUKS2_hdr_restore(cd, &cd->u.luks2.hdr, backup_file);
	} else if (isLUKS1(cd->type) && (!requested_type || isLUKS1(requested_type))) {
		r = LUKS_hdr_restore(backup_file, &cd->u.luks1.hdr, cd);
	} else
		r = -EINVAL;

	return r;
}

static void crypt_free_type(struct crypt_device *cd)
{
	if (isPLAIN(cd->type)) {
		free(CONST_CAST(void*)cd->u.plain.hdr.hash);
		free(cd->u.plain.cipher);
		free(cd->u.plain.cipher_mode);
	} else if (isLUKS2(cd->type)) {
		LUKS2_hdr_free(&cd->u.luks2.hdr);
		free(cd->u.luks2.cipher);
		free(cd->u.luks2.cipher_mode);
	} else if (isLOOPAES(cd->type)) {
		free(CONST_CAST(void*)cd->u.loopaes.hdr.hash);
		free(cd->u.loopaes.cipher);
	} else if (isVERITY(cd->type)) {
		free(CONST_CAST(void*)cd->u.verity.hdr.hash_name);
		free(CONST_CAST(void*)cd->u.verity.hdr.salt);
		free(cd->u.verity.root_hash);
		free(cd->u.verity.uuid);
		device_free(cd->u.verity.fec_device);
	} else if (isINTEGRITY(cd->type)) {
		free(CONST_CAST(void*)cd->u.integrity.params.integrity);
		crypt_free_volume_key(cd->u.integrity.journal_crypt_key);
		crypt_free_volume_key(cd->u.integrity.journal_mac_key);
	} else if (!cd->type) {
		free(cd->u.none.active_name);
	}

	crypt_set_null_type(cd);
}

void crypt_free(struct crypt_device *cd)
{
	if (!cd)
		return;

	log_dbg("Releasing crypt device %s context.", mdata_device_path(cd));

	dm_backend_exit();
	crypt_free_volume_key(cd->volume_key);

	device_free(cd->device);
	device_free(cd->metadata_device);

	free(CONST_CAST(void*)cd->pbkdf.type);
	free(CONST_CAST(void*)cd->pbkdf.hash);

	crypt_free_type(cd);

	/* Some structures can contain keys (TCRYPT), wipe it */
	crypt_memzero(cd, sizeof(*cd));
	free(cd);
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

static int crypt_drop_keyring_key(struct crypt_device *cd, const char *active_key_desc)
{
	char *seg_key_desc;
	int r, ret = 0;

	if (active_key_desc && keyring_revoke_and_unlink_key(active_key_desc))
		ret = -EINVAL;

	if (!crypt_key_in_keyring(cd))
		return ret;

	r = crypt_get_segment_key_description(cd, &seg_key_desc, 0);
	if (r)
		return -EINVAL;

	if (keyring_revoke_and_unlink_key(seg_key_desc))
		ret = -EINVAL;
	else
		crypt_set_key_in_keyring(cd, 0);

	free(seg_key_desc);

	return ret;
}

static char *crypt_get_device_key_description(const char *name)
{
	char *tmp = NULL;
	struct crypt_dm_active_device dmd;

	if (dm_query_device(NULL, name, DM_ACTIVE_CRYPT_KEY | DM_ACTIVE_CRYPT_KEYSIZE, &dmd) < 0 || dmd.target != DM_CRYPT)
		return NULL;

	if (dmd.flags & CRYPT_ACTIVATE_KEYRING_KEY)
		tmp = strdup(crypt_volume_key_get_description(dmd.u.crypt.vk));

	crypt_free_volume_key(dmd.u.crypt.vk);

	return tmp;
}

int crypt_suspend(struct crypt_device *cd,
		  const char *name)
{
	char *key_desc;
	crypt_status_info ci;
	int r;

	log_dbg("Suspending volume %s.", name);

	if (cd->type) {
		r = onlyLUKS(cd);
	} else {
		r = crypt_uuid_type_cmp(cd, CRYPT_LUKS1);
		if (r < 0)
			r = crypt_uuid_type_cmp(cd, CRYPT_LUKS2);
		if (r < 0)
			log_err(cd, _("This operation is supported only for LUKS device.\n"));
	}

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

	if (!r) {
		key_desc = crypt_get_device_key_description(name);
		if (crypt_drop_keyring_key(cd, key_desc))
			log_err(cd, _("Failed to drop device key stored in kernel keyring.\n"));
		free(key_desc);
	}
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

	if (!passphrase)
		return -EINVAL;

	r = dm_status_suspended(cd, name);
	if (r < 0)
		return r;

	if (!r) {
		log_err(cd, _("Volume %s is not suspended.\n"), name);
		return -EINVAL;
	}

	if (isLUKS1(cd->type))
		r = LUKS_open_key_with_hdr(keyslot, passphrase, passphrase_size,
					   &cd->u.luks1.hdr, &vk, cd);
	else
		r = LUKS2_keyslot_open(cd, keyslot, 0, passphrase, passphrase_size, &vk);

	if  (r < 0)
		goto out;

	keyslot = r;

	if (crypt_use_keyring_for_vk(cd)) {
		r = crypt_volume_key_load_in_keyring(cd, vk);
		if (r < 0)
			goto out;
	}

	r = dm_resume_and_reinstate_key(cd, name, vk);

	if (r == -ENOTSUP)
		log_err(cd, _("Resume is not supported for device %s.\n"), name);
	else if (r)
		log_err(cd, _("Error during resuming device %s.\n"), name);
out:
	crypt_free_volume_key(vk);
	if (r < 0)
		crypt_drop_keyring_key(cd, NULL);

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

	r = crypt_keyfile_read(cd, keyfile,
			       &passphrase_read, &passphrase_size_read,
			       keyfile_offset, keyfile_size, 0);
	if (r < 0)
		goto out;

	if (isLUKS1(cd->type))
		r = LUKS_open_key_with_hdr(keyslot, passphrase_read, passphrase_size_read,
					   &cd->u.luks1.hdr, &vk, cd);
	else
		r = LUKS2_keyslot_open(cd, keyslot, 0, passphrase_read, passphrase_size_read, &vk);
	if (r < 0)
		goto out;

	if (crypt_use_keyring_for_vk(cd)) {
		r = crypt_volume_key_load_in_keyring(cd, vk);
		if (r)
			goto out;
	}

	keyslot = r;
	r = dm_resume_and_reinstate_key(cd, name, vk);
	if (r)
		log_err(cd, _("Error during resuming device %s.\n"), name);
out:
	crypt_safe_free(passphrase_read);
	crypt_free_volume_key(vk);
	if (r < 0)
		crypt_drop_keyring_key(cd, NULL);
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

static void _luks2_reload(struct crypt_device *cd)
{
	if (!cd || !isLUKS2(cd->type))
		return;

	log_dbg("Reloading LUKS2 header.");

	(void) crypt_load(cd, CRYPT_LUKS2, NULL);
}

// slot manipulation
int crypt_keyslot_add_by_passphrase(struct crypt_device *cd,
	int keyslot, // -1 any
	const char *passphrase,
	size_t passphrase_size,
	const char *new_passphrase,
	size_t new_passphrase_size)
{
	digests_t digests;
	int r, active_slots;
	struct volume_key *vk = NULL;

	log_dbg("Adding new keyslot, existing passphrase %sprovided,"
		"new passphrase %sprovided.",
		passphrase ? "" : "not ", new_passphrase  ? "" : "not ");

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	if (!passphrase || !new_passphrase)
		return -EINVAL;

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r)
		return r;

	if (isLUKS1(cd->type))
		active_slots = LUKS_keyslot_active_count(&cd->u.luks1.hdr);
	else
		active_slots = LUKS2_keyslot_active_count(&cd->u.luks2.hdr, 0);
	if (active_slots == 0) {
		/* No slots used, try to use pre-generated key in header */
		if (cd->volume_key) {
			vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);
			r = vk ? 0 : -ENOMEM;
		} else {
			log_err(cd, _("Cannot add key slot, all slots disabled and no volume key provided.\n"));
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
			r = LUKS2_keyslot_open(cd, CRYPT_ANY_SLOT, 0, passphrase,
						passphrase_size, &vk);
	}

	if (r < 0)
		goto out;

	if (isLUKS1(cd->type))
		r = LUKS_set_key(keyslot, CONST_CAST(char*)new_passphrase,
				 new_passphrase_size, &cd->u.luks1.hdr, vk,
				 cd->pbkdf.time_ms, &cd->u.luks1.PBKDF2_per_sec, cd);
	else {
		r = LUKS2_digests_verify_by_segment(cd, &cd->u.luks2.hdr, 0, vk, digests);

		if (r >= 0)
			r = LUKS2_digests_assign(cd, &cd->u.luks2.hdr, keyslot, digests, 1, 0);

		if (r >= 0)
			r = LUKS2_keyslot_store(cd,  &cd->u.luks2.hdr, keyslot,
						CONST_CAST(char*)new_passphrase,
						new_passphrase_size, vk);
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
	digests_t digests;
	int r;
	struct volume_key *vk = NULL;

	log_dbg("Changing passphrase from old keyslot %d to new %d.",
		keyslot_old, keyslot_new);

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	if (isLUKS1(cd->type))
		r = LUKS_open_key_with_hdr(keyslot_old, passphrase, passphrase_size,
					   &cd->u.luks1.hdr, &vk, cd);
	else if (isLUKS2(cd->type)) {
		r = LUKS2_keyslot_open(cd, keyslot_old, CRYPT_ANY_SEGMENT, passphrase, passphrase_size, &vk);
		/* will fail for keyslots w/o digest. fix if supported in a future */
		if (r >= 0 && LUKS2_digests_by_keyslot(cd, &cd->u.luks2.hdr, r, digests))
			r = -EINVAL;
	} else
		r = -EINVAL;
	if (r < 0)
		goto out;

	if (keyslot_old != CRYPT_ANY_SLOT && keyslot_old != r) {
		log_dbg("Keyslot mismatch.");
		goto out;
	}
	keyslot_old = r;

	if (keyslot_new == CRYPT_ANY_SLOT) {
		if (isLUKS1(cd->type))
			keyslot_new = LUKS_keyslot_find_empty(&cd->u.luks1.hdr);
		else if (isLUKS2(cd->type))
			keyslot_new = LUKS2_keyslot_find_empty(&cd->u.luks2.hdr, "luks2"); // FIXME
		if (keyslot_new < 0)
			keyslot_new = keyslot_old;
	}
	log_dbg("Key change, old slot %d, new slot %d.", keyslot_old, keyslot_new);

	if (isLUKS1(cd->type)) {
		if (keyslot_old == keyslot_new) {
			log_dbg("Key slot %d is going to be overwritten.", keyslot_old);
			(void)crypt_keyslot_destroy(cd, keyslot_old);
		}
		r = LUKS_set_key(keyslot_new, new_passphrase, new_passphrase_size,
				 &cd->u.luks1.hdr, vk, cd->pbkdf.time_ms,
				 &cd->u.luks1.PBKDF2_per_sec, cd);
	} else if (isLUKS2(cd->type)) {
		if (keyslot_old != keyslot_new) {
			r = LUKS2_digests_assign(cd, &cd->u.luks2.hdr, keyslot_new, digests, 1, 0);
			if (r < 0)
				goto out;
		} else {
			log_dbg("Key slot %d is going to be overwritten.", keyslot_old);
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
					new_passphrase_size, vk);
	} else
		r = -EINVAL;

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
	if (r < 0) {
		_luks2_reload(cd);
		return r;
	}
	return keyslot_new;
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
	digests_t digests;
	int r, active_slots;
	size_t passwordLen, new_passwordLen;
	char *password = NULL, *new_password = NULL;
	struct volume_key *vk = NULL;

	log_dbg("Adding new keyslot, existing keyfile %s, new keyfile %s.",
		keyfile ?: "[none]", new_keyfile ?: "[none]");

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	if (!keyfile || !new_keyfile)
		return -EINVAL;

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r)
		return r;

	if (isLUKS1(cd->type))
		active_slots = LUKS_keyslot_active_count(&cd->u.luks1.hdr);
	else
		active_slots = LUKS2_keyslot_active_count(&cd->u.luks2.hdr, 0);
	if (active_slots == 0) {
		/* No slots used, try to use pre-generated key in header */
		if (cd->volume_key) {
			vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);
			r = vk ? 0 : -ENOMEM;
		} else {
			log_err(cd, _("Cannot add key slot, all slots disabled and no volume key provided.\n"));
			return -EINVAL;
		}
	} else {
		r = crypt_keyfile_read(cd, keyfile,
				       &password, &passwordLen,
				       keyfile_offset, keyfile_size, 0);
		if (r < 0)
			goto out;

		if (isLUKS1(cd->type))
			r = LUKS_open_key_with_hdr(CRYPT_ANY_SLOT, password, passwordLen,
						   &cd->u.luks1.hdr, &vk, cd);
		else
			r = LUKS2_keyslot_open(cd, CRYPT_ANY_SLOT, 0, password, passwordLen, &vk);
	}

	if (r < 0)
		goto out;

	r = crypt_keyfile_read(cd, new_keyfile,
			       &new_password, &new_passwordLen,
			       new_keyfile_offset, new_keyfile_size, 0);
	if (r < 0)
		goto out;

	if (isLUKS1(cd->type))
		r = LUKS_set_key(keyslot, new_password, new_passwordLen,
				 &cd->u.luks1.hdr, vk, cd->pbkdf.time_ms,
				 &cd->u.luks1.PBKDF2_per_sec, cd);
	else {
		r = LUKS2_digests_verify_by_segment(cd, &cd->u.luks2.hdr, 0, vk, digests);

		if (r >= 0)
			r = LUKS2_digests_assign(cd, &cd->u.luks2.hdr, keyslot, digests, 1, 0);

		if (r >= 0)
			r = LUKS2_keyslot_store(cd,  &cd->u.luks2.hdr, keyslot,
						new_password, new_passwordLen, vk);
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

	log_dbg("Adding new keyslot %d using volume key.", keyslot);

	r = onlyLUKS(cd);
	if (r < 0)
		return r;

	if (isLUKS2(cd->type))
		return crypt_keyslot_add_by_volume_key_assign(cd, keyslot,
				volume_key, volume_key_size, passphrase,
				passphrase_size, 0);

	if (!passphrase)
		return -EINVAL;

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
		log_err(cd, _("Volume key does not match the volume.\n"));
	else
		r = LUKS_set_key(keyslot, passphrase, passphrase_size,
			&cd->u.luks1.hdr, vk, cd->pbkdf.time_ms,
			&cd->u.luks1.PBKDF2_per_sec, cd);

	crypt_free_volume_key(vk);
	return (r < 0) ? r : keyslot;
}

int crypt_keyslot_destroy(struct crypt_device *cd, int keyslot)
{
	crypt_keyslot_info ki;
	digests_t digests;
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

	if (isLUKS1(cd->type)) {
		if (ki == CRYPT_SLOT_INACTIVE) {
			log_err(cd, _("Key slot %d is not used.\n"), keyslot);
			return -EINVAL;
		}
		return LUKS_del_key(keyslot, &cd->u.luks1.hdr, cd);
	}

	if (isLUKS2(cd->type)) {
		r = LUKS2_digests_by_keyslot(cd, &cd->u.luks2.hdr, keyslot, digests);
		if (!r)
			(void) LUKS2_digests_assign(cd, &cd->u.luks2.hdr, keyslot, digests, 0, 0);
		(void) LUKS2_digests_erase_unused(cd, &cd->u.luks2.hdr, 0);

		r = LUKS2_keyslot_wipe(cd, &cd->u.luks2.hdr, keyslot, 0);
		if (r)
			_luks2_reload(cd);
		return r;
	}

	return -EINVAL;
}

int crypt_volume_key_load_in_keyring(struct crypt_device *cd, struct volume_key *vk)
{
	char *seg_key_desc = NULL;
	int r;

	if (!vk)
		return -EINVAL;

	r = crypt_get_segment_key_description(cd, &seg_key_desc, 0);
	if (!r)
		r = keyring_add_key_in_thread_keyring(seg_key_desc, vk->key, vk->keylength);

	if (r) {
		free(seg_key_desc);
		log_err(cd, _("Failed to load key in kernel keyring.\n"));
	} else {
		crypt_volume_key_set_description(vk, seg_key_desc);
		crypt_set_key_in_keyring(cd, 1);
	}

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

	/* plain, use hashed passphrase */
	if (isPLAIN(cd->type)) {
		if (!name)
			return -EINVAL;

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
		r = LUKS2_keyslot_open(cd, keyslot, 0, passphrase,
				       passphrase_size, &vk);
		if (r >= 0) {
			keyslot = r;

			if (crypt_use_keyring_for_vk(cd)) {
				if (crypt_volume_key_load_in_keyring(cd, vk))
					goto out;
				flags |= CRYPT_ACTIVATE_KEYRING_KEY;
			}

			if (name)
				r = LUKS2_activate(cd, name, vk, flags);
		}
	} else
		r = -EINVAL;
out:
	crypt_free_volume_key(vk);

	if (r < 0)
		crypt_drop_keyring_key(cd, NULL);

	return r < 0 ? r : keyslot;
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

	log_dbg("%s volume %s [keyslot %d] using %spassphrase.",
		name ? "Activating" : "Checking", name ?: "",
		keyslot, passphrase ? "" : "[none] ");

	if (!passphrase)
		return -EINVAL;

	if (name) {
		ci = crypt_status(NULL, name);
		if (ci == CRYPT_INVALID)
			return -EINVAL;
		else if (ci >= CRYPT_ACTIVE) {
			log_err(cd, _("Device %s already exists.\n"), name);
			return -EEXIST;
		}
	}

	return _activate_by_passphrase(cd, name, keyslot, passphrase, passphrase_size, flags);
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

		r = crypt_keyfile_read(cd, keyfile,
				       &passphrase_read, &passphrase_size_read,
				       keyfile_offset, keyfile_size, 0);
		if (r < 0)
			goto out;

		r = process_key(cd, cd->u.plain.hdr.hash,
				cd->u.plain.key_size,
				passphrase_read, passphrase_size_read, &vk);
		if (r < 0)
			goto out;

		r = PLAIN_activate(cd, name, vk, cd->u.plain.hdr.size, flags);
	} else if (isLUKS1(cd->type)) {
		r = crypt_keyfile_read(cd, keyfile,
				       &passphrase_read, &passphrase_size_read,
				       keyfile_offset, keyfile_size, 0);
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
	} else if (isLUKS2(cd->type)) {
		r = crypt_keyfile_read(cd, keyfile,
				       &passphrase_read, &passphrase_size_read,
				       keyfile_offset, keyfile_size, 0);
		if (r < 0)
			goto out;

		r = LUKS2_keyslot_open(cd, keyslot, 0, passphrase_read,
					passphrase_size_read,  &vk);
		if (r < 0)
			goto out;
		keyslot = r;

		if (crypt_use_keyring_for_vk(cd) && crypt_volume_key_load_in_keyring(cd, vk))
			goto out;

		if (name) {
			r = LUKS2_activate(cd, name, vk, flags);
			if (r < 0)
				goto out;
		}
		r = keyslot;
	} else if (isLOOPAES(cd->type)) {
		r = crypt_keyfile_read(cd, keyfile,
				       &passphrase_read, &passphrase_size_read,
				       keyfile_offset, keyfile_size, 0);
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

	if (r < 0)
		crypt_drop_keyring_key(cd, NULL);

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
	digests_t digests;
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
	} else if (isLUKS1(cd->type)) {
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
	} else if (isLUKS2(cd->type)) {
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

		r = LUKS2_digests_verify_by_segment(cd, &cd->u.luks2.hdr, 0, vk, digests);
		if (r == -EPERM)
			log_err(cd, _("Volume key does not match the volume.\n"));

		if (!r && crypt_use_keyring_for_vk(cd))
			r = crypt_volume_key_load_in_keyring(cd, vk);

		if (!r && name)
			r = LUKS2_activate(cd, name, vk, flags);
	} else if (isVERITY(cd->type)) {
		/* volume_key == root hash */
		if (!volume_key || !volume_key_size) {
			log_err(cd, _("Incorrect root hash specified for verity device.\n"));
			return -EINVAL;
		}

		r = VERITY_activate(cd, name, volume_key, volume_key_size, cd->u.verity.fec_device,
				    &cd->u.verity.hdr, flags|CRYPT_ACTIVATE_READONLY);

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
				       cd->u.integrity.journal_mac_key, flags);
	} else
		log_err(cd, _("Device type is not properly initialised.\n"));

	crypt_free_volume_key(vk);

	if (r < 0)
		crypt_drop_keyring_key(cd, NULL);

	return r;
}

int crypt_deactivate(struct crypt_device *cd, const char *name)
{
	char *key_desc;
	struct crypt_device *fake_cd = NULL;
	const char *namei = NULL;
	struct crypt_dm_active_device dmd = {};
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
			key_desc = crypt_get_device_key_description(name);

			if (crypt_get_integrity_tag_size(cd)) {
				r = dm_query_device(cd, name, DM_ACTIVE_DEVICE, &dmd);
				if (r >= 0)
					namei = device_dm_name(dmd.data_device);
			}

			if (isTCRYPT(cd->type))
				r = TCRYPT_deactivate(cd, name);
			else
				r = dm_remove_device(cd, name, 0, 0);
			if (r < 0 && crypt_status(cd, name) == CRYPT_BUSY) {
				log_err(cd, _("Device %s is still in use.\n"), name);
				r = -EBUSY;
			} else if (namei) {
				log_dbg("Deactivating integrity device %s.", namei);
				r = dm_remove_device(cd, namei, 0, 0);
			}
			if (!r && crypt_drop_keyring_key(cd, key_desc))
				log_err(cd, _("Failed to drop device key stored in kernel keyring.\n"));
			free(key_desc);
			break;
		case CRYPT_INACTIVE:
			log_err(cd, _("Device %s is not active.\n"), name);
			r = -ENODEV;
			break;
		default:
			log_err(cd, _("Invalid device %s.\n"), name);
			r = -EINVAL;
	}

	device_free(dmd.data_device);
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
	} else if (isLUKS1(cd->type)) {
		r = LUKS_open_key_with_hdr(keyslot, passphrase,
					passphrase_size, &cd->u.luks1.hdr, &vk, cd);
	} else if (isLUKS2(cd->type)) {
		r = LUKS2_keyslot_open(cd, keyslot, 0, passphrase,
					passphrase_size, &vk);
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

	if (isLUKS1(cd->type))
		r = LUKS_verify_volume_key(&cd->u.luks1.hdr, vk);
	else if (isLUKS2(cd->type))
		r = LUKS2_digest_verify(cd, &cd->u.luks2.hdr, vk, CRYPT_ANY_SLOT);

	if (r == -EPERM)
		log_err(cd, _("Volume key does not match the volume.\n"));

	crypt_free_volume_key(vk);

	return r;
}

void crypt_set_iteration_time(struct crypt_device *cd, uint64_t iteration_time_ms)
{
	int r = 0;
	struct crypt_pbkdf_type tmp;

	if (!cd)
		return;

	if (isLUKS2(cd->type)) {
		if (iteration_time_ms > UINT32_MAX)
			iteration_time_ms = DEFAULT_LUKS2_ITER_TIME;

		tmp = *crypt_get_pbkdf_type(cd);
		tmp.time_ms = (uint32_t)iteration_time_ms;

		r = crypt_set_pbkdf_type(cd, &tmp);
	} else {
		if (iteration_time_ms > UINT32_MAX)
			iteration_time_ms = DEFAULT_LUKS1_ITER_TIME;
		cd->pbkdf.time_ms = (uint32_t)iteration_time_ms;
		cd->iter_time_set = 1;
	}

	if (!r)
		log_dbg("Iteration time set to %" PRIu64 " miliseconds.", iteration_time_ms);
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

int crypt_set_pbkdf_type(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf)
{
	int r;

	if (!cd || !isLUKS2(cd->type))
		return -EINVAL;

	if (!pbkdf) {
		log_dbg("Resetting pbkdf type to default");
		cd->iter_time_set = 0;
		return init_pbkdf_type(cd, NULL);
	}

	log_dbg("PBKDF %s, hash %s, time_ms %u, max_memory_kb %u, parallel_threads %u.",
		pbkdf->type ?: "(none)", pbkdf->hash ?: "(none)", pbkdf->time_ms,
		pbkdf->max_memory_kb, pbkdf->parallel_threads);

	if (verify_pbkdf_params(cd, pbkdf))
		return -EINVAL;

	r = init_pbkdf_type(cd, pbkdf);
	if (!r)
		cd->iter_time_set = 1;

	return r;
}

const struct crypt_pbkdf_type *crypt_get_pbkdf_type(struct crypt_device *cd)
{
	return cd && (isLUKS2(cd->type) || isLUKS1(cd->type)) ? &cd->pbkdf : NULL;
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
	free(CONST_CAST(void*)dmd.u.crypt.integrity);
	return r;
}

const char *crypt_get_cipher(struct crypt_device *cd)
{
	if (isPLAIN(cd->type))
		return cd->u.plain.cipher;

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.cipherName;

	if (isLUKS2(cd->type))
		return cd->u.luks2.cipher;

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

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.cipherMode;

	if (isLUKS2(cd->type))
		return cd->u.luks2.cipher_mode;

	if (isLOOPAES(cd->type))
		return cd->u.loopaes.cipher_mode;

	if (isTCRYPT(cd->type))
		return cd->u.tcrypt.params.mode;

	if (!cd->type && !_init_by_name_crypt_none(cd))
		return cd->u.none.cipher_mode;

	return NULL;
}

const char *crypt_get_integrity(struct crypt_device *cd)
{
	if (isINTEGRITY(cd->type))
		return cd->u.integrity.params.integrity;

	if (isLUKS2(cd->type))
		return LUKS2_get_integrity(&cd->u.luks2.hdr, 0);

	return NULL;
}

int crypt_get_integrity_key_size(struct crypt_device *cd)
{
	if (isINTEGRITY(cd->type))
		return INTEGRITY_key_size(cd);

	if (isLUKS2(cd->type))
		return INTEGRITY_key_size(cd);

	return 0;
}

int crypt_get_integrity_tag_size(struct crypt_device *cd)
{
	if (isINTEGRITY(cd->type))
		return cd->u.integrity.params.tag_size;

	if (isLUKS2(cd->type))
		return INTEGRITY_tag_size(cd, crypt_get_integrity(cd),
					  crypt_get_cipher_mode(cd));
	return 0;
}

uint64_t crypt_get_integrity_sectors(struct crypt_device *cd)
{
	uint64_t sectors;

	if (!isINTEGRITY(cd->type) && !isLUKS2(cd->type))
		return 0;

	if (INTEGRITY_data_sectors(cd, crypt_data_device(cd),
		crypt_get_data_offset(cd) * SECTOR_SIZE, &sectors) < 0)
		return 0;

	return sectors;
}

int crypt_get_sector_size(struct crypt_device *cd)
{
	if (isINTEGRITY(cd->type))
		return cd->u.integrity.params.sector_size;

	if (isLUKS2(cd->type))
		return LUKS2_get_sector_size(&cd->u.luks2.hdr);

	return SECTOR_SIZE;
}

const char *crypt_get_cipher_segment(struct crypt_device *cd, int segment)
{
	if (isLUKS2(cd->type))
		return LUKS2_get_cipher(&cd->u.luks2.hdr, segment);

	return NULL;
}

const char *crypt_get_uuid(struct crypt_device *cd)
{
	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.uuid;

	if (isLUKS2(cd->type))
		return cd->u.luks2.hdr.uuid;

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

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.keyBytes;

	if (isLUKS2(cd->type))
		return LUKS2_get_volume_key_size(&cd->u.luks2.hdr, 0);

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

	if (isLUKS1(cd->type))
		return cd->u.luks1.hdr.payloadOffset;

	if (isLUKS2(cd->type))
		return LUKS2_get_data_offset(&cd->u.luks2.hdr);

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

	if (isLUKS1(cd->type))
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
	if (onlyLUKS(cd) < 0)
		return -EINVAL;

	if (isLUKS1(cd->type))
		return LUKS_keyslot_area(&cd->u.luks1.hdr, keyslot, offset, length);
	else if(isLUKS2(cd->type))
		return LUKS2_keyslot_area(&cd->u.luks2.hdr, keyslot, offset, length);

	return -EINVAL;
}

crypt_keyslot_priority crypt_keyslot_get_priority(struct crypt_device *cd, int keyslot)
{
	if (!cd)
		return CRYPT_SLOT_PRIORITY_INVALID;

	if (keyslot < 0 || keyslot > crypt_keyslot_max(cd->type))
		return CRYPT_SLOT_PRIORITY_INVALID;

	if (isLUKS1(cd->type))
		return CRYPT_SLOT_PRIORITY_NORMAL;

	if (isLUKS2(cd->type))
		return LUKS2_keyslot_priority_get(cd, &cd->u.luks2.hdr, keyslot);

	return CRYPT_SLOT_PRIORITY_INVALID;
}

int crypt_keyslot_set_priority(struct crypt_device *cd, int keyslot, crypt_keyslot_priority priority)
{
	log_dbg("Setting keyslot %d to priority %d.", keyslot, priority);

	if (!cd || priority == CRYPT_SLOT_PRIORITY_INVALID)
		return -EINVAL;

	if (keyslot < 0 || keyslot > crypt_keyslot_max(cd->type))
		return -EINVAL;

	if (isLUKS2(cd->type))
		return LUKS2_keyslot_priority_set(cd, &cd->u.luks2.hdr, keyslot, priority, 1);

	return -EINVAL;
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

	if (dmd.target != DM_CRYPT &&
	    dmd.target != DM_VERITY &&
	    dmd.target != DM_INTEGRITY)
		return -ENOTSUP;

	if (cd && isTCRYPT(cd->type)) {
		cad->offset	= TCRYPT_get_data_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);
		cad->iv_offset	= TCRYPT_get_iv_offset(cd, &cd->u.tcrypt.hdr, &cd->u.tcrypt.params);
	} else if (dmd.target == DM_CRYPT) {
		cad->offset	= dmd.u.crypt.offset;
		cad->iv_offset	= dmd.u.crypt.iv_offset;
	}
	cad->size	= dmd.size;
	cad->flags	= dmd.flags;

	return 0;
}

int crypt_convert(struct crypt_device *cd,
		  const char *type,
		  void *params)
{
	struct luks_phdr hdr1;
	struct luks2_hdr hdr2;
	int r;

	if (isLUKS1(cd->type) && isLUKS2(type))
		r = LUKS2_luks1_to_luks2(cd, &cd->u.luks1.hdr, &hdr2);
	else if (isLUKS2(cd->type) && isLUKS1(type))
		r = LUKS2_luks2_to_luks1(cd, &cd->u.luks2.hdr, &hdr1);
	else
		return -EINVAL;

	if (r < 0)
		return r;

	crypt_free_type(cd);

	return crypt_load(cd, type, params);
}

/* Internall access function to header pointer */
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

static int check_kernel_keyring_available(void)
{
	static unsigned _checked = 0;

	if (!_checked) {
		_kernel_keyring_supported = keyring_check();
		_checked = 1;
	}

	return _kernel_keyring_supported;
}

int crypt_use_keyring_for_vk(const struct crypt_device *cd)
{
	/* dm backend must be initialised */
	if (!cd || !isLUKS2(cd->type))
		return 0;

	return _vk_via_keyring && check_kernel_keyring_available();
}

/*
 * Token handling
 */
int crypt_activate_by_token(struct crypt_device *cd,
	const char *name, int token, void *usrptr, uint32_t flags)
{
	int r;

	log_dbg("Activating volume %s by token %d.", name ?: "[none]", token);

	if (!isLUKS2(cd->type))
		return -EINVAL;

	if (token == CRYPT_ANY_TOKEN)
		r = LUKS2_token_open_and_activate_any(cd, &cd->u.luks2.hdr, name, flags);
	else
		r = LUKS2_token_open_and_activate(cd, &cd->u.luks2.hdr, token, name, flags, usrptr);

	if (r < 0)
		crypt_drop_keyring_key(cd, NULL);

	return r;
}

int crypt_token_json_get(struct crypt_device *cd, int token, const char **json)
{
	log_dbg("Requesting JSON for token %d.", token);

	if (!isLUKS2(cd->type))
		return -EINVAL;

	return LUKS2_token_json_get(cd, &cd->u.luks2.hdr, token, json);
}

int crypt_token_json_set(struct crypt_device *cd, int token, const char *json)
{
	log_dbg("Updating JSON for token %d.", token);

	if (!isLUKS2(cd->type))
		return -EINVAL;

	return LUKS2_token_create(cd, &cd->u.luks2.hdr, token, json, 1);
}

int crypt_token_assign_keyslot(struct crypt_device *cd, int token, int keyslot)
{
	if (!isLUKS2(cd->type))
		return -EINVAL;

	return LUKS2_token_assign(cd, &cd->u.luks2.hdr, token, keyslot, 1, 1);
}

int crypt_token_unassign_keyslot(struct crypt_device *cd, int token, int keyslot)
{
	if (!isLUKS2(cd->type))
		return -EINVAL;

	return LUKS2_token_assign(cd, &cd->u.luks2.hdr, token, keyslot, 0, 1);
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

int crypt_volume_key_keyring(struct crypt_device *cd, int enable)
{
	_vk_via_keyring = enable ? 1 : 0;
	return 0;
}

int crypt_activate_by_keyring(struct crypt_device *cd,
			      const char *name,
			      const char *key_description,
			      int keyslot,
			      uint32_t flags)
{
	char *passphrase;
	size_t passphrase_size;
	crypt_status_info ci;
	int r;

	log_dbg("%s volume %s [keyslot %d] using passphrase in keyring key %s.",
		name ? "Activating" : "Checking", name ?: "", keyslot, key_description ?: "none");

	if (!key_description)
		return -EINVAL;

	if (!check_kernel_keyring_available()) {
		log_err(cd, _("Kernel keyring is not supported by the kernel.\n"));
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

	if (keyring_get_passphrase(key_description, &passphrase, &passphrase_size)) {
		log_err(cd, _("Failed to read passphrase from keyring key %s"), key_description);
		return -EINVAL;
	}

	r = _activate_by_passphrase(cd, name, keyslot, passphrase, passphrase_size, flags);

	crypt_memzero(passphrase, passphrase_size);
	free(passphrase);

	return r;
}

int crypt_persistent_flags_set(struct crypt_device *cd, uint32_t flags)
{
	if (!isLUKS2(cd->type))
		return -EINVAL;

	return LUKS2_config_set_flags(cd, &cd->u.luks2.hdr, flags);
}

int crypt_keyslot_add_by_volume_key_assign(struct crypt_device *cd,
	int keyslot,
	const char *volume_key,
	size_t volume_key_size,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags)
{
	int r;
	digests_t digests = { -1 };
	struct volume_key *vk = NULL;

	log_dbg("Adding new keyslot %d with volume key %sassigned to crypt segment.",
		keyslot, flags & CRYPT_VOLUME_KEY_NO_SEGMENT ? "un" : "");

	r = onlyLUKS2(cd);
	if (r < 0)
		return r;

	if (!passphrase)
		return -EINVAL;

	r = keyslot_verify_or_find_empty(cd, &keyslot);
	if (r < 0)
		return r;

	if (volume_key)
		vk = crypt_alloc_volume_key(volume_key_size, volume_key);
	else if (cd->volume_key)
		vk = crypt_alloc_volume_key(cd->volume_key->keylength, cd->volume_key->key);
	else if (flags & CRYPT_VOLUME_KEY_NO_SEGMENT)
		vk = crypt_generate_volume_key(cd, volume_key_size);

	if (!vk)
		return -ENOMEM;

	/* no segment means we're going to store key without assigned segment (unused in dm-crypt) */
	if (flags & CRYPT_VOLUME_KEY_NO_SEGMENT)
		r = digests[0] = LUKS2_digest_create(cd, "pbkdf2", &cd->u.luks2.hdr, vk);
	else
		r = LUKS2_digests_verify_by_segment(cd, &cd->u.luks2.hdr, 0, vk, digests);

	if (r < 0) {
		log_err(cd, _("Volume key does not match the volume.\n"));
		goto out;
	}

	r = LUKS2_digests_assign(cd, &cd->u.luks2.hdr, keyslot, digests, 1, 0);
	if (r < 0) {
		log_err(cd, _("Failed to assign keyslot %d to digests.\n"), keyslot);
		goto out;
	}

	r = LUKS2_keyslot_store(cd,  &cd->u.luks2.hdr, keyslot,
				passphrase, passphrase_size, vk);
out:
	crypt_free_volume_key(vk);
	if (r < 0) {
		_luks2_reload(cd);
		return r;
	}
	return keyslot;
}
