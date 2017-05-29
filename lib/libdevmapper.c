/*
 * libdevmapper - device-mapper backend for cryptsetup
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

#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <libdevmapper.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <uuid/uuid.h>
#include <sys/stat.h>

#include "internal.h"

#define DM_UUID_LEN		129
#define DM_UUID_PREFIX		"CRYPT-"
#define DM_UUID_PREFIX_LEN	6
#define DM_CRYPT_TARGET		"crypt"
#define DM_VERITY_TARGET	"verity"
#define DM_INTEGRITY_TARGET	"integrity"
#define RETRY_COUNT		5

/* Set if dm-crypt version was probed */
static int _dm_crypt_checked = 0;
static int _quiet_log = 0;
static uint32_t _dm_crypt_flags = 0;

static struct crypt_device *_context = NULL;
static int _dm_use_count = 0;

/* Check if we have DM flag to instruct kernel to force wipe buffers */
#if !HAVE_DECL_DM_TASK_SECURE_DATA
static int dm_task_secure_data(struct dm_task *dmt) { return 1; }
#endif

/* Compatibility for old device-mapper without udev support */
#if HAVE_DECL_DM_UDEV_DISABLE_DISK_RULES_FLAG
#define CRYPT_TEMP_UDEV_FLAGS	DM_UDEV_DISABLE_SUBSYSTEM_RULES_FLAG | \
				DM_UDEV_DISABLE_DISK_RULES_FLAG | \
				DM_UDEV_DISABLE_OTHER_RULES_FLAG
#define _dm_task_set_cookie	dm_task_set_cookie
#define _dm_udev_wait		dm_udev_wait
#else
#define CRYPT_TEMP_UDEV_FLAGS	0
static int _dm_task_set_cookie(struct dm_task *dmt, uint32_t *cookie, uint16_t flags) { return 0; }
static int _dm_udev_wait(uint32_t cookie) { return 0; };
#endif

static int _dm_use_udev(void)
{
#ifdef USE_UDEV /* cannot be enabled if devmapper is too old */
	return dm_udev_get_sync_support();
#else
	return 0;
#endif
}

__attribute__((format(printf, 4, 5)))
static void set_dm_error(int level,
			 const char *file __attribute__((unused)),
			 int line __attribute__((unused)),
			 const char *f, ...)
{
	char *msg = NULL;
	va_list va;

	va_start(va, f);
	if (vasprintf(&msg, f, va) > 0) {
		if (level < 4 && !_quiet_log) {
			log_err(_context, "%s", msg);
			log_err(_context, "\n");
		} else {
			/* We do not use DM visual stack backtrace here */
			if (strncmp(msg, "<backtrace>", 11))
				log_dbg("%s", msg);
		}
	}
	free(msg);
	va_end(va);
}

static int _dm_simple(int task, const char *name, int udev_wait);

static int _dm_satisfies_version(unsigned target_maj, unsigned target_min,
				 unsigned actual_maj, unsigned actual_min)
{
	if (actual_maj > target_maj)
		return 1;

	if (actual_maj == target_maj && actual_min >= target_min)
		return 1;

	return 0;
}

static void _dm_set_crypt_compat(const char *dm_version, unsigned crypt_maj,
				 unsigned crypt_min, unsigned crypt_patch)
{
	unsigned dm_maj, dm_min, dm_patch;

	if (sscanf(dm_version, "%u.%u.%u", &dm_maj, &dm_min, &dm_patch) != 3)
		dm_maj = dm_min = dm_patch = 0;

	log_dbg("Detected dm-crypt version %i.%i.%i, dm-ioctl version %u.%u.%u.",
		crypt_maj, crypt_min, crypt_patch, dm_maj, dm_min, dm_patch);

	if (_dm_satisfies_version(1, 2, crypt_maj, crypt_min))
		_dm_crypt_flags |= DM_KEY_WIPE_SUPPORTED;
	else
		log_dbg("Suspend and resume disabled, no wipe key support.");

	if (_dm_satisfies_version(1, 10, crypt_maj, crypt_min))
		_dm_crypt_flags |= DM_LMK_SUPPORTED;

	if (_dm_satisfies_version(4, 20, dm_maj, dm_min))
		_dm_crypt_flags |= DM_SECURE_SUPPORTED;

	/* not perfect, 2.6.33 supports with 1.7.0 */
	if (_dm_satisfies_version(1, 8, crypt_maj, crypt_min))
		_dm_crypt_flags |= DM_PLAIN64_SUPPORTED;

	if (_dm_satisfies_version(1, 11, crypt_maj, crypt_min))
		_dm_crypt_flags |= DM_DISCARDS_SUPPORTED;

	if (_dm_satisfies_version(1, 13, crypt_maj, crypt_min))
		_dm_crypt_flags |= DM_TCW_SUPPORTED;

	if (_dm_satisfies_version(1, 14, crypt_maj, crypt_min)) {
		_dm_crypt_flags |= DM_SAME_CPU_CRYPT_SUPPORTED;
		_dm_crypt_flags |= DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED;
	}

	if (_dm_satisfies_version(1, 15, crypt_maj, crypt_min))
		_dm_crypt_flags |= DM_KERNEL_KEYRING_SUPPORTED;

	/* Repeat test if dm-crypt is not present */
	if (crypt_maj > 0)
		_dm_crypt_checked = 1;
}

static void _dm_set_verity_compat(const char *dm_version, unsigned verity_maj,
				   unsigned verity_min, unsigned verity_patch)
{
	if (verity_maj > 0)
		_dm_crypt_flags |= DM_VERITY_SUPPORTED;
	else
		return;
	/*
	 * ignore_corruption, restart_on corruption is available since 1.2 (kernel 4.1)
	 * ignore_zero_blocks since 1.3 (kernel 4.5)
	 * (but some dm-verity targets 1.2 don't support it)
	 * FEC is added in 1.3 as well.
	 */
	if (_dm_satisfies_version(1, 3, verity_maj, verity_min)) {
		_dm_crypt_flags |= DM_VERITY_ON_CORRUPTION_SUPPORTED;
		_dm_crypt_flags |= DM_VERITY_FEC_SUPPORTED;
	}

	log_dbg("Detected dm-verity version %i.%i.%i.",
		verity_maj, verity_min, verity_patch);
}

static void _dm_set_integrity_compat(const char *dm_version, unsigned integrity_maj,
				      unsigned integrity_min, unsigned integrity_patch)
{
	if (integrity_maj > 0)
		_dm_crypt_flags |= DM_INTEGRITY_SUPPORTED;
	else
		return;

	log_dbg("Detected dm-integrity version %i.%i.%i.",
		integrity_maj, integrity_min, integrity_patch);
}

static int _dm_check_versions(void)
{
	struct dm_task *dmt;
	struct dm_versions *target, *last_target;
	char dm_version[16];
	int r = 0;

	if (_dm_crypt_checked)
		return 1;

	/* Shut up DM while checking */
	_quiet_log = 1;

	/* FIXME: add support to DM so it forces crypt target module load here */
	if (!(dmt = dm_task_create(DM_DEVICE_LIST_VERSIONS)))
		goto out;

	if (!dm_task_run(dmt))
		goto out;

	if (!dm_task_get_driver_version(dmt, dm_version, sizeof(dm_version)))
		goto out;

	target = dm_task_get_versions(dmt);
	do {
		last_target = target;
		if (!strcmp(DM_CRYPT_TARGET, target->name)) {
			_dm_set_crypt_compat(dm_version,
					     (unsigned)target->version[0],
					     (unsigned)target->version[1],
					     (unsigned)target->version[2]);
		} else if (!strcmp(DM_VERITY_TARGET, target->name)) {
			_dm_set_verity_compat(dm_version,
					     (unsigned)target->version[0],
					     (unsigned)target->version[1],
					     (unsigned)target->version[2]);
		} else if (!strcmp(DM_INTEGRITY_TARGET, target->name)) {
			_dm_set_integrity_compat(dm_version,
					     (unsigned)target->version[0],
					     (unsigned)target->version[1],
					     (unsigned)target->version[2]);
		} else if (!strcmp(DM_INTEGRITY_TARGET, target->name)) {
			_dm_set_integrity_compat(dm_version,
					     (unsigned)target->version[0],
					     (unsigned)target->version[1],
					     (unsigned)target->version[2]);
		}
		target = (struct dm_versions *)((char *) target + target->next);
	} while (last_target != target);

	r = 1;
	log_dbg("Device-mapper backend running with UDEV support %sabled.",
		_dm_use_udev() ? "en" : "dis");
out:
	if (dmt)
		dm_task_destroy(dmt);

	_quiet_log = 0;
	return r;
}

uint32_t dm_flags(void)
{
	_dm_check_versions();
	return _dm_crypt_flags;
}

/* This doesn't run any kernel checks, just set up userspace libdevmapper */
void dm_backend_init(void)
{
	if (!_dm_use_count++) {
		log_dbg("Initialising device-mapper backend library.");
		dm_log_init(set_dm_error);
		dm_log_init_verbose(10);
	}
}

void dm_backend_exit(void)
{
	if (_dm_use_count && (!--_dm_use_count)) {
		log_dbg("Releasing device-mapper backend.");
		dm_log_init_verbose(0);
		dm_log_init(NULL);
		dm_lib_release();
	}
}

/*
 * libdevmapper is not context friendly, switch context on every DM call.
 * FIXME: this is not safe if called in parallel but neither is DM lib.
 */
static int dm_init_context(struct crypt_device *cd)
{
	_context = cd;
	if (!_dm_check_versions()) {
		if (getuid() || geteuid())
			log_err(cd, _("Cannot initialize device-mapper, "
				      "running as non-root user.\n"));
		else
			log_err(cd, _("Cannot initialize device-mapper. "
				      "Is dm_mod kernel module loaded?\n"));
		_context = NULL;
		return -ENOTSUP;
	}
	return 0;
}
static void dm_exit_context(void)
{
	_context = NULL;
}

/* Return path to DM device */
char *dm_device_path(const char *prefix, int major, int minor)
{
	struct dm_task *dmt;
	const char *name;
	char path[PATH_MAX];

	if (!(dmt = dm_task_create(DM_DEVICE_STATUS)))
		return NULL;
	if (!dm_task_set_minor(dmt, minor) ||
	    !dm_task_set_major(dmt, major) ||
	    !dm_task_run(dmt) ||
	    !(name = dm_task_get_name(dmt))) {
		dm_task_destroy(dmt);
		return NULL;
	}

	if (snprintf(path, sizeof(path), "%s%s", prefix ?: "", name) < 0)
		path[0] = '\0';

	dm_task_destroy(dmt);

	return strdup(path);
}

static void hex_key(char *hexkey, size_t key_size, const char *key)
{
	unsigned i;

	for(i = 0; i < key_size; i++)
		sprintf(&hexkey[i * 2], "%02x", (unsigned char)key[i]);
}

/* get string length for key_size written in decimal system */
static size_t get_key_size_strlen(size_t key_size)
{
	size_t ret = 1;

	while ((key_size /= 10))
		ret++;

	return ret;
}

#define CLEN    64   /* 2*MAX_CIPHER_LEN */
#define CLENS  "63"  /* for sscanf length + '\0' */
#define CAPIL  144   /* should be enough to fit whole capi string */
#define CAPIS "143"  /* for sscanf of crypto API string + 16  + \0 */

static int cipher_c2dm(const char *org_c, const char *org_i, unsigned tag_size,
		       char *c_dm, int c_dm_size,
		       char *i_dm, int i_dm_size)
{
	int c_size = 0, i_size = 0, i;
	char cipher[CLEN], mode[CLEN], iv[CLEN], tmp[CLEN];
	char capi[CAPIL];

	if (!c_dm || !c_dm_size || !i_dm || !i_dm_size)
		return -EINVAL;

	i = sscanf(org_c, "%" CLENS "[^-]-%" CLENS "s", cipher, tmp);
	if (i != 2)
		return -EINVAL;

	i = sscanf(tmp, "%" CLENS "[^-]-%" CLENS "s", mode, iv);
	if (i == 1) {
		strncpy(iv, mode, CLEN);
		*mode = '\0';
		if (snprintf(capi, sizeof(capi), "%s", cipher) < 0)
			return -EINVAL;
	} else if (i == 2) {
		if (snprintf(capi, sizeof(capi), "%s(%s)", mode, cipher) < 0)
			return -EINVAL;
	} else
		return -EINVAL;

	if (!org_i) {
		/* legacy mode: CIPHER-MODE-IV*/
		i_size = snprintf(i_dm, i_dm_size, "%s", "");
		c_size = snprintf(c_dm, c_dm_size, "%s", org_c);
	} else if (!strcmp(org_i, "none")) {
		/* IV only: capi:MODE(CIPHER)-IV */
		i_size = snprintf(i_dm, i_dm_size, " integrity:%u:none", tag_size);
		c_size = snprintf(c_dm, c_dm_size, "capi:%s-%s", capi, iv);
	} else if (!strcmp(org_i, "aead") && !strcmp(mode, "ccm")) {
		/* CCM AEAD: capi:rfc4309(MODE(CIPHER))-IV */
		i_size = snprintf(i_dm, i_dm_size, " integrity:%u:aead", tag_size);
		c_size = snprintf(c_dm, c_dm_size, "capi:rfc4309(%s)-%s", capi, iv);
	} else if (!strcmp(org_i, "aead")) {
		/* AEAD: capi:MODE(CIPHER))-IV */
		i_size = snprintf(i_dm, i_dm_size, " integrity:%u:aead", tag_size);
		c_size = snprintf(c_dm, c_dm_size, "capi:%s-%s", capi, iv);
	} else if (!strcmp(org_i, "poly1305")) {
		/* POLY1305 AEAD: capi:rfc7539(MODE(CIPHER),POLY1305)-IV */
		i_size = snprintf(i_dm, i_dm_size, " integrity:%u:aead", tag_size);
		c_size = snprintf(c_dm, c_dm_size, "capi:rfc7539(%s,poly1305)-%s", capi, iv);
	} else {
		/* other AEAD: capi:authenc(<AUTH>,MODE(CIPHER))-IV */
		i_size = snprintf(i_dm, i_dm_size, " integrity:%u:aead", tag_size);
		c_size = snprintf(c_dm, c_dm_size, "capi:authenc(%s,%s)-%s", org_i, capi, iv);
	}

	if (c_size < 0 || c_size == c_dm_size)
		return -EINVAL;
	if (i_size < 0 || i_size == i_dm_size)
		return -EINVAL;

	return 0;
}

static int cipher_dm2c(char **org_c, char **org_i, const char *c_dm, const char *i_dm)
{
	char cipher[CLEN], mode[CLEN], iv[CLEN], auth[CLEN];
	char tmp[CAPIL], capi[CAPIL];
	size_t len;
	int i;

	if (!c_dm)
		return -EINVAL;

	/* legacy mode */
	if (strncmp(c_dm, "capi:", 4)) {
		if (!(*org_c = strdup(c_dm)))
			return -ENOMEM;
		*org_i = NULL;
		return 0;
	}

	/* modes with capi: prefix */
	i = sscanf(c_dm, "capi:%" CAPIS "[^-]-%" CLENS "s", tmp, iv);
	if (i != 2)
		return -EINVAL;

	len = strlen(tmp);
	if (len < 2)
		return -EINVAL;

	if (tmp[len-1] == ')')
		tmp[len-1] = '\0';

	if (sscanf(tmp, "rfc4309(%" CAPIS "s", capi) == 1) {
		if (!(*org_i = strdup("aead")))
			return -ENOMEM;
	} else if (sscanf(tmp, "rfc7539(%" CAPIS "[^,],%" CLENS "s", capi, auth) == 2) {
		if (!(*org_i = strdup(auth)))
			return -ENOMEM;
	} else if (sscanf(tmp, "authenc(%" CLENS "[^,],%" CAPIS "s", auth, capi) == 2) {
		if (!(*org_i = strdup(auth)))
			return -ENOMEM;
	} else {
		if (i_dm) {
			if (!(*org_i = strdup(i_dm)))
				return -ENOMEM;
		} else
			*org_i = NULL;
		strncpy(capi, tmp, sizeof(capi));
	}

	i = sscanf(capi, "%" CLENS "[^(](%" CLENS "[^)])", mode, cipher);
	if (i == 2)
		snprintf(tmp, sizeof(tmp), "%s-%s-%s", cipher, mode, iv);
	else
		snprintf(tmp, sizeof(tmp), "%s-%s", capi, iv);

	if (!(*org_c = strdup(tmp))) {
		free(*org_i);
		*org_i = NULL;
		return -ENOMEM;
	}

	return 0;
}

/* https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt */
static char *get_dm_crypt_params(struct crypt_dm_active_device *dmd, uint32_t flags)
{
	int r, max_size, null_cipher = 0, num_options = 0, keystr_len = 0;
	char *params, *hexkey;
	char sector_feature[32], features[256], integrity_dm[256], cipher_dm[256];

	if (!dmd)
		return NULL;

	r = cipher_c2dm(dmd->u.crypt.cipher, dmd->u.crypt.integrity, dmd->u.crypt.tag_size,
			cipher_dm, sizeof(cipher_dm), integrity_dm, sizeof(integrity_dm));
	if (r < 0)
		return NULL;

	if (flags & CRYPT_ACTIVATE_ALLOW_DISCARDS)
		num_options++;
	if (flags & CRYPT_ACTIVATE_SAME_CPU_CRYPT)
		num_options++;
	if (flags & CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS)
		num_options++;
	if (dmd->u.crypt.integrity)
		num_options++;

	if (dmd->u.crypt.sector_size != SECTOR_SIZE) {
		num_options++;
		snprintf(sector_feature, sizeof(sector_feature), " sector_size:%u", dmd->u.crypt.sector_size);
	} else
		*sector_feature = '\0';

	if (num_options) {
		snprintf(features, sizeof(features)-1, " %d%s%s%s%s%s", num_options,
		(flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) ? " allow_discards" : "",
		(flags & CRYPT_ACTIVATE_SAME_CPU_CRYPT) ? " same_cpu_crypt" : "",
		(flags & CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS) ? " submit_from_crypt_cpus" : "",
		sector_feature, integrity_dm);
	} else
		*features = '\0';

	if (!strncmp(cipher_dm, "cipher_null-", 12))
		null_cipher = 1;

	if (flags & CRYPT_ACTIVATE_KEYRING_KEY) {
		keystr_len = strlen(dmd->u.crypt.vk->key_description) + get_key_size_strlen(dmd->u.crypt.vk->keylength) + 9;
		hexkey = crypt_safe_alloc(keystr_len);
	} else
		hexkey = crypt_safe_alloc(null_cipher ? 2 : (dmd->u.crypt.vk->keylength * 2 + 1));

	if (!hexkey)
		return NULL;

	if (null_cipher)
		strncpy(hexkey, "-", 2);
	else if (flags & CRYPT_ACTIVATE_KEYRING_KEY) {
		r = snprintf(hexkey, keystr_len, ":%zu:logon:%s", dmd->u.crypt.vk->keylength, dmd->u.crypt.vk->key_description);
		if (r < 0 || r >= keystr_len) {
			params = NULL;
			goto out;
		}
	} else
		hex_key(hexkey, dmd->u.crypt.vk->keylength, dmd->u.crypt.vk->key);

	max_size = strlen(hexkey) + strlen(cipher_dm) +
		   strlen(device_block_path(dmd->data_device)) +
		   strlen(features) + 64;
	params = crypt_safe_alloc(max_size);
	if (!params)
		goto out;

	r = snprintf(params, max_size, "%s %s %" PRIu64 " %s %" PRIu64 "%s",
		     cipher_dm, hexkey, dmd->u.crypt.iv_offset,
		     device_block_path(dmd->data_device), dmd->u.crypt.offset,
		     features);
	if (r < 0 || r >= max_size) {
		crypt_safe_free(params);
		params = NULL;
	}
out:
	crypt_safe_free(hexkey);
	return params;
}

/* https://gitlab.com/cryptsetup/cryptsetup/wikis/DMVerity */
static char *get_dm_verity_params(struct crypt_params_verity *vp,
				   struct crypt_dm_active_device *dmd, uint32_t flags)
{
	int max_size, r, num_options = 0;
	char *params = NULL, *hexroot = NULL, *hexsalt = NULL;
	char features[256], fec_features[256];

	if (!vp || !dmd)
		return NULL;

	/* These flags are not compatible */
	if ((flags & CRYPT_ACTIVATE_IGNORE_CORRUPTION) &&
	    (flags & CRYPT_ACTIVATE_RESTART_ON_CORRUPTION))
		flags &= ~CRYPT_ACTIVATE_IGNORE_CORRUPTION;

	if (flags & CRYPT_ACTIVATE_IGNORE_CORRUPTION)
		num_options++;
	if (flags & CRYPT_ACTIVATE_RESTART_ON_CORRUPTION)
		num_options++;
	if (flags & CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS)
		num_options++;

	if (dmd->u.verity.fec_device) {
		num_options += 8;
		snprintf(fec_features, sizeof(fec_features)-1,
			 " use_fec_from_device %s fec_start %" PRIu64 " fec_blocks %" PRIu64 " fec_roots %" PRIu32,
			 device_block_path(dmd->u.verity.fec_device), dmd->u.verity.fec_offset,
			 vp->data_size + dmd->u.verity.hash_blocks, vp->fec_roots);
	} else
		*fec_features = '\0';

	if (num_options)
		snprintf(features, sizeof(features)-1, " %d%s%s%s", num_options,
		(flags & CRYPT_ACTIVATE_IGNORE_CORRUPTION) ? " ignore_corruption" : "",
		(flags & CRYPT_ACTIVATE_RESTART_ON_CORRUPTION) ? " restart_on_corruption" : "",
		(flags & CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS) ? " ignore_zero_blocks" : "");
	else
		*features = '\0';

	hexroot = crypt_safe_alloc(dmd->u.verity.root_hash_size * 2 + 1);
	if (!hexroot)
		goto out;
	hex_key(hexroot, dmd->u.verity.root_hash_size, dmd->u.verity.root_hash);

	hexsalt = crypt_safe_alloc(vp->salt_size ? vp->salt_size * 2 + 1 : 2);
	if (!hexsalt)
		goto out;
	if (vp->salt_size)
		hex_key(hexsalt, vp->salt_size, vp->salt);
	else
		strncpy(hexsalt, "-", 2);

	max_size = strlen(hexroot) + strlen(hexsalt) +
		   strlen(device_block_path(dmd->data_device)) +
		   strlen(device_block_path(dmd->u.verity.hash_device)) +
		   strlen(vp->hash_name) + strlen(features) + strlen(fec_features) + 128;

	params = crypt_safe_alloc(max_size);
	if (!params)
		goto out;

	r = snprintf(params, max_size,
		     "%u %s %s %u %u %" PRIu64 " %" PRIu64 " %s %s %s%s%s",
		     vp->hash_type, device_block_path(dmd->data_device),
		     device_block_path(dmd->u.verity.hash_device),
		     vp->data_block_size, vp->hash_block_size,
		     vp->data_size, dmd->u.verity.hash_offset,
		     vp->hash_name, hexroot, hexsalt, features, fec_features);
	if (r < 0 || r >= max_size) {
		crypt_safe_free(params);
		params = NULL;
	}
out:
	crypt_safe_free(hexroot);
	crypt_safe_free(hexsalt);
	return params;

}

static char *get_dm_integrity_params(struct crypt_dm_active_device *dmd, uint32_t flags)
{
	int r, max_size, num_options = 0;
	char *params, *hexkey, mode;
	char features[256], feature[256];

	if (!dmd)
		return NULL;

	max_size = strlen(device_block_path(dmd->data_device)) +
			(dmd->u.integrity.vk ? dmd->u.integrity.vk->keylength * 2 : 0) +
			(dmd->u.integrity.journal_integrity_key ? dmd->u.integrity.journal_crypt_key->keylength * 2 : 0) +
			(dmd->u.integrity.journal_crypt_key ? dmd->u.integrity.journal_crypt_key->keylength * 2 : 0) +
			(dmd->u.integrity.integrity ? strlen(dmd->u.integrity.integrity) : 0) +
			(dmd->u.integrity.journal_integrity ? strlen(dmd->u.integrity.journal_integrity) : 0) +
			(dmd->u.integrity.journal_crypt ? strlen(dmd->u.integrity.journal_crypt) : 0) +
			128;

	params = crypt_safe_alloc(max_size);
	if (!params)
		return NULL;

	*features = '\0';
	if (dmd->u.integrity.journal_size) {
		num_options++;
		snprintf(feature, sizeof(feature), "journal_sectors:%u ",
			 (unsigned)(dmd->u.integrity.journal_size / SECTOR_SIZE));
		strncat(features, feature, sizeof(features) - strlen(features) - 1);
	}
	if (dmd->u.integrity.journal_watermark) {
		num_options++;
		snprintf(feature, sizeof(feature), "journal_watermark:%u ",
			 dmd->u.integrity.journal_watermark);
		strncat(features, feature, sizeof(features) - strlen(features) - 1);
	}
	if (dmd->u.integrity.journal_commit_time) {
		num_options++;
		snprintf(feature, sizeof(feature), "commit_time:%u ",
			 dmd->u.integrity.journal_commit_time);
		strncat(features, feature, sizeof(features) - strlen(features) - 1);
	}
	if (dmd->u.integrity.interleave_sectors) {
		num_options++;
		snprintf(feature, sizeof(feature), "interleave_sectors:%u ",
			 dmd->u.integrity.interleave_sectors);
		strncat(features, feature, sizeof(features) - strlen(features) - 1);
	}
	if (dmd->u.integrity.sector_size) {
		num_options++;
		snprintf(feature, sizeof(feature), "block_size:%u ",
			 dmd->u.integrity.sector_size);
		strncat(features, feature, sizeof(features) - strlen(features) - 1);
	}
	if (dmd->u.integrity.buffer_sectors) {
		num_options++;
		snprintf(feature, sizeof(feature), "buffer_sectors:%u ",
			 dmd->u.integrity.buffer_sectors);
		strncat(features, feature, sizeof(features) - strlen(features) - 1);
	}
	if (dmd->u.integrity.integrity) {
		num_options++;

		if (dmd->u.integrity.vk) {
			hexkey = crypt_safe_alloc(dmd->u.integrity.vk->keylength * 2 + 1);
			if (!hexkey) {
				crypt_safe_free(params);
				return NULL;
			}
			hex_key(hexkey, dmd->u.integrity.vk->keylength, dmd->u.integrity.vk->key);
		} else
			hexkey = NULL;

		snprintf(feature, sizeof(feature), "internal_hash:%s%s%s ",
			 dmd->u.integrity.integrity, hexkey ? ":" : "", hexkey ?: "");
		strncat(features, feature, sizeof(features) - strlen(features) - 1);
		crypt_safe_free(hexkey);
	}

	if (dmd->u.integrity.journal_integrity) {
		num_options++;

		if (dmd->u.integrity.journal_integrity_key) {
			hexkey = crypt_safe_alloc(dmd->u.integrity.journal_integrity_key->keylength * 2 + 1);
			if (!hexkey) {
				crypt_safe_free(params);
				return NULL;
			}
			hex_key(hexkey, dmd->u.integrity.journal_integrity_key->keylength,
				dmd->u.integrity.journal_integrity_key->key);
		} else
			hexkey = NULL;

		snprintf(feature, sizeof(feature), "journal_mac:%s%s%s ",
			 dmd->u.integrity.journal_integrity, hexkey ? ":" : "", hexkey ?: "");
		strncat(features, feature, sizeof(features) - strlen(features) - 1);
		crypt_safe_free(hexkey);
	}

	if (dmd->u.integrity.journal_crypt) {
		num_options++;

		if (dmd->u.integrity.journal_crypt_key) {
			hexkey = crypt_safe_alloc(dmd->u.integrity.journal_crypt_key->keylength * 2 + 1);
			if (!hexkey) {
				crypt_safe_free(params);
				return NULL;
			}
			hex_key(hexkey, dmd->u.integrity.journal_crypt_key->keylength,
				dmd->u.integrity.journal_crypt_key->key);
		} else
			hexkey = NULL;

		snprintf(feature, sizeof(feature), "journal_crypt:%s%s%s ",
			 dmd->u.integrity.journal_crypt, hexkey ? ":" : "", hexkey ?: "");
		strncat(features, feature, sizeof(features) - strlen(features) - 1);
		crypt_safe_free(hexkey);
	}

	if (flags & CRYPT_ACTIVATE_RECOVERY)
		mode = 'R';
	else if (flags & CRYPT_ACTIVATE_NO_JOURNAL)
		mode = 'D';
	else
		mode = 'J';

	r = snprintf(params, max_size, "%s %" PRIu64 " %d %c %d %s",
		     device_block_path(dmd->data_device), dmd->u.integrity.offset,
		     dmd->u.integrity.tag_size, mode,
		     num_options, *features ? features : "");
	if (r < 0 || r >= max_size) {
		crypt_safe_free(params);
		params = NULL;
	}

	return params;
}

/* DM helpers */
static int _dm_simple(int task, const char *name, int udev_wait)
{
	int r = 0;
	struct dm_task *dmt;
	uint32_t cookie = 0;

	if (!_dm_use_udev())
		udev_wait = 0;

	if (!(dmt = dm_task_create(task)))
		return 0;

	if (name && !dm_task_set_name(dmt, name))
		goto out;

#if HAVE_DECL_DM_TASK_RETRY_REMOVE
	/* Used only in DM_DEVICE_REMOVE */
	if (name && !dm_task_retry_remove(dmt))
		goto out;
#endif
	if (udev_wait && !_dm_task_set_cookie(dmt, &cookie, 0))
		goto out;

	r = dm_task_run(dmt);

	if (udev_wait)
		(void)_dm_udev_wait(cookie);

out:
	dm_task_destroy(dmt);
	return r;
}

static int _error_device(const char *name, size_t size)
{
	struct dm_task *dmt;
	int r = 0;

	if (!(dmt = dm_task_create(DM_DEVICE_RELOAD)))
		return 0;

	if (!dm_task_set_name(dmt, name))
		goto error;

	if (!dm_task_add_target(dmt, UINT64_C(0), size, "error", ""))
		goto error;

	if (!dm_task_set_ro(dmt))
		goto error;

	if (!dm_task_no_open_count(dmt))
		goto error;

	if (!dm_task_run(dmt))
		goto error;

	if (!_dm_simple(DM_DEVICE_RESUME, name, 1)) {
		_dm_simple(DM_DEVICE_CLEAR, name, 0);
		goto error;
	}

	r = 1;

error:
	dm_task_destroy(dmt);
	return r;
}

int dm_remove_device(struct crypt_device *cd, const char *name,
		     int force, uint64_t size)
{
	int r = -EINVAL;
	int retries = force ? RETRY_COUNT : 1;
	int error_target = 0;

	if (!name || (force && !size))
		return -EINVAL;

	if (dm_init_context(cd))
		return -ENOTSUP;

	do {
		r = _dm_simple(DM_DEVICE_REMOVE, name, 1) ? 0 : -EINVAL;
		if (--retries && r) {
			log_dbg("WARNING: other process locked internal device %s, %s.",
				name, retries ? "retrying remove" : "giving up");
			sleep(1);
			if (force && !error_target) {
				/* If force flag is set, replace device with error, read-only target.
				 * it should stop processes from reading it and also removed underlying
				 * device from mapping, so it is usable again.
				 * Force flag should be used only for temporary devices, which are
				 * intended to work inside cryptsetup only!
				 * Anyway, if some process try to read temporary cryptsetup device,
				 * it is bug - no other process should try touch it (e.g. udev).
				 */
				_error_device(name, size);
				error_target = 1;
			}
		}
	} while (r == -EINVAL && retries);

	dm_task_update_nodes();
	dm_exit_context();

	return r;
}

#define UUID_LEN 37 /* 36 + \0, libuuid ... */
/*
 * UUID has format: CRYPT-<devicetype>-[<uuid>-]<device name>
 * CRYPT-PLAIN-name
 * CRYPT-LUKS1-00000000000000000000000000000000-name
 * CRYPT-TEMP-name
 */
static int dm_prepare_uuid(const char *name, const char *type, const char *uuid, char *buf, size_t buflen)
{
	char *ptr, uuid2[UUID_LEN] = {0};
	uuid_t uu;
	unsigned i = 0;

	/* Remove '-' chars */
	if (uuid) {
		if (uuid_parse(uuid, uu) < 0) {
			log_dbg("Requested UUID %s has invalid format.", uuid);
			return 0;
		}

		for (ptr = uuid2, i = 0; i < UUID_LEN; i++)
			if (uuid[i] != '-') {
				*ptr = uuid[i];
				ptr++;
			}
	}

	i = snprintf(buf, buflen, DM_UUID_PREFIX "%s%s%s%s%s",
		type ?: "", type ? "-" : "",
		uuid2[0] ? uuid2 : "", uuid2[0] ? "-" : "",
		name);

	log_dbg("DM-UUID is %s", buf);
	if (i >= buflen)
		log_err(NULL, _("DM-UUID for device %s was truncated.\n"), name);

	return 1;
}

static int _dm_create_device(const char *name, const char *type,
			     struct device *device, uint32_t flags,
			     const char *uuid, uint64_t size,
			     const char *target, char *params, int reload)
{
	struct dm_task *dmt = NULL;
	struct dm_info dmi;
	char dev_uuid[DM_UUID_LEN] = {0};
	int r = -EINVAL;
	uint32_t read_ahead = 0;
	uint32_t cookie = 0;
	uint16_t udev_flags = 0;

	if (!params)
		return -EINVAL;

	if (flags & CRYPT_ACTIVATE_PRIVATE)
		udev_flags = CRYPT_TEMP_UDEV_FLAGS;

	/* All devices must have DM_UUID, only resize on old device is exception */
	if (reload) {
		if (!(dmt = dm_task_create(DM_DEVICE_RELOAD)))
			goto out_no_removal;

		if (!dm_task_set_name(dmt, name))
			goto out_no_removal;
	} else {
		if (!dm_prepare_uuid(name, type, uuid, dev_uuid, sizeof(dev_uuid)))
			goto out_no_removal;

		if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
			goto out_no_removal;

		if (!dm_task_set_name(dmt, name))
			goto out_no_removal;

		if (!dm_task_set_uuid(dmt, dev_uuid))
			goto out_no_removal;
	}

	if ((dm_flags() & DM_SECURE_SUPPORTED) && !dm_task_secure_data(dmt))
		goto out_no_removal;
	if ((flags & CRYPT_ACTIVATE_READONLY) && !dm_task_set_ro(dmt))
		goto out_no_removal;

	if (!dm_task_add_target(dmt, 0, size, target, params))
		goto out_no_removal;

#ifdef DM_READ_AHEAD_MINIMUM_FLAG
	if (device_read_ahead(device, &read_ahead) &&
	    !dm_task_set_read_ahead(dmt, read_ahead, DM_READ_AHEAD_MINIMUM_FLAG))
		goto out_no_removal;
#endif
	/* do not set cookie for DM_DEVICE_RELOAD task */
	if (!reload && _dm_use_udev() && !_dm_task_set_cookie(dmt, &cookie, udev_flags))
		goto out_no_removal;

	if (!dm_task_run(dmt))
		goto out_no_removal;

	if (reload) {
		dm_task_destroy(dmt);
		if (!(dmt = dm_task_create(DM_DEVICE_RESUME)))
			goto out;
		if (!dm_task_set_name(dmt, name))
			goto out;
		if (uuid && !dm_task_set_uuid(dmt, dev_uuid))
			goto out;
		if (_dm_use_udev() && !_dm_task_set_cookie(dmt, &cookie, udev_flags))
			goto out;
		if (!dm_task_run(dmt))
			goto out;
	}

	if (!dm_task_get_info(dmt, &dmi))
		goto out;

	r = 0;
out:
	if (_dm_use_udev()) {
		(void)_dm_udev_wait(cookie);
		cookie = 0;
	}

	if (r < 0 && !reload)
		_dm_simple(DM_DEVICE_REMOVE, name, 1);

out_no_removal:
	if (cookie && _dm_use_udev())
		(void)_dm_udev_wait(cookie);

	if (dmt)
		dm_task_destroy(dmt);

	dm_task_update_nodes();

	/* If code just loaded target module, update versions */
	_dm_check_versions();

	return r;
}

static int check_retry(uint32_t *dmd_flags)
{
	int ret = 0;

	/* If discard not supported try to load without discard */
	if ((*dmd_flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) &&
	    !(dm_flags() & DM_DISCARDS_SUPPORTED)) {
		log_dbg("Discard/TRIM is not supported");
		*dmd_flags = *dmd_flags & ~CRYPT_ACTIVATE_ALLOW_DISCARDS;
		ret = 1;
	}

	/* If kernel keyring is not supported load key directly in dm-crypt */
	if ((*dmd_flags & CRYPT_ACTIVATE_KEYRING_KEY) &&
	    !(dm_flags() & DM_KERNEL_KEYRING_SUPPORTED)) {
		log_dbg("kernel keyring is not supported");
		*dmd_flags = *dmd_flags & ~CRYPT_ACTIVATE_KEYRING_KEY;
		ret = 1;
	}

	return ret;
}

int dm_create_device(struct crypt_device *cd, const char *name,
		     const char *type,
		     struct crypt_dm_active_device *dmd,
		     int reload)
{
	char *table_params = NULL, *target;
	uint32_t dmd_flags;
	int r;

	if (!type)
		return -EINVAL;

	if (dm_init_context(cd))
		return -ENOTSUP;

	dmd_flags = dmd->flags;

	if (dmd->target == DM_CRYPT) {
		table_params = get_dm_crypt_params(dmd, dmd_flags);
		target = DM_CRYPT_TARGET;
	} else if (dmd->target == DM_VERITY) {
		table_params = get_dm_verity_params(dmd->u.verity.vp, dmd, dmd_flags);
		target = DM_VERITY_TARGET;
	} else if (dmd->target == DM_INTEGRITY) {
		table_params = get_dm_integrity_params(dmd, dmd_flags);
		target = DM_INTEGRITY_TARGET;
	} else {
		dm_exit_context();
		return -EINVAL;
	}

	r = _dm_create_device(name, type, dmd->data_device, dmd_flags,
			      dmd->uuid, dmd->size, target, table_params, reload);

	if (!reload && r && dmd->target == DM_CRYPT && check_retry(&dmd_flags)) {
		crypt_safe_free(table_params);
		table_params = get_dm_crypt_params(dmd, dmd_flags);
		r = _dm_create_device(name, type, dmd->data_device, dmd_flags,
				      dmd->uuid, dmd->size, target, table_params, reload);
	}

	if (r == -EINVAL &&
	    dmd_flags & (CRYPT_ACTIVATE_SAME_CPU_CRYPT|CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS) &&
	    !(dm_flags() & (DM_SAME_CPU_CRYPT_SUPPORTED|DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED)))
		log_err(cd, _("Requested dm-crypt performance options are not supported.\n"));

	if (r == -EINVAL && dmd_flags & (CRYPT_ACTIVATE_IGNORE_CORRUPTION|
					  CRYPT_ACTIVATE_RESTART_ON_CORRUPTION|
					  CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS) &&
	    !(dm_flags() & DM_VERITY_ON_CORRUPTION_SUPPORTED))
		log_err(cd, _("Requested dm-verity data corruption handling options are not supported.\n"));

	if (r == -EINVAL && dmd->target == DM_VERITY && dmd->u.verity.fec_device &&
	    !(dm_flags() & DM_VERITY_FEC_SUPPORTED))
		log_err(cd, _("Requested dm-verity FEC options are not supported.\n"));

	crypt_safe_free(table_params);
	dm_exit_context();
	return r;
}

static int dm_status_dmi(const char *name, struct dm_info *dmi,
			  const char *target, char **status_line)
{
	struct dm_task *dmt;
	uint64_t start, length;
	char *target_type, *params = NULL;
	void *next = NULL;
	int r = -EINVAL;

	if (!(dmt = dm_task_create(DM_DEVICE_STATUS)))
		goto out;

	if (!dm_task_set_name(dmt, name))
		goto out;

	if (!dm_task_run(dmt))
		goto out;

	if (!dm_task_get_info(dmt, dmi))
		goto out;

	if (!dmi->exists) {
		r = -ENODEV;
		goto out;
	}

	next = dm_get_next_target(dmt, next, &start, &length,
	                          &target_type, &params);

	if (!target_type || start != 0 || next)
		goto out;

	if (target && strcmp(target_type, target))
		goto out;

	/* for target == NULL check all supported */
	if (!target && (strcmp(target_type, DM_CRYPT_TARGET) &&
			strcmp(target_type, DM_VERITY_TARGET) &&
			strcmp(target_type, DM_INTEGRITY_TARGET)))
		goto out;
	r = 0;
out:
	if (!r && status_line && !(*status_line = strdup(params)))
		r = -ENOMEM;

	if (dmt)
		dm_task_destroy(dmt);

	return r;
}

int dm_status_device(struct crypt_device *cd, const char *name)
{
	int r;
	struct dm_info dmi;
	struct stat st;

	/* libdevmapper is too clever and handles
	 * path argument differenly with error.
	 * Fail early here if parameter is non-existent path.
	 */
	if (strchr(name, '/') && stat(name, &st) < 0)
		return -ENODEV;

	if (dm_init_context(cd))
		return -ENOTSUP;
	r = dm_status_dmi(name, &dmi, NULL, NULL);
	dm_exit_context();
	if (r < 0)
		return r;

	return (dmi.open_count > 0);
}

int dm_status_suspended(struct crypt_device *cd, const char *name)
{
	int r;
	struct dm_info dmi;

	if (dm_init_context(cd))
		return -ENOTSUP;
	r = dm_status_dmi(name, &dmi, DM_CRYPT_TARGET, NULL);
	dm_exit_context();
	if (r < 0)
		return r;

	return dmi.suspended ? 1 : 0;
}

static int _dm_status_verity_ok(const char *name)
{
	int r;
	struct dm_info dmi;
	char *status_line = NULL;

	r = dm_status_dmi(name, &dmi, DM_VERITY_TARGET, &status_line);
	if (r < 0 || !status_line) {
		free(status_line);
		return r;
	}

	log_dbg("Verity volume %s status is %s.", name, status_line ?: "");
	r = status_line[0] == 'V' ? 1 : 0;
	free(status_line);

	return r;
}

int dm_status_verity_ok(struct crypt_device *cd, const char *name)
{
	int r;

	if (dm_init_context(cd))
		return -ENOTSUP;
	r = _dm_status_verity_ok(name);
	dm_exit_context();
	return r;
}

/* FIXME use hex wrapper, user val wrappers for line parsing */
static int _dm_query_crypt(uint32_t get_flags,
			   struct dm_info *dmi,
			   char *params,
			   struct crypt_dm_active_device *dmd)
{
	uint64_t val64;
	char *rcipher, *rintegrity, *key_, *rdevice, *endp, buffer[3], *arg, *key_desc;
	unsigned int i, val;
	int r;
	size_t key_size;

	memset(dmd, 0, sizeof(*dmd));
	dmd->target = DM_CRYPT;
	dmd->u.crypt.sector_size = SECTOR_SIZE;

	rcipher = strsep(&params, " ");
	rintegrity = NULL;

	/* skip */
	key_ = strsep(&params, " ");
	if (!params)
		return -EINVAL;
	val64 = strtoull(params, &params, 10);
	if (*params != ' ')
		return -EINVAL;
	params++;

	dmd->u.crypt.iv_offset = val64;

	/* device */
	rdevice = strsep(&params, " ");
	if (get_flags & DM_ACTIVE_DEVICE) {
		arg = crypt_lookup_dev(rdevice);
		r = device_alloc(&dmd->data_device, arg);
		free(arg);
		if (r < 0 && r != -ENOTBLK)
			return r;
	}

	/*offset */
	if (!params)
		return -EINVAL;
	val64 = strtoull(params, &params, 10);
	dmd->u.crypt.offset = val64;

	dmd->u.crypt.tag_size = 0;

	/* Features section, available since crypt target version 1.11 */
	if (*params) {
		if (*params != ' ')
			return -EINVAL;
		params++;

		/* Number of arguments */
		val64 = strtoull(params, &params, 10);
		if (*params != ' ')
			return -EINVAL;
		params++;

		for (i = 0; i < val64; i++) {
			if (!params)
				return -EINVAL;
			arg = strsep(&params, " ");
			if (!strcasecmp(arg, "allow_discards"))
				dmd->flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;
			else if (!strcasecmp(arg, "same_cpu_crypt"))
				dmd->flags |= CRYPT_ACTIVATE_SAME_CPU_CRYPT;
			else if (!strcasecmp(arg, "submit_from_crypt_cpus"))
				dmd->flags |= CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS;
			else if (sscanf(arg, "integrity:%u:", &val) == 1) {
				dmd->u.crypt.tag_size = val;
				rintegrity = strchr(arg + strlen("integrity:"), ':') + 1;
				if (!rintegrity)
					return -EINVAL;
			} else if (sscanf(arg, "sector_size:%u", &val) == 1) {
				dmd->u.crypt.sector_size = val;
			} else /* unknown option */
				return -EINVAL;
		}

		/* All parameters should be processed */
		if (params)
			return -EINVAL;
	}

	/* cipher */
	if (get_flags & DM_ACTIVE_CRYPT_CIPHER) {
		r = cipher_dm2c(CONST_CAST(char**)&dmd->u.crypt.cipher,
				CONST_CAST(char**)&dmd->u.crypt.integrity,
				rcipher, rintegrity);
		if (r < 0)
			return r;
	}

	/* Never allow to return empty key */
	if ((get_flags & DM_ACTIVE_CRYPT_KEY) && dmi->suspended) {
		log_dbg("Cannot read volume key while suspended.");
		return -EINVAL;
	}

	if (key_[0] == ':')
		dmd->flags |= CRYPT_ACTIVATE_KEYRING_KEY;

	if (get_flags & DM_ACTIVE_CRYPT_KEYSIZE) {
		/* we will trust kernel the key_string is in expected format */
		if (key_[0] == ':') {
			if (sscanf(key_ + 1, "%zu", &key_size) != 1)
				return -EINVAL;
		} else
			key_size = strlen(key_) / 2;

		dmd->u.crypt.vk = crypt_alloc_volume_key(key_size, NULL);
		if (!dmd->u.crypt.vk)
			return -ENOMEM;

		if (get_flags & DM_ACTIVE_CRYPT_KEY) {
			if (key_[0] == ':') {
				key_desc = strdup(strpbrk(key_ + 1, ":") + 1);
				if (!key_desc) {
					crypt_free_volume_key(dmd->u.crypt.vk);
					return -ENOMEM;
				}
				crypt_volume_key_set_description(dmd->u.crypt.vk, key_desc);
			} else {
				buffer[2] = '\0';
				for(i = 0; i < dmd->u.crypt.vk->keylength; i++) {
					memcpy(buffer, &key_[i * 2], 2);
					dmd->u.crypt.vk->key[i] = strtoul(buffer, &endp, 16);
					if (endp != &buffer[2]) {
						crypt_free_volume_key(dmd->u.crypt.vk);
						dmd->u.crypt.vk = NULL;
						return -EINVAL;
					}
				}
			}
		}
	}
	memset(key_, 0, strlen(key_));

	return 0;
}

static int _dm_query_verity(uint32_t get_flags,
			     struct dm_info *dmi,
			     char *params,
			     struct crypt_dm_active_device *dmd)
{
	struct crypt_params_verity *vp = NULL;
	uint32_t val32;
	uint64_t val64;
	ssize_t len;
	char *str, *str2, *arg;
	unsigned int i, features;
	int r;

	if (get_flags & DM_ACTIVE_VERITY_PARAMS)
		vp = dmd->u.verity.vp;

	memset(dmd, 0, sizeof(*dmd));

	dmd->target = DM_VERITY;
	dmd->u.verity.vp = vp;

	/* version */
	val32 = strtoul(params, &params, 10);
	if (*params != ' ')
		return -EINVAL;
	if (vp)
		vp->hash_type = val32;
	params++;

	/* data device */
	str = strsep(&params, " ");
	if (!params)
		return -EINVAL;
	if (get_flags & DM_ACTIVE_DEVICE) {
		str2 = crypt_lookup_dev(str);
		r = device_alloc(&dmd->data_device, str2);
		free(str2);
		if (r < 0 && r != -ENOTBLK)
			return r;
	}

	/* hash device */
	str = strsep(&params, " ");
	if (!params)
		return -EINVAL;
	if (get_flags & DM_ACTIVE_VERITY_HASH_DEVICE) {
		str2 = crypt_lookup_dev(str);
		r = device_alloc(&dmd->u.verity.hash_device, str2);
		free(str2);
		if (r < 0 && r != -ENOTBLK)
			return r;
	}

	/* data block size*/
	val32 = strtoul(params, &params, 10);
	if (*params != ' ')
		return -EINVAL;
	if (vp)
		vp->data_block_size = val32;
	params++;

	/* hash block size */
	val32 = strtoul(params, &params, 10);
	if (*params != ' ')
		return -EINVAL;
	if (vp)
		vp->hash_block_size = val32;
	params++;

	/* data blocks */
	val64 = strtoull(params, &params, 10);
	if (*params != ' ')
		return -EINVAL;
	if (vp)
		vp->data_size = val64;
	params++;

	/* hash start */
	val64 = strtoull(params, &params, 10);
	if (*params != ' ')
		return -EINVAL;
	dmd->u.verity.hash_offset = val64;
	params++;

	/* hash algorithm */
	str = strsep(&params, " ");
	if (!params)
		return -EINVAL;
	if (vp)
		vp->hash_name = strdup(str);

	/* root digest */
	str = strsep(&params, " ");
	if (!params)
		return -EINVAL;
	len = crypt_hex_to_bytes(str, &str2, 0);
	if (len < 0)
		return len;
	dmd->u.verity.root_hash_size = len;
	if (get_flags & DM_ACTIVE_VERITY_ROOT_HASH)
		dmd->u.verity.root_hash = str2;
	else
		free(str2);

	/* salt */
	str = strsep(&params, " ");
	if (vp) {
		if (!strcmp(str, "-")) {
			vp->salt_size = 0;
			vp->salt = NULL;
		} else {
			len = crypt_hex_to_bytes(str, &str2, 0);
			if (len < 0)
				return len;
			vp->salt_size = len;
			vp->salt = str2;
		}
	}

	/* Features section, available since verity target version 1.3 */
	if (params) {
		/* Number of arguments */
		val64 = strtoull(params, &params, 10);
		if (*params != ' ')
			return -EINVAL;
		params++;

		features = (int)val64;
		for (i = 0; i < features; i++) {
			if (!params)
				return -EINVAL;
			arg = strsep(&params, " ");
			if (!strcasecmp(arg, "ignore_corruption"))
				dmd->flags |= CRYPT_ACTIVATE_IGNORE_CORRUPTION;
			else if (!strcasecmp(arg, "restart_on_corruption"))
				dmd->flags |= CRYPT_ACTIVATE_RESTART_ON_CORRUPTION;
			else if (!strcasecmp(arg, "ignore_zero_blocks"))
				dmd->flags |= CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS;
			else if (!strcasecmp(arg, "use_fec_from_device")) {
				str = strsep(&params, " ");
				str2 = crypt_lookup_dev(str);
				if (get_flags & DM_ACTIVE_VERITY_HASH_DEVICE) {
					r = device_alloc(&dmd->u.verity.fec_device, str2);
					if (r < 0 && r != -ENOTBLK) {
						free(str2);
						return r;
					}
				}
				if (vp)
					vp->fec_device = str2;
				i++;
			} else if (!strcasecmp(arg, "fec_start")) {
				val64 = strtoull(params, &params, 10);
				if (*params)
					params++;
				dmd->u.verity.fec_offset = val64;
				if (vp)
					vp->fec_area_offset = val64 * vp->hash_block_size;
				i++;
			} else if (!strcasecmp(arg, "fec_blocks")) {
				val64 = strtoull(params, &params, 10);
				if (*params)
					params++;
				dmd->u.verity.fec_blocks = val64;
				i++;
			} else if (!strcasecmp(arg, "fec_roots")) {
				val32 = strtoul(params, &params, 10);
				if (*params)
					params++;
				if (vp)
					vp->fec_roots = val32;
				i++;
			} else /* unknown option */
				return -EINVAL;
		}

		/* All parameters should be processed */
		if (params && *params)
			return -EINVAL;
	}

	return 0;
}

static int _dm_query_integrity(uint32_t get_flags,
			     struct dm_info *dmi,
			     char *params,
			     struct crypt_dm_active_device *dmd)
{
	uint32_t val32;
	uint64_t val64;
	char c, *str, *str2, *arg;
	unsigned int features, val;
	ssize_t len;
	int i, r;

	memset(dmd, 0, sizeof(*dmd));

	dmd->target = DM_INTEGRITY;

	/* data device */
	str = strsep(&params, " ");
	if (get_flags & DM_ACTIVE_DEVICE) {
		str2 = crypt_lookup_dev(str);
		r = device_alloc(&dmd->data_device, str2);
		free(str2);
		if (r < 0 && r != -ENOTBLK)
			return r;
	}

	/*offset */
	if (!params)
		return -EINVAL;
	val64 = strtoull(params, &params, 10);
	if (!*params || *params != ' ')
		return -EINVAL;
	dmd->u.integrity.offset = val64;

	/* tag size*/
	val32 = strtoul(params, &params, 10);
	dmd->u.integrity.tag_size = val32;
	if (!*params || *params != ' ')
		return -EINVAL;

	/* journal */
	c = toupper(*(++params));
	if (!*params || *(++params) != ' ' || (c != 'D' && c != 'J' && c != 'R'))
		return -EINVAL;
	if (c == 'D')
		dmd->flags |= CRYPT_ACTIVATE_NO_JOURNAL;
	if (c == 'R')
		dmd->flags |= CRYPT_ACTIVATE_RECOVERY;

	dmd->u.integrity.sector_size = SECTOR_SIZE;

	/* Features section */
	if (params) {
		/* Number of arguments */
		val64 = strtoull(params, &params, 10);
		if (*params != ' ')
			return -EINVAL;
		params++;

		features = (int)val64;
		for (i = 0; i < features; i++) {
			if (!params)
				return -EINVAL;
			arg = strsep(&params, " ");
			if (sscanf(arg, "journal_sectors:%u", &val) == 1)
				dmd->u.integrity.journal_size = val * SECTOR_SIZE;
			else if (sscanf(arg, "journal_watermark:%u", &val) == 1)
				dmd->u.integrity.journal_watermark = val;
			else if (sscanf(arg, "commit_time:%u", &val) == 1)
				dmd->u.integrity.journal_commit_time = val;
			else if (sscanf(arg, "interleave_sectors:%u", &val) == 1)
				dmd->u.integrity.interleave_sectors = val;
			else if (sscanf(arg, "block_size:%u", &val) == 1)
				dmd->u.integrity.sector_size = val;
			else if (sscanf(arg, "buffer_sectors:%u", &val) == 1)
				dmd->u.integrity.buffer_sectors = val;
			else if (!strncmp(arg, "internal_hash:", 14)) {
				str = &arg[14];
				arg = strsep(&str, ":");
				dmd->u.integrity.integrity = strdup(arg);

				if (str) {
					len = crypt_hex_to_bytes(str, &str2, 1);
					if (len < 0)
						return len;

					r = 0;
					if (get_flags & DM_ACTIVE_CRYPT_KEY) {
						dmd->u.integrity.vk = crypt_alloc_volume_key(len, str2);
						if (!dmd->u.integrity.vk)
							r = -ENOMEM;
					} else if (get_flags & DM_ACTIVE_CRYPT_KEYSIZE) {
						dmd->u.integrity.vk = crypt_alloc_volume_key(len, NULL);
						if (!dmd->u.integrity.vk)
							r = -ENOMEM;
					}
					crypt_safe_free(str2);
					if (r)
						return r;
				}
			} else if (!strncmp(arg, "journal_crypt:", 14))
				;/* ignore it for now */
			else if (!strncmp(arg, "journal_mac:", 12))
				;/* ignore it for now */
			else /* unknown option */
				return -EINVAL;
		}

		/* All parameters should be processed */
		if (params && *params)
			return -EINVAL;
	}

	return 0;
}

int dm_query_device(struct crypt_device *cd, const char *name,
		    uint32_t get_flags, struct crypt_dm_active_device *dmd)
{
	struct dm_task *dmt;
	struct dm_info dmi;
	uint64_t start, length;
	char *target_type, *params;
	const char *tmp_uuid;
	void *next = NULL;
	int r = -EINVAL;

	if (dm_init_context(cd))
		return -ENOTSUP;
	if (!(dmt = dm_task_create(DM_DEVICE_TABLE)))
		goto out;
	if ((dm_flags() & DM_SECURE_SUPPORTED) && !dm_task_secure_data(dmt))
		goto out;
	if (!dm_task_set_name(dmt, name))
		goto out;
	r = -ENODEV;
	if (!dm_task_run(dmt))
		goto out;

	r = -EINVAL;
	if (!dm_task_get_info(dmt, &dmi))
		goto out;

	if (!dmi.exists) {
		r = -ENODEV;
		goto out;
	}

	next = dm_get_next_target(dmt, next, &start, &length,
	                          &target_type, &params);

	if (!target_type || start != 0 || next)
		goto out;

	if (!strcmp(target_type, DM_CRYPT_TARGET)) {
		r = _dm_query_crypt(get_flags, &dmi, params, dmd);
	} else if (!strcmp(target_type, DM_VERITY_TARGET)) {
		r = _dm_query_verity(get_flags, &dmi, params, dmd);
		if (r < 0)
			goto out;
		r = _dm_status_verity_ok(name);
		if (r < 0)
			goto out;
		if (r == 0)
			dmd->flags |= CRYPT_ACTIVATE_CORRUPTED;
		r = 0;
	} else if (!strcmp(target_type, DM_INTEGRITY_TARGET)) {
		r = _dm_query_integrity(get_flags, &dmi, params, dmd);
	} else
		r = -EINVAL;

	if (r < 0)
		goto out;

	dmd->size = length;

	if (dmi.read_only)
		dmd->flags |= CRYPT_ACTIVATE_READONLY;

	tmp_uuid = dm_task_get_uuid(dmt);
	if (!tmp_uuid)
		dmd->flags |= CRYPT_ACTIVATE_NO_UUID;
	else if (get_flags & DM_ACTIVE_UUID) {
		if (!strncmp(tmp_uuid, DM_UUID_PREFIX, DM_UUID_PREFIX_LEN))
			dmd->uuid = strdup(tmp_uuid + DM_UUID_PREFIX_LEN);
	}

	r = (dmi.open_count > 0);
out:
	if (dmt)
		dm_task_destroy(dmt);

	dm_exit_context();
	return r;
}

static int _dm_message(const char *name, const char *msg)
{
	int r = 0;
	struct dm_task *dmt;

	if (!(dmt = dm_task_create(DM_DEVICE_TARGET_MSG)))
		return 0;

	if ((dm_flags() & DM_SECURE_SUPPORTED) && !dm_task_secure_data(dmt))
		goto out;

	if (name && !dm_task_set_name(dmt, name))
		goto out;

	if (!dm_task_set_sector(dmt, (uint64_t) 0))
		goto out;

	if (!dm_task_set_message(dmt, msg))
		goto out;

	r = dm_task_run(dmt);

      out:
	dm_task_destroy(dmt);
	return r;
}

int dm_suspend_and_wipe_key(struct crypt_device *cd, const char *name)
{
	int r = -ENOTSUP;

	if (dm_init_context(cd))
		return -ENOTSUP;

	if (!(_dm_crypt_flags & DM_KEY_WIPE_SUPPORTED))
		goto out;

	if (!_dm_simple(DM_DEVICE_SUSPEND, name, 0)) {
		r = -EINVAL;
		goto out;
	}

	if (!_dm_message(name, "key wipe")) {
		_dm_simple(DM_DEVICE_RESUME, name, 1);
		r = -EINVAL;
		goto out;
	}
	r = 0;
out:
	dm_exit_context();
	return r;
}

int dm_resume_and_reinstate_key(struct crypt_device *cd, const char *name,
				const struct volume_key *vk)
{
	int msg_size;
	char *msg = NULL;
	int r = -ENOTSUP;

	if (dm_init_context(cd))
		return -ENOTSUP;

	if (!(_dm_crypt_flags & DM_KEY_WIPE_SUPPORTED))
		goto out;

	if (vk->key_description)
		msg_size = strlen(vk->key_description) + get_key_size_strlen(vk->keylength) + 17;
	else
		msg_size = vk->keylength * 2 + 10; // key set <key>

	msg = crypt_safe_alloc(msg_size);
	if (!msg) {
		r = -ENOMEM;
		goto out;
	}

	strcpy(msg, "key set ");
	if (vk->key_description)
		snprintf(msg + 8, msg_size - 8, ":%zu:logon:%s", vk->keylength, vk->key_description);
	else
		hex_key(&msg[8], vk->keylength, vk->key);

	if (!_dm_message(name, msg) ||
	    !_dm_simple(DM_DEVICE_RESUME, name, 1)) {
		r = -EINVAL;
		goto out;
	}
	r = 0;
out:
	crypt_safe_free(msg);
	dm_exit_context();
	return r;
}

const char *dm_get_dir(void)
{
	return dm_dir();
}

int dm_is_dm_device(int major, int minor)
{
	return dm_is_dm_major((uint32_t)major);
}

int dm_is_dm_kernel_name(const char *name)
{
	return strncmp(name, "dm-", 3) ? 0 : 1;
}
