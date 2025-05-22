// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * libdevmapper - device-mapper backend for cryptsetup
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <libdevmapper.h>
#include <uuid/uuid.h>
#include <sys/stat.h>
#if HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>     /* for major, minor */
#endif
#include "internal.h"

#define DM_CRYPT_TARGET		"crypt"
#define DM_VERITY_TARGET	"verity"
#define DM_INTEGRITY_TARGET	"integrity"
#define DM_LINEAR_TARGET	"linear"
#define DM_ERROR_TARGET         "error"
#define DM_ZERO_TARGET		"zero"
#define RETRY_COUNT		5

/* Set if DM target versions were probed */
static bool _dm_ioctl_checked = false;
static bool _dm_crypt_checked = false;
static bool _dm_verity_checked = false;
static bool _dm_integrity_checked = false;
static bool _dm_zero_checked = false;

static int _quiet_log = 0;
static uint64_t _dm_flags = 0;

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
#if USE_UDEV /* cannot be enabled if devmapper is too old */
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
		} else {
			/* We do not use DM visual stack backtrace here */
			if (strncmp(msg, "<backtrace>", 11))
				log_dbg(_context, "%s", msg);
		}
	}
	free(msg);
	va_end(va);
}

static int _dm_satisfies_version(unsigned target_maj, unsigned target_min, unsigned target_patch,
				 unsigned actual_maj, unsigned actual_min, unsigned actual_patch)
{
	if (actual_maj > target_maj)
		return 1;

	if (actual_maj == target_maj && actual_min > target_min)
		return 1;

	if (actual_maj == target_maj && actual_min == target_min && actual_patch >= target_patch)
		return 1;

	return 0;
}

static void _dm_set_crypt_compat(struct crypt_device *cd,
				 unsigned crypt_maj,
				 unsigned crypt_min,
				 unsigned crypt_patch)
{
	if (_dm_crypt_checked || crypt_maj == 0)
		return;

	log_dbg(cd, "Detected dm-crypt version %i.%i.%i.",
		crypt_maj, crypt_min, crypt_patch);

	if (_dm_satisfies_version(1, 2, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_KEY_WIPE_SUPPORTED;
	else
		log_dbg(cd, "Suspend and resume disabled, no wipe key support.");

	if (_dm_satisfies_version(1, 10, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_LMK_SUPPORTED;

	/* not perfect, 2.6.33 supports with 1.7.0 */
	if (_dm_satisfies_version(1, 8, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_PLAIN64_SUPPORTED;

	if (_dm_satisfies_version(1, 11, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_DISCARDS_SUPPORTED;

	if (_dm_satisfies_version(1, 13, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_TCW_SUPPORTED;

	if (_dm_satisfies_version(1, 14, 0, crypt_maj, crypt_min, crypt_patch)) {
		_dm_flags |= DM_SAME_CPU_CRYPT_SUPPORTED;
		_dm_flags |= DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED;
	}

	if (_dm_satisfies_version(1, 18, 1, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_KERNEL_KEYRING_SUPPORTED;

	if (_dm_satisfies_version(1, 17, 0, crypt_maj, crypt_min, crypt_patch)) {
		_dm_flags |= DM_SECTOR_SIZE_SUPPORTED;
		_dm_flags |= DM_CAPI_STRING_SUPPORTED;
	}

	if (_dm_satisfies_version(1, 19, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_BITLK_EBOIV_SUPPORTED;

	if (_dm_satisfies_version(1, 20, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_BITLK_ELEPHANT_SUPPORTED;

	if (_dm_satisfies_version(1, 22, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_CRYPT_NO_WORKQUEUE_SUPPORTED;

	if (_dm_satisfies_version(1, 26, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_CRYPT_HIGH_PRIORITY_SUPPORTED;

	if (_dm_satisfies_version(1, 28, 0, crypt_maj, crypt_min, crypt_patch))
		_dm_flags |= DM_CRYPT_INTEGRITY_KEY_SIZE_OPT_SUPPORTED;

	_dm_crypt_checked = true;
}

static void _dm_set_verity_compat(struct crypt_device *cd,
				  unsigned verity_maj,
				  unsigned verity_min,
				  unsigned verity_patch)
{
	if (_dm_verity_checked || verity_maj == 0)
		return;

	log_dbg(cd, "Detected dm-verity version %i.%i.%i.",
		verity_maj, verity_min, verity_patch);

	_dm_flags |= DM_VERITY_SUPPORTED;

	/*
	 * ignore_corruption, restart_on corruption is available since 1.2 (kernel 4.1)
	 * ignore_zero_blocks since 1.3 (kernel 4.5)
	 * (but some dm-verity targets 1.2 don't support it)
	 * FEC is added in 1.3 as well.
	 * Check at most once is added in 1.4 (kernel 4.17).
	 */
	if (_dm_satisfies_version(1, 3, 0, verity_maj, verity_min, verity_patch)) {
		_dm_flags |= DM_VERITY_ON_CORRUPTION_SUPPORTED;
		_dm_flags |= DM_VERITY_FEC_SUPPORTED;
	}

	if (_dm_satisfies_version(1, 5, 0, verity_maj, verity_min, verity_patch))
		_dm_flags |= DM_VERITY_SIGNATURE_SUPPORTED;

	if (_dm_satisfies_version(1, 7, 0, verity_maj, verity_min, verity_patch))
		_dm_flags |= DM_VERITY_PANIC_CORRUPTION_SUPPORTED;

	if (_dm_satisfies_version(1, 9, 0, verity_maj, verity_min, verity_patch))
		_dm_flags |= DM_VERITY_TASKLETS_SUPPORTED;

	/* There is actually no correct version set, just use the last available */
	if (_dm_satisfies_version(1, 10, 0, verity_maj, verity_min, verity_patch))
		_dm_flags |= DM_VERITY_ERROR_AS_CORRUPTION_SUPPORTED;

	_dm_verity_checked = true;
}

static void _dm_set_integrity_compat(struct crypt_device *cd,
				     unsigned integrity_maj,
				     unsigned integrity_min,
				     unsigned integrity_patch)
{
	if (_dm_integrity_checked || integrity_maj == 0)
		return;

	log_dbg(cd, "Detected dm-integrity version %i.%i.%i.",
		integrity_maj, integrity_min, integrity_patch);

	_dm_flags |= DM_INTEGRITY_SUPPORTED;

	if (_dm_satisfies_version(1, 2, 0, integrity_maj, integrity_min, integrity_patch))
		_dm_flags |= DM_INTEGRITY_RECALC_SUPPORTED;

	if (_dm_satisfies_version(1, 3, 0, integrity_maj, integrity_min, integrity_patch))
		_dm_flags |= DM_INTEGRITY_BITMAP_SUPPORTED;

	if (_dm_satisfies_version(1, 4, 0, integrity_maj, integrity_min, integrity_patch))
		_dm_flags |= DM_INTEGRITY_FIX_PADDING_SUPPORTED;

	if (_dm_satisfies_version(1, 6, 0, integrity_maj, integrity_min, integrity_patch))
		_dm_flags |= DM_INTEGRITY_DISCARDS_SUPPORTED;

	if (_dm_satisfies_version(1, 7, 0, integrity_maj, integrity_min, integrity_patch))
		_dm_flags |= DM_INTEGRITY_FIX_HMAC_SUPPORTED;

	if (_dm_satisfies_version(1, 8, 0, integrity_maj, integrity_min, integrity_patch))
		_dm_flags |= DM_INTEGRITY_RESET_RECALC_SUPPORTED;

	if (_dm_satisfies_version(1, 12, 0, integrity_maj, integrity_min, integrity_patch))
		_dm_flags |= DM_INTEGRITY_INLINE_MODE_SUPPORTED;

	_dm_integrity_checked = true;
}

static void _dm_set_zero_compat(struct crypt_device *cd,
				unsigned zero_maj,
				unsigned zero_min,
				unsigned zero_patch)
{
	if (_dm_zero_checked || zero_maj == 0)
		return;

	log_dbg(cd, "Detected dm-zero version %i.%i.%i.",
		zero_maj, zero_min, zero_patch);

	_dm_zero_checked = true;
}

/* We use this for loading target module */
static void _dm_check_target(dm_target_type target_type)
{
#if HAVE_DECL_DM_DEVICE_GET_TARGET_VERSION
	struct dm_task *dmt;
	const char *target_name = NULL;

	if (!(_dm_flags & DM_GET_TARGET_VERSION_SUPPORTED))
		return;

	if (target_type == DM_CRYPT)
		target_name = DM_CRYPT_TARGET;
	else if (target_type == DM_VERITY)
		target_name = DM_VERITY_TARGET;
	else if (target_type == DM_INTEGRITY)
		target_name = DM_INTEGRITY_TARGET;
	else
		return;

	if (!(dmt = dm_task_create(DM_DEVICE_GET_TARGET_VERSION)))
		return;

	if (dm_task_set_name(dmt, target_name))
		dm_task_run(dmt);

	dm_task_destroy(dmt);
#endif
}

static int _dm_check_versions(struct crypt_device *cd, dm_target_type target_type)
{
	struct dm_task *dmt;
	struct dm_versions *target, *last_target;
	char dm_version[16];
	unsigned dm_maj, dm_min, dm_patch;
	int r = 0;

	if ((target_type == DM_CRYPT     && _dm_crypt_checked) ||
	    (target_type == DM_VERITY    && _dm_verity_checked) ||
	    (target_type == DM_INTEGRITY && _dm_integrity_checked) ||
	    (target_type == DM_ZERO      && _dm_zero_checked) ||
	    (target_type == DM_LINEAR) ||
	    (_dm_crypt_checked && _dm_verity_checked && _dm_integrity_checked && _dm_zero_checked))
		return 1;

	/* Shut up DM while checking */
	_quiet_log = 1;

	_dm_check_target(target_type);

	if (!(dmt = dm_task_create(DM_DEVICE_LIST_VERSIONS)))
		goto out;

	if (!dm_task_run(dmt))
		goto out;

	if (!dm_task_get_driver_version(dmt, dm_version, sizeof(dm_version)))
		goto out;

	if (!_dm_ioctl_checked) {
		if (sscanf(dm_version, "%u.%u.%u", &dm_maj, &dm_min, &dm_patch) != 3)
			goto out;
		log_dbg(cd, "Detected dm-ioctl version %u.%u.%u.", dm_maj, dm_min, dm_patch);

		if (_dm_satisfies_version(4, 20, 0, dm_maj, dm_min, dm_patch))
			_dm_flags |= DM_SECURE_SUPPORTED;
#if HAVE_DECL_DM_TASK_DEFERRED_REMOVE
		if (_dm_satisfies_version(4, 27, 0, dm_maj, dm_min, dm_patch))
			_dm_flags |= DM_DEFERRED_SUPPORTED;
#endif
#if HAVE_DECL_DM_DEVICE_GET_TARGET_VERSION
		if (_dm_satisfies_version(4, 41, 0, dm_maj, dm_min, dm_patch))
			_dm_flags |= DM_GET_TARGET_VERSION_SUPPORTED;
#endif
	}

	target = dm_task_get_versions(dmt);
	do {
		last_target = target;
		if (!strcmp(DM_CRYPT_TARGET, target->name)) {
			_dm_set_crypt_compat(cd, (unsigned)target->version[0],
					     (unsigned)target->version[1],
					     (unsigned)target->version[2]);
		} else if (!strcmp(DM_VERITY_TARGET, target->name)) {
			_dm_set_verity_compat(cd, (unsigned)target->version[0],
					      (unsigned)target->version[1],
					      (unsigned)target->version[2]);
		} else if (!strcmp(DM_INTEGRITY_TARGET, target->name)) {
			_dm_set_integrity_compat(cd, (unsigned)target->version[0],
						 (unsigned)target->version[1],
						 (unsigned)target->version[2]);
		} else if (!strcmp(DM_ZERO_TARGET, target->name)) {
			_dm_set_zero_compat(cd, (unsigned)target->version[0],
					    (unsigned)target->version[1],
					    (unsigned)target->version[2]);
		}
		target = VOIDP_CAST(struct dm_versions *)((char *) target + target->next);
	} while (last_target != target);

	r = 1;
	if (!_dm_ioctl_checked)
		log_dbg(cd, "Device-mapper backend running with UDEV support %sabled.",
			_dm_use_udev() ? "en" : "dis");

	_dm_ioctl_checked = true;
out:
	if (dmt)
		dm_task_destroy(dmt);

	_quiet_log = 0;
	return r;
}

int dm_flags(struct crypt_device *cd, dm_target_type target, uint64_t *flags)
{
	_dm_check_versions(cd, target);
	*flags = _dm_flags;

	if (target == DM_UNKNOWN &&
	    _dm_crypt_checked && _dm_verity_checked && _dm_integrity_checked && _dm_zero_checked)
		return 0;

	if ((target == DM_CRYPT     && _dm_crypt_checked) ||
	    (target == DM_VERITY    && _dm_verity_checked) ||
	    (target == DM_INTEGRITY && _dm_integrity_checked) ||
	    (target == DM_ZERO      && _dm_zero_checked) ||
	    (target == DM_LINEAR)) /* nothing to check */
		return 0;

	return -ENODEV;
}

/* This doesn't run any kernel checks, just set up userspace libdevmapper */
void dm_backend_init(struct crypt_device *cd)
{
	if (!_dm_use_count++) {
		log_dbg(cd, "Initialising device-mapper backend library.");
		dm_log_init(set_dm_error);
		dm_log_init_verbose(10);
	}
}

void dm_backend_exit(struct crypt_device *cd)
{
	if (_dm_use_count && (!--_dm_use_count)) {
		log_dbg(cd, "Releasing device-mapper backend.");
		dm_log_init_verbose(0);
		dm_log_init(NULL);
		dm_lib_release();
	}
}

/* libdevmapper is not context friendly, switch context on every DM call. */
static int dm_init_context(struct crypt_device *cd, dm_target_type target)
{
	_context = cd;
	if (!_dm_check_versions(cd, target)) {
		if (getuid() || geteuid())
			log_err(cd, _("Cannot initialize device-mapper, "
				      "running as non-root user."));
		else
			log_err(cd, _("Cannot initialize device-mapper. "
				      "Is dm_mod kernel module loaded?"));
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
	    !dm_task_no_flush(dmt) ||
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

char *dm_device_name(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0 || !S_ISBLK(st.st_mode))
		return NULL;

	return dm_device_path(NULL, major(st.st_rdev), minor(st.st_rdev));
}

static size_t int_log10(uint64_t x)
{
	uint64_t r = 0;
	for (x /= 10; x > 0; x /= 10)
		r++;
	return r;
}

static int cipher_dm2c(const char *org_c, const char *org_i, unsigned tag_size,
		       char *c_dm, int c_dm_size,
		       char *i_dm, int i_dm_size)
{
	int c_size = 0, i_size = 0, i;
	char cipher[MAX_CAPI_ONE_LEN], mode[MAX_CAPI_ONE_LEN], iv[MAX_CAPI_ONE_LEN+1],
	     tmp[MAX_CAPI_ONE_LEN], capi[MAX_CAPI_LEN];

	if (!c_dm || !c_dm_size || !i_dm || !i_dm_size)
		return -EINVAL;

	i = sscanf(org_c, "%" MAX_CAPI_ONE_LEN_STR "[^-]-%" MAX_CAPI_ONE_LEN_STR "s", cipher, tmp);
	if (i != 2)
		return -EINVAL;

	i = sscanf(tmp, "%" MAX_CAPI_ONE_LEN_STR "[^-]-%" MAX_CAPI_ONE_LEN_STR "s", mode, iv);
	if (i == 1) {
		memset(iv, 0, sizeof(iv));
		strncpy(iv, mode, sizeof(iv)-1);
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

static char *_uf(char *buf, size_t buf_size, const char *s, unsigned u)
{
	size_t r = snprintf(buf, buf_size, " %s:%u", s, u);
	assert(r > 0 && r < buf_size);
	return buf;
}

/* https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt */
static char *get_dm_crypt_params(const struct dm_target *tgt, uint32_t flags)
{
	int r, max_size, null_cipher = 0, num_options = 0, keystr_len = 0;
	char *params = NULL, *hexkey = NULL;
	char sector_feature[32], features[512], integrity_dm[256], cipher_dm[256];
	char int_ksize_feature[32];

	if (!tgt)
		return NULL;

	r = cipher_dm2c(tgt->u.crypt.cipher, tgt->u.crypt.integrity, tgt->u.crypt.tag_size,
			cipher_dm, sizeof(cipher_dm), integrity_dm, sizeof(integrity_dm));
	if (r < 0)
		return NULL;

	if (flags & CRYPT_ACTIVATE_ALLOW_DISCARDS)
		num_options++;
	if (flags & CRYPT_ACTIVATE_SAME_CPU_CRYPT)
		num_options++;
	if (flags & CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS)
		num_options++;
	if (flags & CRYPT_ACTIVATE_NO_READ_WORKQUEUE)
		num_options++;
	if (flags & CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE)
		num_options++;
	if (flags & CRYPT_ACTIVATE_IV_LARGE_SECTORS)
		num_options++;
	if (flags & CRYPT_ACTIVATE_HIGH_PRIORITY)
		num_options++;
	if (tgt->u.crypt.integrity)
		num_options++;
	if (tgt->u.crypt.sector_size != SECTOR_SIZE)
		num_options++;
	if (tgt->u.crypt.integrity && tgt->u.crypt.integrity_key_size)
		num_options++;

	if (num_options) { /* MAX length  int32 + 15 + 15 + 23 + 18 + 19 + 17 + 14 + 13 + int32 + integrity_str + 21 + int32 */
		r = snprintf(features, sizeof(features), " %d%s%s%s%s%s%s%s%s%s%s", num_options,
		(flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) ? " allow_discards" : "",
		(flags & CRYPT_ACTIVATE_SAME_CPU_CRYPT) ? " same_cpu_crypt" : "",
		(flags & CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS) ? " submit_from_crypt_cpus" : "",
		(flags & CRYPT_ACTIVATE_NO_READ_WORKQUEUE) ? " no_read_workqueue" : "",
		(flags & CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE) ? " no_write_workqueue" : "",
		(flags & CRYPT_ACTIVATE_IV_LARGE_SECTORS) ? " iv_large_sectors" : "",
		(flags & CRYPT_ACTIVATE_HIGH_PRIORITY) ? " high_priority" : "",
		(tgt->u.crypt.sector_size != SECTOR_SIZE) ?
			_uf(sector_feature, sizeof(sector_feature), "sector_size", tgt->u.crypt.sector_size) : "",
		integrity_dm,
		(tgt->u.crypt.integrity && tgt->u.crypt.integrity_key_size) ?
			_uf(int_ksize_feature, sizeof(int_ksize_feature), "integrity_key_size", tgt->u.crypt.integrity_key_size) : "");
		if (r < 0 || (size_t)r >= sizeof(features))
			goto out;
	} else
		*features = '\0';

	if (crypt_is_cipher_null(cipher_dm))
		null_cipher = 1;

	if (null_cipher || crypt_volume_key_length(tgt->u.crypt.vk) == 0)
		hexkey = crypt_bytes_to_hex(0, NULL);
	else if (flags & CRYPT_ACTIVATE_KEYRING_KEY) {
		if (!crypt_volume_key_description(tgt->u.crypt.vk) ||
		    crypt_volume_key_kernel_key_type(tgt->u.crypt.vk) == INVALID_KEY)
			goto out;
		keystr_len = strlen(crypt_volume_key_description(tgt->u.crypt.vk)) +
			int_log10(crypt_volume_key_length(tgt->u.crypt.vk)) +
			24 /* type and separators */;
		hexkey = crypt_safe_alloc(keystr_len);
		if (!hexkey)
			goto out;
		r = snprintf(hexkey, keystr_len, ":%zu:%s:%s", crypt_volume_key_length(tgt->u.crypt.vk),
			     key_type_name(crypt_volume_key_kernel_key_type(tgt->u.crypt.vk)),
			     crypt_volume_key_description(tgt->u.crypt.vk));
		if (r < 0 || r >= keystr_len)
			goto out;
	} else
		hexkey = crypt_bytes_to_hex(crypt_volume_key_length(tgt->u.crypt.vk),
					    crypt_volume_key_get_key(tgt->u.crypt.vk));

	if (!hexkey)
		goto out;

	max_size = strlen(hexkey) + strlen(cipher_dm) +
		   strlen(device_block_path(tgt->data_device)) +
		   strlen(features) + 64;
	params = crypt_safe_alloc(max_size);
	if (!params)
		goto out;

	r = snprintf(params, max_size, "%s %s %" PRIu64 " %s %" PRIu64 "%s",
		     cipher_dm, hexkey, tgt->u.crypt.iv_offset,
		     device_block_path(tgt->data_device), tgt->u.crypt.offset,
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
static char *get_dm_verity_params(const struct dm_target *tgt, uint32_t flags)
{
	int max_size, max_fec_size, max_verify_size, r, num_options = 0;
	struct crypt_params_verity *vp;
	char *params = NULL, *hexroot = NULL, *hexsalt = NULL;
	char features[256], *fec_features = NULL, *verity_verify_args = NULL;

	if (!tgt || !tgt->u.verity.vp)
		return NULL;

	vp = tgt->u.verity.vp;

	/* These flags are not compatible */
	if ((flags & CRYPT_ACTIVATE_RESTART_ON_CORRUPTION) &&
	    (flags & CRYPT_ACTIVATE_PANIC_ON_CORRUPTION))
		flags &= ~CRYPT_ACTIVATE_RESTART_ON_CORRUPTION;
	if ((flags & CRYPT_ACTIVATE_IGNORE_CORRUPTION) &&
	    (flags & (CRYPT_ACTIVATE_RESTART_ON_CORRUPTION|CRYPT_ACTIVATE_PANIC_ON_CORRUPTION)))
		flags &= ~CRYPT_ACTIVATE_IGNORE_CORRUPTION;

	if (flags & CRYPT_ACTIVATE_IGNORE_CORRUPTION)
		num_options++;
	if (flags & CRYPT_ACTIVATE_RESTART_ON_CORRUPTION)
		num_options++;
	if (flags & CRYPT_ACTIVATE_PANIC_ON_CORRUPTION)
		num_options++;
	if (flags & CRYPT_ACTIVATE_ERROR_AS_CORRUPTION)
		num_options++;
	if (flags & CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS)
		num_options++;
	if (flags & CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE)
		num_options++;
	if (flags & CRYPT_ACTIVATE_TASKLETS)
		num_options++;

	max_fec_size = (tgt->u.verity.fec_device ? strlen(device_block_path(tgt->u.verity.fec_device)) : 0) + 256;
	fec_features = crypt_safe_alloc(max_fec_size);
	if (!fec_features)
		goto out;

	if (tgt->u.verity.fec_device) {  /* MAX length 21 + path + 11 + int64 + 12 + int64 + 11 + int32 */
		num_options += 8;
		r = snprintf(fec_features, max_fec_size,
			 " use_fec_from_device %s fec_start %" PRIu64 " fec_blocks %" PRIu64 " fec_roots %" PRIu32,
			 device_block_path(tgt->u.verity.fec_device), tgt->u.verity.fec_offset,
			 tgt->u.verity.fec_blocks, vp->fec_roots);
		if (r < 0 || r >= max_fec_size)
			goto out;
	} else
		*fec_features = '\0';

	max_verify_size = (tgt->u.verity.root_hash_sig_key_desc ? strlen(tgt->u.verity.root_hash_sig_key_desc) : 0) + 32;
	verity_verify_args = crypt_safe_alloc(max_verify_size);
	if (!verity_verify_args)
		goto out;
	if (tgt->u.verity.root_hash_sig_key_desc) {  /* MAX length 24 + key_str */
		num_options += 2;
		r = snprintf(verity_verify_args, max_verify_size,
				" root_hash_sig_key_desc %s", tgt->u.verity.root_hash_sig_key_desc);
		if (r < 0 || r >= max_verify_size)
			goto out;
	} else
		*verity_verify_args = '\0';

	if (num_options) {  /* MAX length int32 + 18 + 22 + 20 + 19 + 19 + 22 */
		r = snprintf(features, sizeof(features), " %d%s%s%s%s%s%s%s", num_options,
		(flags & CRYPT_ACTIVATE_IGNORE_CORRUPTION) ? " ignore_corruption" : "",
		(flags & CRYPT_ACTIVATE_RESTART_ON_CORRUPTION) ? " restart_on_corruption" : "",
		(flags & CRYPT_ACTIVATE_PANIC_ON_CORRUPTION) ? " panic_on_corruption" : "",
		(flags & CRYPT_ACTIVATE_ERROR_AS_CORRUPTION) ? ((flags & CRYPT_ACTIVATE_PANIC_ON_CORRUPTION) ?
			" panic_on_error" : " restart_on_error") : "",
		(flags & CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS) ? " ignore_zero_blocks" : "",
		(flags & CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE) ? " check_at_most_once" : "",
		(flags & CRYPT_ACTIVATE_TASKLETS) ? " try_verify_in_tasklet" : "");
		if (r < 0 || (size_t)r >= sizeof(features))
			goto out;
	} else
		*features = '\0';

	hexroot = crypt_bytes_to_hex(tgt->u.verity.root_hash_size, tgt->u.verity.root_hash);
	if (!hexroot)
		goto out;

	hexsalt = crypt_bytes_to_hex(vp->salt_size, vp->salt);
	if (!hexsalt)
		goto out;

	max_size = strlen(hexroot) + strlen(hexsalt) +
		   strlen(device_block_path(tgt->data_device)) +
		   strlen(device_block_path(tgt->u.verity.hash_device)) +
		   strlen(vp->hash_name) + strlen(features) + strlen(fec_features) + 128 +
		   strlen(verity_verify_args);

	params = crypt_safe_alloc(max_size);
	if (!params)
		goto out;

	r = snprintf(params, max_size,
		     "%u %s %s %u %u %" PRIu64 " %" PRIu64 " %s %s %s%s%s%s",
		     vp->hash_type, device_block_path(tgt->data_device),
		     device_block_path(tgt->u.verity.hash_device),
		     vp->data_block_size, vp->hash_block_size,
		     vp->data_size, tgt->u.verity.hash_offset,
		     vp->hash_name, hexroot, hexsalt, features, fec_features,
		     verity_verify_args);
	if (r < 0 || r >= max_size) {
		crypt_safe_free(params);
		params = NULL;
	}
out:
	crypt_safe_free(fec_features);
	crypt_safe_free(verity_verify_args);
	crypt_safe_free(hexroot);
	crypt_safe_free(hexsalt);
	return params;
}

static char *get_dm_integrity_params(const struct dm_target *tgt, uint32_t flags)
{
	int r, max_size, max_integrity, max_journal_integrity, max_journal_crypt, num_options = 0;
	char *params_out = NULL, *params, *hexkey, mode, feature[6][32];
	char *features, *integrity, *journal_integrity, *journal_crypt;

	if (!tgt)
		return NULL;

	max_integrity = (tgt->u.integrity.integrity && tgt->u.integrity.vk ? crypt_volume_key_length(tgt->u.integrity.vk) * 2 : 0) +
		(tgt->u.integrity.integrity ? strlen(tgt->u.integrity.integrity) : 0) + 32;
	max_journal_integrity = (tgt->u.integrity.journal_integrity && tgt->u.integrity.journal_integrity_key ?
		crypt_volume_key_length(tgt->u.integrity.journal_integrity_key) * 2 : 0) +
		(tgt->u.integrity.journal_integrity ? strlen(tgt->u.integrity.journal_integrity) : 0) + 32;
	max_journal_crypt = (tgt->u.integrity.journal_crypt && tgt->u.integrity.journal_crypt_key ?
		crypt_volume_key_length(tgt->u.integrity.journal_crypt_key) * 2 : 0) +
		(tgt->u.integrity.journal_crypt ? strlen(tgt->u.integrity.journal_crypt) : 0) + 32;
	max_size = strlen(device_block_path(tgt->data_device)) +
		(tgt->u.integrity.meta_device ? strlen(device_block_path(tgt->u.integrity.meta_device)) : 0) +
		max_integrity + max_journal_integrity + max_journal_crypt + 512;

	params = crypt_safe_alloc(max_size);
	features = crypt_safe_alloc(max_size);
	integrity = crypt_safe_alloc(max_integrity);
	journal_integrity = crypt_safe_alloc(max_journal_integrity);
	journal_crypt = crypt_safe_alloc(max_journal_crypt);
	if (!params || !features || !integrity || !journal_integrity || !journal_crypt)
		goto out;

	if (tgt->u.integrity.integrity) { /* MAX length 16 + str_integrity +  str_key */
		num_options++;

		if (tgt->u.integrity.vk) {
			hexkey = crypt_bytes_to_hex(crypt_volume_key_length(tgt->u.integrity.vk),
						    crypt_volume_key_get_key(tgt->u.integrity.vk));
			if (!hexkey)
				goto out;
		} else
			hexkey = NULL;

		r = snprintf(integrity, max_integrity, " internal_hash:%s%s%s",
			 tgt->u.integrity.integrity, hexkey ? ":" : "", hexkey ?: "");
		crypt_safe_free(hexkey);
		if (r < 0 || r >= max_integrity)
			goto out;
	}

	if (tgt->u.integrity.journal_integrity) { /* MAX length 14 + str_journal_integrity + str_key */
		num_options++;

		if (tgt->u.integrity.journal_integrity_key) {
			hexkey = crypt_bytes_to_hex(crypt_volume_key_length(tgt->u.integrity.journal_integrity_key),
				crypt_volume_key_get_key(tgt->u.integrity.journal_integrity_key));
			if (!hexkey)
				goto out;
		} else
			hexkey = NULL;

		r = snprintf(journal_integrity, max_journal_integrity, " journal_mac:%s%s%s",
			 tgt->u.integrity.journal_integrity, hexkey ? ":" : "", hexkey ?: "");
		crypt_safe_free(hexkey);
		if (r < 0 || r >= max_journal_integrity)
			goto out;
	}

	if (tgt->u.integrity.journal_crypt) { /* MAX length 15 + str_journal_crypt + str_key */
		num_options++;

		if (tgt->u.integrity.journal_crypt_key) {
			hexkey = crypt_bytes_to_hex(crypt_volume_key_length(tgt->u.integrity.journal_crypt_key),
						    crypt_volume_key_get_key(tgt->u.integrity.journal_crypt_key));
			if (!hexkey)
				goto out;
		} else
			hexkey = NULL;

		r = snprintf(journal_crypt, max_journal_crypt, " journal_crypt:%s%s%s",
			 tgt->u.integrity.journal_crypt, hexkey ? ":" : "", hexkey ?: "");
		crypt_safe_free(hexkey);
		if (r < 0 || r >= max_journal_crypt)
			goto out;
	}

	if (tgt->u.integrity.journal_size)
		num_options++;
	if (tgt->u.integrity.journal_watermark)
		num_options++;
	if (tgt->u.integrity.journal_commit_time)
		num_options++;
	if (tgt->u.integrity.interleave_sectors)
		num_options++;
	if (tgt->u.integrity.sector_size)
		num_options++;
	if (tgt->u.integrity.buffer_sectors)
		num_options++;
	if (tgt->u.integrity.fix_padding)
		num_options++;
	if (tgt->u.integrity.fix_hmac)
		num_options++;
	if (tgt->u.integrity.legacy_recalc)
		num_options++;
	if (tgt->u.integrity.meta_device)
		num_options++;
	if (flags & CRYPT_ACTIVATE_RECALCULATE)
		num_options++;
	if (flags & CRYPT_ACTIVATE_RECALCULATE_RESET)
		num_options++;
	if (flags & CRYPT_ACTIVATE_ALLOW_DISCARDS)
		num_options++;

	r = snprintf(features, max_size, "%d%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", num_options,
		tgt->u.integrity.journal_size ? _uf(feature[0], sizeof(feature[0]), /* MAX length 17 + int32 */
			"journal_sectors", (unsigned)(tgt->u.integrity.journal_size / SECTOR_SIZE)) : "",
		tgt->u.integrity.journal_watermark ? _uf(feature[1], sizeof(feature[1]), /* MAX length 19 + int32 */
			 /* bitmap overloaded values */
			 (flags & CRYPT_ACTIVATE_NO_JOURNAL_BITMAP) ? "sectors_per_bit" : "journal_watermark",
			 tgt->u.integrity.journal_watermark) : "",
		tgt->u.integrity.journal_commit_time ? _uf(feature[2], sizeof(feature[2]), /* MAX length 23 + int32 */
			 /* bitmap overloaded values */
			 (flags & CRYPT_ACTIVATE_NO_JOURNAL_BITMAP) ? "bitmap_flush_interval" : "commit_time",
			 tgt->u.integrity.journal_commit_time) : "",
		tgt->u.integrity.interleave_sectors ? _uf(feature[3], sizeof(feature[3]), /* MAX length 20 + int32 */
			"interleave_sectors", tgt->u.integrity.interleave_sectors) : "",
		tgt->u.integrity.sector_size ? _uf(feature[4], sizeof(feature[4]), /* MAX length 12 + int32 */
			"block_size", tgt->u.integrity.sector_size) : "",
		tgt->u.integrity.buffer_sectors ? _uf(feature[5], sizeof(feature[5]), /* MAX length 16 + int32 */
			"buffer_sectors", tgt->u.integrity.buffer_sectors) : "",
		tgt->u.integrity.integrity ? integrity : "",
		tgt->u.integrity.journal_integrity ? journal_integrity : "",
		tgt->u.integrity.journal_crypt ? journal_crypt : "",
		tgt->u.integrity.fix_padding ?  " fix_padding" : "", /* MAX length 12 */
		tgt->u.integrity.fix_hmac ?  " fix_hmac" : "", /* MAX length 9 */
		tgt->u.integrity.legacy_recalc ? " legacy_recalculate" : "", /* MAX length 19 */
		flags & CRYPT_ACTIVATE_RECALCULATE ? " recalculate" : "", /* MAX length 12 */
		flags & CRYPT_ACTIVATE_RECALCULATE_RESET ? " reset_recalculate" : "", /* MAX length 18 */
		flags & CRYPT_ACTIVATE_ALLOW_DISCARDS ? " allow_discards" : "", /* MAX length 15 */
		tgt->u.integrity.meta_device ? " meta_device:" : "", /* MAX length 13 + str_device */
		tgt->u.integrity.meta_device ? device_block_path(tgt->u.integrity.meta_device) : "");
	if (r < 0 || r >= max_size)
		goto out;

	if (flags & CRYPT_ACTIVATE_INLINE_MODE)
		mode = 'I';
	else if (flags & CRYPT_ACTIVATE_NO_JOURNAL_BITMAP)
		mode = 'B';
	else if (flags & CRYPT_ACTIVATE_RECOVERY)
		mode = 'R';
	else if (flags & CRYPT_ACTIVATE_NO_JOURNAL)
		mode = 'D';
	else
		mode = 'J';

	r = snprintf(params, max_size, "%s %" PRIu64 " %d %c %s",
		     device_block_path(tgt->data_device), tgt->u.integrity.offset,
		     tgt->u.integrity.tag_size, mode, features);
	if (r < 0 || r >= max_size)
		goto out;

	params_out = params;
out:
	crypt_safe_free(features);
	crypt_safe_free(integrity);
	crypt_safe_free(journal_integrity);
	crypt_safe_free(journal_crypt);
	if (!params_out)
		crypt_safe_free(params);

	return params_out;
}

static char *get_dm_linear_params(const struct dm_target *tgt)
{
	char *params;
	int r;
	int max_size = strlen(device_block_path(tgt->data_device)) + int_log10(tgt->u.linear.offset) + 3;

	params = crypt_safe_alloc(max_size);
	if (!params)
		return NULL;

	r = snprintf(params, max_size, "%s %" PRIu64,
		     device_block_path(tgt->data_device), tgt->u.linear.offset);

	if (r < 0 || r >= max_size) {
		crypt_safe_free(params);
		params = NULL;
	}

	return params;
}

static char *get_dm_zero_params(void)
{
	char *params = crypt_safe_alloc(1);
	if (!params)
		return NULL;

	params[0] = 0;
	return params;
}

/* DM helpers */
static int _dm_remove(const char *name, int udev_wait, int deferred)
{
	int r = 0;
	struct dm_task *dmt;
	uint32_t cookie = 0;

	if (!_dm_use_udev())
		udev_wait = 0;

	if (!(dmt = dm_task_create(DM_DEVICE_REMOVE)))
		return 0;

	if (!dm_task_set_name(dmt, name))
		goto out;

#if HAVE_DECL_DM_TASK_RETRY_REMOVE
	if (!dm_task_retry_remove(dmt))
		goto out;
#endif
#if HAVE_DECL_DM_TASK_DEFERRED_REMOVE
	if (deferred && !dm_task_deferred_remove(dmt))
		goto out;
#endif
	if (udev_wait && !_dm_task_set_cookie(dmt, &cookie, DM_UDEV_DISABLE_LIBRARY_FALLBACK))
		goto out;

	r = dm_task_run(dmt);

	if (udev_wait)
		(void)_dm_udev_wait(cookie);
out:
	dm_task_destroy(dmt);
	return r;
}

static int _dm_simple(int task, const char *name, uint64_t dmflags)
{
	int r = 0;
	struct dm_task *dmt;

	if (!(dmt = dm_task_create(task)))
		return 0;

	if (name && !dm_task_set_name(dmt, name))
		goto out;

	if (task == DM_DEVICE_SUSPEND &&
	    (dmflags & DM_SUSPEND_SKIP_LOCKFS) && !dm_task_skip_lockfs(dmt))
		goto out;

	if (task == DM_DEVICE_SUSPEND &&
	    (dmflags & DM_SUSPEND_NOFLUSH) && !dm_task_no_flush(dmt))
		goto out;

	r = dm_task_run(dmt);
out:
	dm_task_destroy(dmt);
	return r;
}

static int _dm_resume_device(const char *name, uint64_t dmflags);

static int _error_device(const char *name, size_t size)
{
	struct dm_task *dmt;
	int r = 0;

	if (!(dmt = dm_task_create(DM_DEVICE_RELOAD)))
		return 0;

	if (!dm_task_set_name(dmt, name))
		goto out;

	if (!dm_task_add_target(dmt, UINT64_C(0), size, "error", ""))
		goto out;

	if (!dm_task_set_ro(dmt))
		goto out;

	if (!dm_task_no_open_count(dmt))
		goto out;

	if (!dm_task_run(dmt))
		goto out;

	if (_dm_resume_device(name, 0)) {
		_dm_simple(DM_DEVICE_CLEAR, name, 0);
		goto out;
	}

	r = 1;
out:
	dm_task_destroy(dmt);
	return r;
}

int dm_error_device(struct crypt_device *cd, const char *name)
{
	int r;
	struct crypt_dm_active_device dmd;

	if (!name)
		return -EINVAL;

	if (dm_init_context(cd, DM_UNKNOWN))
		return -ENOTSUP;

	if ((dm_query_device(cd, name, 0, &dmd) >= 0) && _error_device(name, dmd.size))
		r = 0;
	else
		r = -EINVAL;

	dm_targets_free(cd, &dmd);

	dm_exit_context();

	return r;
}

int dm_clear_device(struct crypt_device *cd, const char *name)
{
	int r;

	if (!name)
		return -EINVAL;

	if (dm_init_context(cd, DM_UNKNOWN))
		return -ENOTSUP;

	if (_dm_simple(DM_DEVICE_CLEAR, name, 0))
		r = 0;
	else
		r = -EINVAL;

	dm_exit_context();

	return r;
}

int dm_remove_device(struct crypt_device *cd, const char *name, uint32_t flags)
{
	struct crypt_dm_active_device dmd = {};
	int r = -EINVAL;
	int retries = (flags & CRYPT_DEACTIVATE_FORCE) ? RETRY_COUNT : 1;
	int deferred = (flags & CRYPT_DEACTIVATE_DEFERRED) ? 1 : 0;
	int error_target = 0;
	uint64_t dmt_flags;

	if (!name)
		return -EINVAL;

	if (dm_init_context(cd, DM_UNKNOWN))
		return -ENOTSUP;

	if (deferred && !dm_flags(cd, DM_UNKNOWN, &dmt_flags) && !(dmt_flags & DM_DEFERRED_SUPPORTED)) {
		log_err(cd, _("Requested deferred flag is not supported."));
		dm_exit_context();
		return -ENOTSUP;
	}

	do {
		r = _dm_remove(name, 1, deferred) ? 0 : -EINVAL;
		if (--retries && r) {
			log_dbg(cd, "WARNING: other process locked internal device %s, %s.",
				name, retries ? "retrying remove" : "giving up");
			sleep(1);
			if ((flags & CRYPT_DEACTIVATE_FORCE) && !error_target) {
				/* If force flag is set, replace device with error, read-only target.
				 * it should stop processes from reading it and also removed underlying
				 * device from mapping, so it is usable again.
				 * Anyway, if some process try to read temporary cryptsetup device,
				 * it is bug - no other process should try touch it (e.g. udev).
				 */
				if (!dm_query_device(cd, name, 0, &dmd)) {
					_error_device(name, dmd.size);
					error_target = 1;
				}
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
static int dm_prepare_uuid(struct crypt_device *cd, const char *name, const char *type,
			    const char *uuid, char *buf, size_t buflen)
{
	char *ptr, uuid2[UUID_LEN] = {0};
	uuid_t uu;
	int i = 0;

	/* Remove '-' chars */
	if (uuid) {
		if (uuid_parse(uuid, uu) < 0) {
			log_dbg(cd, "Requested UUID %s has invalid format.", uuid);
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
	if (i < 0)
		return 0;

	log_dbg(cd, "DM-UUID is %s", buf);
	if ((size_t)i >= buflen)
		log_err(cd, _("DM-UUID for device %s was truncated."), name);

	return 1;
}

int lookup_dm_dev_by_uuid(struct crypt_device *cd, const char *uuid, const char *type)
{
	int r_udev, r;
	char *c;
	char dev_uuid[DM_UUID_LEN + DM_BY_ID_PREFIX_LEN] = DM_BY_ID_PREFIX;

	if (!dm_prepare_uuid(cd, "", type, uuid, dev_uuid + DM_BY_ID_PREFIX_LEN, DM_UUID_LEN))
		return -EINVAL;

	c = strrchr(dev_uuid, '-');
	if (!c)
		return -EINVAL;

	/* cut of dm name */
	*c = '\0';

	/* Either udev or sysfs can report that device is active. */
	r = lookup_by_disk_id(dev_uuid);
	if (r > 0)
		return r;

	r_udev = r;
	r = lookup_by_sysfs_uuid_field(dev_uuid + DM_BY_ID_PREFIX_LEN);

	return r == -ENOENT ? r_udev : r;
}

static int _add_dm_targets(struct dm_task *dmt, struct crypt_dm_active_device *dmd)
{
	const char *target;
	struct dm_target *tgt = &dmd->segment;

	do {
		switch (tgt->type) {
		case DM_CRYPT:
			target = DM_CRYPT_TARGET;
			break;
		case DM_VERITY:
			target = DM_VERITY_TARGET;
			break;
		case DM_INTEGRITY:
			target = DM_INTEGRITY_TARGET;
			break;
		case DM_LINEAR:
			target = DM_LINEAR_TARGET;
			break;
		case DM_ZERO:
			target = DM_ZERO_TARGET;
			break;
		default:
			return -ENOTSUP;
		}

		if (!dm_task_add_target(dmt, tgt->offset, tgt->size, target, tgt->params))
			return -EINVAL;

		tgt = tgt->next;
	} while (tgt);

	return 0;
}

static void _destroy_dm_targets_params(struct crypt_dm_active_device *dmd)
{
	struct dm_target *t = &dmd->segment;

	do {
		crypt_safe_free(t->params);
		t->params = NULL;
		t = t->next;
	} while (t);
}

static int _create_dm_targets_params(struct crypt_dm_active_device *dmd)
{
	int r;
	struct dm_target *tgt = &dmd->segment;

	do {
		if (tgt->type == DM_CRYPT)
			tgt->params = get_dm_crypt_params(tgt, dmd->flags);
		else if (tgt->type == DM_VERITY)
			tgt->params = get_dm_verity_params(tgt, dmd->flags);
		else if (tgt->type == DM_INTEGRITY)
			tgt->params = get_dm_integrity_params(tgt, dmd->flags);
		else if (tgt->type == DM_LINEAR)
			tgt->params = get_dm_linear_params(tgt);
		else if (tgt->type == DM_ZERO)
			tgt->params = get_dm_zero_params();
		else {
			r = -ENOTSUP;
			goto err;
		}

		if (!tgt->params) {
			r = -EINVAL;
			goto err;
		}
		tgt = tgt->next;
	} while (tgt);

	return 0;
err:
	_destroy_dm_targets_params(dmd);
	return r;
}

static bool device_disappeared(struct crypt_device *cd, struct device *device, const char *type)
{
	struct stat st;

	if (!device)
		return false;

	/*
	 * Cannot use device_check_access(cd, device, DEV_OK) as it always accesses block device,
	 * we want to check for underlying file presence (if device is an image).
	 */
	if (stat(device_path(device), &st) < 0) {
		log_dbg(cd, "%s device %s disappeared.", type, device_path(device));
		return true;
	}

	log_dbg(cd, "%s device %s is OK.", type, device_path(device));
	return false;
}

static bool dm_table_devices_disappeared(struct crypt_device *cd, struct crypt_dm_active_device *dmd)
{
	struct dm_target *tgt = &dmd->segment;

	do {
		if (device_disappeared(cd, tgt->data_device, "Data"))
			return true;
		if (tgt->type == DM_VERITY) {
			if (device_disappeared(cd, tgt->u.verity.hash_device, "Hash"))
				return true;
			if (device_disappeared(cd, tgt->u.verity.fec_device, "FEC"))
				return true;
		} else if (tgt->type == DM_INTEGRITY) {
			if (device_disappeared(cd, tgt->u.integrity.meta_device, "Integrity meta"))
				return true;
		}
		tgt = tgt->next;
	} while (tgt);

	return false;
}

static int _dm_create_device(struct crypt_device *cd, const char *name, const char *type,
			     struct crypt_dm_active_device *dmd)
{
	struct dm_task *dmt = NULL;
	struct dm_info dmi;
	char dev_uuid[DM_UUID_LEN] = {0};
	int r = -EINVAL;
	uint32_t cookie = 0, read_ahead = 0;
	uint16_t udev_flags = DM_UDEV_DISABLE_LIBRARY_FALLBACK;

	if (dmd->flags & CRYPT_ACTIVATE_PRIVATE)
		udev_flags |= CRYPT_TEMP_UDEV_FLAGS;

	/* All devices must have DM_UUID, only resize on old device is exception */
	if (!dm_prepare_uuid(cd, name, type, dmd->uuid, dev_uuid, sizeof(dev_uuid)))
		goto out;

	if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
		goto out;

	if (!dm_task_set_name(dmt, name))
		goto out;

	if (!dm_task_set_uuid(dmt, dev_uuid))
		goto out;

	if (!dm_task_secure_data(dmt))
		goto out;
	if ((dmd->flags & CRYPT_ACTIVATE_READONLY) && !dm_task_set_ro(dmt))
		goto out;

	r = _create_dm_targets_params(dmd);
	if (r)
		goto out;

	r = _add_dm_targets(dmt, dmd);
	if (r)
		goto out;

	r = -EINVAL;

#ifdef DM_READ_AHEAD_MINIMUM_FLAG
	if (device_read_ahead(dmd->segment.data_device, &read_ahead) &&
	    !dm_task_set_read_ahead(dmt, read_ahead, DM_READ_AHEAD_MINIMUM_FLAG))
		goto out;
#endif
	if (_dm_use_udev() && !_dm_task_set_cookie(dmt, &cookie, udev_flags))
		goto out;

	if (!dm_task_run(dmt)) {
		r = -dm_task_get_errno(dmt);
		log_dbg(cd, "DM create task failed, dm_task errno: %i.", r);
		if (r == -ENOKEY || r == -EKEYREVOKED || r == -EKEYEXPIRED) {
			/* propagate DM errors around key management as such */
			r = -ENOKEY;
			goto out;
		}

		r = dm_status_device(cd, name);
		log_dbg(cd, "Device status returned %i.", r);
		if (r >= 0 || r == -EEXIST) {
			r = -EEXIST;
			goto out;
		}

		/* EEXIST above has priority */
		if (dm_task_get_errno(dmt) == EBUSY) {
			r = -EBUSY;
			goto out;
		}

		if (r != -ENODEV) {
			r = -EINVAL;
			goto out;
		}

		/* dm-ioctl failed => -ENODEV */
		if (dm_task_get_errno(dmt) == ENXIO)
			goto out;

		/* Some device or file node disappeared => -ENODEV */
		if (dm_table_devices_disappeared(cd, dmd))
			goto out;

		/* Bail out with EBUSY better than sleep and retry. */
		log_dbg(cd, "No referenced device missing, some device in use.");
		r = -EBUSY;
		goto out;
	}

	if (dm_task_get_info(dmt, &dmi))
		r = 0;

	if (_dm_use_udev()) {
		(void)_dm_udev_wait(cookie);
		cookie = 0;
	}

	if (r < 0)
		_dm_remove(name, 1, 0);

out:
	if (cookie && _dm_use_udev())
		(void)_dm_udev_wait(cookie);

	if (dmt)
		dm_task_destroy(dmt);

	dm_task_update_nodes();

	/* If code just loaded target module, update versions */
	_dm_check_versions(cd, dmd->segment.type);

	_destroy_dm_targets_params(dmd);

	return r;
}

static int _dm_resume_device(const char *name, uint64_t dmflags)
{
	struct dm_task *dmt;
	int r = -EINVAL;
	uint32_t cookie = 0;
	uint16_t udev_flags = DM_UDEV_DISABLE_LIBRARY_FALLBACK;

	if (dmflags & DM_RESUME_PRIVATE)
		udev_flags |= CRYPT_TEMP_UDEV_FLAGS;

	if (!(dmt = dm_task_create(DM_DEVICE_RESUME)))
		return r;

	if (!dm_task_set_name(dmt, name))
		goto out;

	if ((dmflags & DM_SUSPEND_SKIP_LOCKFS) && !dm_task_skip_lockfs(dmt))
		goto out;

	if ((dmflags & DM_SUSPEND_NOFLUSH) && !dm_task_no_flush(dmt))
		goto out;

	if (_dm_use_udev() && !_dm_task_set_cookie(dmt, &cookie, udev_flags))
		goto out;

	if (dm_task_run(dmt))
		r = 0;
out:
	if (cookie && _dm_use_udev())
		(void)_dm_udev_wait(cookie);

	dm_task_destroy(dmt);

	dm_task_update_nodes();

	return r;
}

static int _dm_reload_device(struct crypt_device *cd, const char *name,
			     struct crypt_dm_active_device *dmd)
{
	int r = -EINVAL;
	struct dm_task *dmt = NULL;
	uint32_t read_ahead = 0;

	/* All devices must have DM_UUID, only resize on old device is exception */
	if (!(dmt = dm_task_create(DM_DEVICE_RELOAD)))
		goto out;

	if (!dm_task_set_name(dmt, name))
		goto out;

	if (!dm_task_secure_data(dmt))
		goto out;
	if ((dmd->flags & CRYPT_ACTIVATE_READONLY) && !dm_task_set_ro(dmt))
		goto out;

	r = _create_dm_targets_params(dmd);
	if (r)
		goto out;

	r = _add_dm_targets(dmt, dmd);
	if (r)
		goto out;

	r = -EINVAL;

#ifdef DM_READ_AHEAD_MINIMUM_FLAG
	if (device_read_ahead(dmd->segment.data_device, &read_ahead) &&
	    !dm_task_set_read_ahead(dmt, read_ahead, DM_READ_AHEAD_MINIMUM_FLAG))
		goto out;
#endif

	if (dm_task_run(dmt))
		r = 0;
out:
	if (dmt)
		dm_task_destroy(dmt);

	/* If code just loaded target module, update versions */
	_dm_check_versions(cd, dmd->segment.type);

	_destroy_dm_targets_params(dmd);

	return r;
}

static void crypt_free_verity_params(struct crypt_params_verity *vp)
{
	if (!vp)
		return;

	free(CONST_CAST(void*)vp->hash_name);
	free(CONST_CAST(void*)vp->data_device);
	free(CONST_CAST(void*)vp->hash_device);
	free(CONST_CAST(void*)vp->fec_device);
	free(CONST_CAST(void*)vp->salt);
	free(vp);
}

static void _dm_target_free_query_path(struct crypt_device *cd, struct dm_target *tgt)
{
	switch(tgt->type) {
	case DM_CRYPT:
		crypt_free_volume_key(tgt->u.crypt.vk);
		free(CONST_CAST(void*)tgt->u.crypt.cipher);
		break;
	case DM_INTEGRITY:
		free(CONST_CAST(void*)tgt->u.integrity.integrity);
		crypt_free_volume_key(tgt->u.integrity.vk);

		free(CONST_CAST(void*)tgt->u.integrity.journal_integrity);
		crypt_free_volume_key(tgt->u.integrity.journal_integrity_key);

		free(CONST_CAST(void*)tgt->u.integrity.journal_crypt);
		crypt_free_volume_key(tgt->u.integrity.journal_crypt_key);

		device_free(cd, tgt->u.integrity.meta_device);
		break;
	case DM_VERITY:
		crypt_free_verity_params(tgt->u.verity.vp);
		device_free(cd, tgt->u.verity.hash_device);
		free(CONST_CAST(void*)tgt->u.verity.root_hash);
		free(CONST_CAST(void*)tgt->u.verity.root_hash_sig_key_desc);
		/* fall through */
	case DM_LINEAR:
		/* fall through */
	case DM_ERROR:
		/* fall through */
	case DM_ZERO:
		break;
	default:
		log_err(cd, _("Unknown dm target type."));
		return;
	}

	device_free(cd, tgt->data_device);
}

static void _dm_target_erase(struct crypt_device *cd, struct dm_target *tgt)
{
	if (tgt->direction == TARGET_EMPTY)
		return;

	if (tgt->direction == TARGET_QUERY)
		_dm_target_free_query_path(cd, tgt);

	if (tgt->type == DM_CRYPT)
		free(CONST_CAST(void*)tgt->u.crypt.integrity);
}

void dm_targets_free(struct crypt_device *cd, struct crypt_dm_active_device *dmd)
{
	struct dm_target *t = &dmd->segment, *next = t->next;

	_dm_target_erase(cd, t);

	while (next) {
		t = next;
		next = t->next;
		_dm_target_erase(cd, t);
		free(t);
	}

	memset(&dmd->segment, 0, sizeof(dmd->segment));
}

int dm_targets_allocate(struct dm_target *first, unsigned count)
{
	if (!first || first->next || !count)
		return -EINVAL;

	while (--count) {
		first->next = crypt_zalloc(sizeof(*first));
		if (!first->next)
			return -ENOMEM;
		first = first->next;
	}

	return 0;
}

static int check_retry(struct crypt_device *cd, uint32_t *dmd_flags, uint64_t dmt_flags)
{
	int ret = 0;

	/* If discard not supported try to load without discard */
	if ((*dmd_flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) &&
	    !(dmt_flags & DM_DISCARDS_SUPPORTED)) {
		log_dbg(cd, "Discard/TRIM is not supported");
		*dmd_flags = *dmd_flags & ~CRYPT_ACTIVATE_ALLOW_DISCARDS;
		ret = 1;
	}

	/* If kernel keyring is not supported load key directly in dm-crypt */
	if ((*dmd_flags & CRYPT_ACTIVATE_KEYRING_KEY) &&
	    !(dmt_flags & DM_KERNEL_KEYRING_SUPPORTED)) {
		log_dbg(cd, "dm-crypt does not support kernel keyring");
		*dmd_flags = *dmd_flags & ~CRYPT_ACTIVATE_KEYRING_KEY;
		ret = 1;
	}

	/* Drop performance options if not supported */
	if ((*dmd_flags & (CRYPT_ACTIVATE_SAME_CPU_CRYPT | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS)) &&
	    !(dmt_flags & (DM_SAME_CPU_CRYPT_SUPPORTED | DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED))) {
		log_dbg(cd, "dm-crypt does not support performance options");
		*dmd_flags = *dmd_flags & ~(CRYPT_ACTIVATE_SAME_CPU_CRYPT | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS);
		ret = 1;
	}

	/* Drop no workqueue options if not supported */
	if ((*dmd_flags & (CRYPT_ACTIVATE_NO_READ_WORKQUEUE | CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE)) &&
	    !(dmt_flags & DM_CRYPT_NO_WORKQUEUE_SUPPORTED)) {
		log_dbg(cd, "dm-crypt does not support performance options");
		*dmd_flags = *dmd_flags & ~(CRYPT_ACTIVATE_NO_READ_WORKQUEUE | CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE);
		ret = 1;
	}

	/* Drop high-priority workqueue options if not supported */
	if ((*dmd_flags & CRYPT_ACTIVATE_HIGH_PRIORITY) &&
	    !(dmt_flags & DM_CRYPT_HIGH_PRIORITY_SUPPORTED)) {
		log_dbg(cd, "dm-crypt does not support high-priority option");
		*dmd_flags = *dmd_flags & ~CRYPT_ACTIVATE_HIGH_PRIORITY;
		ret = 1;
	}

	return ret;
}

int dm_create_device(struct crypt_device *cd, const char *name,
		     const char *type,
		     struct crypt_dm_active_device *dmd)
{
	uint64_t dmt_flags = 0;
	int r = -EINVAL;

	if (!type || !dmd)
		return -EINVAL;

	if (dm_init_context(cd, dmd->segment.type))
		return -ENOTSUP;

	r = _dm_create_device(cd, name, type, dmd);
	if (!r || r == -EEXIST)
		goto out;

	if (dm_flags(cd, dmd->segment.type, &dmt_flags))
		goto out;

	if ((dmd->segment.type == DM_CRYPT || dmd->segment.type == DM_LINEAR || dmd->segment.type == DM_ZERO) &&
		check_retry(cd, &dmd->flags, dmt_flags)) {
		log_dbg(cd, "Retrying open without incompatible options.");
		r = _dm_create_device(cd, name, type, dmd);
		if (!r || r == -EEXIST)
			goto out;
	}

	if (dmd->flags & (CRYPT_ACTIVATE_SAME_CPU_CRYPT|CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS) &&
	    !(dmt_flags & (DM_SAME_CPU_CRYPT_SUPPORTED|DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED))) {
		log_err(cd, _("Requested dm-crypt performance options are not supported."));
		r = -EINVAL;
	}

	if (dmd->flags & (CRYPT_ACTIVATE_NO_READ_WORKQUEUE | CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE) &&
	    !(dmt_flags & DM_CRYPT_NO_WORKQUEUE_SUPPORTED)) {
		log_err(cd, _("Requested dm-crypt performance options are not supported."));
		r = -EINVAL;
	}

	if (dmd->flags & (CRYPT_ACTIVATE_IGNORE_CORRUPTION|
			  CRYPT_ACTIVATE_RESTART_ON_CORRUPTION|
			  CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS|
			  CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE) &&
	    !(dmt_flags & DM_VERITY_ON_CORRUPTION_SUPPORTED)) {
		log_err(cd, _("Requested dm-verity data corruption handling options are not supported."));
		r = -EINVAL;
	}

	if ((dmd->flags & CRYPT_ACTIVATE_ERROR_AS_CORRUPTION) &&
	    !(dmt_flags & DM_VERITY_ERROR_AS_CORRUPTION_SUPPORTED)) {
		log_err(cd, _("Requested dm-verity data corruption handling options are not supported."));
		r = -EINVAL;
	}

	if (dmd->flags & CRYPT_ACTIVATE_TASKLETS &&
	    !(dmt_flags & DM_VERITY_TASKLETS_SUPPORTED)) {
		log_err(cd, _("Requested dm-verity tasklets option is not supported."));
		r = -EINVAL;
	}

	if (dmd->flags & CRYPT_ACTIVATE_PANIC_ON_CORRUPTION &&
	    !(dmt_flags & DM_VERITY_PANIC_CORRUPTION_SUPPORTED)) {
		log_err(cd, _("Requested dm-verity data corruption handling options are not supported."));
		r = -EINVAL;
	}

	if (dmd->segment.type == DM_VERITY &&
	    dmd->segment.u.verity.fec_device && !(dmt_flags & DM_VERITY_FEC_SUPPORTED)) {
		log_err(cd, _("Requested dm-verity FEC options are not supported."));
		r = -EINVAL;
	}

	if (dmd->segment.type == DM_CRYPT) {
		if (dmd->segment.u.crypt.integrity && !(dmt_flags & DM_INTEGRITY_SUPPORTED)) {
			log_err(cd, _("Requested data integrity options are not supported."));
			r = -EINVAL;
		}
		if (dmd->segment.u.crypt.sector_size != SECTOR_SIZE && !(dmt_flags & DM_SECTOR_SIZE_SUPPORTED)) {
			log_err(cd, _("Requested sector_size option is not supported."));
			r = -EINVAL;
		}
		if (dmd->segment.u.crypt.sector_size > SECTOR_SIZE &&
		    dmd->size % dmd->segment.u.crypt.sector_size) {
			log_err(cd, _("The device size is not multiple of the requested sector size."));
			r = -EINVAL;
		}
		if (dmd->segment.u.crypt.integrity_key_size && !(dmt_flags & DM_CRYPT_INTEGRITY_KEY_SIZE_OPT_SUPPORTED)) {
			log_err(cd, _("Requested integrity_key_size option is not supported."));
			r = -EINVAL;
		}
	}

	if (dmd->segment.type == DM_INTEGRITY && (dmd->flags & CRYPT_ACTIVATE_RECALCULATE) &&
	    !(dmt_flags & DM_INTEGRITY_RECALC_SUPPORTED)) {
		log_err(cd, _("Requested automatic recalculation of integrity tags is not supported."));
		r = -EINVAL;
	}

	if (dmd->segment.type == DM_INTEGRITY && (dmd->flags & CRYPT_ACTIVATE_RECALCULATE_RESET) &&
	    !(dmt_flags & DM_INTEGRITY_RESET_RECALC_SUPPORTED)) {
		log_err(cd, _("Requested automatic recalculation of integrity tags is not supported."));
		r = -EINVAL;
	}

	if (dmd->segment.type == DM_INTEGRITY && (dmd->flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) &&
	    !(dmt_flags & DM_INTEGRITY_DISCARDS_SUPPORTED)) {
		log_err(cd, _("Discard/TRIM is not supported."));
		r = -EINVAL;
	}

	if (dmd->segment.type == DM_INTEGRITY && (dmd->flags & CRYPT_ACTIVATE_NO_JOURNAL_BITMAP) &&
	    !(dmt_flags & DM_INTEGRITY_BITMAP_SUPPORTED)) {
		log_err(cd, _("Requested dm-integrity bitmap mode is not supported."));
		r = -EINVAL;
	}

	if (dmd->segment.type == DM_INTEGRITY && (dmd->flags & CRYPT_ACTIVATE_INLINE_MODE) &&
	    !(dmt_flags & DM_INTEGRITY_INLINE_MODE_SUPPORTED)) {
		log_err(cd, _("Requested dm-integrity inline mode is not supported."));
		r = -EINVAL;
	}
out:
	/*
	 * Print warning if activating dm-crypt cipher_null device unless it's reencryption helper or
	 * keyslot encryption helper device (LUKS1 cipher_null devices).
	 */
	if (!r && !(dmd->flags & CRYPT_ACTIVATE_PRIVATE) && single_segment(dmd) && dmd->segment.type == DM_CRYPT &&
	    crypt_is_cipher_null(dmd->segment.u.crypt.cipher))
		log_dbg(cd, "Activated dm-crypt device with cipher_null. Device is not encrypted.");

	dm_exit_context();
	return r;
}

int dm_reload_device(struct crypt_device *cd, const char *name,
		     struct crypt_dm_active_device *dmd, uint64_t dmflags, unsigned resume)
{
	int r;
	uint64_t dmt_flags;

	if (!dmd)
		return -EINVAL;

	if (dm_init_context(cd, dmd->segment.type))
		return -ENOTSUP;

	if (dm_flags(cd, DM_INTEGRITY, &dmt_flags) || !(dmt_flags & DM_INTEGRITY_RECALC_SUPPORTED))
		dmd->flags &= ~CRYPT_ACTIVATE_RECALCULATE;

	r = _dm_reload_device(cd, name, dmd);

	if (r == -EINVAL && (dmd->segment.type == DM_CRYPT || dmd->segment.type == DM_LINEAR)) {
		if ((dmd->flags & (CRYPT_ACTIVATE_SAME_CPU_CRYPT|CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS)) &&
		    !dm_flags(cd, DM_CRYPT, &dmt_flags) && !(dmt_flags & (DM_SAME_CPU_CRYPT_SUPPORTED | DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED)))
			log_err(cd, _("Requested dm-crypt performance options are not supported."));
		if ((dmd->flags & (CRYPT_ACTIVATE_NO_READ_WORKQUEUE | CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE)) &&
		    !dm_flags(cd, DM_CRYPT, &dmt_flags) && !(dmt_flags & DM_CRYPT_NO_WORKQUEUE_SUPPORTED))
			log_err(cd, _("Requested dm-crypt performance options are not supported."));
		if ((dmd->flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) &&
		    !dm_flags(cd, DM_CRYPT, &dmt_flags) && !(dmt_flags & DM_DISCARDS_SUPPORTED))
			log_err(cd, _("Discard/TRIM is not supported."));
		if ((dmd->flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) &&
		    !dm_flags(cd, DM_INTEGRITY, &dmt_flags) && !(dmt_flags & DM_INTEGRITY_DISCARDS_SUPPORTED))
			log_err(cd, _("Discard/TRIM is not supported."));
	}

	if (!r && resume)
		r = _dm_resume_device(name, dmflags | act2dmflags(dmd->flags));

	dm_exit_context();
	return r;
}

static int dm_status_dmi(const char *name, struct dm_info *dmi,
			  const char *target, char **status_line)
{
	struct dm_task *dmt;
	uint64_t start, length;
	char *target_type, *params = NULL;
	int r = -EINVAL;

	if (!(dmt = dm_task_create(DM_DEVICE_STATUS)))
		return r;

	if (!dm_task_no_flush(dmt))
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

	r = -EEXIST;
	dm_get_next_target(dmt, NULL, &start, &length,
			   &target_type, &params);

	if (!target_type || start != 0)
		goto out;

	if (target && strcmp(target_type, target))
		goto out;

	/* for target == NULL check all supported */
	if (!target && (strcmp(target_type, DM_CRYPT_TARGET) &&
			strcmp(target_type, DM_VERITY_TARGET) &&
			strcmp(target_type, DM_INTEGRITY_TARGET) &&
			strcmp(target_type, DM_LINEAR_TARGET) &&
			strcmp(target_type, DM_ZERO_TARGET) &&
			strcmp(target_type, DM_ERROR_TARGET)))
		goto out;
	r = 0;
out:
	if (!r && status_line && !(*status_line = strdup(params)))
		r = -ENOMEM;

	dm_task_destroy(dmt);

	return r;
}

int dm_status_device(struct crypt_device *cd, const char *name)
{
	int r;
	struct dm_info dmi;
	struct stat st;

	/* libdevmapper is too clever and handles
	 * path argument differently with error.
	 * Fail early here if parameter is non-existent path.
	 */
	if (strchr(name, '/') && stat(name, &st) < 0)
		return -ENODEV;

	if (dm_init_context(cd, DM_UNKNOWN))
		return -ENOTSUP;
	r = dm_status_dmi(name, &dmi, NULL, NULL);
	dm_exit_context();

	if (r < 0)
		return r;

	return (dmi.open_count > 0) ? 1 : 0;
}

int dm_status_suspended(struct crypt_device *cd, const char *name)
{
	int r;
	struct dm_info dmi;

	if (dm_init_context(cd, DM_UNKNOWN))
		return -ENOTSUP;
	r = dm_status_dmi(name, &dmi, NULL, NULL);
	dm_exit_context();

	if (r < 0 && r != -EEXIST)
		return r;

	return dmi.suspended ? 1 : 0;
}

static int _dm_status_verity_ok(struct crypt_device *cd, const char *name)
{
	int r;
	struct dm_info dmi;
	char *status_line = NULL;

	r = dm_status_dmi(name, &dmi, DM_VERITY_TARGET, &status_line);
	if (r < 0 || !status_line) {
		free(status_line);
		return r;
	}

	log_dbg(cd, "Verity volume %s status is %s.", name, status_line ?: "");
	r = status_line[0] == 'V' ? 1 : 0;
	free(status_line);

	return r;
}

int dm_status_verity_ok(struct crypt_device *cd, const char *name)
{
	int r;

	if (dm_init_context(cd, DM_VERITY))
		return -ENOTSUP;
	r = _dm_status_verity_ok(cd, name);
	dm_exit_context();
	return r;
}

int dm_status_integrity_failures(struct crypt_device *cd, const char *name, uint64_t *count)
{
	int r;
	struct dm_info dmi;
	char *status_line = NULL;

	if (dm_init_context(cd, DM_INTEGRITY))
		return -ENOTSUP;

	r = dm_status_dmi(name, &dmi, DM_INTEGRITY_TARGET, &status_line);
	if (r < 0 || !status_line) {
		free(status_line);
		dm_exit_context();
		return r;
	}

	log_dbg(cd, "Integrity volume %s failure status is %s.", name, status_line ?: "");
	*count = strtoull(status_line, NULL, 10);
	free(status_line);
	dm_exit_context();

	return 0;
}

/* FIXME use hex wrapper, user val wrappers for line parsing */
static int _dm_target_query_crypt(struct crypt_device *cd, uint64_t get_flags,
				  char *params, struct dm_target *tgt,
				  uint32_t *act_flags)
{
	uint64_t val64;
	char *rcipher, *rintegrity, *key_, *rdevice, *endp, buffer[3], *arg, *key_desc, keyring[16];
	unsigned int i, val;
	int r;
	size_t key_size;
	struct device *data_device = NULL;
	char *cipher = NULL, *integrity = NULL;
	struct volume_key *vk = NULL;
	void *key = NULL;

	tgt->type = DM_CRYPT;
	tgt->direction = TARGET_QUERY;
	tgt->u.crypt.sector_size = SECTOR_SIZE;

	r = -EINVAL;

	rcipher = strsep(&params, " ");
	rintegrity = NULL;

	/* skip */
	key_ = strsep(&params, " ");
	if (!params)
		goto err;
	val64 = strtoull(params, &params, 10);
	if (*params != ' ')
		goto err;
	params++;

	tgt->u.crypt.iv_offset = val64;

	/* device */
	rdevice = strsep(&params, " ");
	if (get_flags & DM_ACTIVE_DEVICE) {
		arg = crypt_lookup_dev(rdevice);
		r = device_alloc(cd, &data_device, arg);
		free(arg);
		if (r < 0 && r != -ENOTBLK)
			goto err;
	}

	r = -EINVAL;

	/*offset */
	if (!params)
		goto err;
	val64 = strtoull(params, &params, 10);
	tgt->u.crypt.offset = val64;

	tgt->u.crypt.tag_size = 0;

	/* Features section, available since crypt target version 1.11 */
	if (*params) {
		if (*params != ' ')
			goto err;
		params++;

		/* Number of arguments */
		val64 = strtoull(params, &params, 10);
		if (*params != ' ')
			goto err;
		params++;

		for (i = 0; i < val64; i++) {
			if (!params)
				goto err;
			arg = strsep(&params, " ");
			if (!strcasecmp(arg, "allow_discards"))
				*act_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;
			else if (!strcasecmp(arg, "same_cpu_crypt"))
				*act_flags |= CRYPT_ACTIVATE_SAME_CPU_CRYPT;
			else if (!strcasecmp(arg, "submit_from_crypt_cpus"))
				*act_flags |= CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS;
			else if (!strcasecmp(arg, "no_read_workqueue"))
				*act_flags |= CRYPT_ACTIVATE_NO_READ_WORKQUEUE;
			else if (!strcasecmp(arg, "no_write_workqueue"))
				*act_flags |= CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE;
			else if (!strcasecmp(arg, "iv_large_sectors"))
				*act_flags |= CRYPT_ACTIVATE_IV_LARGE_SECTORS;
			else if (!strcasecmp(arg, "high_priority"))
				*act_flags |= CRYPT_ACTIVATE_HIGH_PRIORITY;
			else if (sscanf(arg, "integrity:%u:", &val) == 1) {
				tgt->u.crypt.tag_size = val;
				rintegrity = strchr(arg + strlen("integrity:"), ':');
				if (!rintegrity)
					goto err;
				rintegrity++;
			} else if (sscanf(arg, "integrity_key_size:%u", &val) == 1) {
				tgt->u.crypt.integrity_key_size = val;
			} else if (sscanf(arg, "sector_size:%u", &val) == 1) {
				tgt->u.crypt.sector_size = val;
			} else /* unknown option */
				goto err;
		}

		/* All parameters should be processed */
		if (params)
			goto err;
	}

	/* cipher */
	if (get_flags & DM_ACTIVE_CRYPT_CIPHER) {
		r = crypt_capi_to_cipher(&cipher, &integrity, rcipher, rintegrity);
		if (r < 0)
			goto err;
	}

	r = -EINVAL;

	if (key_[0] == ':')
		*act_flags |= CRYPT_ACTIVATE_KEYRING_KEY;

	if (get_flags & DM_ACTIVE_CRYPT_KEYSIZE) {
		/* we will trust kernel the key_string is in expected format */
		if (key_[0] == ':') {
			if (sscanf(key_ + 1, "%zu", &key_size) != 1)
				goto err;
		} else
			key_size = strlen(key_) / 2;

		vk = crypt_alloc_volume_key(key_size, NULL);
		if (!vk) {
			r = -ENOMEM;
			goto err;
		}

		if (get_flags & DM_ACTIVE_CRYPT_KEY) {
			if (key_[0] == ':') {
				/* :<key_size>:<key_type>:<key_description> */
				key_desc = NULL;
				r = -ENOMEM;
				endp = strpbrk(key_ + 1, ":");
				if (!endp)
					goto err;
				key_desc = strpbrk(endp + 1, ":");
				if (!key_desc)
					goto err;
				memcpy(keyring, endp + 1, key_desc - endp - 1);
				keyring[key_desc - endp - 1] = '\0';
				key_desc++;
				r = crypt_volume_key_set_description(vk, key_desc, key_type_by_name(keyring));
				if (r < 0)
					goto err;
			} else if (key_size) {
				key = crypt_safe_alloc(key_size);
				if (!key) {
					r = -ENOMEM;
					goto err;
				}
				buffer[2] = '\0';
				for(i = 0; i < crypt_volume_key_length(vk); i++) {
					crypt_safe_memcpy(buffer, &key_[i * 2], 2);
					*((char *)key + i) = strtoul(buffer, &endp, 16);
					if (endp != &buffer[2]) {
						r = -EINVAL;
						goto err;
					}
				}
				crypt_volume_key_pass_safe_alloc(vk, &key);
			}
		}
	}
	memset(key_, 0, strlen(key_));

	if (cipher)
		tgt->u.crypt.cipher = cipher;
	if (integrity)
		tgt->u.crypt.integrity = integrity;
	if (data_device)
		tgt->data_device = data_device;
	if (vk)
		tgt->u.crypt.vk = vk;
	return 0;
err:
	free(cipher);
	free(integrity);
	device_free(cd, data_device);
	crypt_safe_free(key);
	crypt_free_volume_key(vk);
	return r;
}

static int _dm_target_query_verity(struct crypt_device *cd,
				   uint64_t get_flags,
			           char *params,
			           struct dm_target *tgt,
				   uint32_t *act_flags)
{
	struct crypt_params_verity *vp = NULL;
	uint32_t val32;
	uint64_t val64;
	ssize_t len;
	char *str, *str2, *arg;
	unsigned int i, features;
	int r;
	struct device *data_device = NULL, *hash_device = NULL, *fec_device = NULL;
	char *hash_name = NULL, *root_hash = NULL, *salt = NULL, *fec_dev_str = NULL;
	char *root_hash_sig_key_desc = NULL;

	if (get_flags & DM_ACTIVE_VERITY_PARAMS) {
		vp = crypt_zalloc(sizeof(*vp));
		if (!vp)
			return -ENOMEM;
	}

	tgt->type = DM_VERITY;
	tgt->direction = TARGET_QUERY;
	tgt->u.verity.vp = vp;

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
		r = device_alloc(cd, &data_device, str2);
		free(str2);
		if (r < 0 && r != -ENOTBLK)
			return r;
	}

	r = -EINVAL;

	/* hash device */
	str = strsep(&params, " ");
	if (!params)
		goto err;
	if (get_flags & DM_ACTIVE_VERITY_HASH_DEVICE) {
		str2 = crypt_lookup_dev(str);
		r = device_alloc(cd, &hash_device, str2);
		free(str2);
		if (r < 0 && r != -ENOTBLK)
			goto err;
	}

	r = -EINVAL;

	/* data block size*/
	val32 = strtoul(params, &params, 10);
	if (*params != ' ')
		goto err;
	if (vp)
		vp->data_block_size = val32;
	params++;

	/* hash block size */
	val32 = strtoul(params, &params, 10);
	if (*params != ' ')
		goto err;
	if (vp)
		vp->hash_block_size = val32;
	params++;

	/* data blocks */
	val64 = strtoull(params, &params, 10);
	if (*params != ' ')
		goto err;
	if (vp)
		vp->data_size = val64;
	params++;

	/* hash start */
	val64 = strtoull(params, &params, 10);
	if (*params != ' ')
		goto err;
	tgt->u.verity.hash_offset = val64;
	params++;

	/* hash algorithm */
	str = strsep(&params, " ");
	if (!params)
		goto err;
	if (vp) {
		hash_name = strdup(str);
		if (!hash_name) {
			r = -ENOMEM;
			goto err;
		}
	}

	/* root digest */
	str = strsep(&params, " ");
	if (!params)
		goto err;
	len = crypt_hex_to_bytes(str, &str2, 0);
	if (len < 0) {
		r = len;
		goto err;
	}
	tgt->u.verity.root_hash_size = len;
	if (get_flags & DM_ACTIVE_VERITY_ROOT_HASH)
		root_hash = str2;
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
			if (len < 0) {
				r = len;
				goto err;
			}
			vp->salt_size = len;
			salt = str2;
		}
	}

	r = -EINVAL;

	/* Features section, available since verity target version 1.3 */
	if (params) {
		/* Number of arguments */
		val64 = strtoull(params, &params, 10);
		if (*params != ' ')
			goto err;
		params++;

		features = (int)val64;
		for (i = 0; i < features; i++) {
			r = -EINVAL;
			if (!params)
				goto err;
			arg = strsep(&params, " ");
			if (!strcasecmp(arg, "ignore_corruption"))
				*act_flags |= CRYPT_ACTIVATE_IGNORE_CORRUPTION;
			else if (!strcasecmp(arg, "restart_on_corruption"))
				*act_flags |= CRYPT_ACTIVATE_RESTART_ON_CORRUPTION;
			else if (!strcasecmp(arg, "panic_on_corruption"))
				*act_flags |= CRYPT_ACTIVATE_PANIC_ON_CORRUPTION;
			else if (!strcasecmp(arg, "restart_on_error") ||
				 !strcasecmp(arg, "panic_on_error"))
				*act_flags |= CRYPT_ACTIVATE_ERROR_AS_CORRUPTION;
			else if (!strcasecmp(arg, "ignore_zero_blocks"))
				*act_flags |= CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS;
			else if (!strcasecmp(arg, "check_at_most_once"))
				*act_flags |= CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE;
			else if (!strcasecmp(arg, "try_verify_in_tasklet"))
				*act_flags |= CRYPT_ACTIVATE_TASKLETS;
			else if (!strcasecmp(arg, "use_fec_from_device")) {
				str = strsep(&params, " ");
				str2 = crypt_lookup_dev(str);
				if (get_flags & DM_ACTIVE_VERITY_HASH_DEVICE) {
					r = device_alloc(cd, &fec_device, str2);
					if (r < 0 && r != -ENOTBLK) {
						free(str2);
						goto err;
					}
				}
				if (vp) {
					free(fec_dev_str);
					fec_dev_str = str2;
				} else
					free(str2);
				i++;
			} else if (!strcasecmp(arg, "fec_start")) {
				val64 = strtoull(params, &params, 10);
				if (*params)
					params++;
				tgt->u.verity.fec_offset = val64;
				if (vp)
					vp->fec_area_offset = val64 * vp->hash_block_size;
				i++;
			} else if (!strcasecmp(arg, "fec_blocks")) {
				val64 = strtoull(params, &params, 10);
				if (*params)
					params++;
				tgt->u.verity.fec_blocks = val64;
				i++;
			} else if (!strcasecmp(arg, "fec_roots")) {
				val32 = strtoul(params, &params, 10);
				if (*params)
					params++;
				if (vp)
					vp->fec_roots = val32;
				i++;
			} else if (!strcasecmp(arg, "root_hash_sig_key_desc")) {
				str = strsep(&params, " ");
				if (!str)
					goto err;
				if (vp && !root_hash_sig_key_desc) {
					root_hash_sig_key_desc = strdup(str);
					if (!root_hash_sig_key_desc) {
						r = -ENOMEM;
						goto err;
					}
					/* not stored in params, but cannot be used without vp */
					vp->flags |= CRYPT_VERITY_ROOT_HASH_SIGNATURE;
				}
				i++;
			} else /* unknown option */
				goto err;
		}

		/* All parameters should be processed */
		if (params && *params) {
			r = -EINVAL;
			goto err;
		}
	}

	if (data_device)
		tgt->data_device = data_device;
	if (hash_device)
		tgt->u.verity.hash_device = hash_device;
	if (fec_device)
		tgt->u.verity.fec_device = fec_device;
	if (root_hash)
		tgt->u.verity.root_hash = root_hash;
	if (vp && hash_name)
		vp->hash_name = hash_name;
	if (vp && salt)
		vp->salt = salt;
	if (vp && fec_dev_str)
		vp->fec_device = fec_dev_str;
	if (root_hash_sig_key_desc)
		tgt->u.verity.root_hash_sig_key_desc = root_hash_sig_key_desc;

	return 0;
err:
	device_free(cd, data_device);
	device_free(cd, hash_device);
	device_free(cd, fec_device);
	free(root_hash_sig_key_desc);
	free(root_hash);
	free(hash_name);
	free(salt);
	free(fec_dev_str);
	free(vp);
	return r;
}

static int _dm_target_query_integrity(struct crypt_device *cd,
			     uint64_t get_flags,
			     char *params,
			     struct dm_target *tgt,
			     uint32_t *act_flags)
{
	uint32_t val32;
	uint64_t val64;
	char c, *str, *str2, *arg;
	unsigned int i, features, val;
	ssize_t len;
	int r;
	struct device *data_device = NULL, *meta_device = NULL;
	char *integrity = NULL, *journal_crypt = NULL, *journal_integrity = NULL;
	struct volume_key *vk = NULL;
	struct volume_key *journal_integrity_key = NULL;
	struct volume_key *journal_crypt_key = NULL;

	tgt->type = DM_INTEGRITY;
	tgt->direction = TARGET_QUERY;

	/* data device */
	str = strsep(&params, " ");
	if (get_flags & DM_ACTIVE_DEVICE) {
		str2 = crypt_lookup_dev(str);
		r = device_alloc(cd, &data_device, str2);
		free(str2);
		if (r < 0 && r != -ENOTBLK)
			return r;
	}

	r = -EINVAL;

	/*offset */
	if (!params)
		goto err;
	val64 = strtoull(params, &params, 10);
	if (!*params || *params != ' ')
		goto err;
	tgt->u.integrity.offset = val64;

	/* tag size*/
	val32 = strtoul(params, &params, 10);
	tgt->u.integrity.tag_size = val32;
	if (!*params || *params != ' ')
		goto err;

	/* journal */
	c = toupper(*(++params));
	if (!*params || *(++params) != ' ' || (c != 'D' && c != 'J' && c != 'R' && c != 'B' && c != 'I'))
		goto err;
	if (c == 'D')
		*act_flags |= CRYPT_ACTIVATE_NO_JOURNAL;
	if (c == 'R')
		*act_flags |= CRYPT_ACTIVATE_RECOVERY;
	if (c == 'B') {
		*act_flags |= CRYPT_ACTIVATE_NO_JOURNAL;
		*act_flags |= CRYPT_ACTIVATE_NO_JOURNAL_BITMAP;
	}
	if (c == 'I') {
		*act_flags |= CRYPT_ACTIVATE_NO_JOURNAL;
		*act_flags |= CRYPT_ACTIVATE_INLINE_MODE;
	}

	tgt->u.integrity.sector_size = SECTOR_SIZE;

	/* Features section, number of arguments (always included) */
	val64 = strtoull(params, &params, 10);
	if (*params != ' ')
		goto err;
	params++;

	features = (int)val64;
	for (i = 0; i < features; i++) {
		r = -EINVAL;
		if (!params)
			goto err;
		arg = strsep(&params, " ");
		if (sscanf(arg, "journal_sectors:%u", &val) == 1)
			tgt->u.integrity.journal_size = val * SECTOR_SIZE;
		else if (sscanf(arg, "journal_watermark:%u", &val) == 1)
			tgt->u.integrity.journal_watermark = val;
		else if (sscanf(arg, "sectors_per_bit:%" PRIu64, &val64) == 1) {
			if (val64 > UINT_MAX)
				goto err;
			/* overloaded value for bitmap mode */
			tgt->u.integrity.journal_watermark = (unsigned int)val64;
		} else if (sscanf(arg, "commit_time:%u", &val) == 1)
			tgt->u.integrity.journal_commit_time = val;
		else if (sscanf(arg, "bitmap_flush_interval:%u", &val) == 1)
			/* overloaded value for bitmap mode */
			tgt->u.integrity.journal_commit_time = val;
		else if (sscanf(arg, "interleave_sectors:%u", &val) == 1)
			tgt->u.integrity.interleave_sectors = val;
		else if (sscanf(arg, "block_size:%u", &val) == 1)
			tgt->u.integrity.sector_size = val;
		else if (sscanf(arg, "buffer_sectors:%u", &val) == 1)
			tgt->u.integrity.buffer_sectors = val;
		else if (!strncmp(arg, "internal_hash:", 14) && !integrity) {
			str = &arg[14];
			arg = strsep(&str, ":");
			if (get_flags & DM_ACTIVE_INTEGRITY_PARAMS) {
				integrity = strdup(arg);
				if (!integrity) {
					r = -ENOMEM;
					goto err;
				}
			}

			if (str) {
				len = crypt_hex_to_bytes(str, &str2, 1);
				if (len < 0) {
					r = len;
					goto err;
				}

				r = 0;
				if (get_flags & DM_ACTIVE_CRYPT_KEY) {
					vk = crypt_alloc_volume_key(len, str2);
					if (!vk)
						r = -ENOMEM;
				} else if (get_flags & DM_ACTIVE_CRYPT_KEYSIZE) {
					vk = crypt_alloc_volume_key(len, NULL);
					if (!vk)
						r = -ENOMEM;
				}
				crypt_safe_free(str2);
				if (r < 0)
					goto err;
			}
		} else if (!strncmp(arg, "meta_device:", 12) && !meta_device) {
			if (get_flags & DM_ACTIVE_DEVICE) {
				str = crypt_lookup_dev(&arg[12]);
				r = device_alloc(cd, &meta_device, str);
				free(str);
				if (r < 0 && r != -ENOTBLK)
					goto err;
			}
		} else if (!strncmp(arg, "journal_crypt:", 14) && !journal_crypt) {
			str = &arg[14];
			arg = strsep(&str, ":");
			if (get_flags & DM_ACTIVE_INTEGRITY_PARAMS) {
				journal_crypt = strdup(arg);
				if (!journal_crypt) {
					r = -ENOMEM;
					goto err;
				}
			}

			if (str) {
				len = crypt_hex_to_bytes(str, &str2, 1);
				if (len < 0) {
					r = len;
					goto err;
				}

				r = 0;
				if (get_flags & DM_ACTIVE_JOURNAL_CRYPT_KEY) {
					journal_crypt_key = crypt_alloc_volume_key(len, str2);
					if (!journal_crypt_key)
						r = -ENOMEM;
				} else if (get_flags & DM_ACTIVE_JOURNAL_CRYPT_KEYSIZE) {
					journal_crypt_key = crypt_alloc_volume_key(len, NULL);
					if (!journal_crypt_key)
						r = -ENOMEM;
				}
				crypt_safe_free(str2);
				if (r < 0)
					goto err;
			}
		} else if (!strncmp(arg, "journal_mac:", 12) && !journal_integrity) {
			str = &arg[12];
			arg = strsep(&str, ":");
			if (get_flags & DM_ACTIVE_INTEGRITY_PARAMS) {
				journal_integrity = strdup(arg);
				if (!journal_integrity) {
					r = -ENOMEM;
					goto err;
				}
			}

			if (str) {
				len = crypt_hex_to_bytes(str, &str2, 1);
				if (len < 0) {
					r = len;
					goto err;
				}

				r = 0;
				if (get_flags & DM_ACTIVE_JOURNAL_MAC_KEY) {
					journal_integrity_key = crypt_alloc_volume_key(len, str2);
					if (!journal_integrity_key)
						r = -ENOMEM;
				} else if (get_flags & DM_ACTIVE_JOURNAL_MAC_KEYSIZE) {
					journal_integrity_key = crypt_alloc_volume_key(len, NULL);
					if (!journal_integrity_key)
						r = -ENOMEM;
				}
				crypt_safe_free(str2);
				if (r < 0)
					goto err;
			}
		} else if (!strcmp(arg, "recalculate")) {
			*act_flags |= CRYPT_ACTIVATE_RECALCULATE;
		} else if (!strcmp(arg, "reset_recalculate")) {
			*act_flags |= CRYPT_ACTIVATE_RECALCULATE_RESET;
		} else if (!strcmp(arg, "fix_padding")) {
			tgt->u.integrity.fix_padding = true;
		} else if (!strcmp(arg, "fix_hmac")) {
			tgt->u.integrity.fix_hmac = true;
		} else if (!strcmp(arg, "legacy_recalculate")) {
			tgt->u.integrity.legacy_recalc = true;
		} else if (!strcmp(arg, "allow_discards")) {
			*act_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;
		} else /* unknown option */
			goto err;
	}

	/* All parameters should be processed */
	if (params && *params) {
		r = -EINVAL;
		goto err;
	}

	if (data_device)
		tgt->data_device = data_device;
	if (meta_device)
		tgt->u.integrity.meta_device = meta_device;
	if (integrity)
		tgt->u.integrity.integrity = integrity;
	if (journal_crypt)
		tgt->u.integrity.journal_crypt = journal_crypt;
	if (journal_integrity)
		tgt->u.integrity.journal_integrity = journal_integrity;
	if (vk)
		tgt->u.integrity.vk = vk;
	if (journal_integrity_key)
		tgt->u.integrity.journal_integrity_key = journal_integrity_key;
	if (journal_crypt_key)
		tgt->u.integrity.journal_crypt_key = journal_crypt_key;
	return 0;
err:
	device_free(cd, data_device);
	device_free(cd, meta_device);
	free(integrity);
	free(journal_crypt);
	free(journal_integrity);
	crypt_free_volume_key(vk);
	crypt_free_volume_key(journal_integrity_key);
	crypt_free_volume_key(journal_crypt_key);
	return r;
}

static int _dm_target_query_linear(struct crypt_device *cd, struct dm_target *tgt,
				   uint64_t get_flags, char *params)
{
	uint64_t val64;
	char *rdevice, *arg;
	int r;
	struct device *device = NULL;

	/* device */
	rdevice = strsep(&params, " ");
	if (get_flags & DM_ACTIVE_DEVICE) {
		arg = crypt_lookup_dev(rdevice);
		r = device_alloc(cd, &device, arg);
		free(arg);
		if (r < 0 && r != -ENOTBLK)
			return r;
	}

	r = -EINVAL;

	/*offset */
	if (!params)
		goto err;
	val64 = strtoull(params, &params, 10);

	/* params should be empty now */
	if (*params)
		goto err;

	tgt->type = DM_LINEAR;
	tgt->direction = TARGET_QUERY;
	tgt->data_device = device;
	tgt->u.linear.offset = val64;

	return 0;
err:
	device_free(cd, device);
	return r;
}

static int _dm_target_query_error(struct dm_target *tgt)
{
	tgt->type = DM_ERROR;
	tgt->direction = TARGET_QUERY;

	return 0;
}

static int _dm_target_query_zero(struct dm_target *tgt)
{
	tgt->type = DM_ZERO;
	tgt->direction = TARGET_QUERY;

	return 0;
}

/*
 * on error retval has to be negative
 *
 * also currently any _dm_target_query fn does not perform cleanup on error
 */
static int dm_target_query(struct crypt_device *cd, struct dm_target *tgt, const uint64_t *start,
		    const uint64_t *length, const char *target_type,
		    char *params, uint64_t get_flags, uint32_t *act_flags)
{
	int r = -ENOTSUP;

	if (!strcmp(target_type, DM_CRYPT_TARGET))
		r = _dm_target_query_crypt(cd, get_flags, params, tgt, act_flags);
	else if (!strcmp(target_type, DM_VERITY_TARGET))
		r = _dm_target_query_verity(cd, get_flags, params, tgt, act_flags);
	else if (!strcmp(target_type, DM_INTEGRITY_TARGET))
		r = _dm_target_query_integrity(cd, get_flags, params, tgt, act_flags);
	else if (!strcmp(target_type, DM_LINEAR_TARGET))
		r = _dm_target_query_linear(cd, tgt, get_flags, params);
	else if (!strcmp(target_type, DM_ERROR_TARGET))
		r = _dm_target_query_error(tgt);
	else if (!strcmp(target_type, DM_ZERO_TARGET))
		r = _dm_target_query_zero(tgt);

	if (!r) {
		tgt->offset = *start;
		tgt->size = *length;
	}

	return r;
}

static int _dm_query_device(struct crypt_device *cd, const char *name,
		    uint64_t get_flags, struct crypt_dm_active_device *dmd)
{
	struct dm_target *t;
	struct dm_task *dmt;
	struct dm_info dmi;
	uint64_t start, length;
	char *target_type, *params;
	const char *tmp_uuid;
	void *next = NULL;
	int r = -EINVAL;

	t = &dmd->segment;

	if (!(dmt = dm_task_create(DM_DEVICE_TABLE)))
		return r;
	if (!dm_task_secure_data(dmt))
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

	if (dmi.target_count <= 0) {
		r = -EINVAL;
		goto out;
	}

	/* Never allow one to return empty key */
	if ((get_flags & DM_ACTIVE_CRYPT_KEY) && dmi.suspended) {
		log_dbg(cd, "Cannot read volume key while suspended.");
		r = -EINVAL;
		goto out;
	}

	r = dm_targets_allocate(&dmd->segment, dmi.target_count);
	if (r)
		goto out;

	do {
		next = dm_get_next_target(dmt, next, &start, &length,
	                                  &target_type, &params);

		r = dm_target_query(cd, t, &start, &length, target_type, params, get_flags, &dmd->flags);
		if (!r && t->type == DM_VERITY) {
			r = _dm_status_verity_ok(cd, name);
			if (r == 0)
				dmd->flags |= CRYPT_ACTIVATE_CORRUPTED;
		}

		if (r < 0) {
			if (r != -ENOTSUP)
				log_err(cd, _("Failed to query dm-%s segment."), target_type);
			goto out;
		}

		dmd->size += length;
		t = t->next;
	} while (next && t);

	if (dmi.read_only)
		dmd->flags |= CRYPT_ACTIVATE_READONLY;

	if (dmi.suspended)
		dmd->flags |= CRYPT_ACTIVATE_SUSPENDED;

	tmp_uuid = dm_task_get_uuid(dmt);
	if (!tmp_uuid)
		dmd->flags |= CRYPT_ACTIVATE_NO_UUID;
	else if (get_flags & DM_ACTIVE_UUID) {
		if (!strncmp(tmp_uuid, DM_UUID_PREFIX, DM_UUID_PREFIX_LEN))
			dmd->uuid = strdup(tmp_uuid + DM_UUID_PREFIX_LEN);
	}

	dmd->holders = 0;
#if (HAVE_DECL_DM_DEVICE_HAS_HOLDERS && HAVE_DECL_DM_DEVICE_HAS_MOUNTED_FS)
	if (get_flags & DM_ACTIVE_HOLDERS)
		dmd->holders = (dm_device_has_mounted_fs(dmi.major, dmi.minor) ||
				dm_device_has_holders(dmi.major, dmi.minor));
#endif

	r = (dmi.open_count > 0);
out:
	dm_task_destroy(dmt);

	if (r < 0)
		dm_targets_free(cd, dmd);

	return r;
}

int dm_query_device(struct crypt_device *cd, const char *name,
		    uint64_t get_flags, struct crypt_dm_active_device *dmd)
{
	int r;

	if (!dmd)
		return -EINVAL;

	memset(dmd, 0, sizeof(*dmd));

	if (dm_init_context(cd, DM_UNKNOWN))
		return -ENOTSUP;

	r = _dm_query_device(cd, name, get_flags, dmd);

	dm_exit_context();
	return r;
}

static int _process_deps(struct crypt_device *cd, const char *prefix, struct dm_deps *deps,
			 char **names, size_t names_offset, size_t names_length)
{
#if HAVE_DECL_DM_DEVICE_GET_NAME
	struct crypt_dm_active_device dmd;
	char dmname[PATH_MAX];
	unsigned i;
	int r, major, minor, count = 0;

	if (!prefix || !deps)
		return -EINVAL;

	for (i = 0; i < deps->count; i++) {
		major = major(deps->device[i]);
		if (!dm_is_dm_major(major))
			continue;

		minor = minor(deps->device[i]);
		if (!dm_device_get_name(major, minor, 0, dmname, PATH_MAX))
			return -EINVAL;

		memset(&dmd, 0, sizeof(dmd));
		r = _dm_query_device(cd, dmname, DM_ACTIVE_UUID, &dmd);
		if (r < 0)
			continue;

		if (!dmd.uuid ||
		    strncmp(prefix, dmd.uuid, strlen(prefix)) ||
		    crypt_string_in(dmname, names, names_length))
			*dmname = '\0';

		dm_targets_free(cd, &dmd);
		free(CONST_CAST(void*)dmd.uuid);

		if ((size_t)count >= (names_length - names_offset))
			return -ENOMEM;

		if (*dmname && !(names[names_offset + count++] = strdup(dmname)))
			return -ENOMEM;
	}

	return count;
#else
	return -EINVAL;
#endif
}

int dm_device_deps(struct crypt_device *cd, const char *name, const char *prefix,
		   char **names, size_t names_length)
{
	struct dm_task *dmt = NULL;
	struct dm_info dmi;
	struct dm_deps *deps;
	int r = -EINVAL;
	size_t i, last = 0, offset = 0;

	if (!name || !names_length || !names)
		return -EINVAL;

	if (dm_init_context(cd, DM_UNKNOWN))
		return -ENOTSUP;

	while (name) {
		if (!(dmt = dm_task_create(DM_DEVICE_DEPS)))
			goto out;
		if (!dm_task_set_name(dmt, name))
			goto out;

		r = -ENODEV;
		if (!dm_task_run(dmt))
			goto out;

		r = -EINVAL;
		if (!dm_task_get_info(dmt, &dmi))
			goto out;
		if (!(deps = dm_task_get_deps(dmt)))
			goto out;

		r = -ENODEV;
		if (!dmi.exists)
			goto out;

		r = _process_deps(cd, prefix, deps, names, offset, names_length - 1);
		if (r < 0)
			goto out;

		dm_task_destroy(dmt);
		dmt = NULL;

		offset += r;
		name = names[last++];
	}

	r = 0;
out:
	if (r < 0) {
		for (i = 0; i < names_length - 1; i++)
			free(names[i]);
		*names = NULL;
	}

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

	if (!dm_task_secure_data(dmt))
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

int dm_suspend_device(struct crypt_device *cd, const char *name, uint64_t dmflags)
{
	uint64_t dmt_flags;
	int r = -ENOTSUP;

	if (dm_init_context(cd, DM_UNKNOWN))
		return r;

	if (dmflags & DM_SUSPEND_WIPE_KEY) {
		if (dm_flags(cd, DM_CRYPT, &dmt_flags))
			goto out;

		if (!(dmt_flags & DM_KEY_WIPE_SUPPORTED))
			goto out;
	}

	r = -EINVAL;

	if (!_dm_simple(DM_DEVICE_SUSPEND, name, dmflags))
		goto out;

	if (dmflags & DM_SUSPEND_WIPE_KEY) {
		if (!_dm_message(name, "key wipe")) {
			_dm_resume_device(name, 0);
			goto out;
		}
	}

	r = 0;
out:
	dm_exit_context();
	return r;
}

int dm_resume_device(struct crypt_device *cd, const char *name, uint64_t dmflags)
{
	int r;

	if (dm_init_context(cd, DM_UNKNOWN))
		return -ENOTSUP;

	r = _dm_resume_device(name, dmflags);

	dm_exit_context();

	return r;
}

int dm_resume_and_reinstate_key(struct crypt_device *cd, const char *name,
				const struct volume_key *vk)
{
	uint64_t dmt_flags;
	int msg_size;
	char *msg = NULL, *key = NULL;
	int r = -ENOTSUP;

	if (dm_init_context(cd, DM_CRYPT) || dm_flags(cd, DM_CRYPT, &dmt_flags))
		return -ENOTSUP;

	if (!(dmt_flags & DM_KEY_WIPE_SUPPORTED))
		goto out;

	if (!crypt_volume_key_length(vk))
		msg_size = 11; // key set -
	else if (crypt_volume_key_description(vk))
		msg_size = strlen(crypt_volume_key_description(vk)) + int_log10(crypt_volume_key_length(vk)) + 18;
	else
		msg_size = crypt_volume_key_length(vk) * 2 + 10; // key set <key>

	msg = crypt_safe_alloc(msg_size);
	if (!msg) {
		r = -ENOMEM;
		goto out;
	}

	if (crypt_volume_key_description(vk)) {
		r = snprintf(msg, msg_size, "key set :%zu:logon:%s", crypt_volume_key_length(vk),
			     crypt_volume_key_description(vk));
	} else {
		if (!crypt_volume_key_length(vk))
			key = crypt_bytes_to_hex(0, NULL);
		else
			key = crypt_bytes_to_hex(crypt_volume_key_length(vk),
						 crypt_volume_key_get_key(vk));
		if (!key) {
			r = -ENOMEM;
			goto out;
		}

		r = snprintf(msg, msg_size, "key set %s", key);
	}
	if (r < 0 || r >= msg_size) {
		r = -EINVAL;
		goto out;
	}
	if (!_dm_message(name, msg) ||
	    _dm_resume_device(name, 0)) {
		r = -EINVAL;
		goto out;
	}
	r = 0;
out:
	crypt_safe_free(msg);
	crypt_safe_free(key);
	dm_exit_context();
	return r;
}

int dm_cancel_deferred_removal(const char *name)
{
	return _dm_message(name, "@cancel_deferred_remove") ? 0 : -ENOTSUP;
}

const char *dm_get_dir(void)
{
	return dm_dir();
}

int dm_get_iname(const char *name, char **iname, bool with_path)
{
	int r;

	if (with_path)
		r = asprintf(iname, "%s/%s_dif", dm_get_dir(), name);
	else
		r = asprintf(iname, "%s_dif", name);

	return r < 0 ? -ENOMEM : 0;
}

char *dm_get_active_iname(struct crypt_device *cd, const char *name)
{
	struct crypt_dm_active_device dmd = {}, dmdi = {};
	struct dm_target *tgt = &dmd.segment, *tgti = &dmdi.segment;
	char *ipath = NULL, *iname = NULL, *ret_iname = NULL;
	struct stat st;

	if (!name)
		return NULL;

	if (dm_query_device(cd, name, DM_ACTIVE_UUID, &dmd) < 0)
		return NULL;

	if (!single_segment(&dmd))
		goto out;

	if (tgt->type != DM_CRYPT || tgt->u.crypt.tag_size == 0)
		goto out;

	if (dm_get_iname(name, &iname, false) < 0)
		goto out;

	if (dm_get_iname(name, &ipath, true) < 0)
		goto out;

	if (stat(ipath, &st) < 0 || !S_ISBLK(st.st_mode))
		goto out;

	if (dm_query_device(cd, iname, DM_ACTIVE_UUID, &dmdi) < 0)
		goto out;

	if (single_segment(&dmdi) &&
	    tgti->type == DM_INTEGRITY &&
	    dm_uuid_integrity_cmp(dmd.uuid, dmdi.uuid) == 0) {
		ret_iname = iname;
		iname = NULL;
	}
out:
	dm_targets_free(cd, &dmdi);
	dm_targets_free(cd, &dmd);
	free(CONST_CAST(void*)dmd.uuid);
	free(CONST_CAST(void*)dmdi.uuid);
	free(ipath);
	free(iname);

	return ret_iname;
}

int dm_is_dm_device(int major)
{
	return dm_is_dm_major((uint32_t)major);
}

int dm_is_dm_kernel_name(const char *name)
{
	return strncmp(name, "dm-", 3) ? 0 : 1;
}

/*
 * compares UUIDs returned by device-mapper (striped by cryptsetup) and uuid in header
 */
int dm_uuid_cmp(const char *dm_uuid, const char *hdr_uuid)
{
	int i, j;
	char *str;

	if (!dm_uuid || !hdr_uuid)
		return -EINVAL;

	/* skip beyond LUKS2_HW_OPAL prefix */
	if (!strncmp(dm_uuid, CRYPT_LUKS2_HW_OPAL, strlen(CRYPT_LUKS2_HW_OPAL)))
		dm_uuid = dm_uuid + strlen(CRYPT_LUKS2_HW_OPAL);

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
 * compares two UUIDs returned by device-mapper (striped by cryptsetup)
 * used for stacked LUKS2 & INTEGRITY devices
 */
int dm_uuid_integrity_cmp(const char *dm_uuid, const char *dmi_uuid)
{
	int i;
	char *str, *stri;

	if (!dm_uuid || !dmi_uuid)
		return -EINVAL;

	/* skip beyond LUKS2_HW_OPAL prefix */
	if (!strncmp(dm_uuid, CRYPT_LUKS2_HW_OPAL, strlen(CRYPT_LUKS2_HW_OPAL)))
		dm_uuid = dm_uuid + strlen(CRYPT_LUKS2_HW_OPAL);

	str = strchr(dm_uuid, '-');
	if (!str)
		return -EINVAL;

	stri = strchr(dmi_uuid, '-');
	if (!stri)
		return -EINVAL;

	for (i = 1; str[i] && str[i] != '-'; i++) {
		if (!stri[i])
			return -EINVAL;

		if (str[i] != stri[i])
			return -EINVAL;
	}

	return 0;
}

/*
 * compares type of active device to provided string
 */
int dm_uuid_type_cmp(const char *dm_uuid, const char *type)
{
	size_t len;

	assert(type);

	len = strlen(type);
	if (dm_uuid && strlen(dm_uuid) > len &&
	    !strncmp(dm_uuid, type, len) && dm_uuid[len] == '-')
		return 0;

	return -ENODEV;
}

int dm_crypt_target_set(struct dm_target *tgt, uint64_t seg_offset, uint64_t seg_size,
	struct device *data_device, struct volume_key *vk, const char *cipher,
	uint64_t iv_offset, uint64_t data_offset,
	const char *integrity, uint32_t integrity_key_size, uint32_t tag_size,
	uint32_t sector_size)
{
	char *dm_integrity = NULL;

	if (tag_size) {
		/* Space for IV metadata only */
		dm_integrity = strdup(integrity ?: "none");
		if (!dm_integrity)
			return -ENOMEM;
	}

	tgt->data_device = data_device;

	tgt->type = DM_CRYPT;
	tgt->direction = TARGET_SET;
	tgt->u.crypt.vk = vk;
	tgt->offset = seg_offset;
	tgt->size = seg_size;

	tgt->u.crypt.cipher = cipher;
	tgt->u.crypt.integrity = dm_integrity;
	tgt->u.crypt.iv_offset = iv_offset;
	tgt->u.crypt.offset = data_offset;
	tgt->u.crypt.tag_size = tag_size;
	tgt->u.crypt.sector_size = sector_size;
	tgt->u.crypt.integrity_key_size = integrity_key_size;

	return 0;
}

int dm_verity_target_set(struct dm_target *tgt, uint64_t seg_offset, uint64_t seg_size,
	struct device *data_device, struct device *hash_device, struct device *fec_device,
	const char *root_hash, uint32_t root_hash_size, const char* root_hash_sig_key_desc,
	uint64_t hash_offset_block, uint64_t fec_blocks, struct crypt_params_verity *vp)
{
	if (!data_device || !hash_device || !vp)
		return -EINVAL;

	tgt->type = DM_VERITY;
	tgt->direction = TARGET_SET;
	tgt->offset = seg_offset;
	tgt->size = seg_size;
	tgt->data_device = data_device;

	tgt->u.verity.hash_device = hash_device;
	tgt->u.verity.fec_device = fec_device;
	tgt->u.verity.root_hash = root_hash;
	tgt->u.verity.root_hash_size = root_hash_size;
	tgt->u.verity.root_hash_sig_key_desc = root_hash_sig_key_desc;
	tgt->u.verity.hash_offset = hash_offset_block;
	tgt->u.verity.fec_offset = vp->fec_area_offset / vp->hash_block_size;
	tgt->u.verity.fec_blocks = fec_blocks;
	tgt->u.verity.vp = vp;

	return 0;
}

int dm_integrity_target_set(struct crypt_device *cd,
			struct dm_target *tgt, uint64_t seg_offset, uint64_t seg_size,
			struct device *meta_device,
		        struct device *data_device, uint64_t tag_size, uint64_t offset,
			uint32_t sector_size, struct volume_key *vk,
			struct volume_key *journal_crypt_key, struct volume_key *journal_mac_key,
			const struct crypt_params_integrity *ip)
{
	uint64_t dmi_flags;

	if (!data_device)
		return -EINVAL;

	_dm_check_versions(cd, DM_INTEGRITY);

	tgt->type = DM_INTEGRITY;
	tgt->direction = TARGET_SET;
	tgt->offset = seg_offset;
	tgt->size = seg_size;
	tgt->data_device = data_device;
	if (meta_device != data_device)
		tgt->u.integrity.meta_device = meta_device;
	tgt->u.integrity.tag_size = tag_size;
	tgt->u.integrity.offset = offset;
	tgt->u.integrity.sector_size = sector_size;

	tgt->u.integrity.vk = vk;
	tgt->u.integrity.journal_crypt_key = journal_crypt_key;
	tgt->u.integrity.journal_integrity_key = journal_mac_key;

	if (!dm_flags(cd, DM_INTEGRITY, &dmi_flags) &&
	    (dmi_flags & DM_INTEGRITY_FIX_PADDING_SUPPORTED) &&
	    !(crypt_get_compatibility(cd) & CRYPT_COMPAT_LEGACY_INTEGRITY_PADDING))
		tgt->u.integrity.fix_padding = true;

	if (!dm_flags(cd, DM_INTEGRITY, &dmi_flags) &&
	    (dmi_flags & DM_INTEGRITY_FIX_HMAC_SUPPORTED) &&
	    !(crypt_get_compatibility(cd) & CRYPT_COMPAT_LEGACY_INTEGRITY_HMAC))
		tgt->u.integrity.fix_hmac = true;

	/* This flag can be backported, just try to set it always */
	if (crypt_get_compatibility(cd) & CRYPT_COMPAT_LEGACY_INTEGRITY_RECALC)
		tgt->u.integrity.legacy_recalc = true;

	if (ip) {
		tgt->u.integrity.journal_size = ip->journal_size;
		tgt->u.integrity.journal_watermark = ip->journal_watermark;
		tgt->u.integrity.journal_commit_time = ip->journal_commit_time;
		tgt->u.integrity.interleave_sectors = ip->interleave_sectors;
		tgt->u.integrity.buffer_sectors = ip->buffer_sectors;
		tgt->u.integrity.journal_integrity = ip->journal_integrity;
		tgt->u.integrity.journal_crypt = ip->journal_crypt;
		tgt->u.integrity.integrity = ip->integrity;
	}

	return 0;
}

int dm_linear_target_set(struct dm_target *tgt, uint64_t seg_offset, uint64_t seg_size,
	struct device *data_device, uint64_t data_offset)
{
	if (!data_device)
		return -EINVAL;

	tgt->type = DM_LINEAR;
	tgt->direction = TARGET_SET;
	tgt->offset = seg_offset;
	tgt->size = seg_size;
	tgt->data_device = data_device;

	tgt->u.linear.offset = data_offset;

	return 0;
}

int dm_zero_target_set(struct dm_target *tgt, uint64_t seg_offset, uint64_t seg_size)
{
	tgt->type = DM_ZERO;
	tgt->direction = TARGET_SET;
	tgt->offset = seg_offset;
	tgt->size = seg_size;

	return 0;
}
