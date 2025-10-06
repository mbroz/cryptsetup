// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * OPAL utilities
 *
 * Copyright (C) 2022-2023 Luca Boccassi <bluca@debian.org>
 * Copyright (C) 2023-2025 Ondrej Kozina <okozina@redhat.com>
 * Copyright (C) 2024-2025 Milan Broz
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>     /* for major, minor */
#endif

#include "internal.h"
#include "libcryptsetup.h"
#include "luks2/hw_opal/hw_opal.h"
#include "utils_device_locking.h"

#if HAVE_HW_OPAL

#include <linux/sed-opal.h>
#include <linux/fs.h>

/* Error codes are defined in the specification:
 * TCG_Storage_Architecture_Core_Spec_v2.01_r1.00
 * Section 5.1.5: Method Status Codes
 * Names and values from table 166 */
typedef enum OpalStatus {
	OPAL_STATUS_SUCCESS = 0x00,
	OPAL_STATUS_NOT_AUTHORIZED = 0x01,
	OPAL_STATUS_OBSOLETE0 = 0x02, /* Undefined but possible return values are called 'obsolete' */
	OPAL_STATUS_SP_BUSY = 0x03,
	OPAL_STATUS_SP_FAILED = 0x04,
	OPAL_STATUS_SP_DISABLED = 0x05,
	OPAL_STATUS_SP_FROZEN = 0x06,
	OPAL_STATUS_NO_SESSIONS_AVAILABLE = 0x07,
	OPAL_STATUS_UNIQUENESS_CONFLICT = 0x08,
	OPAL_STATUS_INSUFFICIENT_SPACE = 0x09,
	OPAL_STATUS_INSUFFICIENT_ROWS = 0x0a,
	OPAL_STATUS_OBSOLETE1 = 0x0b, /* Undefined but possible return values are called 'obsolete' */
	OPAL_STATUS_INVALID_PARAMETER = 0x0c,
	OPAL_STATUS_OBSOLETE2 = 0x0d,
	OPAL_STATUS_OBSOLETE3 = 0x0e,
	OPAL_STATUS_TPER_MALFUNCTION = 0x0f,
	OPAL_STATUS_TRANSACTION_FAILURE = 0x10,
	OPAL_STATUS_RESPONSE_OVERFLOW = 0x11,
	OPAL_STATUS_AUTHORITY_LOCKED_OUT = 0x12,
	_OPAL_STATUS_MAX = 0x13,
} OpalStatus;

static const char* const opal_status_table[_OPAL_STATUS_MAX] = {
	[OPAL_STATUS_SUCCESS]               = "success",
	[OPAL_STATUS_NOT_AUTHORIZED]        = "not authorized",
	[OPAL_STATUS_OBSOLETE0]             = "obsolete (0x02)",
	[OPAL_STATUS_SP_BUSY]               = "SP busy",
	[OPAL_STATUS_SP_FAILED]             = "SP failed",
	[OPAL_STATUS_SP_DISABLED]           = "SP disabled",
	[OPAL_STATUS_SP_FROZEN]             = "SP frozen",
	[OPAL_STATUS_NO_SESSIONS_AVAILABLE] = "no sessions available",
	[OPAL_STATUS_UNIQUENESS_CONFLICT]   = "uniqueness conflict",
	[OPAL_STATUS_INSUFFICIENT_SPACE]    = "insufficient space",
	[OPAL_STATUS_INSUFFICIENT_ROWS]     = "insufficient rows",
	[OPAL_STATUS_OBSOLETE1]             = "obsolete (0x0b)",
	[OPAL_STATUS_INVALID_PARAMETER]     = "invalid parameter",
	[OPAL_STATUS_OBSOLETE2]             = "obsolete (0x0d)",
	[OPAL_STATUS_OBSOLETE3]             = "obsolete (0x0e)",
	[OPAL_STATUS_TPER_MALFUNCTION]      = "TPer malfunction",
	[OPAL_STATUS_TRANSACTION_FAILURE]   = "transaction failure",
	[OPAL_STATUS_RESPONSE_OVERFLOW]     = "response overflow",
	[OPAL_STATUS_AUTHORITY_LOCKED_OUT]  = "authority locked out",
};

static const char *opal_status_to_string(int t)
{
	if (t < 0)
		return strerror(-t);

	/* Fail, as defined by specification */
	if (t == 0x3f)
		return "unknown failure";

	if (t >= _OPAL_STATUS_MAX)
		return "unknown error";

	return opal_status_table[t];
}

static const char *opal_ioctl_to_string(unsigned long rq)
{
	switch(rq) {
	case IOC_OPAL_GET_STATUS:      return "GET_STATUS";
	case IOC_OPAL_GET_GEOMETRY:    return "GET_GEOMETRY";
	case IOC_OPAL_GET_LR_STATUS:   return "GET_LR_STATUS";
	case IOC_OPAL_TAKE_OWNERSHIP:  return "TAKE_OWNERSHIP";
	case IOC_OPAL_ACTIVATE_USR:    return "ACTIVATE_USR";
	case IOC_OPAL_ACTIVATE_LSP:    return "ACTIVATE_LSP";
	case IOC_OPAL_ERASE_LR:        return "ERASE_LR";
	case IOC_OPAL_SECURE_ERASE_LR: return "SECURE_ERASE_LR";
	case IOC_OPAL_ADD_USR_TO_LR:   return "ADD_USR_TO_LR";
	case IOC_OPAL_SET_PW:          return "SET_PW";
	case IOC_OPAL_LR_SETUP:        return "LR_SETUP";
	case IOC_OPAL_LOCK_UNLOCK:     return "LOCK_UNLOCK";
	case IOC_OPAL_SAVE:            return "SAVE";
	case IOC_OPAL_PSID_REVERT_TPR: return "PSID_REVERT_TPR";
	}

	assert(false && "unknown OPAL ioctl");
	return NULL;
}

static void opal_ioctl_debug(struct crypt_device *cd,
				    unsigned long rq,
				    void *args,
				    bool post,
				    int ret)
{
	const char *cmd = opal_ioctl_to_string(rq);

	if (ret) {
		log_dbg(cd, "OPAL %s failed: %s", cmd, opal_status_to_string(ret));
		return;
	}

	if (post) switch(rq) {
	case IOC_OPAL_GET_STATUS: { /* OUT */
		struct opal_status *st = args;
		log_dbg(cd, "OPAL %s: flags:%" PRIu32, cmd, st->flags);
		};
		break;
	case IOC_OPAL_GET_GEOMETRY: { /* OUT */
		struct opal_geometry *geo = args;
		log_dbg(cd, "OPAL %s: align:%" PRIu8 ", lb_size:%" PRIu32 ", gran:%" PRIu64 ", lowest_lba:%" PRIu64,
			cmd, geo->align, geo->logical_block_size, geo->alignment_granularity, geo->lowest_aligned_lba);
		};
		break;
	case IOC_OPAL_GET_LR_STATUS: { /* OUT */
		struct opal_lr_status *lrs = args;
		log_dbg(cd, "OPAL %s: sum:%" PRIu32 ", who:%" PRIu32 ", lr:%" PRIu8
			", start:%" PRIu64 ", length:%" PRIu64 ", rle:%" PRIu32 ", rwe:%" PRIu32 ", state:%" PRIu32,
			cmd, lrs->session.sum, lrs->session.who, lrs->session.opal_key.lr,
			lrs->range_start, lrs->range_length, lrs->RLE, lrs->WLE, lrs->l_state);
		};
		break;
	} else switch (rq) {
	case IOC_OPAL_TAKE_OWNERSHIP: { /* IN */
		log_dbg(cd, "OPAL %s", cmd);
		};
		break;
	case IOC_OPAL_ACTIVATE_USR: { /* IN */
		struct opal_session_info *ui = args;
		log_dbg(cd, "OPAL %s: sum:%" PRIu32 ", who:%" PRIu32 ", lr:%" PRIu8,
			cmd, ui->sum, ui->who, ui->opal_key.lr);
		};
		break;
	case IOC_OPAL_ACTIVATE_LSP: { /* IN */
		struct opal_lr_act *act = args;
		log_dbg(cd, "OPAL %s: k.lr:%" PRIu8 ", sum:%" PRIu32 ", num_lrs:%" PRIu8 ", lr:"
			"%"PRIu8"|%"PRIu8"|%"PRIu8"|%"PRIu8"|%"PRIu8"|%"PRIu8"|%"PRIu8"|%"PRIu8"|%"PRIu8,
			cmd, act->key.lr, act->sum, act->num_lrs,
			act->lr[0], act->lr[1], act->lr[2], act->lr[3], act->lr[4],
			act->lr[5], act->lr[6], act->lr[7], act->lr[8]);
		};
		break;
	case IOC_OPAL_ERASE_LR: { /* IN */
		struct opal_session_info *ui = args;
		log_dbg(cd, "OPAL %s: sum:%" PRIu32 ", who:%" PRIu32 ", lr:%" PRIu8,
			cmd, ui->sum, ui->who, ui->opal_key.lr);
		};
		break;
	case IOC_OPAL_SECURE_ERASE_LR: { /* IN */
		struct opal_session_info *ui = args;
		log_dbg(cd, "OPAL %s: sum:%" PRIu32 ", who:%" PRIu32 ", lr:%" PRIu8,
			cmd, ui->sum, ui->who, ui->opal_key.lr);
		};
		break;
	case IOC_OPAL_ADD_USR_TO_LR: { /* IN */
		struct opal_lock_unlock *lu = args;
		log_dbg(cd, "OPAL %s: sum:%" PRIu32 ", who:%" PRIu32 ", lr:%" PRIu8
			", l_state:%" PRIu32 ", flags:%" PRIu16,
			cmd, lu->session.sum, lu->session.who, lu->session.opal_key.lr,
			lu->l_state, lu->flags);
		};
		break;
	case IOC_OPAL_SET_PW: { /* IN */
		struct opal_new_pw *pw = args;
		log_dbg(cd, "OPAL %s: sum:%" PRIu32 ", who:%" PRIu32 ", lr:%" PRIu8,
			cmd, pw->session.sum, pw->session.who, pw->session.opal_key.lr);
		};
		break;
	case IOC_OPAL_LR_SETUP: { /* IN */
		struct opal_user_lr_setup *lrs = args;
		log_dbg(cd, "OPAL %s: sum:%" PRIu32 ", who:%" PRIu32 ", lr:%" PRIu8
			", start:%" PRIu64 ", length:%" PRIu64 ", rle:%" PRIu32 ", rwe:%" PRIu32,
			cmd, lrs->session.sum, lrs->session.who, lrs->session.opal_key.lr,
			lrs->range_start, lrs->range_length, lrs->RLE, lrs->WLE);
		};
		break;
	case IOC_OPAL_LOCK_UNLOCK: { /* IN */
		struct opal_lock_unlock *lu = args;
		log_dbg(cd, "OPAL %s: sum:%" PRIu32 ", who:%" PRIu32 ", lr:%" PRIu8
			", l_state:%" PRIu32 ", flags:%" PRIu16,
			cmd, lu->session.sum, lu->session.who, lu->session.opal_key.lr,
			lu->l_state, lu->flags);
		};
		break;
	case IOC_OPAL_SAVE: { /* IN */
		struct opal_lock_unlock *lu = args;
		log_dbg(cd, "OPAL %s: sum:%" PRIu32 ", who:%" PRIu32 ", lr:%" PRIu8
			", l_state:%" PRIu32 ", flags:%" PRIu16,
			cmd, lu->session.sum, lu->session.who, lu->session.opal_key.lr,
			lu->l_state, lu->flags);
		};
		break;
	case IOC_OPAL_PSID_REVERT_TPR: { /* IN */
		struct opal_key *key = args;
		log_dbg(cd, "OPAL %s: lr:%" PRIu8,
			cmd, key->lr);
		};
		break;
	}
}

static int opal_ioctl(struct crypt_device *cd, int fd, unsigned long rq, void *args)
{
	int r;

	opal_ioctl_debug(cd, rq, args, false, 0);
	r = ioctl(fd, rq, args);
	opal_ioctl_debug(cd, rq, args, true, r);

	return r;
}

static int opal_geometry_fd(struct crypt_device *cd,
			    int fd,
			    bool *ret_align,
			    uint32_t *ret_block_size,
			    uint64_t *ret_alignment_granularity_blocks,
			    uint64_t *ret_lowest_lba_blocks)
{
	int r;
	struct opal_geometry geo;

	assert(fd >= 0);

	r = opal_ioctl(cd, fd, IOC_OPAL_GET_GEOMETRY, &geo);
	if (r != OPAL_STATUS_SUCCESS)
		return r;

	if (ret_align)
		*ret_align = (geo.align == 1);
	if (ret_block_size)
		*ret_block_size = geo.logical_block_size;
	if (ret_alignment_granularity_blocks)
		*ret_alignment_granularity_blocks = geo.alignment_granularity;
	if (ret_lowest_lba_blocks)
		*ret_lowest_lba_blocks = geo.lowest_aligned_lba;

	return r;
}

static int opal_range_check_attributes_fd(struct crypt_device *cd,
	int fd,
	uint32_t segment_number,
	const struct volume_key *vk,
	const uint64_t *check_offset_sectors,
	const uint64_t *check_length_sectors,
	bool *check_read_locked,
	bool *check_write_locked,
	bool *ret_read_locked,
	bool *ret_write_locked)
{
	int r;
	struct opal_lr_status *lrs;
	int device_block_bytes;
	uint32_t opal_block_bytes = 0;
	uint64_t offset, length;
	bool read_locked, write_locked;

	assert(fd >= 0);
	assert(cd);
	assert(vk);
	assert(check_offset_sectors);
	assert(check_length_sectors);

	r = opal_geometry_fd(cd, fd, NULL, &opal_block_bytes, NULL, NULL);
	if (r != OPAL_STATUS_SUCCESS)
		return -EINVAL;

	/* Keep this as warning only */
	if (ioctl(fd, BLKSSZGET, &device_block_bytes) < 0 ||
	    (uint32_t)device_block_bytes != opal_block_bytes)
		log_err(cd, _("Bogus OPAL logical block size differs from device block size."));

	lrs = crypt_safe_alloc(sizeof(*lrs));
	if (!lrs)
		return -ENOMEM;

	*lrs = (struct opal_lr_status) {
		.session = {
			.who = segment_number + 1,
			.opal_key = {
				.key_len = crypt_volume_key_length(vk),
				.lr = segment_number
			}
		}
	};
	crypt_safe_memcpy(lrs->session.opal_key.key, crypt_volume_key_get_key(vk),
			  crypt_volume_key_length(vk));

	r = opal_ioctl(cd, fd, IOC_OPAL_GET_LR_STATUS, lrs);
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to get locking range status on device '%s'.",
			crypt_get_device_name(cd));
		r = -EINVAL;
		goto out;
	}

	r = 0;

	offset = lrs->range_start * opal_block_bytes / SECTOR_SIZE;
	if (offset != *check_offset_sectors) {
		log_err(cd, _("OPAL range %d offset %" PRIu64 " does not match expected values %" PRIu64 "."),
			segment_number, offset, *check_offset_sectors);
		r = -EINVAL;
	}

	length = lrs->range_length * opal_block_bytes / SECTOR_SIZE;
	if (length != *check_length_sectors) {
		log_err(cd, _("OPAL range %d length %" PRIu64" does not match device length %" PRIu64 "."),
			segment_number, length, *check_length_sectors);
		r = -EINVAL;
	}

	if (!lrs->RLE || !lrs->WLE) {
		log_err(cd, _("OPAL range %d locking is disabled."), segment_number);
		r = -EINVAL;
	}

	read_locked = (lrs->l_state == OPAL_LK);
	write_locked = !!(lrs->l_state & (OPAL_RO | OPAL_LK));

	if (check_read_locked && (read_locked != *check_read_locked)) {
		log_dbg(cd, "OPAL range %d read lock is %slocked.",
			segment_number, *check_read_locked ? "" : "not ");
		log_err(cd, _("Unexpected OPAL range %d lock state."), segment_number);
		r = -EINVAL;
	}

	if (check_write_locked && (write_locked != *check_write_locked)) {
		log_dbg(cd, "OPAL range %d write lock is %slocked.",
			segment_number, *check_write_locked ? "" : "not ");
		log_err(cd, _("Unexpected OPAL range %d lock state."), segment_number);
		r = -EINVAL;
	}

	if (ret_read_locked)
		*ret_read_locked = read_locked;
	if (ret_write_locked)
		*ret_write_locked = write_locked;
out:
	crypt_safe_free(lrs);

	return r;
}

static int opal_query_status(struct crypt_device *cd, struct device *dev, unsigned expected)
{
	struct opal_status st = { };
	int fd, r;

	assert(cd);
	assert(dev);

	fd = device_open(cd, dev, O_RDONLY);
	if (fd < 0)
		return -EIO;

	r = opal_ioctl(cd, fd, IOC_OPAL_GET_STATUS, &st);

	return r < 0 ? -EINVAL : (st.flags & expected) ? 1 : 0;
}

static int opal_enabled(struct crypt_device *cd, struct device *dev)
{
	return opal_query_status(cd, dev, OPAL_FL_LOCKING_ENABLED);
}

/* requires opal lock */
int opal_setup_ranges(struct crypt_device *cd,
		      struct device *dev,
		      const struct volume_key *vk,
		      uint64_t range_start_blocks,
		      uint64_t range_length_blocks,
		      uint32_t opal_block_bytes,
		      uint32_t segment_number,
		      const void *admin_key,
		      size_t admin_key_len)
{
	struct opal_lr_act *activate = NULL;
	struct opal_session_info *user_session = NULL;
	struct opal_lock_unlock *user_add_to_lr = NULL, *lock = NULL;
	struct opal_new_pw *new_pw = NULL;
	struct opal_user_lr_setup *setup = NULL;
	int r, fd;

	assert(cd);
	assert(dev);
	assert(vk);
	assert(admin_key);
	assert(crypt_volume_key_length(vk) <= OPAL_KEY_MAX);
	assert(opal_block_bytes >= SECTOR_SIZE);

	if (admin_key_len > OPAL_KEY_MAX)
		return -EINVAL;

	if (((UINT64_MAX / opal_block_bytes) < range_start_blocks) ||
	    ((UINT64_MAX / opal_block_bytes) < range_length_blocks))
		return -EINVAL;

	fd = device_open(cd, dev, O_RDONLY);
	if (fd < 0)
		return -EIO;

	r = opal_enabled(cd, dev);
	if (r < 0)
		return r;

	/* If OPAL has never been enabled, we need to take ownership and do basic setup first */
	if (r == 0) {
		activate = crypt_safe_alloc(sizeof(struct opal_lr_act));
		if (!activate) {
			r = -ENOMEM;
			goto out;
		}
		*activate = (struct opal_lr_act) {
			.key = {
				.key_len = admin_key_len,
			},
			.num_lrs = 8,
			/* A max of 9 segments are supported, enable them all as there's no reason not to
			 * (0 is whole-volume)
			 */
			.lr = { 1, 2, 3, 4, 5, 6, 7, 8 },
		};
		crypt_safe_memcpy(activate->key.key, admin_key, admin_key_len);

		r = opal_ioctl(cd, fd, IOC_OPAL_TAKE_OWNERSHIP, &activate->key);
		if (r < 0) {
			r = -ENOTSUP;
			log_dbg(cd, "OPAL not supported on this kernel version, refusing.");
			goto out;
		}
		if (r == OPAL_STATUS_NOT_AUTHORIZED) /* We'll try again with a different key. */ {
			r = -EPERM;
			log_dbg(cd, "Failed to take ownership of OPAL device '%s': permission denied",
				crypt_get_device_name(cd));
			goto out;
		}
		if (r != OPAL_STATUS_SUCCESS) {
			log_dbg(cd, "Failed to take ownership of OPAL device '%s': %s",
				crypt_get_device_name(cd), opal_status_to_string(r));
			r = -EINVAL;
			goto out;
		}

		r = opal_ioctl(cd, fd, IOC_OPAL_ACTIVATE_LSP, activate);
		if (r != OPAL_STATUS_SUCCESS) {
			log_dbg(cd, "Failed to activate OPAL device '%s': %s",
				crypt_get_device_name(cd), opal_status_to_string(r));
			r = -EINVAL;
			goto out;
		}
	} else {
		/* If it is already enabled, wipe the locking range first */
		user_session = crypt_safe_alloc(sizeof(struct opal_session_info));
		if (!user_session) {
			r = -ENOMEM;
			goto out;
		}
		*user_session = (struct opal_session_info) {
			.who = OPAL_ADMIN1,
			.opal_key = {
				.lr = segment_number,
				.key_len = admin_key_len,
			},
		};
		crypt_safe_memcpy(user_session->opal_key.key, admin_key, admin_key_len);

		r = opal_ioctl(cd, fd, IOC_OPAL_SECURE_ERASE_LR, user_session);
		if (r != OPAL_STATUS_SUCCESS) {
			log_dbg(cd, "Failed to reset (secure erase) OPAL locking range %u on device '%s': %s",
				segment_number, crypt_get_device_name(cd), opal_status_to_string(r));
			r = -EINVAL;
			goto out;
		}
	}

	crypt_safe_free(user_session);

	user_session = crypt_safe_alloc(sizeof(struct opal_session_info));
	if (!user_session) {
		r = -ENOMEM;
		goto out;
	}
	*user_session = (struct opal_session_info) {
		.who = segment_number + 1,
		.opal_key = {
			.key_len = admin_key_len,
		},
	};
	crypt_safe_memcpy(user_session->opal_key.key, admin_key, admin_key_len);

	r = opal_ioctl(cd, fd, IOC_OPAL_ACTIVATE_USR, user_session);
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to activate OPAL user on device '%s': %s",
			crypt_get_device_name(cd), opal_status_to_string(r));
		r = -EINVAL;
		goto out;
	}

	user_add_to_lr = crypt_safe_alloc(sizeof(struct opal_lock_unlock));
	if (!user_add_to_lr) {
		r = -ENOMEM;
		goto out;
	}
	*user_add_to_lr = (struct opal_lock_unlock) {
		.session = {
			.who = segment_number + 1,
			.opal_key = {
				.lr = segment_number,
				.key_len = admin_key_len,
			},
		},
		.l_state = OPAL_RO,
	};
	crypt_safe_memcpy(user_add_to_lr->session.opal_key.key, admin_key, admin_key_len);

	r = opal_ioctl(cd, fd, IOC_OPAL_ADD_USR_TO_LR, user_add_to_lr);
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to add OPAL user to locking range %u (RO) on device '%s': %s",
			segment_number, crypt_get_device_name(cd), opal_status_to_string(r));
		r = -EINVAL;
		goto out;
	}
	user_add_to_lr->l_state = OPAL_RW;
	r = opal_ioctl(cd, fd, IOC_OPAL_ADD_USR_TO_LR, user_add_to_lr);
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to add OPAL user to locking range %u (RW) on device '%s': %s",
			segment_number, crypt_get_device_name(cd), opal_status_to_string(r));
		r = -EINVAL;
		goto out;
	}

	new_pw = crypt_safe_alloc(sizeof(struct opal_new_pw));
	if (!new_pw) {
		r = -ENOMEM;
		goto out;
	}
	*new_pw = (struct opal_new_pw) {
		.session = {
			.who = OPAL_ADMIN1,
			.opal_key = {
				.lr = segment_number,
				.key_len = admin_key_len,
			},
		},
		.new_user_pw = {
			.who = segment_number + 1,
			.opal_key = {
				.key_len = crypt_volume_key_length(vk),
				.lr = segment_number,
			},
		},
	};
	crypt_safe_memcpy(new_pw->new_user_pw.opal_key.key, crypt_volume_key_get_key(vk),
			  crypt_volume_key_length(vk));
	crypt_safe_memcpy(new_pw->session.opal_key.key, admin_key, admin_key_len);

	r = opal_ioctl(cd, fd, IOC_OPAL_SET_PW, new_pw);
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to set OPAL user password on device '%s': (%d) %s",
			crypt_get_device_name(cd), r, opal_status_to_string(r));
		r = -EINVAL;
		goto out;
	}

	setup = crypt_safe_alloc(sizeof(struct opal_user_lr_setup));
	if (!setup) {
		r = -ENOMEM;
		goto out;
	}
	*setup = (struct opal_user_lr_setup) {
		.range_start = range_start_blocks,
		.range_length = range_length_blocks,
		/* Some drives do not enable Locking Ranges on setup. This have some
		 * interesting consequences: Lock command called later below will pass,
		 * but locking range will _not_ be locked at all.
		 */
		.RLE = 1,
		.WLE = 1,
		.session = {
			.who = OPAL_ADMIN1,
			.opal_key = {
				.key_len = admin_key_len,
				.lr = segment_number,
			},
		},
	};
	crypt_safe_memcpy(setup->session.opal_key.key, admin_key, admin_key_len);

	r = opal_ioctl(cd, fd, IOC_OPAL_LR_SETUP, setup);
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to setup locking range of length %llu at offset %llu on OPAL device '%s': %s",
			setup->range_length, setup->range_start, crypt_get_device_name(cd), opal_status_to_string(r));
		r = -EINVAL;
		goto out;
	}

	/* After setup an OPAL device is unlocked, but the expectation with cryptsetup is that it needs
	 * to be activated separately, so lock it immediately. */
	lock = crypt_safe_alloc(sizeof(struct opal_lock_unlock));
	if (!lock) {
		r = -ENOMEM;
		goto out;
	}
	*lock = (struct opal_lock_unlock) {
		.l_state = OPAL_LK,
		.session = {
			.who = segment_number + 1,
			.opal_key = {
				.key_len = crypt_volume_key_length(vk),
				.lr = segment_number,
			},
		}
	};
	crypt_safe_memcpy(lock->session.opal_key.key, crypt_volume_key_get_key(vk),
			  crypt_volume_key_length(vk));

	r = opal_ioctl(cd, fd, IOC_OPAL_LOCK_UNLOCK, lock);
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to lock OPAL device '%s': %s",
			crypt_get_device_name(cd), opal_status_to_string(r));
		r = -EINVAL;
		goto out;
	}

	/* Double check the locking range is locked and the ranges are set up as configured */
	r = opal_range_check_attributes_fd(cd, fd, segment_number, vk,
					   &(uint64_t) {range_start_blocks * opal_block_bytes / SECTOR_SIZE},
					   &(uint64_t) {range_length_blocks * opal_block_bytes / SECTOR_SIZE},
					   &(bool) {true}, &(bool){true}, NULL, NULL);
out:
	crypt_safe_free(activate);
	crypt_safe_free(user_session);
	crypt_safe_free(user_add_to_lr);
	crypt_safe_free(new_pw);
	crypt_safe_free(setup);
	crypt_safe_free(lock);

	return r;
}

static int opal_lock_unlock(struct crypt_device *cd,
			    struct device *dev,
			    uint32_t segment_number,
			    const struct volume_key *vk,
			    bool lock)
{
	struct opal_lock_unlock unlock = {
		.l_state = lock ? OPAL_LK : OPAL_RW,
		.session = {
			.who = segment_number + 1,
			.opal_key = {
				.lr = segment_number,
			},
		},
	};
	int r, fd;

	if (opal_supported(cd, dev) <= 0)
		return -ENOTSUP;
	if (!lock && !vk)
		return -EINVAL;

	fd = device_open(cd, dev, O_RDONLY);
	if (fd < 0)
		return -EIO;

	if (!lock) {
		assert(crypt_volume_key_length(vk) <= OPAL_KEY_MAX);

		unlock.session.opal_key.key_len = crypt_volume_key_length(vk);
		crypt_safe_memcpy(unlock.session.opal_key.key, crypt_volume_key_get_key(vk),
				  crypt_volume_key_length(vk));
	}

	r = opal_ioctl(cd, fd, IOC_OPAL_LOCK_UNLOCK, &unlock);
	if (r < 0) {
		r = -ENOTSUP;
		log_dbg(cd, "OPAL not supported on this kernel version, refusing.");
		goto out;
	}
	if (r == OPAL_STATUS_NOT_AUTHORIZED) /* We'll try again with a different key. */ {
		r = -EPERM;
		log_dbg(cd, "Failed to %slock OPAL device '%s': permission denied",
			lock ? "" : "un", crypt_get_device_name(cd));
		goto out;
	}
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to %slock OPAL device '%s': %s",
			lock ? "" : "un", crypt_get_device_name(cd), opal_status_to_string(r));
		r = -EINVAL;
		goto out;
	}

	/* If we are unlocking, also tell the kernel to automatically unlock when resuming
	 * from suspend, otherwise the drive will be locked and everything will go up in flames.
	 * Also set the flag to allow locking without having to pass the key again.
	 * But do not error out if this fails, as the device will already be unlocked.
	 *
	 * On a lock path we have to overwrite the cached key from kernel otherwise the locking range
	 * gets unlocked automatically after system resume even when cryptsetup previously locked it
	 * on purpose (crypt_deactivate* or crypt_suspend)
	 */
	if (!lock)
		unlock.flags = OPAL_SAVE_FOR_LOCK;

	r = opal_ioctl(cd, fd, IOC_OPAL_SAVE, &unlock);
	if (r != OPAL_STATUS_SUCCESS) {
		if (!lock)
			log_std(cd, "Failed to prepare OPAL device '%s' for sleep resume, be aware before suspending: %s",
				crypt_get_device_name(cd), opal_status_to_string(r));
		else
			log_std(cd, "Failed to erase OPAL key for device '%s' from kernel: %s",
				crypt_get_device_name(cd), opal_status_to_string(r));
		r = 0;
	}
out:
	if (!lock)
		crypt_safe_memzero(unlock.session.opal_key.key, unlock.session.opal_key.key_len);

	return r;
}

/* requires opal lock */
int opal_lock(struct crypt_device *cd, struct device *dev, uint32_t segment_number)
{
	return opal_lock_unlock(cd, dev, segment_number, NULL, /* lock= */ true);
}

/* requires opal lock */
int opal_unlock(struct crypt_device *cd,
		struct device *dev,
		uint32_t segment_number,
		const struct volume_key *vk)
{
	return opal_lock_unlock(cd, dev, segment_number, vk, /* lock= */ false);
}

/*
 * It does not require opal lock. This completely destroys
 * data on whole OPAL block device. Serialization does not
 * make sense here.
 */
int opal_factory_reset(struct crypt_device *cd,
		       struct device *dev,
		       const char *password,
		       size_t password_len)
{
	struct opal_key reset = {
		.key_len = password_len,
	};
	int r, fd;

	assert(cd);
	assert(dev);
	assert(password);

	if (password_len > OPAL_KEY_MAX)
		return -EINVAL;

	/*
	 * Submit PSID reset on R/W file descriptor so it
	 * triggers blkid rescan after we close it.
	 */
	fd = device_open(cd, dev, O_RDWR);
	if (fd < 0)
		return -EIO;

	crypt_safe_memcpy(reset.key, password, password_len);

	r = opal_ioctl(cd, fd, IOC_OPAL_PSID_REVERT_TPR, &reset);
	if (r < 0) {
		r = -ENOTSUP;
		log_dbg(cd, "OPAL not supported on this kernel version, refusing.");
		goto out;
	}
	if (r == OPAL_STATUS_NOT_AUTHORIZED) /* We'll try again with a different key. */ {
		r = -EPERM;
		log_dbg(cd, "Failed to reset OPAL device '%s', incorrect PSID?",
			crypt_get_device_name(cd));
		goto out;
	}
	if (r != OPAL_STATUS_SUCCESS) {
		r = -EINVAL;
		log_dbg(cd, "Failed to reset OPAL device '%s' with PSID: %s",
			crypt_get_device_name(cd), opal_status_to_string(r));
		goto out;
	}
out:
	crypt_safe_memzero(reset.key, reset.key_len);

	return r;
}

/* requires opal lock */
int opal_reset_segment(struct crypt_device *cd,
		       struct device *dev,
		       uint32_t segment_number,
		       const char *password,
		       size_t password_len)
{
	struct opal_session_info *user_session = NULL;
	struct opal_user_lr_setup *setup = NULL;
	int r, fd;

	assert(cd);
	assert(dev);
	assert(password);

	if (password_len > OPAL_KEY_MAX)
		return -EINVAL;

	if (opal_enabled(cd, dev) <= 0)
		return -EINVAL;

	user_session = crypt_safe_alloc(sizeof(struct opal_session_info));
	if (!user_session)
		return -ENOMEM;
	*user_session = (struct opal_session_info) {
		.who = OPAL_ADMIN1,
		.opal_key = {
			.lr = segment_number,
			.key_len = password_len,
		},
	};
	crypt_safe_memcpy(user_session->opal_key.key, password, password_len);

	fd = device_open(cd, dev, O_RDONLY);
	if (fd < 0) {
		r = -EIO;
		goto out;
	}

	r = opal_ioctl(cd, fd, IOC_OPAL_SECURE_ERASE_LR, user_session);
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to reset (secure erase) OPAL locking range %u on device '%s': %s",
			segment_number, crypt_get_device_name(cd), opal_status_to_string(r));
		r = -EINVAL;
		goto out;
	}

	/* Disable the locking range */
	setup = crypt_safe_alloc(sizeof(struct opal_user_lr_setup));
	if (!setup) {
		r = -ENOMEM;
		goto out;
	}
	*setup = (struct opal_user_lr_setup) {
		.range_start = 0,
		.range_length = 0,
		.session = {
			.who = OPAL_ADMIN1,
			.opal_key = user_session->opal_key,
		},
	};

	r = opal_ioctl(cd, fd, IOC_OPAL_LR_SETUP, setup);
	if (r != OPAL_STATUS_SUCCESS) {
		log_dbg(cd, "Failed to disable locking range on OPAL device '%s': %s",
			crypt_get_device_name(cd), opal_status_to_string(r));
		r = -EINVAL;
		goto out;
	}
out:
	crypt_safe_free(user_session);
	crypt_safe_free(setup);

	return r;
}

/*
 * Does not require opal lock (immutable).
 */
int opal_supported(struct crypt_device *cd, struct device *dev)
{
	return opal_query_status(cd, dev, OPAL_FL_SUPPORTED|OPAL_FL_LOCKING_SUPPORTED);
}

/*
 * Does not require opal lock (immutable).
 */
int opal_geometry(struct crypt_device *cd,
		  struct device *dev,
		  bool *ret_align,
		  uint32_t *ret_block_size,
		  uint64_t *ret_alignment_granularity_blocks,
		  uint64_t *ret_lowest_lba_blocks)
{
	int fd;

	assert(cd);
	assert(dev);

	fd = device_open(cd, dev, O_RDONLY);
	if (fd < 0)
		return -EIO;

	return opal_geometry_fd(cd, fd, ret_align, ret_block_size,
				ret_alignment_granularity_blocks, ret_lowest_lba_blocks);
}

/* requires opal lock */
int opal_range_check_attributes_and_get_lock_state(struct crypt_device *cd,
		     struct device *dev,
		     uint32_t segment_number,
		     const struct volume_key *vk,
		     const uint64_t *check_offset_sectors,
		     const uint64_t *check_length_sectors,
		     bool *ret_read_locked,
		     bool *ret_write_locked)
{
	int fd;

	assert(cd);
	assert(dev);
	assert(vk);

	fd = device_open(cd, dev, O_RDONLY);
	if (fd < 0)
		return -EIO;

	return opal_range_check_attributes_fd(cd, fd, segment_number, vk,
					      check_offset_sectors, check_length_sectors, NULL,
					      NULL, ret_read_locked, ret_write_locked);
}

static int opal_lock_internal(struct crypt_device *cd, struct device *opal_device, struct crypt_lock_handle **opal_lock)
{
	char *lock_resource;
	int devfd, r;
	struct stat st;

	if (!crypt_metadata_locking_enabled()) {
		*opal_lock = NULL;
		return 0;
	}

	/*
	 * This also asserts we do not hold any metadata lock on the same device to
	 * avoid deadlock (OPAL lock must be taken first)
	 */
	devfd = device_open(cd, opal_device, O_RDONLY);
	if (devfd < 0)
		return -EINVAL;

	if (fstat(devfd, &st) || !S_ISBLK(st.st_mode))
		return -EINVAL;

	r = asprintf(&lock_resource, "OPAL_%d:%d", major(st.st_rdev), minor(st.st_rdev));
	if (r < 0)
		return -ENOMEM;

	r = crypt_write_lock(cd, lock_resource, true, opal_lock);

	free(lock_resource);

	return r;
}

int opal_exclusive_lock(struct crypt_device *cd, struct device *opal_device, struct crypt_lock_handle **opal_lock)
{
	if (!cd || !opal_device || (crypt_get_type(cd) && strcmp(crypt_get_type(cd), CRYPT_LUKS2)))
		return -EINVAL;

	return opal_lock_internal(cd, opal_device, opal_lock);
}

void opal_exclusive_unlock(struct crypt_device *cd, struct crypt_lock_handle *opal_lock)
{
	crypt_unlock_internal(cd, opal_lock);
}

#else
#pragma GCC diagnostic ignored "-Wunused-parameter"

int opal_setup_ranges(struct crypt_device *cd,
		      struct device *dev,
		      const struct volume_key *vk,
		      uint64_t range_start_blocks,
		      uint64_t range_length_blocks,
		      uint32_t opal_block_bytes,
		      uint32_t segment_number,
		      const void *admin_key,
		      size_t admin_key_len)
{
	return -ENOTSUP;
}

int opal_lock(struct crypt_device *cd, struct device *dev, uint32_t segment_number)
{
	return -ENOTSUP;
}

int opal_unlock(struct crypt_device *cd,
		struct device *dev,
		uint32_t segment_number,
		const struct volume_key *vk)
{
	return -ENOTSUP;
}

int opal_supported(struct crypt_device *cd, struct device *dev)
{
	return -ENOTSUP;
}

int opal_factory_reset(struct crypt_device *cd,
		       struct device *dev,
		       const char *password,
		       size_t password_len)
{
	return -ENOTSUP;
}

int opal_reset_segment(struct crypt_device *cd,
		       struct device *dev,
		       uint32_t segment_number,
		       const char *password,
		       size_t password_len)
{
	return -ENOTSUP;
}

int opal_geometry(struct crypt_device *cd,
		  struct device *dev,
		  bool *ret_align,
		  uint32_t *ret_block_size,
		  uint64_t *ret_alignment_granularity_blocks,
		  uint64_t *ret_lowest_lba_blocks)
{
	return -ENOTSUP;
}

int opal_range_check_attributes_and_get_lock_state(struct crypt_device *cd,
		     struct device *dev,
		     uint32_t segment_number,
		     const struct volume_key *vk,
		     const uint64_t *check_offset_sectors,
		     const uint64_t *check_length_sectors,
		     bool *ret_read_locked,
		     bool *ret_write_locked)
{
	return -ENOTSUP;
}

int opal_exclusive_lock(struct crypt_device *cd, struct device *opal_device, struct crypt_lock_handle **opal_lock)
{
	return -ENOTSUP;
}

void opal_exclusive_unlock(struct crypt_device *cd, struct crypt_lock_handle *opal_lock)
{
}

#endif
