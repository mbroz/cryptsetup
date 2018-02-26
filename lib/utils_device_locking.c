/*
 * Metadata on-disk locking for processes serialization
 *
 * Copyright (C) 2016-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2018, Ondrej Kozina. All rights reserved.
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

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>     /* for major, minor */
#endif
#include <libgen.h>

#include "internal.h"
#include "utils_device_locking.h"

#define same_inode(buf1, buf2) \
	((buf1).st_ino == (buf2).st_ino && \
	 (buf1).st_dev == (buf2).st_dev)

#ifndef __GNUC__
# define __typeof__ typeof
#endif

enum lock_type {
	DEV_LOCK_READ = 0,
	DEV_LOCK_WRITE
};

struct crypt_lock_handle {
	dev_t devno;
	int flock_fd;
	enum lock_type type;
	__typeof__( ((struct stat*)0)->st_mode) mode;
};

static int resource_by_devno(char *res, size_t res_size, dev_t devno, unsigned fullpath)
{
	int r;

	if (fullpath)
		r = snprintf(res, res_size, "%s/L_%d:%d", DEFAULT_LUKS2_LOCK_PATH, major(devno), minor(devno));
	else
		r = snprintf(res, res_size, "L_%d:%d", major(devno), minor(devno));

	return (r < 0 || (size_t)r >= res_size) ? -EINVAL : 0;
}

static int open_lock_dir(struct crypt_device *cd, const char *dir, const char *base)
{
	int dirfd, lockdfd;

	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0) {
		log_dbg("Failed to open directory %s: (%d: %s).", dir, errno, strerror(errno));
		if (errno == ENOTDIR || errno == ENOENT)
			log_err(cd, _("Locking aborted. The locking path %s/%s is unusable (not a directory or missing).\n"), dir, base);
		return -EINVAL;
	}

	lockdfd = openat(dirfd, base, O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
	if (lockdfd < 0) {
		if (errno == ENOENT) {
			log_std(cd, _("WARNING: Locking directory %s/%s is missing!\n"), dir, base);

			/* success or failure w/ errno == EEXIST either way just try to open the 'base' directory again */
			if (mkdirat(dirfd, base, DEFAULT_LUKS2_LOCK_DIR_PERMS) && errno != EEXIST)
				log_dbg("Failed to create directory %s in %s (%d: %s).", base, dir, errno, strerror(errno));
			else
				lockdfd = openat(dirfd, base, O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
		} else {
			log_dbg("Failed to open directory %s/%s: (%d: %s)", dir, base, errno, strerror(errno));
			if (errno == ENOTDIR || errno == ELOOP)
				log_err(cd, _("Locking aborted. The locking path %s/%s is unusable (%s is not a directory).\n"), dir, base, base);
		}
	}

	close(dirfd);
	return lockdfd >= 0 ? lockdfd : -EINVAL;
}

static int open_resource(struct crypt_device *cd, const char *res)
{
	int err, lockdir_fd, r;
	char dir[] = DEFAULT_LUKS2_LOCK_PATH,
	     base[] = DEFAULT_LUKS2_LOCK_PATH;

	lockdir_fd = open_lock_dir(cd, dirname(dir), basename(base));
	if (lockdir_fd < 0)
		return -EINVAL;

	log_dbg("Opening lock resource file %s/%s", DEFAULT_LUKS2_LOCK_PATH, res);
	r = openat(lockdir_fd, res, O_CREAT | O_NOFOLLOW | O_RDWR | O_CLOEXEC, 0777);
	err = errno;

	close(lockdir_fd);

	return r < 0 ? -err : r;
}

static int acquire_lock_handle(struct crypt_device *cd, const char *device_path, struct crypt_lock_handle *h)
{
	char res[PATH_MAX];
	int dev_fd, fd;
	struct stat st;

	dev_fd = open(device_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (dev_fd < 0)
		return -EINVAL;

	if (fstat(dev_fd, &st)) {
		close(dev_fd);
		return -EINVAL;
	}

	if (S_ISBLK(st.st_mode)) {
		if (resource_by_devno(res, sizeof(res), st.st_rdev, 0)) {
			close(dev_fd);
			return -EINVAL;
		}

		fd = open_resource(cd, res);
		close(dev_fd);
		if (fd < 0)
			return fd;

		h->flock_fd = fd;
		h->devno = st.st_rdev;
	} else if (S_ISREG(st.st_mode)) {
		// FIXME: workaround for nfsv4
		fd = open(device_path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			h->flock_fd = dev_fd;
		else {
			h->flock_fd = fd;
			close(dev_fd);
		}
	} else {
		/* Wrong device type */
		close(dev_fd);
		return -EINVAL;
	}

	h->mode = st.st_mode;

	return 0;
}

static void release_lock_handle(struct crypt_lock_handle *h)
{
	char res[PATH_MAX];
	struct stat buf_a, buf_b;

	if (S_ISBLK(h->mode) && /* was it block device */
	    !flock(h->flock_fd, LOCK_EX | LOCK_NB) && /* lock to drop the file */
	    !resource_by_devno(res, sizeof(res), h->devno, 1) && /* acquire lock resource name */
	    !fstat(h->flock_fd, &buf_a) && /* read inode id referred by fd */
	    !stat(res, &buf_b) && /* does path file stil exist? */
	    same_inode(buf_a, buf_b)) { /* is it same id as the one referenced by fd? */
		/* coverity[toctou] */
		if (unlink(res)) /* yes? unlink the file */
			log_dbg("Failed to unlink resource file: %s", res);
	}

	if (close(h->flock_fd))
		log_dbg("Failed to close resource fd (%d).", h->flock_fd);
}

int device_locked(struct crypt_lock_handle *h)
{
	return (h && (h->type == DEV_LOCK_READ || h->type == DEV_LOCK_WRITE));
}

int device_locked_readonly(struct crypt_lock_handle *h)
{
	return (h && h->type == DEV_LOCK_READ);
}

static int verify_lock_handle(const char *device_path, struct crypt_lock_handle *h)
{
	char res[PATH_MAX];
	struct stat lck_st, res_st;

	/* we locked a regular file, check during device_open() instead. No reason to check now */
	if (S_ISREG(h->mode))
		return 0;

	if (resource_by_devno(res, sizeof(res), h->devno, 1))
		return -EINVAL;

	if (fstat(h->flock_fd, &lck_st))
		return -EINVAL;

	return (stat(res, &res_st) || !same_inode(lck_st, res_st)) ? -EAGAIN : 0;
}

struct crypt_lock_handle *device_read_lock_handle(struct crypt_device *cd, const char *device_path)
{
	int r;
	struct crypt_lock_handle *h = malloc(sizeof(*h));

	if (!h)
		return NULL;

	do {
		r = acquire_lock_handle(cd, device_path, h);
		if (r)
			break;

		log_dbg("Acquiring read lock for device %s.", device_path);

		if (flock(h->flock_fd, LOCK_SH)) {
			log_dbg("Shared flock failed with errno %d.", errno);
			r = -EINVAL;
			release_lock_handle(h);
			break;
		}

		log_dbg("Verifying read lock handle for device %s.", device_path);

		/*
		 * check whether another libcryptsetup process removed resource file before this
		 * one managed to flock() it. See release_lock_handle() for details
		 */
		r = verify_lock_handle(device_path, h);
		if (r) {
			flock(h->flock_fd, LOCK_UN);
			release_lock_handle(h);
			log_dbg("Read lock handle verification failed.");
		}
	} while (r == -EAGAIN);

	if (r) {
		free(h);
		return NULL;
	}

	h->type = DEV_LOCK_READ;

	return h;
}

struct crypt_lock_handle *device_write_lock_handle(struct crypt_device *cd, const char *device_path)
{
	int r;
	struct crypt_lock_handle *h = malloc(sizeof(*h));

	if (!h)
		return NULL;

	do {
		r = acquire_lock_handle(cd, device_path, h);
		if (r)
			break;

		log_dbg("Acquiring write lock for device %s.", device_path);

		if (flock(h->flock_fd, LOCK_EX)) {
			log_dbg("Exclusive flock failed with errno %d.", errno);
			r = -EINVAL;
			release_lock_handle(h);
			break;
		}

		log_dbg("Verifying write lock handle for device %s.", device_path);

		/*
		 * check whether another libcryptsetup process removed resource file before this
		 * one managed to flock() it. See release_lock_handle() for details
		 */
		r = verify_lock_handle(device_path, h);
		if (r) {
			flock(h->flock_fd, LOCK_UN);
			release_lock_handle(h);
			log_dbg("Write lock handle verification failed.");
		}
	} while (r == -EAGAIN);

	if (r) {
		free(h);
		return NULL;
	}

	h->type = DEV_LOCK_WRITE;

	return h;
}

void device_unlock_handle(struct crypt_lock_handle *h)
{
	if (flock(h->flock_fd, LOCK_UN))
		log_dbg("flock on fd %d failed.", h->flock_fd);

	release_lock_handle(h);

	free(h);
}

int device_locked_verify(int dev_fd, struct crypt_lock_handle *h)
{
	char res[PATH_MAX];
	struct stat dev_st, lck_st, st;

	if (fstat(dev_fd, &dev_st) || fstat(h->flock_fd, &lck_st))
		return 1;

	/* if device handle is regular file the handle must match the lock handle */
	if (S_ISREG(dev_st.st_mode)) {
		log_dbg("Veryfing locked device handle (regular file)");
		if (!same_inode(dev_st, lck_st))
			return 1;
	} else if (S_ISBLK(dev_st.st_mode)) {
		log_dbg("Veryfing locked device handle (bdev)");
		if (resource_by_devno(res, sizeof(res), dev_st.st_rdev, 1) ||
		    stat(res, &st) ||
		    !same_inode(lck_st, st))
			return 1;
	} else
		return 1;

	return 0;
}
