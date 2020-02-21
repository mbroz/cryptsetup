/*
 * Metadata on-disk locking for processes serialization
 *
 * Copyright (C) 2016-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2020 Ondrej Kozina
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
#include <assert.h>

#include "internal.h"
#include "utils_device_locking.h"

#define same_inode(buf1, buf2) \
	((buf1).st_ino == (buf2).st_ino && \
	 (buf1).st_dev == (buf2).st_dev)

enum lock_type {
	DEV_LOCK_READ = 0,
	DEV_LOCK_WRITE
};

enum lock_mode {
	DEV_LOCK_FILE = 0,
	DEV_LOCK_BDEV,
	DEV_LOCK_NAME
};

struct crypt_lock_handle {
	unsigned refcnt;
	int flock_fd;
	enum lock_type type;
	enum lock_mode mode;
	union {
	struct {
		dev_t devno;
	} bdev;
	struct {
		char *name;
	} name;
	} u;
};

static int resource_by_name(char *res, size_t res_size, const char *name, bool fullpath)
{
	int r;

	if (fullpath)
		r = snprintf(res, res_size, "%s/LN_%s", DEFAULT_LUKS2_LOCK_PATH, name);
	else
		r = snprintf(res, res_size, "LN_%s", name);

	return (r < 0 || (size_t)r >= res_size) ? -EINVAL : 0;
}

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
		log_dbg(cd, "Failed to open directory %s: (%d: %s).", dir, errno, strerror(errno));
		if (errno == ENOTDIR || errno == ENOENT)
			log_err(cd, _("Locking aborted. The locking path %s/%s is unusable (not a directory or missing)."), dir, base);
		return -EINVAL;
	}

	lockdfd = openat(dirfd, base, O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
	if (lockdfd < 0) {
		if (errno == ENOENT) {
			log_std(cd, _("WARNING: Locking directory %s/%s is missing!\n"), dir, base);

			/* success or failure w/ errno == EEXIST either way just try to open the 'base' directory again */
			if (mkdirat(dirfd, base, DEFAULT_LUKS2_LOCK_DIR_PERMS) && errno != EEXIST)
				log_dbg(cd, "Failed to create directory %s in %s (%d: %s).", base, dir, errno, strerror(errno));
			else
				lockdfd = openat(dirfd, base, O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC);
		} else {
			log_dbg(cd, "Failed to open directory %s/%s: (%d: %s)", dir, base, errno, strerror(errno));
			if (errno == ENOTDIR || errno == ELOOP)
				log_err(cd, _("Locking aborted. The locking path %s/%s is unusable (%s is not a directory)."), dir, base, base);
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

	log_dbg(cd, "Opening lock resource file %s/%s", DEFAULT_LUKS2_LOCK_PATH, res);
	r = openat(lockdir_fd, res, O_CREAT | O_NOFOLLOW | O_RDWR | O_CLOEXEC, 0777);
	err = errno;

	close(lockdir_fd);

	return r < 0 ? -err : r;
}

static int acquire_lock_handle(struct crypt_device *cd, struct device *device, struct crypt_lock_handle *h)
{
	char res[PATH_MAX];
	int dev_fd, fd;
	struct stat st;

	dev_fd = open(device_path(device), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
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
		h->u.bdev.devno = st.st_rdev;
		h->mode = DEV_LOCK_BDEV;
	} else if (S_ISREG(st.st_mode)) {
		// FIXME: workaround for nfsv4
		fd = open(device_path(device), O_RDWR | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0)
			h->flock_fd = dev_fd;
		else {
			h->flock_fd = fd;
			close(dev_fd);
		}
		h->mode = DEV_LOCK_FILE;
	} else {
		/* Wrong device type */
		close(dev_fd);
		return -EINVAL;
	}

	return 0;
}

static int acquire_lock_handle_by_name(struct crypt_device *cd, const char *name, struct crypt_lock_handle *h)
{
	char res[PATH_MAX];
	int fd;

	h->u.name.name = strdup(name);
	if (!h->u.name.name)
		return -ENOMEM;

	if (resource_by_name(res, sizeof(res), name, false)) {
		free(h->u.name.name);
		return -EINVAL;
	}

	fd = open_resource(cd, res);
	if (fd < 0) {
		free(h->u.name.name);
		return fd;
	}

	h->flock_fd = fd;
	h->mode = DEV_LOCK_NAME;

	return 0;
}

static void release_lock_handle(struct crypt_device *cd, struct crypt_lock_handle *h)
{
	char res[PATH_MAX];
	struct stat buf_a, buf_b;

	if ((h->mode == DEV_LOCK_NAME) && /* was it name lock */
	    !flock(h->flock_fd, LOCK_EX | LOCK_NB) && /* lock to drop the file */
	    !resource_by_name(res, sizeof(res), h->u.name.name, true) && /* acquire lock resource name */
	    !fstat(h->flock_fd, &buf_a) && /* read inode id referred by fd */
	    !stat(res, &buf_b) && /* does path file still exist? */
	    same_inode(buf_a, buf_b)) { /* is it same id as the one referenced by fd? */
		/* coverity[toctou] */
		if (unlink(res)) /* yes? unlink the file */
			log_dbg(cd, "Failed to unlink resource file: %s", res);
	}

	if ((h->mode == DEV_LOCK_BDEV) && /* was it block device */
	    !flock(h->flock_fd, LOCK_EX | LOCK_NB) && /* lock to drop the file */
	    !resource_by_devno(res, sizeof(res), h->u.bdev.devno, 1) && /* acquire lock resource name */
	    !fstat(h->flock_fd, &buf_a) && /* read inode id referred by fd */
	    !stat(res, &buf_b) && /* does path file still exist? */
	    same_inode(buf_a, buf_b)) { /* is it same id as the one referenced by fd? */
		/* coverity[toctou] */
		if (unlink(res)) /* yes? unlink the file */
			log_dbg(cd, "Failed to unlink resource file: %s", res);
	}

	if (h->mode == DEV_LOCK_NAME)
		free(h->u.name.name);

	if (close(h->flock_fd))
		log_dbg(cd, "Failed to close lock resource fd (%d).", h->flock_fd);
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
	if (h->mode == DEV_LOCK_FILE)
		return 0;

	if (h->mode == DEV_LOCK_NAME) {
		if (resource_by_name(res, sizeof(res), h->u.name.name, true))
			return -EINVAL;
	} else if (h->mode == DEV_LOCK_BDEV) {
		if (resource_by_devno(res, sizeof(res), h->u.bdev.devno, true))
			return -EINVAL;
	} else
		return -EINVAL;

	if (fstat(h->flock_fd, &lck_st))
		return -EINVAL;

	return (stat(res, &res_st) || !same_inode(lck_st, res_st)) ? -EAGAIN : 0;
}

static unsigned device_lock_inc(struct crypt_lock_handle *h)
{
	return ++h->refcnt;
}

static unsigned device_lock_dec(struct crypt_lock_handle *h)
{
	assert(h->refcnt);

	return --h->refcnt;
}

static int acquire_and_verify(struct crypt_device *cd, struct device *device, const char *resource, int flock_op, struct crypt_lock_handle **lock)
{
	int r;
	struct crypt_lock_handle *h;

	if (device && resource)
		return -EINVAL;

	if (!(h = malloc(sizeof(*h))))
		return -ENOMEM;

	do {
		r = device ? acquire_lock_handle(cd, device, h) : acquire_lock_handle_by_name(cd, resource, h);
		if (r < 0)
			break;

		if (flock(h->flock_fd, flock_op)) {
			log_dbg(cd, "Flock on fd %d failed with errno %d.", h->flock_fd, errno);
			r = (errno == EWOULDBLOCK) ? -EBUSY : -EINVAL;
			release_lock_handle(cd, h);
			break;
		}

		log_dbg(cd, "Verifying lock handle for %s.", device ? device_path(device) : resource);

		/*
		 * check whether another libcryptsetup process removed resource file before this
		 * one managed to flock() it. See release_lock_handle() for details
		 */
		r = verify_lock_handle(device_path(device), h);
		if (r < 0) {
			if (flock(h->flock_fd, LOCK_UN))
				log_dbg(cd, "flock on fd %d failed.", h->flock_fd);
			release_lock_handle(cd, h);
			log_dbg(cd, "Lock handle verification failed.");
		}
	} while (r == -EAGAIN);

	if (r < 0) {
		free(h);
		return r;
	}

	*lock = h;

	return 0;
}

int device_read_lock_internal(struct crypt_device *cd, struct device *device)
{
	int r;
	struct crypt_lock_handle *h;

	if (!device)
		return -EINVAL;

	h = device_get_lock_handle(device);

	if (device_locked(h)) {
		device_lock_inc(h);
		log_dbg(cd, "Device %s READ lock (or higher) already held.", device_path(device));
		return 0;
	}

	log_dbg(cd, "Acquiring read lock for device %s.", device_path(device));

	r = acquire_and_verify(cd, device, NULL, LOCK_SH, &h);
	if (r < 0)
		return r;

	h->type = DEV_LOCK_READ;
	h->refcnt = 1;
	device_set_lock_handle(device, h);

	log_dbg(cd, "Device %s READ lock taken.", device_path(device));

	return 0;
}

int device_write_lock_internal(struct crypt_device *cd, struct device *device)
{
	int r;
	struct crypt_lock_handle *h;

	if (!device)
		return -EINVAL;

	h = device_get_lock_handle(device);

	if (device_locked(h)) {
		log_dbg(cd, "Device %s WRITE lock already held.", device_path(device));
		return device_lock_inc(h);
	}

	log_dbg(cd, "Acquiring write lock for device %s.", device_path(device));

	r = acquire_and_verify(cd, device, NULL, LOCK_EX, &h);
	if (r < 0)
		return r;

	h->type = DEV_LOCK_WRITE;
	h->refcnt = 1;
	device_set_lock_handle(device, h);

	log_dbg(cd, "Device %s WRITE lock taken.", device_path(device));

	return 1;
}

int crypt_read_lock(struct crypt_device *cd, const char *resource, bool blocking, struct crypt_lock_handle **lock)
{
	int r;
	struct crypt_lock_handle *h;

	if (!resource)
		return -EINVAL;

	log_dbg(cd, "Acquiring %sblocking read lock for resource %s.", blocking ? "" : "non", resource);

	r = acquire_and_verify(cd, NULL, resource, LOCK_SH | (blocking ? 0 : LOCK_NB), &h);
	if (r < 0)
		return r;

	h->type = DEV_LOCK_READ;
	h->refcnt = 1;

	log_dbg(cd, "READ lock for resource %s taken.", resource);

	*lock = h;

	return 0;
}

int crypt_write_lock(struct crypt_device *cd, const char *resource, bool blocking, struct crypt_lock_handle **lock)
{
	int r;
	struct crypt_lock_handle *h;

	if (!resource)
		return -EINVAL;

	log_dbg(cd, "Acquiring %sblocking write lock for resource %s.", blocking ? "" : "non", resource);

	r = acquire_and_verify(cd, NULL, resource, LOCK_EX | (blocking ? 0 : LOCK_NB), &h);
	if (r < 0)
		return r;

	h->type = DEV_LOCK_WRITE;
	h->refcnt = 1;

	log_dbg(cd, "WRITE lock for resource %s taken.", resource);

	*lock = h;

	return 0;
}

static void unlock_internal(struct crypt_device *cd, struct crypt_lock_handle *h)
{
	if (flock(h->flock_fd, LOCK_UN))
		log_dbg(cd, "flock on fd %d failed.", h->flock_fd);
	release_lock_handle(cd, h);
	free(h);
}

void crypt_unlock_internal(struct crypt_device *cd, struct crypt_lock_handle *h)
{
	if (!h)
		return;

	/* nested locks are illegal */
	assert(!device_lock_dec(h));

	log_dbg(cd, "Unlocking %s lock for resource %s.",
		device_locked_readonly(h) ? "READ" : "WRITE", h->u.name.name);

	unlock_internal(cd, h);
}

void device_unlock_internal(struct crypt_device *cd, struct device *device)
{
	bool readonly;
	struct crypt_lock_handle *h = device_get_lock_handle(device);
	unsigned u = device_lock_dec(h);

	if (u)
		return;

	readonly = device_locked_readonly(h);

	unlock_internal(cd, h);

	log_dbg(cd, "Device %s %s lock released.", device_path(device),
		readonly ? "READ" : "WRITE");

	device_set_lock_handle(device, NULL);
}

int device_locked_verify(struct crypt_device *cd, int dev_fd, struct crypt_lock_handle *h)
{
	char res[PATH_MAX];
	struct stat dev_st, lck_st, st;

	if (fstat(dev_fd, &dev_st) || fstat(h->flock_fd, &lck_st))
		return 1;

	/* if device handle is regular file the handle must match the lock handle */
	if (S_ISREG(dev_st.st_mode)) {
		log_dbg(cd, "Veryfing locked device handle (regular file)");
		if (!same_inode(dev_st, lck_st))
			return 1;
	} else if (S_ISBLK(dev_st.st_mode)) {
		log_dbg(cd, "Veryfing locked device handle (bdev)");
		if (resource_by_devno(res, sizeof(res), dev_st.st_rdev, 1) ||
		    stat(res, &st) ||
		    !same_inode(lck_st, st))
			return 1;
	} else
		return 1;

	return 0;
}
