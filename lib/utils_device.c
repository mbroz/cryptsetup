/*
 * device backend utilities
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2019 Milan Broz
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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <unistd.h>
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>     /* for major, minor */
#endif
#ifdef HAVE_SYS_STATVFS_H
# include <sys/statvfs.h>
#endif
#include "internal.h"
#include "utils_device_locking.h"

struct device {
	char *path;

	char *file_path;
	int loop_fd;

	struct crypt_lock_handle *lh;

	unsigned int o_direct:1;
	unsigned int init_done:1; /* path is bdev or loop already initialized */

	/* cached values */
	size_t alignment;
	size_t block_size;
};

static size_t device_fs_block_size_fd(int fd)
{
	size_t page_size = crypt_getpagesize();

#ifdef HAVE_SYS_STATVFS_H
	struct statvfs buf;

	/*
	 * NOTE: some filesystems (NFS) returns bogus blocksize (1MB).
	 * Page-size io should always work and avoids increasing IO beyond aligned LUKS header.
	 */
	if (!fstatvfs(fd, &buf) && buf.f_bsize && buf.f_bsize <= page_size)
		return (size_t)buf.f_bsize;
#endif
	return page_size;
}

static size_t device_block_size_fd(int fd, size_t *min_size)
{
	struct stat st;
	size_t bsize;
	int arg;

	if (fstat(fd, &st) < 0)
		return 0;

	if (S_ISREG(st.st_mode))
		bsize = device_fs_block_size_fd(fd);
	else {
		if (ioctl(fd, BLKSSZGET, &arg) < 0)
			bsize = crypt_getpagesize();
		else
			bsize = (size_t)arg;
	}

	if (!min_size)
		return bsize;

	if (S_ISREG(st.st_mode)) {
		/* file can be empty as well */
		if (st.st_size > (ssize_t)bsize)
			*min_size = bsize;
		else
			*min_size = st.st_size;
	} else {
		/* block device must have at least one block */
		*min_size = bsize;
	}

	return bsize;
}

static size_t device_alignment_fd(int devfd)
{
	long alignment = DEFAULT_MEM_ALIGNMENT;

#ifdef _PC_REC_XFER_ALIGN
	alignment = fpathconf(devfd, _PC_REC_XFER_ALIGN);
	if (alignment < 0)
		alignment = DEFAULT_MEM_ALIGNMENT;
#endif
	return (size_t)alignment;
}

static int device_read_test(int devfd)
{
	char buffer[512];
	int r = -EIO;
	size_t minsize = 0, blocksize, alignment;

	blocksize = device_block_size_fd(devfd, &minsize);
	alignment = device_alignment_fd(devfd);

	if (!blocksize || !alignment)
		return -EINVAL;

	if (minsize == 0)
		return 0;

	if (minsize > sizeof(buffer))
		minsize = sizeof(buffer);

	if (read_blockwise(devfd, blocksize, alignment, buffer, minsize) == (ssize_t)minsize)
		r = 0;

	crypt_memzero(buffer, sizeof(buffer));
	return r;
}

/*
 * The direct-io is always preferred. The header is usually mapped to the same
 * device and can be accessed when the rest of device is mapped to data device.
 * Using dirct-io encsures that we do not mess with data in cache.
 * (But proper alignment should prevent this in the first place.)
 * The read test is needed to detect broken configurations (seen with remote
 * block devices) that allow open with direct-io but then fails on read.
 */
static int device_ready(struct crypt_device *cd, struct device *device)
{
	int devfd = -1, r = 0;
	struct stat st;
	size_t tmp_size;

	if (device->o_direct) {
		log_dbg(cd, "Trying to open and read device %s with direct-io.",
			device_path(device));
		device->o_direct = 0;
		devfd = open(device_path(device), O_RDONLY | O_DIRECT);
		if (devfd >= 0) {
			if (device_read_test(devfd) == 0) {
				device->o_direct = 1;
			} else {
				close(devfd);
				devfd = -1;
			}
		}
	}

	if (devfd < 0) {
		log_dbg(cd, "Trying to open device %s without direct-io.",
			device_path(device));
		devfd = open(device_path(device), O_RDONLY);
	}

	if (devfd < 0) {
		log_err(cd, _("Device %s doesn't exist or access denied."),
			device_path(device));
		return -EINVAL;
	}

	if (fstat(devfd, &st) < 0)
		r = -EINVAL;
	else if (!S_ISBLK(st.st_mode))
		r = S_ISREG(st.st_mode) ? -ENOTBLK : -EINVAL;
	if (r == -EINVAL) {
		log_err(cd, _("Device %s is not compatible."),
			device_path(device));
		close(devfd);
		return r;
	}

	/* Allow only increase (loop device) */
	tmp_size = device_alignment_fd(devfd);
	if (tmp_size > device->alignment)
		device->alignment = tmp_size;

	tmp_size = device_block_size_fd(devfd, NULL);
	if (tmp_size > device->block_size)
		device->block_size = tmp_size;

	close(devfd);
	return r;
}

static int _open_locked(struct crypt_device *cd, struct device *device, int flags)
{
	int fd;

	log_dbg(cd, "Opening locked device %s", device_path(device));

	if ((flags & O_ACCMODE) != O_RDONLY && device_locked_readonly(device->lh)) {
		log_dbg(cd, "Can not open locked device %s in write mode. Read lock held.", device_path(device));
		return -EAGAIN;
	}

	fd = open(device_path(device), flags);
	if (fd < 0)
		return -errno;

	if (device_locked_verify(cd, fd, device->lh)) {
		/* fd doesn't correspond to a locked resource */
		close(fd);
		log_dbg(cd, "Failed to verify lock resource for device %s.", device_path(device));
		return -EINVAL;
	}

	return fd;
}

/*
 * Common wrapper for device sync.
 * FIXME: file descriptor will be in struct later.
 */
void device_sync(struct crypt_device *cd, struct device *device, int devfd)
{
	if (fsync(devfd) == -1)
		log_dbg(cd, "Cannot sync device %s.", device_path(device));
}

/*
 * in non-locked mode returns always fd or -1
 *
 * in locked mode:
 * 	opened fd or one of:
 * 	-EAGAIN : requested write mode while device being locked in via shared lock
 * 	-EINVAL : invalid lock fd state
 * 	-1	: all other errors
 */
static int device_open_internal(struct crypt_device *cd, struct device *device, int flags)
{
	int devfd;

	if (device->o_direct)
		flags |= O_DIRECT;

	if (device_locked(device->lh))
		devfd = _open_locked(cd, device, flags);
	else
		devfd = open(device_path(device), flags);

	if (devfd < 0)
		log_dbg(cd, "Cannot open device %s%s.",
			device_path(device),
			(flags & O_ACCMODE) != O_RDONLY ? " for write" : "");

	return devfd;
}

int device_open(struct crypt_device *cd, struct device *device, int flags)
{
	assert(!device_locked(device->lh));
	return device_open_internal(cd, device, flags);
}

int device_open_excl(struct crypt_device *cd, struct device *device, int flags)
{
	struct stat st;

	if (stat(device_path(device), &st))
		return -EINVAL;
	if (S_ISBLK(st.st_mode))
		flags |= O_EXCL;

	assert(!device_locked(device->lh));
	return device_open_internal(cd, device, flags);
}

int device_open_locked(struct crypt_device *cd, struct device *device, int flags)
{
	assert(!crypt_metadata_locking_enabled() || device_locked(device->lh));
	return device_open_internal(cd, device, flags);
}

/* Avoid any read from device, expects direct-io to work. */
int device_alloc_no_check(struct device **device, const char *path)
{
	struct device *dev;

	if (!path) {
		*device = NULL;
		return 0;
	}

	dev = malloc(sizeof(struct device));
	if (!dev)
		return -ENOMEM;

	memset(dev, 0, sizeof(struct device));
	dev->path = strdup(path);
	if (!dev->path) {
		free(dev);
		return -ENOMEM;
	}
	dev->loop_fd = -1;
	dev->o_direct = 1;

	*device = dev;
	return 0;
}

int device_alloc(struct crypt_device *cd, struct device **device, const char *path)
{
	struct device *dev;
	int r;

	r = device_alloc_no_check(&dev, path);
	if (r < 0)
		return r;

	if (dev) {
		r = device_ready(cd, dev);
		if (!r) {
			dev->init_done = 1;
		} else if (r == -ENOTBLK) {
			/* alloc loop later */
		} else if (r < 0) {
			free(dev->path);
			free(dev);
			return -ENOTBLK;
		}
	}

	*device = dev;
	return 0;
}

void device_free(struct crypt_device *cd, struct device *device)
{
	if (!device)
		return;

	if (device->loop_fd != -1) {
		log_dbg(cd, "Closed loop %s (%s).", device->path, device->file_path);
		close(device->loop_fd);
	}

	assert(!device_locked(device->lh));

	free(device->file_path);
	free(device->path);
	free(device);
}

/* Get block device path */
const char *device_block_path(const struct device *device)
{
	if (!device || !device->init_done)
		return NULL;

	return device->path;
}

/* Get device-mapper name of device (if possible) */
const char *device_dm_name(const struct device *device)
{
	const char *dmdir = dm_get_dir();
	size_t dmdir_len = strlen(dmdir);

	if (!device || !device->init_done)
		return NULL;

	if (strncmp(device->path, dmdir, dmdir_len))
		return NULL;

	return &device->path[dmdir_len+1];
}

/* Get path to device / file */
const char *device_path(const struct device *device)
{
	if (!device)
		return NULL;

	if (device->file_path)
		return device->file_path;

	return device->path;
}

/* block device topology ioctls, introduced in 2.6.32 */
#ifndef BLKIOMIN
#define BLKIOMIN    _IO(0x12,120)
#define BLKIOOPT    _IO(0x12,121)
#define BLKALIGNOFF _IO(0x12,122)
#endif

void device_topology_alignment(struct crypt_device *cd,
			       struct device *device,
			       unsigned long *required_alignment, /* bytes */
			       unsigned long *alignment_offset,   /* bytes */
			       unsigned long default_alignment)
{
	int dev_alignment_offset = 0;
	unsigned int min_io_size = 0, opt_io_size = 0;
	unsigned long temp_alignment = 0;
	int fd;

	*required_alignment = default_alignment;
	*alignment_offset = 0;

	if (!device || !device->path) //FIXME
		return;

	fd = open(device->path, O_RDONLY);
	if (fd == -1)
		return;

	/* minimum io size */
	if (ioctl(fd, BLKIOMIN, &min_io_size) == -1) {
		log_dbg(cd, "Topology info for %s not supported, using default offset %lu bytes.",
			device->path, default_alignment);
		goto out;
	}

	/* optimal io size */
	if (ioctl(fd, BLKIOOPT, &opt_io_size) == -1)
		opt_io_size = min_io_size;

	/* alignment offset, bogus -1 means misaligned/unknown */
	if (ioctl(fd, BLKALIGNOFF, &dev_alignment_offset) == -1 || dev_alignment_offset < 0)
		dev_alignment_offset = 0;
	*alignment_offset = (unsigned long)dev_alignment_offset;

	temp_alignment = (unsigned long)min_io_size;

	/* Ignore bogus opt-io that could break alignment */
	if ((temp_alignment < (unsigned long)opt_io_size) &&
	    !((unsigned long)opt_io_size % temp_alignment))
		temp_alignment = (unsigned long)opt_io_size;

	/* If calculated alignment is multiple of default, keep default */
	if (temp_alignment && (default_alignment % temp_alignment))
		*required_alignment = temp_alignment;

	log_dbg(cd, "Topology: IO (%u/%u), offset = %lu; Required alignment is %lu bytes.",
		min_io_size, opt_io_size, *alignment_offset, *required_alignment);
out:
	(void)close(fd);
}

size_t device_block_size(struct crypt_device *cd, struct device *device)
{
	int fd;

	if (!device)
		return 0;

	if (device->block_size)
		return device->block_size;

	fd = open(device->file_path ?: device->path, O_RDONLY);
	if (fd >= 0) {
		device->block_size = device_block_size_fd(fd, NULL);
		close(fd);
	}

	if (!device->block_size)
		log_dbg(cd, "Cannot get block size for device %s.", device_path(device));

	return device->block_size;
}

int device_read_ahead(struct device *device, uint32_t *read_ahead)
{
	int fd, r = 0;
	long read_ahead_long;

	if (!device)
		return 0;

	if ((fd = open(device->path, O_RDONLY)) < 0)
		return 0;

	r = ioctl(fd, BLKRAGET, &read_ahead_long) ? 0 : 1;
	close(fd);

	if (r)
		*read_ahead = (uint32_t) read_ahead_long;

	return r;
}

/* Get data size in bytes */
int device_size(struct device *device, uint64_t *size)
{
	struct stat st;
	int devfd, r = -EINVAL;

	devfd = open(device->path, O_RDONLY);
	if(devfd == -1)
		return -EINVAL;

	if (fstat(devfd, &st) < 0)
		goto out;

	if (S_ISREG(st.st_mode)) {
		*size = (uint64_t)st.st_size;
		r = 0;
	} else if (ioctl(devfd, BLKGETSIZE64, size) >= 0)
		r = 0;
out:
	close(devfd);
	return r;
}

/* For a file, allocate the required space */
int device_fallocate(struct device *device, uint64_t size)
{
	struct stat st;
	int devfd, r = -EINVAL;

	devfd = open(device_path(device), O_RDWR);
	if (devfd == -1)
		return -EINVAL;

	if (!fstat(devfd, &st) && S_ISREG(st.st_mode) &&
	    ((uint64_t)st.st_size >= size || !posix_fallocate(devfd, 0, size))) {
		r = 0;
		if (device->file_path && crypt_loop_resize(device->path))
			r = -EINVAL;
	}

	close(devfd);
	return r;
}

int device_check_size(struct crypt_device *cd,
		      struct device *device,
		      uint64_t req_offset, int falloc)
{
	uint64_t dev_size;

	if (device_size(device, &dev_size)) {
		log_dbg(cd, "Cannot get device size for device %s.", device_path(device));
		return -EIO;
	}

	log_dbg(cd, "Device size %" PRIu64 ", offset %" PRIu64 ".", dev_size, req_offset);

	if (req_offset > dev_size) {
		/* If it is header file, increase its size */
		if (falloc && !device_fallocate(device, req_offset))
			return 0;

		log_err(cd, _("Device %s is too small. Need at least %" PRIu64 " bytes."),
			device_path(device), req_offset);
		return -EINVAL;
	}

	return 0;
}

static int device_info(struct crypt_device *cd,
		       struct device *device,
		       enum devcheck device_check,
		       int *readonly, uint64_t *size)
{
	struct stat st;
	int fd = -1, r, flags = 0, real_readonly;
	uint64_t real_size;

	if (!device)
		return -ENOTBLK;

	real_readonly = 0;
	real_size = 0;

	if (stat(device->path, &st) < 0) {
		r = -EINVAL;
		goto out;
	}

	/* never wipe header on mounted device */
	if (device_check == DEV_EXCL && S_ISBLK(st.st_mode))
		flags |= O_EXCL;

	/* Try to open read-write to check whether it is a read-only device */
	/* coverity[toctou] */
	fd = open(device->path, O_RDWR | flags);
	if (fd == -1 && errno == EROFS) {
		real_readonly = 1;
		fd = open(device->path, O_RDONLY | flags);
	}

	if (fd == -1 && device_check == DEV_EXCL && errno == EBUSY) {
		r = -EBUSY;
		goto out;
	}

	if (fd == -1) {
		r = errno ? -errno : -EINVAL;
		goto out;
	}

	r = 0;
	if (S_ISREG(st.st_mode)) {
		//FIXME: add readonly check
		real_size = (uint64_t)st.st_size;
		real_size >>= SECTOR_SHIFT;
	} else {
		/* If the device can be opened read-write, i.e. readonly is still 0, then
		 * check whether BKROGET says that it is read-only. E.g. read-only loop
		 * devices may be opened read-write but are read-only according to BLKROGET
		 */
		if (real_readonly == 0 && (r = ioctl(fd, BLKROGET, &real_readonly)) < 0)
			goto out;

		r = ioctl(fd, BLKGETSIZE64, &real_size);
		if (r >= 0) {
			real_size >>= SECTOR_SHIFT;
			goto out;
		}
	}
out:
	if (fd != -1)
		close(fd);

	switch (r) {
	case 0:
		if (readonly)
			*readonly = real_readonly;
		if (size)
			*size = real_size;
		break;
	case -EBUSY:
		log_err(cd, _("Cannot use device %s which is in use "
			      "(already mapped or mounted)."), device_path(device));
		break;
	case -EACCES:
		log_err(cd, _("Cannot use device %s, permission denied."), device_path(device));
		break;
	default:
		log_err(cd, _("Cannot get info about device %s."), device_path(device));
		r = -EINVAL;
	}

	return r;
}

int device_check_access(struct crypt_device *cd,
			struct device *device,
			enum devcheck device_check)
{
	return device_info(cd, device, device_check, NULL, NULL);
}

static int device_internal_prepare(struct crypt_device *cd, struct device *device)
{
	char *loop_device = NULL, *file_path = NULL;
	int r, loop_fd, readonly = 0;

	if (device->init_done)
		return 0;

	if (getuid() || geteuid()) {
		log_err(cd, _("Cannot use a loopback device, "
			      "running as non-root user."));
		return -ENOTSUP;
	}

	log_dbg(cd, "Allocating a free loop device.");

	/* Keep the loop open, dettached on last close. */
	loop_fd = crypt_loop_attach(&loop_device, device->path, 0, 1, &readonly);
	if (loop_fd == -1) {
		log_err(cd, _("Attaching loopback device failed "
			"(loop device with autoclear flag is required)."));
		free(loop_device);
		return -EINVAL;
	}

	file_path = device->path;
	device->path = loop_device;

	r = device_ready(cd, device);
	if (r < 0) {
		device->path = file_path;
		crypt_loop_detach(loop_device);
		free(loop_device);
		return r;
	}

	device->loop_fd = loop_fd;
	device->file_path = file_path;
	device->init_done = 1;

	return 0;
}

int device_block_adjust(struct crypt_device *cd,
			struct device *device,
			enum devcheck device_check,
			uint64_t device_offset,
			uint64_t *size,
			uint32_t *flags)
{
	int r, real_readonly;
	uint64_t real_size;

	if (!device)
		return -ENOTBLK;

	r = device_internal_prepare(cd, device);
	if (r)
		return r;

	r = device_info(cd, device, device_check, &real_readonly, &real_size);
	if (r)
		return r;

	if (device_offset >= real_size) {
		log_err(cd, _("Requested offset is beyond real size of device %s."),
			device_path(device));
		return -EINVAL;
	}

	if (size && !*size) {
		*size = real_size;
		if (!*size) {
			log_err(cd, _("Device %s has zero size."), device_path(device));
			return -ENOTBLK;
		}
		*size -= device_offset;
	}

	/* in case of size is set by parameter */
	if (size && ((real_size - device_offset) < *size)) {
		log_dbg(cd, "Device %s: offset = %" PRIu64 " requested size = %" PRIu64
			", backing device size = %" PRIu64,
			device->path, device_offset, *size, real_size);
		log_err(cd, _("Device %s is too small."), device_path(device));
		return -EINVAL;
	}

	if (flags && real_readonly)
		*flags |= CRYPT_ACTIVATE_READONLY;

	if (size)
		log_dbg(cd, "Calculated device size is %" PRIu64" sectors (%s), offset %" PRIu64 ".",
		*size, real_readonly ? "RO" : "RW", device_offset);
	return 0;
}

size_t size_round_up(size_t size, size_t block)
{
	size_t s = (size + (block - 1)) / block;
	return s * block;
}

void device_disable_direct_io(struct device *device)
{
	device->o_direct = 0;
}

int device_direct_io(const struct device *device)
{
	return device->o_direct;
}

static dev_t device_devno(const struct device *device)
{
	struct stat st;

	if (stat(device->path, &st) || !S_ISBLK(st.st_mode))
		return 0;

	return st.st_rdev;
}

int device_is_identical(struct device *device1, struct device *device2)
{
	if (!device1 || !device2)
		return 0;

	if (device1 == device2)
		return 1;

	if (device1->init_done && device2->init_done)
		return (device_devno(device1) == device_devno(device2));
	else if (device1->init_done || device2->init_done)
		return 0;

	if (!strcmp(device_path(device1), device_path(device2)))
		return 1;

	return 0;
}

int device_is_rotational(struct device *device)
{
	struct stat st;

	if (stat(device_path(device), &st) < 0)
		return -EINVAL;

	if (!S_ISBLK(st.st_mode))
		return 0;

	return crypt_dev_is_rotational(major(st.st_rdev), minor(st.st_rdev));
}

size_t device_alignment(struct device *device)
{
	int devfd;

	if (!device->alignment) {
		devfd = open(device_path(device), O_RDONLY);
		if (devfd != -1) {
			device->alignment = device_alignment_fd(devfd);
			close(devfd);
		}
	}

	return device->alignment;
}

void device_set_lock_handle(struct device *device, struct crypt_lock_handle *h)
{
	device->lh = h;
}

struct crypt_lock_handle *device_get_lock_handle(struct device *device)
{
	return device->lh;
}

int device_read_lock(struct crypt_device *cd, struct device *device)
{
	if (!crypt_metadata_locking_enabled())
		return 0;

	if (device_read_lock_internal(cd, device))
		return -EBUSY;

	return 0;
}

int device_write_lock(struct crypt_device *cd, struct device *device)
{
	if (!crypt_metadata_locking_enabled())
		return 0;

	assert(!device_locked(device->lh) || !device_locked_readonly(device->lh));

	if (device_write_lock_internal(cd, device))
		return -EBUSY;

	return 0;
}

void device_read_unlock(struct crypt_device *cd, struct device *device)
{
	if (!crypt_metadata_locking_enabled())
		return;

	assert(device_locked(device->lh));

	device_unlock_internal(cd, device);
}

void device_write_unlock(struct crypt_device *cd, struct device *device)
{
	if (!crypt_metadata_locking_enabled())
		return;

	assert(device_locked(device->lh) && !device_locked_readonly(device->lh));

	device_unlock_internal(cd, device);
}

bool device_is_locked(struct device *device)
{
	return device ? device_locked(device->lh) : 0;
}
