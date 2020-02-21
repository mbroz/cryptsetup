/*
 * devname - search for device name
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
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>     /* for major, minor */
#endif
#include "internal.h"

static char *__lookup_dev(char *path, dev_t dev, int dir_level, const int max_level)
{
	struct dirent *entry;
	struct stat st;
	char *ptr;
	char *result = NULL;
	DIR *dir;
	int space;

	/* Ignore strange nested directories */
	if (dir_level > max_level)
		return NULL;

	path[PATH_MAX - 1] = '\0';
	ptr = path + strlen(path);
	*ptr++ = '/';
	*ptr = '\0';
	space = PATH_MAX - (ptr - path);

	dir = opendir(path);
	if (!dir)
		return NULL;

	while((entry = readdir(dir))) {
		if (entry->d_name[0] == '.' ||
		    !strncmp(entry->d_name, "..", 2))
			continue;

		if (dir_level == 0 &&
		    (!strcmp(entry->d_name, "shm") ||
		     !strcmp(entry->d_name, "fd") ||
		     !strcmp(entry->d_name, "char") ||
		     !strcmp(entry->d_name, "pts")))
			continue;

		strncpy(ptr, entry->d_name, space);
		if (stat(path, &st) < 0)
			continue;

		if (S_ISDIR(st.st_mode)) {
			result = __lookup_dev(path, dev, dir_level + 1, max_level);
			if (result)
				break;
		} else if (S_ISBLK(st.st_mode)) {
			/* workaround: ignore dm-X devices, these are internal kernel names */
			if (dir_level == 0 && dm_is_dm_kernel_name(entry->d_name))
				continue;
			if (st.st_rdev == dev) {
				result = strdup(path);
				break;
			}
		}
	}

	closedir(dir);
	return result;
}

/*
 * Non-udev systemd need to scan for device here.
 */
static char *lookup_dev_old(int major, int minor)
{
	dev_t dev;
	char *result = NULL, buf[PATH_MAX + 1];

	dev = makedev(major, minor);
	strncpy(buf, "/dev", PATH_MAX);
	buf[PATH_MAX] = '\0';

	/* First try low level device */
	if ((result = __lookup_dev(buf, dev, 0, 0)))
		return result;

	/* If it is dm, try DM dir  */
	if (dm_is_dm_device(major)) {
		strncpy(buf, dm_get_dir(), PATH_MAX);
		if ((result = __lookup_dev(buf, dev, 0, 0)))
			return result;
	}

	strncpy(buf, "/dev", PATH_MAX);
	return  __lookup_dev(buf, dev, 0, 4);
}

/*
 * Returns string pointing to device in /dev according to "major:minor" dev_id
 */
char *crypt_lookup_dev(const char *dev_id)
{
	int major, minor;
	char link[PATH_MAX], path[PATH_MAX], *devname, *devpath = NULL;
	struct stat st;
	ssize_t len;

	if (sscanf(dev_id, "%d:%d", &major, &minor) != 2)
		return NULL;

	if (snprintf(path, sizeof(path), "/sys/dev/block/%s", dev_id) < 0)
		return NULL;

	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0) {
		/* Without /sys use old scan */
		if (stat("/sys/dev/block", &st) < 0)
			return lookup_dev_old(major, minor);
		return NULL;
	}

	link[len] = '\0';
	devname = strrchr(link, '/');
	if (!devname)
		return NULL;
	devname++;

	if (dm_is_dm_kernel_name(devname))
		devpath = dm_device_path("/dev/mapper/", major, minor);
	else if (snprintf(path, sizeof(path), "/dev/%s", devname) > 0)
		devpath = strdup(path);

	/*
	 * Check that path is correct.
	 */
	if (devpath && ((stat(devpath, &st) < 0) ||
	    !S_ISBLK(st.st_mode) ||
	    (st.st_rdev != makedev(major, minor)))) {
		free(devpath);
		/* Should never happen unless user mangles with dev nodes. */
		return lookup_dev_old(major, minor);
	}

	return devpath;
}

static int _read_uint64(const char *sysfs_path, uint64_t *value)
{
	char tmp[64] = {0};
	int fd, r;

	if ((fd = open(sysfs_path, O_RDONLY)) < 0)
		return 0;
	r = read(fd, tmp, sizeof(tmp));
	close(fd);

	if (r <= 0)
		return 0;

        if (sscanf(tmp, "%" PRIu64, value) != 1)
		return 0;

	return 1;
}

static int _sysfs_get_uint64(int major, int minor, uint64_t *value, const char *attr)
{
	char path[PATH_MAX];

	if (snprintf(path, sizeof(path), "/sys/dev/block/%d:%d/%s",
		     major, minor, attr) < 0)
		return 0;

	return _read_uint64(path, value);
}

static int _path_get_uint64(const char *sysfs_path, uint64_t *value, const char *attr)
{
	char path[PATH_MAX];

	if (snprintf(path, sizeof(path), "%s/%s",
		     sysfs_path, attr) < 0)
		return 0;

	return _read_uint64(path, value);
}

int crypt_dev_is_rotational(int major, int minor)
{
	uint64_t val;

	if (!_sysfs_get_uint64(major, minor, &val, "queue/rotational"))
		return 1; /* if failed, expect rotational disk */

	return val ? 1 : 0;
}

int crypt_dev_is_partition(const char *dev_path)
{
	uint64_t val;
	struct stat st;

	if (stat(dev_path, &st) < 0)
		return 0;

	if (!S_ISBLK(st.st_mode))
		return 0;

	if (!_sysfs_get_uint64(major(st.st_rdev), minor(st.st_rdev),
			      &val, "partition"))
		return 0;

	return val ? 1 : 0;
}

uint64_t crypt_dev_partition_offset(const char *dev_path)
{
	uint64_t val;
	struct stat st;

	if (!crypt_dev_is_partition(dev_path))
		return 0;

	if (stat(dev_path, &st) < 0)
		return 0;

	if (!_sysfs_get_uint64(major(st.st_rdev), minor(st.st_rdev),
			      &val, "start"))
		return 0;

	return val;
}

/* Try to find partition which match offset and size on top level device */
char *crypt_get_partition_device(const char *dev_path, uint64_t offset, uint64_t size)
{
	char link[PATH_MAX], path[PATH_MAX], part_path[PATH_MAX], *devname;
	char *result = NULL;
	struct stat st;
	size_t devname_len;
	ssize_t len;
	struct dirent *entry;
	DIR *dir;
	uint64_t part_offset, part_size;

	if (stat(dev_path, &st) < 0)
		return NULL;

	if (!S_ISBLK(st.st_mode))
		return NULL;

	if (snprintf(path, sizeof(path), "/sys/dev/block/%d:%d",
		major(st.st_rdev), minor(st.st_rdev)) < 0)
		return NULL;

	dir = opendir(path);
	if (!dir)
		return NULL;

	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0) {
		closedir(dir);
		return NULL;
	}

	/* Get top level disk name for sysfs search */
	link[len] = '\0';
	devname = strrchr(link, '/');
	if (!devname) {
		closedir(dir);
		return NULL;
	}
	devname++;

	/* DM devices do not use kernel partitions. */
	if (dm_is_dm_kernel_name(devname)) {
		closedir(dir);
		return NULL;
	}

	devname_len = strlen(devname);
	while((entry = readdir(dir))) {
		if (strncmp(entry->d_name, devname, devname_len))
			continue;

		if (snprintf(part_path, sizeof(part_path), "%s/%s",
		    path, entry->d_name) < 0)
			continue;

		if (stat(part_path, &st) < 0)
			continue;

		if (S_ISDIR(st.st_mode)) {
			if (!_path_get_uint64(part_path, &part_offset, "start") ||
			    !_path_get_uint64(part_path, &part_size, "size"))
				continue;
			if (part_offset == offset && part_size == size &&
			    snprintf(part_path, sizeof(part_path), "/dev/%s",
				     entry->d_name) > 0) {
				result = strdup(part_path);
				break;
			}
		}
	}
	closedir(dir);

	return result;
}

/* Try to find base device from partition */
char *crypt_get_base_device(const char *dev_path)
{
	char link[PATH_MAX], path[PATH_MAX], part_path[PATH_MAX], *devname;
	struct stat st;
	ssize_t len;

	if (!crypt_dev_is_partition(dev_path))
		return NULL;

	if (stat(dev_path, &st) < 0)
		return NULL;

	if (snprintf(path, sizeof(path), "/sys/dev/block/%d:%d",
		major(st.st_rdev), minor(st.st_rdev)) < 0)
		return NULL;

	len = readlink(path, link, sizeof(link) - 1);
	if (len < 0)
		return NULL;

	/* Get top level disk name for sysfs search */
	link[len] = '\0';
	devname = strrchr(link, '/');
	if (!devname)
		return NULL;
	*devname = '\0';
	devname = strrchr(link, '/');
	if (!devname)
		return NULL;
	devname++;

	if (dm_is_dm_kernel_name(devname))
		return NULL;

	snprintf(part_path, sizeof(part_path), "/dev/%s", devname);
	return strdup(part_path);
}

int lookup_by_disk_id(const char *dm_uuid)
{
	struct dirent *entry;
	struct stat st;
	int r = 0; /* not found */
	DIR *dir = opendir("/dev/disk/by-id");

	if (!dir)
		/* map ENOTDIR to ENOENT we'll handle both errors same */
		return errno == ENOTDIR ? -ENOENT : -errno;

	while ((entry = readdir(dir))) {
		if (entry->d_name[0] == '.' ||
		    !strncmp(entry->d_name, "..", 2))
			continue;

		if (fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
			r = -EINVAL;
			break;
		}

		if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode))
			continue;

		if (!strncmp(entry->d_name, dm_uuid, strlen(dm_uuid))) {
			r = 1;
			break;
		}
	}

	closedir(dir);

	return r;
}

int lookup_by_sysfs_uuid_field(const char *dm_uuid, size_t max_len)
{
	struct dirent *entry;
	char subpath[PATH_MAX], uuid[max_len];
	ssize_t s;
	struct stat st;
	int fd, len, r = 0; /* not found */
	DIR *dir = opendir("/sys/block/");

	if (!dir)
		/* map ENOTDIR to ENOENT we'll handle both errors same */
		return errno == ENOTDIR ? -ENOENT : -errno;

	while (r != 1 && (entry = readdir(dir))) {
		if (entry->d_name[0] == '.' ||
		    !strncmp(entry->d_name, "..", 2))
			continue;

		len = snprintf(subpath, PATH_MAX, "%s/%s", entry->d_name, "dm/uuid");
		if (len < 0 || len >= PATH_MAX) {
			r = -EINVAL;
			break;
		}

		/* looking for dm-X/dm/uuid file, symlinks are fine */
		fd = openat(dirfd(dir), subpath, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;

		if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
			close(fd);
			continue;
		}

		/* reads binary data */
		s = read_buffer(fd, uuid, max_len - 1);
		if (s > 0) {
			uuid[s] = '\0';
			if (!strncmp(uuid, dm_uuid, strlen(dm_uuid)))
				r = 1;
		}

		close(fd);
	}

	closedir(dir);

	return r;
}
