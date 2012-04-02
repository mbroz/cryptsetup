/*
 * devname - search for device name
 *
 * Copyright (C) 2004, Christophe Saout <christophe@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "utils_dm.h"

char *crypt_lookup_dev(const char *dev_id);
int crypt_sysfs_check_crypt_segment(const char *device, uint64_t offset, uint64_t size);
int crypt_sysfs_get_rotational(int major, int minor, int *rotational);

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
	if (dm_is_dm_device(major, minor)) {
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

	len = readlink(path, link, sizeof(link));
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

static int crypt_sysfs_get_major_minor(const char *kname, int *major, int *minor)
{
	char path[PATH_MAX], tmp[64] = {0};
	int fd, r = 0;

	if (snprintf(path, sizeof(path), "/sys/block/%s/dev", kname) < 0)
		return 0;

	if ((fd = open(path, O_RDONLY)) < 0)
		return 0;
	r = read(fd, tmp, sizeof(tmp));
	close(fd);

	if (r <= 0)
		return 0;

	tmp[63] = '\0';
	if (sscanf(tmp, "%d:%d", major, minor) != 2)
		return 0;

	return 1;
}

static int crypt_sysfs_get_holders_dir(const char *device, char *path, int size)
{
	struct stat st;

	if (stat(device, &st) < 0 || !S_ISBLK(st.st_mode))
		return 0;

	if (snprintf(path, size, "/sys/dev/block/%d:%d/holders",
		     major(st.st_rdev), minor(st.st_rdev)) < 0)
		return 0;

	return 1;
}

int crypt_sysfs_check_crypt_segment(const char *device, uint64_t offset, uint64_t size)
{
	DIR *dir;
	struct dirent *d;
	char path[PATH_MAX], *dmname;
	int major, minor, r = 0;

	if (!crypt_sysfs_get_holders_dir(device, path, sizeof(path)))
		return -EINVAL;

	if (!(dir = opendir(path)))
		return -EINVAL;

	while (!r && (d = readdir(dir))) {
		if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
			continue;

		if (!dm_is_dm_kernel_name(d->d_name)) {
			r = -EBUSY;
			break;
		}

		if (!crypt_sysfs_get_major_minor(d->d_name, &major, &minor)) {
			r = -EINVAL;
			break;
		}

		if (!(dmname = dm_device_path(NULL, major, minor))) {
			r = -EINVAL;
			break;
		}
		r = dm_check_segment(dmname, offset, size);
		free(dmname);
	}
	closedir(dir);

	return r;
}

int crypt_sysfs_get_rotational(int major, int minor, int *rotational)
{
	char path[PATH_MAX], tmp[64] = {0};
	int fd, r;

	if (snprintf(path, sizeof(path), "/sys/dev/block/%d:%d/queue/rotational",
		     major, minor) < 0)
		return 0;

	if ((fd = open(path, O_RDONLY)) < 0)
		return 0;
	r = read(fd, tmp, sizeof(tmp));
	close(fd);

	if (r <= 0)
		return 0;

        if (sscanf(tmp, "%d", rotational) != 1)
		return 0;

	return 1;
}
