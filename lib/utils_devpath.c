/*
 * devname - search for device name
 *
 * Copyright (C) 2004, Christophe Saout <christophe@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2011, Red Hat, Inc. All rights reserved.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "internal.h"

#define DEVICE_DIR	"/dev"

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

		strncpy(ptr, entry->d_name, space);
		if (stat(path, &st) < 0)
			continue;

		if (S_ISDIR(st.st_mode)) {
			result = __lookup_dev(path, dev, dir_level + 1, max_level);
			if (result)
				break;
		} else if (S_ISBLK(st.st_mode)) {
			/* workaround: ignore dm-X devices, these are internal kernel names */
			if (dir_level == 0 && !strncmp(entry->d_name, "dm-", 3))
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

static char *lookup_dev_old(const char *dev_id)
{
	int major, minor;
	dev_t dev;
	char *result = NULL, buf[PATH_MAX + 1];

	if (sscanf(dev_id, "%d:%d", &major, &minor) != 2)
		return NULL;

	dev = makedev(major, minor);
	strncpy(buf, DEVICE_DIR, PATH_MAX);
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

	strncpy(buf, DEVICE_DIR, PATH_MAX);
	result = __lookup_dev(buf, dev, 0, 4);

	/* If not found, return NULL */
	return result;
}

char *crypt_lookup_dev(const char *dev_id)
{
	char link[PATH_MAX], path[PATH_MAX], *devname;
	struct stat st;
	ssize_t len;

	if (snprintf(path, sizeof(path), "/sys/dev/block/%s", dev_id) < 0)
		return NULL;

	len = readlink(path, link, sizeof(link));
	if (len < 0) {
		if (stat("/sys/dev/block", &st) < 0)
			return lookup_dev_old(dev_id);
		return NULL;
	}

	link[len] = '\0';
	devname = strrchr(link, '/');
	if (!devname)
		return NULL;
	devname++;

	if (!strncmp(devname, "dm-", 3))
		return dm_device_path(dev_id);

	if (snprintf(path, sizeof(path), "/dev/%s", devname) < 0)
		return NULL;

	return strdup(path);
}
