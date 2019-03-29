/*
 * Linux block devices helpers
 *
 * Copyright (C) 2018-2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2019 Ondrej Kozina
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

#include "cryptsetup.h"
#include <dirent.h>
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>     /* for major, minor */
#endif
#include <uuid/uuid.h>

#define DM_UUID_LEN		129
#define DM_BY_ID_PREFIX		"dm-uuid-"
#define DM_BY_ID_PREFIX_LEN	8
#define DM_UUID_PREFIX		"CRYPT-"
#define DM_UUID_PREFIX_LEN	6
#define UUID_LEN 37 /* 36 + \0, libuuid ... */

static int dm_prepare_uuid(const char *type, const char *uuid, char *buf, size_t buflen)
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

	snprintf(buf, buflen, DM_UUID_PREFIX "%s%s%s%s",
		type ?: "", type ? "-" : "",
		uuid2[0] ? uuid2 : "", uuid2[0] ? "-" : "");

	return 1;
}

/* return number of holders in general, if matched dm_uuid prefix it's returned via dm_name */
/* negative value is error */
static int lookup_holder_dm_name(const char *dm_uuid, size_t max_len, dev_t devno, char *dm_name, size_t dm_name_length)
{
	struct dirent *entry;
	char dm_subpath[PATH_MAX], data_dev_dir[PATH_MAX], uuid[max_len];
	ssize_t s;
	struct stat st;
	int dmfd, fd, len, r = 0; /* not found */
	DIR *dir;

	if (!dm_name || !dm_name_length)
		return -EINVAL;

	*dm_name = '\0';

	len = snprintf(data_dev_dir, PATH_MAX, "/sys/dev/block/%u:%u/holders", major(devno), minor(devno));
	if (len < 0 || len >= PATH_MAX)
		return -EINVAL;

	if (!(dir = opendir(data_dev_dir)))
		/* map ENOTDIR to ENOENT we'll handle both errors same */
		return errno == ENOTDIR ? -ENOENT : -errno;

	while (r != 1 && (entry = readdir(dir))) {
		if (entry->d_name[0] == '.' ||
		    !strncmp(entry->d_name, "..", 2))
			continue;

		/* there's a holder */
		r++;

		/* we already have a dm_name, just count remaining holders */
		if (*dm_name != '\0')
			continue;

		len = snprintf(dm_subpath, PATH_MAX, "%s/%s", entry->d_name, "dm");
		if (len < 0 || len >= PATH_MAX) {
			r = -EINVAL;
			break;
		}

		/* looking for dm-X/dm directory, symlinks are fine */
		dmfd = openat(dirfd(dir), dm_subpath, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
		if (dmfd < 0)
			continue;

		fd = openat(dmfd, "uuid", O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			close(dmfd);
			continue;
		}

		if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
			close(fd);
			close(dmfd);
			continue;
		}

		/* reads binary data */
		s = read_buffer(fd, uuid, max_len - 1);
		close(fd);
		uuid[s > 0 ? s : 0] = '\0';
		if (!strncmp(uuid, dm_uuid, strlen(dm_uuid)))
			log_dbg("Found candidate device %s", entry->d_name);
		else {
			close(dmfd);
			continue;
		}

		fd = openat(dmfd, "name", O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			close(dmfd);
			continue;
		}

		if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
			close(fd);
			close(dmfd);
			continue;
		}

		/* reads binary data */
		s = read_buffer(fd, dm_name, dm_name_length - 1);
		close(fd);
		close(dmfd);
		if (s > 1) {
			dm_name[s-1] = '\0';
			log_dbg("Found dm device %s", dm_name);
		}
	}

	closedir(dir);

	return r;
}

int tools_lookup_crypt_device(struct crypt_device *cd, const char *type,
		const char *data_device_path, char *name, size_t name_length)
{
	int r;
	char *c;
	struct stat st;
	char dev_uuid[DM_UUID_LEN + DM_BY_ID_PREFIX_LEN] = DM_BY_ID_PREFIX;

	if (!dm_prepare_uuid(type, crypt_get_uuid(cd), dev_uuid + DM_BY_ID_PREFIX_LEN, DM_UUID_LEN))
		return -EINVAL;

	c = strrchr(dev_uuid, '-');
	if (!c)
		return -EINVAL;

	/* cut of dm name */
	*c = '\0';

	log_dbg("Looking for any dm device with prefix: %s", dev_uuid);

	if (stat(data_device_path, &st) < 0)
		return -ENODEV;

	if (!S_ISBLK(st.st_mode))
		return -ENOTBLK;

	r = lookup_holder_dm_name(dev_uuid + DM_BY_ID_PREFIX_LEN, DM_UUID_LEN,
			st.st_rdev, name, name_length);
	return r;
}
