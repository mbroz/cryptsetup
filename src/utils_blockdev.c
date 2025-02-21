// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux block devices helpers
 *
 * Copyright (C) 2018-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2025 Ondrej Kozina
 */

#include "cryptsetup.h"
#include <dirent.h>
#if HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>     /* for major, minor */
#endif
#include <uuid/uuid.h>

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

	if (snprintf(buf, buflen, DM_UUID_PREFIX "%s%s%s%s",
	    type ?: "", type ? "-" : "",
	    uuid2[0] ? uuid2 : "", uuid2[0] ? "-" : "") < 0)
		return 0;

	return 1;
}

/* return number of holders in general, if matched dm_uuid prefix it's returned via dm_name */
/* negative value is error */
static int lookup_holder_dm_name(const char *dm_uuid, dev_t devno, char **r_dm_name)
{
	struct dirent *entry;
	char dm_subpath[PATH_MAX], data_dev_dir[PATH_MAX], uuid[DM_UUID_LEN], dm_name[PATH_MAX] = {};
	ssize_t s;
	struct stat st;
	int dmfd, fd, dfd, len, r = 0; /* not found */
	DIR *dir;

	if (!r_dm_name)
		return -EINVAL;

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
		dfd = dirfd(dir);
		if (dfd < 0)
			continue;
		dmfd = openat(dfd, dm_subpath, O_DIRECTORY | O_RDONLY);
		if (dmfd < 0)
			continue;

		fd = openat(dmfd, "uuid", O_RDONLY);
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
		s = read_buffer(fd, uuid, sizeof(uuid) - 1);
		close(fd);
		uuid[s > 0 ? s : 0] = '\0';
		if (!strncmp(uuid, dm_uuid, strlen(dm_uuid)))
			log_dbg("Found candidate device %s", entry->d_name);
		else {
			close(dmfd);
			continue;
		}

		fd = openat(dmfd, "name", O_RDONLY);
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
		s = read_buffer(fd, dm_name, sizeof(dm_name));
		close(fd);
		close(dmfd);
		if (s > 1) {
			dm_name[s-1] = '\0';
			log_dbg("Found dm device %s", dm_name);
			if (!(*r_dm_name = strdup(dm_name)))
				return -ENOMEM;
		}
	}

	closedir(dir);

	return r;
}

int tools_lookup_crypt_device(struct crypt_device *cd, const char *type,
		const char *data_device_path, char **r_name)
{
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

	return lookup_holder_dm_name(dev_uuid + DM_BY_ID_PREFIX_LEN, st.st_rdev, r_name);
}

static void report_partition(const char *value, const char *device, bool batch_mode)
{
	if (batch_mode)
		log_dbg("Device %s already contains a '%s' partition signature.", device, value);
	else
		log_std(_("WARNING: Device %s already contains a '%s' partition signature.\n"), device, value);
}

static void report_superblock(const char *value, const char *device, bool batch_mode)
{
	if (batch_mode)
		log_dbg("Device %s already contains a '%s' superblock signature.", device, value);
	else
		log_std(_("WARNING: Device %s already contains a '%s' superblock signature.\n"), device, value);
}

int tools_detect_signatures(const char *device, tools_probe_filter_info filter,
		size_t *count,bool batch_mode)
{
	int r;
	size_t tmp_count;
	struct blkid_handle *h;
	blk_probe_status pr;

	if (!count)
		count = &tmp_count;

	*count = 0;

	if (!blk_supported()) {
		log_dbg("Blkid support disabled.");
		return 0;
	}

	if ((r = blk_init_by_path(&h, device))) {
		log_err(_("Failed to initialize device signature probes."));
		return -EINVAL;
	}

	switch (filter) {
	case PRB_FILTER_LUKS:
		log_dbg("Blkid check (filter LUKS).");
		if (blk_superblocks_filter_luks(h)) {
			r = -EINVAL;
			log_dbg("Blkid filter LUKS probe failed.");
			goto out;
		}
		/* fall-through */
	case PRB_FILTER_NONE:
		log_dbg("Blkid check (filter none).");
		blk_set_chains_for_full_print(h);
		break;
	case PRB_ONLY_LUKS:
		log_dbg("Blkid check (LUKS only).");
		blk_set_chains_for_fast_detection(h);
		if (blk_superblocks_only_luks(h)) {
			log_dbg("Blkid only LUKS probe failed.");
			r = -EINVAL;
			goto out;
		}
	}

	while ((pr = blk_probe(h)) < PRB_EMPTY) {
		if (blk_is_partition(h))
			report_partition(blk_get_partition_type(h), device, batch_mode);
		else if (blk_is_superblock(h))
			report_superblock(blk_get_superblock_type(h), device, batch_mode);
		else {
			log_dbg("Internal tools_detect_signatures() error.");
			r = -EINVAL;
			goto out;
		}
		(*count)++;
	}

	if (pr == PRB_FAIL) {
		/* Expect device cannot be read */
		r = -EIO;
		log_dbg("Blkid probe failed.");
	}
out:
	blk_free(h);
	return r;
}

int tools_wipe_all_signatures(const char *path, bool exclusive, bool only_luks)
{
	int fd, flags, r;
	blk_probe_status pr;
	struct stat st;
	struct blkid_handle *h = NULL;

	if (!blk_supported()) {
		log_dbg("Blkid support disabled.");
		return 0;
	}

	if (stat(path, &st)) {
		log_err(_("Failed to stat device %s."), path);
		return -EINVAL;
	}

	flags = O_RDWR;
	if (S_ISBLK(st.st_mode) && exclusive)
		flags |= O_EXCL;

	/* better than opening regular file with O_EXCL (undefined) */
	/* coverity[toctou] */
	fd = open(path, flags); /* lgtm[cpp/toctou-race-condition] */
	if (fd < 0) {
		if (errno == EBUSY)
			log_err(_("Cannot exclusively open %s, device in use."), path);
		else
			log_err(_("Failed to open file %s in read/write mode."), path);
		return -EINVAL;
	}

	if ((r = blk_init_by_fd(&h, fd))) {
		log_err(_("Failed to initialize device signature probes."));
		r = -EINVAL;
		goto out;
	}

	blk_set_chains_for_wipes(h);
	if (only_luks && (r = blk_superblocks_only_luks(h))) {
		r = -EINVAL;
		goto out;
	}

	log_dbg("Blkid wipe.");

	while ((pr = blk_probe(h)) < PRB_EMPTY) {
		if (blk_is_partition(h))
			log_verbose(_("Existing '%s' partition signature on device %s will be wiped."),
				    blk_get_partition_type(h), path);
		if (blk_is_superblock(h))
			log_verbose(_("Existing '%s' superblock signature on device %s will be wiped."),
				    blk_get_superblock_type(h), path);
		if (blk_do_wipe(h) || fsync(fd)) {
			log_err(_("Failed to wipe device signature."));
			r = -EINVAL;
			goto out;
		}
	}

	if (pr != PRB_EMPTY) {
		log_err(_("Failed to probe device %s for a signature."), path);
		r = -EINVAL;
	}
out:
	close(fd);
	blk_free(h);
	return r;
}

int tools_superblock_block_size(const char *device, char *sb_name, size_t sb_name_len, unsigned *r_block_size)
{
	struct blkid_handle *h;
	const char *name;
	int r = 0;

	if (!r_block_size || !sb_name || sb_name_len < 1)
		return -EINVAL;

	if (!blk_supported()) {
		log_dbg("Blkid support disabled.");
		return 0;
	}

	if ((r = blk_init_by_path(&h, device))) {
		log_err(_("Failed to initialize device signature probes."));
		return -EINVAL;
	}

	blk_set_chains_for_superblocks(h);

	switch (blk_probe(h)) {
	case PRB_OK:
		*r_block_size = blk_get_block_size(h);
		if (!*r_block_size) /* same as not-found */
			break;

		if (!(name = blk_get_superblock_type(h))) {
			r = -EINVAL;
			break;
		}

		/* we don't mind truncating */
		strncpy(sb_name, name, sb_name_len - 1);
		sb_name[sb_name_len-1] = '\0';

		log_dbg("Detected superblock %s on device %s (block size: %u).", sb_name, device, *r_block_size);
		r = 1;
		/* fall-through */
	case PRB_EMPTY:
		break;
	default:
		r = -EINVAL;
	}

	blk_free(h);

	return r;
}

bool tools_blkid_supported(void)
{
	return blk_supported() != 0;
}
