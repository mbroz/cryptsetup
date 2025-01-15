// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * loopback block device utilities
 *
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>     /* for major, minor */
#endif
#include <linux/types.h>
#include <linux/loop.h>

#include "utils_loop.h"
#include "libcryptsetup_macros.h"

#define LOOP_DEV_MAJOR 7

#ifndef LO_FLAGS_AUTOCLEAR
#define LO_FLAGS_AUTOCLEAR 4
#endif

#ifndef LOOP_CTL_GET_FREE
#define LOOP_CTL_GET_FREE 0x4C82
#endif

#ifndef LOOP_SET_CAPACITY
#define LOOP_SET_CAPACITY 0x4C07
#endif

#ifndef LOOP_SET_BLOCK_SIZE
#define LOOP_SET_BLOCK_SIZE 0x4C09
#endif

#ifndef LOOP_CONFIGURE
#define LOOP_CONFIGURE 0x4C0A
struct loop_config {
  __u32 fd;
  __u32 block_size;
  struct loop_info64 info;
  __u64 __reserved[8];
};
#endif

static char *crypt_loop_get_device_old(void)
{
	char dev[64];
	int i, loop_fd;
	struct loop_info64 lo64 = {0};

	for (i = 0; i < 256; i++) {
		sprintf(dev, "/dev/loop%d", i);

		loop_fd = open(dev, O_RDONLY);
		if (loop_fd < 0)
			return NULL;

		if (ioctl(loop_fd, LOOP_GET_STATUS64, &lo64) &&
		    errno == ENXIO) {
			close(loop_fd);
			return strdup(dev);
		}
		close(loop_fd);
	}

	return NULL;
}

static char *crypt_loop_get_device(void)
{
	char dev[64];
	int i, loop_fd;
	struct stat st;

	loop_fd = open("/dev/loop-control", O_RDONLY);
	if (loop_fd < 0)
		return crypt_loop_get_device_old();

	i = ioctl(loop_fd, LOOP_CTL_GET_FREE);
	if (i < 0) {
		close(loop_fd);
		return NULL;
	}
	close(loop_fd);

	if (sprintf(dev, "/dev/loop%d", i) < 0)
		return NULL;

	if (stat(dev, &st) || !S_ISBLK(st.st_mode))
		return NULL;

	return strdup(dev);
}

int crypt_loop_attach(char **loop, const char *file, int offset,
		      int autoclear, int *readonly, size_t blocksize)
{
	struct loop_config config = {0};
	char *lo_file_name;
	int loop_fd = -1, file_fd = -1, r = 1;
	int fallback = 0;

	*loop = NULL;

	file_fd = open(file, *readonly ? O_RDONLY : O_RDWR);
	if (file_fd < 0 && (errno == EROFS || errno == EACCES) && !*readonly) {
		*readonly = 1;
		file_fd = open(file, O_RDONLY);
	}
	if (file_fd < 0)
		goto out;

	config.fd = file_fd;

	lo_file_name = (char*)config.info.lo_file_name;
	lo_file_name[LO_NAME_SIZE-1] = '\0';
	strncpy(lo_file_name, file, LO_NAME_SIZE-1);
	config.info.lo_offset = offset;
	if (autoclear)
		config.info.lo_flags |= LO_FLAGS_AUTOCLEAR;
	if (blocksize > SECTOR_SIZE)
		config.block_size = blocksize;

	while (loop_fd < 0) {
		*loop = crypt_loop_get_device();
		if (!*loop)
			goto out;

		loop_fd = open(*loop, *readonly ? O_RDONLY : O_RDWR);
		if (loop_fd < 0)
			goto out;
		if (ioctl(loop_fd, LOOP_CONFIGURE, &config) < 0) {
			if (errno == EINVAL || errno == ENOTTY) {
				free(*loop);
				*loop = NULL;

				close(loop_fd);
				loop_fd = -1;

				/* kernel doesn't support LOOP_CONFIGURE */
				fallback = 1;
				break;
			}
			if (errno != EBUSY)
				goto out;
			free(*loop);
			*loop = NULL;

			close(loop_fd);
			loop_fd = -1;
		}
	}

	if (fallback) {
		while (loop_fd < 0) {
			*loop = crypt_loop_get_device();
			if (!*loop)
				goto out;

			loop_fd = open(*loop, *readonly ? O_RDONLY : O_RDWR);
			if (loop_fd < 0)
				goto out;
			if (ioctl(loop_fd, LOOP_SET_FD, file_fd) < 0) {
				if (errno != EBUSY)
					goto out;
				free(*loop);
				*loop = NULL;

				close(loop_fd);
				loop_fd = -1;
			}
		}

		if (blocksize > SECTOR_SIZE)
			(void)ioctl(loop_fd, LOOP_SET_BLOCK_SIZE, (unsigned long)blocksize);

		if (ioctl(loop_fd, LOOP_SET_STATUS64, &config.info) < 0) {
			(void)ioctl(loop_fd, LOOP_CLR_FD, 0);
			goto out;
		}
	}

	/* Verify that autoclear is really set */
	if (autoclear) {
		memset(&config.info, 0, sizeof(config.info));
		if (ioctl(loop_fd, LOOP_GET_STATUS64, &config.info) < 0 ||
		   !(config.info.lo_flags & LO_FLAGS_AUTOCLEAR)) {
		(void)ioctl(loop_fd, LOOP_CLR_FD, 0);
			goto out;
		}
	}

	r = 0;
out:
	if (r && loop_fd >= 0)
		close(loop_fd);
	if (file_fd >= 0)
		close(file_fd);
	if (r && *loop) {
		free(*loop);
		*loop = NULL;
	}
	return r ? -1 : loop_fd;
}

int crypt_loop_detach(const char *loop)
{
	int loop_fd = -1, r = 1;

	loop_fd = open(loop, O_RDONLY);
	if (loop_fd < 0)
                return 1;

	if (!ioctl(loop_fd, LOOP_CLR_FD, 0))
		r = 0;

	close(loop_fd);
	return r;
}

int crypt_loop_resize(const char *loop)
{
	int loop_fd = -1, r = 1;

	loop_fd = open(loop, O_RDONLY);
	if (loop_fd < 0)
                return 1;

	if (!ioctl(loop_fd, LOOP_SET_CAPACITY, 0))
		r = 0;

	close(loop_fd);
	return r;
}

static char *_ioctl_backing_file(const char *loop)
{
	struct loop_info64 lo64 = {0};
	int loop_fd;

	loop_fd = open(loop, O_RDONLY);
	if (loop_fd < 0)
		return NULL;

	if (ioctl(loop_fd, LOOP_GET_STATUS64, &lo64) < 0) {
		close(loop_fd);
		return NULL;
	}

	lo64.lo_file_name[LO_NAME_SIZE-2] = '*';
	lo64.lo_file_name[LO_NAME_SIZE-1] = 0;

	close(loop_fd);

	return strdup((char*)lo64.lo_file_name);
}

static char *_sysfs_backing_file(const char *loop)
{
	struct stat st;
	char buf[PATH_MAX];
	ssize_t len;
	int fd;

	if (stat(loop, &st) || !S_ISBLK(st.st_mode))
		return NULL;

	if (snprintf(buf, sizeof(buf), "/sys/dev/block/%d:%d/loop/backing_file",
		     major(st.st_rdev), minor(st.st_rdev)) < 0)
		return NULL;

	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return NULL;

	len = read(fd, buf, PATH_MAX);
	close(fd);
	if (len < 2)
		return NULL;

	buf[len - 1] = '\0';
	return strdup(buf);
}

char *crypt_loop_backing_file(const char *loop)
{
	char *bf;

	if (!crypt_loop_device(loop))
		return NULL;

	bf = _sysfs_backing_file(loop);
	return bf ?: _ioctl_backing_file(loop);
}

int crypt_loop_device(const char *loop)
{
	struct stat st;

	if (!loop)
		return 0;

	if (stat(loop, &st) || !S_ISBLK(st.st_mode) ||
	    major(st.st_rdev) != LOOP_DEV_MAJOR)
		return 0;

	return 1;
}
