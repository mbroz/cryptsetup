/*
 * cryptsetup library API test utilities
 *
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <libdevmapper.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef KERNEL_KEYRING
# include <linux/keyctl.h>
# include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>
#endif
#include <linux/loop.h>

#include "api_test.h"
#include "libcryptsetup.h"

static char last_error[256];
static char global_log[4096];
static uint32_t t_dm_crypt_flags = 0;

char *THE_LOOP_DEV = NULL;
int _debug   = 0;
int global_lines = 0;
int _quit = 0;
int _verbose = 0;
uint64_t t_dev_offset = 0;

static void (*_cleanup)(void);

void register_cleanup(void (*cleanup)(void))
{
	_cleanup = cleanup;
}

void check_ok(int status, int line, const char *func)
{
	if (status) {
		printf("FAIL line %d [%s]: code %d, %s\n", line, func, status, last_error);
		_cleanup();
		exit(-1);
	}
}

void check_ok_return(int status, int line, const char *func)
{
	if (status < 0) {
		printf("FAIL line %d [%s]: code %d, %s\n", line, func, status, last_error);
		_cleanup();
		exit(-1);
	}
}

void check_ko(int status, int line, const char *func)
{
	if (status >= 0) {
		printf("FAIL line %d [%s]: code %d, %s\n", line, func, status, last_error);
		_cleanup();
		exit(-1);
	} else if (_verbose)
		printf("   => errno %d, errmsg: %s\n", status, last_error);
}

void check_equal(int line, const char *func, int64_t x, int64_t y)
{
	printf("FAIL line %d [%s]: expected equal values differs: %"
		PRIi64 " != %" PRIi64 "\n", line, func, x, y);
	_cleanup();
	exit(-1);
}

void check_null(int line, const char *func, const void *x)
{
	if (x) {
		printf("FAIL line %d [%s]: expected NULL value: %p\n", line, func, x);
		_cleanup();
		exit(-1);
	}
}

void check_notnull(int line, const char *func, const void *x)
{
	if (!x) {
		printf("FAIL line %d [%s]: expected not NULL value: %p\n", line, func, x);
		_cleanup();
		exit(-1);
	}
}

void xlog(const char *msg, const char *tst, const char *func, int line, const char *txt)
{
	if (_verbose) {
		if (txt)
			printf(" [%s,%s:%d] %s [%s]\n", msg, func, line, tst, txt);
		else
			printf(" [%s,%s:%d] %s\n", msg, func, line, tst);
	}
	if (_quit) {
		if (_verbose)
			printf("Interrupted by a signal.\n");
		_cleanup();
		exit(-1);
	}
}

int t_device_size(const char *device, uint64_t *size)
{
	int devfd, r = 0;

	devfd = open(device, O_RDONLY);
	if(devfd == -1)
		return -EINVAL;

	if (ioctl(devfd, BLKGETSIZE64, size) < 0)
		r = -EINVAL;
	close(devfd);
	return r;
}

int fips_mode(void)
{
	int fd;
	char buf = 0;

	fd = open("/proc/sys/crypto/fips_enabled", O_RDONLY);

	if (fd < 0)
		return 0;

	if (read(fd, &buf, 1) != 1)
		buf = '0';

	close(fd);

	return (buf == '1');
}

/*
 * Creates dm-linear target over the test loop device. Offset is held in
 * global variables so that size can be tested whether it fits into remaining
 * size of the loop device or not
 */
int create_dmdevice_over_loop(const char *dm_name, const uint64_t size)
{
	char cmd[128];
	int r;
	uint64_t r_size;

	if (t_device_size(THE_LOOP_DEV, &r_size) < 0 || r_size <= t_dev_offset || !size)
		return -1;
	if ((r_size - t_dev_offset) < size) {
		printf("No enough space on backing loop device\n.");
		return -2;
	}
	snprintf(cmd, sizeof(cmd),
		 "dmsetup create %s --table \"0 %" PRIu64 " linear %s %" PRIu64 "\"",
		 dm_name, size, THE_LOOP_DEV, t_dev_offset);
	if (!(r = _system(cmd, 1)))
		t_dev_offset += size;
	return r;
}

// Get key from kernel dm mapping table using dm-ioctl
int get_key_dm(const char *name, char *buffer, unsigned int buffer_size)
{
	struct dm_task *dmt;
	struct dm_info dmi;
	uint64_t start, length;
	char *target_type, *key, *params;
	void *next = NULL;
	int r = -EINVAL;

	if (!(dmt = dm_task_create(DM_DEVICE_TABLE)))
		goto out;
	if (!dm_task_set_name(dmt, name))
		goto out;
	if (!dm_task_run(dmt))
		goto out;
	if (!dm_task_get_info(dmt, &dmi))
		goto out;
	if (!dmi.exists)
		goto out;

	next = dm_get_next_target(dmt, next, &start, &length, &target_type, &params);
	if (!target_type || strcmp(target_type, "crypt") != 0)
		goto out;

	(void)strsep(&params, " "); /* rcipher */
	key = strsep(&params, " ");

	if (buffer_size <= strlen(key))
		goto out;

	strncpy(buffer, key, buffer_size);
	r = 0;
out:
	if (dmt)
		dm_task_destroy(dmt);

	return r;
}

int prepare_keyfile(const char *name, const char *passphrase, int size)
{
	int fd, r;

	fd = open(name, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR|S_IWUSR);
	if (fd != -1) {
		r = write(fd, passphrase, size);
		close(fd);
	} else
		r = 0;

	return r == size ? 0 : 1;
}

// Decode key from its hex representation
int crypt_decode_key(char *key, const char *hex, unsigned int size)
{
	char buffer[3];
	char *endp;
	unsigned int i;

	buffer[2] = '\0';

	for (i = 0; i < size; i++) {
		buffer[0] = *hex++;
		buffer[1] = *hex++;

		key[i] = (unsigned char)strtoul(buffer, &endp, 16);

		if (endp != &buffer[2])
			return -1;
	}

	if (*hex != '\0')
		return -1;

	return 0;
}

void global_log_callback(int level, const char *msg, void *usrptr)
{
	size_t len;

	if (_debug) {
		if (level == CRYPT_LOG_DEBUG)
			fprintf(stdout, "# %s", msg);
		else
			fprintf(stdout, "%s", msg);
	}

	if (level <= CRYPT_LOG_DEBUG)
		return;

	strncat(global_log, msg, sizeof(global_log) - strlen(global_log));
	global_lines++;
	if (level == CRYPT_LOG_ERROR) {
		len = strlen(msg);
		if (len > sizeof(last_error))
			len = sizeof(last_error);
		strncpy(last_error, msg, sizeof(last_error));
		last_error[len-1] = '\0';
	}
}

void reset_log(void)
{
	memset(global_log, 0, sizeof(global_log));
	memset(last_error, 0, sizeof(last_error));
	global_lines = 0;
}

int _system(const char *command, int warn)
{
	int r;
	if (_debug)
		printf("Running system: %s\n", command);
	if ((r=system(command)) < 0 && warn)
		printf("System command failed: %s", command);
	return r;
}

static int keyring_check(void)
{
#ifdef KERNEL_KEYRING
	return syscall(__NR_request_key, "logon", "dummy", NULL, 0) == -1l && errno != ENOSYS;
#else
	return 0;
#endif
}

static int t_dm_satisfies_version(unsigned target_maj, unsigned target_min, unsigned target_patch,
				 unsigned actual_maj, unsigned actual_min, unsigned actual_patch)
{
	if (actual_maj > target_maj)
		return 1;
	if (actual_maj == target_maj && actual_min > target_min)
		return 1;
	if (actual_maj == target_maj && actual_min == target_min && actual_patch >= target_patch)
		return 1;
	return 0;
}

static void t_dm_set_crypt_compat(const char *dm_version, unsigned crypt_maj,
				 unsigned crypt_min, unsigned crypt_patch)
{
	unsigned dm_maj = 0, dm_min = 0, dm_patch = 0;

	if (sscanf(dm_version, "%u.%u.%u", &dm_maj, &dm_min, &dm_patch) != 3) {
		dm_maj = 0;
		dm_min = 0;
		dm_patch = 0;
	}

	if (t_dm_satisfies_version(1, 2, 0, crypt_maj, crypt_min, 0))
		t_dm_crypt_flags |= T_DM_KEY_WIPE_SUPPORTED;

	if (t_dm_satisfies_version(1, 10, 0, crypt_maj, crypt_min, 0))
		t_dm_crypt_flags |= T_DM_LMK_SUPPORTED;

	if (t_dm_satisfies_version(4, 20, 0, dm_maj, dm_min, 0))
		t_dm_crypt_flags |= T_DM_SECURE_SUPPORTED;

	if (t_dm_satisfies_version(1, 8, 0, crypt_maj, crypt_min, 0))
		t_dm_crypt_flags |= T_DM_PLAIN64_SUPPORTED;

	if (t_dm_satisfies_version(1, 11, 0, crypt_maj, crypt_min, 0))
		t_dm_crypt_flags |= T_DM_DISCARDS_SUPPORTED;

	if (t_dm_satisfies_version(1, 13, 0, crypt_maj, crypt_min, 0))
		t_dm_crypt_flags |= T_DM_TCW_SUPPORTED;

	if (t_dm_satisfies_version(1, 14, 0, crypt_maj, crypt_min, 0)) {
		t_dm_crypt_flags |= T_DM_SAME_CPU_CRYPT_SUPPORTED;
		t_dm_crypt_flags |= T_DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED;
	}

	if (t_dm_satisfies_version(1, 18, 1, crypt_maj, crypt_min, crypt_patch) && keyring_check())
		t_dm_crypt_flags |= T_DM_KERNEL_KEYRING_SUPPORTED;
}

static void t_dm_set_verity_compat(const char *dm_version, unsigned verity_maj,
				   unsigned verity_min, unsigned verity_patch)
{
	if (verity_maj > 0)
		t_dm_crypt_flags |= T_DM_VERITY_SUPPORTED;
	else
		return;
	/*
	 * ignore_corruption, restart_on corruption is available since 1.2 (kernel 4.1)
	 * ignore_zero_blocks since 1.3 (kernel 4.5)
	 * (but some dm-verity targets 1.2 don't support it)
	 * FEC is added in 1.3 as well.
	 */
	if (t_dm_satisfies_version(1, 3, 0, verity_maj, verity_min, 0)) {
		t_dm_crypt_flags |= T_DM_VERITY_ON_CORRUPTION_SUPPORTED;
		t_dm_crypt_flags |= T_DM_VERITY_FEC_SUPPORTED;
	}
}

static void t_dm_set_integrity_compat(const char *dm_version, unsigned integrity_maj,
				      unsigned integrity_min, unsigned integrity_patch)
{
	if (integrity_maj > 0)
		t_dm_crypt_flags |= T_DM_INTEGRITY_SUPPORTED;
}

int t_dm_check_versions(void)
{
	struct dm_task *dmt;
	struct dm_versions *target, *last_target;
	char dm_version[16];
	int r = 1;

	if (!(dmt = dm_task_create(DM_DEVICE_LIST_VERSIONS)))
		goto out;

	if (!dm_task_run(dmt))
		goto out;

	if (!dm_task_get_driver_version(dmt, dm_version, sizeof(dm_version)))
		goto out;

	target = dm_task_get_versions(dmt);
	do {
		last_target = target;
		if (!strcmp("crypt", target->name)) {
			t_dm_set_crypt_compat(dm_version,
					     (unsigned)target->version[0],
					     (unsigned)target->version[1],
					     (unsigned)target->version[2]);
		} else if (!strcmp("verity", target->name)) {
			t_dm_set_verity_compat(dm_version,
					     (unsigned)target->version[0],
					     (unsigned)target->version[1],
					     (unsigned)target->version[2]);
		} else if (!strcmp("integrity", target->name)) {
			t_dm_set_integrity_compat(dm_version,
					     (unsigned)target->version[0],
					     (unsigned)target->version[1],
					     (unsigned)target->version[2]);
		}
		target = (struct dm_versions *)((char *) target + target->next);
	} while (last_target != target);

	r = 0;
out:
	if (dmt)
		dm_task_destroy(dmt);

	return r;
}

int t_dm_crypt_keyring_support(void)
{
	return t_dm_crypt_flags & T_DM_KERNEL_KEYRING_SUPPORTED;
}

int t_dm_crypt_cpu_switch_support(void)
{
	return t_dm_crypt_flags & (T_DM_SAME_CPU_CRYPT_SUPPORTED |
				   T_DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED);
}

int t_dm_crypt_discard_support(void)
{
	return t_dm_crypt_flags & T_DM_DISCARDS_SUPPORTED;
}

/* loop helpers */

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

int loop_device(const char *loop)
{
	struct stat st;

	if (!loop)
		return 0;

	if (stat(loop, &st) || !S_ISBLK(st.st_mode) ||
	    major(st.st_rdev) != LOOP_DEV_MAJOR)
		return 0;

	return 1;
}

static char *crypt_loop_get_device_old(void)
{
	char dev[20];
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

int loop_attach(char **loop, const char *file, int offset,
		      int autoclear, int *readonly)
{
	struct loop_info64 lo64 = {0};
	char *lo_file_name;
	int loop_fd = -1, file_fd = -1, r = 1;

	*loop = NULL;

	file_fd = open(file, (*readonly ? O_RDONLY : O_RDWR) | O_EXCL);
	if (file_fd < 0 && (errno == EROFS || errno == EACCES) && !*readonly) {
		*readonly = 1;
		file_fd = open(file, O_RDONLY | O_EXCL);
	}
	if (file_fd < 0)
		goto out;

	while (loop_fd < 0)  {
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

	lo_file_name = (char*)lo64.lo_file_name;
	lo_file_name[LO_NAME_SIZE-1] = '\0';
	strncpy(lo_file_name, file, LO_NAME_SIZE-1);
	lo64.lo_offset = offset;
	if (autoclear)
		lo64.lo_flags |= LO_FLAGS_AUTOCLEAR;

	if (ioctl(loop_fd, LOOP_SET_STATUS64, &lo64) < 0) {
		(void)ioctl(loop_fd, LOOP_CLR_FD, 0);
		goto out;
	}

	/* Verify that autoclear is really set */
	if (autoclear) {
		memset(&lo64, 0, sizeof(lo64));
		if (ioctl(loop_fd, LOOP_GET_STATUS64, &lo64) < 0 ||
		   !(lo64.lo_flags & LO_FLAGS_AUTOCLEAR)) {
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

int loop_detach(const char *loop)
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
