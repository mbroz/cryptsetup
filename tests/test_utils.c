// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup library API test utilities
 *
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include <assert.h>
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
#if KERNEL_KEYRING
# include <linux/keyctl.h>
# include <sys/syscall.h>
#endif
#if HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>
#endif
#include <linux/loop.h>

#include "api_test.h"
#include "libcryptsetup.h"

#ifndef LOOP_CONFIGURE
#define LOOP_CONFIGURE 0x4C0A
struct loop_config {
	__u32 fd;
	__u32 block_size;
	struct loop_info64 info;
	__u64 __reserved[8];
};
#endif

static char last_error[256];
static char global_log[4096];
static uint64_t t_dm_crypt_flags = 0;

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

void check_ge_equal(int line, const char *func, int64_t x, int64_t y)
{
	printf("FAIL line %d [%s]: expected greater or equal values differs: %"
		PRIi64 " < %" PRIi64 "\n", line, func, x, y);
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

int t_set_readahead(const char *device, unsigned value)
{
	int devfd, r = 0;

	devfd = open(device, O_RDONLY);
	if(devfd == -1)
		return -EINVAL;

	if (ioctl(devfd, BLKRASET, value) < 0)
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
	int r;

	r = create_dmdevice_over_device(dm_name, THE_LOOP_DEV, size, t_dev_offset);
	if (r != 0)
		return r;

	t_dev_offset += size;

	return r;
}

/*
 * Creates dm-linear target over the desired block device.
 */
int create_dmdevice_over_device(const char *dm_name, const char *device, uint64_t size, uint64_t offset)
{
	char cmd[128];
	int r;
	uint64_t r_size;

	if (!device || t_device_size(device, &r_size) < 0 || r_size <= offset || !size)
		return -1;
	if ((r_size - offset) < size) {
		printf("No enough space on device %s\n.", device);
		return -2;
	}
	r = snprintf(cmd, sizeof(cmd),
		     "dmsetup create %s --table \"0 %" PRIu64 " linear %s %" PRIu64 "\"",
		     dm_name, size, device, offset);
	if (r < 0 || (size_t)r >= sizeof(cmd))
		return -3;

	return _system(cmd, 1);
}

__attribute__((format(printf, 3, 4)))
static int _snprintf(char **r_ptr, size_t *r_remains, const char *format, ...)
{
	int len, r = 0;
	va_list argp;

	assert(r_remains);
	assert(r_ptr);

	va_start(argp, format);

	len = vsnprintf(*r_ptr, *r_remains, format, argp);
	if (len < 0 || (size_t)len >= *r_remains) {
		r = -EINVAL;
	} else {
		*r_ptr += len;
		*r_remains -= len;
	}

	va_end(argp);

	return r;
}

int dmdevice_error_io(const char *dm_name,
	const char *dm_device,
	const char *error_device,
	uint64_t data_offset,
	uint64_t offset,
	uint64_t length,
	error_io_info ei)
{
	char str[256], cmd[384];
	int r;
	uint64_t dev_size;
	size_t remains;
	char *ptr;

	if (t_device_size(dm_device, &dev_size) < 0 || !length)
		return -1;

	dev_size >>= TST_SECTOR_SHIFT;

	if (dev_size <= offset)
		return -1;

	if (ei == ERR_REMOVE) {
		r = snprintf(cmd, sizeof(cmd),
			     "dmsetup load %s --table \"0 %" PRIu64 " linear %s %" PRIu64 "\"",
			     dm_name, dev_size, THE_LOOP_DEV, data_offset);
		if (r < 0 || (size_t)r >= sizeof(str))
			return -3;

		if ((r = _system(cmd, 1)))
			return r;

		r = snprintf(cmd, sizeof(cmd), "dmsetup resume %s", dm_name);
		if (r < 0 || (size_t)r >= sizeof(cmd))
			return -3;

		return _system(cmd, 1);
	}

	if ((dev_size - offset) < length) {
		printf("Not enough space on target device\n.");
		return -2;
	}

	remains = sizeof(str);
	ptr = str;

	if (offset) {
		r = _snprintf(&ptr, &remains,
			     "0 %" PRIu64 " linear %s %" PRIu64 "\n",
			     offset, THE_LOOP_DEV, data_offset);
		if (r < 0)
			return r;
	}
	r = _snprintf(&ptr, &remains, "%" PRIu64 " %" PRIu64 " delay ",
		      offset, length);
	if (r < 0)
		return r;

	if (ei == ERR_RW || ei == ERR_RD) {
		r = _snprintf(&ptr, &remains, "%s 0 0",
			     error_device);
		if (r < 0)
			return r;
		if (ei == ERR_RD) {
			r = _snprintf(&ptr, &remains, " %s %" PRIu64 " 0",
				     THE_LOOP_DEV, data_offset + offset);
			if (r < 0)
				return r;
		}
	} else if (ei == ERR_WR) {
		r = _snprintf(&ptr, &remains, "%s %" PRIu64 " 0 %s 0 0",
			     THE_LOOP_DEV, data_offset + offset, error_device);
		if (r < 0)
			return r;
	}

	if (dev_size > (offset + length)) {
		r = _snprintf(&ptr, &remains,
			     "\n%" PRIu64 " %" PRIu64 " linear %s %" PRIu64,
			     offset + length, dev_size - offset - length, THE_LOOP_DEV,
			     data_offset + offset + length);
		if (r < 0)
			return r;
	}

	/*
	 * Hello darkness, my old friend...
	 *
	 * On few old distributions there's issue with
	 * processing multiline tables via dmsetup load --table.
	 * This workaround passes on all systems we run tests on.
	 */
	r = snprintf(cmd, sizeof(cmd), "dmsetup load %s <<EOF\n%s\nEOF", dm_name, str);
	if (r < 0 || (size_t)r >= sizeof(cmd))
		return -3;

	if ((r = _system(cmd, 1)))
		return r;

	r = snprintf(cmd, sizeof(cmd), "dmsetup resume %s", dm_name);
	if (r < 0 || (size_t)r >= sizeof(cmd))
		return -3;

	if ((r = _system(cmd, 1)))
		return r;

	return t_set_readahead(dm_device, 0);
}

// Get key from kernel dm mapping table using dm-ioctl
int get_key_dm(const char *name, char *buffer, unsigned int buffer_size)
{
	struct dm_task *dmt;
	struct dm_info dmi;
	uint64_t start, length;
	char *target_type, *key, *params;
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

	dm_get_next_target(dmt, NULL, &start, &length, &target_type, &params);
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

void global_log_callback(int level, const char *msg, void *usrptr __attribute__((unused)))
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

	len = strlen(global_log);

	if (len + strlen(msg) >= sizeof(global_log)) {
			printf("Log buffer is too small, fix the test.\n");
			return;
	}

	strncat(global_log, msg, sizeof(global_log) - len - 1);
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

static int _keyring_check(void)
{
#if KERNEL_KEYRING
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

	if (t_dm_satisfies_version(1, 18, 1, crypt_maj, crypt_min, crypt_patch) && _keyring_check())
		t_dm_crypt_flags |= T_DM_KERNEL_KEYRING_SUPPORTED;

	if (t_dm_satisfies_version(1, 17, 0, crypt_maj, crypt_min, crypt_patch)) {
		t_dm_crypt_flags |= T_DM_SECTOR_SIZE_SUPPORTED;
		t_dm_crypt_flags |= T_DM_CAPI_STRING_SUPPORTED;
	}

	if (t_dm_satisfies_version(1, 19, 0, crypt_maj, crypt_min, crypt_patch))
		t_dm_crypt_flags |= T_DM_BITLK_EBOIV_SUPPORTED;

	if (t_dm_satisfies_version(1, 20, 0, crypt_maj, crypt_min, crypt_patch))
		t_dm_crypt_flags |= T_DM_BITLK_ELEPHANT_SUPPORTED;

	if (t_dm_satisfies_version(1, 22, 0, crypt_maj, crypt_min, crypt_patch))
		t_dm_crypt_flags |= T_DM_CRYPT_NO_WORKQUEUE_SUPPORTED;

	if (t_dm_satisfies_version(1, 26, 0, crypt_maj, crypt_min, crypt_patch))
		t_dm_crypt_flags |= T_DM_CRYPT_HIGH_PRIORITY_SUPPORTED;

	if (t_dm_satisfies_version(1, 28, 0, crypt_maj, crypt_min, crypt_patch))
		t_dm_crypt_flags |= T_DM_CRYPT_INTEGRITY_KEY_SIZE_OPT_SUPPORTED;
}

static void t_dm_set_verity_compat(const char *dm_version __attribute__((unused)),
	unsigned verity_maj,
	unsigned verity_min,
	unsigned verity_patch __attribute__((unused)))
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

	if (t_dm_satisfies_version(1, 5, 0, verity_maj, verity_min, verity_patch))
		t_dm_crypt_flags |= T_DM_VERITY_SIGNATURE_SUPPORTED;

	if (t_dm_satisfies_version(1, 7, 0, verity_maj, verity_min, verity_patch))
		t_dm_crypt_flags |= T_DM_VERITY_PANIC_CORRUPTION_SUPPORTED;

	if (t_dm_satisfies_version(1, 9, 0, verity_maj, verity_min, verity_patch))
		t_dm_crypt_flags |= T_DM_VERITY_TASKLETS_SUPPORTED;

	/* There is actually no correct version set, just use the last available */
	if (t_dm_satisfies_version(1, 10, 0, verity_maj, verity_min, verity_patch))
		t_dm_crypt_flags |= T_DM_VERITY_ERROR_AS_CORRUPTION_SUPPORTED;
}

static void t_dm_set_integrity_compat(const char *dm_version __attribute__((unused)),
	unsigned integrity_maj __attribute__((unused)),
	unsigned integrity_min __attribute__((unused)),
	unsigned integrity_patch __attribute__((unused)))
{
	if (integrity_maj > 0)
		t_dm_crypt_flags |= T_DM_INTEGRITY_SUPPORTED;

	if (t_dm_satisfies_version(1, 2, 0, integrity_maj, integrity_min, integrity_patch))
		t_dm_crypt_flags |= T_DM_INTEGRITY_RECALC_SUPPORTED;

	if (t_dm_satisfies_version(1, 3, 0, integrity_maj, integrity_min, integrity_patch))
		t_dm_crypt_flags |= T_DM_INTEGRITY_BITMAP_SUPPORTED;

	if (t_dm_satisfies_version(1, 4, 0, integrity_maj, integrity_min, integrity_patch))
		t_dm_crypt_flags |= T_DM_INTEGRITY_FIX_PADDING_SUPPORTED;

	if (t_dm_satisfies_version(1, 6, 0, integrity_maj, integrity_min, integrity_patch))
		t_dm_crypt_flags |= T_DM_INTEGRITY_DISCARDS_SUPPORTED;

	if (t_dm_satisfies_version(1, 7, 0, integrity_maj, integrity_min, integrity_patch))
		t_dm_crypt_flags |= T_DM_INTEGRITY_FIX_HMAC_SUPPORTED;

	if (t_dm_satisfies_version(1, 8, 0, integrity_maj, integrity_min, integrity_patch))
		t_dm_crypt_flags |= T_DM_INTEGRITY_RESET_RECALC_SUPPORTED;

	if (t_dm_satisfies_version(1, 12, 0, integrity_maj, integrity_min, integrity_patch))
		t_dm_crypt_flags |= T_DM_INTEGRITY_INLINE_MODE_SUPPORTED;
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
		target = VOIDP_CAST(struct dm_versions *)((char *) target + target->next);
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

int t_dm_integrity_resize_support(void)
{
	return t_dm_crypt_flags & T_DM_INTEGRITY_RESIZE_SUPPORTED;
}

int t_dm_integrity_recalculate_support(void)
{
	return t_dm_crypt_flags & T_DM_INTEGRITY_RECALC_SUPPORTED;
}

int t_dm_capi_string_supported(void)
{
	return t_dm_crypt_flags & T_DM_CAPI_STRING_SUPPORTED;
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

int loop_attach(char **loop, const char *file, int offset,
		      int autoclear, int *readonly)
{
	struct loop_config config = {0};
	char *lo_file_name;
	int loop_fd = -1, file_fd = -1, r = 1;
	int fallback = 0;

	*loop = NULL;

	file_fd = open(file, (*readonly ? O_RDONLY : O_RDWR) | O_EXCL);
	if (file_fd < 0 && (errno == EROFS || errno == EACCES) && !*readonly) {
		*readonly = 1;
		file_fd = open(file, O_RDONLY | O_EXCL);
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

	while (loop_fd < 0)  {
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

	if (fallback)
	{
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

int t_get_devno(const char *name, dev_t *devno)
{
	char path[PATH_MAX];
	int r;
	struct stat st;

	r = snprintf(path, sizeof(path), DMDIR "%s", name);
	if (r < 0 || (size_t)r >= sizeof(path))
		return 1;

	if (stat(path, &st) || !S_ISBLK(st.st_mode))
		return 1;

	*devno = st.st_rdev;

	return 0;
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

	if (snprintf(path, sizeof(path), "/sys/dev/block/%d:%d/%s", major, minor, attr) < 0)
		return 0;

	return _read_uint64(path, value);
}

int t_device_size_by_devno(dev_t devno, uint64_t *retval)
{
	if (!_sysfs_get_uint64(major(devno), minor(devno), retval, "size"))
		return 1;

	*retval *= 512;
	return 0;
}
