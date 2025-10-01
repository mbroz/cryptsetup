// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup library LUKS2 API check functions
 *
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 * Copyright (C) 2016-2025 Ondrej Kozina
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <sys/types.h>
#if KERNEL_KEYRING
#include <linux/keyctl.h>
#include <sys/syscall.h>
#ifndef HAVE_KEY_SERIAL_T
#define HAVE_KEY_SERIAL_T
#include <stdint.h>
typedef int32_t key_serial_t;
#endif
#endif

#include "api_test.h"
#include "luks1/luks.h"
#include "libcryptsetup.h"

#define DEVICE_1_UUID "28632274-8c8a-493f-835b-da802e1c576b"
#define DEVICE_EMPTY_name "crypt_zero"
#define DEVICE_EMPTY DMDIR DEVICE_EMPTY_name
#define DEVICE_ERROR_name "crypt_error"
#define DEVICE_ERROR DMDIR DEVICE_ERROR_name

#define CDEVICE_1 "ctest1"
#define CDEVICE_2 "ctest2"
#define CDEVICE_WRONG "O_o"
#define H_DEVICE "head_ok"
#define H_DEVICE_WRONG "head_wr"
#define L_DEVICE_1S "luks_onesec"
#define L_DEVICE_0S "luks_zerosec"
#define L_DEVICE_WRONG "luks_wr"
#define L_DEVICE_OK "luks_ok"
#define L_PLACEHOLDER "bdev_reference_placeholder"
#define REQS_LUKS2_HEADER "luks2_header_requirements"
#define NO_REQS_LUKS2_HEADER "luks2_header_requirements_free"
#define BACKUP_FILE "csetup_backup_file"
#define IMAGE1 "compatimage2.img"
#define EMPTY_HEADER "empty.hdr"
#define IMAGE_EMPTY "empty.img"
#define IMAGE_EMPTY_SMALL "empty_small.img"
#define IMAGE_EMPTY_SMALL_2 "empty_small2.img"
#define IMAGE_PV_LUKS2_SEC "blkid-luks2-pv.img"

#define KEYFILE1 "key1.file"
#define KEY1 "compatkey"

#define KEYFILE2 "key2.file"
#define KEY2 "0123456789abcdef"

#define PASSPHRASE "blablabl"
#define PASSPHRASE1 "albalbal"

#define DEVICE_TEST_UUID "12345678-1234-1234-1234-123456789abc"

#define DEVICE_WRONG "/dev/Ooo_"
#define DEVICE_CHAR "/dev/zero"
#define THE_LFILE_TEMPLATE "cryptsetup-tstlp.XXXXXX"

#define TEST_KEYRING_USER "cs_apitest2_keyring_in_user"
#define TEST_KEYRING_USER_NAME "%keyring:" TEST_KEYRING_USER
#define TEST_KEYRING_SESSION "cs_apitest2_keyring_in_session"
#define TEST_KEYRING_SESSION_NAME "%keyring:" TEST_KEYRING_SESSION
#define TEST_KEY_VK_USER "api_test_user_vk1"
#define TEST_KEY_VK_USER_NAME "\%user:" TEST_KEY_VK_USER
#define TEST_KEY_VK_LOGON "cs_api_test_prefix:api_test_logon_vk1"
#define TEST_KEY_VK_LOGON_NAME "\%logon:" TEST_KEY_VK_LOGON
#define TEST_KEY_VK_USER2 "api_test_user_vk2"
#define TEST_KEY_VK_USER2_NAME "\%user:" TEST_KEY_VK_USER2
#define TEST_KEY_VK_LOGON2 "cs_api_test_prefix:api_test_logon_vk2"
#define TEST_KEY_VK_LOGON2_NAME "\%logon:" TEST_KEY_VK_LOGON

#define KEY_DESC_TEST0 "cs_token_test:test_key0"
#define KEY_DESC_TEST1 "cs_token_test:test_key1"

#define CONV_DIR "conversion_imgs"
#define CONV_L1_128 "l1_128b"
#define CONV_L1_256 "l1_256b"
#define CONV_L1_512 "l1_512b"
#define CONV_L2_128 "l2_128b"
#define CONV_L2_128_FULL "l2_128b_full"
#define CONV_L2_256 "l2_256b"
#define CONV_L2_256_FULL "l2_256b_full"
#define CONV_L2_512 "l2_512b"
#define CONV_L2_512_FULL "l2_512b_full"
#define CONV_L1_128_DET "l1_128b_det"
#define CONV_L1_256_DET "l1_256b_det"
#define CONV_L1_512_DET "l1_512b_det"
#define CONV_L2_128_DET "l2_128b_det"
#define CONV_L2_128_DET_FULL "l2_128b_det_full"
#define CONV_L2_256_DET "l2_256b_det"
#define CONV_L2_256_DET_FULL "l2_256b_det_full"
#define CONV_L2_512_DET "l2_512b_det"
#define CONV_L2_512_DET_FULL "l2_512b_det_full"
#define CONV_L1_256_LEGACY "l1_256b_legacy_offset"
#define CONV_L1_256_UNMOVABLE "l1_256b_unmovable"
#define PASS0 "aaablabl"
#define PASS1 "hhhblabl"
#define PASS2 "cccblabl"
#define PASS3 "dddblabl"
#define PASS4 "eeeblabl"
#define PASS5 "fffblabl"
#define PASS6 "gggblabl"
#define PASS7 "bbbblabl"
#define PASS8 "iiiblabl"

static int _fips_mode = 0;

static char *DEVICE_1 = NULL;
static char *DEVICE_2 = NULL;
static char *DEVICE_3 = NULL;
static char *DEVICE_4 = NULL;
static char *DEVICE_5 = NULL;
static char *DEVICE_6 = NULL;

static char *tmp_file_1 = NULL;
static char *test_loop_file = NULL;

unsigned int test_progress_steps;

struct crypt_device *cd = NULL, *cd2 = NULL;

static const char *default_luks1_hash = NULL;
static uint32_t default_luks1_iter_time = 0;

static const char *default_luks2_pbkdf = NULL;
static uint32_t default_luks2_iter_time = 0;
static uint32_t default_luks2_memory_kb = 0;
static uint32_t default_luks2_parallel_threads = 0;

#if KERNEL_KEYRING
static char keyring_in_user_str_id[32] = {0};
#endif

static struct crypt_pbkdf_type min_pbkdf2 = {
	.type = "pbkdf2",
	.iterations = 1000,
	.flags = CRYPT_PBKDF_NO_BENCHMARK
}, min_argon2 = {
	.type = "argon2id",
	.iterations = 4,
	.max_memory_kb = 32,
	.parallel_threads = 1,
	.flags = CRYPT_PBKDF_NO_BENCHMARK
};

// Helpers

static unsigned cpus_online(void)
{
	static long r = -1;

	if (r < 0) {
		r = sysconf(_SC_NPROCESSORS_ONLN);
		if (r < 0)
			r = 1;
	}

	return r;
}

static uint32_t adjusted_pbkdf_memory(void)
{
	long pagesize = sysconf(_SC_PAGESIZE);
	long pages = sysconf(_SC_PHYS_PAGES);
	uint64_t memory_kb;

	if (pagesize <= 0 || pages <= 0)
		return default_luks2_memory_kb;

	memory_kb = pagesize / 1024 * pages / 2;

	if (memory_kb < default_luks2_memory_kb)
		return (uint32_t)memory_kb;

	return default_luks2_memory_kb;
}

static unsigned _min(unsigned a, unsigned b)
{
	return a < b ? a : b;
}

static int get_luks2_offsets(int metadata_device,
			    unsigned int alignpayload_sec,
			    unsigned int sector_size,
			    uint64_t *r_header_size,
			    uint64_t *r_payload_offset)
{
	struct crypt_device *_cd = NULL;
	static uint64_t default_header_size = 0;

	if (r_header_size)
		*r_header_size = 0;
	if (r_payload_offset)
		*r_payload_offset = 0;

	if (!default_header_size) {
		if (crypt_init(&_cd, THE_LOOP_DEV))
			return -EINVAL;
		if (crypt_format(_cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, NULL)) {
			crypt_free(_cd);
			return -EINVAL;
		}

		default_header_size = crypt_get_data_offset(_cd);

		crypt_free(_cd);
	}

	if (!sector_size)
		sector_size = 512; /* default? */

	if ((sector_size % 512) && (sector_size % 4096))
		return -1;

	if (r_payload_offset) {
		if (metadata_device)
			*r_payload_offset = (uint64_t)alignpayload_sec * sector_size;
		else
			*r_payload_offset = DIV_ROUND_UP_MODULO(default_header_size * 512, (alignpayload_sec ?: 1) * sector_size);

		*r_payload_offset /= sector_size;
	}

	if (r_header_size)
		*r_header_size = default_header_size;

	return 0;
}

static bool get_luks_pbkdf_defaults(void)
{
	const struct crypt_pbkdf_type *pbkdf_defaults = crypt_get_pbkdf_default(CRYPT_LUKS1);

	if (!pbkdf_defaults)
		return false;

	default_luks1_hash = pbkdf_defaults->hash;
	default_luks1_iter_time = pbkdf_defaults->time_ms;

	pbkdf_defaults = crypt_get_pbkdf_default(CRYPT_LUKS2);
	if (!pbkdf_defaults)
		return false;

	default_luks2_pbkdf = pbkdf_defaults->type;
	default_luks2_iter_time = pbkdf_defaults->time_ms;
	default_luks2_memory_kb = pbkdf_defaults->max_memory_kb;
	default_luks2_parallel_threads = pbkdf_defaults->parallel_threads;

	return true;
}

static void _remove_keyfiles(void)
{
	remove(KEYFILE1);
	remove(KEYFILE2);
}

#if HAVE_DECL_DM_TASK_RETRY_REMOVE
#define DM_RETRY "--retry "
#else
#define DM_RETRY ""
#endif

#define DM_NOSTDERR " 2>/dev/null"

static void _cleanup_dmdevices(void)
{
	struct stat st;

	if (!stat(DMDIR L_PLACEHOLDER, &st))
		_system("dmsetup remove " DM_RETRY L_PLACEHOLDER DM_NOSTDERR, 0);

	if (!stat(DMDIR H_DEVICE, &st))
		_system("dmsetup remove " DM_RETRY H_DEVICE DM_NOSTDERR, 0);

	if (!stat(DMDIR H_DEVICE_WRONG, &st))
		_system("dmsetup remove " DM_RETRY H_DEVICE_WRONG DM_NOSTDERR, 0);

	if (!stat(DMDIR L_DEVICE_0S, &st))
		_system("dmsetup remove " DM_RETRY L_DEVICE_0S DM_NOSTDERR, 0);

	if (!stat(DMDIR L_DEVICE_1S, &st))
		_system("dmsetup remove " DM_RETRY L_DEVICE_1S DM_NOSTDERR, 0);

	if (!stat(DMDIR L_DEVICE_WRONG, &st))
		_system("dmsetup remove " DM_RETRY L_DEVICE_WRONG DM_NOSTDERR, 0);

	if (!stat(DMDIR L_DEVICE_OK, &st))
		_system("dmsetup remove " DM_RETRY L_DEVICE_OK DM_NOSTDERR, 0);

	t_dev_offset = 0;
}

static int _setup(void)
{
	int fd, ro = 0;
	char cmd[128];

	test_loop_file = strdup(THE_LFILE_TEMPLATE);
	if (!test_loop_file)
		return 1;

	if ((fd=mkstemp(test_loop_file)) == -1) {
		printf("cannot create temporary file with template %s\n", test_loop_file);
		return 1;
	}
	close(fd);
	if (snprintf(cmd, sizeof(cmd), "dd if=/dev/zero of=%s bs=%d count=%d 2>/dev/null",
	    test_loop_file, TST_SECTOR_SIZE, TST_LOOP_FILE_SIZE) < 0)
		return 1;
	if (_system(cmd, 1))
		return 1;

	fd = loop_attach(&THE_LOOP_DEV, test_loop_file, 0, 0, &ro);
	close(fd);

	tmp_file_1 = strdup(THE_LFILE_TEMPLATE);
	if (!tmp_file_1)
		return 1;

	if ((fd=mkstemp(tmp_file_1)) == -1) {
		printf("cannot create temporary file with template %s\n", tmp_file_1);
		return 1;
	}
	close(fd);
	if (snprintf(cmd, sizeof(cmd), "dd if=/dev/zero of=%s bs=%d count=%d 2>/dev/null",
	    tmp_file_1, TST_SECTOR_SIZE, 10) < 0)
		return 1;
	if (_system(cmd, 1))
		return 1;

	_system("dmsetup create " DEVICE_EMPTY_name " --table \"0 10000 zero\"", 1);
	_system("dmsetup create " DEVICE_ERROR_name " --table \"0 10000 error\"", 1);

	if (t_set_readahead(DEVICE_ERROR, 0))
		printf("cannot set read ahead on device %s\n", DEVICE_ERROR);

	_system(" [ ! -e " IMAGE1 " ] && xz -dk " IMAGE1 ".xz", 1);
	fd = loop_attach(&DEVICE_1, IMAGE1, 0, 0, &ro);
	close(fd);

	_system("dd if=/dev/zero of=" IMAGE_EMPTY " bs=1M count=32 2>/dev/null", 1);
	fd = loop_attach(&DEVICE_2, IMAGE_EMPTY, 0, 0, &ro);
	close(fd);

	_system("dd if=/dev/zero of=" IMAGE_EMPTY_SMALL " bs=1M count=7 2>/dev/null", 1);

	_system("dd if=/dev/zero of=" IMAGE_EMPTY_SMALL_2 " bs=512 count=2050 2>/dev/null", 1);

	_system("dd if=/dev/zero of=" EMPTY_HEADER " bs=4K count=1 2>/dev/null", 1);

	_system(" [ ! -e " NO_REQS_LUKS2_HEADER " ] && tar xJf " REQS_LUKS2_HEADER ".tar.xz", 1);
	fd = loop_attach(&DEVICE_4, NO_REQS_LUKS2_HEADER, 0, 0, &ro);
	close(fd);

	_system(" [ ! -e " REQS_LUKS2_HEADER " ] && tar xJf " REQS_LUKS2_HEADER ".tar.xz", 1);
	fd = loop_attach(&DEVICE_5, REQS_LUKS2_HEADER, 0, 0, &ro);
	close(fd);

	_system(" [ ! -e " IMAGE_PV_LUKS2_SEC " ] && xz -dk " IMAGE_PV_LUKS2_SEC ".xz", 1);
	_system(" [ ! -e " IMAGE_PV_LUKS2_SEC ".bcp ] && cp " IMAGE_PV_LUKS2_SEC " " IMAGE_PV_LUKS2_SEC ".bcp", 1);
	fd = loop_attach(&DEVICE_6, IMAGE_PV_LUKS2_SEC, 0, 0, &ro);
	close(fd);

	_system(" [ ! -d " CONV_DIR " ] && tar xJf " CONV_DIR ".tar.xz 2>/dev/null", 1);

	if (_system("modprobe dm-crypt >/dev/null 2>&1", 1))
		return 1;

	if (t_dm_check_versions())
		return 1;

	_system("rmmod dm-crypt >/dev/null 2>&1", 0);

	_fips_mode = fips_mode();
	if (_debug)
		printf("FIPS MODE: %d\n", _fips_mode);

	/* Use default log callback */
	crypt_set_log_callback(NULL, &global_log_callback, NULL);

	if (!get_luks_pbkdf_defaults())
		return 1;

	min_pbkdf2.hash = min_argon2.hash = default_luks1_hash;

	return 0;
}

static int set_fast_pbkdf(struct crypt_device *_cd)
{
	const struct crypt_pbkdf_type *pbkdf = &min_argon2;

	/* Cannot use Argon2 in FIPS */
	if (_fips_mode)
		pbkdf = &min_pbkdf2;

	return crypt_set_pbkdf_type(_cd, pbkdf);
}

#if KERNEL_KEYRING
static key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring)
{
	return syscall(__NR_add_key, type, description, payload, plen, keyring);
}

static key_serial_t keyctl_unlink(key_serial_t key, key_serial_t keyring)
{
	return syscall(__NR_keyctl, KEYCTL_UNLINK, key, keyring);
}

static key_serial_t keyctl_link(key_serial_t key, key_serial_t keyring)
{
	return syscall(__NR_keyctl, KEYCTL_LINK, key, keyring);
}

static long keyctl_update(key_serial_t id, const void *payload, size_t plen)
{
	return syscall(__NR_keyctl, KEYCTL_UPDATE, id, payload, plen);
}

static long keyctl_read(key_serial_t id, char *buffer, size_t buflen)
{
	return syscall(__NR_keyctl, KEYCTL_READ, id, buffer, buflen);
}

static key_serial_t request_key(const char *type,
	const char *description,
	const char *callout_info,
	key_serial_t keyring)
{
	return syscall(__NR_request_key, type, description, callout_info, keyring);
}

/* key handle permissions mask */
typedef uint32_t key_perm_t;
#define KEY_POS_ALL	0x3f000000
#define KEY_USR_ALL	0x003f0000

static key_serial_t add_key_set_perm(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring, key_perm_t perm)
{
	long l;
	key_serial_t kid = syscall(__NR_add_key, type, description, payload, plen, KEY_SPEC_THREAD_KEYRING);

	if (kid < 0)
		return kid;

	l = syscall(__NR_keyctl, KEYCTL_SETPERM, kid, perm);
	if (l == 0)
		l = syscall(__NR_keyctl, KEYCTL_LINK, kid, keyring);

	syscall(__NR_keyctl, KEYCTL_UNLINK, kid, KEY_SPEC_THREAD_KEYRING);

	return l == 0 ? kid : -EINVAL;
}

static key_serial_t _kernel_key_by_segment_and_type(struct crypt_device *_cd, int segment,
						    const char* type)
{
	char key_description[1024];

	if (snprintf(key_description, sizeof(key_description), "cryptsetup:%s-d%u", crypt_get_uuid(_cd), segment) < 1)
		return -1;

	return request_key(type, key_description, NULL, 0);
}

static key_serial_t _kernel_key_by_segment(struct crypt_device *_cd, int segment)
{
	return _kernel_key_by_segment_and_type(_cd, segment, "logon");
}

static int _volume_key_in_keyring(struct crypt_device *_cd, int segment)
{
	return _kernel_key_by_segment(_cd, segment) >= 0 ? 0 : -1;
}

static int _drop_keyring_key_from_keyring_name(const char *key_description, key_serial_t keyring, const char* type)
{
	//key_serial_t kid = request_key(type, key_description, NULL, keyring);
	key_serial_t kid = request_key(type, key_description, NULL, 0);

	if (kid < 0)
		return -2;

	return keyctl_unlink(kid, keyring);
}

static int _drop_keyring_key_from_keyring_type(struct crypt_device *_cd, int segment,
					       key_serial_t keyring, const char* type)
{
	key_serial_t kid = _kernel_key_by_segment_and_type(_cd, segment, type);

	if (kid < 0)
		return -1;

	return keyctl_unlink(kid, keyring);
}

static int _drop_keyring_key(struct crypt_device *_cd, int segment)
{
	return _drop_keyring_key_from_keyring_type(_cd, segment, KEY_SPEC_THREAD_KEYRING, "logon");
}
#endif

static void _cleanup(void)
{
	struct stat st;

	CRYPT_FREE(cd);
	CRYPT_FREE(cd2);

	//_system("udevadm settle", 0);

	if (!stat(DMDIR CDEVICE_1, &st))
		_system("dmsetup remove " DM_RETRY CDEVICE_1 DM_NOSTDERR, 0);

	if (!stat(DMDIR CDEVICE_2, &st))
		_system("dmsetup remove " DM_RETRY CDEVICE_2 DM_NOSTDERR, 0);

	if (!stat(DEVICE_EMPTY, &st))
		_system("dmsetup remove " DM_RETRY DEVICE_EMPTY_name DM_NOSTDERR, 0);

	if (!stat(DEVICE_ERROR, &st))
		_system("dmsetup remove " DM_RETRY DEVICE_ERROR_name DM_NOSTDERR, 0);

	_cleanup_dmdevices();

	if (loop_device(THE_LOOP_DEV))
		loop_detach(THE_LOOP_DEV);

	if (loop_device(DEVICE_1))
		loop_detach(DEVICE_1);

	if (loop_device(DEVICE_2))
		loop_detach(DEVICE_2);

	if (loop_device(DEVICE_3))
		loop_detach(DEVICE_3);

	if (loop_device(DEVICE_4))
		loop_detach(DEVICE_4);

	if (loop_device(DEVICE_5))
		loop_detach(DEVICE_5);

	if (loop_device(DEVICE_6))
		loop_detach(DEVICE_6);

	_system("rm -f " IMAGE_EMPTY, 0);
	_system("rm -f " IMAGE1, 0);
	_system("rm -rf " CONV_DIR, 0);
	_system("rm -f " EMPTY_HEADER, 0);

	if (test_loop_file)
		remove(test_loop_file);
	if (tmp_file_1)
		remove(tmp_file_1);

	remove(REQS_LUKS2_HEADER);
	remove(NO_REQS_LUKS2_HEADER);
	remove(BACKUP_FILE);
	remove(IMAGE_PV_LUKS2_SEC);
	remove(IMAGE_PV_LUKS2_SEC ".bcp");
	remove(IMAGE_EMPTY_SMALL);
	remove(IMAGE_EMPTY_SMALL_2);

	_remove_keyfiles();

	free(tmp_file_1);
	free(test_loop_file);
	free(THE_LOOP_DEV);
	free(DEVICE_1);
	free(DEVICE_2);
	free(DEVICE_3);
	free(DEVICE_4);
	free(DEVICE_5);
	free(DEVICE_6);

#if KERNEL_KEYRING
	char *end;
	key_serial_t krid;

	if (keyring_in_user_str_id[0] != '\0') {
		krid = strtoul(keyring_in_user_str_id, &end, 0);
		if (!*end)
			(void)keyctl_unlink(krid, KEY_SPEC_USER_KEYRING);
	}

	krid = request_key("keyring", TEST_KEYRING_SESSION, NULL, 0);
	if (krid > 0)
		(void)keyctl_unlink(krid, KEY_SPEC_SESSION_KEYRING);
#endif
}

static int test_open(struct crypt_device *_cd __attribute__((unused)),
	int token __attribute__((unused)),
	char **buffer,
	size_t *buffer_len,
	void *usrptr)
{
	const char *str = (const char *)usrptr;

	*buffer = strdup(str);
	if (!*buffer)
		return -ENOMEM;
	*buffer_len = strlen(*buffer);

	return 0;
}

static int test_open_pass(struct crypt_device *_cd __attribute__((unused)),
	int token __attribute__((unused)),
	char **buffer,
	size_t *buffer_len,
	void *usrptr __attribute__((unused)))
{
	*buffer = strdup(PASSPHRASE);
	if (!*buffer)
		return -ENOMEM;
	*buffer_len = strlen(*buffer);

	return 0;
}

static int test_open_pass1(struct crypt_device *_cd __attribute__((unused)),
	int token __attribute__((unused)),
	char **buffer,
	size_t *buffer_len,
	void *usrptr __attribute__((unused)))
{
	*buffer = strdup(PASSPHRASE1);
	if (!*buffer)
		return -ENOMEM;
	*buffer_len = strlen(*buffer);

	return 0;
}

static int test_validate(struct crypt_device *_cd __attribute__((unused)), const char *json)
{
	return (strstr(json, "magic_string") == NULL);
}

static void UseLuks2Device(void)
{
	char key[128];
	size_t key_size;

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	OK_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0), "already open");
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_deactivate(cd, CDEVICE_1), "no such device");

	if (!_fips_mode) {
		/* keyslot 0 is PBKDF2, keyslot 1 is Argon2id */
		OK_(crypt_activate_by_passphrase(cd, NULL, 0, KEY1, strlen(KEY1), 0));
		EQ_(crypt_activate_by_passphrase(cd, NULL, 1, KEY2, strlen(KEY2), 0), 1);
		EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, KEY2, strlen(KEY2), 0), 1);
		FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, KEY2, strlen(KEY2), 0), "already open");
		GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
		OK_(crypt_deactivate(cd, CDEVICE_1));
		FAIL_(crypt_deactivate(cd, CDEVICE_1), "no such device");
	}

#if KERNEL_KEYRING
	// repeat previous tests and check kernel keyring is released when not needed
	if (t_dm_crypt_keyring_support()) {
		OK_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
		FAIL_(_drop_keyring_key(cd, 0), "");
		OK_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), CRYPT_ACTIVATE_KEYRING_KEY));
		OK_(_drop_keyring_key(cd, 0));
		OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
		OK_(_drop_keyring_key(cd, 0));
		FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0), "already open");
		FAIL_(_volume_key_in_keyring(cd, 0), "");
		OK_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
		OK_(crypt_deactivate(cd, CDEVICE_1));
		FAIL_(_volume_key_in_keyring(cd, 0), "");

		if (!_fips_mode) {
			/* keyslot 0 is PBKDF2, keyslot 1 is Argon2id */
			EQ_(crypt_activate_by_passphrase(cd, NULL, 1, KEY2, strlen(KEY2), 0), 1);
			FAIL_(_drop_keyring_key(cd, 0), "");
			EQ_(crypt_activate_by_passphrase(cd, NULL, 1, KEY2, strlen(KEY2), CRYPT_ACTIVATE_KEYRING_KEY), 1);
			OK_(_drop_keyring_key(cd, 0));
			EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, KEY2, strlen(KEY2), 0), 1);
			OK_(_drop_keyring_key(cd, 0));
			FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, KEY2, strlen(KEY2), 0), "already open");
			FAIL_(_volume_key_in_keyring(cd, 0), "");
			EQ_(crypt_activate_by_passphrase(cd, NULL, 1, KEY2, strlen(KEY2), 0), 1);
			OK_(crypt_deactivate(cd, CDEVICE_1));
			FAIL_(_volume_key_in_keyring(cd, 0), "");
		}
	}
#endif

	key_size = 16;
	OK_(strcmp("aes", crypt_get_cipher(cd)));
	OK_(strcmp("cbc-essiv:sha256", crypt_get_cipher_mode(cd)));
	OK_(strcmp(DEVICE_1_UUID, crypt_get_uuid(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(8192, crypt_get_data_offset(cd));

	EQ_(0, crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size, KEY1, strlen(KEY1)));
	OK_(crypt_volume_key_verify(cd, key, key_size));
	OK_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	key[1] = ~key[1];
	FAIL_(crypt_volume_key_verify(cd, key, key_size), "key mismatch");
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "key mismatch");

	CRYPT_FREE(cd);
}

static void SuspendDevice(void)
{
	struct crypt_active_device cad;
	char key[128];
	size_t key_size;
	int suspend_status;
	uint64_t r_payload_offset;

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));

	suspend_status = crypt_suspend(cd, CDEVICE_1);
	if (suspend_status == -ENOTSUP) {
		printf("WARNING: Suspend/Resume not supported, skipping test.\n");
		OK_(crypt_deactivate(cd, CDEVICE_1));
		CRYPT_FREE(cd);
		return;
	}

	OK_(suspend_status);
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(CRYPT_ACTIVATE_SUSPENDED, cad.flags & CRYPT_ACTIVATE_SUSPENDED);
#if KERNEL_KEYRING
	FAIL_(_volume_key_in_keyring(cd, 0), "");
#endif
	FAIL_(crypt_suspend(cd, CDEVICE_1), "already suspended");

	FAIL_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)-1), "wrong key");
	OK_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)));
	FAIL_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)), "not suspended");

	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(0, cad.flags & CRYPT_ACTIVATE_SUSPENDED);

	OK_(prepare_keyfile(KEYFILE1, KEY1, strlen(KEY1)));
	OK_(crypt_suspend(cd, CDEVICE_1));
	FAIL_(crypt_resume_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1 "blah", 0), "wrong keyfile");
	FAIL_(crypt_resume_by_keyfile_offset(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 1, 0), "wrong key");
	OK_(crypt_resume_by_keyfile_offset(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0, 0));
	FAIL_(crypt_resume_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0), "not suspended");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	/* create LUKS device with detached header */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DEVICE_2));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
	CRYPT_FREE(cd);

	/* Should be able to suspend but not resume if not header specified */
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	OK_(crypt_suspend(cd, CDEVICE_1));
	FAIL_(crypt_suspend(cd, CDEVICE_1), "already suspended");
	FAIL_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)-1), "no header");
	CRYPT_FREE(cd);

	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, DEVICE_1));
	OK_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)));

	/* Resume by volume key */
	OK_(crypt_suspend(cd, CDEVICE_1));
	key_size = sizeof(key);
	memset(key, 0, key_size);
	FAIL_(crypt_resume_by_volume_key(cd, CDEVICE_1, key, key_size), "wrong key");
	OK_(crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size, KEY1, strlen(KEY1)));
	OK_(crypt_resume_by_volume_key(cd, CDEVICE_1, key, key_size));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1));

	/* Resume device with cipher_null */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, "cipher_null", "ecb", NULL, key, key_size, NULL));
	EQ_(0, crypt_keyslot_add_by_volume_key(cd, 0, key, key_size, PASSPHRASE, strlen(PASSPHRASE)));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	OK_(crypt_suspend(cd, CDEVICE_1));
	OK_(crypt_resume_by_volume_key(cd, CDEVICE_1, key, key_size));
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(0, cad.flags & CRYPT_ACTIVATE_SUSPENDED);
	OK_(crypt_suspend(cd, CDEVICE_1));
	OK_(crypt_resume_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE)));
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(0, cad.flags & CRYPT_ACTIVATE_SUSPENDED);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	_remove_keyfiles();
	_cleanup_dmdevices();
}

static void AddDeviceLuks2(void)
{
	enum { OFFSET_1M = 2048 , OFFSET_2M = 4096, OFFSET_4M = 8192, OFFSET_8M = 16384 };
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha256",
		.parallel_threads = 4,
		.max_memory_kb = 1024,
		.time_ms = 1
	}, pbkdf_tmp;
	struct crypt_params_luks2 params = {
		.pbkdf = &pbkdf,
		.data_device = DEVICE_2,
		.sector_size = 512
	};
	char key[128], key2[128], key3[128];

	const char *tmp_buf, *passphrase = PASSPHRASE, *passphrase2 = "nsdkFI&Y#.sd";
	const char *vk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	const char *vk_hex2 = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1e";
	size_t key_size = strlen(vk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset, r_header_size, r_size_1;

	/* Cannot use Argon2 in FIPS */
	if (_fips_mode) {
		pbkdf.type = CRYPT_KDF_PBKDF2;
		pbkdf.parallel_threads = 0;
		pbkdf.max_memory_kb = 0;
	}

	OK_(crypt_decode_key(key, vk_hex, key_size));
	OK_(crypt_decode_key(key3, vk_hex2, key_size));

	// init test devices
	OK_(get_luks2_offsets(0, 0, 0, &r_header_size, &r_payload_offset));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, r_header_size - 1));


	// format
	OK_(crypt_init(&cd, DMDIR H_DEVICE_WRONG));
	params.data_alignment = 0;
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Not enough space for keyslots material");
	CRYPT_FREE(cd);

	// test payload_offset = 0 for encrypted device with external header device
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_get_data_offset(cd), 0);
	CRYPT_FREE(cd);

	params.data_alignment = 0;
	params.data_device = NULL;

	// test payload_offset = 0. format() should look up alignment offset from device topology
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(!(crypt_get_data_offset(cd) > 0));
	CRYPT_FREE(cd);

	// set_data_offset has priority, alignment must be 0 or must be compatible
	params.data_alignment = 0;
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_set_data_offset(cd, OFFSET_8M));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_get_data_offset(cd), OFFSET_8M);
	CRYPT_FREE(cd);

	// Load gets the value from metadata
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(crypt_set_data_offset(cd, OFFSET_2M));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), OFFSET_8M);
	CRYPT_FREE(cd);

	params.data_alignment = OFFSET_4M;
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(set_fast_pbkdf(cd));
	FAIL_(crypt_set_data_offset(cd, OFFSET_2M + 1), "Not aligned to 4096"); // must be aligned to 4k
	OK_(crypt_set_data_offset(cd, OFFSET_2M));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Alignment not compatible");
	OK_(crypt_set_data_offset(cd, OFFSET_4M));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_get_data_offset(cd), OFFSET_4M);
	CRYPT_FREE(cd);

	/*
	 * test limit values for backing device size
	 */
	params.data_alignment = OFFSET_4M;
	OK_(get_luks2_offsets(0, params.data_alignment, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_0S, r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));
	OK_(create_dmdevice_over_loop(L_DEVICE_WRONG, r_payload_offset - 1));

	// 1 sector less than required
	OK_(crypt_init(&cd, DMDIR L_DEVICE_WRONG));
	OK_(set_fast_pbkdf(cd));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params),	"Device too small");
	CRYPT_FREE(cd);

	// 0 sectors for encrypted area
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Encrypted area too small");
	CRYPT_FREE(cd);

	// 1 sector for encrypted area
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_get_data_offset(cd), r_payload_offset);
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(t_device_size(DMDIR CDEVICE_1, &r_size_1));
	EQ_(r_size_1, TST_SECTOR_SIZE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	// restrict format only to empty context
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Context is already formatted");
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL), "Context is already formatted");
	// change data device to wrong one
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_0S));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Device too small");
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_1S));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	params.data_alignment = 0;
	params.data_device = DEVICE_2;

	// generate keyslot material at the end of luks header
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, passphrase, strlen(passphrase)), 7);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 7, passphrase, strlen(passphrase) ,0), 7);

	OK_(crypt_keyslot_get_pbkdf(cd, 7, &pbkdf_tmp));
	OK_(strcmp(pbkdf_tmp.type, pbkdf.type));
	if (!_fips_mode) {
		NULL_(pbkdf_tmp.hash);
		OK_(!(pbkdf_tmp.max_memory_kb >= 32));
		OK_(!(pbkdf_tmp.parallel_threads >= 1));
	} else
		OK_(strcmp(pbkdf_tmp.hash, pbkdf.hash));
	OK_(!(pbkdf_tmp.iterations >= 4));
	EQ_(0, pbkdf_tmp.time_ms); /* not usable in per-keyslot call */

	CRYPT_FREE(cd);
	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, DMDIR H_DEVICE));
	OK_(set_fast_pbkdf(cd));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Context is already formatted");
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	CRYPT_FREE(cd);
	// check active status without header
	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, NULL));
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	NULL_(crypt_get_type(cd));
	OK_(strcmp(cipher, crypt_get_cipher(cd)));
	OK_(strcmp(cipher_mode, crypt_get_cipher_mode(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	params.data_alignment = OFFSET_1M;
	params.data_device = NULL;

	// test uuid mismatch and _init_by_name_and_header
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(0, crypt_header_is_detached(cd));
	CRYPT_FREE(cd);
	params.data_alignment = 0;
	params.data_device = DEVICE_2;
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	CRYPT_FREE(cd);
	// there we've got uuid mismatch
	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, DMDIR H_DEVICE));
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	NULL_(crypt_get_type(cd));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Device is active");
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, key, key_size, 0), "Device is active");
	EQ_(crypt_status(cd, CDEVICE_2), CRYPT_INACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_header_is_detached(cd), 1);
	CRYPT_FREE(cd);

	params.data_device = NULL;

	OK_(crypt_init(&cd, DEVICE_2));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));

	// even with no keyslots defined it can be activated by volume key
	OK_(crypt_volume_key_verify(cd, key, key_size));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_2, key, key_size, 0));
	GE_(crypt_status(cd, CDEVICE_2), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_2));

	// now with keyslot
	EQ_(7, crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, passphrase, strlen(passphrase)));
	EQ_(CRYPT_SLOT_ACTIVE_LAST, crypt_keyslot_status(cd, 7));
	EQ_(7, crypt_activate_by_passphrase(cd, CDEVICE_2, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0));
	GE_(crypt_status(cd, CDEVICE_2), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_2));

	EQ_(1, crypt_keyslot_add_by_volume_key(cd, 1, key, key_size, KEY1, strlen(KEY1)));
	OK_(prepare_keyfile(KEYFILE1, KEY1, strlen(KEY1)));
	OK_(prepare_keyfile(KEYFILE2, KEY2, strlen(KEY2)));
	EQ_(2, crypt_keyslot_add_by_keyfile(cd, 2, KEYFILE1, 0, KEYFILE2, 0));
	FAIL_(crypt_keyslot_add_by_keyfile_offset(cd, 3, KEYFILE1, 0, 1, KEYFILE2, 0, 1), "wrong key");
	EQ_(3, crypt_keyslot_add_by_keyfile_offset(cd, 3, KEYFILE1, 0, 0, KEYFILE2, 0, 1));
	EQ_(4, crypt_keyslot_add_by_keyfile_offset(cd, 4, KEYFILE2, 0, 1, KEYFILE1, 0, 1));
	FAIL_(crypt_activate_by_keyfile(cd, CDEVICE_2, CRYPT_ANY_SLOT, KEYFILE2, strlen(KEY2)-1, 0), "key mismatch");
	EQ_(2, crypt_activate_by_keyfile(cd, NULL, CRYPT_ANY_SLOT, KEYFILE2, 0, 0));
	EQ_(3, crypt_activate_by_keyfile_offset(cd, NULL, CRYPT_ANY_SLOT, KEYFILE2, 0, 1, 0));
	EQ_(4, crypt_activate_by_keyfile_offset(cd, NULL, CRYPT_ANY_SLOT, KEYFILE1, 0, 1, 0));
	FAIL_(crypt_activate_by_keyfile_offset(cd, CDEVICE_2, CRYPT_ANY_SLOT, KEYFILE2, strlen(KEY2), 2, 0), "not enough data");
	FAIL_(crypt_activate_by_keyfile_offset(cd, CDEVICE_2, CRYPT_ANY_SLOT, KEYFILE2, 0, strlen(KEY2) + 1, 0), "cannot seek");
	FAIL_(crypt_activate_by_keyfile_offset(cd, CDEVICE_2, CRYPT_ANY_SLOT, KEYFILE2, 0, 2, 0), "wrong key");
	EQ_(2, crypt_activate_by_keyfile(cd, CDEVICE_2, CRYPT_ANY_SLOT, KEYFILE2, 0, 0));
	OK_(crypt_keyslot_destroy(cd, 1));
	OK_(crypt_keyslot_destroy(cd, 2));
	OK_(crypt_keyslot_destroy(cd, 3));
	OK_(crypt_keyslot_destroy(cd, 4));
	OK_(crypt_deactivate(cd, CDEVICE_2));
	_remove_keyfiles();

	FAIL_(crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, passphrase, strlen(passphrase)), "slot used");
	key[1] = ~key[1];
	FAIL_(crypt_keyslot_add_by_volume_key(cd, 6, key, key_size, passphrase, strlen(passphrase)), "key mismatch");
	key[1] = ~key[1];
	EQ_(6, crypt_keyslot_add_by_volume_key(cd, 6, key, key_size, passphrase2, strlen(passphrase2)));
	EQ_(CRYPT_SLOT_ACTIVE, crypt_keyslot_status(cd, 6));

	FAIL_(crypt_keyslot_destroy(cd, 8), "invalid keyslot");
	FAIL_(crypt_keyslot_destroy(cd, CRYPT_ANY_SLOT), "invalid keyslot");
	FAIL_(crypt_keyslot_destroy(cd, 0), "keyslot not used");
	OK_(crypt_keyslot_destroy(cd, 7));
	EQ_(CRYPT_SLOT_INACTIVE, crypt_keyslot_status(cd, 7));
	EQ_(CRYPT_SLOT_ACTIVE_LAST, crypt_keyslot_status(cd, 6));

	EQ_(6, crypt_keyslot_change_by_passphrase(cd, 6, CRYPT_ANY_SLOT, passphrase2, strlen(passphrase2), passphrase, strlen(passphrase)));
	EQ_(CRYPT_SLOT_ACTIVE_LAST, crypt_keyslot_status(cd, 6));
	EQ_(7, crypt_keyslot_change_by_passphrase(cd, 6, 7, passphrase, strlen(passphrase), passphrase2, strlen(passphrase2)));
	EQ_(CRYPT_SLOT_ACTIVE_LAST, crypt_keyslot_status(cd, 7));
	EQ_(7, crypt_activate_by_passphrase(cd, NULL, 7, passphrase2, strlen(passphrase2), 0));
	EQ_(6, crypt_keyslot_change_by_passphrase(cd, CRYPT_ANY_SLOT, 6, passphrase2, strlen(passphrase2), passphrase, strlen(passphrase)));

	EQ_(6, crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key2, &key_size, passphrase, strlen(passphrase)));
	OK_(crypt_volume_key_verify(cd, key2, key_size));
	OK_(memcmp(key, key2, key_size));

	OK_(strcmp(cipher, crypt_get_cipher(cd)));
	OK_(strcmp(cipher_mode, crypt_get_cipher_mode(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(r_payload_offset, crypt_get_data_offset(cd));
	OK_(strcmp(DEVICE_2, crypt_get_device_name(cd)));

	reset_log();
	OK_(crypt_dump(cd));
	OK_(!(global_lines != 0));
	reset_log();

	FAIL_(crypt_dump_json(cd, NULL, 42), "flags be used later");
	OK_(crypt_dump_json(cd, NULL, 0));
	OK_(!(global_lines != 0));
	reset_log();
	OK_(crypt_dump_json(cd, &tmp_buf, 0));
	OK_(!(tmp_buf && strlen(tmp_buf) != 0));

	FAIL_(crypt_set_uuid(cd, "blah"), "wrong UUID format");
	OK_(crypt_set_uuid(cd, DEVICE_TEST_UUID));
	OK_(strcmp(DEVICE_TEST_UUID, crypt_get_uuid(cd)));

	FAIL_(crypt_deactivate(cd, CDEVICE_2), "not active");
	CRYPT_FREE(cd);
	_cleanup_dmdevices();

	/* LUKSv2 format tests */

	/* very basic test */
	OK_(crypt_init(&cd, DEVICE_2));
	crypt_set_iteration_time(cd, 1);
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 0, NULL), "Wrong key size");
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	CRYPT_FREE(cd);
	/* some invalid parameters known to cause troubles */
	OK_(crypt_init(&cd, DEVICE_2));
	crypt_set_iteration_time(cd, 0); /* wrong for argon2 but we don't know the pbkdf type yet, ignored */
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, key_size, PASSPHRASE, strlen(PASSPHRASE)), 0);
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DEVICE_2));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, key_size, NULL));
	FAIL_(crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, key, key_size, PASSPHRASE, strlen(PASSPHRASE)), "VK doesn't match any digest");
	FAIL_(crypt_keyslot_add_by_volume_key(cd, 1, key, key_size, PASSPHRASE, strlen(PASSPHRASE)), "VK doesn't match any digest");
	CRYPT_FREE(cd);

	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 3, NULL, key_size, PASSPHRASE, strlen(PASSPHRASE)), 3);
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key3, key_size, 0), "VK doesn't match any digest assigned to segment 0");
	CRYPT_FREE(cd);

	/*
	 * Check regression in getting keyslot encryption parameters when
	 * volume key size is unknown (no active keyslots).
	 */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, key_size, PASSPHRASE, strlen(PASSPHRASE)), 0);
	/* drop context copy of volume key */
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	EQ_(crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size, PASSPHRASE, strlen(PASSPHRASE)), 0);
	OK_(crypt_keyslot_destroy(cd, 0));
	OK_(set_fast_pbkdf(cd));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, key, key_size, PASSPHRASE, strlen(PASSPHRASE)), 0);
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
}

static void Luks2MetadataSize(void)
{
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha256",
		.parallel_threads = 1,
		.max_memory_kb = 128,
		.iterations = 4,
		.flags = CRYPT_PBKDF_NO_BENCHMARK
	};
	struct crypt_params_luks2 params = {
		.pbkdf = &pbkdf,
		.data_device = DEVICE_2,
		.sector_size = 512
	};
	char key[128], tmp[128];

	const char *vk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(vk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_header_size, default_mdata_size, default_keyslots_size, mdata_size,
		 keyslots_size, r_header_wrong_size = 14336;

	/* Cannot use Argon2 in FIPS */
	if (_fips_mode) {
		pbkdf.type = CRYPT_KDF_PBKDF2;
		pbkdf.parallel_threads = 0;
		pbkdf.max_memory_kb = 0;
		pbkdf.iterations = 1000;
	}

	OK_(crypt_decode_key(key, vk_hex, key_size));

	// init test devices
	OK_(get_luks2_offsets(0, 0, 0, &r_header_size, NULL));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, r_header_wrong_size)); /* 7 MiBs only */
	//default metadata sizes
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_get_metadata_size(cd, &mdata_size, &keyslots_size));
	EQ_(mdata_size, 0);
	EQ_(keyslots_size, 0);
	OK_(crypt_set_metadata_size(cd, 0, 0));
	OK_(crypt_get_metadata_size(cd, &mdata_size, &keyslots_size));
	EQ_(mdata_size, 0);
	EQ_(keyslots_size, 0);
	OK_(crypt_set_metadata_size(cd, 0x004000, 0x004000));
	OK_(crypt_get_metadata_size(cd, &mdata_size, &keyslots_size));
	EQ_(mdata_size, 0x004000);
	EQ_(keyslots_size, 0x004000);
	OK_(crypt_set_metadata_size(cd, 0x008000, 0x008000));
	OK_(crypt_get_metadata_size(cd, &mdata_size, &keyslots_size));
	EQ_(mdata_size, 0x008000);
	EQ_(keyslots_size, 0x008000);
	FAIL_(crypt_set_metadata_size(cd, 0x008001, 0x008000), "Wrong size");
	FAIL_(crypt_set_metadata_size(cd, 0x008000, 0x008001), "Wrong size");
	CRYPT_FREE(cd);

	// metadata settings
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_set_metadata_size(cd, 0x080000, 0x080000));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, PASSPHRASE, strlen(PASSPHRASE)), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_get_metadata_size(cd, &mdata_size, &keyslots_size));
	EQ_(mdata_size, 0x080000);
	EQ_(keyslots_size, 0x080000);
	CRYPT_FREE(cd);
	// default
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_get_metadata_size(cd, &default_mdata_size, &default_keyslots_size));
	EQ_(default_mdata_size, 0x04000);
	EQ_(default_keyslots_size, (r_header_size * 512) - 2 * 0x04000);
	CRYPT_FREE(cd);
	// check keyslots size calculation is correct
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_set_metadata_size(cd, 0x80000, 0));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_get_metadata_size(cd, &mdata_size, &keyslots_size));
	EQ_(mdata_size, 0x80000);
	EQ_(keyslots_size, (r_header_size * 512) - 2 * 0x80000);
	CRYPT_FREE(cd);

	// various metadata size checks combined with data offset
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_set_metadata_size(cd, 0, default_keyslots_size + 4096));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Device is too small.");
	OK_(crypt_set_metadata_size(cd, 0x20000, (r_header_size * 512) - 2 * 0x20000 + 4096));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Device is too small.");
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_set_metadata_size(cd, 0x80000, 0));
	OK_(crypt_set_data_offset(cd, 0x80000 / 512 - 8));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Data offset is too small.");
	CRYPT_FREE(cd);

	// H_DEVICE_WRONG size is 7MiB
	OK_(crypt_init(&cd, DMDIR H_DEVICE_WRONG));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_get_metadata_size(cd, &mdata_size, &keyslots_size));
	EQ_(mdata_size, default_mdata_size);
	EQ_(keyslots_size, (r_header_wrong_size * 512) - 2 * default_mdata_size);
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DMDIR H_DEVICE_WRONG));
	OK_(crypt_set_metadata_size(cd, 0x400000, 0));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Device is too small.");
	CRYPT_FREE(cd);

	// IMAGE_EMPTY_SMALL size is 7MiB but now it's regulare file
	OK_(crypt_init(&cd, IMAGE_EMPTY_SMALL));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_get_metadata_size(cd, &mdata_size, &keyslots_size));
	EQ_(mdata_size, default_mdata_size);
	EQ_(keyslots_size, default_keyslots_size);
	EQ_(crypt_get_data_offset(cd), 0);
	CRYPT_FREE(cd);

	sprintf(tmp, "truncate -s %" PRIu64 " " IMAGE_EMPTY_SMALL, r_header_wrong_size * 512);
	_system(tmp, 1);

	// check explicit keyslots size and data offset are respected even with regular file mdevice
	OK_(crypt_init(&cd, IMAGE_EMPTY_SMALL));
	OK_(crypt_set_metadata_size(cd, 0, default_keyslots_size));
	OK_(crypt_set_data_offset(cd, r_header_size + 8));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_get_metadata_size(cd, &mdata_size, &keyslots_size));
	EQ_(mdata_size, default_mdata_size);
	EQ_(keyslots_size, default_keyslots_size);
	EQ_(crypt_get_data_offset(cd), r_header_size + 8);
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
}

static void UseTempVolumes(void)
{
	char tmp[256];

	// Tepmporary device without keyslot but with on-disk LUKS header
	OK_(crypt_init(&cd, DEVICE_2));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "not yet formatted");
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 16, NULL));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0));
	GE_(crypt_status(cd, CDEVICE_2), CRYPT_ACTIVE);
	CRYPT_FREE(cd);

	OK_(crypt_init_by_name(&cd, CDEVICE_2));
	OK_(crypt_deactivate(cd, CDEVICE_2));
	CRYPT_FREE(cd);

	// Dirty checks: device without UUID
	// we should be able to remove it but not manipulate with it
	GE_(snprintf(tmp, sizeof(tmp), "dmsetup create %s --table \""
		"0 100 crypt aes-cbc-essiv:sha256 deadbabedeadbabedeadbabedeadbabe 0 "
		"%s 2048\"", CDEVICE_2, DEVICE_2), 0);
	_system(tmp, 1);
	OK_(crypt_init_by_name(&cd, CDEVICE_2));
	OK_(crypt_deactivate(cd, CDEVICE_2));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "No known device type");
	CRYPT_FREE(cd);

	// Dirty checks: device with UUID but LUKS header key fingerprint must fail)
	GE_(snprintf(tmp, sizeof(tmp), "dmsetup create %s --table \""
		"0 100 crypt aes-cbc-essiv:sha256 deadbabedeadbabedeadbabedeadbabe 0 "
		"%s 2048\" -u CRYPT-LUKS2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ctest1",
		 CDEVICE_2, DEVICE_2), 0);
	_system(tmp, 1);
	OK_(crypt_init_by_name(&cd, CDEVICE_2));
	OK_(crypt_deactivate(cd, CDEVICE_2));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "wrong volume key");
	CRYPT_FREE(cd);

	// No slots
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "volume key is lost");
	CRYPT_FREE(cd);
}

static void Luks2HeaderRestore(void)
{
	char key[128];
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha256",
		.parallel_threads = 4,
		.max_memory_kb = 1024,
		.time_ms = 1
	};
	struct crypt_params_luks2 params = {
		.pbkdf = &pbkdf,
		.data_alignment = 8192, // 4M, data offset will be 4096
		.sector_size = 512
	};
	struct crypt_params_plain pl_params = {
		.hash = "sha256",
		.skip = 0,
		.offset = 0,
		.size = 0
	};
	struct crypt_params_luks1 luks1 = {
		.data_alignment = 8192, // 4M offset to pass alignment test
	};
	uint32_t flags = 0;

	const char *vk_hex = "ccadd99b16cd3d200c22d6db45d8b6630ef3d936767127347ec8a76ab992c2ea";
	size_t key_size = strlen(vk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset;

	/* Cannot use Argon2 in FIPS */
	if (_fips_mode) {
		pbkdf.type = CRYPT_KDF_PBKDF2;
		pbkdf.parallel_threads = 0;
		pbkdf.max_memory_kb = 0;
	}

	OK_(crypt_decode_key(key, vk_hex, key_size));

	OK_(get_luks2_offsets(0, params.data_alignment, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 5000));

	// do not restore header over plain device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &pl_params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	FAIL_(crypt_header_restore(cd, CRYPT_PLAIN, NO_REQS_LUKS2_HEADER), "Cannot restore header to PLAIN type device");
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, NO_REQS_LUKS2_HEADER), "Cannot restore header over PLAIN type device");
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	// FIXME: does following test make a sense in LUKS2?
	// volume key_size mismatch
	// OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	// memcpy(key2, key, key_size / 2);
	// OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key2, key_size / 2, &params));
	// FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, VALID_LUKS2_HEADER), "Volume keysize mismatch");
	// CRYPT_FREE(cd);

	// payload offset mismatch
	params.data_alignment = 8193;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, NO_REQS_LUKS2_HEADER), "Payload offset mismatch");
	CRYPT_FREE(cd);
	params.data_alignment = 4096;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	// FIXME: either format has to fail or next line must be true
	// EQ_(crypt_get_data_offset(cd), params.data_alignment);
	// FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, VALID_LUKS2_HEADER), "Payload offset mismatch");
	CRYPT_FREE(cd);

	// do not allow restore over LUKS1 header on device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, NULL, 32, &luks1));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, NO_REQS_LUKS2_HEADER), "LUKS1 format detected");
	CRYPT_FREE(cd);

	/* check crypt_header_restore() properly loads crypt_device context */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_wipe(cd, NULL, CRYPT_WIPE_ZERO, 0, 1*1024*1024, 1*1024*1024, 0, NULL, NULL));
	OK_(crypt_header_restore(cd, CRYPT_LUKS2, NO_REQS_LUKS2_HEADER));
	/* check LUKS2 specific API call returns non-error code */
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &flags));
	EQ_(flags, 0);
	/* same test, any LUKS */
	OK_(crypt_wipe(cd, NULL, CRYPT_WIPE_ZERO, 0, 1*1024*1024, 1*1024*1024, 0, NULL, NULL));
	OK_(crypt_header_restore(cd, CRYPT_LUKS, NO_REQS_LUKS2_HEADER));
	/* check LUKS2 specific API call returns non-error code */
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &flags));
	EQ_(flags, 0);

	CRYPT_FREE(cd);

	_cleanup_dmdevices();
}

static void Luks2HeaderLoad(void)
{
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha256",
		.parallel_threads = 4,
		.max_memory_kb = 1024,
		.time_ms = 1
	};
	struct crypt_params_luks2 params = {
		.pbkdf = &pbkdf,
		.data_alignment = 8192, // 4M, data offset will be 4096
		.data_device = DEVICE_2,
		.sector_size = 512
	};
	struct crypt_params_plain pl_params = {
		.hash = "sha256",
		.skip = 0,
		.offset = 0,
		.size = 0
	};
	char key[128], cmd[256];

	const char *vk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(vk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset, r_header_size, img_size;

	/* Cannot use Argon2 in FIPS */
	if (_fips_mode) {
		pbkdf.type = CRYPT_KDF_PBKDF2;
		pbkdf.parallel_threads = 0;
		pbkdf.max_memory_kb = 0;
	}

	OK_(crypt_decode_key(key, vk_hex, key_size));

	// hardcoded values for existing image IMAGE1
	img_size = 8192;
	// prepare test env
	OK_(get_luks2_offsets(0, 0, 0, &r_header_size, &r_payload_offset));
	// external header device
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	// prepared header on a device too small to contain header and payload
	//OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, r_payload_offset - 1));
	OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, img_size - 1));
	GE_(snprintf(cmd, sizeof(cmd), "dd if=" IMAGE1 " of=" DMDIR H_DEVICE_WRONG " bs=%" PRIu32
	    " count=%" PRIu64 " 2>/dev/null", params.sector_size, img_size - 1), 0);
	OK_(_system(cmd, 1));
	// some device
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1000));
	// 1 sector device
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_header_size + 1));
	// 0 sectors device for payload
	OK_(create_dmdevice_over_loop(L_DEVICE_0S, r_header_size));

	// valid metadata and device size
	params.data_alignment = 0;
	params.data_device = DMDIR L_DEVICE_OK;
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(!crypt_get_metadata_device_name(cd));
	EQ_(strcmp(DMDIR H_DEVICE, crypt_get_metadata_device_name(cd)), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(1, crypt_header_is_detached(cd));
	CRYPT_FREE(cd);

	// repeat with init with two devices
	OK_(crypt_init_data_device(&cd, DMDIR H_DEVICE, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	CRYPT_FREE(cd);
	OK_(crypt_init_data_device(&cd, DMDIR H_DEVICE, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(!crypt_get_metadata_device_name(cd));
	EQ_(strcmp(DMDIR H_DEVICE, crypt_get_metadata_device_name(cd)), 0);
	EQ_(1, crypt_header_is_detached(cd));
	CRYPT_FREE(cd);

	// bad header: device too small (payloadOffset > device_size)
	OK_(crypt_init(&cd, DMDIR H_DEVICE_WRONG));
	FAIL_(crypt_load(cd, CRYPT_LUKS2, NULL), "Device too small");
	NULL_(crypt_get_type(cd));
	CRYPT_FREE(cd);

	// 0 secs for encrypted data area
	params.data_alignment = 8192;
	params.data_device = NULL;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	CRYPT_FREE(cd);
	// load should be ok
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Device too small");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	CRYPT_FREE(cd);

	// damaged header
	OK_(_system("dd if=/dev/zero of=" DMDIR L_DEVICE_OK " bs=512 count=8 2>/dev/null", 1));
	OK_(_system("dd if=/dev/zero of=" DMDIR L_DEVICE_OK " bs=512 seek=32 count=8 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	FAIL_(crypt_load(cd, CRYPT_LUKS2, NULL), "Header not found");
	CRYPT_FREE(cd);

	// plain device
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	FAIL_(crypt_load(cd, CRYPT_PLAIN, NULL), "Can't load nonLUKS device type");
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, key, key_size, &pl_params));
	FAIL_(crypt_load(cd, CRYPT_LUKS2, NULL), "Can't load over nonLUKS device type");
	CRYPT_FREE(cd);

	//LUKSv2 device
	OK_(crypt_init(&cd, DEVICE_4));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DEVICE_4));
	crypt_set_iteration_time(cd, 0); /* invalid for argon2 pbkdf, ignored */
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	CRYPT_FREE(cd);

	/* check load sets proper device type */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	EQ_(strcmp(CRYPT_LUKS2, crypt_get_type(cd)), 0);
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
}

static void Luks2HeaderBackup(void)
{
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha256",
		.parallel_threads = 4,
		.max_memory_kb = 1024,
		.time_ms = 1
	};
	struct crypt_params_luks2 params = {
		.pbkdf = &pbkdf,
		.data_alignment = 8192, // 4M, data offset will be 4096
		.data_device = DEVICE_2,
		.sector_size = 512
	};
	char key[128];
	int fd, ro = O_RDONLY;

	const char *vk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(vk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset;

	const char *passphrase = PASSPHRASE;

	/* Cannot use Argon2 in FIPS */
	if (_fips_mode) {
		pbkdf.type = CRYPT_KDF_PBKDF2;
		pbkdf.parallel_threads = 0;
		pbkdf.max_memory_kb = 0;
	}

	OK_(crypt_decode_key(key, vk_hex, key_size));

	OK_(get_luks2_offsets(1, params.data_alignment, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1));

	// create LUKS device and backup the header
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, passphrase, strlen(passphrase)), 7);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, key, key_size, passphrase, strlen(passphrase)), 0);
	OK_(crypt_header_backup(cd, CRYPT_LUKS2, BACKUP_FILE));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	// restore header from backup
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_header_restore(cd, CRYPT_LUKS2, BACKUP_FILE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(0, crypt_header_is_detached(cd));
	CRYPT_FREE(cd);

	// exercise luksOpen using backup header in file
	OK_(crypt_init(&cd, BACKUP_FILE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, passphrase, strlen(passphrase), 0), 0);
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(1, crypt_header_is_detached(cd));
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, BACKUP_FILE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 7, passphrase, strlen(passphrase), 0), 7);
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	// exercise luksOpen using backup header on block device
	fd = loop_attach(&DEVICE_3, BACKUP_FILE, 0, 0, &ro);
	NOTFAIL_(fd, "Bad loop device.");
	close(fd);
	OK_(crypt_init(&cd, DEVICE_3));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, passphrase, strlen(passphrase), 0), 0);
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DEVICE_3));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 7, passphrase, strlen(passphrase), 0), 7);
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
}

static void ResizeDeviceLuks2(void)
{
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha256",
		.parallel_threads = 4,
		.max_memory_kb = 1024,
		.time_ms = 1
	};
	struct crypt_params_luks2 params = {
		.pbkdf = &pbkdf,
		.data_alignment = 8192, // 4M, data offset will be 4096
		.sector_size = 512
	};
	char key[128];

	const char *vk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(vk_hex) / 2;
	const char *cipher = "aes", *capi_cipher = "capi:cbc(aes)";
	const char *cipher_mode = "cbc-essiv:sha256", *capi_cipher_mode = "essiv:sha256";
	uint64_t r_payload_offset, r_header_size, r_size;

	/* Cannot use Argon2 in FIPS */
	if (_fips_mode) {
		pbkdf.type = CRYPT_KDF_PBKDF2;
		pbkdf.parallel_threads = 0;
		pbkdf.max_memory_kb = 0;
	}

	OK_(crypt_decode_key(key, vk_hex, key_size));

	// prepare env
	OK_(get_luks2_offsets(0, params.data_alignment, 0, NULL, &r_payload_offset));
	OK_(get_luks2_offsets(0, 0, 0, &r_header_size, NULL));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1000));
	OK_(create_dmdevice_over_loop(L_DEVICE_0S, 1000));
	OK_(create_dmdevice_over_loop(L_DEVICE_WRONG, r_payload_offset + 1000));

	// test header and encrypted payload all in one device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	// disable loading VKs in kernel keyring (compatible mode)
	OK_(crypt_volume_key_keyring(cd, 0));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	OK_(crypt_resize(cd, CDEVICE_1, 42));
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(42, r_size >> TST_SECTOR_SHIFT);
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	// autodetect encrypted device area size
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> TST_SECTOR_SHIFT);
	FAIL_(crypt_resize(cd, CDEVICE_1, 1001), "Device too small");
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> TST_SECTOR_SHIFT);
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	params.data_alignment = 0;
	params.data_device = DMDIR L_DEVICE_0S;
	// test case for external header
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	OK_(crypt_resize(cd, CDEVICE_1, 666));
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(666, r_size >> TST_SECTOR_SHIFT);
	// autodetect encrypted device size
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> TST_SECTOR_SHIFT);
	FAIL_(crypt_resize(cd, CDEVICE_1, 1001), "Device too small");
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> TST_SECTOR_SHIFT);
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

#if KERNEL_KEYRING
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	// enable loading VKs in kernel keyring (default mode)
	OK_(crypt_volume_key_keyring(cd, 1));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	// erase volume key from kernel keyring
	if (t_dm_crypt_keyring_support())
		OK_(_drop_keyring_key(cd, 0));
	else
		FAIL_(_drop_keyring_key(cd, 0), "key not found");
	// same size is ok
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	// kernel fails to find the volume key in keyring
	if (t_dm_crypt_keyring_support())
		FAIL_(crypt_resize(cd, CDEVICE_1, 42), "Unable to find volume key in keyring");
	else
		OK_(crypt_resize(cd, CDEVICE_1, 42));
	// test mode must not load vk in keyring
	OK_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0));
	if (t_dm_crypt_keyring_support())
		FAIL_(crypt_resize(cd, CDEVICE_1, 44), "VK must be in keyring to perform resize");
	else
		OK_(crypt_resize(cd, CDEVICE_1, 44));
	// reinstate the volume key in keyring
	OK_(crypt_activate_by_volume_key(cd, NULL, key, key_size, t_dm_crypt_keyring_support() ? CRYPT_ACTIVATE_KEYRING_KEY : 0));
	OK_(crypt_resize(cd, CDEVICE_1, 43));
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(43, r_size >> TST_SECTOR_SHIFT);
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	// check userspace gets hint volume key must be properly loaded in kernel keyring
	if (t_dm_crypt_keyring_support())
		EQ_(crypt_resize(cd, CDEVICE_1, 0), -EPERM);
	else
		OK_(crypt_resize(cd, CDEVICE_1, 0));
	CRYPT_FREE(cd);

	// same as above for handles initialised by name
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	if (t_dm_crypt_keyring_support())
		EQ_(crypt_resize(cd, CDEVICE_1, 0), -EPERM);
	else
		OK_(crypt_resize(cd, CDEVICE_1, 0));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);
#endif
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, NULL, NULL));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));

	/* create second LUKS2 device */
	OK_(crypt_init(&cd2, DMDIR L_DEVICE_WRONG));
	OK_(crypt_format(cd2, CRYPT_LUKS2, cipher, cipher_mode, crypt_get_uuid(cd), key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd2, CDEVICE_2, key, key_size, 0));
	/* do not allow resize of other device */
	FAIL_(crypt_resize(cd2, CDEVICE_1, 1), "Device got resized by wrong device context.");
	OK_(crypt_deactivate(cd2, CDEVICE_2));
	CRYPT_FREE(cd2);

	OK_(crypt_init(&cd2, DMDIR L_DEVICE_WRONG));
	OK_(crypt_set_pbkdf_type(cd2, &min_pbkdf2));
	OK_(crypt_format(cd2, CRYPT_LUKS1, cipher, cipher_mode, crypt_get_uuid(cd), key, key_size, NULL));
	OK_(crypt_activate_by_volume_key(cd2, CDEVICE_2, key, key_size, 0));
	FAIL_(crypt_resize(cd2, CDEVICE_1, 1), "Device got resized by wrong device context.");
	OK_(crypt_deactivate(cd2, CDEVICE_2));
	CRYPT_FREE(cd2);

	OK_(crypt_init(&cd2, DMDIR L_DEVICE_WRONG));
	OK_(crypt_format(cd2, CRYPT_PLAIN, cipher, cipher_mode, NULL, key, key_size, NULL));
	OK_(crypt_activate_by_volume_key(cd2, CDEVICE_2, key, key_size, 0));
	FAIL_(crypt_resize(cd2, CDEVICE_1, 1), "Device got resized by wrong device context.");
	OK_(crypt_deactivate(cd2, CDEVICE_2));
	CRYPT_FREE(cd2);

	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	if (t_dm_capi_string_supported()) {
		OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
		OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
		OK_(crypt_format(cd, CRYPT_LUKS2, capi_cipher, capi_cipher_mode, NULL, key, key_size, NULL));
		OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
		OK_(crypt_resize(cd, CDEVICE_1, 8));
		if (!t_device_size(DMDIR CDEVICE_1, &r_size))
			EQ_(8, r_size >> TST_SECTOR_SHIFT);
		OK_(crypt_deactivate(cd, CDEVICE_1));
		CRYPT_FREE(cd);
	}

	_cleanup_dmdevices();
}

static void TokenActivationByKeyring(void)
{
#if KERNEL_KEYRING
	key_serial_t kid, kid1;
	struct crypt_active_device cad;

	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

	const struct crypt_token_params_luks2_keyring params = {
		.key_description = KEY_DESC_TEST0
	}, params2 = {
		.key_description = KEY_DESC_TEST1
	}, params_invalid = {};
	uint64_t r_payload_offset;

	if (!t_dm_crypt_keyring_support()) {
		printf("WARNING: Kernel keyring not supported, skipping test.\n");
		return;
	}

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");

	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));

	// prepare the device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	FAIL_(crypt_token_luks2_keyring_set(cd, CRYPT_ANY_TOKEN, &params_invalid), "Invalid key description property.");
	EQ_(crypt_token_luks2_keyring_set(cd, 3, &params), 3);
	EQ_(crypt_token_assign_keyslot(cd, 3, 0), 3);
	CRYPT_FREE(cd);

	// test thread keyring key in token 0
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 3, NULL, 0), 0);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 3, NULL, 0), "already open");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_PROCESS_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");

	// add token 1 with process keyring key
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_token_json_set(cd, 3, NULL), 3);
	EQ_(crypt_token_luks2_keyring_set(cd, 1, &params), 1);
	EQ_(crypt_token_assign_keyslot(cd, 1, 0), 1);
	CRYPT_FREE(cd);

	// test process keyring key in token 1
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 1, NULL, 0), 0);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 1, NULL, 0), "already open");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_PROCESS_KEYRING), "Test or kernel keyring are broken.");

	// create two tokens and let the cryptsetup unlock the volume with the valid one
	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");

	kid1 = add_key("user", KEY_DESC_TEST1, PASSPHRASE1, strlen(PASSPHRASE1), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid1, "Test or kernel keyring are broken.");

	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_token_luks2_keyring_set(cd, 0, &params), 0);
	EQ_(crypt_token_assign_keyslot(cd, 0, 0), 0);
	EQ_(crypt_token_luks2_keyring_set(cd, 1, &params2), 1);
	FAIL_(crypt_token_assign_keyslot(cd, 1, 1), "Keyslot 1 doesn't exist");
	OK_(set_fast_pbkdf(cd));
	EQ_(crypt_keyslot_add_by_passphrase(cd, 1, PASSPHRASE, strlen(PASSPHRASE), PASSPHRASE1, strlen(PASSPHRASE1)), 1);
	EQ_(crypt_token_assign_keyslot(cd, 1, 1), 1);
	CRYPT_FREE(cd);

	// activate by specific token
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 0, NULL, 0), 0);
	if (t_dm_crypt_keyring_support()) {
		OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
		EQ_(cad.flags & CRYPT_ACTIVATE_KEYRING_KEY, CRYPT_ACTIVATE_KEYRING_KEY);
	}
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 1, NULL, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");

	// activate by any token with token 0 having absent pass from keyring
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, CRYPT_ANY_TOKEN, NULL, 0), 1);
	if (t_dm_crypt_keyring_support()) {
		OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
		EQ_(cad.flags & CRYPT_ACTIVATE_KEYRING_KEY, CRYPT_ACTIVATE_KEYRING_KEY);
	}
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");

	// replace pass for keyslot 0 making token 0 invalid
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_keyslot_destroy(cd, 0));
	OK_(set_fast_pbkdf(cd));
	EQ_(crypt_keyslot_add_by_passphrase(cd, 0, PASSPHRASE1, strlen(PASSPHRASE1), PASSPHRASE1, strlen(PASSPHRASE1)), 0);
	CRYPT_FREE(cd);

	// activate by any token with token 0 having wrong pass for keyslot 0
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, CRYPT_ANY_TOKEN, NULL, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	 // create new device, with two tokens:
	 // 1st token being invalid (missing key in keyring)
	 // 2nd token can activate keyslot 1 after failing to do so w/ keyslot 0 (wrong pass)
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 1);
	EQ_(crypt_token_luks2_keyring_set(cd, 0, &params), 0);
	EQ_(crypt_token_assign_keyslot(cd, 0, 0), 0);
	EQ_(crypt_token_luks2_keyring_set(cd, 2, &params2), 2);
	EQ_(crypt_token_assign_keyslot(cd, 2, 1), 2);
	CRYPT_FREE(cd);

	NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");

	kid1 = add_key("user", KEY_DESC_TEST1, PASSPHRASE1, strlen(PASSPHRASE1), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid1, "Test or kernel keyring are broken.");

	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, CRYPT_ANY_TOKEN, NULL, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);
	_cleanup_dmdevices();
#else
	printf("WARNING: cryptsetup compiled with kernel keyring service disabled, skipping test.\n");
#endif
}

static void Tokens(void)
{
#define TEST_TOKEN_JSON(x) "{\"type\":\"test_token\",\"keyslots\":[" x "]," \
			"\"key_length\":32,\"a_field\":\"magic_string\"}"

#define TEST_TOKEN_JSON_INVALID(x) "{\"type\":\"test_token\",\"keyslots\":[" x "]," \
			"\"key_length\":32}"

#define TEST_TOKEN1_JSON(x) "{\"type\":\"test_token1\",\"keyslots\":[" x "]," \
			"\"key_length\":32,\"a_field\":\"magic_string\"}"

#define TEST_TOKEN1_JSON_INVALID(x) "{\"type\":\"test_token1\",\"keyslots\":[" x "]," \
			"\"key_length\":32}"

#define BOGUS_TOKEN0_JSON "{\"type\":\"luks2-\",\"keyslots\":[]}"
#define BOGUS_TOKEN1_JSON "{\"type\":\"luks2-a\",\"keyslots\":[]}"

#define LUKS2_KEYRING_TOKEN_JSON(x, y) "{\"type\":\"luks2-keyring\",\"keyslots\":[" x "]," \
			"\"key_description\":" y "}"

#define LUKS2_KEYRING_TOKEN_JSON_BAD(x, y) "{\"type\":\"luks2-keyring\",\"keyslots\":[" x "]," \
			"\"key_description\":" y ", \"some_field\":\"some_value\"}"

#define TEST_TOKEN2_JSON(x) "{\"type\":\"test_token2\",\"keyslots\":[" x "] }"

#define TEST_TOKEN3_JSON(x) "{\"type\":\"test_token3\",\"keyslots\":[" x "] }"


	int ks, token_max;
	const char *dummy;
	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";
	char passptr[] = PASSPHRASE;
	char passptr1[] = PASSPHRASE1;
	struct crypt_active_device cad;
	struct crypt_keyslot_context *kc;

	static const crypt_token_handler th = {
		.name = "test_token",
		.open = test_open,
		.validate = test_validate
	}, th2 = {
		.name = "test_token",
		.open = test_open
	}, th3 = {
		.name = "test_token1",
		.open = test_open,
		.validate = test_validate
	}, th_reserved = {
		.name = "luks2-prefix",
		.open = test_open
	}, th4 = {
		.name = "test_token2",
		.open = test_open_pass, // PASSPHRASE
	}, th5 = {
		.name = "test_token3",
		.open = test_open_pass1, // PASSPHRASE1
	};

	struct crypt_token_params_luks2_keyring params = {
		.key_description = "desc"
	};
	uint64_t r_payload_offset;

	OK_(crypt_token_register(&th));
	FAIL_(crypt_token_register(&th2), "Token handler with the name already registered.");

	FAIL_(crypt_token_register(&th_reserved), "luks2- is reserved prefix");

	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));

	// basic token API tests
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_token_status(cd, -1, NULL), CRYPT_TOKEN_INVALID);
	EQ_(crypt_token_status(cd, 32, NULL), CRYPT_TOKEN_INVALID);
	EQ_(crypt_token_status(cd, 0, NULL), CRYPT_TOKEN_INACTIVE);
	EQ_(crypt_token_status(cd, 31, NULL), CRYPT_TOKEN_INACTIVE);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 1);
	FAIL_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN_JSON_INVALID("\"0\"")), "Token validation failed");
	EQ_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN_JSON("\"0\"")), 0);
	EQ_(crypt_token_status(cd, 0, NULL), CRYPT_TOKEN_EXTERNAL);
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 0, passptr, 0), 0);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 0, passptr, 0), "already active");
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// write invalid token and verify that validate() can detect it after handler being registered
	EQ_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN1_JSON_INVALID("\"1\"")), 1);
	EQ_(crypt_token_status(cd, 1, NULL), CRYPT_TOKEN_EXTERNAL_UNKNOWN);
	EQ_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN1_JSON("\"1\"")), 2);
	EQ_(crypt_token_status(cd, 2, &dummy), CRYPT_TOKEN_EXTERNAL_UNKNOWN);
	OK_(strcmp(dummy, "test_token1"));
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 1, passptr1, 0), "Unknown token handler");
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 2, passptr1, 0), "Unknown token handler");
	OK_(crypt_token_register(&th3));
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 1, passptr1, 0), "Token validation failed");
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, passptr1, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// test crypt_token_json_get returns correct token id
	EQ_(crypt_token_json_get(cd, 2, &dummy), 2);

	// exercise assign/unassign keyslots API
	FAIL_(crypt_token_unassign_keyslot(cd, CRYPT_ANY_TOKEN, 1), "Token id must be specific.");
	OK_(crypt_token_is_assigned(cd, 2, 1));
	EQ_(crypt_token_unassign_keyslot(cd, 2, 1), 2);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 2, passptr1, 0), "Token assigned to no keyslot");
	FAIL_(crypt_token_assign_keyslot(cd, CRYPT_ANY_TOKEN, 0), "Token id must be specific.");
	FAIL_(crypt_token_is_assigned(cd, 2, 0), "Token 2 must not be assigned to keyslot 0.");
	EQ_(crypt_token_assign_keyslot(cd, 2, 0), 2);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 2, passptr1, 0), "Wrong passphrase");
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, passptr, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_token_json_set(cd, 1, NULL), 1);
	FAIL_(crypt_token_json_get(cd, 1, &dummy), "Token is not there");
	EQ_(crypt_token_unassign_keyslot(cd, 2, CRYPT_ANY_SLOT), 2);
	EQ_(crypt_token_unassign_keyslot(cd, 0, CRYPT_ANY_SLOT), 0);

	// various tests related to unassigned keyslot to volume segment
	EQ_(crypt_keyslot_add_by_key(cd, 3, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 3);
	EQ_(crypt_token_assign_keyslot(cd, 2, 0), 2);
	EQ_(crypt_token_assign_keyslot(cd, 0, 3), 0);

	EQ_(crypt_activate_by_token(cd, NULL, 2, passptr, 0), 0);
	EQ_(crypt_activate_by_token(cd, NULL, 0, passptr1, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), 3);
	// FIXME: useless error message here (or missing one to be specific)
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 0, passptr1, 0), "No volume key available in token keyslots");
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, passptr, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_token_assign_keyslot(cd, 0, 1), 0);
	OK_(crypt_token_is_assigned(cd, 0, 1));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 0, passptr1, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	EQ_(crypt_token_assign_keyslot(cd, 2, 3), 2);
	OK_(crypt_token_is_assigned(cd, 2, 3));
	EQ_(crypt_activate_by_token(cd, NULL, 2, passptr, 0), 0);
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, passptr, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));

#if KERNEL_KEYRING
	if (t_dm_crypt_keyring_support()) {
		EQ_(crypt_activate_by_token(cd, NULL, 2, passptr, CRYPT_ACTIVATE_KEYRING_KEY), 0);
		OK_(_volume_key_in_keyring(cd, 0));
	}
	OK_(crypt_volume_key_keyring(cd, 0));
#endif
	FAIL_(crypt_activate_by_token(cd, NULL, 2, passptr, CRYPT_ACTIVATE_KEYRING_KEY), "Can't use keyring when disabled in library");
	OK_(crypt_volume_key_keyring(cd, 1));

	EQ_(crypt_token_luks2_keyring_set(cd, 5, &params), 5);
	EQ_(crypt_token_status(cd, 5, &dummy), CRYPT_TOKEN_INTERNAL);
	OK_(strcmp(dummy, "luks2-keyring"));

	FAIL_(crypt_token_luks2_keyring_get(cd, 2, &params), "Token is not luks2-keyring type");

	FAIL_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, BOGUS_TOKEN0_JSON), "luks2- reserved prefix.");
	FAIL_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, BOGUS_TOKEN1_JSON), "luks2- reserved prefix.");

	// test we can use crypt_token_json_set for valid luks2-keyring token
	FAIL_(crypt_token_json_set(cd, 12, LUKS2_KEYRING_TOKEN_JSON_BAD("\"0\"", "\"my_desc_x\"")), "Strict luks2-keyring token validation failed");
	EQ_(crypt_token_status(cd, 12, NULL), CRYPT_TOKEN_INACTIVE);
	FAIL_(crypt_token_json_set(cd, 12, LUKS2_KEYRING_TOKEN_JSON("\"5\"", "\"my_desc\"")), "Missing keyslot 5.");
	EQ_(crypt_token_json_set(cd, 10, LUKS2_KEYRING_TOKEN_JSON("\"1\"", "\"my_desc\"")), 10);
	EQ_(crypt_token_status(cd, 10, &dummy), CRYPT_TOKEN_INTERNAL);
	OK_(strcmp(dummy, "luks2-keyring"));
	params.key_description = NULL;
	EQ_(crypt_token_luks2_keyring_get(cd, 10, &params), 10);
	OK_(strcmp(params.key_description, "my_desc"));

	OK_(crypt_token_is_assigned(cd, 10, 1));
	// unassigned tests
	EQ_(crypt_token_is_assigned(cd, 10, 21), -ENOENT);
	EQ_(crypt_token_is_assigned(cd, 21, 1), -ENOENT);
	// wrong keyslot or token id tests
	EQ_(crypt_token_is_assigned(cd, -1, 1), -EINVAL);
	EQ_(crypt_token_is_assigned(cd, 32, 1), -EINVAL);
	EQ_(crypt_token_is_assigned(cd, 10, -1), -EINVAL);
	EQ_(crypt_token_is_assigned(cd, 10, 32), -EINVAL);
	EQ_(crypt_token_is_assigned(cd, -1, -1), -EINVAL);
	EQ_(crypt_token_is_assigned(cd, 32, 32), -EINVAL);

	// test crypt_keyslot_change_by_passphrase does not erase token references
	EQ_(crypt_keyslot_change_by_passphrase(cd, 1, 5, PASSPHRASE1, strlen(PASSPHRASE1), PASSPHRASE1, strlen(PASSPHRASE1)), 5);
	OK_(crypt_token_is_assigned(cd, 10, 5));
	ks = crypt_keyslot_change_by_passphrase(cd, 5, CRYPT_ANY_SLOT, PASSPHRASE1, strlen(PASSPHRASE1), PASSPHRASE1, strlen(PASSPHRASE1));
	NOTFAIL_(ks, "Failed to change keyslot passphrase.");
	OK_(crypt_token_is_assigned(cd, 10, ks));
	CRYPT_FREE(cd);

	// test token activation respects keyslot priorities
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0,  NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd,        3,  NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 3);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 5,  NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 5);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 8,  NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 8);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 12, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 12);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 21, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 21);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 31, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 31);

	OK_(crypt_keyslot_set_priority(cd, 0, CRYPT_SLOT_PRIORITY_IGNORE));
	OK_(crypt_keyslot_set_priority(cd, 3, CRYPT_SLOT_PRIORITY_PREFER));
	OK_(crypt_keyslot_set_priority(cd, 8, CRYPT_SLOT_PRIORITY_PREFER));
	OK_(crypt_keyslot_set_priority(cd, 12,CRYPT_SLOT_PRIORITY_PREFER));

	// expected unusable with CRYPT_ANY_TOKEN
	EQ_(crypt_token_json_set(cd, 1, TEST_TOKEN_JSON("\"0\", \"3\"")), 1);

	// expected unusable (-EPERM)
	EQ_(crypt_token_json_set(cd, 5, TEST_TOKEN_JSON("\"8\"")), 5);

	// expected unusable (-EPERM)
	EQ_(crypt_token_json_set(cd, 4, TEST_TOKEN_JSON("\"8\", \"3\"")), 4);

	// expected unusable (-ENOENT)
	EQ_(crypt_token_json_set(cd, 6, TEST_TOKEN_JSON("\"3\"")), 6);

	// expected unusable (-ENOENT)
	EQ_(crypt_token_json_set(cd, 11, TEST_TOKEN_JSON("")), 11);

	token_max = crypt_token_max(CRYPT_LUKS2) - 1;
	GE_(token_max, 0);

	// expected to be used first with CRYPT_ANY_TOKEN (unlocks with high priority ks 12)
	EQ_(crypt_token_json_set(cd, token_max, TEST_TOKEN_JSON("\"12\", \"0\", \"3\"")), token_max);

	// expected usable with CRYPT_ANY_TOKEN
	EQ_(crypt_token_json_set(cd, 8, TEST_TOKEN_JSON("\"5\", \"0\", \"3\"")), 8);

	// of all tokens keyslot 12 has highest priority now
	EQ_(crypt_activate_by_token_pin(cd, NULL, "test_token", CRYPT_ANY_TOKEN, NULL, 0, passptr, 0), 12);
	EQ_(crypt_activate_by_token_pin(cd, CDEVICE_1, "test_token", CRYPT_ANY_TOKEN, NULL, 0, passptr, 0), 12);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// with explicit token priority ignore may be used
	EQ_(crypt_activate_by_token_pin(cd, NULL, "test_token", 1, NULL, 0, passptr, 0), 0);
	EQ_(crypt_activate_by_token_pin(cd, CDEVICE_1, "test_token", 1, NULL, 0, passptr, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	EQ_(crypt_token_json_set(cd, token_max, NULL), token_max);

	EQ_(crypt_activate_by_token_pin(cd, NULL, "test_token", CRYPT_ANY_TOKEN, NULL, 0, passptr, 0), 5);

	EQ_(crypt_activate_by_token_pin(cd, NULL, "test_token", 5, NULL, 0, passptr, 0), -EPERM);
	EQ_(crypt_activate_by_token_pin(cd, NULL, "test_token", 4, NULL, 0, passptr, 0), -EPERM);

	EQ_(crypt_activate_by_token_pin(cd, NULL, "test_token", 6, NULL, 0, passptr, 0), -ENOENT);
	EQ_(crypt_activate_by_token_pin(cd, NULL, "test_token", 6, NULL, 0, passptr, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), 3);

	EQ_(crypt_activate_by_token_pin(cd, NULL, "test_token", 11, NULL, 0, passptr, 0), -ENOENT);
	EQ_(crypt_activate_by_token_pin(cd, NULL, "test_token", 11, NULL, 0, passptr, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), -ENOENT);

	// test crypt_resume_by_token_pin
	EQ_(crypt_activate_by_token_pin(cd, CDEVICE_1, "test_token", CRYPT_ANY_TOKEN, NULL, 0, passptr, 0), 5);
	OK_(crypt_suspend(cd, CDEVICE_1));
	EQ_(crypt_resume_by_token_pin(cd, CDEVICE_1, "test_token", CRYPT_ANY_TOKEN, NULL, 0, passptr), 5);
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(0, cad.flags & CRYPT_ACTIVATE_SUSPENDED);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	// test token based API with keyslot parameter
	OK_(crypt_token_register(&th4)); // PASSPHRASE
	OK_(crypt_token_register(&th5)); // PASSPHRASE1
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0,  NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1,  NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 1);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 2,  NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 2);

	EQ_(crypt_keyslot_add_by_volume_key(cd, 3,  NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 3);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 4,  NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 4);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 5,  NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 5);

	OK_(crypt_keyslot_set_priority(cd, 0, CRYPT_SLOT_PRIORITY_IGNORE));
	OK_(crypt_keyslot_set_priority(cd, 3, CRYPT_SLOT_PRIORITY_IGNORE));

	OK_(crypt_keyslot_set_priority(cd, 2, CRYPT_SLOT_PRIORITY_PREFER));
	OK_(crypt_keyslot_set_priority(cd, 5, CRYPT_SLOT_PRIORITY_PREFER));

	EQ_(crypt_keyslot_add_by_key(cd, 6, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 6);
	EQ_(crypt_keyslot_add_by_key(cd, 7, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 7);

	OK_(crypt_keyslot_set_priority(cd, 6, CRYPT_SLOT_PRIORITY_PREFER));
	OK_(crypt_keyslot_set_priority(cd, 7, CRYPT_SLOT_PRIORITY_PREFER));

	EQ_(crypt_token_json_set(cd, 0, TEST_TOKEN2_JSON("\"0\", \"5\", \"1\", \"6\"")), 0); // PASSPHRASE
	EQ_(crypt_token_json_set(cd, 1, TEST_TOKEN3_JSON("\"4\", \"6\", \"0\", \"5\"")), 1); // PASSPHRASE1

	/* keyslots:
	 *
	 * 0 ignore (token 0)
	 * 1 normal (token 0)
	 * 2 prefer -
	 * 3 ignore -
	 * 4 normal (token 1)
	 * 5 prefer (token 1, token 0 wrong passphrase)
	 * 6 prefer (unbound, token 0, token 1 wrong passphrase)
	 * 7 prefer (unbound)
	 */

	OK_(crypt_keyslot_context_init_by_token(cd, 0, NULL, NULL, 0, NULL, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 1);
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), 6);
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, 7, kc, CRYPT_ANY_SLOT, NULL, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), -ENOENT);
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, 5, kc, CRYPT_ANY_SLOT, NULL, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), -EPERM);
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_token(cd, CRYPT_ANY_TOKEN, NULL, NULL, 0, NULL, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 5);
	crypt_keyslot_context_free(kc);

	CRYPT_FREE(cd);

	EQ_(crypt_token_max(CRYPT_LUKS2), 32);
	FAIL_(crypt_token_max(CRYPT_LUKS1), "No token support in LUKS1");
	FAIL_(crypt_token_max(NULL), "No LUKS format specified");
	_cleanup_dmdevices();
}

static void LuksConvert(void)
{
	uint64_t offset, r_payload_offset;

	const char *json = "{\"type\":\"convert_block\",\"keyslots\":[]}";
	const struct crypt_pbkdf_type argon = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha512",
		.time_ms = 1,
		.max_memory_kb = 1024,
		.parallel_threads = 1
	}, pbkdf2 = {
		.type = CRYPT_KDF_PBKDF2,
		.hash = "sha256",
		.time_ms = 1
	};

	struct crypt_params_luks1 luks1 = {
		.hash = "sha256",
		.data_device = DMDIR L_DEVICE_1S
	};

	struct crypt_params_luks2 luks2 = {
		.pbkdf = &pbkdf2,
		.sector_size = 512
	};

	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

	// prepare the device
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, NULL, 32, NULL));
	offset = crypt_get_data_offset(cd);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 7);
	CRYPT_FREE(cd);

	// convert LUKSv1 -> LUKSv2
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "format is already LUKSv1");
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	FAIL_(crypt_convert(cd, CRYPT_LUKS2, NULL), "device is active");
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS1));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS2));
	CRYPT_FREE(cd);

	// check result
	OK_(crypt_init(&cd, DEVICE_1));
	FAIL_(crypt_load(cd, CRYPT_LUKS1, NULL), "wrong luks format");
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS2));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE1, strlen(PASSPHRASE1), 0), 7);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_convert(cd, CRYPT_LUKS2, NULL), "format is already LUKSv2");
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS2));
	CRYPT_FREE(cd);

	// convert LUKSv2 -> LUKSv1
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "device is active");
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS2));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS1));
	CRYPT_FREE(cd);

	// check result
	OK_(crypt_init(&cd, DEVICE_1));
	FAIL_(crypt_load(cd, CRYPT_LUKS2, NULL), "wrong luks format");
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS1));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE1, strlen(PASSPHRASE1), 0), 7);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "format is already LUKSv1");
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS1));
	CRYPT_FREE(cd);

	// exercise non-pbkdf2 LUKSv2 conversion
	if (!_fips_mode) {
		OK_(crypt_init(&cd, DEVICE_1));
		OK_(crypt_set_data_offset(cd, offset));
		OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
		OK_(crypt_set_pbkdf_type(cd, &argon));
		EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
		FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "Incompatible pbkdf with LUKSv1 format");
		CRYPT_FREE(cd);
	}

	// exercise non LUKS1 compatible keyslot
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_set_data_offset(cd, offset));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, &luks2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	// FIXME: following test fails as expected but for a different reason
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "Unassigned keyslots are incompatible with LUKSv1 format");
	CRYPT_FREE(cd);

	// exercise LUKSv2 conversion with single pbkdf2 keyslot being active
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_set_data_offset(cd, offset));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	offset = crypt_get_data_offset(cd);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	if (!_fips_mode) {
		OK_(crypt_set_pbkdf_type(cd, &argon));
		EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 1);
		FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "Different hash for digest and keyslot.");
		OK_(crypt_keyslot_destroy(cd, 1));
	}
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	CRYPT_FREE(cd);

	// do not allow conversion on keyslot No > 7
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_set_data_offset(cd, offset));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, &luks2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 8, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 8);
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "Can't convert keyslot No 8");
	CRYPT_FREE(cd);

	// do not allow conversion with token
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_set_data_offset(cd, offset));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, &luks2));
	OK_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, json));
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "Can't convert header with token.");
	CRYPT_FREE(cd);

	// should be enough for both luks1 and luks2 devices with all vk lengths
	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));

	// do not allow conversion for legacy luks1 device (non-aligned keyslot offset)
	OK_(_system("dd if=" CONV_DIR "/" CONV_L1_256_LEGACY " of=" DMDIR L_DEVICE_1S " bs=1M count=2 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	FAIL_(crypt_convert(cd, CRYPT_LUKS2, NULL), "Can't convert device with unaligned keyslot offset");
	CRYPT_FREE(cd);

	/*
	 * do not allow conversion on images if there's not enough space between
	 * last keyslot and data offset (should not happen on headers created
	 * with cryptsetup)
	 */
	OK_(_system("dd if=" CONV_DIR "/" CONV_L1_256_UNMOVABLE " of=" DMDIR L_DEVICE_1S " bs=1M count=2 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	FAIL_(crypt_convert(cd, CRYPT_LUKS2, NULL), "Can't convert device with unaligned keyslot offset");
	CRYPT_FREE(cd);

	// compat conversion tests
	// LUKS1 -> LUKS2

	// 128b key
	OK_(_system("dd if=" CONV_DIR "/" CONV_L1_128 " of=" DMDIR L_DEVICE_1S " bs=1M count=2 oflag=direct 2>/dev/null", 1));

	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS2), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 256b key
	OK_(_system("dd if=" CONV_DIR "/" CONV_L1_256 " of=" DMDIR L_DEVICE_1S " bs=1M count=2 oflag=direct 2>/dev/null", 1));

	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS2), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 512b key
	OK_(_system("dd if=" CONV_DIR "/" CONV_L1_512 " of=" DMDIR L_DEVICE_1S " bs=1M count=2 oflag=direct 2>/dev/null", 1));

	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS2), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// detached LUKS1 header conversion
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_128_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS2), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_128_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 256b key
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_256_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS2), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_256_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 512b key
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_512_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS2), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_512_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// LUKS2 -> LUKS1
	// 128b key
	OK_(_system("dd if=" CONV_DIR "/" CONV_L2_128 " of=" DMDIR L_DEVICE_1S " bs=1M count=4 oflag=direct 2>/dev/null", 1));

	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 128b all LUKS1 keyslots used
	OK_(_system("dd if=" CONV_DIR "/" CONV_L2_128_FULL " of=" DMDIR L_DEVICE_1S " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 1, PASS1, strlen(PASS1), 0), 1);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 2, PASS2, strlen(PASS2), 0), 2);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 3, PASS3, strlen(PASS3), 0), 3);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 4, PASS4, strlen(PASS4), 0), 4);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 5, PASS5, strlen(PASS5), 0), 5);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 6, PASS6, strlen(PASS6), 0), 6);
	CRYPT_FREE(cd);

	// 256b key
	OK_(_system("dd if=" CONV_DIR "/" CONV_L2_256 " of=" DMDIR L_DEVICE_1S " bs=1M count=4 oflag=direct 2>/dev/null", 1));

	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 256b all LUKS1 keyslots used
	OK_(_system("dd if=" CONV_DIR "/" CONV_L2_256_FULL " of=" DMDIR L_DEVICE_1S " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 1, PASS1, strlen(PASS1), 0), 1);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 2, PASS2, strlen(PASS2), 0), 2);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 3, PASS3, strlen(PASS3), 0), 3);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 4, PASS4, strlen(PASS4), 0), 4);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 5, PASS5, strlen(PASS5), 0), 5);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 6, PASS6, strlen(PASS6), 0), 6);
	CRYPT_FREE(cd);

	// 512b key
	OK_(_system("dd if=" CONV_DIR "/" CONV_L2_512 " of=" DMDIR L_DEVICE_1S " bs=1M count=4 oflag=direct 2>/dev/null", 1));

	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 512b all LUKS1 keyslots used
	OK_(_system("dd if=" CONV_DIR "/" CONV_L2_512_FULL " of=" DMDIR L_DEVICE_1S " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 1, PASS1, strlen(PASS1), 0), 1);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 2, PASS2, strlen(PASS2), 0), 2);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 3, PASS3, strlen(PASS3), 0), 3);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 4, PASS4, strlen(PASS4), 0), 4);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 5, PASS5, strlen(PASS5), 0), 5);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 6, PASS6, strlen(PASS6), 0), 6);
	CRYPT_FREE(cd);

	// detached headers
	// 128b
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_128_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_128_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 128b all LUKS1 keyslots used
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_128_DET_FULL));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_128_DET_FULL));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 1, PASS1, strlen(PASS1), 0), 1);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 2, PASS2, strlen(PASS2), 0), 2);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 3, PASS3, strlen(PASS3), 0), 3);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 4, PASS4, strlen(PASS4), 0), 4);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 5, PASS5, strlen(PASS5), 0), 5);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 6, PASS6, strlen(PASS6), 0), 6);
	CRYPT_FREE(cd);

	// 256b key
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_256_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_256_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 256b all LUKS1 keyslots used
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_256_DET_FULL));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_256_DET_FULL));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 1, PASS1, strlen(PASS1), 0), 1);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 2, PASS2, strlen(PASS2), 0), 2);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 3, PASS3, strlen(PASS3), 0), 3);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 4, PASS4, strlen(PASS4), 0), 4);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 5, PASS5, strlen(PASS5), 0), 5);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 6, PASS6, strlen(PASS6), 0), 6);
	CRYPT_FREE(cd);

	// 512b key
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_512_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_512_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	CRYPT_FREE(cd);

	// 512b all LUKS1 keyslots used
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_512_DET_FULL));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_512_DET_FULL));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 1, PASS1, strlen(PASS1), 0), 1);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 2, PASS2, strlen(PASS2), 0), 2);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 3, PASS3, strlen(PASS3), 0), 3);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 4, PASS4, strlen(PASS4), 0), 4);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 5, PASS5, strlen(PASS5), 0), 5);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 6, PASS6, strlen(PASS6), 0), 6);
	CRYPT_FREE(cd);

	// detached LUKS1 header upconversion
	OK_(create_dmdevice_over_loop(H_DEVICE, 2050)); // default LUKS1 header should fit there
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
	OK_(crypt_format(cd, CRYPT_LUKS1, "aes", "xts-plain64", NULL, NULL, 32, &luks1));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 7);
	FAIL_(crypt_convert(cd, CRYPT_LUKS2, NULL), "Unable to move keyslots. Not enough space.");
	CRYPT_FREE(cd);

	// 2050 sectors, empty file
	OK_(crypt_init(&cd, IMAGE_EMPTY_SMALL_2));
	OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
	OK_(crypt_format(cd, CRYPT_LUKS1, "aes", "xts-plain64", NULL, NULL, 32, &luks1));
	EQ_(crypt_get_data_offset(cd), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 7);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
}

static void Pbkdf(void)
{
	const struct crypt_pbkdf_type *pbkdf;

	const char *cipher = "aes", *mode="xts-plain64";
	struct crypt_pbkdf_type argon2 = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = default_luks1_hash,
		.time_ms = 6,
		.max_memory_kb = 1024,
		.parallel_threads = 1
	}, pbkdf2 = {
		.type = CRYPT_KDF_PBKDF2,
		.hash = default_luks1_hash,
		.time_ms = 9
	}, bad = {
		.type = "hamster_pbkdf",
		.hash = default_luks1_hash
	};
	struct crypt_params_plain params = {
		.hash = "sha256",
		.skip = 0,
		.offset = 0,
		.size = 0
	};
	struct crypt_params_luks1 luks1 = {
		.hash = "sha512", // test non-standard hash
		.data_alignment = 2048,
	};

	uint64_t r_payload_offset;

	/* Only PBKDF2 is allowed in FIPS, these tests cannot be run. */
	if (_fips_mode)
		return;

	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1));

	NULL_(crypt_get_pbkdf_type_params(NULL));
	NULL_(crypt_get_pbkdf_type_params("suslik"));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type_params(CRYPT_KDF_PBKDF2));
	OK_(strcmp(pbkdf->type, CRYPT_KDF_PBKDF2));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type_params(CRYPT_KDF_ARGON2I));
	OK_(strcmp(pbkdf->type, CRYPT_KDF_ARGON2I));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type_params(CRYPT_KDF_ARGON2ID));
	OK_(strcmp(pbkdf->type, CRYPT_KDF_ARGON2ID));

	// test empty context
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	NULL_(crypt_get_pbkdf_type(cd));
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	NOTNULL_(crypt_get_pbkdf_type(cd));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	NOTNULL_(crypt_get_pbkdf_type(cd));
	OK_(crypt_set_pbkdf_type(cd, NULL));
	NOTNULL_(crypt_get_pbkdf_type(cd));

	// test plain device
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, mode, NULL, NULL, 32, &params));
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	OK_(crypt_set_pbkdf_type(cd, NULL));
	NOTNULL_(crypt_get_pbkdf_type(cd));
	CRYPT_FREE(cd);

	// test LUKSv1 device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, mode, NULL, NULL, 32, NULL));
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Unsupported with non-LUKS2 devices");
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	OK_(crypt_set_pbkdf_type(cd, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, default_luks1_iter_time);
	CRYPT_FREE(cd);
	// test value set in crypt_set_iteration_time() can be obtained via following crypt_get_pbkdf_type()
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	crypt_set_iteration_time(cd, 42);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, mode, NULL, NULL, 32, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, 42);
	// test crypt_get_pbkdf_type() returns expected values for LUKSv1
	OK_(strcmp(pbkdf->type, CRYPT_KDF_PBKDF2));
	OK_(strcmp(pbkdf->hash, default_luks1_hash));
	EQ_(pbkdf->max_memory_kb, 0);
	EQ_(pbkdf->parallel_threads, 0);
	crypt_set_iteration_time(cd, 43);
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, 43);
	CRYPT_FREE(cd);
	// test whether crypt_get_pbkdf_type() after double crypt_load()
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	crypt_set_iteration_time(cd, 42);
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, 42);
	CRYPT_FREE(cd);
	// test whether hash passed via *params in crypt_load() has higher priority
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, mode, NULL, NULL, 32, &luks1));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->hash, luks1.hash));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->hash, luks1.hash));
	CRYPT_FREE(cd);

	// test LUKSv2 device
	// test default values are set
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, mode, NULL, NULL, 32, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, default_luks2_pbkdf));
	OK_(strcmp(pbkdf->hash, default_luks1_hash));
	EQ_(pbkdf->time_ms, default_luks2_iter_time);
	GE_(pbkdf->max_memory_kb, 64 * 1024);
	GE_(adjusted_pbkdf_memory(), pbkdf->max_memory_kb);
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), default_luks2_parallel_threads));
	// set and verify argon2 type
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, argon2.type));
	OK_(strcmp(pbkdf->hash, argon2.hash));
	EQ_(pbkdf->time_ms, argon2.time_ms);
	EQ_(pbkdf->max_memory_kb, argon2.max_memory_kb);
	EQ_(pbkdf->parallel_threads, argon2.parallel_threads);
	// set and verify pbkdf2 type
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, pbkdf2.type));
	OK_(strcmp(pbkdf->hash, pbkdf2.hash));
	EQ_(pbkdf->time_ms, pbkdf2.time_ms);
	EQ_(pbkdf->max_memory_kb, pbkdf2.max_memory_kb);
	EQ_(pbkdf->parallel_threads, pbkdf2.parallel_threads);
	// reset and verify default values
	crypt_set_iteration_time(cd, 1); // it's supposed to override this call
	OK_(crypt_set_pbkdf_type(cd, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, default_luks2_pbkdf));
	OK_(strcmp(pbkdf->hash, default_luks1_hash));
	EQ_(pbkdf->time_ms, default_luks2_iter_time);
	GE_(pbkdf->max_memory_kb, 64 * 1024);
	GE_(adjusted_pbkdf_memory(), pbkdf->max_memory_kb);
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), default_luks2_parallel_threads));
	// try to pass illegal values
	argon2.parallel_threads = 0;
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Parallel threads can't be 0");
	argon2.parallel_threads = 99;
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Parallel threads can't be higher than maximum");
	argon2.parallel_threads = 1;
	argon2.max_memory_kb = 0;
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Memory can't be 0");
	argon2.max_memory_kb = 1024;
	pbkdf2.parallel_threads = 1;
	FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Parallel threads can't be set with pbkdf2 type");
	pbkdf2.parallel_threads = 0;
	pbkdf2.max_memory_kb = 512;
	FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Memory can't be set with pbkdf2 type");
	FAIL_(crypt_set_pbkdf_type(cd, &bad), "Unknown type member");
	bad.type = CRYPT_KDF_PBKDF2;
	bad.hash = NULL;
	FAIL_(crypt_set_pbkdf_type(cd, &bad), "Hash member is empty");
	bad.type = NULL;
	bad.hash = default_luks1_hash;
	FAIL_(crypt_set_pbkdf_type(cd, &bad), "Pbkdf type member is empty");
	bad.hash = "hamster_hash";
	FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Unknown hash member");
	CRYPT_FREE(cd);
	// test whether crypt_get_pbkdf_type() behaves accordingly after second crypt_load() call
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, default_luks2_pbkdf));
	OK_(strcmp(pbkdf->hash, default_luks1_hash));
	EQ_(pbkdf->time_ms, default_luks2_iter_time);
	GE_(pbkdf->max_memory_kb, 64 * 1024);
	GE_(adjusted_pbkdf_memory(), pbkdf->max_memory_kb);
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), default_luks2_parallel_threads));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	OK_(strcmp(pbkdf->type, default_luks2_pbkdf));
	OK_(strcmp(pbkdf->hash, default_luks1_hash));
	EQ_(pbkdf->time_ms, 1);
	GE_(pbkdf->max_memory_kb, 64 * 1024);
	GE_(adjusted_pbkdf_memory(), pbkdf->max_memory_kb);
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), default_luks2_parallel_threads));
	CRYPT_FREE(cd);

	// test crypt_set_pbkdf_type() overwrites invalid value set by crypt_set_iteration_time()
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	crypt_set_iteration_time(cd, 0);
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, argon2.type));
	EQ_(pbkdf->time_ms, argon2.time_ms);

	// force iterations
	argon2.iterations = 33;
	argon2.flags = CRYPT_PBKDF_NO_BENCHMARK;
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->iterations, 33);
	EQ_(pbkdf->flags, CRYPT_PBKDF_NO_BENCHMARK);

	// time may be unset with iterations
	argon2.time_ms = 0;
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	argon2.flags &= ~CRYPT_PBKDF_NO_BENCHMARK;
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Illegal time value.");

	pbkdf2.time_ms = 0;
	pbkdf2.flags = CRYPT_PBKDF_NO_BENCHMARK;
	pbkdf2.parallel_threads = 0;
	pbkdf2.max_memory_kb = 0;
	pbkdf2.iterations = 1000;
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	pbkdf2.flags &= ~CRYPT_PBKDF_NO_BENCHMARK;
	FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Illegal time value.");

	// hash is relevant only with pbkdf2
	pbkdf2.time_ms = 9;
	pbkdf2.hash = NULL;
	FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Hash is mandatory for pbkdf2");
	pbkdf2.hash = "sha256";
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));

	argon2.time_ms = 9;
	argon2.hash = "sha256"; // will be ignored
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	argon2.hash = NULL;
	OK_(crypt_set_pbkdf_type(cd, &argon2));

	argon2.flags = CRYPT_PBKDF_NO_BENCHMARK;
	argon2.max_memory_kb = 2 * 1024 * 1024;
	argon2.iterations = 6;
	argon2.parallel_threads = 4;
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->iterations, 6);
	EQ_(pbkdf->max_memory_kb, 2 * 1024 *1024);
	EQ_(pbkdf->parallel_threads, 4); /* hard maximum*/
	EQ_(pbkdf->flags, CRYPT_PBKDF_NO_BENCHMARK);

	CRYPT_FREE(cd);

	NOTNULL_(pbkdf = crypt_get_pbkdf_default(CRYPT_LUKS1));
	OK_(strcmp(pbkdf->type, CRYPT_KDF_PBKDF2));
	EQ_(pbkdf->time_ms, default_luks1_iter_time);
	OK_(strcmp(pbkdf->hash, default_luks1_hash));
	EQ_(pbkdf->max_memory_kb, 0);
	EQ_(pbkdf->parallel_threads, 0);

	NOTNULL_(pbkdf = crypt_get_pbkdf_default(CRYPT_LUKS2));
	OK_(strcmp(pbkdf->type, default_luks2_pbkdf));
	EQ_(pbkdf->time_ms, default_luks2_iter_time);
	OK_(strcmp(pbkdf->hash, default_luks1_hash));
	EQ_(pbkdf->max_memory_kb, default_luks2_memory_kb);
	EQ_(pbkdf->parallel_threads, default_luks2_parallel_threads);

	NULL_(pbkdf = crypt_get_pbkdf_default(CRYPT_PLAIN));

	_cleanup_dmdevices();
}

static void Luks2KeyslotAdd(void)
{
	char key[128], key2[128], key_ret[128];
	const char *cipher = "aes", *cipher_mode="xts-plain64";
	const char *vk_hex =  "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	const char *vk_hex2 = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1e";
	size_t key_ret_len, key_size = strlen(vk_hex) / 2;
	uint64_t r_payload_offset;
	struct crypt_pbkdf_type pbkdf = {
		.type = "argon2i",
		.hash = "sha256",
		.iterations = 4,
		.max_memory_kb = 32,
		.parallel_threads = 1,
		.flags = CRYPT_PBKDF_NO_BENCHMARK,
	};
	struct crypt_params_luks2 params2 = {
		.pbkdf = &pbkdf,
		.sector_size = TST_SECTOR_SIZE
	};

	OK_(crypt_decode_key(key, vk_hex, key_size));
	OK_(crypt_decode_key(key2, vk_hex2, key_size));

	/* Cannot use Argon2 in FIPS */
	if (_fips_mode) {
		pbkdf.type = CRYPT_KDF_PBKDF2;
		pbkdf.parallel_threads = 0;
		pbkdf.max_memory_kb = 0;
		pbkdf.iterations = 1000;
	}

	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1));

	/* test crypt_keyslot_add_by_key */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params2));
	EQ_(crypt_keyslot_add_by_key(cd, 1, key2, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, key, key_size, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_status(cd, 0), CRYPT_SLOT_ACTIVE_LAST);
	EQ_(crypt_keyslot_status(cd, 1), CRYPT_SLOT_UNBOUND);
	/* drop the generated volume key from device context cache */
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	/* must not activate volume with keyslot unassigned to a segment */
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key2, key_size, 0), "Key doesn't match volume key digest");
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, PASSPHRASE1, strlen(PASSPHRASE1), 0), "Keyslot not assigned to volume");
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE1, strlen(PASSPHRASE1), 0), "No keyslot assigned to volume with this passphrase");
	/* unusable for volume activation even in test mode */
	FAIL_(crypt_activate_by_volume_key(cd, NULL, key2, key_size, 0), "Key doesn't match volume key digest");
	/* otoh passphrase check should pass */
	EQ_(crypt_activate_by_passphrase(cd, NULL, 1, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), 1);
	EQ_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), 1);
	/* in general crypt_keyslot_add_by_key must allow any reasonable key size
	 * even though such keyslot will not be usable for segment encryption */
	EQ_(crypt_keyslot_add_by_key(cd, 2, key2, key_size-1, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 2);
	/* As per SP800-132 112 bits (14 bytes) is minimal key length */
	EQ_(crypt_keyslot_add_by_key(cd, 3, key2, 14, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 3);

	FAIL_(crypt_keyslot_get_key_size(cd, CRYPT_ANY_SLOT), "Bad keyslot specification.");
	EQ_(crypt_get_volume_key_size(cd), key_size);
	EQ_(crypt_keyslot_get_key_size(cd, 0), key_size);
	EQ_(crypt_keyslot_get_key_size(cd, 1), key_size);
	EQ_(crypt_keyslot_get_key_size(cd, 2), key_size-1);
	EQ_(crypt_keyslot_get_key_size(cd, 3), 14);

	key_ret_len = key_size - 1;
	FAIL_(crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key_ret, &key_ret_len, PASSPHRASE1, strlen(PASSPHRASE1)), "Wrong size");

	key_ret_len = 14;
	FAIL_(crypt_volume_key_get(cd, 2, key_ret, &key_ret_len, PASSPHRASE1, strlen(PASSPHRASE1)), "wrong size");
	EQ_(crypt_volume_key_get(cd, 3, key_ret, &key_ret_len, PASSPHRASE1, strlen(PASSPHRASE1)), 3);
	FAIL_(crypt_activate_by_volume_key(cd, NULL, key_ret, key_ret_len, 0), "Not a volume key");
	key_ret_len = key_size;
	EQ_(crypt_volume_key_get(cd, 1, key_ret, &key_ret_len, PASSPHRASE1, strlen(PASSPHRASE1)), 1);

	/* test force volume key change works as expected */
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 0, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_SET), 1);
	OK_(crypt_activate_by_volume_key(cd, NULL, key2, key_size, 0));
	OK_(crypt_activate_by_volume_key(cd, NULL, key_ret, key_ret_len, 0));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key2, key_size, 0));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_passphrase(cd, NULL, 1, PASSPHRASE1, strlen(PASSPHRASE1), 0), 1);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, PASSPHRASE1, strlen(PASSPHRASE1), 0), 1);
	/* check we can resume device with new volume key */
	OK_(crypt_suspend(cd, CDEVICE_1));
	EQ_(crypt_resume_by_passphrase(cd, CDEVICE_1, 1, PASSPHRASE1, strlen(PASSPHRASE1)), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	/* old keyslot must be unusable */
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Key doesn't match volume key digest");
	FAIL_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0), "Key doesn't match volume key digest");
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), 0), "Keyslot not assigned to volume");
	EQ_(crypt_keyslot_add_by_passphrase(cd, 5, PASSPHRASE1, strlen(PASSPHRASE1), PASSPHRASE1, strlen(PASSPHRASE1)), 5);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 6, key2, key_size, PASSPHRASE1, strlen(PASSPHRASE1)), 6);
	/* regression test. check new keyslot is properly assigned to new volume key digest */
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 5, PASSPHRASE1, strlen(PASSPHRASE1), 0), 5);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 6, PASSPHRASE1, strlen(PASSPHRASE1), 0), 6);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params2));
	/* keyslot 0, volume key, digest 0 */
	EQ_(crypt_keyslot_add_by_key(cd, 0, key, key_size, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	 /* keyslot 1, unbound key, digest 1 */
	EQ_(crypt_keyslot_add_by_key(cd, 1, key2, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	 /* keyslot 2, unbound key, digest 1 */
	EQ_(crypt_keyslot_add_by_key(cd, 2, key2, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT | CRYPT_VOLUME_KEY_DIGEST_REUSE), 2);
	 /* keyslot 3, unbound key, digest 2 */
	EQ_(crypt_keyslot_add_by_key(cd, 3, key2, key_size - 1, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT | CRYPT_VOLUME_KEY_DIGEST_REUSE), 3);
	 /* keyslot 4, unbound key, digest 1 */
	EQ_(crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, key2, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT | CRYPT_VOLUME_KEY_DIGEST_REUSE), 4);
	FAIL_(crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, key, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT | CRYPT_VOLUME_KEY_SET), "Illegal");
	FAIL_(crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, key, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT | CRYPT_VOLUME_KEY_SET | CRYPT_VOLUME_KEY_DIGEST_REUSE), "Illegal");
	/* Such key doesn't exist, nothing to reuse */
	FAIL_(crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, key2, key_size - 2, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_DIGEST_REUSE), "Key digest doesn't match any existing.");
	/* Keyslot 5, volume key, digest 0 */
	EQ_(crypt_keyslot_add_by_key(cd, 5, key, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_DIGEST_REUSE), 5);

	OK_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0));
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_SET), 1);
	OK_(crypt_activate_by_volume_key(cd, NULL, key2, key_size, 0));
	FAIL_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0), "Not a volume key");
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, PASSPHRASE1, strlen(PASSPHRASE1), 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 2, PASSPHRASE1, strlen(PASSPHRASE1), 0), 2);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), 0), "No volume key keyslot");

	/* TODO: key is unusable with aes-xts */
	// FAIL_(crypt_keyslot_add_by_key(cd, 3, NULL, 0, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_SET), "Unusable key with segment cipher");

	EQ_(crypt_keyslot_add_by_key(cd, 5, NULL, 0, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_SET), 5);
	FAIL_(crypt_activate_by_volume_key(cd, NULL, key2, key_size, 0), "Not a volume key");
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 5, PASSPHRASE1, strlen(PASSPHRASE1), 0), 5);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	CRYPT_FREE(cd);

	_cleanup_dmdevices();
}

static void Luks2KeyslotParams(void)
{
	char key[128], key2[128];
	const char *cipher = "aes", *cipher_mode="xts-plain64";
	const char *cipher_spec = "aes-xts-plain64", *cipher_keyslot = "aes-cbc-essiv:sha256";
	const char *vk_hex =  "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	const char *vk_hex2 = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1e";
	size_t key_size_ret, key_size = strlen(vk_hex) / 2, keyslot_key_size = 16;
	uint64_t r_payload_offset;

	OK_(crypt_decode_key(key, vk_hex, key_size));
	OK_(crypt_decode_key(key2, vk_hex2, key_size));

	OK_(prepare_keyfile(KEYFILE1, PASSPHRASE, strlen(PASSPHRASE)));
	OK_(prepare_keyfile(KEYFILE2, PASSPHRASE1, strlen(PASSPHRASE1)));

	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1));

	EQ_(key_size, 2 * keyslot_key_size);
	/* test crypt_keyslot_add_by_key */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	NULL_(crypt_keyslot_get_encryption(cd, 0, &key_size_ret));
	OK_(strcmp(crypt_keyslot_get_encryption(cd, CRYPT_ANY_SLOT, &key_size_ret), cipher_spec));
	EQ_(key_size_ret, key_size);

	// Normal slots
	EQ_(0, crypt_keyslot_add_by_volume_key(cd, 0, key, key_size, PASSPHRASE, strlen(PASSPHRASE)));
	EQ_(1, crypt_keyslot_add_by_passphrase(cd, 1, PASSPHRASE, strlen(PASSPHRASE), PASSPHRASE1,strlen(PASSPHRASE1)));
	EQ_(2, crypt_keyslot_add_by_key(cd, 2, key2, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT));
	EQ_(6, crypt_keyslot_add_by_keyfile(cd, 6, KEYFILE1, 0, KEYFILE2, 0));

	// Slots with different encryption type
	OK_(crypt_keyslot_set_encryption(cd, cipher_keyslot, keyslot_key_size));
	OK_(strcmp(crypt_keyslot_get_encryption(cd, CRYPT_ANY_SLOT, &key_size_ret), cipher_keyslot));
	EQ_(key_size_ret, keyslot_key_size);

	EQ_(3, crypt_keyslot_add_by_volume_key(cd, 3, key, key_size, PASSPHRASE, strlen(PASSPHRASE)));
	EQ_(4, crypt_keyslot_add_by_passphrase(cd, 4, PASSPHRASE, strlen(PASSPHRASE), PASSPHRASE1,strlen(PASSPHRASE1)));
	EQ_(5, crypt_keyslot_add_by_key(cd, 5, key2, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT));
	EQ_(7, crypt_keyslot_add_by_keyfile(cd, 7, KEYFILE1, 0, KEYFILE2, 0));

	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));

	EQ_(crypt_keyslot_status(cd, 0), CRYPT_SLOT_ACTIVE);
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 0, &key_size_ret), cipher_spec));
	EQ_(key_size_ret, key_size);

	EQ_(crypt_keyslot_status(cd, 1), CRYPT_SLOT_ACTIVE);
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 1, &key_size_ret), cipher_spec));
	EQ_(key_size_ret, key_size);

	EQ_(crypt_keyslot_status(cd, 2), CRYPT_SLOT_UNBOUND);
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 2, &key_size_ret), cipher_spec));
	EQ_(key_size_ret, key_size);

	EQ_(crypt_keyslot_status(cd, 6), CRYPT_SLOT_ACTIVE);
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 6, &key_size_ret), cipher_spec));
	EQ_(key_size_ret, key_size);

	EQ_(crypt_keyslot_status(cd, 3), CRYPT_SLOT_ACTIVE);
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 3, &key_size_ret), cipher_keyslot));
	EQ_(key_size_ret, keyslot_key_size);

	EQ_(crypt_keyslot_status(cd, 4), CRYPT_SLOT_ACTIVE);
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 4, &key_size_ret), cipher_keyslot));
	EQ_(key_size_ret, keyslot_key_size);

	EQ_(crypt_keyslot_status(cd, 5), CRYPT_SLOT_UNBOUND);
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 5, &key_size_ret), cipher_keyslot));
	EQ_(key_size_ret, keyslot_key_size);

	EQ_(crypt_keyslot_status(cd, 7), CRYPT_SLOT_ACTIVE);
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 7, &key_size_ret), cipher_keyslot));
	EQ_(key_size_ret, keyslot_key_size);

	OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
	EQ_(8, crypt_keyslot_change_by_passphrase(cd, 1, 8, PASSPHRASE1, strlen(PASSPHRASE1), PASSPHRASE, strlen(PASSPHRASE)));
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 8, &key_size_ret), cipher_spec));
	EQ_(key_size_ret, key_size);

	/* Revert to default */
	EQ_(9, crypt_keyslot_change_by_passphrase(cd, 5, 9, PASSPHRASE1, strlen(PASSPHRASE1), PASSPHRASE, strlen(PASSPHRASE)));
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 9, &key_size_ret), cipher_spec));
	EQ_(key_size_ret, key_size);

	/* Set new encryption params */
	OK_(crypt_keyslot_set_encryption(cd, cipher_keyslot, keyslot_key_size));

	EQ_(1, crypt_keyslot_change_by_passphrase(cd, 8, 1, PASSPHRASE, strlen(PASSPHRASE), PASSPHRASE1, strlen(PASSPHRASE1)));
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 1, &key_size_ret), cipher_keyslot));
	EQ_(key_size_ret, keyslot_key_size);

	EQ_(10, crypt_keyslot_change_by_passphrase(cd, 2, 10, PASSPHRASE1, strlen(PASSPHRASE1), PASSPHRASE, strlen(PASSPHRASE)));
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 10, &key_size_ret), cipher_keyslot));
	EQ_(key_size_ret, keyslot_key_size);

	EQ_(0, crypt_keyslot_change_by_passphrase(cd, 0, 0, PASSPHRASE, strlen(PASSPHRASE), PASSPHRASE1, strlen(PASSPHRASE1)));
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 0, &key_size_ret), cipher_keyslot));
	EQ_(key_size_ret, keyslot_key_size);

	CRYPT_FREE(cd);

	/* LUKS1 compatible calls */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, NULL));
	NULL_(crypt_keyslot_get_encryption(cd, 0, &key_size_ret));
	OK_(strcmp(crypt_keyslot_get_encryption(cd, CRYPT_ANY_SLOT, &key_size_ret), cipher_spec));
	EQ_(key_size_ret, key_size);
	EQ_(0, crypt_keyslot_add_by_volume_key(cd, 0, key, key_size, PASSPHRASE, strlen(PASSPHRASE)));
	OK_(strcmp(crypt_keyslot_get_encryption(cd, 0, &key_size_ret), cipher_spec));
	EQ_(key_size_ret, key_size);
	CRYPT_FREE(cd);

	/* LUKS2 cipher null checks */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_set_pbkdf_type(cd, &min_pbkdf2));
	OK_(crypt_format(cd, CRYPT_LUKS2, "cipher_null", "ecb", NULL, key, key_size, NULL));
	FAIL_(crypt_keyslot_set_encryption(cd, "null", 32), "cipher null is not allowed");
	FAIL_(crypt_keyslot_set_encryption(cd, "cipher_null", 32), "cipher null is not allowed");
	FAIL_(crypt_keyslot_set_encryption(cd, "cipher_null-ecb", 32), "cipher null is not allowed");
	EQ_(0, crypt_keyslot_add_by_volume_key(cd, 0, key, key_size, PASSPHRASE, strlen(PASSPHRASE)));
	NOTNULL_(crypt_keyslot_get_encryption(cd, 0, &key_size_ret));
	NULL_(strstr(crypt_keyslot_get_encryption(cd, 0, &key_size_ret), "null"));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
	_remove_keyfiles();
}

static void Luks2ActivateByKeyring(void)
{
#if KERNEL_KEYRING

	key_serial_t kid, kid1;
	uint64_t r_payload_offset;

	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

	if (!t_dm_crypt_keyring_support()) {
		printf("WARNING: Kernel keyring not supported, skipping test.\n");
		return;
	}

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");
	kid1 = add_key("user", KEY_DESC_TEST1, PASSPHRASE1, strlen(PASSPHRASE1), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid1, "Test or kernel keyring are broken.");

	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1));

	// prepare the device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 2, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 2);
	CRYPT_FREE(cd);

	// FIXME: all following tests work as expected but most error messages are missing
	// check activate by keyring works exactly same as by passphrase
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, 0, 0), 0);
	EQ_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST0, 0, 0), 0);
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	FAIL_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST0, 0, 0), "already open");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	EQ_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST1, 1, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), 1);
	EQ_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST1, 2, 0), 2);
	FAIL_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST1, 1, 0), "Keyslot not assigned to volume");
	EQ_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST1, 2, 0), 2);
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST1, CRYPT_ANY_SLOT, 0), 2);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, 2, 0), "Failed to unclock keyslot");
	FAIL_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST1, 0, 0), "Failed to unclock keyslot");
	CRYPT_FREE(cd);

	NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");
	NOTFAIL_(keyctl_unlink(kid1, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	FAIL_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, CRYPT_ANY_SLOT, 0), "no such key in keyring");
	FAIL_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST0, CRYPT_ANY_SLOT, 0), "no such key in keyring");
	FAIL_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST1, 2, 0), "no such key in keyring");
	FAIL_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST1, 1, 0), "no such key in keyring");
	CRYPT_FREE(cd);
	_cleanup_dmdevices();
#else
	printf("WARNING: cryptsetup compiled with kernel keyring service disabled, skipping test.\n");
#endif
}

static void Luks2Requirements(void)
{
	int r;
	char key[128];
	size_t key_size = 128;
	const struct crypt_pbkdf_type *pbkdf;
#if KERNEL_KEYRING
	key_serial_t kid;
#endif
	uint32_t flags;
	uint64_t dummy, r_payload_offset;
	struct crypt_active_device cad;

	const char *token, *json = "{\"type\":\"test_token\",\"keyslots\":[]}";
	struct crypt_pbkdf_type argon2 = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = default_luks1_hash,
		.time_ms = 6,
		.max_memory_kb = 1024,
		.parallel_threads = 1
	}, pbkdf2 = {
		.type = CRYPT_KDF_PBKDF2,
		.hash = default_luks1_hash,
		.time_ms = 9
	};
	struct crypt_token_params_luks2_keyring params_get, params = {
		.key_description = KEY_DESC_TEST0
	};

	OK_(prepare_keyfile(KEYFILE1, PASSPHRASE, strlen(PASSPHRASE)));
	OK_(prepare_keyfile(KEYFILE2, PASSPHRASE1, strlen(PASSPHRASE1)));

	/* crypt_load (unrestricted) */
	OK_(crypt_init(&cd, DEVICE_5));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DEVICE_5));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));

	/* crypt_dump (unrestricted) */
	reset_log();
	OK_(crypt_dump(cd));
	OK_(!(global_lines != 0));
	reset_log();

	/* get & set pbkdf params (unrestricted) */
	if (!_fips_mode) {
		OK_(crypt_set_pbkdf_type(cd, &argon2));
		NOTNULL_(crypt_get_pbkdf_type(cd));
	}

	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	NOTNULL_(crypt_get_pbkdf_type(cd));

	/* crypt_set_iteration_time (unrestricted) */
	crypt_set_iteration_time(cd, 1);
	pbkdf = crypt_get_pbkdf_type(cd);
	NOTNULL_(pbkdf);
	EQ_(pbkdf->time_ms, 1);

	/* crypt_convert (restricted) */
	FAIL_((r = crypt_convert(cd, CRYPT_LUKS1, NULL)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_set_uuid (restricted) */
	FAIL_((r = crypt_set_uuid(cd, NULL)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_set_label (restricted) */
	FAIL_((r = crypt_set_label(cd, "label", "subsystem")), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_get_label (unrestricted) */
	NOTNULL_(crypt_get_label(cd));
	OK_(strcmp("", crypt_get_label(cd)));
	/* crypt_get_subsystem (unrestricted) */
	NOTNULL_(crypt_get_subsystem(cd));
	OK_(strcmp("", crypt_get_subsystem(cd)));

	/* crypt_repair (with current repair capabilities it's unrestricted) */
	OK_(crypt_repair(cd, CRYPT_LUKS2, NULL));

	/* crypt_keyslot_add_passphrase (restricted) */
	FAIL_((r = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), "bbb", 3)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_change_by_passphrase (restricted) */
	FAIL_((r = crypt_keyslot_change_by_passphrase(cd, CRYPT_ANY_SLOT, 9, PASSPHRASE, strlen(PASSPHRASE), "bbb", 3)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_add_by_keyfile (restricted) */
	FAIL_((r = crypt_keyslot_add_by_keyfile(cd, CRYPT_ANY_SLOT, KEYFILE1, 0, KEYFILE2, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_add_by_keyfile_offset (restricted) */
	FAIL_((r = crypt_keyslot_add_by_keyfile_offset(cd, CRYPT_ANY_SLOT, KEYFILE1, 0, 0, KEYFILE2, 0, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_volume_key_get (unrestricted, but see below) */
	OK_(crypt_volume_key_get(cd, 0, key, &key_size, PASSPHRASE, strlen(PASSPHRASE)));

	/* crypt_keyslot_add_by_volume_key (restricted) */
	FAIL_((r = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, key, key_size, PASSPHRASE1, strlen(PASSPHRASE1))), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_add_by_key (restricted) */
	FAIL_((r = crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, NULL, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_add_by_key (restricted) */
	FAIL_((r = crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, key, key_size, PASSPHRASE1, strlen(PASSPHRASE1), 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_persistent_flasgs_set (restricted) */
	FAIL_((r = crypt_persistent_flags_set(cd, CRYPT_FLAGS_ACTIVATION, CRYPT_ACTIVATE_ALLOW_DISCARDS)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_persistent_flasgs_get (unrestricted) */
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &flags));
	EQ_(flags, CRYPT_REQUIREMENT_UNKNOWN);

	/* crypt_activate_by_passphrase (restricted for activation only) */
	FAIL_((r = crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	OK_(crypt_activate_by_passphrase(cd, NULL, 0, PASSPHRASE, strlen(PASSPHRASE), 0));
	OK_(crypt_activate_by_passphrase(cd, NULL, 0, PASSPHRASE, strlen(PASSPHRASE), t_dm_crypt_keyring_support() ? CRYPT_ACTIVATE_KEYRING_KEY : 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);

	/* crypt_activate_by_keyfile (restricted for activation only) */
	FAIL_((r = crypt_activate_by_keyfile(cd, CDEVICE_1, 0, KEYFILE1, 0, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	OK_(crypt_activate_by_keyfile(cd, NULL, 0, KEYFILE1, 0, 0));
	OK_(crypt_activate_by_keyfile(cd, NULL, 0, KEYFILE1, 0, t_dm_crypt_keyring_support() ? CRYPT_ACTIVATE_KEYRING_KEY : 0));

	/* crypt_activate_by_volume_key (restricted for activation only) */
	FAIL_((r = crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	OK_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0));
	OK_(crypt_activate_by_volume_key(cd, NULL, key, key_size, t_dm_crypt_keyring_support() ? CRYPT_ACTIVATE_KEYRING_KEY : 0));

#if KERNEL_KEYRING
	if (t_dm_crypt_keyring_support()) {
		kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
		NOTFAIL_(kid, "Test or kernel keyring are broken.");

		/* crypt_activate_by_keyring (restricted for activation only) */
		FAIL_((r = crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST0, 0, 0)), "Unmet requirements detected");
		EQ_(r, t_dm_crypt_keyring_support() ? -ETXTBSY : -EINVAL);
		OK_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, 0, 0));
		OK_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, 0, CRYPT_ACTIVATE_KEYRING_KEY));

		NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");
	}
#endif

	/* crypt_volume_key_verify (unrestricted) */
	OK_(crypt_volume_key_verify(cd, key, key_size));

	/* crypt_get_cipher (unrestricted) */
	OK_(strcmp(crypt_get_cipher(cd)?:"", "aes"));

	/* crypt_get_cipher_mode (unrestricted) */
	OK_(strcmp(crypt_get_cipher_mode(cd)?:"", "xts-plain64"));

	/* crypt_get_uuid (unrestricted) */
	NOTNULL_(crypt_get_uuid(cd));

	/* crypt_get_device_name (unrestricted) */
	NOTNULL_(crypt_get_device_name(cd));

	/* crypt_get_data_offset (unrestricted) */
	OK_(!crypt_get_data_offset(cd));

	/* crypt_get_iv_offset (unrestricted, nothing to test) */

	/* crypt_get_volume_key_size (unrestricted) */
	EQ_(crypt_get_volume_key_size(cd), key_size);

	/* crypt_keyslot_status (unrestricted) */
	EQ_(crypt_keyslot_status(cd, 0), CRYPT_SLOT_ACTIVE_LAST);
	EQ_(crypt_keyslot_status(cd, 1), CRYPT_SLOT_INACTIVE);

	/* crypt_keyslot_get_priority (unrestricted) */
	EQ_(crypt_keyslot_get_priority(cd, 0), CRYPT_SLOT_PRIORITY_NORMAL);

	/* crypt_keyslot_set_priority (restricted) */
	FAIL_((r = crypt_keyslot_set_priority(cd, 0, CRYPT_SLOT_PRIORITY_PREFER)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_area (unrestricted) */
	OK_(crypt_keyslot_area(cd, 0, &dummy, &dummy));
	OK_(!dummy);

	/* crypt_header_backup (unrestricted) */
	remove(BACKUP_FILE);
	OK_(crypt_header_backup(cd, CRYPT_LUKS, BACKUP_FILE));

	/* crypt_header_restore (restricted, do not drop the test until we have safe option) */
	FAIL_((r = crypt_header_restore(cd, CRYPT_LUKS2, BACKUP_FILE)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	remove(BACKUP_FILE);

	/* crypt_token_json_set (restricted) */
	FAIL_((r = crypt_token_json_set(cd, CRYPT_ANY_TOKEN, json)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_token_json_get (unrestricted) */
	OK_(crypt_token_json_get(cd, 0, &token));
	NOTNULL_(strstr(token, "user_type"));

	/* crypt_token_status (unrestricted) */
	EQ_(crypt_token_status(cd, 0, &token), CRYPT_TOKEN_EXTERNAL_UNKNOWN);
	OK_(strcmp(token, "user_type"));
	EQ_(crypt_token_status(cd, 1, &token), CRYPT_TOKEN_INTERNAL);
	OK_(strcmp(token, "luks2-keyring"));
	EQ_(crypt_token_status(cd, 2, NULL), CRYPT_TOKEN_INACTIVE);
	EQ_(crypt_token_status(cd, 6, &token), CRYPT_TOKEN_INTERNAL_UNKNOWN);

	/* crypt_token_luks2_keyring_set (restricted) */
	FAIL_((r = crypt_token_luks2_keyring_set(cd, CRYPT_ANY_TOKEN, &params)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_token_luks2_keyring_get (unrestricted) */
	EQ_(crypt_token_luks2_keyring_get(cd, 1, &params_get), 1);
	OK_(strcmp(params_get.key_description, KEY_DESC_TEST0));

	/* crypt_token_assign_keyslot (unrestricted) */
	FAIL_((r = crypt_token_assign_keyslot(cd, 0, 1)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_token_unassign_keyslot (unrestricted) */
	FAIL_((r = crypt_token_unassign_keyslot(cd, CRYPT_ANY_TOKEN, CRYPT_ANY_SLOT)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_activate_by_token (restricted for activation only) */
#if KERNEL_KEYRING
	if (t_dm_crypt_keyring_support()) {
		kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
		NOTFAIL_(kid, "Test or kernel keyring are broken.");

		FAIL_((r = crypt_activate_by_token(cd, CDEVICE_1, 1, NULL, 0)), ""); // supposed to be silent
		EQ_(r, -ETXTBSY);
		OK_(crypt_activate_by_token(cd, NULL, 1, NULL, 0));
		OK_(crypt_activate_by_token(cd, NULL, 1, NULL, CRYPT_ACTIVATE_KEYRING_KEY));

		NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");
	}
#endif
	OK_(get_luks2_offsets(0, 8192, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 2));
	//OK_(_system("dd if=" NO_REQS_LUKS2_HEADER " of=" NO_REQS_LUKS2_HEADER " bs=4096 2>/dev/null", 1));
	OK_(_system("dd if=" NO_REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));

	/* need to fake activated LUKSv2 device with requirements features */
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), 0));
	OK_(crypt_header_backup(cd, CRYPT_LUKS2, BACKUP_FILE));
	/* replace header with no requirements */
	OK_(_system("dd if=" REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	CRYPT_FREE(cd);

	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, DEVICE_5));
	CRYPT_FREE(cd);
	OK_(crypt_init_by_name(&cd, CDEVICE_1));

	/* crypt_header_restore (restricted with confirmation required) */
	/* allow force restore over device header w/ requirements */
	OK_(crypt_header_restore(cd, CRYPT_LUKS2, BACKUP_FILE));
	remove(BACKUP_FILE);
	OK_(_system("dd if=" REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_header_backup(cd, CRYPT_LUKS2, BACKUP_FILE)); /* create backup with requirements */

	/* crypt_suspend (restricted) */
	FAIL_((r = crypt_suspend(cd, CDEVICE_1)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	CRYPT_FREE(cd);

	/* replace header again to suspend the device */
	OK_(_system("dd if=" NO_REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	OK_(crypt_suspend(cd, CDEVICE_1));

	/* crypt_header_restore (restricted, do not drop the test until we have safe option) */
	/* refuse to overwrite header w/ backup including requirements */
	FAIL_((r = crypt_header_restore(cd, CRYPT_LUKS2, BACKUP_FILE)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	CRYPT_FREE(cd);

	OK_(_system("dd if=" REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init_by_name(&cd, CDEVICE_1));

	/* crypt_resume_by_passphrase (restricted) */
	FAIL_((r = crypt_resume_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE))), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_resume_by_keyfile (restricted) */
	FAIL_((r = crypt_resume_by_keyfile(cd, CDEVICE_1, 0, KEYFILE1, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_resume_by_keyfile_offset (restricted) */
	FAIL_((r = crypt_resume_by_keyfile_offset(cd, CDEVICE_1, 0, KEYFILE1, 0, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	CRYPT_FREE(cd);

	OK_(_system("dd if=" NO_REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	OK_(crypt_resume_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE)));
	CRYPT_FREE(cd);
	OK_(_system("dd if=" REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));

	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	/* load VK in keyring */
	OK_(crypt_activate_by_passphrase(cd, NULL, 0, PASSPHRASE, strlen(PASSPHRASE), t_dm_crypt_keyring_support() ? CRYPT_ACTIVATE_KEYRING_KEY : 0));
	/* crypt_resize (restricted) */
	FAIL_((r = crypt_resize(cd, CDEVICE_1, 1)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	GE_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);

	/* crypt_get_active_device (unrestricted) */
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
#if KERNEL_KEYRING
	if (t_dm_crypt_keyring_support())
		EQ_(cad.flags & CRYPT_ACTIVATE_KEYRING_KEY, CRYPT_ACTIVATE_KEYRING_KEY);
#endif

	/* crypt_deactivate (unrestricted) */
	OK_(crypt_deactivate(cd, CDEVICE_1));

	/* crypt_token_is_assigned (unrestricted) */
	OK_(crypt_token_is_assigned(cd, 1, 0));
	OK_(crypt_token_is_assigned(cd, 6, 0));
	EQ_(crypt_token_is_assigned(cd, 0, 0), -ENOENT);

	/* crypt_keyslot_destroy (unrestricted) */
	OK_(crypt_keyslot_destroy(cd, 0));

	CRYPT_FREE(cd);
	_cleanup_dmdevices();
}

static void Luks2Integrity(void)
{
	struct crypt_params_integrity ip = {};
	struct crypt_params_luks2 params = {
		.sector_size = 512,
		.integrity = "hmac(sha256)"
	};
	size_t key_size = 32 + 32;
	const char *cipher = "aes";
	const char *cipher_mode = "xts-random";
	int ret;

	// FIXME: This is just a stub
	OK_(crypt_init(&cd, DEVICE_2));
	ret = crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, key_size, &params);
	if (ret < 0) {
		printf("WARNING: cannot format integrity device, skipping test.\n");
		CRYPT_FREE(cd);
		return;
	}

	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, NULL, key_size, PASSPHRASE, strlen(PASSPHRASE)), 7);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_2, 7, PASSPHRASE, strlen(PASSPHRASE) ,0), 7);
	GE_(crypt_status(cd, CDEVICE_2), CRYPT_ACTIVE);
	CRYPT_FREE(cd);

	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_2, NULL));
	OK_(crypt_get_integrity_info(cd, &ip));
	OK_(strcmp(cipher, crypt_get_cipher(cd)));
	OK_(strcmp(cipher_mode, crypt_get_cipher_mode(cd)));
	OK_(strcmp("hmac(sha256)", ip.integrity));
	EQ_(32, ip.integrity_key_size);
	EQ_(32+16, ip.tag_size);
	OK_(crypt_deactivate(cd, CDEVICE_2));
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DEVICE_2));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, key_size - 32, &params), "Wrong key size.");
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, "xts-plainx", NULL, NULL, key_size, &params), "Wrong cipher.");
	CRYPT_FREE(cd);
}

static int check_flag(uint32_t flags, uint32_t flag)
{
	return (flags & flag) ? 0 : -1;
}

static void Luks2Refresh(void)
{
	uint64_t r_payload_offset;
	char key[128], key1[128];
	const char *cipher = "aes", *mode = "xts-plain64";
	const char *vk_hex =  "bb21158c733229347bd4e681891e213d94c645be6a5b84818afe7a78a6de7a1a";
	const char *vk_hex2 = "bb22158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1e";
	size_t key_size = strlen(vk_hex) / 2;
	struct crypt_params_luks2 params = {
		.sector_size = 512,
		.integrity = "aead"
	};
	struct crypt_active_device cad = {};

	OK_(crypt_decode_key(key, vk_hex, key_size));
	OK_(crypt_decode_key(key1, vk_hex2, key_size));

	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1000));
	OK_(create_dmdevice_over_loop(L_DEVICE_WRONG, r_payload_offset + 5000));
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_payload_offset));

	/* prepare test device */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, mode, NULL, key, 32, NULL));
	OK_(crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, key, 32, PASSPHRASE, strlen(PASSPHRASE)));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), 0));

	/* check we can refresh significant flags */
	if (t_dm_crypt_discard_support()) {
		OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH | CRYPT_ACTIVATE_ALLOW_DISCARDS));
		OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
		OK_(check_flag(cad.flags, CRYPT_ACTIVATE_ALLOW_DISCARDS));
		cad.flags = 0;
	}

	if (t_dm_crypt_cpu_switch_support()) {
		OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH | CRYPT_ACTIVATE_SAME_CPU_CRYPT));
		OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
		OK_(check_flag(cad.flags, CRYPT_ACTIVATE_SAME_CPU_CRYPT));
		cad.flags = 0;

		OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS));
		OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
		OK_(check_flag(cad.flags, CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS));
		cad.flags = 0;

		OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS));
		OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
		OK_(check_flag(cad.flags, CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS));
		cad.flags = 0;
	}

	OK_(crypt_volume_key_keyring(cd, 0));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH));
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	FAIL_(check_flag(cad.flags, CRYPT_ACTIVATE_KEYRING_KEY), "Unexpected flag raised.");
	cad.flags = 0;

#if KERNEL_KEYRING
	if (t_dm_crypt_keyring_support()) {
		OK_(crypt_volume_key_keyring(cd, 1));
		OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH));
		OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
		OK_(check_flag(cad.flags, CRYPT_ACTIVATE_KEYRING_KEY));
		cad.flags = 0;
	}
#endif

	/* multiple flags at once */
	if (t_dm_crypt_discard_support() && t_dm_crypt_cpu_switch_support()) {
		OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS | CRYPT_ACTIVATE_ALLOW_DISCARDS));
		OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
		OK_(check_flag(cad.flags, CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS | CRYPT_ACTIVATE_ALLOW_DISCARDS));
		cad.flags = 0;
	}

	/* do not allow reactivation with read-only (and drop flag silently because activation behaves exactly same) */
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH | CRYPT_ACTIVATE_READONLY));
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	FAIL_(check_flag(cad.flags, CRYPT_ACTIVATE_READONLY), "Reactivated with read-only flag.");
	cad.flags = 0;

	/* reload flag is dropped silently */
	OK_(crypt_deactivate(cd, CDEVICE_1));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH));

	/* check read-only flag is not lost after reload */
	OK_(crypt_deactivate(cd, CDEVICE_1));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_READONLY));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH));
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	OK_(check_flag(cad.flags, CRYPT_ACTIVATE_READONLY));
	cad.flags = 0;

	/* check LUKS2 with auth. enc. reload */
	OK_(crypt_init(&cd2, DMDIR L_DEVICE_WRONG));
	if (!crypt_format(cd2, CRYPT_LUKS2, "aes", "gcm-random", crypt_get_uuid(cd), key, 32, &params)) {
		OK_(crypt_keyslot_add_by_volume_key(cd2, 0, key, 32, PASSPHRASE, strlen(PASSPHRASE)));
		OK_(crypt_activate_by_volume_key(cd2, CDEVICE_2, key, 32, 0));
		OK_(crypt_activate_by_volume_key(cd2, CDEVICE_2, key, 32, CRYPT_ACTIVATE_REFRESH | CRYPT_ACTIVATE_NO_JOURNAL));
		OK_(crypt_get_active_device(cd2, CDEVICE_2, &cad));
		OK_(check_flag(cad.flags, CRYPT_ACTIVATE_NO_JOURNAL));
		cad.flags = 0;
		OK_(crypt_activate_by_volume_key(cd2, CDEVICE_2, key, 32, CRYPT_ACTIVATE_REFRESH | CRYPT_ACTIVATE_NO_JOURNAL | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS));
		OK_(crypt_get_active_device(cd2, CDEVICE_2, &cad));
		OK_(check_flag(cad.flags, CRYPT_ACTIVATE_NO_JOURNAL | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS));
		cad.flags = 0;
		OK_(crypt_activate_by_passphrase(cd2, CDEVICE_2, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH));
		OK_(crypt_get_active_device(cd2, CDEVICE_2, &cad));
		FAIL_(check_flag(cad.flags, CRYPT_ACTIVATE_NO_JOURNAL), "");
		FAIL_(check_flag(cad.flags, CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS), "");
		FAIL_(crypt_activate_by_passphrase(cd2, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH), "Refreshed LUKS2 device with LUKS2/aead context");
		OK_(crypt_deactivate(cd2, CDEVICE_2));
	} else {
		printf("WARNING: cannot format integrity device, skipping few reload tests.\n");
	}
	CRYPT_FREE(cd2);

	/* Use LUKS1 context on LUKS2 device */
	OK_(crypt_init(&cd2, DMDIR L_DEVICE_1S));
	OK_(crypt_format(cd2, CRYPT_LUKS1, cipher, mode, crypt_get_uuid(cd), key, 32, NULL));
	OK_(crypt_keyslot_add_by_volume_key(cd2, CRYPT_ANY_SLOT, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)));
	FAIL_(crypt_activate_by_passphrase(cd2, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH), "Refreshed LUKS2 device with LUKS1 context");
	CRYPT_FREE(cd2);

	/* Use PLAIN context on LUKS2 device */
	OK_(crypt_init(&cd2, DMDIR L_DEVICE_1S));
	OK_(crypt_format(cd2, CRYPT_PLAIN, cipher, mode, NULL, key, 32, NULL));
	OK_(crypt_activate_by_volume_key(cd2, CDEVICE_2, key, key_size, 0));
	FAIL_(crypt_activate_by_volume_key(cd2, CDEVICE_1, key, key_size, CRYPT_ACTIVATE_REFRESH), "Refreshed LUKS2 device with PLAIN context");
	OK_(crypt_deactivate(cd2, CDEVICE_2));
	CRYPT_FREE(cd2);

	/* (snapshot-like case) */
	/* try to refresh almost identical device (differs only in major:minor of data device) */
	OK_(crypt_init(&cd2, DMDIR L_DEVICE_WRONG));
	OK_(set_fast_pbkdf(cd2));
	OK_(crypt_format(cd2, CRYPT_LUKS2, cipher, mode, crypt_get_uuid(cd), key, 32, NULL));
	OK_(crypt_keyslot_add_by_volume_key(cd2, CRYPT_ANY_SLOT, key, 32, PASSPHRASE, strlen(PASSPHRASE)));
	FAIL_(crypt_activate_by_passphrase(cd2, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_REFRESH), "Refreshed dm-crypt mapped over mismatching data device");

	OK_(crypt_deactivate(cd, CDEVICE_1));

	CRYPT_FREE(cd);
	CRYPT_FREE(cd2);

	_cleanup_dmdevices();
}

static void Luks2Flags(void)
{
	uint32_t flags = 42;
	const char *longlabel = "0123456789abcedf0123456789abcedf0123456789abcedf";

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));

	/* check library erase passed variable on success when no flags set */
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_ACTIVATION, &flags));
	EQ_(flags, 0);

	/* check set and get behave as expected */
	flags = CRYPT_ACTIVATE_ALLOW_DISCARDS;
	OK_(crypt_persistent_flags_set(cd, CRYPT_FLAGS_ACTIVATION, flags));
	flags = 0;
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_ACTIVATION, &flags));
	EQ_(flags, CRYPT_ACTIVATE_ALLOW_DISCARDS);

	flags = CRYPT_ACTIVATE_ALLOW_DISCARDS | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS;
	OK_(crypt_persistent_flags_set(cd, CRYPT_FLAGS_ACTIVATION, flags));
	flags = ~UINT32_C(0);
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_ACTIVATION, &flags));
	EQ_(flags,CRYPT_ACTIVATE_ALLOW_DISCARDS | CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS);

	/* label and subsystem (second label */
	OK_(crypt_set_label(cd, "label", "subsystem"));
	OK_(strcmp("label", crypt_get_label(cd)));
	OK_(strcmp("subsystem", crypt_get_subsystem(cd)));

	OK_(crypt_set_label(cd, NULL, NULL));
	OK_(strcmp("", crypt_get_label(cd)));
	OK_(strcmp("", crypt_get_subsystem(cd)));

	FAIL_(crypt_set_label(cd, longlabel, NULL), "long label");
	FAIL_(crypt_set_label(cd, NULL, longlabel), "long subsystem");

	CRYPT_FREE(cd);
}

#if KERNEL_KEYRING && USE_LUKS2_REENCRYPTION
static int test_progress(uint64_t size __attribute__((unused)),
	uint64_t offset __attribute__((unused)),
	void *usrptr __attribute__((unused)))
{
	while (--test_progress_steps)
		return 0;
	return 1;
}

static void Luks2Reencryption(void)
{
/* reencryption currently depends on kernel keyring support */
	/* NOTES:
	 *  - reencryption requires luks2 parameters. can we avoid it?
	 */
	uint32_t getflags;
	uint64_t r_header_size, r_size_1;
	struct crypt_active_device cad;
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha256",
		.parallel_threads = 1,
		.max_memory_kb = 128,
		.iterations = 4,
		.flags = CRYPT_PBKDF_NO_BENCHMARK
	};
	struct crypt_params_luks2 params2 = {
		.pbkdf = &pbkdf,
		.sector_size = 4096
	};
	struct crypt_params_reencrypt retparams = {}, rparams = {
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "checksum",
		.hash = "sha256",
		.luks2 = &params2,
	};
	dev_t devno;
	key_serial_t kid, kid1;
	struct crypt_keyslot_context *kc_pass12 = NULL, *kc_pass21 = NULL, *kc_file12 = NULL, *kc_file21 = NULL,
				     *kc_token12 = NULL, *kc_token21 = NULL, *kc_key = NULL, *kc_key2 = NULL;

	const char *vk_hex =  "bb21babe733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a",
		   *vk_hex2 = "bb21bebe733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a" \
			      "cc21cfcf733229347ce4f681891f213d94d685cf6b5b84818baf7b78b6df7b1b";
	size_t key_size = strlen(vk_hex) / 2,
	       key_size2 = strlen(vk_hex2) / 2;
	char key[128], key2[64];

	OK_(crypt_decode_key(key, vk_hex, key_size));
	OK_(crypt_decode_key(key2, vk_hex2, key_size2));

	/* reencryption currently depends on kernel keyring support in dm-crypt */
	if (!t_dm_crypt_keyring_support())
		return;

	/* Cannot use Argon2 in FIPS */
	if (_fips_mode) {
		pbkdf.type = CRYPT_KDF_PBKDF2;
		pbkdf.parallel_threads = 0;
		pbkdf.max_memory_kb = 0;
		pbkdf.iterations = 1000;
	}

	OK_(get_luks2_offsets(1, 0, 0, &r_header_size, NULL));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_header_size + 16));

	/* create device */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 21, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 21);

	/* add several unbound keys */
	EQ_(crypt_keyslot_add_by_key(cd, 9, NULL, 64, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 9);
	EQ_(crypt_keyslot_add_by_key(cd, 10, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 10);
	EQ_(crypt_keyslot_add_by_key(cd, 11, NULL, 42, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 11);
	EQ_(crypt_keyslot_status(cd, 21), CRYPT_SLOT_ACTIVE_LAST);

	/* test cipher parameters validation */
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 11, "aes", "xts-plain64", &rparams), "Cipher not compatible with new volume key size.");
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 10, "tHeHamstErciphErr", "xts-plain64", &rparams), "Wrong cipher.");
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 10, "aes", "HamSterMoOode-plain64", &rparams), "Wrong mode.");

	/* test reencryption flags */
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams), "Reencryption not initialized.");
	rparams.flags |= CRYPT_REENCRYPT_INITIALIZE_ONLY;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams), "Invalid flags combination.");

	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &getflags));
	EQ_(getflags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT, 0);
	FAIL_(crypt_reencrypt_run(cd, NULL, NULL), "Reencryption context not initialized.");

	rparams.flags &= ~CRYPT_REENCRYPT_RESUME_ONLY;
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams));
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &getflags));
	EQ_(getflags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT, CRYPT_REQUIREMENT_ONLINE_REENCRYPT);

	/* check reencrypt status is correct */
	EQ_(crypt_reencrypt_status(cd, &retparams), CRYPT_REENCRYPT_CLEAN);
	EQ_(retparams.mode, CRYPT_REENCRYPT_REENCRYPT);
	EQ_(retparams.direction, CRYPT_REENCRYPT_FORWARD);
	EQ_(retparams.data_shift, 0);
	EQ_(retparams.device_size, 0);

	/* check reencryption flag in metadata */
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &getflags));
	EQ_(getflags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT, CRYPT_REQUIREMENT_ONLINE_REENCRYPT);

	/* some parameters are expected to change immediately after reencryption initialization */
	EQ_(crypt_get_old_volume_key_size(cd), 32);
	EQ_(crypt_get_volume_key_size(cd), 64);
	OK_(strcmp(crypt_get_cipher_mode(cd), "xts-plain64"));
	EQ_(crypt_get_sector_size(cd), 4096);
	/* reencrypt keyslot must be unbound */
	EQ_(crypt_keyslot_status(cd, 0), CRYPT_SLOT_UNBOUND);
	/* keyslot assigned to new segment is switched to last active */
	EQ_(crypt_keyslot_status(cd, 9), CRYPT_SLOT_ACTIVE_LAST);
	/* keyslot assigned to old segment remains active */
	EQ_(crypt_keyslot_status(cd, 21), CRYPT_SLOT_ACTIVE);

	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 10, "aes", "xts-plain", &rparams), "Reencryption already initialized.");

	rparams.flags = 0;
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));

	/* check keyslots are reassigned to segment after reencryption */
	EQ_(crypt_keyslot_status(cd, 0), CRYPT_SLOT_INACTIVE);
	EQ_(crypt_keyslot_status(cd, 9), CRYPT_SLOT_ACTIVE_LAST);
	EQ_(crypt_keyslot_status(cd, 10), CRYPT_SLOT_UNBOUND);
	EQ_(crypt_keyslot_status(cd, 11), CRYPT_SLOT_UNBOUND);
	EQ_(crypt_keyslot_status(cd, 21), CRYPT_SLOT_INACTIVE);

	EQ_(crypt_keyslot_add_by_key(cd, 21, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 21);
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;
	params2.sector_size = 512;
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 9, 21, "aes", "xts-plain64", &rparams));

	/* fixed device size parameter impact */
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	rparams.device_size = 24;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 9, 21, "aes", "xts-plain64", &rparams), "Invalid device size.");
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &getflags));
	EQ_(getflags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT, CRYPT_REQUIREMENT_ONLINE_REENCRYPT);
	rparams.device_size = 15;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 9, 21, "aes", "xts-plain64", &rparams), "Invalid device size alignment.");
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &getflags));
	EQ_(getflags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT, CRYPT_REQUIREMENT_ONLINE_REENCRYPT);
	FAIL_(crypt_reencrypt_run(cd, NULL, NULL), "Reencryption context not initialized.");
	rparams.device_size = 16;
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 9, 21, "aes", "xts-plain64", &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &getflags));
	EQ_(getflags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT, 0);

	/* limited hotzone size parameter impact */
	EQ_(crypt_keyslot_add_by_key(cd, 9, NULL, 64, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 9);
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;
	rparams.device_size = 0;
	params2.sector_size = 4096;
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams));

	/* max hotzone size parameter impact */
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	rparams.max_hotzone_size = 1;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams), "Invalid hotzone size alignment.");
	rparams.max_hotzone_size = 24; /* should be ok. Device size is 16 sectors and the parameter defines upper limit, not lower */
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams));
	rparams.max_hotzone_size = 8;
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams));
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));

	rparams.max_hotzone_size = 0;
	rparams.resilience = "haMster";
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams), "Invalid resilience mode.");
	rparams.resilience = "checksum";
	rparams.hash = "hamSter";
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams), "Invalid resilience hash.");

	rparams.hash = "sha256";
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));

	/* FIXME: this is a bug, but not critical (data shift parameter is ignored after initialization) */
	//rparams.data_shift = 8;
	//FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams), "Invalid reencryption parameters.");

	EQ_(crypt_keyslot_add_by_key(cd, 21, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 21);
	rparams.flags = 0;
	rparams.resilience = "none";
	rparams.max_hotzone_size = 2048;
	/* online reencryption on inactive device */
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), 9, 21, "aes", "xts-plain64", &rparams), "Device is not active.");
	/* FIXME: this is minor bug. In fact we need only key from keyslot 9 */
	//EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 9, PASSPHRASE, strlen(PASSPHRASE), 0), 9);
	NOTFAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), "Failed to activate device.");
	/* offline reencryption on active device */
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 9, 21, "aes", "xts-plain64", &rparams), "Device mounted or active.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	/* Wrong context checks */
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 9, 21, "aes", "xts-plain64", &rparams));
	/* cd is ready for reencryption */
	OK_(crypt_init(&cd2, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd2, CRYPT_LUKS2, NULL));
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd2, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams), "Reencryption already running.");
	rparams.flags = 0;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd2, NULL, PASSPHRASE, strlen(PASSPHRASE), 21, 9, "aes", "xts-plain64", &rparams), "Reencryption already running.");
	FAIL_(crypt_reencrypt_run(cd2, NULL, NULL), "Invalid reencryption context.");
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &getflags));
	EQ_(getflags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT, CRYPT_REQUIREMENT_ONLINE_REENCRYPT);
	OK_(crypt_persistent_flags_get(cd2, CRYPT_FLAGS_REQUIREMENTS, &getflags));
	EQ_(getflags & CRYPT_REQUIREMENT_ONLINE_REENCRYPT, CRYPT_REQUIREMENT_ONLINE_REENCRYPT);
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_CLEAN);
	EQ_(crypt_reencrypt_status(cd2, NULL), CRYPT_REENCRYPT_CLEAN);
	FAIL_(crypt_activate_by_passphrase(cd2, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), "Reencryption already in progress.");
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), "Reencryption already in progress.");
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	CRYPT_FREE(cd);
	CRYPT_FREE(cd2);

	/* Partial device reencryption parameter */
	params2.sector_size = 512;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);

	rparams.device_size = 2;
	rparams.max_hotzone_size = 1;
	rparams.resilience = "none";
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), 2);

	/* interrupt reencryption after 'test_progress_steps' */
	test_progress_steps = 2;
	OK_(crypt_reencrypt_run(cd, &test_progress, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_CLEAN);

	NOTFAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), "Could not activate device in reencryption.");
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(cad.size, 2);
	EQ_(cad.offset, r_header_size);
	/* TODO: this should work in future releases unless reencryption process is running */
	FAIL_(crypt_resize(cd, CDEVICE_1, 1), "Device in reencryption.");
	FAIL_(crypt_resize(cd, CDEVICE_1, 0), "Device in reencryption.");

	rparams.max_hotzone_size = 0;
	rparams.device_size = 3;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), "Invalid device size.");
	crypt_deactivate(cd, CDEVICE_1);
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), "Invalid device size.");
	rparams.device_size = 2;
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	NOTFAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), "Failed to initialize reencryption.");
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, PASSPHRASE, strlen(PASSPHRASE), 0), 1);
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	/* after reencryption use whole device again */
	EQ_(cad.size, 16);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	/* Reencrypt device with wrong size */
	EQ_(crypt_keyslot_add_by_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 0);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, PASSPHRASE, strlen(PASSPHRASE), 0), 1);
	OK_(crypt_resize(cd, CDEVICE_1, 7));
	rparams.device_size = 0;
	rparams.flags = 0;
	params2.sector_size = 4096;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), 1, 0, "aes", "xts-plain64", &rparams), "Active device size is not aligned to new sector size.");
	rparams.device_size = 8;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 1, 0, "aes", "xts-plain64", &rparams), "Reduced reencryption size does not match active device.");
	/* FIXME: allow after resize in reencryption is supported */
	//NOTFAIL_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY | CRYPT_ACTIVATE_KEYRING_KEY), "Failed to load keys.");
	// OK_(crypt_resize(cd, CDEVICE_1, 8));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	params2.sector_size = 512;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_init(&cd2, DMDIR H_DEVICE));
	OK_(crypt_set_data_offset(cd2, r_header_size - 8));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	OK_(crypt_set_pbkdf_type(cd2, &pbkdf));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_format(cd2, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd2, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	EQ_(crypt_keyslot_add_by_key(cd2, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd2, CDEVICE_2, 0, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), 2);
	EQ_(crypt_reencrypt_init_by_passphrase(cd2, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), 2);
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	/* reference wrong device in active device name */
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_2, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), "Wrong device.");
	FAIL_(crypt_reencrypt_init_by_passphrase(cd2, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), "Wrong device.");
	EQ_(crypt_reencrypt_init_by_passphrase(cd2, CDEVICE_2, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), 2);
	FAIL_(crypt_set_data_device(cd2, DMDIR L_DEVICE_OK), "Device in reencryption.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	OK_(crypt_deactivate(cd2, CDEVICE_2));
	CRYPT_FREE(cd);
	CRYPT_FREE(cd2);

	/* same key size reencryption */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 10, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 10);
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_REENCRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "none",
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY
	};
	rparams.luks2 = &(struct crypt_params_luks2){ .sector_size = 512 };
	NOTFAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, 10, "aes", "xts-plain64", &rparams), "Failed to initialize reencryption");
	EQ_(crypt_get_volume_key_size(cd), 32);
	EQ_(crypt_get_old_volume_key_size(cd), 32);
	CRYPT_FREE(cd);

	/* same key reencryption */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	NOTFAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, 0, "aes", "xts-plain64", &rparams), "Failed to initialize reencryption");
	EQ_(crypt_get_volume_key_size(cd), 32);
	EQ_(crypt_get_old_volume_key_size(cd), 32);
	CRYPT_FREE(cd);

	/* data shift related tests */
	params2.sector_size = 512;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	rparams = (struct crypt_params_reencrypt) {
		.direction = CRYPT_REENCRYPT_BACKWARD,
		.resilience = "datashift",
		.data_shift = 8,
		.luks2 = &params2,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY
	};
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), 2);
	EQ_(crypt_reencrypt_status(cd, &retparams), CRYPT_REENCRYPT_CLEAN);
	EQ_(retparams.data_shift, 8);
	EQ_(retparams.mode, CRYPT_REENCRYPT_REENCRYPT);
	OK_(strcmp(retparams.resilience, "datashift"));
	EQ_(crypt_get_data_offset(cd), 32776);
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), 2);
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, PASSPHRASE, strlen(PASSPHRASE), 0), 1);
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(cad.size, 8);
	EQ_(crypt_get_data_offset(cd), 32776);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	rparams.flags = 0;
	EQ_(crypt_keyslot_add_by_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 0);
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 1, 0, "aes", "xts-plain64", &rparams), "Device is too small.");
	CRYPT_FREE(cd);
	// BUG: We need reencrypt abort flag
	/* it fails, but it's already initialized and we have no way to abort yet */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 1);
	EQ_(crypt_keyslot_add_by_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 0);
	rparams.direction = CRYPT_REENCRYPT_FORWARD;
	rparams.resilience = "datashift";
	rparams.data_shift = 8;
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 1, 0, "aes", "xts-plain64", &rparams), 2);
	EQ_(crypt_reencrypt_status(cd, &retparams), CRYPT_REENCRYPT_CLEAN);
	EQ_(retparams.data_shift, 8);
	EQ_(retparams.mode, CRYPT_REENCRYPT_REENCRYPT);
	OK_(strcmp(retparams.resilience, "datashift"));
	EQ_(crypt_get_data_offset(cd), 32760);
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 1, 0, "aes", "xts-plain64", &rparams), 2);
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(cad.size, 24);
	EQ_(crypt_get_data_offset(cd), 32760);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	/* data shift with online device */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	rparams.direction = CRYPT_REENCRYPT_BACKWARD;
	rparams.resilience = "datashift";
	rparams.data_shift = 8;
	rparams.flags = 0;
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), "Active device too large.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), "Failed to activate device in reencryption.");
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(cad.size, 8);
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), 0, 1, "aes", "xts-plain64", &rparams), 2);
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();

	/* encryption with datashift and moved segment (limit values for data shift) */
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, 12*1024*2));

	OK_(crypt_init(&cd, DMDIR H_DEVICE));

	params2.sector_size = 512;
	params2.data_device = DMDIR L_DEVICE_OK;
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_ENCRYPT,
		.direction = CRYPT_REENCRYPT_BACKWARD,
		.resilience = "datashift",
		.data_shift = 8192,
		.luks2 = &params2,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY | CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT
	};
	OK_(crypt_set_data_offset(cd, 8192));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 30, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 30);
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 30, "aes", "xts-plain64", &rparams), 0);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_header_restore(cd, CRYPT_LUKS2, DMDIR H_DEVICE));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_reencrypt_status(cd, &retparams), CRYPT_REENCRYPT_CLEAN);
	/* With encryption there's no old volume key */
	EQ_(crypt_get_old_volume_key_size(cd), 0);
	EQ_(retparams.mode, CRYPT_REENCRYPT_ENCRYPT);
	OK_(strcmp(retparams.resilience, "datashift"));
	EQ_(retparams.data_shift, 8192);
	EQ_(retparams.flags & CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT, CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT);
	EQ_(crypt_get_data_offset(cd), 8192);
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 30, NULL, NULL, &rparams), 0);
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, 8*1024*2+1));

	/* encryption with datashift and moved segment (data shift + 1 sector) */
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY | CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT;
	OK_(crypt_set_data_offset(cd, 8192));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 30, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 30);
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 30, "aes", "xts-plain64", &rparams), 0);
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_header_restore(cd, CRYPT_LUKS2, DMDIR H_DEVICE));
	EQ_(crypt_get_data_offset(cd), 8192);
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 30, NULL, NULL, &rparams), 0);
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, 2*8200));

	OK_(crypt_init(&cd, DMDIR H_DEVICE));

	/* encryption with datashift and moved segment (data shift + data offset <= device size) */
	params2.sector_size = 512;
	params2.data_device = DMDIR L_DEVICE_OK;
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_ENCRYPT,
		.direction = CRYPT_REENCRYPT_BACKWARD,
		.resilience = "datashift",
		.data_shift = 8200,
		.luks2 = &params2,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY | CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT
	};
	OK_(crypt_set_data_offset(cd, 8200));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 30, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 30);
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 30, "aes", "xts-plain64", &rparams), "Data device is too small");
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_header_size + 1));

	/* offline in-place encryption with reserved space in the head of data device */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	params2.sector_size = 512;
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_ENCRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "checksum",
		.hash = "sha256",
		.luks2 = &params2,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY
	};
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 30, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 30);
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 30, "aes", "xts-plain64", &rparams));
	FAIL_(crypt_reencrypt_run(cd, NULL, NULL), "context not initialized");
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 30, "aes", "xts-plain64", &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);
	CRYPT_FREE(cd);

	/* wipe existing header from previous run */
	_system("dd if=/dev/zero of=" DMDIR L_DEVICE_OK " bs=4K count=5 2>/dev/null", 1);

	/* offline in-place encryption with reserved space in the head of data device (using no keyslot, by volume key) */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_ENCRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "checksum",
		.hash = "sha256",
		.luks2 = &(struct crypt_params_luks2){ .sector_size = 512 },
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY | CRYPT_REENCRYPT_CREATE_NEW_DIGEST
	};
	/* key does not matter. the new one from encrypt will be used */
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, &params2));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_keyslot_context_init_by_volume_key(cd, key, key_size, &kc_key));
	OK_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, NULL, kc_key, CRYPT_ANY_SLOT, CRYPT_ANY_SLOT, "aes", "xts-plain64", &rparams));
	OK_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc_key, CRYPT_ANY_SLOT, NULL, 0));
	FAIL_(crypt_reencrypt_run(cd, NULL, NULL), "context not initialized");
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY | CRYPT_REENCRYPT_CREATE_NEW_DIGEST;
	FAIL_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, NULL, kc_key, CRYPT_ANY_SLOT, CRYPT_ANY_SLOT, "aes", "xts-plain64", &rparams), "Can not use direct key flag with resume only.");
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	OK_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, NULL, kc_key, CRYPT_ANY_SLOT, CRYPT_ANY_SLOT, NULL, NULL, &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);
	OK_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc_key, CRYPT_ANY_SLOT, NULL, 0));
	crypt_keyslot_context_free(kc_key);
	CRYPT_FREE(cd);

	/* wipe existing header from previous run */
	_system("dd if=/dev/zero of=" DMDIR L_DEVICE_OK " bs=4K count=5 2>/dev/null", 1);
	/* open existing device from kernel (simulate active filesystem) */
	OK_(create_dmdevice_over_device(L_PLACEHOLDER, DMDIR L_DEVICE_OK, 1, r_header_size));

	/* online in-place encryption with reserved space */
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;
	OK_(crypt_init(&cd, EMPTY_HEADER));
	OK_(crypt_set_data_offset(cd, r_header_size));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 30, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 30);
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 30, "aes", "xts-plain64", &rparams));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_header_restore(cd, CRYPT_LUKS2, EMPTY_HEADER));
	NOTFAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_SHARED), "Failed to activate device in reencryption with shared flag.");
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	OK_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 30, "aes", "xts-plain64", &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_header_size + 1));

	/* decryption backward  */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	params2.data_device = NULL;
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 6, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 6);
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_BACKWARD,
		.resilience = "none",
		.max_hotzone_size = 2048
	};
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 6, CRYPT_ANY_SLOT, NULL, NULL, &rparams));
	EQ_(crypt_get_old_volume_key_size(cd), 32);
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), r_header_size);
	EQ_(crypt_get_volume_key_size(cd), 0);
	OK_(strcmp(crypt_get_cipher(cd), "cipher_null"));
	CRYPT_FREE(cd);

	/* decryption forward */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	params2.data_device = NULL;
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 6, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 6);
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "none",
		.max_hotzone_size = 2048
	};
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 6, CRYPT_ANY_SLOT, NULL, NULL, &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	CRYPT_FREE(cd);

	/* decryption forward (online) */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	params2.data_device = NULL;
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 6, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 6);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_2, 6, PASSPHRASE, strlen(PASSPHRASE), 0), 6);
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "none",
		.max_hotzone_size = 2048
	};
	OK_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_2, PASSPHRASE, strlen(PASSPHRASE), 6, CRYPT_ANY_SLOT, NULL, NULL, &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	CRYPT_FREE(cd);

	/* decryption with data shift */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	params2.data_device = NULL;
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 6, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 6);
	remove(BACKUP_FILE);
	OK_(crypt_header_backup(cd, CRYPT_LUKS2, BACKUP_FILE));
	CRYPT_FREE(cd);
	// FIXME: we need write flock
	OK_(chmod(BACKUP_FILE, S_IRUSR|S_IWUSR));
	OK_(crypt_init_data_device(&cd, BACKUP_FILE, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), r_header_size);
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "datashift",
		.data_shift = r_header_size
	};
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 6, CRYPT_ANY_SLOT, NULL, NULL, &rparams));
	EQ_(crypt_get_data_offset(cd), 0);
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	remove(BACKUP_FILE);
	CRYPT_FREE(cd);

	/* online decryption with data shift (future feature) */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	params2.data_device = NULL;
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 6, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 6);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_2, 6, PASSPHRASE, strlen(PASSPHRASE), 0), 6);
	OK_(t_device_size(DMDIR CDEVICE_2, &r_size_1));
	EQ_(r_size_1, 512);
	// store devno for later size check
	OK_(t_get_devno(CDEVICE_2, &devno));
	// create placeholder device to block automatic deactivation after decryption
	OK_(_system("dmsetup create " CDEVICE_1 " --table \"0 1 linear " DMDIR CDEVICE_2 " 0\"", 1));
	remove(BACKUP_FILE);
	OK_(crypt_header_backup(cd, CRYPT_LUKS2, BACKUP_FILE));
	CRYPT_FREE(cd);
	// FIXME: we need write flock
	OK_(chmod(BACKUP_FILE, S_IRUSR|S_IWUSR));
	OK_(crypt_init_data_device(&cd, BACKUP_FILE, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), r_header_size);
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "datashift",
		.data_shift = r_header_size
	};
	OK_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_2, PASSPHRASE, strlen(PASSPHRASE), 6, CRYPT_ANY_SLOT, NULL, NULL, &rparams));
	EQ_(crypt_get_data_offset(cd), 0);
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	remove(BACKUP_FILE);
	OK_(t_device_size_by_devno(devno, &r_size_1));
	EQ_(r_size_1, 512);
	OK_(_system("dmsetup remove " DM_RETRY CDEVICE_1 DM_NOSTDERR, 0));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_WRONG, r_header_size));

	/* check detached header misuse (mismatching keys in table and mda) */
	OK_(crypt_init(&cd, IMAGE_EMPTY_SMALL));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	params2.data_device = DMDIR L_DEVICE_WRONG;
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 6, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 6);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 6, PASSPHRASE, strlen(PASSPHRASE), 0), 6);
	/* activate second device using same header */
	OK_(crypt_init_data_device(&cd2, IMAGE_EMPTY_SMALL, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd2, CRYPT_LUKS2, NULL));
	OK_(crypt_set_pbkdf_type(cd2, &pbkdf));
	EQ_(crypt_activate_by_passphrase(cd2, CDEVICE_2, 6, PASSPHRASE, strlen(PASSPHRASE), 0), 6);
	CRYPT_FREE(cd2);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	rparams = (struct crypt_params_reencrypt) {
		.resilience = "none",
		.max_hotzone_size = 16*2048,
		.luks2 = &params2
	};

	OK_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), 6, 1, "aes", "cbc-essiv:sha256", &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));

	OK_(crypt_init_data_device(&cd2, IMAGE_EMPTY_SMALL, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd2, CRYPT_LUKS2, NULL));
	OK_(crypt_set_pbkdf_type(cd2, &pbkdf));
	EQ_(crypt_keyslot_add_by_key(cd2, 2, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 2);
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd2, CDEVICE_2, PASSPHRASE, strlen(PASSPHRASE), 1, 2, "aes", "cbc-essiv:sha256", &rparams), "Mismatching parameters in device table.");
	OK_(crypt_reencrypt_init_by_passphrase(cd2, NULL, PASSPHRASE, strlen(PASSPHRASE), 1, 2, "aes", "cbc-essiv:sha256", &rparams));
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd2, CDEVICE_2, PASSPHRASE, strlen(PASSPHRASE), 1, 2, "aes", "cbc-essiv:sha256", &rparams), "Mismatching parameters in device table.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	OK_(crypt_deactivate(cd2, CDEVICE_2));
	CRYPT_FREE(cd);
	CRYPT_FREE(cd2);

	/* check detached header misuse (mismatching progress data in active device and mda) */
	OK_(crypt_init(&cd, IMAGE_EMPTY_SMALL));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	params2.data_device = DMDIR L_DEVICE_WRONG;
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 6, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 6);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	rparams.flags = 0;
	rparams.max_hotzone_size = 8;
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 6, 1, "aes", "cbc-essiv:sha256", &rparams));
	/* reencrypt 8 sectors of device */
	test_progress_steps = 2;
	OK_(crypt_reencrypt_run(cd, &test_progress, NULL));

	/* activate another data device with same LUKS2 header (this is wrong, but we can't detect such mistake) */
	OK_(crypt_init_data_device(&cd2, IMAGE_EMPTY_SMALL, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd2, CRYPT_LUKS2, NULL));
	NOTFAIL_(crypt_activate_by_passphrase(cd2, CDEVICE_2, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), "Failed to activate device in reencryption.");
	CRYPT_FREE(cd2);

	/* reencrypt yet another 8 sectors of first device */
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 6, 1, "aes", "cbc-essiv:sha256", &rparams));
	test_progress_steps = 2;
	OK_(crypt_reencrypt_run(cd, &test_progress, NULL));

	/* Now active mapping for second data device does not match its metadata */
	OK_(crypt_init_data_device(&cd2, IMAGE_EMPTY_SMALL, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd2, CRYPT_LUKS2, NULL));
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	FAIL_(crypt_reencrypt_init_by_passphrase(cd2, CDEVICE_2, PASSPHRASE, strlen(PASSPHRASE), 6, 1, "aes", "cbc-essiv:sha256", &rparams), "Mismatching device table.");
	OK_(crypt_deactivate(cd2, CDEVICE_2));
	CRYPT_FREE(cd2);
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_header_size + 16));

	/* Test LUKS2 reencryption honors flags device was activate with */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	params2.sector_size = 512;
	params2.data_device = NULL;
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 6, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 6);
	OK_(crypt_volume_key_keyring(cd, 0)); /* disable keyring */
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 6, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ACTIVATE_ALLOW_DISCARDS), 6);
	OK_(crypt_volume_key_keyring(cd, 1));
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_REENCRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "none",
		.max_hotzone_size = 8,
		.luks2 = &params2
	};
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	OK_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), 6, 1, "aes", "xts-plain64", &rparams));
	test_progress_steps = 2;
	OK_(crypt_reencrypt_run(cd, &test_progress, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_CLEAN);
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(cad.flags & CRYPT_ACTIVATE_ALLOW_DISCARDS, CRYPT_ACTIVATE_ALLOW_DISCARDS);
	EQ_(cad.flags & CRYPT_ACTIVATE_KEYRING_KEY, 0);
	CRYPT_FREE(cd);
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	OK_(crypt_reencrypt_init_by_passphrase(cd, CDEVICE_1, PASSPHRASE, strlen(PASSPHRASE), 6, 1, "aes", "xts-plain64", &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(cad.flags & CRYPT_ACTIVATE_ALLOW_DISCARDS, CRYPT_ACTIVATE_ALLOW_DISCARDS);
	EQ_(cad.flags & CRYPT_ACTIVATE_KEYRING_KEY, 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_header_size + 16));

	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_REENCRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "none",
		.luks2 = &params2
	};

	/* Test support for specific key reencryption */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 3, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 3);
	EQ_(crypt_keyslot_add_by_key(cd, 9, key, key_size, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 9);
	EQ_(crypt_keyslot_add_by_key(cd, 10, key, key_size, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT | CRYPT_VOLUME_KEY_DIGEST_REUSE ), 10);
	OK_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 3, 9, "aes", "xts-plain64", &rparams));
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	OK_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0));
	OK_(crypt_keyslot_destroy(cd, 9));
	OK_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0));
	CRYPT_FREE(cd);

	_cleanup_dmdevices();
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, 2 * r_header_size));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));

	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "datashift-checksum",
		.hash = "sha256",
		.data_shift = r_header_size,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY | CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT
	};

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, NULL));
	EQ_(0, crypt_keyslot_add_by_volume_key(cd, 0, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)));
	OK_(crypt_header_backup(cd, CRYPT_LUKS2, BACKUP_FILE));
	CRYPT_FREE(cd);

	params2.data_device = DMDIR L_DEVICE_OK;
	params2.sector_size = 512;

	/* create detached LUKS2 header (with data_offset == 0) */
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, &params2));
	EQ_(crypt_get_data_offset(cd), 0);
	OK_(set_fast_pbkdf(cd));
	EQ_(0, crypt_keyslot_add_by_volume_key(cd, 0, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)));
	CRYPT_FREE(cd);

	/* initiate LUKS2 decryption with datashift on bogus LUKS2 header (data_offset == 0) */
	OK_(crypt_init_data_device(&cd, DMDIR H_DEVICE, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Illegal data offset");
	/* reencryption must not initialize */
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);
	CRYPT_FREE(cd);
	/* original data device must stay untouched */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);
	CRYPT_FREE(cd);

	OK_(chmod(BACKUP_FILE, S_IRUSR|S_IWUSR));
	OK_(crypt_init_data_device(&cd, BACKUP_FILE, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));

	/* simulate read error at first segment beyond data offset*/
	OK_(dmdevice_error_io(L_DEVICE_OK, DMDIR L_DEVICE_OK, DEVICE_ERROR, 0, r_header_size, 8, ERR_RD));

	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Could not read first data segment");
	CRYPT_FREE(cd);

	/* Device must not be in reencryption */
	OK_(crypt_init_data_device(&cd, BACKUP_FILE, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);

	/* simulate write error in original LUKS2 header area */
	OK_(dmdevice_error_io(L_DEVICE_OK, DMDIR L_DEVICE_OK, DEVICE_ERROR, 0, 0, 8, ERR_WR));

	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Could not write first data segment");
	CRYPT_FREE(cd);

	/* Device must not be in reencryption */
	OK_(crypt_init_data_device(&cd, BACKUP_FILE, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);
	CRYPT_FREE(cd);
	remove(BACKUP_FILE);

	/* remove error mapping */
	OK_(dmdevice_error_io(L_DEVICE_OK, DMDIR L_DEVICE_OK, DEVICE_ERROR, 0, 0, 8, ERR_REMOVE));

	/* test various bogus reencryption resilience parameters */
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "checksum", /* should have been datashift-checksum */
		.hash = "sha256",
		.data_shift = r_header_size,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY | CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT
	};

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, NULL));
	EQ_(0, crypt_keyslot_add_by_volume_key(cd, 0, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)));
	OK_(crypt_header_backup(cd, CRYPT_LUKS2, BACKUP_FILE));
	CRYPT_FREE(cd);

	OK_(chmod(BACKUP_FILE, S_IRUSR|S_IWUSR));
	OK_(crypt_init_data_device(&cd, BACKUP_FILE, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));

	/* decryption on device with data offset and no datashift subvariant mode */
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Invalid reencryption params");
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);

	rparams.resilience = "journal"; /* should have been datashift-journal */
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Invalid reencryption params");
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);

	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_DECRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "datashift-checksum",
		.hash = "sha256",
		.data_shift = 0, /* must be non zero */
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY | CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT
	};

	/* datashift = 0 */
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Invalid reencryption params");
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);

	rparams.resilience = "datashift-journal";
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Invalid reencryption params");
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);

	rparams.resilience = "datashift"; /* datashift only is not supported in decryption mode with moved segment */
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Invalid reencryption params");
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);

	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 21, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 21);

	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_REENCRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "datashift-checksum",
		.hash = "sha256",
		.data_shift = r_header_size,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY
	};

	/* regular reencryption must not accept datashift subvariants */
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Invalid reencryption params");
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);

	rparams.resilience = "datashift-journal";
	FAIL_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 0, CRYPT_ANY_SLOT, NULL, NULL, &rparams), "Invalid reencryption params");
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_NONE);

	CRYPT_FREE(cd);
	_cleanup_dmdevices();
	_remove_keyfiles();

	OK_(prepare_keyfile(KEYFILE1, PASSPHRASE, strlen(PASSPHRASE)));
	OK_(prepare_keyfile(KEYFILE2, PASSPHRASE1, strlen(PASSPHRASE1)));

	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_header_size + 16));

	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_REENCRYPT,
		.direction = CRYPT_REENCRYPT_FORWARD,
		.luks2 = &(struct crypt_params_luks2){ .sector_size = 512 },
		.resilience = "none",
	};

	/* FIXME */
	/* FIXME it breaks when params2.data_device == metadata device */
	/* FIXME */

	/* create device */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, key, key_size, &(struct crypt_params_luks2){ .sector_size = 512 }));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 21, key, key_size, PASSPHRASE, strlen(PASSPHRASE)), 21);

	/* add unbound key */
	EQ_(crypt_keyslot_add_by_key(cd, 12, key2, key_size2, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 12);
	/* add unbound key that will not be used in reencryption */
	EQ_(crypt_keyslot_add_by_key(cd, 13, NULL, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 13);

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");
	kid1 = add_key("user", KEY_DESC_TEST1, PASSPHRASE1, strlen(PASSPHRASE1), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid1, "Test or kernel keyring are broken.");

	EQ_(crypt_token_luks2_keyring_set(cd, 21, &(const struct crypt_token_params_luks2_keyring){.key_description = KEY_DESC_TEST0}), 21);
	EQ_(crypt_token_luks2_keyring_set(cd, 12, &(const struct crypt_token_params_luks2_keyring){.key_description = KEY_DESC_TEST1}), 12);

	EQ_(crypt_token_assign_keyslot(cd, 21, 21), 21);
	EQ_(crypt_token_assign_keyslot(cd, 12, 12), 12);

	// key
	OK_(crypt_keyslot_context_init_by_volume_key(cd, key, key_size, &kc_key));
	// key2
	OK_(crypt_keyslot_context_init_by_volume_key(cd, key2, key_size2, &kc_key2));
	// token 21, keyslot 21
	OK_(crypt_keyslot_context_init_by_token(cd, 21, NULL, NULL, 0, NULL, &kc_token21));
	// token 12, keyslot 12
	OK_(crypt_keyslot_context_init_by_token(cd, 12, NULL, NULL, 0, NULL, &kc_token12));
	// keyfile21
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &kc_file21));
	// keyfile12
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE2, 0, 0, &kc_file12));
	// passphrase21
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &kc_pass21));
	// passphrase12
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE1, strlen(PASSPHRASE1), &kc_pass12));

	// reencrypt by token
	NOTFAIL_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, kc_token21, kc_token12, CRYPT_ANY_SLOT, 12, "aes", "xts-plain64", &rparams), "Reencrypt init failed");
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	EQ_(crypt_keyslot_status(cd, 13), CRYPT_SLOT_UNBOUND);

	// add previous key as unbound key
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, kc_key, 21, kc_token21, CRYPT_VOLUME_KEY_NO_SEGMENT), 21);

	EQ_(crypt_activate_by_keyslot_context(cd, NULL, 12, kc_pass12, CRYPT_ANY_SLOT, NULL, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), 12);
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, 12, kc_file12, CRYPT_ANY_SLOT, NULL, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), 12);
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, 21, kc_file21, CRYPT_ANY_SLOT, NULL, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY), 21);

	// reencrypt by keyfile
	NOTFAIL_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, kc_file12, kc_file21, CRYPT_ANY_SLOT, 21, "aes", "xts-plain64", &rparams), "Reencrypt init failed");
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	EQ_(crypt_keyslot_status(cd, 13), CRYPT_SLOT_UNBOUND);

	// reencrypt just by volume keys (new key is passed directly w/o being stored in any keyslot)
	rparams.flags |= CRYPT_REENCRYPT_CREATE_NEW_DIGEST;
	NOTFAIL_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, kc_key, kc_key2, CRYPT_ANY_SLOT, CRYPT_ANY_SLOT, "aes", "xts-plain64", &rparams), "Reencrypt init failed");
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	EQ_(crypt_keyslot_status(cd, 13), CRYPT_SLOT_UNBOUND);
	rparams.flags &= ~CRYPT_REENCRYPT_CREATE_NEW_DIGEST;
	// store new key in a keyslot
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, kc_key2, 12, kc_token12, 0), 12);

	// add previous key as unbound key.
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, kc_key, 21, kc_token21, CRYPT_VOLUME_KEY_NO_SEGMENT), 21);

	NOTFAIL_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, kc_pass12, kc_token21, CRYPT_ANY_SLOT, 21, "aes", "xts-plain64", &rparams), "Reencrypt init failed");
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	EQ_(crypt_keyslot_status(cd, 13), CRYPT_SLOT_UNBOUND);

	// add previous key as unbound key.
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, kc_key2, 12, kc_token12, CRYPT_VOLUME_KEY_NO_SEGMENT), 12);

	rparams.max_hotzone_size = 1;
	NOTFAIL_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, kc_key, kc_key2, CRYPT_ANY_SLOT, 12, "aes", "xts-plain64", &rparams), "Reencrypt init failed");
	test_progress_steps = 2;
	OK_(crypt_reencrypt_run(cd, &test_progress, NULL));
	EQ_(crypt_reencrypt_status(cd, NULL), CRYPT_REENCRYPT_CLEAN);

	// test device activation via additional keyslot
	// keys
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc_key, CRYPT_ANY_SLOT, NULL, 0), -ESRCH);
	NOTFAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc_key, CRYPT_ANY_SLOT, kc_key2, 0), "Failed to activate device in reencryption");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	// tokens
	NOTFAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc_token21, CRYPT_ANY_SLOT, kc_token12, 0), "Failed to activate device in reencryption");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	// files
	NOTFAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc_file21, CRYPT_ANY_SLOT, kc_file12, 0), "Failed to activate device in reencryption");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	// passphrases
	NOTFAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc_pass21, CRYPT_ANY_SLOT, kc_pass12, 0), "Failed to activate device in reencryption");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);

	EQ_(crypt_keyslot_status(cd, 13), CRYPT_SLOT_UNBOUND);

	crypt_keyslot_context_free(kc_pass21);
	crypt_keyslot_context_free(kc_file12);
	crypt_keyslot_context_free(kc_file21);
	crypt_keyslot_context_free(kc_token12);
	crypt_keyslot_context_free(kc_token21);

	CRYPT_FREE(cd);

	/* specifically test reencryption of device with no active keyslots */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, key, key_size, &(struct crypt_params_luks2){ .sector_size = 512 }));
	FAIL_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, kc_key, kc_key2, CRYPT_ANY_SLOT, CRYPT_ANY_SLOT, "aes", "xts-plain64", &rparams), "Reencrypt init failed due to missing new key keyslot.");
	rparams.flags |= CRYPT_REENCRYPT_CREATE_NEW_DIGEST;
	NOTFAIL_(crypt_reencrypt_init_by_keyslot_context(cd, NULL, kc_key, kc_key2, CRYPT_ANY_SLOT, CRYPT_ANY_SLOT, "aes", "xts-plain64", &rparams), "Reencrypt init failed.");

	FAIL_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc_key, CRYPT_ANY_SLOT, NULL, 0), "Missing key for device in reencryption.");
	FAIL_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc_key2, CRYPT_ANY_SLOT, NULL, 0), "Missing key for device in reencryption.");

	/* after reencryption gets initialized the order in which user provides keyslot contexts does not matter */
	OK_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc_key, CRYPT_ANY_SLOT, kc_key2, 0));
	OK_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc_key2, CRYPT_ANY_SLOT, kc_key, 0));

	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));

	/* check digest was properly stored in mda */
	OK_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc_key2, CRYPT_ANY_SLOT, NULL, 0));
	FAIL_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc_key, CRYPT_ANY_SLOT, NULL, 0), "Not valid volume key");

	/* add keyslot by new volume key */
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, kc_key2, 12, kc_pass12, 0), 12);
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, 12, kc_pass12, CRYPT_ANY_SLOT, NULL, 0), 12);

	crypt_keyslot_context_free(kc_pass12);
	crypt_keyslot_context_free(kc_key);
	crypt_keyslot_context_free(kc_key2);

	CRYPT_FREE(cd);

	NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");
	NOTFAIL_(keyctl_unlink(kid1, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");

	_cleanup_dmdevices();
}
#endif

static void LuksKeyslotAdd(void)
{
	struct crypt_params_luks2 params = {
		.sector_size = 512
	};
	char key[128], key3[128];
#if KERNEL_KEYRING
	int ks;
	key_serial_t kid;
#endif
	const struct crypt_token_params_luks2_keyring tparams = {
		.key_description = KEY_DESC_TEST0
	};

	const char *vk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	const char *vk_hex2 = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1e";
	size_t key_size = strlen(vk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset;
	struct crypt_keyslot_context *um1, *um2;

	OK_(crypt_decode_key(key, vk_hex, key_size));
	OK_(crypt_decode_key(key3, vk_hex2, key_size));

	// init test devices
	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_payload_offset + 1));

	// test support for embedded key (after crypt_format)
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_keyslot_context_init_by_volume_key(cd, NULL, key_size, &um1));
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &um2));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 3, um2, 0), 3);
	EQ_(crypt_keyslot_status(cd, 3), CRYPT_SLOT_ACTIVE_LAST);
	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);
	CRYPT_FREE(cd);

	// test add by volume key
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_keyslot_context_init_by_volume_key(cd, key, key_size, &um1));
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE1, strlen(PASSPHRASE1), &um2));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, CRYPT_ANY_SLOT, um2, 0), 0);
	EQ_(crypt_keyslot_status(cd, 0), CRYPT_SLOT_ACTIVE);
	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);

	// Add by same passphrase
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &um1));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 1, um1, 0), 1);
	EQ_(crypt_keyslot_status(cd, 1), CRYPT_SLOT_ACTIVE);
	crypt_keyslot_context_free(um1);

	// new passphrase can't be provided by key method
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &um1));
	OK_(crypt_keyslot_context_init_by_volume_key(cd, key, key_size, &um2));
	FAIL_(crypt_keyslot_add_by_keyslot_context(cd, 1, um1, CRYPT_ANY_SLOT, um2, 0), "Can't get passphrase via selected unlock method");
	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);

	// add by keyfile
	OK_(prepare_keyfile(KEYFILE1, PASSPHRASE1, strlen(PASSPHRASE1)));
	OK_(prepare_keyfile(KEYFILE2, KEY1, strlen(KEY1)));
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &um1));
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE2, 0, 0, &um2));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, 0, um1, 2, um2, 0), 2);
	EQ_(crypt_keyslot_status(cd, 2), CRYPT_SLOT_ACTIVE);
	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);

	// add by same keyfile
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE2, 0, 0, &um1));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, 2, um1, 4, um1, 0), 4);
	EQ_(crypt_keyslot_status(cd, 4), CRYPT_SLOT_ACTIVE);
	crypt_keyslot_context_free(um1);

	// keyslot already exists
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &um1));
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &um2));
	FAIL_(crypt_keyslot_add_by_keyslot_context(cd, 3, um1, 0, um2, 0), "Keyslot already exists.");
	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);

	// generate new unbound key
	OK_(crypt_keyslot_context_init_by_volume_key(cd, NULL, 9, &um1));
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &um2));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 10, um2, CRYPT_VOLUME_KEY_NO_SEGMENT), 10);
	EQ_(crypt_keyslot_status(cd, 10), CRYPT_SLOT_UNBOUND);
	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);

	EQ_(crypt_token_luks2_keyring_set(cd, 3, &tparams), 3);
	EQ_(crypt_token_assign_keyslot(cd, 3, 1), 3);
	EQ_(crypt_token_assign_keyslot(cd, 3, 3), 3);

	// test unlocking/adding keyslot by LUKS2 token
	OK_(crypt_keyslot_context_init_by_token(cd, CRYPT_ANY_TOKEN, NULL, NULL, 0, NULL, &um1));
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &um2));
	// passphrase not in keyring
	FAIL_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 13, um2, 0), "No token available.");
#if KERNEL_KEYRING
	// wrong passphrase in keyring
	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE1, strlen(PASSPHRASE1), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");
	FAIL_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 13, um2, 0), "No token available.");

	// token unlocks keyslot
	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 13, um2, 0), 13);
	EQ_(crypt_keyslot_status(cd, 13), CRYPT_SLOT_ACTIVE);

	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);

	// token provides passphrase for new keyslot
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &um1));
	OK_(crypt_keyslot_context_init_by_token(cd, CRYPT_ANY_TOKEN, NULL, NULL, 0, NULL, &um2));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, 3, um1, 30, um2, 0), 30);
	EQ_(crypt_keyslot_status(cd, 30), CRYPT_SLOT_ACTIVE);
	OK_(crypt_token_is_assigned(cd, 3, 30));

	// unlock and add by same token
	crypt_keyslot_context_free(um1);
	OK_(crypt_keyslot_context_init_by_token(cd, CRYPT_ANY_TOKEN, NULL, NULL, 0, NULL, &um1));
	ks = crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, CRYPT_ANY_SLOT, um1, 0);
	GE_(ks, 0);
	EQ_(crypt_keyslot_status(cd, ks), CRYPT_SLOT_ACTIVE);
	OK_(crypt_token_is_assigned(cd, 3, ks));
#endif
	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);

	CRYPT_FREE(cd);

	_cleanup_dmdevices();
}

static void VolumeKeyGet(void)
{
	struct crypt_params_luks2 params = {
		.sector_size = 512
	};
	char key[256], key2[256], key3[256];
#if KERNEL_KEYRING
	key_serial_t kid;
	const struct crypt_token_params_luks2_keyring tparams = {
		.key_description = KEY_DESC_TEST0
	};
#endif

	const char *vk_hex =  "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a"
			      "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1b",
		   *vk2_hex = "cb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a"
			      "cb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1c";
	size_t key_size = strlen(vk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";
	uint64_t r_payload_offset;
	struct crypt_keyslot_context *um1, *um2;

	OK_(crypt_decode_key(key, vk_hex, key_size));
	OK_(crypt_decode_key(key3, vk2_hex, key_size));

	OK_(prepare_keyfile(KEYFILE1, PASSPHRASE1, strlen(PASSPHRASE1)));

#if KERNEL_KEYRING
	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE1, strlen(PASSPHRASE1), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");
#endif

	// init test devices
	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_payload_offset + 1));

	// test support for embedded key (after crypt_format)
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, key_size, &params));
	key_size--;
	FAIL_(crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, key2, &key_size, NULL), "buffer too small");

	// check cached generated volume key can be retrieved
	key_size++;
	OK_(crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, key2, &key_size, NULL));
	OK_(crypt_volume_key_verify(cd, key2, key_size));
	CRYPT_FREE(cd);

	// check we can add keyslot via retrieved key
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_keyslot_context_init_by_volume_key(cd, key2, key_size, &um1));
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &um2));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 3, um2, 0), 3);
	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);
	CRYPT_FREE(cd);

	// check selected volume key can be retrieved and added
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	memset(key2, 0, key_size);
	OK_(crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, key2, &key_size, NULL));
	OK_(memcmp(key, key2, key_size));
	OK_(crypt_keyslot_context_init_by_volume_key(cd, key2, key_size, &um1));
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &um2));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 0, um2, 0), 0);
	crypt_keyslot_context_free(um2);
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &um2));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 1, um2, 0), 1);
	crypt_keyslot_context_free(um2);
#if KERNEL_KEYRING
	EQ_(crypt_token_luks2_keyring_set(cd, 0, &tparams), 0);
	EQ_(crypt_token_assign_keyslot(cd, 0, 1), 0);
#endif
	crypt_keyslot_context_free(um1);
	OK_(crypt_keyslot_context_init_by_volume_key(cd, key3, key_size, &um1));
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE1, strlen(PASSPHRASE1), &um2));
	EQ_(crypt_keyslot_add_by_keyslot_context(cd, CRYPT_ANY_SLOT, um1, 4, um2, CRYPT_VOLUME_KEY_NO_SEGMENT), 4);
	crypt_keyslot_context_free(um1);
	crypt_keyslot_context_free(um2);
	CRYPT_FREE(cd);

	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	// check key context is not usable
	OK_(crypt_keyslot_context_init_by_volume_key(cd, key, key_size, &um1));
	EQ_(crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, key2, &key_size, um1), -EINVAL);
	crypt_keyslot_context_free(um1);

	// by passphrase
	memset(key2, 0, key_size);
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &um1));
	EQ_(crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, key2, &key_size, um1), 0);
	OK_(memcmp(key, key2, key_size));
	memset(key2, 0, key_size);
	EQ_(crypt_volume_key_get_by_keyslot_context(cd, 0, key2, &key_size, um1), 0);
	OK_(memcmp(key, key2, key_size));
	crypt_keyslot_context_free(um1);

	// by keyfile
	memset(key2, 0, key_size);
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &um1));
	EQ_(crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, key2, &key_size, um1), 1);
	OK_(memcmp(key, key2, key_size));
	memset(key2, 0, key_size);
	EQ_(crypt_volume_key_get_by_keyslot_context(cd, 1, key2, &key_size, um1), 1);
	crypt_keyslot_context_free(um1);

#if KERNEL_KEYRING
	// by token
	OK_(crypt_keyslot_context_init_by_token(cd, CRYPT_ANY_TOKEN, NULL, NULL, 0, NULL, &um1));
	memset(key2, 0, key_size);
	EQ_(crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, key2, &key_size, um1), 1);
	OK_(memcmp(key, key2, key_size));
	crypt_keyslot_context_free(um1);

	// unbound keyslot by passphrase in keyring
	OK_(crypt_keyslot_context_init_by_keyring(cd, KEY_DESC_TEST0, &um1));
	memset(key2, 0, key_size);
	EQ_(crypt_volume_key_get_by_keyslot_context(cd, 4, key2, &key_size, um1), 4);
	OK_(memcmp(key3, key2, key_size));
	crypt_keyslot_context_free(um1);

	// by passphrase in keyring
	OK_(crypt_keyslot_context_init_by_keyring(cd, KEY_DESC_TEST0, &um1));
	memset(key2, 0, key_size);
	EQ_(crypt_volume_key_get_by_keyslot_context(cd, CRYPT_ANY_SLOT, key2, &key_size, um1), 1);
	OK_(memcmp(key, key2, key_size));
	crypt_keyslot_context_free(um1);
#endif
	CRYPT_FREE(cd);

	_remove_keyfiles();
	_cleanup_dmdevices();
}

static void KeyslotContextAndKeyringLink(void)
{
#if KERNEL_KEYRING
	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";
	struct crypt_keyslot_context *kc, *kc2;
	uint64_t r_payload_offset;
	char key[128];
	size_t key_size = 128;
	key_serial_t kid, keyring_in_user_id, keyring_in_session_id, linked_kid, linked_kid2;
	int suspend_status;
	struct crypt_active_device cad;
	char vk_buf[1024];
	long vk_len;

	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha256",
		.parallel_threads = 1,
		.max_memory_kb = 128,
		.iterations = 4,
		.flags = CRYPT_PBKDF_NO_BENCHMARK
	};
	struct crypt_params_luks2 params2 = {
		.pbkdf = &pbkdf,
		.sector_size = 4096
	};
	struct crypt_params_reencrypt rparams = {
		.direction = CRYPT_REENCRYPT_FORWARD,
		.resilience = "checksum",
		.hash = "sha256",
		.luks2 = &params2,
	};
	uint64_t r_header_size;

	if (_fips_mode) {
		pbkdf.type = CRYPT_KDF_PBKDF2;
		pbkdf.parallel_threads = 0;
		pbkdf.max_memory_kb = 0;
		pbkdf.iterations = 1000;
	}

	if (!t_dm_crypt_keyring_support()) {
		printf("WARNING: dm-crypt does not support keyring, skipping test.\n");
		return;
	}

	OK_(get_luks2_offsets(0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));

	// prepare the device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(set_fast_pbkdf(cd));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 32, KEY1, strlen(KEY1)), 1);
	EQ_(0, crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size, NULL, 0));

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	NOTFAIL_(kid, "Test or kernel keyring are broken.");

	keyring_in_user_id = add_key_set_perm("keyring", TEST_KEYRING_USER, NULL, 0, KEY_SPEC_USER_KEYRING, KEY_POS_ALL | KEY_USR_ALL);
	NOTFAIL_(keyring_in_user_id, "Test or kernel keyring are broken.");
	NOTFAIL_(snprintf(keyring_in_user_str_id, sizeof(keyring_in_user_str_id)-1, "%u", keyring_in_user_id), "Failed to get string id.");
	keyring_in_session_id = add_key_set_perm("keyring", TEST_KEYRING_SESSION, NULL, 0, KEY_SPEC_SESSION_KEYRING, KEY_POS_ALL | KEY_USR_ALL);
	NOTFAIL_(keyring_in_session_id, "Test or kernel keyring are broken.");

	// test passphrase
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, NULL, CRYPT_ANY_SLOT, NULL, 0), -EINVAL);
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_passphrase(cd, KEY1, strlen(KEY1), &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 1);
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_volume_key(cd, key, key_size, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	crypt_keyslot_context_free(kc);

	OK_(prepare_keyfile(KEYFILE1, KEY1, strlen(KEY1)));
	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 1);
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_keyring(cd, KEY_DESC_TEST0, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	crypt_keyslot_context_free(kc);

	// test activation
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	FAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), "already active");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_volume_key(cd, key, key_size, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	FAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), "already active");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 1);
	FAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), "already active");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_keyring(cd, KEY_DESC_TEST0, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_keyslot_context_free(kc);

	// test linking to a custom keyring linked in user keyring
	OK_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, NULL, "user", keyring_in_user_str_id /* TEST_KEYRING_USER_NAME */));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0));

	/*
	 * Otherwise we will not be able to search the TEST_KEYRING_USER in current context (see request_key(2):
	 * "The keyrings are searched in the order: thread-specific keyring, process-specific keyring, and then session keyring."
	 */
	NOTFAIL_(keyctl_link(keyring_in_user_id, KEY_SPEC_THREAD_KEYRING), "Failed to link in thread keyring.");

	FAIL_((linked_kid = request_key("logon", TEST_KEY_VK_USER, NULL, 0)), "VK was linked to custom keyring under wrong key type.");
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	NOTFAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "dm-crypt VK was not uploaded in thread kernel keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(keyctl_unlink(linked_kid, keyring_in_user_id), "VK was not linked to custom keyring after deactivation.");
	FAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "dm-crypt VK remain linked in thread keyring.");

	OK_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_LOGON, NULL, "logon", keyring_in_user_str_id /* TEST_KEYRING_USER_NAME */));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0));
	NOTFAIL_((linked_kid = request_key("logon", TEST_KEY_VK_LOGON, NULL, 0)), "VK was not linked to custom keyring.");
	NOTFAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "dm-crypt VK was not uploaded in thread kernel keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(keyctl_unlink(linked_kid, keyring_in_user_id), "VK was not linked to custom keyring after deactivation.");
	FAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "dm-crypt VK remain linked in thread keyring.");

	OK_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_LOGON, NULL, "logon", TEST_KEYRING_SESSION_NAME));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0));
	NOTFAIL_((linked_kid = request_key("logon", TEST_KEY_VK_LOGON, NULL, 0)), "VK was not linked to custom keyring.");
	NOTFAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "dm-crypt VK was not uploaded in thread kernel keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(keyctl_unlink(linked_kid, keyring_in_session_id), "VK was not linked to custom keyring after deactivation.");
	FAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "dm-crypt VK remain linked in thread keyring.");

	// test repeated activation
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0));
	NOTFAIL_((linked_kid = request_key("logon", TEST_KEY_VK_LOGON, NULL, 0)), "VK was not linked to custom keyring after repeated activation.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(request_key("logon", TEST_KEY_VK_LOGON, NULL, 0), "VK was not linked to custom keyring after deactivation.");
	NOTFAIL_(keyctl_unlink(linked_kid, keyring_in_session_id), "VK was not linked to custom keyring after deactivation.");
	FAIL_(request_key("logon", TEST_KEY_VK_LOGON, NULL, 0), "VK was probably wrongly linked in yet another keyring ");

	// change key type to default (user)
	OK_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, NULL, NULL, TEST_KEYRING_USER_NAME));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0));
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring after resetting key type.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	//NOTFAIL_(request_key("user", TEST_KEY_VK_USER, NULL, 0), "VK was not linked to custom keyring after deactivation.");
	NOTFAIL_(keyctl_unlink(linked_kid, keyring_in_user_id), "VK was not linked to custom keyring after deactivation.");
	FAIL_(request_key("user", TEST_KEY_VK_USER, NULL, 0), "VK was probably wrongly linked in yet another keyring ");

	// disable linking to session keyring
	crypt_set_keyring_to_link(cd, NULL, NULL, NULL, NULL);
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0));
	FAIL_(request_key("user", TEST_KEY_VK_USER, NULL, 0), "VK was probably wrongly linked in yet another keyring ");
	FAIL_(request_key("logon", TEST_KEY_VK_LOGON, NULL, 0), "VK was probably wrongly linked in yet another keyring ");
	NOTFAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "VK was not found in thread keyring");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "failed to unlink the key from thread keyring");

	// link VK to keyring and re-activate by the linked VK
	crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, NULL, "user", TEST_KEYRING_SESSION_NAME);
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(request_key("user", TEST_KEY_VK_USER, NULL, 0), "VK was not linked to session keyring.");
	OK_(crypt_keyslot_context_init_by_vk_in_keyring(cd, TEST_KEY_VK_USER_NAME, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(request_key("user", TEST_KEY_VK_USER, NULL, 0), "VK was not linked to session keyring after deactivation.");
	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER, keyring_in_session_id, "user"));
	FAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), "activation via VK in keyring after dropping the key");

	// load VK back to keyring by activating
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// activate by bad VK in keyring (test if VK digest is verified)
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to session keyring after activation.");
	GE_((vk_len = keyctl_read(linked_kid, vk_buf, sizeof(vk_buf))), 0);
	vk_buf[0] = ~vk_buf[0];
	OK_(keyctl_update(linked_kid, vk_buf, vk_len));
	FAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER, keyring_in_session_id, "user"));
	crypt_keyslot_context_free(kc);

	// After this point put resume tests only!
	OK_(crypt_keyslot_context_init_by_passphrase(cd, PASSPHRASE, strlen(PASSPHRASE), &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	suspend_status = crypt_suspend(cd, CDEVICE_1);
	if (suspend_status == -ENOTSUP) {
		printf("WARNING: Suspend/Resume not supported, skipping test.\n");
		OK_(crypt_deactivate(cd, CDEVICE_1));

		NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");
		CRYPT_FREE(cd);
		_cleanup_dmdevices();
		return;
	}
	OK_(suspend_status);
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(CRYPT_ACTIVATE_SUSPENDED, cad.flags & CRYPT_ACTIVATE_SUSPENDED);
	OK_(crypt_resume_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc));
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(0, cad.flags & CRYPT_ACTIVATE_SUSPENDED);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_volume_key(cd, key, key_size, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	OK_(crypt_suspend(cd, CDEVICE_1));
	EQ_(crypt_resume_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_keyfile(cd, KEYFILE1, 0, 0, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 1);
	OK_(crypt_suspend(cd, CDEVICE_1));
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(CRYPT_ACTIVATE_SUSPENDED, cad.flags & CRYPT_ACTIVATE_SUSPENDED);
	EQ_(crypt_resume_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_keyslot_context_free(kc);

	OK_(crypt_keyslot_context_init_by_keyring(cd, KEY_DESC_TEST0, &kc));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	OK_(crypt_suspend(cd, CDEVICE_1));
	EQ_(crypt_resume_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_keyslot_context_free(kc);

	// resume by VK keyring context
	crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, NULL, "user", TEST_KEYRING_SESSION_NAME);
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0));
	NOTFAIL_(request_key("user", TEST_KEY_VK_USER, NULL, 0), "VK was not linked to session keyring.");
	OK_(crypt_suspend(cd, CDEVICE_1));
	OK_(crypt_keyslot_context_init_by_vk_in_keyring(cd, TEST_KEY_VK_USER_NAME, &kc));
	EQ_(crypt_resume_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(request_key("user", TEST_KEY_VK_USER, NULL, 0), "VK was not linked to session keyring after deactivation.");
	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER, keyring_in_session_id, "user"));
	FAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), "activation via VK in keyring after dropping the key");
	crypt_keyslot_context_free(kc);

	NOTFAIL_(keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING), "Test or kernel keyring are broken.");
	CRYPT_FREE(cd);

	// test storing two VKs in keyring during reencryption
	OK_(get_luks2_offsets(1, 0, 0, &r_header_size, NULL));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_header_size + 16));

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 1);
	EQ_(crypt_keyslot_add_by_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 0);
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 1, 0, "aes", "xts-plain64", &rparams), 2);

	// when no key name is specified, don't allow specifying type and keyring
	EQ_(crypt_set_keyring_to_link(cd, NULL, NULL, NULL, keyring_in_user_str_id), -EINVAL);
	EQ_(crypt_set_keyring_to_link(cd, NULL, NULL, "user", NULL), -EINVAL);
	EQ_(crypt_set_keyring_to_link(cd, NULL, NULL, "user", keyring_in_user_str_id), -EINVAL);

	// key names have to be specified starting from the first
	EQ_(crypt_set_keyring_to_link(cd, NULL, TEST_KEY_VK_USER, "user", keyring_in_user_str_id), -EINVAL);
	EQ_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, NULL, "user", keyring_in_user_str_id), -ESRCH);

	EQ_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, TEST_KEY_VK_USER2, "user", keyring_in_user_str_id), 0);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	FAIL_((linked_kid = request_key("logon", TEST_KEY_VK_USER, NULL, 0)), "VK was linked to custom keyring under wrong key type.");
	FAIL_((linked_kid2 = request_key("logon", TEST_KEY_VK_USER2, NULL, 0)), "VK was linked to custom keyring under wrong key type.");
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	NOTFAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "VK was not linked to custom keyring.");
	NOTFAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "dm-crypt VK was not uploaded in thread kernel keyring.");
	NOTFAIL_(_kernel_key_by_segment_and_type(cd, 1, "logon"), "dm-crypt VK was not uploaded in thread kernel keyring.");

	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(keyctl_unlink(linked_kid, keyring_in_user_id), "VK was not linked to custom keyring after deactivation.");
	NOTFAIL_(keyctl_unlink(linked_kid2, keyring_in_user_id), "VK was not linked to custom keyring after deactivation.");
	FAIL_(_kernel_key_by_segment_and_type(cd, 0, "logon"), "dm-crypt VK remain linked in thread keyring.");
	// BUG: Reencryption code does not unlink the second VK
	// FAIL_(_kernel_key_by_segment_and_type(cd, 1, "logon"), "dm-crypt VK remain linked in thread keyring.");

	// check that VKs are linked without calling crypt_activate_by_passphrase again, when activate is called on the same context
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	NOTFAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "VK was not linked to custom keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	NOTFAIL_(keyctl_unlink(linked_kid, keyring_in_user_id), "VK was not linked to custom keyring after deactivation.");
	NOTFAIL_(keyctl_unlink(linked_kid2, keyring_in_user_id), "VK was not linked to custom keyring after deactivation.");

	// verify that the VK is no longer stored in a custom keyring
	EQ_(crypt_set_keyring_to_link(cd, NULL, NULL, NULL, NULL), 0);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	FAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	FAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "VK was not linked to custom keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// test that after reencryption finishes (and there is only one VK), only one VK name is used
	EQ_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, TEST_KEY_VK_USER2, "user", keyring_in_user_str_id), 0);
	rparams.flags = CRYPT_REENCRYPT_RESUME_ONLY;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 1, 0, "aes", "xts-plain64", &rparams), 2);
	OK_(crypt_reencrypt_run(cd, NULL, NULL));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	FAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "VK was not linked to custom keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	CRYPT_FREE(cd);

	// Reenncryption: test reactivation using linked keys
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 1);
	EQ_(crypt_keyslot_add_by_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE), CRYPT_VOLUME_KEY_NO_SEGMENT), 0);
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;

	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 1, 0, "aes", "xts-plain64", &rparams), 2);
	EQ_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, TEST_KEY_VK_USER2, "user", keyring_in_user_str_id), 0);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	NOTFAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "VK was not linked to custom keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	OK_(crypt_keyslot_context_init_by_vk_in_keyring(cd, TEST_KEY_VK_USER_NAME , &kc));
	OK_(crypt_keyslot_context_init_by_vk_in_keyring(cd, TEST_KEY_VK_USER2_NAME, &kc2));

	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), -ESRCH);
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc2, CRYPT_ANY_SLOT, NULL, 0), -ESRCH);
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, NULL, CRYPT_ANY_SLOT, kc, 0), -EINVAL);
	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, NULL, CRYPT_ANY_SLOT, kc2, 0), -EINVAL);

	EQ_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc2, 0), 0);
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc2, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER, keyring_in_user_id, "user"));
	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER2, keyring_in_user_id, "user"));
	FAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc2, 0), "Failed to read key from kernel keyring");

	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	NOTFAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "VK was not linked to custom keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));

	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc2, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	GE_((vk_len = keyctl_read(linked_kid, vk_buf, sizeof(vk_buf))), 0);
	vk_buf[0] = ~vk_buf[0];
	OK_(keyctl_update(linked_kid, vk_buf, vk_len));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc2, 0), -EPERM);

	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER, keyring_in_user_id, "user"));
	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER2, keyring_in_user_id, "user"));
	CRYPT_FREE(cd);

	// Decryption: test reactivation using linked keys
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 32, &params2));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 1);
	rparams.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY;
	rparams.mode = CRYPT_REENCRYPT_DECRYPT;
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), 1, CRYPT_ANY_SLOT, NULL, NULL, &rparams), 0);
	EQ_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, TEST_KEY_VK_USER2, "user", keyring_in_user_str_id), 0);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 1);
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	FAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "second VK was linked to custom keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));

	OK_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0));
	OK_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc, 0));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER, keyring_in_user_id, "user"));
	FAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), "Failed to read key from kernel keyring");

	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 1);
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	FAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "VK was not linked to custom keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));

	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc2, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	GE_((vk_len = keyctl_read(linked_kid, vk_buf, sizeof(vk_buf))), 0);
	vk_buf[0] = ~vk_buf[0];
	OK_(keyctl_update(linked_kid, vk_buf, vk_len));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc, 0), -EPERM);
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), -EPERM);

	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER, keyring_in_user_id, "user"));
	CRYPT_FREE(cd);

	// Encryption: test reactivation using linked keys
	_cleanup_dmdevices();
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, 12*1024*2));

	OK_(crypt_init(&cd, DMDIR H_DEVICE));

	params2.sector_size = 512;
	params2.data_device = DMDIR L_DEVICE_OK;
	rparams = (struct crypt_params_reencrypt) {
		.mode = CRYPT_REENCRYPT_ENCRYPT,
		.resilience = "checksum",
		.hash = "sha256",
		.luks2 = &params2,
		.flags = CRYPT_REENCRYPT_INITIALIZE_ONLY,
	};
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", NULL, NULL, 64, &params2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 64, PASSPHRASE, strlen(PASSPHRASE)), 1);
	EQ_(crypt_reencrypt_init_by_passphrase(cd, NULL, PASSPHRASE, strlen(PASSPHRASE), CRYPT_ANY_SLOT, 1, "aes", "xts-plain64", &rparams), 0);

	EQ_(crypt_set_keyring_to_link(cd, TEST_KEY_VK_USER, TEST_KEY_VK_USER2, "user", keyring_in_user_str_id), 0);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 1);
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	FAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "second VK was linked to custom keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));

	OK_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0));
	OK_(crypt_activate_by_keyslot_context(cd, NULL, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc, 0));

	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER, keyring_in_user_id, "user"));
	FAIL_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), "Failed to read key from kernel keyring");

	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 1);
	NOTFAIL_((linked_kid = request_key("user", TEST_KEY_VK_USER, NULL, 0)), "VK was not linked to custom keyring.");
	FAIL_((linked_kid2 = request_key("user", TEST_KEY_VK_USER2, NULL, 0)), "VK was not linked to custom keyring.");
	OK_(crypt_deactivate(cd, CDEVICE_1));

	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	GE_((vk_len = keyctl_read(linked_kid, vk_buf, sizeof(vk_buf))), 0);
	vk_buf[0] = ~vk_buf[0];
	OK_(keyctl_update(linked_kid, vk_buf, vk_len));
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, kc, 0), -EPERM);
	EQ_(crypt_activate_by_keyslot_context(cd, CDEVICE_1, CRYPT_ANY_SLOT, kc, CRYPT_ANY_SLOT, NULL, 0), -EPERM);

	OK_(_drop_keyring_key_from_keyring_name(TEST_KEY_VK_USER, keyring_in_user_id, "user"));
	CRYPT_FREE(cd);

	crypt_keyslot_context_free(kc);
	crypt_keyslot_context_free(kc2);

	_cleanup_dmdevices();
#else
	printf("WARNING: cryptsetup compiled with kernel keyring service disabled, skipping test.\n");
#endif
}

static int _crypt_load_check(struct crypt_device *_cd)
{
#if HAVE_BLKID
	return crypt_load(_cd, CRYPT_LUKS, NULL);
#else
	return -ENOTSUP;
#endif
}

static void Luks2Repair(void)
{
	char rollback[256];

	GE_(snprintf(rollback, sizeof(rollback),
	    "dd if=" IMAGE_PV_LUKS2_SEC ".bcp of=%s bs=1M 2>/dev/null", DEVICE_6), 0);

	OK_(crypt_init(&cd, DEVICE_6));

	FAIL_(_crypt_load_check(cd), "Ambiguous signature detected");
	FAIL_(crypt_repair(cd, CRYPT_LUKS1, NULL), "Not a LUKS2 device");

	/* check explicit LUKS2 repair works */
	OK_(crypt_repair(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DEVICE_6));

	/* rollback */
	OK_(_system(rollback, 1));
	FAIL_(_crypt_load_check(cd), "Ambiguous signature detected");

	/* check repair with type detection works */
	OK_(crypt_repair(cd, CRYPT_LUKS, NULL));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	CRYPT_FREE(cd);

	/* repeat with locking disabled (must not have any effect) */
	OK_(_system(rollback, 1));
	OK_(crypt_init(&cd, DEVICE_6));
	OK_(crypt_metadata_locking(cd, 0));

	FAIL_(_crypt_load_check(cd), "Ambiguous signature detected");
	FAIL_(crypt_repair(cd, CRYPT_LUKS1, NULL), "Not a LUKS2 device");

	/* check explicit LUKS2 repair works */
	OK_(crypt_repair(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	CRYPT_FREE(cd);
	OK_(crypt_init(&cd, DEVICE_6));

	/* rollback */
	OK_(_system(rollback, 1));
	FAIL_(_crypt_load_check(cd), "Ambiguous signature detected");

	/* check repair with type detection works */
	OK_(crypt_repair(cd, CRYPT_LUKS, NULL));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	CRYPT_FREE(cd);
}

static void int_handler(int sig __attribute__((__unused__)))
{
	_quit++;
}

int main(int argc, char *argv[])
{
	struct sigaction sa = { .sa_handler = int_handler };
	int i;

	if (getuid() != 0) {
		printf("You must be root to run this test.\n");
		exit(77);
	}
#ifndef NO_CRYPTSETUP_PATH
	if (getenv("CRYPTSETUP_PATH")) {
		printf("Cannot run this test with CRYPTSETUP_PATH set.\n");
		exit(77);
	}
#endif
	for (i = 1; i < argc; i++) {
		if (!strcmp("-v", argv[i]) || !strcmp("--verbose", argv[i]))
			_verbose = 1;
		else if (!strcmp("--debug", argv[i]))
			_debug = _verbose = 1;
	}

	/* Handle interrupt properly */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	register_cleanup(_cleanup);

	_cleanup();
	if (_setup()) {
		printf("Cannot set test devices.\n");
		_cleanup();
		exit(77);
	}

	crypt_set_debug_level(_debug ? CRYPT_DEBUG_JSON : CRYPT_DEBUG_NONE);

	RUN_(AddDeviceLuks2, "Format and use LUKS2 device");
	RUN_(Luks2MetadataSize, "LUKS2 metadata settings");
	RUN_(Luks2HeaderLoad, "LUKS2 header load");
	RUN_(Luks2HeaderRestore, "LUKS2 header restore");
	RUN_(Luks2HeaderBackup, "LUKS2 header backup");
	RUN_(ResizeDeviceLuks2, "LUKS2 device resize tests");
	RUN_(UseLuks2Device, "Use pre-formated LUKS2 device");
	RUN_(SuspendDevice, "LUKS2 Suspend/Resume");
	RUN_(UseTempVolumes, "Format and use temporary encrypted device");
	RUN_(Tokens, "General tokens API");
	RUN_(TokenActivationByKeyring, "Builtin kernel keyring token");
	RUN_(LuksConvert, "LUKS1 <-> LUKS2 conversions");
	RUN_(Pbkdf, "Default PBKDF manipulation routines");
	RUN_(Luks2KeyslotParams, "Add a new keyslot with different encryption");
	RUN_(Luks2KeyslotAdd, "Add a new keyslot by unused key");
	RUN_(Luks2ActivateByKeyring, "LUKS2 activation by passphrase in keyring");
	RUN_(Luks2Requirements, "LUKS2 requirements flags");
	RUN_(Luks2Integrity, "LUKS2 with data integrity");
	RUN_(Luks2Refresh, "Active device table refresh");
	RUN_(Luks2Flags, "LUKS2 persistent flags");
#if KERNEL_KEYRING && USE_LUKS2_REENCRYPTION
	RUN_(Luks2Reencryption, "LUKS2 reencryption");
#endif
	RUN_(LuksKeyslotAdd, "Adding keyslot via new API");
	RUN_(VolumeKeyGet, "Getting volume key via keyslot context API");
	RUN_(KeyslotContextAndKeyringLink, "Activate via keyslot context API and linking VK to a keyring");
	RUN_(Luks2Repair, "LUKS2 repair"); // test disables metadata locking. Run always last!

	_cleanup();
	return 0;
}
