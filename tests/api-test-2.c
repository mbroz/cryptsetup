/*
 * cryptsetup library LUKS2 API check functions
 *
 * Copyright (C) 2009-2018 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2018, Milan Broz
 * Copyright (C) 2016-2018, Ondrej Kozina
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <sys/types.h>
#ifdef KERNEL_KEYRING
#include <linux/keyctl.h>
#include <sys/syscall.h>
#ifndef HAVE_KEY_SERIAL_T
#define HAVE_KEY_SERIAL_T
#include <stdint.h>
typedef int32_t key_serial_t;
#endif
#endif

#include "api_test.h"
#include "luks.h"
#include "libcryptsetup.h"

#define DMDIR "/dev/mapper/"

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
#define REQS_LUKS2_HEADER "luks2_header_requirements"
#define NO_REQS_LUKS2_HEADER "luks2_header_requirements_free"
#define BACKUP_FILE "csetup_backup_file"
#define IMAGE1 "compatimage2.img"
#define IMAGE_EMPTY "empty.img"

#define KEYFILE1 "key1.file"
#define KEY1 "compatkey"

#define KEYFILE2 "key2.file"
#define KEY2 "0123456789abcdef"

#define PASSPHRASE "blabla"
#define PASSPHRASE1 "albalb"

#define DEVICE_TEST_UUID "12345678-1234-1234-1234-123456789abc"

#define DEVICE_WRONG "/dev/Ooo_"
#define DEVICE_CHAR "/dev/zero"
#define THE_LFILE_TEMPLATE "cryptsetup-tstlp.XXXXXX"

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
#define PASS0 "aaa"
#define PASS1 "hhh"
#define PASS2 "ccc"
#define PASS3 "ddd"
#define PASS4 "eee"
#define PASS5 "fff"
#define PASS6 "ggg"
#define PASS7 "bbb"
#define PASS8 "iii"

static int _fips_mode = 0;

static char *DEVICE_1 = NULL;
static char *DEVICE_2 = NULL;
static char *DEVICE_3 = NULL;
static char *DEVICE_4 = NULL;
static char *DEVICE_5 = NULL;

static char *tmp_file_1 = NULL;
static char *test_loop_file = NULL;

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
		return DEFAULT_LUKS2_MEMORY_KB;

	memory_kb = pagesize / 1024 * pages / 2;

	if (memory_kb < DEFAULT_LUKS2_MEMORY_KB)
		return (uint32_t)memory_kb;

	return DEFAULT_LUKS2_MEMORY_KB;
}

static unsigned _min(unsigned a, unsigned b)
{
	return a < b ? a : b;
}

/* FIXME: will fail with various LUKS2 header sizes */
static int get_luks2_offsets(int metadata_device,
			    unsigned int alignpayload_sec,
			    unsigned int alignoffset_sec, /* unused in LUKS2, bug? */
			    unsigned int sector_size,
			    uint64_t *r_header_size,
			    uint64_t *r_payload_offset)
{
	if (!sector_size)
		sector_size = 512; /* default? */

	if ((sector_size % 512) && (sector_size % 4096))
		return -1;

	if (r_payload_offset) {
		if (metadata_device)
			*r_payload_offset = DIV_ROUND_UP_MODULO(4*1024*1024, (alignpayload_sec ?: 1) * sector_size);
		else
			*r_payload_offset = alignpayload_sec * sector_size;

		*r_payload_offset /= sector_size;
	}

	if (r_header_size)
		*r_header_size = (4*1024*1024) / sector_size;

	return 0;
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

static void _cleanup_dmdevices(void)
{
	struct stat st;

	if (!stat(DMDIR H_DEVICE, &st))
		_system("dmsetup remove " DM_RETRY H_DEVICE, 0);

	if (!stat(DMDIR H_DEVICE_WRONG, &st))
		_system("dmsetup remove " DM_RETRY H_DEVICE_WRONG, 0);

	if (!stat(DMDIR L_DEVICE_0S, &st))
		_system("dmsetup remove " DM_RETRY L_DEVICE_0S, 0);

	if (!stat(DMDIR L_DEVICE_1S, &st))
		_system("dmsetup remove " DM_RETRY L_DEVICE_1S, 0);

	if (!stat(DMDIR L_DEVICE_WRONG, &st))
		_system("dmsetup remove " DM_RETRY L_DEVICE_WRONG, 0);

	if (!stat(DMDIR L_DEVICE_OK, &st))
		_system("dmsetup remove " DM_RETRY L_DEVICE_OK, 0);

	t_dev_offset = 0;
}

static void _cleanup(void)
{
	struct stat st;

	//_system("udevadm settle", 0);

	if (!stat(DMDIR CDEVICE_1, &st))
		_system("dmsetup remove " CDEVICE_1, 0);

	if (!stat(DMDIR CDEVICE_2, &st))
		_system("dmsetup remove " CDEVICE_2, 0);

	if (!stat(DEVICE_EMPTY, &st))
		_system("dmsetup remove " DEVICE_EMPTY_name, 0);

	if (!stat(DEVICE_ERROR, &st))
		_system("dmsetup remove " DEVICE_ERROR_name, 0);

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

	_system("rm -f " IMAGE_EMPTY, 0);
	_system("rm -f " IMAGE1, 0);
	_system("rm -rf " CONV_DIR, 0);

	if (test_loop_file)
		remove(test_loop_file);
	if (tmp_file_1)
		remove(tmp_file_1);

	remove(REQS_LUKS2_HEADER);
	remove(NO_REQS_LUKS2_HEADER);
	remove(BACKUP_FILE);

	_remove_keyfiles();

	free(tmp_file_1);
	free(test_loop_file);
	free(THE_LOOP_DEV);
	free(DEVICE_1);
	free(DEVICE_2);
	free(DEVICE_3);
	free(DEVICE_4);
	free(DEVICE_5);
}

static int _setup(void)
{
	int fd, ro = 0;
	char cmd[128];

	test_loop_file = strdup(THE_LFILE_TEMPLATE);
	if ((fd=mkstemp(test_loop_file)) == -1) {
		printf("cannot create temporary file with template %s\n", test_loop_file);
		return 1;
	}
	close(fd);
	snprintf(cmd, sizeof(cmd), "dd if=/dev/zero of=%s bs=%d count=%d 2>/dev/null",
		 test_loop_file, SECTOR_SIZE, TST_LOOP_FILE_SIZE);
	if (_system(cmd, 1))
		return 1;

	fd = loop_attach(&THE_LOOP_DEV, test_loop_file, 0, 0, &ro);
	close(fd);

	tmp_file_1 = strdup(THE_LFILE_TEMPLATE);
	if ((fd=mkstemp(tmp_file_1)) == -1) {
		printf("cannot create temporary file with template %s\n", tmp_file_1);
		return 1;
	}
	close(fd);
	snprintf(cmd, sizeof(cmd), "dd if=/dev/zero of=%s bs=%d count=%d 2>/dev/null",
		 tmp_file_1, SECTOR_SIZE, 10);
	if (_system(cmd, 1))
		return 1;

	_system("dmsetup create " DEVICE_EMPTY_name " --table \"0 10000 zero\"", 1);
	_system("dmsetup create " DEVICE_ERROR_name " --table \"0 10000 error\"", 1);

	_system(" [ ! -e " IMAGE1 " ] && xz -dk " IMAGE1 ".xz", 1);
	fd = loop_attach(&DEVICE_1, IMAGE1, 0, 0, &ro);
	close(fd);

	_system("dd if=/dev/zero of=" IMAGE_EMPTY " bs=1M count=32 2>/dev/null", 1);
	fd = loop_attach(&DEVICE_2, IMAGE_EMPTY, 0, 0, &ro);
	close(fd);

	_system(" [ ! -e " NO_REQS_LUKS2_HEADER " ] && xz -dk " NO_REQS_LUKS2_HEADER ".xz", 1);
	fd = loop_attach(&DEVICE_4, NO_REQS_LUKS2_HEADER, 0, 0, &ro);
	close(fd);

	_system(" [ ! -e " REQS_LUKS2_HEADER " ] && xz -dk " REQS_LUKS2_HEADER ".xz", 1);
	fd = loop_attach(&DEVICE_5, REQS_LUKS2_HEADER, 0, 0, &ro);
	close(fd);

	_system(" [ ! -d " CONV_DIR " ] && tar xJf " CONV_DIR ".tar.xz", 1);

	if (_system("modprobe dm-crypt", 1))
		return 1;

	if (t_dm_check_versions())
		return 1;

	_system("rmmod dm-crypt", 0);

	_fips_mode = fips_mode();
	if (_debug)
		printf("FIPS MODE: %d\n", _fips_mode);

	/* Use default log callback */
	crypt_set_log_callback(NULL, &global_log_callback, NULL);

	return 0;
}

#ifdef KERNEL_KEYRING
static key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring)
{
	return syscall(__NR_add_key, type, description, payload, plen, keyring);
}

static key_serial_t keyctl_unlink(key_serial_t key, key_serial_t keyring)
{
	return syscall(__NR_keyctl, KEYCTL_UNLINK, key, keyring);
}

static key_serial_t request_key(const char *type,
	const char *description,
	const char *callout_info,
	key_serial_t keyring)
{
	return syscall(__NR_request_key, type, description, callout_info, keyring);
}

static key_serial_t _kernel_key_by_segment(struct crypt_device *cd, int segment)
{
	char key_description[1024];

	if (snprintf(key_description, sizeof(key_description), "cryptsetup:%s-d%u", crypt_get_uuid(cd), segment) < 1)
		return -1;

	return request_key("logon", key_description, NULL, 0);
}

static int _volume_key_in_keyring(struct crypt_device *cd, int segment)
{
	return _kernel_key_by_segment(cd, segment);
}

static int _drop_keyring_key(struct crypt_device *cd, int segment)
{
	key_serial_t kid = _kernel_key_by_segment(cd, segment);

	if (kid < 0)
		return -1;

	return keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING);
}
#endif

static int test_open(struct crypt_device *cd,
		     int token,
		     char **buffer,
		     size_t *buffer_len,
		     void *usrptr)
{
	const char *str = (const char *)usrptr;
	char *buf = malloc(strlen(str));
	if (!buf)
		return -ENOMEM;

	strncpy(buf, str, strlen(str));
	*buffer = buf;
	*buffer_len = strlen(str);

	return 0;
}

static int test_validate(struct crypt_device *cd, const char *json)
{
	return (strstr(json, "magic_string") == NULL);
}

static void UseLuks2Device(void)
{
	struct crypt_device *cd;
	char key[128];
	size_t key_size;

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	OK_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0), "already open");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_deactivate(cd, CDEVICE_1), "no such device");

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
	}
#endif

	key_size = 16;
	OK_(strcmp("aes", crypt_get_cipher(cd)));
	OK_(strcmp("cbc-essiv:sha256", crypt_get_cipher_mode(cd)));
	OK_(strcmp(DEVICE_1_UUID, crypt_get_uuid(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(8192, crypt_get_data_offset(cd));

	if (!_fips_mode) {
		EQ_(0, crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size, KEY1, strlen(KEY1)));
		OK_(crypt_volume_key_verify(cd, key, key_size));
		OK_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0));
		OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
		EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
		OK_(crypt_deactivate(cd, CDEVICE_1));

		key[1] = ~key[1];
		FAIL_(crypt_volume_key_verify(cd, key, key_size), "key mismatch");
		FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "key mismatch");
	}
	crypt_free(cd);
}

static void SuspendDevice(void)
{
	int suspend_status;
	struct crypt_device *cd;

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));

	suspend_status = crypt_suspend(cd, CDEVICE_1);
	if (suspend_status == -ENOTSUP) {
		printf("WARNING: Suspend/Resume not supported, skipping test.\n");
		OK_(crypt_deactivate(cd, CDEVICE_1));
		crypt_free(cd);
		return;
	}

	OK_(suspend_status);
#ifdef KERNEL_KEYRING
	FAIL_(_volume_key_in_keyring(cd, 0), "");
#endif
	FAIL_(crypt_suspend(cd, CDEVICE_1), "already suspended");

	FAIL_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)-1), "wrong key");
	OK_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)));
	FAIL_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)), "not suspended");

	OK_(prepare_keyfile(KEYFILE1, KEY1, strlen(KEY1)));
	OK_(crypt_suspend(cd, CDEVICE_1));
	FAIL_(crypt_resume_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1 "blah", 0), "wrong keyfile");
	FAIL_(crypt_resume_by_keyfile_offset(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 1, 0), "wrong key");
	OK_(crypt_resume_by_keyfile_offset(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0, 0));
	FAIL_(crypt_resume_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0), "not suspended");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	/* create LUKS device with detached header */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DEVICE_2));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
	crypt_free(cd);

	/* Should be able to suspend but not resume if not header specified */
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	OK_(crypt_suspend(cd, CDEVICE_1));
	FAIL_(crypt_suspend(cd, CDEVICE_1), "already suspended");
	FAIL_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)-1), "no header");
	crypt_free(cd);

	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, DEVICE_1));
	OK_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)));

	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	_remove_keyfiles();
}

static void AddDeviceLuks2(void)
{
	struct crypt_device *cd;
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha256",
		.parallel_threads = 4,
		.max_memory_kb = 1024,
		.time_ms = 1
	};
	struct crypt_params_luks2 params = {
		.pbkdf = &pbkdf,
		.data_device = DEVICE_2,
		.sector_size = 512
	};
	char key[128], key2[128], key3[128];

	const char *passphrase = "blabla", *passphrase2 = "nsdkFI&Y#.sd";
	const char *mk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	const char *mk_hex2 = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1e";
	size_t key_size = strlen(mk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset, r_header_size, r_size_1;

	crypt_decode_key(key, mk_hex, key_size);
	crypt_decode_key(key3, mk_hex2, key_size);

	// init test devices
	OK_(get_luks2_offsets(1, 0, 0, 0, &r_header_size, &r_payload_offset));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, r_header_size - 1));

	// format
	OK_(crypt_init(&cd, DMDIR H_DEVICE_WRONG));
	params.data_alignment = 0;
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Not enough space for keyslots material");
	crypt_free(cd);

	// test payload_offset = 0 for encrypted device with external header device
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_get_data_offset(cd), 0);
	crypt_free(cd);

	params.data_alignment = 0;
	params.data_device = NULL;

	// test payload_offset = 0. format() should look up alignment offset from device topology
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(!(crypt_get_data_offset(cd) > 0));
	crypt_free(cd);

	/*
	 * test limit values for backing device size
	 */
	params.data_alignment = 8192;
	OK_(get_luks2_offsets(0, params.data_alignment, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_0S, r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));
	OK_(create_dmdevice_over_loop(L_DEVICE_WRONG, r_payload_offset - 1));

	// 1 sector less than required
	OK_(crypt_init(&cd, DMDIR L_DEVICE_WRONG));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params),	"Device too small");
	crypt_free(cd);

	// 0 sectors for encrypted area
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Encrypted area too small");
	crypt_free(cd);

	// 1 sector for encrypted area
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_get_data_offset(cd), params.data_alignment);
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(t_device_size(DMDIR CDEVICE_1, &r_size_1));
	EQ_(r_size_1, SECTOR_SIZE);
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
	crypt_free(cd);

	params.data_alignment = 0;
	params.data_device = DEVICE_2;

	// generate keyslot material at the end of luks header
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, passphrase, strlen(passphrase)), 7);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 7, passphrase, strlen(passphrase) ,0), 7);
	crypt_free(cd);
	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, DMDIR H_DEVICE));
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params), "Context is already formatted");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	crypt_free(cd);
	// check active status without header
	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, NULL));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	NULL_(crypt_get_type(cd));
	OK_(strcmp(cipher, crypt_get_cipher(cd)));
	OK_(strcmp(cipher_mode, crypt_get_cipher_mode(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	params.data_alignment = 2048;
	params.data_device = NULL;

	// test uuid mismatch and _init_by_name_and_header
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	crypt_free(cd);
	params.data_alignment = 0;
	params.data_device = DEVICE_2;
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	crypt_free(cd);
	// there we've got uuid mismatch
	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, DMDIR H_DEVICE));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	NULL_(crypt_get_type(cd));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Device is active");
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, key, key_size, 0), "Device is active");
	EQ_(crypt_status(cd, CDEVICE_2), CRYPT_INACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	params.data_device = NULL;

	OK_(crypt_init(&cd, DEVICE_2));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));

	// even with no keyslots defined it can be activated by volume key
	OK_(crypt_volume_key_verify(cd, key, key_size));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_2, key, key_size, 0));
	EQ_(crypt_status(cd, CDEVICE_2), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_2));

	// now with keyslot
	EQ_(7, crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, passphrase, strlen(passphrase)));
	EQ_(CRYPT_SLOT_ACTIVE_LAST, crypt_keyslot_status(cd, 7));
	EQ_(7, crypt_activate_by_passphrase(cd, CDEVICE_2, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0));
	EQ_(crypt_status(cd, CDEVICE_2), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_2));

	crypt_set_iteration_time(cd, 1);
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
	EQ_(6, crypt_keyslot_add_by_volume_key(cd, 6, key, key_size, passphrase, strlen(passphrase)));
	EQ_(CRYPT_SLOT_ACTIVE, crypt_keyslot_status(cd, 6));

	FAIL_(crypt_keyslot_destroy(cd, 8), "invalid keyslot");
	FAIL_(crypt_keyslot_destroy(cd, CRYPT_ANY_SLOT), "invalid keyslot");
	FAIL_(crypt_keyslot_destroy(cd, 0), "keyslot not used");
	OK_(crypt_keyslot_destroy(cd, 7));
	EQ_(CRYPT_SLOT_INACTIVE, crypt_keyslot_status(cd, 7));
	EQ_(CRYPT_SLOT_ACTIVE_LAST, crypt_keyslot_status(cd, 6));

	EQ_(7, crypt_keyslot_change_by_passphrase(cd, 6, 7, passphrase, strlen(passphrase), passphrase2, strlen(passphrase2)));
	EQ_(CRYPT_SLOT_ACTIVE_LAST, crypt_keyslot_status(cd, 7));
	EQ_(7, crypt_activate_by_passphrase(cd, NULL, 7, passphrase2, strlen(passphrase2), 0));
	EQ_(6, crypt_keyslot_change_by_passphrase(cd, CRYPT_ANY_SLOT, 6, passphrase2, strlen(passphrase2), passphrase, strlen(passphrase)));

	if (!_fips_mode) {
		EQ_(6, crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key2, &key_size, passphrase, strlen(passphrase)));
		OK_(crypt_volume_key_verify(cd, key2, key_size));

		OK_(memcmp(key, key2, key_size));
	}
	OK_(strcmp(cipher, crypt_get_cipher(cd)));
	OK_(strcmp(cipher_mode, crypt_get_cipher_mode(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(8192, crypt_get_data_offset(cd));
	OK_(strcmp(DEVICE_2, crypt_get_device_name(cd)));

	reset_log();
	OK_(crypt_dump(cd));
	OK_(!(global_lines != 0));
	reset_log();

	FAIL_(crypt_set_uuid(cd, "blah"), "wrong UUID format");
	OK_(crypt_set_uuid(cd, DEVICE_TEST_UUID));
	OK_(strcmp(DEVICE_TEST_UUID, crypt_get_uuid(cd)));

	FAIL_(crypt_deactivate(cd, CDEVICE_2), "not active");
	crypt_free(cd);
	_cleanup_dmdevices();

	/* LUKSv2 format tests */

	/* very basic test */
	OK_(crypt_init(&cd, DEVICE_2));
	crypt_set_iteration_time(cd, 1);
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 0, NULL), "Wrong key size");
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	crypt_free(cd);
	/* some invalid parameters known to cause troubles */
	OK_(crypt_init(&cd, DEVICE_2));
	crypt_set_iteration_time(cd, 0); /* wrong for argon2 but we don't know the pbkdf type yet, ignored */
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	crypt_free(cd);
	OK_(crypt_init(&cd, DEVICE_2));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, key_size, PASSPHRASE, strlen(PASSPHRASE)), 0);
	crypt_free(cd);

	OK_(crypt_init(&cd, DEVICE_2));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, key_size, NULL));
	FAIL_(crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, key, key_size, PASSPHRASE, strlen(PASSPHRASE)), "VK doesn't match any digest");
	FAIL_(crypt_keyslot_add_by_volume_key(cd, 1, key, key_size, PASSPHRASE, strlen(PASSPHRASE)), "VK doesn't match any digest");
	crypt_free(cd);

	OK_(create_dmdevice_over_loop(L_DEVICE_1S, 8193));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 3, NULL, key_size, PASSPHRASE, strlen(PASSPHRASE)), 3);
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key3, key_size, 0), "VK doesn't match any digest assigned to segment 0");
	crypt_free(cd);

	_cleanup_dmdevices();
}

static void UseTempVolumes(void)
{
	struct crypt_device *cd;
	char tmp[256];

	// Tepmporary device without keyslot but with on-disk LUKS header
	OK_(crypt_init(&cd, DEVICE_2));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "not yet formatted");
	OK_(crypt_format(cd, CRYPT_LUKS2, "aes", "cbc-essiv:sha256", NULL, NULL, 16, NULL));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0));
	EQ_(crypt_status(cd, CDEVICE_2), CRYPT_ACTIVE);
	crypt_free(cd);

	OK_(crypt_init_by_name(&cd, CDEVICE_2));
	OK_(crypt_deactivate(cd, CDEVICE_2));
	crypt_free(cd);

	// Dirty checks: device without UUID
	// we should be able to remove it but not manuipulate with it
	snprintf(tmp, sizeof(tmp), "dmsetup create %s --table \""
		"0 100 crypt aes-cbc-essiv:sha256 deadbabedeadbabedeadbabedeadbabe 0 "
		"%s 2048\"", CDEVICE_2, DEVICE_2);
	_system(tmp, 1);
	OK_(crypt_init_by_name(&cd, CDEVICE_2));
	OK_(crypt_deactivate(cd, CDEVICE_2));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "No known device type");
	crypt_free(cd);

	// Dirty checks: device with UUID but LUKS header key fingerprint must fail)
	snprintf(tmp, sizeof(tmp), "dmsetup create %s --table \""
		"0 100 crypt aes-cbc-essiv:sha256 deadbabedeadbabedeadbabedeadbabe 0 "
		"%s 2048\" -u CRYPT-LUKS2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ctest1",
		 CDEVICE_2, DEVICE_2);
	_system(tmp, 1);
	OK_(crypt_init_by_name(&cd, CDEVICE_2));
	OK_(crypt_deactivate(cd, CDEVICE_2));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "wrong volume key");
	crypt_free(cd);

	// No slots
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "volume key is lost");
	crypt_free(cd);
}

static void Luks2HeaderRestore(void)
{
	struct crypt_device *cd;
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
		.hash = "sha1",
		.skip = 0,
		.offset = 0,
		.size = 0
	};
	struct crypt_params_luks1 luks1 = {
		.data_alignment = 8192, // 4M offset to pass alignment test
	};
	char key[128];

	const char *mk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(mk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset;

	crypt_decode_key(key, mk_hex, key_size);

	OK_(get_luks2_offsets(0, params.data_alignment, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 5000));

	// do not restore header over plain device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &pl_params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	FAIL_(crypt_header_restore(cd, CRYPT_PLAIN, NO_REQS_LUKS2_HEADER), "Cannot restore header to PLAIN type device");
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, NO_REQS_LUKS2_HEADER), "Cannot restore header over PLAIN type device");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// FIXME: does following test make a sense in LUKS2?
	// volume key_size mismatch
	// OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	// memcpy(key2, key, key_size / 2);
	// OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key2, key_size / 2, &params));
	// FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, VALID_LUKS2_HEADER), "Volume keysize mismatch");
	// crypt_free(cd);

	// payload offset mismatch
	params.data_alignment = 8193;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, NO_REQS_LUKS2_HEADER), "Payload offset mismatch");
	crypt_free(cd);
	params.data_alignment = 4096;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	// FIXME: either format has to fail or next line must be true
	// EQ_(crypt_get_data_offset(cd), params.data_alignment);
	// FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, VALID_LUKS2_HEADER), "Payload offset mismatch");
	crypt_free(cd);

	// do not allow restore over LUKS1 header on device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, NULL, 32, &luks1));
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS2, NO_REQS_LUKS2_HEADER), "LUKS1 format detected");
	crypt_free(cd);

	_cleanup_dmdevices();
}

static void Luks2HeaderLoad(void)
{
	struct crypt_device *cd;
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
		.hash = "sha1",
		.skip = 0,
		.offset = 0,
		.size = 0
	};
	char key[128], cmd[256];

	const char *mk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(mk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset, r_header_size;

	crypt_decode_key(key, mk_hex, key_size);

	// prepare test env
	OK_(get_luks2_offsets(0, params.data_alignment, 0, 0, &r_header_size, &r_payload_offset));
	// external header device
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	// prepared header on a device too small to contain header and payload
	//OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, r_payload_offset - 1));
	OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, r_header_size - 1));
	snprintf(cmd, sizeof(cmd), "dd if=" IMAGE1 " of=" DMDIR H_DEVICE_WRONG " bs=%" PRIu32 " count=%" PRIu64 " 2>/dev/null", params.sector_size, r_header_size - 1);
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
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// bad header: device too small (payloadOffset > device_size)
	OK_(crypt_init(&cd, DMDIR H_DEVICE_WRONG));
	FAIL_(crypt_load(cd, CRYPT_LUKS2, NULL), "Device too small");
	NULL_(crypt_get_type(cd));
	crypt_free(cd);

	// 0 secs for encrypted data area
	params.data_alignment = 8192;
	params.data_device = NULL;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	crypt_free(cd);
	// load should be ok
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Device too small");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	crypt_free(cd);

	// damaged header
	OK_(_system("dd if=/dev/zero of=" DMDIR L_DEVICE_OK " bs=512 count=8 2>/dev/null", 1));
	OK_(_system("dd if=/dev/zero of=" DMDIR L_DEVICE_OK " bs=512 seek=32 count=8 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	FAIL_(crypt_load(cd, CRYPT_LUKS2, NULL), "Header not found");
	crypt_free(cd);

	// plain device
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	FAIL_(crypt_load(cd, CRYPT_PLAIN, NULL), "Can't load nonLUKS device type");
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, key, key_size, &pl_params));
	FAIL_(crypt_load(cd, CRYPT_LUKS2, NULL), "Can't load over nonLUKS device type");
	crypt_free(cd);

	//LUKSv2 device
	OK_(crypt_init(&cd, DEVICE_4));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	crypt_free(cd);
	OK_(crypt_init(&cd, DEVICE_4));
	crypt_set_iteration_time(cd, 0); /* invalid for argon2 pbkdf, ignored */
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	crypt_free(cd);

	/* check load sets proper device type */
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	EQ_(strcmp(CRYPT_LUKS2, crypt_get_type(cd)), 0);
	crypt_free(cd);

	_cleanup_dmdevices();
}

static void Luks2HeaderBackup(void)
{
	struct crypt_device *cd;
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

	const char *mk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(mk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset;

	const char *passphrase = PASSPHRASE;

	crypt_decode_key(key, mk_hex, key_size);

	OK_(get_luks2_offsets(0, params.data_alignment, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1));

	// create LUKS device and backup the header
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, passphrase, strlen(passphrase)), 7);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, key, key_size, passphrase, strlen(passphrase)), 0);
	OK_(crypt_header_backup(cd, CRYPT_LUKS2, BACKUP_FILE));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// restore header from backup
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_header_restore(cd, CRYPT_LUKS2, BACKUP_FILE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// exercise luksOpen using backup header in file
	OK_(crypt_init(&cd, BACKUP_FILE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, passphrase, strlen(passphrase), 0), 0);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	OK_(crypt_init(&cd, BACKUP_FILE));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 7, passphrase, strlen(passphrase), 0), 7);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// exercise luksOpen using backup header on block device
	fd = loop_attach(&DEVICE_3, BACKUP_FILE, 0, 0, &ro);
	close(fd);
	OK_(fd < 0);
	OK_(crypt_init(&cd, DEVICE_3));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, passphrase, strlen(passphrase), 0), 0);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	OK_(crypt_init(&cd, DEVICE_3));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 7, passphrase, strlen(passphrase), 0), 7);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	_cleanup_dmdevices();
}

static void ResizeDeviceLuks2(void)
{
	struct crypt_device *cd;
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

	const char *mk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(mk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset, r_header_size, r_size;

	crypt_decode_key(key, mk_hex, key_size);

	// prepare env
	OK_(get_luks2_offsets(0, params.data_alignment, 0, 0, NULL, &r_payload_offset));
	OK_(get_luks2_offsets(1, 0, 0, 0, &r_header_size, NULL));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1000));
	OK_(create_dmdevice_over_loop(L_DEVICE_0S, 1000));

	// test header and encrypted payload all in one device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	// disable loading VKs in kernel keyring (compatible mode)
	OK_(crypt_volume_key_keyring(cd, 0));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	OK_(crypt_resize(cd, CDEVICE_1, 42));
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(42, r_size >> SECTOR_SHIFT);
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	// autodetect encrypted device area size
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> SECTOR_SHIFT);
	FAIL_(crypt_resize(cd, CDEVICE_1, 1001), "Device too small");
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> SECTOR_SHIFT);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	params.data_alignment = 0;
	params.data_device = DMDIR L_DEVICE_0S;
	// test case for external header
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	OK_(crypt_resize(cd, CDEVICE_1, 666));
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(666, r_size >> SECTOR_SHIFT);
	// autodetect encrypted device size
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> SECTOR_SHIFT);
	FAIL_(crypt_resize(cd, CDEVICE_1, 1001), "Device too small");
	if (!t_device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> SECTOR_SHIFT);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

#ifdef KERNEL_KEYRING
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
		EQ_(43, r_size >> SECTOR_SHIFT);
	crypt_free(cd);

	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	// check userspace gets hint volume key must be properly loaded in kernel keyring
	if (t_dm_crypt_keyring_support())
		EQ_(crypt_resize(cd, CDEVICE_1, 0), -EPERM);
	else
		OK_(crypt_resize(cd, CDEVICE_1, 0));
	crypt_free(cd);

	// same as above for handles initialised by name
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	if (t_dm_crypt_keyring_support())
		EQ_(crypt_resize(cd, CDEVICE_1, 0), -EPERM);
	else
		OK_(crypt_resize(cd, CDEVICE_1, 0));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);
#endif

	_cleanup_dmdevices();
}

static void TokenActivationByKeyring(void)
{
#ifdef KERNEL_KEYRING
	key_serial_t kid, kid1;
	struct crypt_device *cd;

	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

	const struct crypt_token_params_luks2_keyring params = {
		.key_description = KEY_DESC_TEST0
	}, params2 = {
		.key_description = KEY_DESC_TEST1
	};

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	if (kid < 0) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	// prepare the device
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_token_luks2_keyring_set(cd, 3, &params), 3);
	EQ_(crypt_token_assign_keyslot(cd, 3, 0), 3);
	crypt_free(cd);

	// test thread keyring key in token 0
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 3, NULL, 0), 0);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 3, NULL, 0), "already open");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	if (keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING)) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_PROCESS_KEYRING);
	if (kid < 0) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	// add token 1 with process keyring key
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_token_json_set(cd, 3, NULL), 3);
	EQ_(crypt_token_luks2_keyring_set(cd, 1, &params), 1);
	EQ_(crypt_token_assign_keyslot(cd, 1, 0), 1);
	crypt_free(cd);

	// test process keyring key in token 1
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 1, NULL, 0), 0);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 1, NULL, 0), "already open");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	if (keyctl_unlink(kid, KEY_SPEC_PROCESS_KEYRING)) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	// create two tokens and let the cryptsetup unlock the volume with the valid one
	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	if (kid < 0) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	kid1 = add_key("user", KEY_DESC_TEST1, PASSPHRASE1, strlen(PASSPHRASE1), KEY_SPEC_THREAD_KEYRING);
	if (kid1 < 0) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_token_luks2_keyring_set(cd, 0, &params), 0);
	EQ_(crypt_token_assign_keyslot(cd, 0, 0), 0);
	EQ_(crypt_token_luks2_keyring_set(cd, 1, &params2), 1);
	FAIL_(crypt_token_assign_keyslot(cd, 1, 1), "Keyslot 1 doesn't exist");
	crypt_set_iteration_time(cd, 1);
	EQ_(crypt_keyslot_add_by_passphrase(cd, 1, PASSPHRASE, strlen(PASSPHRASE), PASSPHRASE1, strlen(PASSPHRASE1)), 1);
	EQ_(crypt_token_assign_keyslot(cd, 1, 1), 1);
	crypt_free(cd);

	// activate by specific token
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 0, NULL, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 1, NULL, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	if (keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING)) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	// activate by any token with token 0 having absent pass from keyring
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, CRYPT_ANY_TOKEN, NULL, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	if (kid < 0) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	// replace pass for keyslot 0 making token 0 invalid
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_keyslot_destroy(cd, 0));
	crypt_set_iteration_time(cd, 1);
	EQ_(crypt_keyslot_add_by_passphrase(cd, 0, PASSPHRASE1, strlen(PASSPHRASE1), PASSPHRASE1, strlen(PASSPHRASE1)), 0);
	crypt_free(cd);

	// activate by any token with token 0 having wrong pass for keyslot 0
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, CRYPT_ANY_TOKEN, NULL, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	 // create new device, with two tokens:
	 // 1st token being invalid (missing key in keyring)
	 // 2nd token can activate keyslot 1 after failing to do so w/ keyslot 0 (wrong pass)
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 1);
	EQ_(crypt_token_luks2_keyring_set(cd, 0, &params), 0);
	EQ_(crypt_token_assign_keyslot(cd, 0, 0), 0);
	EQ_(crypt_token_luks2_keyring_set(cd, 2, &params2), 2);
	EQ_(crypt_token_assign_keyslot(cd, 2, 1), 2);
	crypt_free(cd);

	if (keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING)) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	kid1 = add_key("user", KEY_DESC_TEST1, PASSPHRASE1, strlen(PASSPHRASE1), KEY_SPEC_THREAD_KEYRING);
	if (kid1 < 0) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, CRYPT_ANY_TOKEN, NULL, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);
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

	struct crypt_device *cd;

	const char *dummy;
	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

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
	};

	struct crypt_token_params_luks2_keyring params = {
		.key_description = "desc"
	};

	OK_(crypt_token_register(&th));
	FAIL_(crypt_token_register(&th2), "Token handler with the name already registered.");

	FAIL_(crypt_token_register(&th_reserved), "luks2- is reserved prefix");

	// basic token API tests
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
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
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 0, PASSPHRASE, 0), 0);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 0, PASSPHRASE, 0), "already active");
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// write invalid token and verify that validate() can detect it after handler being registered
	EQ_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN1_JSON_INVALID("\"1\"")), 1);
	EQ_(crypt_token_status(cd, 1, NULL), CRYPT_TOKEN_EXTERNAL_UNKNOWN);
	EQ_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN1_JSON("\"1\"")), 2);
	EQ_(crypt_token_status(cd, 2, &dummy), CRYPT_TOKEN_EXTERNAL_UNKNOWN);
	OK_(strcmp(dummy, "test_token1"));
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 1, PASSPHRASE1, 0), "Unknown token handler");
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE1, 0), "Unknown token handler");
	OK_(crypt_token_register(&th3));
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 1, PASSPHRASE1, 0), "Token validation failed");
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE1, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// test crypt_token_json_get returns correct token id
	EQ_(crypt_token_json_get(cd, 2, &dummy), 2);

	// exercise assign/unassign keyslots API
	EQ_(crypt_token_unassign_keyslot(cd, 2, 1), 2);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE1, 0), "Token assigned to no keyslot");
	EQ_(crypt_token_assign_keyslot(cd, 2, 0), 2);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE1, 0), "Wrong passphrase");
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_token_json_set(cd, 1, NULL), 1);
	FAIL_(crypt_token_json_get(cd, 1, &dummy), "Token is not there");
	EQ_(crypt_token_unassign_keyslot(cd, 2, CRYPT_ANY_SLOT), 2);
	EQ_(crypt_token_unassign_keyslot(cd, 0, CRYPT_ANY_SLOT), 0);

	// various tests related to unassigned keyslot to volume segment
	EQ_(crypt_keyslot_add_by_key(cd, 3, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 3);
	EQ_(crypt_token_assign_keyslot(cd, 2, 0), 2);
	EQ_(crypt_token_assign_keyslot(cd, 0, 3), 0);

	EQ_(crypt_activate_by_token(cd, NULL, 2, PASSPHRASE, 0), 0);
	EQ_(crypt_activate_by_token(cd, NULL, 0, PASSPHRASE1, 0), 3);
	// FIXME: useless error message here (or missing one to be specific)
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 0, PASSPHRASE1, 0), "No volume key available in token keyslots");
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_token_assign_keyslot(cd, 0, 1), 0);
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 0, PASSPHRASE1, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	EQ_(crypt_token_assign_keyslot(cd, 2, 3), 2);
	EQ_(crypt_activate_by_token(cd, NULL, 2, PASSPHRASE, 0), 0);
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	EQ_(crypt_token_luks2_keyring_set(cd, 5, &params), 5);
	EQ_(crypt_token_status(cd, 5, &dummy), CRYPT_TOKEN_INTERNAL);
	OK_(strcmp(dummy, "luks2-keyring"));

	FAIL_(crypt_token_luks2_keyring_get(cd, 2, &params), "Token is not luks2-keyring type");

	FAIL_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, BOGUS_TOKEN0_JSON), "luks2- reserved prefix.");
	FAIL_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, BOGUS_TOKEN1_JSON), "luks2- reserved prefix.");

	crypt_free(cd);
}

static void LuksConvert(void)
{
	struct crypt_device *cd;
	uint64_t offset, r_payload_offset;

	const struct crypt_pbkdf_type argon = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = "sha512",
		.time_ms = 1,
		.max_memory_kb = 1024,
		.parallel_threads = 1
	}, pbkdf2 = {
		.type = CRYPT_KDF_PBKDF2,
		.hash = "sha1",
		.time_ms = 1
	};

	struct crypt_params_luks2 luks2 = {
		.pbkdf = &pbkdf2,
		.sector_size = 512
	};

	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

	// prepare the device
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, NULL, 32, NULL));
	offset = crypt_get_data_offset(cd);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 7);
	crypt_free(cd);

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
	crypt_free(cd);

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
	crypt_free(cd);

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
	crypt_free(cd);

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
	crypt_free(cd);

	// exercice non-pbkdf2 LUKSv2 conversion
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	OK_(crypt_set_pbkdf_type(cd, &argon));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "Incompatible pbkdf with LUKSv1 format");
	crypt_free(cd);

	// exercice non LUKS1 compatible keyslot
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, &luks2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	// FIXME: following test fails as expected but for a different reason
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "Unassigned keyslots are incompatible with LUKSv1 format");
	crypt_free(cd);

	// exercice LUKSv2 conversion with single pbkdf2 keyslot being active
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	crypt_free(cd);
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	crypt_free(cd);

	// do not allow conversion on keyslot No > 7
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, &luks2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 8, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 8);
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "Can't convert keyslot No 8");
	crypt_free(cd);

	// should be enough for both luks1 and luks2 devices with all vk lengths
	OK_(get_luks2_offsets(1, 0, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));

	// do not allow conversion for legacy luks1 device (non-aligned keyslot offset)
	OK_(_system("dd if=" CONV_DIR "/" CONV_L1_256_LEGACY " of=" DMDIR L_DEVICE_1S " bs=1M count=2 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	FAIL_(crypt_convert(cd, CRYPT_LUKS2, NULL), "Can't convert device with unaligned keyslot offset");
	crypt_free(cd);

	/*
	 * do not allow conversion on images if there's not enough space between
	 * last keyslot and data offset (should not happen on headers created
	 * with cryptsetup)
	 */
	OK_(_system("dd if=" CONV_DIR "/" CONV_L1_256_UNMOVABLE " of=" DMDIR L_DEVICE_1S " bs=1M count=2 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	FAIL_(crypt_convert(cd, CRYPT_LUKS2, NULL), "Can't convert device with unaligned keyslot offset");
	crypt_free(cd);

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
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

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
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

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
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

	// detached LUKS1 header conversion
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_128_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS2), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_128_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

	// 256b key
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_256_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS2), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_256_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

	// 512b key
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_512_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS2), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L1_512_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

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
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

	// 128b all LUKS1 keyslots used
	OK_(_system("dd if=" CONV_DIR "/" CONV_L2_128_FULL " of=" DMDIR L_DEVICE_1S " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	crypt_free(cd);
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
	crypt_free(cd);

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
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

	// 256b all LUKS1 keyslots used
	OK_(_system("dd if=" CONV_DIR "/" CONV_L2_256_FULL " of=" DMDIR L_DEVICE_1S " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	crypt_free(cd);
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
	crypt_free(cd);

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
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

	// 512b all LUKS1 keyslots used
	OK_(_system("dd if=" CONV_DIR "/" CONV_L2_512_FULL " of=" DMDIR L_DEVICE_1S " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	crypt_free(cd);
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
	crypt_free(cd);

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
	crypt_free(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_128_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

	// 128b all LUKS1 keyslots used
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_128_DET_FULL));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	crypt_free(cd);
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
	crypt_free(cd);

	// 256b key
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_256_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_256_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

	// 256b all LUKS1 keyslots used
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_256_DET_FULL));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	crypt_free(cd);
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
	crypt_free(cd);

	// 512b key
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_512_DET));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	offset = crypt_get_data_offset(cd);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_512_DET));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_get_data_offset(cd), offset);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 0, PASS0, strlen(PASS0), 0), 0);
	EQ_(crypt_activate_by_passphrase(cd, NULL, 7, PASS7, strlen(PASS7), 0), 7);
	crypt_free(cd);

	// 512b all LUKS1 keyslots used
	OK_(crypt_init(&cd, CONV_DIR "/" CONV_L2_512_DET_FULL));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	EQ_(strcmp(crypt_get_type(cd), CRYPT_LUKS1), 0);
	crypt_free(cd);
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
	crypt_free(cd);

	_cleanup_dmdevices();
}

static void Pbkdf(void)
{
	struct crypt_device *cd;
	const struct crypt_pbkdf_type *pbkdf;

	const char *cipher = "aes", *mode="xts-plain64";
	struct crypt_pbkdf_type argon2 = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = DEFAULT_LUKS1_HASH,
		.time_ms = 6,
		.max_memory_kb = 1024,
		.parallel_threads = 1
	}, pbkdf2 = {
		.type = CRYPT_KDF_PBKDF2,
		.hash = DEFAULT_LUKS1_HASH,
		.time_ms = 9
	}, bad = {
		.type = "hamster_pbkdf",
		.hash = DEFAULT_LUKS1_HASH
	};
	struct crypt_params_plain params = {
		.hash = "sha1",
		.skip = 0,
		.offset = 0,
		.size = 0
	};
	struct crypt_params_luks1 luks1 = {
		.hash = "whirlpool", // test non-standard hash
		.data_alignment = 2048,
	};

	// test empty context
	OK_(crypt_init(&cd, DEVICE_1));
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
	crypt_free(cd);

	// test LUKSv1 device
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, mode, NULL, NULL, 32, NULL));
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Unsupported with non-LUKS2 devices");
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	OK_(crypt_set_pbkdf_type(cd, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, DEFAULT_LUKS1_ITER_TIME);
	crypt_free(cd);
	// test value set in crypt_set_iteration_time() can be obtained via following crypt_get_pbkdf_type()
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 42);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, mode, NULL, NULL, 32, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, 42);
	// test crypt_get_pbkdf_type() returns expected values for LUKSv1
	OK_(strcmp(pbkdf->type, CRYPT_KDF_PBKDF2));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->max_memory_kb, 0);
	EQ_(pbkdf->parallel_threads, 0);
	crypt_set_iteration_time(cd, 43);
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, 43);
	crypt_free(cd);
	// test whether crypt_get_pbkdf_type() after double crypt_load()
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	crypt_set_iteration_time(cd, 42);
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, 42);
	crypt_free(cd);
	// test whether hash passed via *params in crypt_load() has higher priority
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, mode, NULL, NULL, 32, &luks1));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->hash, luks1.hash));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->hash, luks1.hash));
	crypt_free(cd);

	// test LUKSv2 device
	// test default values are set
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, mode, NULL, NULL, 32, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, DEFAULT_LUKS2_PBKDF));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->time_ms, DEFAULT_LUKS2_ITER_TIME);
	EQ_(pbkdf->max_memory_kb, adjusted_pbkdf_memory());
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), DEFAULT_LUKS2_PARALLEL_THREADS));
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
	OK_(strcmp(pbkdf->type, DEFAULT_LUKS2_PBKDF));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->time_ms, DEFAULT_LUKS2_ITER_TIME);
	EQ_(pbkdf->max_memory_kb, adjusted_pbkdf_memory());
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), DEFAULT_LUKS2_PARALLEL_THREADS));
	// try to pass illegal values
	argon2.parallel_threads = 0;
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Parallel threads can't be 0");
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
	bad.hash = DEFAULT_LUKS1_HASH;
	FAIL_(crypt_set_pbkdf_type(cd, &bad), "Pbkdf type member is empty");
	// following test fails atm
	// bad.hash = "hamster_hash";
	// FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Unknown hash member");
	crypt_free(cd);
	// test whether crypt_get_pbkdf_type() behaves accordingly after second crypt_load() call
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, DEFAULT_LUKS2_PBKDF));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->time_ms, DEFAULT_LUKS2_ITER_TIME);
	EQ_(pbkdf->max_memory_kb, adjusted_pbkdf_memory());
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), DEFAULT_LUKS2_PARALLEL_THREADS));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	OK_(strcmp(pbkdf->type, DEFAULT_LUKS2_PBKDF));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->time_ms, 1);
	EQ_(pbkdf->max_memory_kb, adjusted_pbkdf_memory());
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), DEFAULT_LUKS2_PARALLEL_THREADS));
	crypt_free(cd);

	// test crypt_set_pbkdf_type() overwrites invalid value set by crypt_set_iteration_time()
	OK_(crypt_init(&cd, DEVICE_1));
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

	crypt_free(cd);
}

static void Luks2KeyslotAdd(void)
{
	char key[128], key2[128];
	struct crypt_device *cd;
	const char *cipher = "aes", *cipher_mode="xts-plain64";
	const char *mk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	const char *mk_hex2 = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1e";
	size_t key_size = strlen(mk_hex) / 2;

	crypt_decode_key(key, mk_hex, key_size);
	crypt_decode_key(key2, mk_hex2, key_size);

	/* test crypt_keyslot_add_by_key */
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, key_size, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 1, key2, key_size, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	EQ_(crypt_keyslot_status(cd, 0), CRYPT_SLOT_ACTIVE_LAST);
	EQ_(crypt_keyslot_status(cd, 1), CRYPT_SLOT_ACTIVE);
	/* must not activate volume with keyslot unassigned to a segment */
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key2, key_size, 0), "Key doesn't match volume key digest");
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, 1, PASSPHRASE1, strlen(PASSPHRASE1), 0), "Keyslot not assigned to volume");
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE1, strlen(PASSPHRASE1), 0), "No keyslot assigned to volume with this passphrase");
	/* unusable for volume activation even in test mode */
	FAIL_(crypt_activate_by_volume_key(cd, NULL, key2, key_size, 0), "Key doesn't match volume key digest");
	/* otoh passphrase check should pass */
	EQ_(crypt_activate_by_passphrase(cd, NULL, 1, PASSPHRASE1, strlen(PASSPHRASE1), 0), 1);
	EQ_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, PASSPHRASE1, strlen(PASSPHRASE1), 0), 1);
	/* in general crypt_keyslot_add_by_key must allow any reasonable key size
	 * even though such keyslot will not be usable for segment encryption */
	EQ_(crypt_keyslot_add_by_key(cd, 2, key2, key_size-1, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 2);
	EQ_(crypt_keyslot_add_by_key(cd, 3, key2, 13, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 3);

	crypt_free(cd);
}

static void Luks2ActivateByKeyring(void)
{
#ifdef KERNEL_KEYRING

	key_serial_t kid, kid1;
	struct crypt_device *cd;

	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	kid1 = add_key("user", KEY_DESC_TEST1, PASSPHRASE1, strlen(PASSPHRASE1), KEY_SPEC_THREAD_KEYRING);
	if (kid < 0 || kid1 < 0) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	// prepare the device
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_key(cd, 1, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1), CRYPT_VOLUME_KEY_NO_SEGMENT), 1);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 2, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 2);
	crypt_free(cd);

	// FIXME: all following tests work as expected but most error messages are missing
	// check activate by keyring works exactly same as by passphrase
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, 0, 0), 0);
	EQ_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST0, 0, 0), 0);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	FAIL_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST0, 0, 0), "already open");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	EQ_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST1, 1, 0), 1);
	EQ_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST1, 2, 0), 2);
	FAIL_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST1, 1, 0), "Keyslot not assigned to volume");
	EQ_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST1, 2, 0), 2);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST1, CRYPT_ANY_SLOT, 0), 2);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, 2, 0), "Failed to unclock keyslot");
	FAIL_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST1, 0, 0), "Failed to unclock keyslot");
	crypt_free(cd);

	if (keyctl_unlink(kid, KEY_SPEC_THREAD_KEYRING)) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	if (keyctl_unlink(kid1, KEY_SPEC_THREAD_KEYRING)) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	FAIL_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, CRYPT_ANY_SLOT, 0), "no such key in keyring");
	FAIL_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST0, CRYPT_ANY_SLOT, 0), "no such key in keyring");
	FAIL_(crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST1, 2, 0), "no such key in keyring");
	FAIL_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST1, 1, 0), "no such key in keyring");
	crypt_free(cd);
#else
	printf("WARNING: cryptsetup compiled with kernel keyring service disabled, skipping test.\n");
#endif
}

static void Luks2Requirements(void)
{
	int r;
	struct crypt_device *cd;
	char key[128];
	size_t key_size = 128;
	const struct crypt_pbkdf_type *pbkdf;
#ifdef KERNEL_KEYRING
	key_serial_t kid;
#endif
	uint32_t flags;
	uint64_t dummy, r_payload_offset;
	struct crypt_active_device cad;

	const char *token, *json = "{\"type\":\"test_token\",\"keyslots\":[]}";
	struct crypt_pbkdf_type argon2 = {
		.type = CRYPT_KDF_ARGON2I,
		.hash = DEFAULT_LUKS1_HASH,
		.time_ms = 6,
		.max_memory_kb = 1024,
		.parallel_threads = 1
	}, pbkdf2 = {
		.type = CRYPT_KDF_PBKDF2,
		.hash = DEFAULT_LUKS1_HASH,
		.time_ms = 9
	};
	struct crypt_token_params_luks2_keyring params_get, params = {
		.key_description = KEY_DESC_TEST0
	};

	OK_(prepare_keyfile(KEYFILE1, "aaa", 3));
	OK_(prepare_keyfile(KEYFILE2, "xxx", 3));

	/* crypt_load (unrestricted) */
	OK_(crypt_init(&cd, DEVICE_5));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	crypt_free(cd);

	OK_(crypt_init(&cd, DEVICE_5));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));

	/* crypt_dump (unrestricted) */
	reset_log();
	OK_(crypt_dump(cd));
	OK_(!(global_lines != 0));
	reset_log();

	/* get & set pbkdf params (unrestricted) */
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	NOTNULL_(crypt_get_pbkdf_type(cd));
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

	/* crypt_repair (not implemented for luks2) */
	FAIL_(crypt_repair(cd, CRYPT_LUKS2, NULL), "Not implemented");

	/* crypt_keyslot_add_passphrase (restricted) */
	FAIL_((r = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, "aaa", 3, "bbb", 3)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_change_by_passphrase (restricted) */
	FAIL_((r = crypt_keyslot_change_by_passphrase(cd, CRYPT_ANY_SLOT, 9, "aaa", 3, "bbb", 3)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_add_by_keyfile (restricted) */
	FAIL_((r = crypt_keyslot_add_by_keyfile(cd, CRYPT_ANY_SLOT, KEYFILE1, 0, KEYFILE2, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_add_by_keyfile_offset (restricted) */
	FAIL_((r = crypt_keyslot_add_by_keyfile_offset(cd, CRYPT_ANY_SLOT, KEYFILE1, 0, 0, KEYFILE2, 0, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_volume_key_get (unrestricted, but see below) */
	/* FIXME: eventual fips requirement should stop this */
	if (!_fips_mode)
		OK_(crypt_volume_key_get(cd, 0, key, &key_size, "aaa", 3));

	/* crypt_keyslot_add_by_volume_key (restricted) */
	FAIL_((r = crypt_keyslot_add_by_volume_key(cd, CRYPT_ANY_SLOT, key, key_size, "xxx", 3)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_add_by_key (restricted) */
	FAIL_((r = crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, NULL, key_size, "xxx", 3, CRYPT_VOLUME_KEY_NO_SEGMENT)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_keyslot_add_by_key (restricted) */
	FAIL_((r = crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, key, key_size, "xxx", 3, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_persistent_flasgs_set (restricted) */
	FAIL_((r = crypt_persistent_flags_set(cd, CRYPT_FLAGS_ACTIVATION, CRYPT_ACTIVATE_ALLOW_DISCARDS)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_persistent_flasgs_get (unrestricted) */
	OK_(crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &flags));
	EQ_(flags, (uint32_t) CRYPT_REQUIREMENT_UNKNOWN);

	/* crypt_activate_by_passphrase (restricted for activation only) */
	FAIL_((r = crypt_activate_by_passphrase(cd, CDEVICE_1, 0, "aaa", 3, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	OK_(crypt_activate_by_passphrase(cd, NULL, 0, "aaa", 3, 0));
	OK_(crypt_activate_by_passphrase(cd, NULL, 0, "aaa", 3, t_dm_crypt_keyring_support() ? CRYPT_ACTIVATE_KEYRING_KEY : 0));
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

#ifdef KERNEL_KEYRING
	kid = add_key("user", KEY_DESC_TEST0, "aaa", 3, KEY_SPEC_THREAD_KEYRING);
	if (kid < 0) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	/* crypt_activate_by_keyring (restricted for activation only) */
	FAIL_((r = crypt_activate_by_keyring(cd, CDEVICE_1, KEY_DESC_TEST0, 0, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	OK_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, 0, 0));
	OK_(crypt_activate_by_keyring(cd, NULL, KEY_DESC_TEST0, 0, t_dm_crypt_keyring_support() ? CRYPT_ACTIVATE_KEYRING_KEY : 0));
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
#ifdef KERNEL_KEYRING
	FAIL_((r = crypt_activate_by_token(cd, CDEVICE_1, 1, NULL, 0)), ""); // supposed to be silent
	EQ_(r, -ETXTBSY);
	OK_(crypt_activate_by_token(cd, NULL, 1, NULL, 0));
	OK_(crypt_activate_by_token(cd, NULL, 1, NULL, t_dm_crypt_keyring_support() ? CRYPT_ACTIVATE_KEYRING_KEY : 0));
#endif
	OK_(get_luks2_offsets(1, 8192, 0, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 2));
	//OK_(_system("dd if=" NO_REQS_LUKS2_HEADER " of=" NO_REQS_LUKS2_HEADER " bs=4096 2>/dev/null", 1));
	OK_(_system("dd if=" NO_REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));

	/* need to fake activated LUKSv2 device with requirements features */
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, "aaa", 3, 0));
	OK_(crypt_header_backup(cd, CRYPT_LUKS2, BACKUP_FILE));
	/* replace header with no requirements */
	OK_(_system("dd if=" REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	crypt_free(cd);

	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, DEVICE_5));
	crypt_free(cd);
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
	crypt_free(cd);

	/* replace header again to suspend the device */
	OK_(_system("dd if=" NO_REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	OK_(crypt_suspend(cd, CDEVICE_1));

	/* crypt_header_restore (restricted, do not drop the test until we have safe option) */
	/* refuse to overwrite header w/ backup including requirements */
	FAIL_((r = crypt_header_restore(cd, CRYPT_LUKS2, BACKUP_FILE)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	crypt_free(cd);

	OK_(_system("dd if=" REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init_by_name(&cd, CDEVICE_1));

	/* crypt_resume_by_passphrase (restricted) */
	FAIL_((r = crypt_resume_by_passphrase(cd, CDEVICE_1, 0, "aaa", 3)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_resume_by_keyfile (restricted) */
	FAIL_((r = crypt_resume_by_keyfile(cd, CDEVICE_1, 0, KEYFILE1, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);

	/* crypt_resume_by_keyfile_offset (restricted) */
	FAIL_((r = crypt_resume_by_keyfile_offset(cd, CDEVICE_1, 0, KEYFILE1, 0, 0)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	crypt_free(cd);

	OK_(_system("dd if=" NO_REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	OK_(crypt_resume_by_passphrase(cd, CDEVICE_1, 0, "aaa", 3));
	crypt_free(cd);
	OK_(_system("dd if=" REQS_LUKS2_HEADER " of=" DMDIR L_DEVICE_OK " bs=1M count=4 oflag=direct 2>/dev/null", 1));

	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	/* load VK in keyring */
	OK_(crypt_activate_by_passphrase(cd, NULL, 0, "aaa", 3, t_dm_crypt_keyring_support() ? CRYPT_ACTIVATE_KEYRING_KEY : 0));
	/* crypt_resize (restricted) */
	FAIL_((r = crypt_resize(cd, CDEVICE_1, 1)), "Unmet requirements detected");
	EQ_(r, -ETXTBSY);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);

	/* crypt_get_active_device (unrestricted) */
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
#ifdef KERNEL_KEYRING
	if (t_dm_crypt_keyring_support())
		EQ_(cad.flags & CRYPT_ACTIVATE_KEYRING_KEY, CRYPT_ACTIVATE_KEYRING_KEY);
#endif

	/* crypt_deactivate (unrestricted) */
	OK_(crypt_deactivate(cd, CDEVICE_1));

	/* crypt_keyslot_destroy (unrestricted) */
	OK_(crypt_keyslot_destroy(cd, 0));

	crypt_free(cd);

	_cleanup_dmdevices();
}

static void Luks2Integrity(void)
{
	struct crypt_device *cd;
	struct crypt_params_integrity ip = {};
	struct crypt_params_luks2 params = {
		.sector_size = 512,
		.integrity = "hmac(sha256)"
	};
	size_t key_size = 32 + 32;
	const char *passphrase = "blabla";
	const char *cipher = "aes";
	const char *cipher_mode = "xts-random";
	int ret;

	// FIXME: This is just a stub
	OK_(crypt_init(&cd, DEVICE_2));
	ret = crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, key_size, &params);
	if (ret < 0) {
		printf("WARNING: cannot format integrity device, skipping test.\n");
		crypt_free(cd);
		return;
	}

	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, NULL, key_size, passphrase, strlen(passphrase)), 7);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_2, 7, passphrase, strlen(passphrase) ,0), 7);
	EQ_(crypt_status(cd, CDEVICE_2), CRYPT_ACTIVE);
	crypt_free(cd);

	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_2, NULL));
	OK_(crypt_get_integrity_info(cd, &ip));
	OK_(strcmp(cipher, crypt_get_cipher(cd)));
	OK_(strcmp(cipher_mode, crypt_get_cipher_mode(cd)));
	OK_(strcmp("hmac(sha256)", ip.integrity));
	EQ_(32, ip.integrity_key_size);
	EQ_(32+16, ip.tag_size);
	OK_(crypt_deactivate(cd, CDEVICE_2));
	crypt_free(cd);
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
	if (_setup())
		goto out;

	crypt_set_debug_level(_debug ? CRYPT_DEBUG_ALL : CRYPT_DEBUG_NONE);

	RUN_(AddDeviceLuks2, "Format and use LUKS2 device");
	RUN_(Luks2HeaderLoad, "test header load");
	RUN_(Luks2HeaderRestore, "test LUKS2 header restore");
	RUN_(Luks2HeaderBackup, "test LUKS2 header backup");
	RUN_(ResizeDeviceLuks2, "Luks device resize tests");
	RUN_(UseLuks2Device, "Use pre-formated LUKS2 device");
	RUN_(SuspendDevice, "Suspend/Resume test");
	RUN_(UseTempVolumes, "Format and use temporary encrypted device");
	RUN_(Tokens, "General tokens API tests");
	RUN_(TokenActivationByKeyring, "Builtin kernel keyring token tests");
	RUN_(LuksConvert, "Test LUKS1 <-> LUKS2 conversions");
	RUN_(Pbkdf, "Exercice default pbkdf manipulation routines");
	RUN_(Luks2KeyslotAdd, "Add new keyslot by unused key");
	RUN_(Luks2ActivateByKeyring, "Test LUKS2 activation by passphrase in keyring");
	RUN_(Luks2Requirements, "Test LUKS2 requirements flags");
	RUN_(Luks2Integrity, "Test LUKS2 with data integrity");
out:
	_cleanup();
	return 0;
}
