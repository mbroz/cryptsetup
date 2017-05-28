/*
 * cryptsetup library API check functions
 *
 * Copyright (C) 2009-2013 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2014, Milan Broz
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <libdevmapper.h>
#ifdef KERNEL_KEYRING
#include <linux/keyctl.h>
#include <sys/syscall.h>
#ifndef HAVE_KEY_SERIAL_T
#define HAVE_KEY_SERIAL_T
#include <stdint.h>
typedef int32_t key_serial_t;
#endif
#endif


#include "luks.h"
#include "libcryptsetup.h"
#include "utils_loop.h"

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
#define EVL_HEADER_1 "evil_hdr-luks_hdr_damage"
#define EVL_HEADER_2 "evil_hdr-payload_overwrite"
#define EVL_HEADER_3 "evil_hdr-stripes_payload_dmg"
#define EVL_HEADER_4 "evil_hdr-small_luks_device"
#define VALID_HEADER "valid_header_file"
#define VALID_LUKS2_HEADER "luks2_header_file"
#define BACKUP_FILE "csetup_backup_file"
#define IMAGE1 "compatimage.img"
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

#define SECTOR_SHIFT 9L
#define SECTOR_SIZE 512
#define TST_LOOP_FILE_SIZE (((1<<20)*50)>>SECTOR_SHIFT)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_UP_MODULO(n,d) (DIV_ROUND_UP(n,d)*(d))
#define LUKS_PHDR_SIZE_B 1024

#define KEY_DESC_TEST0 "cs_token_test:test_key0"
#define KEY_DESC_TEST1 "cs_token_test:test_key1"

static int _debug   = 0;
static int _verbose = 1;
static int _fips_mode = 0;

static int _quit = 0;

static char global_log[4096];
static char last_error[256];
static int global_lines = 0;

static char *DEVICE_1 = NULL;
static char *DEVICE_2 = NULL;
static char *DEVICE_3 = NULL;
static char *DEVICE_4 = NULL;
static char *THE_LOOP_DEV = NULL;

static char *tmp_file_1 = NULL;
static char *test_loop_file = NULL;
static uint64_t t_dev_offset = 0;

static int _system(const char*, int);

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

static unsigned _min(unsigned a, unsigned b)
{
	return a < b ? a : b;
}

static int device_size(const char *device, uint64_t *size)
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

static int fips_mode(void)
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

static int get_luks_offsets(int metadata_device,
			    size_t keylength,
			    unsigned int alignpayload_sec,
			    unsigned int alignoffset_sec,
			    uint64_t *r_header_size,
			    uint64_t *r_payload_offset)
{
	int i;
	uint64_t current_sector;
	uint32_t sectors_per_stripes_set;

	if (!keylength)
		return -1;

	sectors_per_stripes_set = DIV_ROUND_UP(keylength*LUKS_STRIPES, SECTOR_SIZE);
	printf("sectors_per_stripes %" PRIu32 "\n", sectors_per_stripes_set);
	current_sector = DIV_ROUND_UP_MODULO(DIV_ROUND_UP(LUKS_PHDR_SIZE_B, SECTOR_SIZE),
			LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
	for(i=0;i < (LUKS_NUMKEYS - 1);i++)
		current_sector = DIV_ROUND_UP_MODULO(current_sector + sectors_per_stripes_set,
				LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
	if (r_header_size)
		*r_header_size = current_sector + sectors_per_stripes_set;

	current_sector = DIV_ROUND_UP_MODULO(current_sector + sectors_per_stripes_set,
				LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);

	if (r_payload_offset) {
		if (metadata_device)
			*r_payload_offset = alignpayload_sec;
		else
			*r_payload_offset = DIV_ROUND_UP_MODULO(current_sector, alignpayload_sec)
				+ alignoffset_sec;
	}

	return 0;
}

/*
 * Creates dm-linear target over the test loop device. Offset is held in
 * global variables so that size can be tested whether it fits into remaining
 * size of the loop device or not
 */
static int create_dmdevice_over_loop(const char *dm_name, const uint64_t size)
{
	char cmd[128];
	int r;
	uint64_t r_size;

	if(device_size(THE_LOOP_DEV, &r_size) < 0 || r_size <= t_dev_offset || !size) 
		return -1;
	if ((r_size - t_dev_offset) < size) {
		printf("No enough space on backing loop device\n.");
		return -2;
	}
	snprintf(cmd, sizeof(cmd),
		 "dmsetup create %s --table \"0 %" PRIu64 " linear %s %" PRIu64 "\"",
		 dm_name, size, THE_LOOP_DEV, t_dev_offset);
	if  (!(r = _system(cmd, 1))) {
		t_dev_offset += size;
	}
	return r;
}

// TODO some utility to remove dmdevice over the loop file

// Get key from kernel dm mapping table using dm-ioctl
static int _get_key_dm(const char *name, char *buffer, unsigned int buffer_size)
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

static int _prepare_keyfile(const char *name, const char *passphrase, int size)
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

static void _remove_keyfiles(void)
{
	remove(KEYFILE1);
	remove(KEYFILE2);
}

// Decode key from its hex representation
static int crypt_decode_key(char *key, const char *hex, unsigned int size)
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

static void global_log_callback(int level, const char *msg, void *usrptr)
{
	int len;

	if (_debug)
		printf("LOG: %s", msg);
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

static void reset_log(void)
{
	memset(global_log, 0, sizeof(global_log));
	memset(last_error, 0, sizeof(last_error));
	global_lines = 0;
}

static int _system(const char *command, int warn)
{
	int r;
	if (_debug)
		printf("Running system: %s\n", command);
	if ((r=system(command)) < 0 && warn)
		printf("System command failed: %s", command);
	return r;
}

static void _cleanup_dmdevices(void)
{
	struct stat st;

	if (!stat(DMDIR H_DEVICE, &st)) {
		_system("dmsetup remove " H_DEVICE, 0);
	}
	if (!stat(DMDIR H_DEVICE_WRONG, &st)) {
		_system("dmsetup remove " H_DEVICE_WRONG, 0);
	}
	if (!stat(DMDIR L_DEVICE_0S, &st)) {
		_system("dmsetup remove " L_DEVICE_0S, 0);
	}
	if (!stat(DMDIR L_DEVICE_1S, &st)) {
		_system("dmsetup remove " L_DEVICE_1S, 0);
	}
	if (!stat(DMDIR L_DEVICE_WRONG, &st)) {
		_system("dmsetup remove " L_DEVICE_WRONG, 0);
	}
	if (!stat(DMDIR L_DEVICE_OK, &st)) {
		_system("dmsetup remove " L_DEVICE_OK, 0);
	}

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

	if (crypt_loop_device(THE_LOOP_DEV))
		crypt_loop_detach(THE_LOOP_DEV);

	if (crypt_loop_device(DEVICE_1))
		crypt_loop_detach(DEVICE_1);

	if (crypt_loop_device(DEVICE_2))
		crypt_loop_detach(DEVICE_2);

	if (crypt_loop_device(DEVICE_3))
		crypt_loop_detach(DEVICE_3);

	if (crypt_loop_device(DEVICE_4))
		crypt_loop_detach(DEVICE_4);

	_system("rm -f " IMAGE_EMPTY, 0);
	_system("rm -f " IMAGE1, 0);

	remove(test_loop_file);
	remove(tmp_file_1);

	remove(EVL_HEADER_1);
	remove(EVL_HEADER_2);
	remove(EVL_HEADER_3);
	remove(EVL_HEADER_4);
	remove(VALID_HEADER);
	remove(VALID_LUKS2_HEADER);
	remove(BACKUP_FILE);

	_remove_keyfiles();

	free(tmp_file_1);
	free(test_loop_file);
	free(THE_LOOP_DEV);
	free(DEVICE_1);
	free(DEVICE_2);
	free(DEVICE_3);
	free(DEVICE_4);
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

	fd = crypt_loop_attach(&THE_LOOP_DEV, test_loop_file, 0, 0, &ro);
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

	_system(" [ ! -e " IMAGE1 " ] && bzip2 -dk " IMAGE1 ".bz2", 1);
	fd = crypt_loop_attach(&DEVICE_1, IMAGE1, 0, 0, &ro);
	close(fd);

	_system("dd if=/dev/zero of=" IMAGE_EMPTY " bs=1M count=4 2>/dev/null", 1);
	fd = crypt_loop_attach(&DEVICE_2, IMAGE_EMPTY, 0, 0, &ro);
	close(fd);

	_system(" [ ! -e " VALID_LUKS2_HEADER " ] && xz -dk " VALID_LUKS2_HEADER ".xz", 1);
	fd = crypt_loop_attach(&DEVICE_4, VALID_LUKS2_HEADER, 0, 0, &ro);
	close(fd);

	/* Keymaterial offset is less than 8 sectors */
	_system(" [ ! -e " EVL_HEADER_1 " ] && bzip2 -dk " EVL_HEADER_1 ".bz2", 1);
	/* keymaterial offset aims into payload area */
	_system(" [ ! -e " EVL_HEADER_2 " ] && bzip2 -dk " EVL_HEADER_2 ".bz2", 1);
	/* keymaterial offset is valid, number of stripes causes payload area to be overwriten */
	_system(" [ ! -e " EVL_HEADER_3 " ] && bzip2 -dk " EVL_HEADER_3 ".bz2", 1);
	/* luks device header for data and header on same device. payloadOffset is greater than
	 * device size (crypt_load() test) */
	_system(" [ ! -e " EVL_HEADER_4 " ] && bzip2 -dk " EVL_HEADER_4 ".bz2", 1);
	/* valid header: payloadOffset=4096, key_size=32,
	 * volume_key = bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a */
	_system(" [ ! -e " VALID_HEADER " ] && bzip2 -dk " VALID_HEADER ".bz2", 1);

	/* Prepare tcrypt images */
	_system(" [ ! -d tcrypt-images ] && tar xjf tcrypt-images.tar.bz2 2>/dev/null", 1);

	_system("modprobe dm-crypt", 0);
	_system("modprobe dm-verity", 0);

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

static void check_ok(int status, int line, const char *func)
{
	if (status) {
		printf("FAIL line %d [%s]: code %d, %s\n", line, func, status, last_error);
		_cleanup();
		exit(-1);
	}
}

static void check_ko(int status, int line, const char *func)
{
	if (status >= 0) {
		printf("FAIL line %d [%s]: code %d, %s\n", line, func, status, last_error);
		_cleanup();
		exit(-1);
	} else if (_verbose)
		printf("   => errno %d, errmsg: %s\n", status, last_error);
}

static void check_equal(int line, const char *func, int64_t x, int64_t y)
{
	printf("FAIL line %d [%s]: expected equal values differs: %"
		PRIi64 " != %" PRIi64 "\n", line, func, x, y);
	_cleanup();
	exit(-1);
}

static void check_null(int line, const char *func, const void *x)
{
	if (x) {
		printf("FAIL line %d [%s]: expected NULL value: %p\n", line, func, x);
		_cleanup();
		exit(-1);
	}
}

static void check_notnull(int line, const char *func, const void *x)
{
	if (!x) {
		printf("FAIL line %d [%s]: expected not NULL value: %p\n", line, func, x);
		_cleanup();
		exit(-1);
	}
}

static void xlog(const char *msg, const char *tst, const char *func, int line, const char *txt)
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

/* crypt_device context must be "cd" to parse error properly here */
#define OK_(x)		do { xlog("(success)", #x, __FUNCTION__, __LINE__, NULL); \
			     check_ok((x), __LINE__, __FUNCTION__); \
			} while(0)
#define FAIL_(x, y)	do { xlog("(fail)   ", #x, __FUNCTION__, __LINE__, y); \
			     check_ko((x), __LINE__, __FUNCTION__); \
			} while(0)
#define EQ_(x, y)	do { int64_t _x = (x), _y = (y); \
			     xlog("(equal)  ", #x " == " #y, __FUNCTION__, __LINE__, NULL); \
			     if (_x != _y) check_equal(__LINE__, __FUNCTION__, _x, _y); \
			} while(0)
#define NULL_(x)	do { xlog("(null)   ", #x, __FUNCTION__, __LINE__, NULL); \
			     check_null(__LINE__, __FUNCTION__, (x)); \
			} while(0)
#define NOTNULL_(x)	do { xlog("(notnull)", #x, __FUNCTION__, __LINE__, NULL); \
			     check_notnull(__LINE__, __FUNCTION__, (x)); \
			} while(0)
#define RUN_(x, y)	do { reset_log(); \
			     printf("%s: %s\n", #x, (y)); x(); \
			} while (0)

static void AddDevicePlain(void)
{
	struct crypt_device *cd;
	struct crypt_params_plain params = {
		.hash = "sha1",
		.skip = 0,
		.offset = 0,
		.size = 0
	};
	int fd;
	char key[128], key2[128], path[128];

	const char *passphrase = PASSPHRASE;
	// hashed hex version of PASSPHRASE
	const char *mk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(mk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";

	uint64_t size, r_size;

	crypt_decode_key(key, mk_hex, key_size);
	FAIL_(crypt_init(&cd, ""), "empty device string");
	FAIL_(crypt_init(&cd, DEVICE_WRONG), "nonexistent device name ");
	FAIL_(crypt_init(&cd, DEVICE_CHAR), "character device as backing device");
	OK_(crypt_init(&cd, tmp_file_1));
	crypt_free(cd);

	// test crypt_format, crypt_get_cipher, crypt_get_cipher_mode, crypt_get_volume_key_size
	OK_(crypt_init(&cd,DEVICE_1));
	params.skip = 3;
	params.offset = 42;
	FAIL_(crypt_format(cd,CRYPT_PLAIN,NULL,cipher_mode,NULL,NULL,key_size,&params),"cipher param is null");
	FAIL_(crypt_format(cd,CRYPT_PLAIN,cipher,NULL,NULL,NULL,key_size,&params),"cipher_mode param is null");
	OK_(crypt_format(cd,CRYPT_PLAIN,cipher,cipher_mode,NULL,NULL,key_size,&params));
	OK_(strcmp(cipher_mode,crypt_get_cipher_mode(cd)));
	OK_(strcmp(cipher,crypt_get_cipher(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(params.skip, crypt_get_iv_offset(cd));
	EQ_(params.offset, crypt_get_data_offset(cd));
	params.skip = 0;
	params.offset = 0;

	// crypt_set_uuid()
	FAIL_(crypt_set_uuid(cd,DEVICE_1_UUID),"can't set uuid to plain device");

	crypt_free(cd);

	// default is "plain" hash - no password hash
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, NULL));
	FAIL_(crypt_activate_by_volume_key(cd, NULL, key, key_size, 0), "cannot verify key with plain");
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// test boundaries in offset parameter
	device_size(DEVICE_1,&size);
	params.hash = NULL;
	// zero sectors length
	params.offset = size >> SECTOR_SHIFT;
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	EQ_(crypt_get_data_offset(cd),params.offset);
	// device size is 0 sectors
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0), "invalid device size (0 blocks)");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	// data part of crypt device is of 1 sector size
	params.offset = (size >> SECTOR_SHIFT) - 1;
	crypt_free(cd);

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	snprintf(path, sizeof(path), "%s/%s", crypt_get_dir(), CDEVICE_1);
	if (device_size(path, &r_size) >= 0)
		EQ_(r_size>>SECTOR_SHIFT, 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// size > device_size
	params.offset = 0;
	params.size = (size >> SECTOR_SHIFT) + 1;
	crypt_init(&cd, DEVICE_1);
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0),"Device too small");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	crypt_free(cd);

	// offset == device_size (autodetect size)
	params.offset = (size >> SECTOR_SHIFT);
	params.size = 0;
	crypt_init(&cd, DEVICE_1);
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0),"Device too small");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	crypt_free(cd);

	// offset == device_size (user defined size)
	params.offset = (size >> SECTOR_SHIFT);
	params.size = 123;
	crypt_init(&cd, DEVICE_1);
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0),"Device too small");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	crypt_free(cd);

	// offset+size > device_size
	params.offset = 42;
	params.size = (size >> SECTOR_SHIFT) - params.offset + 1;
	crypt_init(&cd, DEVICE_1);
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0),"Offset and size are beyond device real size");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	crypt_free(cd);

	// offset+size == device_size
	params.offset = 42;
	params.size = (size >> SECTOR_SHIFT) - params.offset;
	crypt_init(&cd, DEVICE_1);
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	if (!device_size(path, &r_size))
		EQ_((r_size >> SECTOR_SHIFT),params.size);
	OK_(crypt_deactivate(cd,CDEVICE_1));

	crypt_free(cd);
	params.hash = "sha1";
	params.offset = 0;
	params.size = 0;
	params.skip = 0;

	// Now use hashed password
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	FAIL_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0),
	      "cannot verify passphrase with plain" );
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0));

	// device status check
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	snprintf(path, sizeof(path), "%s/%s", crypt_get_dir(), CDEVICE_1);
	fd = open(path, O_RDONLY);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_BUSY);
	FAIL_(crypt_deactivate(cd, CDEVICE_1), "Device is busy");
	close(fd);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	crypt_free(cd);

	// crypt_init_by_name_and_header
	OK_(crypt_init(&cd,DEVICE_1));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	crypt_free(cd);

	FAIL_(crypt_init_by_name_and_header(&cd, CDEVICE_1, H_DEVICE),"can't init plain device by header device");
	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	OK_(strcmp(cipher_mode,crypt_get_cipher_mode(cd)));
	OK_(strcmp(cipher,crypt_get_cipher(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(params.skip, crypt_get_iv_offset(cd));
	EQ_(params.offset, crypt_get_data_offset(cd));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	OK_(crypt_init(&cd,DEVICE_1));
	OK_(crypt_format(cd,CRYPT_PLAIN,cipher,cipher_mode,NULL,NULL,key_size,&params));
	params.size = 0;
	params.offset = 0;

	// crypt_set_data_device
	FAIL_(crypt_set_data_device(cd,H_DEVICE),"can't set data device for plain device");

	// crypt_get_type
	OK_(strcmp(crypt_get_type(cd),CRYPT_PLAIN));

	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);

	// crypt_resize()
	OK_(crypt_resize(cd,CDEVICE_1,size>>SECTOR_SHIFT)); // same size
	if (!device_size(path,&r_size))
		EQ_(r_size, size);

	// size overlaps
	FAIL_(crypt_resize(cd, CDEVICE_1, (uint64_t)-1),"Backing device is too small");
	FAIL_(crypt_resize(cd, CDEVICE_1, (size>>SECTOR_SHIFT)+1),"crypt device overlaps backing device");

	// resize ok
	OK_(crypt_resize(cd,CDEVICE_1, 123));
	if (!device_size(path,&r_size))
		EQ_(r_size>>SECTOR_SHIFT, 123);
	OK_(crypt_resize(cd,CDEVICE_1,0)); // full size (autodetect)
	if (!device_size(path,&r_size))
		EQ_(r_size, size);
	OK_(crypt_deactivate(cd,CDEVICE_1));
	EQ_(crypt_status(cd,CDEVICE_1),CRYPT_INACTIVE);
	crypt_free(cd);

	// offset tests
	OK_(crypt_init(&cd,DEVICE_1));
	params.offset = 42;
	params.size = (size>>SECTOR_SHIFT) - params.offset - 10;
	OK_(crypt_format(cd,CRYPT_PLAIN,cipher,cipher_mode,NULL,NULL,key_size,&params));
	OK_(crypt_activate_by_volume_key(cd,CDEVICE_1,key,key_size,0));
	if (!device_size(path,&r_size))
		EQ_(r_size>>SECTOR_SHIFT, params.size);
	// resize to fill remaining capacity
	OK_(crypt_resize(cd,CDEVICE_1,params.size + 10));
	if (!device_size(path,&r_size))
		EQ_(r_size>>SECTOR_SHIFT, params.size + 10);

	// 1 sector beyond real size
	FAIL_(crypt_resize(cd,CDEVICE_1,params.size + 11), "new device size overlaps backing device"); // with respect to offset
	if (!device_size(path,&r_size))
		EQ_(r_size>>SECTOR_SHIFT, params.size + 10);
	EQ_(crypt_status(cd,CDEVICE_1),CRYPT_ACTIVE);
	fd = open(path, O_RDONLY);
	close(fd);
	OK_(fd < 0);

	// resize to minimal size
	OK_(crypt_resize(cd,CDEVICE_1, 1)); // minimal device size
	if (!device_size(path,&r_size))
		EQ_(r_size>>SECTOR_SHIFT, 1);
	// use size of backing device (autodetect with respect to offset)
	OK_(crypt_resize(cd,CDEVICE_1,0));
	if (!device_size(path,&r_size))
		EQ_(r_size>>SECTOR_SHIFT, (size >> SECTOR_SHIFT)- 42);
	OK_(crypt_deactivate(cd,CDEVICE_1));
	crypt_free(cd);

	params.size = 0;
	params.offset = 0;
	OK_(crypt_init(&cd,DEVICE_1));
	OK_(crypt_format(cd,CRYPT_PLAIN,cipher,cipher_mode,NULL,NULL,key_size,&params));
	OK_(crypt_activate_by_volume_key(cd,CDEVICE_1,key,key_size,0));

	// suspend/resume tests
	FAIL_(crypt_suspend(cd,CDEVICE_1),"cannot suspend plain device");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	FAIL_(crypt_resume_by_passphrase(cd,CDEVICE_1,CRYPT_ANY_SLOT,passphrase, strlen(passphrase)),"cannot resume plain device");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);

	// retrieve volume key check
	if (!_fips_mode) {
		memset(key2, 0, key_size);
		key_size--;
		// small buffer
		FAIL_(crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key2, &key_size, passphrase, strlen(passphrase)), "small buffer");
		key_size++;
		OK_(crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key2, &key_size, passphrase, strlen(passphrase)));

		OK_(memcmp(key, key2, key_size));
	}
	OK_(strcmp(cipher, crypt_get_cipher(cd)));
	OK_(strcmp(cipher_mode, crypt_get_cipher_mode(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(0, crypt_get_data_offset(cd));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// now with keyfile
	OK_(_prepare_keyfile(KEYFILE1, KEY1, strlen(KEY1)));
	OK_(_prepare_keyfile(KEYFILE2, KEY2, strlen(KEY2)));
	FAIL_(crypt_activate_by_keyfile(cd, NULL, CRYPT_ANY_SLOT, KEYFILE1, 0, 0), "cannot verify key with plain");
	EQ_(0, crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0, 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_activate_by_keyfile_offset(cd, NULL, CRYPT_ANY_SLOT, KEYFILE1, 0, strlen(KEY1) + 1, 0), "cannot seek");
	EQ_(0, crypt_activate_by_keyfile_offset(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0, 0, 0));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	_remove_keyfiles();
	crypt_free(cd);

	OK_(crypt_init(&cd,DEVICE_1));
	OK_(crypt_format(cd,CRYPT_PLAIN,cipher,cipher_mode,NULL,NULL,key_size,&params));

	// crypt_keyslot_*()
	FAIL_(crypt_keyslot_add_by_passphrase(cd,CRYPT_ANY_SLOT,passphrase,strlen(passphrase),passphrase,strlen(passphrase)), "can't add keyslot to plain device");
	FAIL_(crypt_keyslot_add_by_volume_key(cd,CRYPT_ANY_SLOT	,key,key_size,passphrase,strlen(passphrase)),"can't add keyslot to plain device");
	FAIL_(crypt_keyslot_add_by_keyfile(cd,CRYPT_ANY_SLOT,KEYFILE1,strlen(KEY1),KEYFILE2,strlen(KEY2)),"can't add keyslot to plain device");
	FAIL_(crypt_keyslot_destroy(cd,1),"can't manipulate keyslots on plain device");
	EQ_(crypt_keyslot_status(cd, 0), CRYPT_SLOT_INVALID);
	_remove_keyfiles();

	crypt_free(cd);
}

static int new_messages = 0;
static void new_log(int level, const char *msg, void *usrptr)
{
	if (level == CRYPT_LOG_ERROR)
		new_messages++;
	global_log_callback(level, msg, usrptr);
}

static void CallbacksTest(void)
{
	struct crypt_device *cd;
	struct crypt_params_plain params = {
		.hash = "sha1",
		.skip = 0,
		.offset = 0,
	};

	size_t key_size = 256 / 8;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	const char *passphrase = PASSPHRASE;

	OK_(crypt_init(&cd, DEVICE_1));
	new_messages = 0;
	crypt_set_log_callback(cd, &new_log, NULL);
	EQ_(new_messages, 0);
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &params));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	EQ_(new_messages, 0);
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, passphrase, strlen(passphrase), 0), "already exists");
	EQ_(new_messages, 1);
	crypt_set_log_callback(cd, NULL, NULL);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);
}

static void UseLuksDevice(void)
{
	struct crypt_device *cd;
	char key[128];
	size_t key_size;

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	OK_(crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));
	FAIL_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0), "already open");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_deactivate(cd, CDEVICE_1), "no such device");

	key_size = 16;
	OK_(strcmp("aes", crypt_get_cipher(cd)));
	OK_(strcmp("cbc-essiv:sha256", crypt_get_cipher_mode(cd)));
	OK_(strcmp(DEVICE_1_UUID, crypt_get_uuid(cd)));
	EQ_((int)key_size, crypt_get_volume_key_size(cd));
	EQ_(1032, crypt_get_data_offset(cd));

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
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	OK_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1), 0));

	suspend_status = crypt_suspend(cd, CDEVICE_1);
	if (suspend_status == -ENOTSUP) {
		printf("WARNING: Suspend/Resume not supported, skipping test.\n");
		OK_(crypt_deactivate(cd, CDEVICE_1));
		crypt_free(cd);
		return;
	}

	OK_(suspend_status);
	FAIL_(crypt_suspend(cd, CDEVICE_1), "already suspended");

	FAIL_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)-1), "wrong key");
	OK_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)));
	FAIL_(crypt_resume_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEY1, strlen(KEY1)), "not suspended");

	OK_(_prepare_keyfile(KEYFILE1, KEY1, strlen(KEY1)));
	OK_(crypt_suspend(cd, CDEVICE_1));
	FAIL_(crypt_resume_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1 "blah", 0), "wrong keyfile");
	FAIL_(crypt_resume_by_keyfile_offset(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 1, 0), "wrong key");
	OK_(crypt_resume_by_keyfile_offset(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0, 0));
	FAIL_(crypt_resume_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0), "not suspended");
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	/* create LUKS device with detached header */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
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

static void AddDeviceLuks(void)
{
	struct crypt_device *cd;
	struct crypt_params_luks1 params = {
		.hash = "sha512",
		.data_alignment = 2048, // 4M, data offset will be 4096
		.data_device = DEVICE_2
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
	OK_(get_luks_offsets(1, key_size, 0, 0, &r_header_size, &r_payload_offset));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, r_header_size - 1));

	// format
	OK_(crypt_init(&cd, DMDIR H_DEVICE_WRONG));
	params.data_alignment = 0;
	FAIL_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params), "Not enough space for keyslots material");
	crypt_free(cd);

	// test payload_offset = 0 for encrypted device with external header device
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_get_data_offset(cd), 0);
	crypt_free(cd);

	params.data_alignment = 0;
	params.data_device = NULL;

	// test payload_offset = 0. format() should look up alignment offset from device topology
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(!(crypt_get_data_offset(cd) > 0));
	crypt_free(cd);

	/*
	 * test limit values for backing device size
	 */
	params.data_alignment = 4096;
	OK_(get_luks_offsets(0, key_size, params.data_alignment, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_0S, r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));
	//OK_(create_dmdevice_over_loop(L_DEVICE_WRONG, r_payload_offset - 1));
	OK_(create_dmdevice_over_loop(L_DEVICE_WRONG, 2050 - 1)); //FIXME last keyslot - 1 sector

	// 1 sector less than required
	OK_(crypt_init(&cd, DMDIR L_DEVICE_WRONG));
	FAIL_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params),	"Device too small");
	crypt_free(cd);

	// 0 sectors for encrypted area
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Encrypted area too small");
	crypt_free(cd);

	// 1 sector for encrypted area
	OK_(crypt_init(&cd, DMDIR L_DEVICE_1S));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_get_data_offset(cd), params.data_alignment);
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(device_size(DMDIR CDEVICE_1, &r_size_1));
	EQ_(r_size_1, SECTOR_SIZE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	// restrict format only to empty context
	FAIL_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params), "Context is already formated");
	FAIL_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, NULL), "Context is already formated");
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
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, passphrase, strlen(passphrase)), 7);
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 7, passphrase, strlen(passphrase) ,0), 7);
	crypt_free(cd);
	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, DMDIR H_DEVICE));
	FAIL_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params), "Context is already formated");
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
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	crypt_free(cd);
	params.data_alignment = 0;
	params.data_device = DEVICE_2;
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
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
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));

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
	OK_(_prepare_keyfile(KEYFILE1, KEY1, strlen(KEY1)));
	OK_(_prepare_keyfile(KEYFILE2, KEY2, strlen(KEY2)));
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
	EQ_(4096, crypt_get_data_offset(cd));
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
	crypt_set_iteration_time(cd, 0); /* wrong for argon2 but we don't know the pbkdf type yet */
	FAIL_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, key, key_size, NULL), "Invalid argon2 params");
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

	OK_(create_dmdevice_over_loop(L_DEVICE_1S, 5242880/512));
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
	OK_(crypt_format(cd, CRYPT_LUKS1, "aes", "cbc-essiv:sha256", NULL, NULL, 16, NULL));
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
		"%s 2048\" -u CRYPT-LUKS1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ctest1",
		 CDEVICE_2, DEVICE_2);
	_system(tmp, 1);
	OK_(crypt_init_by_name(&cd, CDEVICE_2));
	OK_(crypt_deactivate(cd, CDEVICE_2));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "wrong volume key");
	crypt_free(cd);

	// No slots
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, NULL, 0, 0), "volume key is lost");
	crypt_free(cd);

	// Plain device
	OK_(crypt_init(&cd, DEVICE_2));
	OK_(crypt_format(cd, CRYPT_PLAIN, "aes", "cbc-essiv:sha256", NULL, NULL, 16, NULL));
	FAIL_(crypt_activate_by_volume_key(cd, NULL, "xxx", 3, 0), "cannot verify key with plain");
	FAIL_(crypt_volume_key_verify(cd, "xxx", 3), "cannot verify key with plain");
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_2, "xxx", 3, 0), "wrong key lenght");
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_2, "volumekeyvolumek", 16, 0));
	EQ_(crypt_status(cd, CDEVICE_2), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_2));
	crypt_free(cd);
}

static void LuksHeaderRestore(void)
{
	struct crypt_device *cd;
	struct crypt_params_luks1 params = {
		.hash = "sha512",
		.data_alignment = 2048, // 4M, data offset will be 4096
	};
	struct crypt_params_plain pl_params = {
		.hash = "sha1",
		.skip = 0,
		.offset = 0,
		.size = 0
	};
	char key[128], key2[128], cmd[256];

	const char *mk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(mk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset;

	crypt_decode_key(key, mk_hex, key_size);

	OK_(get_luks_offsets(0, key_size, params.data_alignment, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 5000));

	// do not restore header over plain device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, NULL, key_size, &pl_params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	FAIL_(crypt_header_restore(cd, CRYPT_PLAIN, VALID_HEADER), "Cannot restore header to PLAIN type device");
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, VALID_HEADER), "Cannot restore header over PLAIN type device");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// invalid headers
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, EVL_HEADER_1), "Header corrupted");
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, EVL_HEADER_2), "Header corrupted");
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, EVL_HEADER_3), "Header corrupted");
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, EVL_HEADER_4), "Header too small");
	OK_(crypt_header_restore(cd, CRYPT_LUKS1, VALID_HEADER));
	// wipe valid luks header
	snprintf(cmd, sizeof(cmd), "dd if=/dev/zero of=" DMDIR L_DEVICE_OK " bs=512 count=%" PRIu64 " 2>/dev/null", r_payload_offset);
	OK_(_system(cmd, 1));
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, EVL_HEADER_1), "Header corrupted");
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, EVL_HEADER_2), "Header corrupted");
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, EVL_HEADER_3), "Header corrupted");
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, EVL_HEADER_4), "Header too small");
	OK_(crypt_header_restore(cd, CRYPT_LUKS1, VALID_HEADER));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// volume key_size mismatch
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	memcpy(key2, key, key_size / 2);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key2, key_size / 2, &params));
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, VALID_HEADER), "Volume keysize mismatch");
	crypt_free(cd);

	// payload offset mismatch
	params.data_alignment = 8192;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	FAIL_(crypt_header_restore(cd, CRYPT_LUKS1, VALID_HEADER), "Payload offset mismatch");
	//_system("dmsetup table;sleep 1",1);
	crypt_free(cd);

	_cleanup_dmdevices();
}

static void LuksHeaderLoad(void)
{
	struct crypt_device *cd;
	struct crypt_params_luks1 params = {
		.hash = "sha512",
		.data_alignment = 2048,
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
	OK_(get_luks_offsets(0, key_size, params.data_alignment, 0, &r_header_size, &r_payload_offset));
	// external header device
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	// prepared header on a device too small to contain header and payload
	//OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, r_payload_offset - 1));
	OK_(create_dmdevice_over_loop(H_DEVICE_WRONG, 2050 - 1)); //FIXME
	//snprintf(cmd, sizeof(cmd), "dd if=" EVL_HEADER_4 " of=" DMDIR H_DEVICE_WRONG " bs=512 count=%" PRIu64, r_payload_offset - 1);
	snprintf(cmd, sizeof(cmd), "dd if=" EVL_HEADER_4 " of=" DMDIR H_DEVICE_WRONG " bs=512 count=%d 2>/dev/null", 2050 - 1);
	OK_(_system(cmd, 1));
	// some device
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1000));
	// 1 sector device
	OK_(create_dmdevice_over_loop(L_DEVICE_1S, r_payload_offset + 1));
	// 0 sectors device for payload
	OK_(create_dmdevice_over_loop(L_DEVICE_0S, r_payload_offset));

	// valid metadata and device size
	params.data_alignment = 0;
	params.data_device = DMDIR L_DEVICE_OK;
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// bad header: device too small (payloadOffset > device_size)
	OK_(crypt_init(&cd, DMDIR H_DEVICE_WRONG));
	FAIL_(crypt_load(cd, CRYPT_LUKS1, NULL), "Device too small");
	NULL_(crypt_get_type(cd));
	crypt_free(cd);

	// 0 secs for encrypted data area
	params.data_alignment = 2048;
	params.data_device = NULL;
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	crypt_free(cd);
	// load should be ok
	OK_(crypt_init(&cd, DMDIR L_DEVICE_0S));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	FAIL_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0), "Device too small");
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_INACTIVE);
	crypt_free(cd);

	// damaged header
	OK_(_system("dd if=/dev/zero of=" DMDIR L_DEVICE_OK " bs=512 count=8 2>/dev/null", 1));
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	FAIL_(crypt_load(cd, CRYPT_LUKS1, NULL), "Header not found");
	crypt_free(cd);

	// plain device
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	FAIL_(crypt_load(cd, CRYPT_PLAIN, NULL), "Can't load nonLUKS device type");
	crypt_free(cd);
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, cipher_mode, NULL, key, key_size, &pl_params));
	FAIL_(crypt_load(cd, CRYPT_LUKS1, NULL), "Can't load over nonLUKS device type");
	crypt_free(cd);

	//LUKSv2 device
	OK_(crypt_init(&cd, DEVICE_4));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	crypt_free(cd);
	OK_(crypt_init(&cd, DEVICE_4));
	crypt_set_iteration_time(cd, 0); /* invalid for argon2 pbkdf */
	FAIL_(crypt_load(cd, CRYPT_LUKS, NULL), "Invalid pbkdf parameters");
	crypt_free(cd);

	_cleanup_dmdevices();
}

static void LuksHeaderBackup(void)
{
	struct crypt_device *cd;
	struct crypt_params_luks1 params = {
		.hash = "sha512",
		.data_alignment = 2048,
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

	OK_(get_luks_offsets(0, key_size, params.data_alignment, 0, NULL, &r_payload_offset));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1));

	// create LUKS device and backup the header
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, key, key_size, passphrase, strlen(passphrase)), 7);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, key, key_size, passphrase, strlen(passphrase)), 0);
	OK_(crypt_header_backup(cd, CRYPT_LUKS1, BACKUP_FILE));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// restore header from backup
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_header_restore(cd, CRYPT_LUKS1, BACKUP_FILE));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// exercise luksOpen using backup header in file
	OK_(crypt_init(&cd, BACKUP_FILE));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, passphrase, strlen(passphrase), 0), 0);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	OK_(crypt_init(&cd, BACKUP_FILE));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 7, passphrase, strlen(passphrase), 0), 7);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// exercise luksOpen using backup header on block device
	fd = crypt_loop_attach(&DEVICE_3, BACKUP_FILE, 0, 0, &ro);
	close(fd);
	OK_(fd < 0);
	OK_(crypt_init(&cd, DEVICE_3));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 0, passphrase, strlen(passphrase), 0), 0);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	OK_(crypt_init(&cd, DEVICE_3));
	OK_(crypt_load(cd, CRYPT_LUKS1, NULL));
	OK_(crypt_set_data_device(cd, DMDIR L_DEVICE_OK));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, 7, passphrase, strlen(passphrase), 0), 7);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	_cleanup_dmdevices();
}

static void ResizeDeviceLuks(void)
{
	struct crypt_device *cd;
	struct crypt_params_luks1 params = {
		.hash = "sha512",
		.data_alignment = 2048,
	};
	char key[128];

	const char *mk_hex = "bb21158c733229347bd4e681891e213d94c685be6a5b84818afe7a78a6de7a1a";
	size_t key_size = strlen(mk_hex) / 2;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	uint64_t r_payload_offset, r_header_size, r_size;

	crypt_decode_key(key, mk_hex, key_size);

	// prepare env
	OK_(get_luks_offsets(0, key_size, params.data_alignment, 0, NULL, &r_payload_offset));
	OK_(get_luks_offsets(1, key_size, 0, 0, &r_header_size, NULL));
	OK_(create_dmdevice_over_loop(H_DEVICE, r_header_size));
	OK_(create_dmdevice_over_loop(L_DEVICE_OK, r_payload_offset + 1000));
	OK_(create_dmdevice_over_loop(L_DEVICE_0S, 1000));

	// test header and encrypted payload all in one device
	OK_(crypt_init(&cd, DMDIR L_DEVICE_OK));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	OK_(crypt_resize(cd, CDEVICE_1, 42));
	if (!device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(42, r_size >> SECTOR_SHIFT);
	// autodetect encrypted device area size
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	if (!device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> SECTOR_SHIFT);
	FAIL_(crypt_resize(cd, CDEVICE_1, 1001), "Device too small");
	if (!device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> SECTOR_SHIFT);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	params.data_alignment = 0;
	params.data_device = DMDIR L_DEVICE_0S;
	// test case for external header
	OK_(crypt_init(&cd, DMDIR H_DEVICE));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, key, key_size, 0));
	OK_(crypt_resize(cd, CDEVICE_1, 666));
	if (!device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(666, r_size >> SECTOR_SHIFT);
	// autodetect encrypted device size
	OK_(crypt_resize(cd, CDEVICE_1, 0));
	if (!device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> SECTOR_SHIFT);
	FAIL_(crypt_resize(cd, CDEVICE_1, 1001), "Device too small");
	if (!device_size(DMDIR CDEVICE_1, &r_size))
		EQ_(1000, r_size >> SECTOR_SHIFT);
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	_cleanup_dmdevices();
}

static void HashDevicePlain(void)
{
	struct crypt_device *cd;
	struct crypt_params_plain params = {
		.hash = NULL,
		.skip = 0,
		.offset = 0,
	};

	size_t key_size;
	const char *mk_hex, *keystr;
	char key[256];

	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_PLAIN, "aes", "cbc-essiv:sha256", NULL, NULL, 16, &params));

	// hash PLAIN, short key
	OK_(_prepare_keyfile(KEYFILE1, "tooshort", 8));
	FAIL_(crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 16, 0), "not enough data in keyfile");
	_remove_keyfiles();

	// hash PLAIN, exact key
	//         0 1 2 3 4 5 6 7 8 9 a b c d e f
	mk_hex = "caffeecaffeecaffeecaffeecaffee88";
	key_size = 16;
	crypt_decode_key(key, mk_hex, key_size);
	OK_(_prepare_keyfile(KEYFILE1, key, key_size));
	OK_(crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, key_size, 0));
	OK_(_get_key_dm(CDEVICE_1, key, sizeof(key)));
	OK_(strcmp(key, mk_hex));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// Limit plain key
	mk_hex = "caffeecaffeecaffeecaffeeca000000";
	OK_(crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, key_size - 3, 0));
	OK_(_get_key_dm(CDEVICE_1, key, sizeof(key)));
	OK_(strcmp(key, mk_hex));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	_remove_keyfiles();

	// hash PLAIN, long key
	//         0 1 2 3 4 5 6 7 8 9 a b c d e f
	mk_hex = "caffeecaffeecaffeecaffeecaffee88babebabe";
	key_size = 16;
	crypt_decode_key(key, mk_hex, key_size);
	OK_(_prepare_keyfile(KEYFILE1, key, strlen(mk_hex) / 2));
	OK_(crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, key_size, 0));
	OK_(_get_key_dm(CDEVICE_1, key, sizeof(key)));
	FAIL_(strcmp(key, mk_hex), "only key length used");
	OK_(strncmp(key, mk_hex, key_size));
	OK_(crypt_deactivate(cd, CDEVICE_1));


	// Now without explicit limit
	OK_(crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0, 0));
	OK_(_get_key_dm(CDEVICE_1, key, sizeof(key)));
	FAIL_(strcmp(key, mk_hex), "only key length used");
	OK_(strncmp(key, mk_hex, key_size));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	_remove_keyfiles();

	// hash sha256
	params.hash = "sha256";
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_PLAIN, "aes", "cbc-essiv:sha256", NULL, NULL, 16, &params));

	//         0 1 2 3 4 5 6 7 8 9 a b c d e f
	mk_hex = "c62e4615bd39e222572f3a1bf7c2132e";
	keystr = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
	key_size = strlen(keystr); // 32
	OK_(_prepare_keyfile(KEYFILE1, keystr, strlen(keystr)));
	OK_(crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, key_size, 0));
	OK_(_get_key_dm(CDEVICE_1, key, sizeof(key)));
	OK_(strcmp(key, mk_hex));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// Read full keyfile
	OK_(crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0, 0));
	OK_(_get_key_dm(CDEVICE_1, key, sizeof(key)));
	OK_(strcmp(key, mk_hex));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	_remove_keyfiles();

	// Limit keyfile read
	keystr = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxAAAAAAAA";
	OK_(_prepare_keyfile(KEYFILE1, keystr, strlen(keystr)));
	OK_(crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, key_size, 0));
	OK_(_get_key_dm(CDEVICE_1, key, sizeof(key)));
	OK_(strcmp(key, mk_hex));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	// Full keyfile
	OK_(crypt_activate_by_keyfile(cd, CDEVICE_1, CRYPT_ANY_SLOT, KEYFILE1, 0, 0));
	OK_(_get_key_dm(CDEVICE_1, key, sizeof(key)));
	OK_(strcmp(key, "0e49cb34a1dee1df33f6505e4de44a66"));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	_remove_keyfiles();

	// FIXME: add keyfile="-" tests somehow

	crypt_free(cd);
}

static void VerityTest(void)
{
	struct crypt_device *cd;
	const char *salt_hex =  "20c28ffc129c12360ba6ceea2b6cf04e89c2b41cfe6b8439eb53c1897f50df7b";
	const char *root_hex =  "ab018b003a967fc782effb293b6dccb60b4f40c06bf80d16391acf686d28b5d6";
	char salt[256], root_hash[256];
	struct crypt_active_device cad;
	struct crypt_params_verity params = {
		.data_device = DEVICE_EMPTY,
		.salt = salt,
		.data_size = 0, /* whole device */
		.hash_area_offset = 0,
		.flags = CRYPT_VERITY_CREATE_HASH,
	};

	crypt_decode_key(salt, salt_hex, strlen(salt_hex) / 2);
	crypt_decode_key(root_hash, root_hex, strlen(root_hex) / 2);

	/* Format */
	OK_(crypt_init(&cd, DEVICE_2));

	/* block size */
	params.data_block_size = 333;
	FAIL_(crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params),
		"Unsupppored block size.");
	params.data_block_size = 4096;
	params.hash_block_size = 333;
	FAIL_(crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params),
		"Unsupppored block size.");
	params.hash_block_size = 4096;

	/* salt size */
	params.salt_size = 257;
	FAIL_(crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params),
		"Too large salt.");
	params.salt_size = 32;

	/* hash_type */
	params.hash_type = 3;
	FAIL_(crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params),
		"Unsupported hash type.");
	params.hash_type = 1;
	params.hash_name = "blah";
	FAIL_(crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params),
		"Unsupported hash name.");
	params.hash_name = "sha256";

	OK_(crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params));
	crypt_free(cd);

	/* Verify */
	OK_(crypt_init(&cd, DEVICE_2));
	memset(&params, 0, sizeof(params));
	params.data_device = DEVICE_EMPTY;
	params.flags = CRYPT_VERITY_CHECK_HASH;
	OK_(crypt_load(cd, CRYPT_VERITY, &params));

	/* check verity params */
	EQ_(crypt_get_volume_key_size(cd), 32);
	OK_(strcmp(CRYPT_VERITY, crypt_get_type(cd)));
	memset(&params, 0, sizeof(params));
	OK_(crypt_get_verity_info(cd, &params));
	OK_(strcmp("sha256", params.hash_name));
	EQ_(strlen(salt_hex) / 2, params.salt_size);
	OK_(memcmp(salt, params.salt, params.salt_size));
	EQ_(4096, params.data_block_size);
	EQ_(4096, params.hash_block_size);
	EQ_(1, params.hash_type);
	EQ_(crypt_get_volume_key_size(cd), 32);

	OK_(crypt_activate_by_volume_key(cd, NULL, root_hash, 32, 0));
	OK_(crypt_set_data_device(cd, DEVICE_1));
	FAIL_(crypt_activate_by_volume_key(cd, NULL, root_hash, 32, 0), "Data corrupted");;

	OK_(crypt_set_data_device(cd, DEVICE_EMPTY));
	if (crypt_activate_by_volume_key(cd, CDEVICE_1, root_hash, 32,
	    CRYPT_ACTIVATE_READONLY) == -ENOTSUP) {
		printf("WARNING: kernel dm-verity not supported, skipping test.\n");
		crypt_free(cd);
		return;
	}
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(CRYPT_ACTIVATE_READONLY, cad.flags);
	crypt_free(cd);

	OK_(crypt_init_by_name(&cd, CDEVICE_1));
	OK_(crypt_deactivate(cd, CDEVICE_1));

	/* hash fail */
	root_hash[1] = ~root_hash[1];
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, root_hash, 32, CRYPT_ACTIVATE_READONLY));
	/* Be sure there was some read activity to mark device corrupted. */
	_system("blkid " DMDIR CDEVICE_1, 0);
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(CRYPT_ACTIVATE_READONLY|CRYPT_ACTIVATE_CORRUPTED, cad.flags);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	root_hash[1] = ~root_hash[1];

	/* data fail */
	OK_(crypt_set_data_device(cd, DEVICE_1));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, root_hash, 32, CRYPT_ACTIVATE_READONLY));
	_system("blkid " DMDIR CDEVICE_1, 0);
	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(CRYPT_ACTIVATE_READONLY|CRYPT_ACTIVATE_CORRUPTED, cad.flags);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	crypt_free(cd);
}

static void TcryptTest(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_active_device cad;
	const char *passphrase = "aaaaaaaaaaaa";
	const char *kf1 = "tcrypt-images/keyfile1";
	const char *kf2 = "tcrypt-images/keyfile2";
	const char *keyfiles[] = { kf1, kf2 };
	struct crypt_params_tcrypt params = {
		.passphrase = passphrase,
		.passphrase_size = strlen(passphrase),
		.keyfiles = keyfiles,
		.keyfiles_count = 2,
	};
	double enc_mbr = 0, dec_mbr = 0;
	const char *tcrypt_dev = "tcrypt-images/tck_5-sha512-xts-aes";
	const char *tcrypt_dev2 = "tcrypt-images/tc_5-sha512-xts-serpent-twofish-aes";
	size_t key_size = 64;
	char key[key_size], key_def[key_size];
	const char *key_hex =
		"98dee64abe44bbf41d171c1f7b3e8eacda6d6b01f459097459a167f8c2872a96"
		"3979531d1cdc18af62757cf22286f16f8583d848524f128d7594ac2082668c73";
	int r;

	crypt_decode_key(key_def, key_hex, strlen(key_hex) / 2);

	// First ensure we can use af_alg skcipher interface
	r = crypt_benchmark(NULL, "aes", "xts", 512, 16, 1024, &enc_mbr, &dec_mbr);
	if (r == -ENOTSUP || r == -ENOENT) {
		printf("WARNING: algif_skcipher interface not present, skipping test.\n");
		return;
	}

	OK_(crypt_init(&cd, tcrypt_dev));
	params.passphrase_size--;
	FAIL_(crypt_load(cd, CRYPT_TCRYPT, &params), "Wrong passphrase");
	params.passphrase_size++;
	OK_(crypt_load(cd, CRYPT_TCRYPT, &params));

	// check params after load
	OK_(strcmp("xts-plain64", crypt_get_cipher_mode(cd)));
	OK_(strcmp("aes", crypt_get_cipher(cd)));
	EQ_(key_size, crypt_get_volume_key_size(cd));
	EQ_(256, crypt_get_iv_offset(cd));
	EQ_(256, crypt_get_data_offset(cd));

	memset(key, 0, key_size);
	if (!_fips_mode) {
		key_size--;
		// small buffer
		FAIL_(crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size, NULL, 0), "small buffer");
		key_size++;
		OK_(crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size, NULL, 0));
		OK_(memcmp(key, key_def, key_size));
	}

	reset_log();
	OK_(crypt_dump(cd));
	OK_(!(global_lines != 0));
	reset_log();

	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, NULL, 0, CRYPT_ACTIVATE_READONLY));
	crypt_free(cd);

	OK_(crypt_init_by_name_and_header(&cd, CDEVICE_1, NULL));
	EQ_(crypt_status(cd, CDEVICE_1), CRYPT_ACTIVE);

	FAIL_(crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size, NULL, 0), "Need crypt_load");

	// check params after init_by_name
	OK_(strcmp("xts-plain64", crypt_get_cipher_mode(cd)));
	OK_(strcmp("aes", crypt_get_cipher(cd)));
	EQ_(key_size, crypt_get_volume_key_size(cd));
	EQ_(256, crypt_get_iv_offset(cd));
	EQ_(256, crypt_get_data_offset(cd));

	OK_(crypt_get_active_device(cd, CDEVICE_1, &cad));
	EQ_(CRYPT_ACTIVATE_READONLY, cad.flags);
	EQ_(256, cad.offset);
	EQ_(256, cad.iv_offset);
	EQ_(72, cad.size);

	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	// Following test uses non-FIPS algorithms in the cipher chain
	if(_fips_mode)
		return;

	OK_(crypt_init(&cd, tcrypt_dev2));
	params.keyfiles = NULL;
	params.keyfiles_count = 0;
	OK_(crypt_load(cd, CRYPT_TCRYPT, &params));
	OK_(crypt_activate_by_volume_key(cd, CDEVICE_1, NULL, 0, CRYPT_ACTIVATE_READONLY));
	crypt_free(cd);

	// Deactivate the whole chain
	EQ_(crypt_status(NULL, CDEVICE_1 "_1"), CRYPT_BUSY);
	OK_(crypt_deactivate(NULL, CDEVICE_1));
	EQ_(crypt_status(NULL, CDEVICE_1 "_1"), CRYPT_INACTIVE);
}

// Check that gcrypt is properly initialised in format
static void NonFIPSAlg(void)
{
	struct crypt_device *cd;
	struct crypt_params_luks1 params = {0};
	char key[128] = "";
	size_t key_size = 128 / 8;
	const char *cipher = "aes";
	const char *cipher_mode = "cbc-essiv:sha256";
	int ret;

	OK_(crypt_init(&cd, DEVICE_2));
	params.hash = "sha256";
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params));
	FAIL_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params),
	      "Already formatted.");
	crypt_free(cd);

	params.hash = "whirlpool";
	OK_(crypt_init(&cd, DEVICE_2));
	ret = crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params);
	if (ret < 0) {
		printf("WARNING: whirlpool not supported, skipping test.\n");
		crypt_free(cd);
		return;
	}
	crypt_free(cd);

	params.hash = "md5";
	OK_(crypt_init(&cd, DEVICE_2));
	FAIL_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, key, key_size, &params),
	      "MD5 unsupported, too short");
	crypt_free(cd);
}

static void TokenActivationByKeyring(void)
{
#ifdef KERNEL_KEYRING
#define TOKEN_JSON(x,y) "{\"type\":\"keyring\",\"keyslots\":[" y "]," \
			"\"key_length\":32,\"key_description\":\"" x "\"}"

	key_serial_t kid, kid1;
	struct crypt_device *cd;

	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

	kid = add_key("user", KEY_DESC_TEST0, PASSPHRASE, strlen(PASSPHRASE), KEY_SPEC_THREAD_KEYRING);
	if (kid < 0) {
		printf("Test or kernel keyring are broken.\n");
		exit(1);
	}

	/* prepare the device */
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_token_json_set(cd, 0, TOKEN_JSON(KEY_DESC_TEST0, "\"0\"")), 0);
	crypt_free(cd);

	/* test thread keyring key in token 0 */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 0, NULL, 0), 0);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 0, NULL, 0), "already open");
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

	/* add token 1 with process keyring key */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_token_json_set(cd, 0, NULL), 0);
	EQ_(crypt_token_json_set(cd, 1, TOKEN_JSON(KEY_DESC_TEST0, "\"0\"")), 1);
	crypt_free(cd);

	/* test process keyring key in token 1 */
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

	/* create two tokens and let the cryptsetup unlock the volume with the valid one */
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
	EQ_(crypt_token_json_set(cd, 0, TOKEN_JSON(KEY_DESC_TEST0, "\"0\"")), 0);
	FAIL_(crypt_token_json_set(cd, 1, TOKEN_JSON(KEY_DESC_TEST1, "\"1\"")), "keyslot 1 not present");
	crypt_set_iteration_time(cd, 1);
	EQ_(crypt_keyslot_add_by_passphrase(cd, 1, PASSPHRASE, strlen(PASSPHRASE), PASSPHRASE1, strlen(PASSPHRASE1)), 1);
	EQ_(crypt_token_json_set(cd, 1, TOKEN_JSON(KEY_DESC_TEST1, "\"1\"")), 1);
	crypt_free(cd);

	/* activate by specific token */
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

	/* activate by any token with token 0 having absent pass from keyring */
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

	/* replace pass for keyslot 0 making token 0 invalid */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	OK_(crypt_keyslot_destroy(cd, 0));
	crypt_set_iteration_time(cd, 1);
	EQ_(crypt_keyslot_add_by_passphrase(cd, 0, PASSPHRASE1, strlen(PASSPHRASE1), PASSPHRASE1, strlen(PASSPHRASE1)), 0);
	crypt_free(cd);

	/* activate by any token with token 0 having wrong pass for keyslot 0 */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS2, NULL));
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, CRYPT_ANY_TOKEN, NULL, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	crypt_free(cd);

	/*
	 * create new device, with two tokens:
	 * 1st token being invalid (missing key in keyring)
	 * 2nd token can activate keyslot 1 after failing to do so w/ keyslot 0 (wrong pass)
	 */
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 1);
	EQ_(crypt_token_json_set(cd, 0, TOKEN_JSON(KEY_DESC_TEST0, "\"0\"")), 0);
	EQ_(crypt_token_json_set(cd, 2, TOKEN_JSON(KEY_DESC_TEST1, "\"0\",\"1\"")), 2);
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

	struct crypt_device *cd;

	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

	const crypt_token_handler th = {
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
	};

	OK_(crypt_token_register(&th));
	FAIL_(crypt_token_register(&th2), "Token handler with the name already registered.");

	/* basic token API tests */
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 1, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 1);
	FAIL_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN_JSON_INVALID("\"0\"")), "Token validation failed");
	EQ_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN_JSON("\"0\"")), 0);
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 0, PASSPHRASE, 0), 0);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 0, PASSPHRASE, 0), "already active");
	OK_(crypt_deactivate(cd, CDEVICE_1));

	/* write invalid token and verify that validate() can detect it after handler being registered  */
	EQ_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN1_JSON_INVALID("\"1\"")), 1);
	EQ_(crypt_token_json_set(cd, CRYPT_ANY_TOKEN, TEST_TOKEN1_JSON("\"1\"")), 2);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 1, PASSPHRASE1, 0), "Unknown token handler");
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE1, 0), "Unknown token handler");
	OK_(crypt_token_register(&th3));
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 1, PASSPHRASE1, 0), "Token validation failed");
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE1, 0), 1);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	/* exercise assign/unassign keyslots API */
	EQ_(crypt_token_unassign_keyslot(cd, 2, 1), 2);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE1, 0), "Token assigned to no keyslot");
	EQ_(crypt_token_assign_keyslot(cd, 2, 0), 2);
	FAIL_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE1, 0), "Wrong passphrase");
	EQ_(crypt_activate_by_token(cd, CDEVICE_1, 2, PASSPHRASE, 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));

	crypt_free(cd);
}

static void LuksConvert(void)
{
	struct crypt_device *cd;

	const struct crypt_pbkdf_type argon = {
		.type = "argon2",
		.hash = "sha512",
		.time_ms = 1,
		.max_memory_kb = 1024,
		.parallel_threads = 1
	}, pbkdf2 = {
		.type = "pbkdf2",
		.hash = "sha1",
		.time_ms = 1
	};

	const char *cipher = "aes";
	const char *cipher_mode = "xts-plain64";

	/* prepare the device */
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, cipher_mode, NULL, NULL, 32, NULL));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	EQ_(crypt_keyslot_add_by_volume_key(cd, 7, NULL, 32, PASSPHRASE1, strlen(PASSPHRASE1)), 7);
	crypt_free(cd);

	/* convert LUKSv1 -> LUKSv2 */
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

	/* check result */
	OK_(crypt_init(&cd, DEVICE_1));
	FAIL_(crypt_load(cd, CRYPT_LUKS1, NULL), "wrong luks format");
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS2));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE1, strlen(PASSPHRASE1), 0), 7);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_convert(cd, CRYPT_LUKS2, NULL), "format is already LUKSv2");
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS2));
	crypt_free(cd);

	/* convert LUKSv2 -> LUKSv1 */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "device is active");
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS2));
	OK_(crypt_deactivate(cd, CDEVICE_1));
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS1));
	crypt_free(cd);

	/* check result */
	OK_(crypt_init(&cd, DEVICE_1));
	FAIL_(crypt_load(cd, CRYPT_LUKS2, NULL), "wrong luks format");
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS1));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE, strlen(PASSPHRASE), 0), 0);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	EQ_(crypt_activate_by_passphrase(cd, CDEVICE_1, CRYPT_ANY_SLOT, PASSPHRASE1, strlen(PASSPHRASE1), 0), 7);
	OK_(crypt_deactivate(cd, CDEVICE_1));
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "format is already LUKSv1");
	OK_(strcmp(crypt_get_type(cd), CRYPT_LUKS1));
	crypt_free(cd);

	/* exercice non-pbkdf2 LUKSv2 conversion */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	OK_(crypt_set_pbkdf_type(cd, &argon));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	FAIL_(crypt_convert(cd, CRYPT_LUKS1, NULL), "Incompatible pbkdf with LUKSv1 format");
	crypt_free(cd);

	/* exercice LUKSv2 conversion with single pbkdf2 keyslot being active */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, cipher_mode, NULL, NULL, 32, NULL));
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	EQ_(crypt_keyslot_add_by_volume_key(cd, 0, NULL, 32, PASSPHRASE, strlen(PASSPHRASE)), 0);
	OK_(crypt_convert(cd, CRYPT_LUKS1, NULL));
	crypt_free(cd);
}

static void Pbkdf(void)
{
	struct crypt_device *cd;
	const struct crypt_pbkdf_type *pbkdf;

	const char *cipher = "aes", *mode="xts-plain64";
	struct crypt_pbkdf_type argon2 = {
		.type = "argon2",
		.hash = DEFAULT_LUKS1_HASH,
		.time_ms = 6,
		.max_memory_kb = 1024,
		.parallel_threads = 1
	}, pbkdf2 = {
		.type = "pbkdf2",
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
		.hash = "whirlpool", /* test non-standard hash */
		.data_alignment = 2048,
	};

	/* test empty context */
	OK_(crypt_init(&cd, DEVICE_1));
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Unsupported with non-LUKS2 devices");
	FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Unsupported with non-LUKS2 devices");
	FAIL_(crypt_set_pbkdf_type(cd, NULL), "Unsupported with non-LUKS2 devices");
	NULL_(crypt_get_pbkdf_type(cd));

	/* test plain device */
	OK_(crypt_format(cd, CRYPT_PLAIN, cipher, mode, NULL, NULL, 32, &params));
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Unsupported with non-LUKS2 devices");
	FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Unsupported with non-LUKS2 devices");
	FAIL_(crypt_set_pbkdf_type(cd, NULL), "Unsupported with non-LUKS2 devices");
	NULL_(crypt_get_pbkdf_type(cd));
	crypt_free(cd);

	/* TODO: add tcrypt, vera_crypt... */

	/* test LUKSv1 device */
	/* test crypt_set_pbkdf_type() is disabled for LUKSv1 */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, mode, NULL, NULL, 32, NULL));
	FAIL_(crypt_set_pbkdf_type(cd, &argon2), "Unsupported with non-LUKS2 devices");
	FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Unsupported with non-LUKS2 devices");
	FAIL_(crypt_set_pbkdf_type(cd, NULL), "Unsupported with non-LUKS2 devices");
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, DEFAULT_LUKS1_ITER_TIME);
	crypt_free(cd);
	/* test value set in crypt_set_iteration_time() can be obtained via following crypt_get_pbkdf_type() */
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 42);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, mode, NULL, NULL, 32, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, 42);
	/* test crypt_get_pbkdf_type() returns expected values for LUKSv1 */
	OK_(strcmp(pbkdf->type, "pbkdf2"));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->max_memory_kb, 0);
	EQ_(pbkdf->parallel_threads, 0);
	crypt_set_iteration_time(cd, 43);
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, 43);
	crypt_free(cd);
	/* test whether crypt_get_pbkdf_type() after double crypt_load() */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	crypt_set_iteration_time(cd, 42);
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	EQ_(pbkdf->time_ms, 42);
	crypt_free(cd);
	/* test whether hash passed via *params in crypt_load() has higher priority */
	OK_(crypt_init(&cd, DEVICE_1));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_format(cd, CRYPT_LUKS1, cipher, mode, NULL, NULL, 32, &luks1));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->hash, luks1.hash));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->hash, luks1.hash));
	crypt_free(cd);

	/* test LUKSv2 device */
	/* test default values are set */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_format(cd, CRYPT_LUKS2, cipher, mode, NULL, NULL, 32, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, DEFAULT_LUKS2_PBKDF));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->time_ms, DEFAULT_LUKS2_ITER_TIME);
	EQ_(pbkdf->max_memory_kb, DEFAULT_LUKS2_MEMORY_KB);
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), DEFAULT_LUKS2_PARALLEL_THREADS));
	/* set and verify argon2 type */
	OK_(crypt_set_pbkdf_type(cd, &argon2));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, argon2.type));
	OK_(strcmp(pbkdf->hash, argon2.hash));
	EQ_(pbkdf->time_ms, argon2.time_ms);
	EQ_(pbkdf->max_memory_kb, argon2.max_memory_kb);
	EQ_(pbkdf->parallel_threads, argon2.parallel_threads);
	/* set and verify pbkdf2 type */
	OK_(crypt_set_pbkdf_type(cd, &pbkdf2));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, pbkdf2.type));
	OK_(strcmp(pbkdf->hash, pbkdf2.hash));
	EQ_(pbkdf->time_ms, pbkdf2.time_ms);
	EQ_(pbkdf->max_memory_kb, pbkdf2.max_memory_kb);
	EQ_(pbkdf->parallel_threads, pbkdf2.parallel_threads);
	/* reset and verify default values */
	crypt_set_iteration_time(cd, 1); /* it's supposed to override this call */
	OK_(crypt_set_pbkdf_type(cd, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, DEFAULT_LUKS2_PBKDF));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->time_ms, DEFAULT_LUKS2_ITER_TIME);
	EQ_(pbkdf->max_memory_kb, DEFAULT_LUKS2_MEMORY_KB);
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), DEFAULT_LUKS2_PARALLEL_THREADS));
	/* try to pass illegal values */
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
	bad.type = "pbkdf2";
	bad.hash = NULL;
	FAIL_(crypt_set_pbkdf_type(cd, &bad), "Hash member is empty");
	bad.type = NULL;
	bad.hash = DEFAULT_LUKS1_HASH;
	FAIL_(crypt_set_pbkdf_type(cd, &bad), "Pbkdf type member is empty");
	/* following test fails atm */
	/* bad.hash = "hamster_hash";
	FAIL_(crypt_set_pbkdf_type(cd, &pbkdf2), "Unknown hash member"); */
	crypt_free(cd);
	/* test whether crypt_get_pbkdf_type() behaves accordinglt after second crypt_load() call */
	OK_(crypt_init(&cd, DEVICE_1));
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	NOTNULL_(pbkdf = crypt_get_pbkdf_type(cd));
	OK_(strcmp(pbkdf->type, DEFAULT_LUKS2_PBKDF));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->time_ms, DEFAULT_LUKS2_ITER_TIME);
	EQ_(pbkdf->max_memory_kb, DEFAULT_LUKS2_MEMORY_KB);
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), DEFAULT_LUKS2_PARALLEL_THREADS));
	crypt_set_iteration_time(cd, 1);
	OK_(crypt_load(cd, CRYPT_LUKS, NULL));
	OK_(strcmp(pbkdf->type, DEFAULT_LUKS2_PBKDF));
	OK_(strcmp(pbkdf->hash, DEFAULT_LUKS1_HASH));
	EQ_(pbkdf->time_ms, 1);
	EQ_(pbkdf->max_memory_kb, DEFAULT_LUKS2_MEMORY_KB);
	EQ_(pbkdf->parallel_threads, _min(cpus_online(), DEFAULT_LUKS2_PARALLEL_THREADS));
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
		exit(0);
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

	_cleanup();
	if (_setup())
		goto out;

	crypt_set_debug_level(_debug ? CRYPT_DEBUG_ALL : CRYPT_DEBUG_NONE);

	RUN_(NonFIPSAlg, "Crypto is properly initialised in format"); //must be the first!
	RUN_(AddDevicePlain, "plain device API creation exercise");
	RUN_(HashDevicePlain, "plain device API hash test");
	RUN_(AddDeviceLuks, "Format and use LUKS device");
	RUN_(LuksHeaderLoad, "test header load");
	RUN_(LuksHeaderRestore, "test LUKS header restore");
	RUN_(LuksHeaderBackup, "test LUKS header backup");
	RUN_(ResizeDeviceLuks, "Luks device resize tests");
	RUN_(UseLuksDevice, "Use pre-formated LUKS device");
	RUN_(SuspendDevice, "Suspend/Resume test");
	RUN_(UseTempVolumes, "Format and use temporary encrypted device");
	RUN_(CallbacksTest, "API callbacks test");
	RUN_(VerityTest, "DM verity test");
	RUN_(TcryptTest, "Tcrypt API test");

	/* Temporary before figuring out where to place 2.0 API tests */
	RUN_(Tokens, "General tokens API tests");
	RUN_(TokenActivationByKeyring, "Builtin kernel keyring token tests");
	RUN_(LuksConvert, "Test LUKSv1 <-> LUKSv2 conversions");
	RUN_(Pbkdf, "Exercice default pbkdf manipulation routines");
out:
	_cleanup();
	return 0;
}
