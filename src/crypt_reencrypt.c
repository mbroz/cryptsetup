/*
 * crypt_reencrypt - crypt utility for offline reencryption
 *
 * Copyright (C) 2012 Milan Broz All rights reserved.
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

/* The code works as follows:
 *  - create backup (detached) headers fo old and new device
 *  - mark original device unusable
 *  - maps two devices, one with old header one with new onto
 *    the _same_ underlying device
 *  - with direct-io reads old device and copy to new device in defined steps
 *  - keps simple off in file (allows restart)
 *  - there is several windows when corruption can happen
 *
 * null target
 * dmsetup create x --table "0 $(blockdev --getsz DEV) crypt cipher_null-ecb-null - 0 DEV 0"
 */
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <libcryptsetup.h>
#include <popt.h>

#include "cryptsetup.h"

static int opt_verbose = 0;
static int opt_debug = 0;
static const char *opt_cipher = NULL;
static const char *opt_hash = NULL;
static const char *opt_key_file = NULL;
static int opt_iteration_time = 1000;
static int opt_batch_mode = 0;
static int opt_version_mode = 0;
static int opt_random = 0;
static int opt_urandom = 0;
static int opt_bsize = 4;
static int opt_new = 0;
static int opt_directio = 0;
static int opt_write_log = 0;
static const char *opt_new_file = NULL;

static const char **action_argv;

static volatile int quit = 0;

struct {
	char *device;
	char *device_uuid;
	uint64_t device_size;
	uint64_t device_offset;
	uint64_t device_shift;

	int in_progress:1;
	enum { FORWARD = 0, BACKWARD = 1 } reencrypt_direction;

	char header_file_org[PATH_MAX];
	char header_file_new[PATH_MAX];
	char log_file[PATH_MAX];

	char crypt_path_org[PATH_MAX];
	char crypt_path_new[PATH_MAX];
	int log_fd;

	char *password;
	size_t passwordLen;
	int keyslot;

	struct timeval start_time, end_time;
} rnc;

char MAGIC[]   = {'L','U','K','S', 0xba, 0xbe};
char NOMAGIC[] = {'L','U','K','S', 0xde, 0xad};
int  MAGIC_L = 6;

typedef enum {
	MAKE_UNUSABLE,
	MAKE_USABLE,
	CHECK_UNUSABLE
} header_magic;

__attribute__((format(printf, 5, 6)))
static void clogger(struct crypt_device *cd, int level, const char *file,
		   int line, const char *format, ...)
{
	va_list argp;
	char *target = NULL;

	va_start(argp, format);

	if (vasprintf(&target, format, argp) > 0) {
		if (level >= 0) {
			crypt_log(cd, level, target);
		} else if (opt_debug)
			printf("# %s\n", target);
	}

	va_end(argp);
	free(target);
}

static void _log(int level, const char *msg, void *usrptr __attribute__((unused)))
{
	switch(level) {

	case CRYPT_LOG_NORMAL:
		fputs(msg, stdout);
		break;
	case CRYPT_LOG_VERBOSE:
		if (opt_verbose)
			fputs(msg, stdout);
		break;
	case CRYPT_LOG_ERROR:
		fputs(msg, stderr);
		break;
	case CRYPT_LOG_DEBUG:
		if (opt_debug)
			printf("# %s\n", msg);
		break;
	default:
		fprintf(stderr, "Internal error on logging class for msg: %s", msg);
		break;
	}
}

static void _quiet_log(int level, const char *msg, void *usrptr)
{
	if (!opt_verbose && (level == CRYPT_LOG_ERROR || level == CRYPT_LOG_NORMAL))
		level = CRYPT_LOG_VERBOSE;
	_log(level, msg, usrptr);
}

static void int_handler(int sig __attribute__((__unused__)))
{
	quit++;
}

static void set_int_block(int block)
{
	sigset_t signals_open;

	sigemptyset(&signals_open);
	sigaddset(&signals_open, SIGINT);
	sigaddset(&signals_open, SIGTERM);
	sigprocmask(block ? SIG_SETMASK : SIG_UNBLOCK, &signals_open, NULL);
}

static void set_int_handler(void)
{
	struct sigaction sigaction_open;

	memset(&sigaction_open, 0, sizeof(struct sigaction));
	sigaction_open.sa_handler = int_handler;
	sigaction(SIGINT, &sigaction_open, 0);
	sigaction(SIGTERM, &sigaction_open, 0);
	set_int_block(0);
}

/* The difference in seconds between two times in "timeval" format. */
double time_diff(struct timeval start, struct timeval end)
{
	return (end.tv_sec - start.tv_sec)
		+ (end.tv_usec - start.tv_usec) / 1E6;
}

static int alignment(int fd)
{
	int alignment;

	alignment = fpathconf(fd, _PC_REC_XFER_ALIGN);
	if (alignment < 0)
		alignment = 4096;
	return alignment;
}

static int device_magic(header_magic set_magic)
{
	char *buf = NULL;
	size_t block_size = 512;
	int r, devfd;
	ssize_t s;

	devfd = open(rnc.device, O_RDWR | O_DIRECT);
	if (devfd == -1)
		return errno == EBUSY ? -EBUSY : -EINVAL;

	if (posix_memalign((void *)&buf, alignment(devfd), block_size)) {
		r = -ENOMEM;
		goto out;
	}

	s = read(devfd, buf, block_size);
	if (s < 0 || s != block_size) {
		log_verbose(_("Cannot read device %s.\n"), rnc.device);
		close(devfd);
		return -EIO;
	}

	if (set_magic == MAKE_UNUSABLE && !memcmp(buf, MAGIC, MAGIC_L)) {
		log_dbg("Marking LUKS device %s unusable.", rnc.device);
		memcpy(buf, NOMAGIC, MAGIC_L);
		r = 0;

	} else if (set_magic == MAKE_USABLE && !memcmp(buf, NOMAGIC, MAGIC_L)) {
		log_dbg("Marking LUKS device %s usable.", rnc.device);
		memcpy(buf, MAGIC, MAGIC_L);
		r = 0;
	} else if (set_magic == CHECK_UNUSABLE) {
		r = memcmp(buf, NOMAGIC, MAGIC_L) ? -EINVAL : 0;
		if (!r)
			rnc.device_uuid = strndup(&buf[0xa8], 40);
		goto out;
	} else
		r = -EINVAL;

	if (!r) {
		if (lseek(devfd, 0, SEEK_SET) == -1)
			goto out;
		s = write(devfd, buf, block_size);
		if (s < 0 || s != block_size) {
			log_verbose(_("Cannot write device %s.\n"), rnc.device);
			r = -EIO;
		}
	} else
		log_dbg("LUKS signature check failed for %s.", rnc.device);
out:
	if (buf)
		memset(buf, 0, block_size);
	free(buf);
	close(devfd);
	return r;
}

static int create_empty_header(const char *new_file, uint64_t size)
{
	int fd, r = 0;
	char *buf;

	log_dbg("Creating empty file %s of size %lu.", new_file, (unsigned long)size);

	if (!(buf = malloc(size)))
		return -ENOMEM;
	memset(buf, 0, size);

	fd = creat(new_file, S_IRUSR|S_IWUSR);
	if(fd == -1) {
		free(buf);
		return -EINVAL;
	}

	if (write(fd, buf, size) < size)
		r = -EIO;

	close(fd);
	free(buf);
	return r;
}

static int write_log(void)
{
	static char buf[512];
	ssize_t r;

	//log_dbg("Updating LUKS reencryption log offset %" PRIu64 ".", offset);
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf), "# LUKS reencryption log, DO NOT EDIT OR DELETE.\n"
		"version = %d\nUUID = %s\ndirection = %d\n"
		"offset = %" PRIu64 "\nshift = %" PRIu64 "\n# EOF\n",
		1, rnc.device_uuid, rnc.reencrypt_direction,
		rnc.device_offset, rnc.device_shift);

	lseek(rnc.log_fd, 0, SEEK_SET);
	r = write(rnc.log_fd, buf, sizeof(buf));
	if (r < 0 || r != sizeof(buf))
		return -EIO;

	return 0;
}

static int parse_line_log(const char *line)
{
	uint64_t u64;
	int i;
	char s[64];

	/* comment */
	if (*line == '#')
		return 0;

	if (sscanf(line, "version = %d", &i) == 1) {
		if (i != 1) {
			log_dbg("Log: Unexpected version = %i", i);
			return -EINVAL;
		}
	} else if (sscanf(line, "UUID = %40s", s) == 1) {
		if (!rnc.device_uuid || strcmp(rnc.device_uuid, s)) {
			log_dbg("Log: Unexpected UUID %s", s);
			return -EINVAL;
		}
	} else if (sscanf(line, "direction = %d", &i) == 1) {
		log_dbg("Log: direction = %i", i);
		rnc.reencrypt_direction = i;
	} else if (sscanf(line, "offset = %" PRIu64, &u64) == 1) {
		log_dbg("Log: offset = %" PRIu64, u64);
		rnc.device_offset = u64;
	} else if (sscanf(line, "shift = %" PRIu64, &u64) == 1) {
		log_dbg("Log: shift = %" PRIu64, u64);
		rnc.device_shift = u64;
	} else
		return -EINVAL;

	return 0;
}

static int parse_log(void)
{
	static char buf[512];
	char *start, *end;
	ssize_t s;

	s = read(rnc.log_fd, buf, sizeof(buf));
	if (s == -1)
		return -EIO;

	buf[511] = '\0';
	start = buf;
	do {
		end = strchr(start, '\n');
		if (end) {
			*end++ = '\0';
			if (parse_line_log(start)) {
				log_err("Wrong log format.\n");
				return -EINVAL;
			}
		}

		start = end;
	} while (start);

	return 0;
}

static int open_log(void)
{
	int flags;
	struct stat st;

	if(stat(rnc.log_file, &st) < 0) {
		log_dbg("Creating LUKS reencryption log file %s.", rnc.log_file);

		// FIXME: move that somewhere else
		rnc.reencrypt_direction = BACKWARD;

		flags = opt_directio ? O_RDWR|O_CREAT|O_DIRECT : O_RDWR|O_CREAT;
		rnc.log_fd = open(rnc.log_file, flags, S_IRUSR|S_IWUSR);
		if (rnc.log_fd == -1)
			return -EINVAL;
		if (write_log() < 0)
			return -EIO;
	} else {
		log_dbg("Log file %s exists, restarting.", rnc.log_file);
		flags = opt_directio ? O_RDWR|O_DIRECT : O_RDWR;
		rnc.log_fd = open(rnc.log_file, flags);
		if (rnc.log_fd == -1)
			return -EINVAL;
		rnc.in_progress = 1;
	}

	/* Be sure it is correct format */
	return parse_log();
}

static void close_log(void)
{
	log_dbg("Closing LUKS reencryption log file %s.", rnc.log_file);
	if (rnc.log_fd != -1)
		close(rnc.log_fd);
}

static int activate_luks_headers(void)
{
	struct crypt_device *cd = NULL, *cd_new = NULL;
	int r;

	log_dbg("Activating LUKS devices from headers.");

	if ((r = crypt_init(&cd, rnc.header_file_org)) ||
	    (r = crypt_load(cd, CRYPT_LUKS1, NULL)) ||
	    (r = crypt_set_data_device(cd, rnc.device)))
		goto out;

	if ((r = crypt_activate_by_passphrase(cd, rnc.header_file_org,
		CRYPT_ANY_SLOT, rnc.password, rnc.passwordLen,
		CRYPT_ACTIVATE_READONLY|CRYPT_ACTIVATE_PRIVATE)) < 0)
		goto out;

	if ((r = crypt_init(&cd_new, rnc.header_file_new)) ||
	    (r = crypt_load(cd_new, CRYPT_LUKS1, NULL)) ||
	    (r = crypt_set_data_device(cd_new, rnc.device)))
		goto out;

	if ((r = crypt_activate_by_passphrase(cd_new, rnc.header_file_new,
		CRYPT_ANY_SLOT, rnc.password, rnc.passwordLen,
		CRYPT_ACTIVATE_SHARED|CRYPT_ACTIVATE_PRIVATE)) < 0)
		goto out;
out:
	crypt_free(cd);
	crypt_free(cd_new);
	return r;
}

static int backup_luks_headers(void)
{
	struct crypt_device *cd = NULL, *cd_new = NULL;
	struct crypt_params_luks1 params = {0};
	char cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	int r;

	log_dbg("Creating LUKS header backup for device %s.", rnc.device);
	if ((r = crypt_init(&cd, rnc.device)) ||
	    (r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	crypt_set_confirm_callback(cd, NULL, NULL);
	if ((r = crypt_header_backup(cd, CRYPT_LUKS1, rnc.header_file_org)))
		goto out;

	if ((r = create_empty_header(rnc.header_file_new,
				     crypt_get_data_offset(cd) * 512)))
		goto out;

	params.hash = opt_hash ?: DEFAULT_LUKS1_HASH;
	params.data_alignment = crypt_get_data_offset(cd);
	params.data_device = rnc.device;

	if ((r = crypt_init(&cd_new, rnc.header_file_new)))
		goto out;

	if (opt_random)
		crypt_set_rng_type(cd_new, CRYPT_RNG_RANDOM);
	else if (opt_urandom)
		crypt_set_rng_type(cd_new, CRYPT_RNG_URANDOM);

	if (opt_iteration_time)
		crypt_set_iteration_time(cd_new, opt_iteration_time);

	if (opt_cipher) {
		r = crypt_parse_name_and_mode(opt_cipher, cipher, NULL, cipher_mode);
		if (r < 0) {
			log_err(_("No known cipher specification pattern detected.\n"));
			goto out;
		}
	}

	if ((r = crypt_format(cd_new, CRYPT_LUKS1,
			opt_cipher ? cipher : crypt_get_cipher(cd),
			opt_cipher ? cipher_mode : crypt_get_cipher_mode(cd),
			crypt_get_uuid(cd),
			NULL, crypt_get_volume_key_size(cd), &params)))
		goto out;

	if ((r = crypt_keyslot_add_by_volume_key(cd_new, rnc.keyslot,
				NULL, 0, rnc.password, rnc.passwordLen)) < 0)
		goto out;

out:
	crypt_free(cd);
	crypt_free(cd_new);
	return r;
}

static void remove_headers(void)
{
	struct crypt_device *cd = NULL;

	if (crypt_init(&cd, NULL))
		return;
	crypt_set_log_callback(cd, _quiet_log, NULL);
	(void)crypt_deactivate(cd, rnc.header_file_org);
	(void)crypt_deactivate(cd, rnc.header_file_new);
	crypt_free(cd);
}

static int restore_luks_header(const char *backup)
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_init(&cd, rnc.device);

	if (r == 0) {
		crypt_set_confirm_callback(cd, NULL, NULL);
		r = crypt_header_restore(cd, CRYPT_LUKS1, backup);
	}

	crypt_free(cd);
	return r;
}

void print_progress(uint64_t bytes, int final)
{
	uint64_t mbytes = bytes / 1024 / 1024;
	struct timeval now_time;
	double tdiff;

	gettimeofday(&now_time, NULL);
	if (!final && time_diff(rnc.end_time, now_time) < 0.5)
		return;

	rnc.end_time = now_time;

	if (opt_batch_mode)
		return;

	tdiff = time_diff(rnc.start_time, rnc.end_time);
	if (!tdiff)
		return;

	log_err("\33[2K\rProgress: %5.1f%%, time elapsed %3.1f seconds, %4"
		PRIu64 " MB written, speed %5.2f MB/s%s",
		(double)bytes / rnc.device_size * 100,
		time_diff(rnc.start_time, rnc.end_time),
		mbytes, (double)(mbytes) / tdiff,
		final ? "\n" :"");
}

static int copy_data_forward(int fd_old, int fd_new, size_t block_size, void *buf, uint64_t *bytes)
{
	ssize_t s1, s2;

	*bytes = rnc.device_offset;
	while (!quit && rnc.device_offset < rnc.device_size) {
		s1 = read(fd_old, buf, block_size);
		if (s1 < 0 || (s1 != block_size && (rnc.device_offset + s1) != rnc.device_size)) {
			log_err("Read error, expecting %d, got %d.\n", (int)block_size, (int)s1);
			return -EIO;
		}
		s2 = write(fd_new, buf, s1);
		if (s2 < 0) {
			log_err("Write error, expecting %d, got %d.\n", (int)block_size, (int)s2);
			return -EIO;
		}
		rnc.device_offset += s1;
		if (opt_write_log && write_log() < 0) {
			log_err("Log write error, some data are perhaps lost.\n");
			return -EIO;
		}

		*bytes += (uint64_t)s2;
		print_progress(*bytes, 0);
	}

	return quit ? -EAGAIN : 0;
}

static int copy_data_backward(int fd_old, int fd_new, size_t block_size, void *buf, uint64_t *bytes)
{
	ssize_t s1, s2, working_block;
	off64_t working_offset;

	*bytes = rnc.device_size - rnc.device_offset;
	while (!quit && rnc.device_offset) {
		if (rnc.device_offset < block_size) {
			working_offset = 0;
			working_block = rnc.device_offset;
		} else {
			working_offset = rnc.device_offset - block_size;
			working_block = block_size;
		}

		if (lseek64(fd_old, working_offset, SEEK_SET) < 0 ||
		    lseek64(fd_new, working_offset, SEEK_SET) < 0) {
			log_err("Cannot seek to device offset.\n");
			return -EIO;
		}

		s1 = read(fd_old, buf, working_block);
		if (s1 < 0 || (s1 != working_block)) {
			log_err("Read error, expecting %d, got %d.\n", (int)block_size, (int)s1);
			return -EIO;
		}
		s2 = write(fd_new, buf, working_block);
		if (s2 < 0) {
			log_err("Write error, expecting %d, got %d.\n", (int)block_size, (int)s2);
			return -EIO;
		}
		rnc.device_offset -= s1;
		if (opt_write_log && write_log() < 0) {
			log_err("Log write error, some data are perhaps lost.\n");
			return -EIO;
		}

		*bytes += (uint64_t)s2;
		print_progress(*bytes, 0);
	}

	return quit ? -EAGAIN : 0;
}

static int copy_data(void)
{
	size_t block_size = opt_bsize * 1024 * 1024;
	int fd_old = -1, fd_new = -1;
	int r = -EINVAL;
	void *buf = NULL;
	uint64_t bytes = 0;

	fd_old = open(rnc.crypt_path_org, O_RDONLY | (opt_directio ? O_DIRECT : 0));
	if (fd_old == -1)
		goto out;

	fd_new = open(rnc.crypt_path_new, O_WRONLY | (opt_directio ? O_DIRECT : 0));
	if (fd_new == -1)
		goto out;

	if (lseek(fd_old, rnc.device_offset, SEEK_SET) == -1)
		goto out;

	if (lseek(fd_new, rnc.device_offset, SEEK_SET) == -1)
		goto out;

	/* Check size */
	if (ioctl(fd_old, BLKGETSIZE64, &rnc.device_size) < 0)
		goto out;

	if (posix_memalign((void *)&buf, alignment(fd_new), block_size)) {
		r = -ENOMEM;
		goto out;
	}

	set_int_handler();
	// FIXME: all this should be in init
	if (!rnc.in_progress && rnc.reencrypt_direction == BACKWARD)
		rnc.device_offset = rnc.device_size;

	gettimeofday(&rnc.start_time, NULL);

	if (rnc.reencrypt_direction == FORWARD)
		r = copy_data_forward(fd_old, fd_new, block_size, buf, &bytes);
	else
		r = copy_data_backward(fd_old, fd_new, block_size, buf, &bytes);

	set_int_block(1);
	print_progress(bytes, 1);

	if (r < 0)
		log_err("ERROR during reencryption.\n");

	if (write_log() < 0)
		log_err("Log write error, ignored.\n");

out:
	if (fd_old != -1)
		close(fd_old);
	if (fd_new != -1)
		close(fd_new);
	free(buf);
	return r;
}

static int initialize_uuid(void)
{
	struct crypt_device *cd = NULL;
	int r;

	/* Try to load LUKS from device */
	if ((r = crypt_init(&cd, rnc.device)))
		return r;
	crypt_set_log_callback(cd, _quiet_log, NULL);
	r = crypt_load(cd, CRYPT_LUKS1, NULL);
	if (!r)
		rnc.device_uuid = strdup(crypt_get_uuid(cd));
	else
		/* Reencryption already in progress - magic header? */
		r = device_magic(CHECK_UNUSABLE);

	crypt_free(cd);
	return r;
}

static int initialize_passphrase(const char *device)
{
	struct crypt_device *cd = NULL;
	int r;

	if ((r = crypt_init(&cd, device)) ||
	    (r = crypt_load(cd, CRYPT_LUKS1, NULL)) ||
	    (r = crypt_set_data_device(cd, rnc.device)))
		goto out;

	if ((r = crypt_get_key(_("Enter LUKS passphrase: "),
			  &rnc.password, &rnc.passwordLen,
			  0, 0, opt_key_file,
			  0, 0, cd)) <0)
		goto out;

	if ((r = crypt_activate_by_passphrase(cd, NULL,
		CRYPT_ANY_SLOT, rnc.password, rnc.passwordLen, 0) < 0))
		goto out;

	if (r >= 0) {
		rnc.keyslot = r;
		r = 0;
	}
out:
	crypt_free(cd);
	return r;
}

static int initialize_context(const char *device)
{
	log_dbg("Initialising reencryption context.");

	rnc.log_fd =-1;

	if (!(rnc.device = strndup(device, PATH_MAX)))
		return -ENOMEM;
/*
	if (opt_new_file && !create_uuid()) {
		log_err("Cannot create fake header.\n");
		return -EINVAL;
	}
*/
	if (initialize_uuid()) {
		log_err("No header found on device.\n");
		return -EINVAL;
	}

	/* Prepare device names */
	if (snprintf(rnc.log_file, PATH_MAX,
		     "LUKS-%s.log", rnc.device_uuid) < 0)
		return -ENOMEM;
	if (snprintf(rnc.header_file_org, PATH_MAX,
		     "LUKS-%s.org", rnc.device_uuid) < 0)
		return -ENOMEM;
	if (snprintf(rnc.header_file_new, PATH_MAX,
		     "LUKS-%s.new", rnc.device_uuid) < 0)
		return -ENOMEM;

	/* Paths to encrypted devices */
	if (snprintf(rnc.crypt_path_org, PATH_MAX,
		     "%s/%s", crypt_get_dir(), rnc.header_file_org) < 0)
		return -ENOMEM;
	if (snprintf(rnc.crypt_path_new, PATH_MAX,
		     "%s/%s", crypt_get_dir(), rnc.header_file_new) < 0)
		return -ENOMEM;

	remove_headers();

	return open_log();
}

static void destroy_context(void)
{
	log_dbg("Destroying reencryption context.");

	close_log();
	remove_headers();

	if ((rnc.reencrypt_direction == FORWARD &&
	     rnc.device_offset == rnc.device_size) ||
	     rnc.device_offset == 0) {
		unlink(rnc.log_file);
		unlink(rnc.header_file_org);
		unlink(rnc.header_file_new);
	}

	crypt_safe_free(rnc.password);

	free(rnc.device);
	free(rnc.device_uuid);
}

int run_reencrypt(const char *device)
{
	int r = -EINVAL;
	if (initialize_context(device))
		goto out;

	log_dbg("Running reencryption.");

	if (!rnc.in_progress) {
		if ((r = initialize_passphrase(rnc.device)) ||
		    (r = backup_luks_headers()) ||
		    (r = device_magic(MAKE_UNUSABLE)))
			goto out;
	} else {
		if ((r = initialize_passphrase(rnc.header_file_org)))
			goto out;
	}

	if ((r = activate_luks_headers()))
		goto out;

	if ((r = copy_data()))
		goto out;

	r = restore_luks_header(rnc.header_file_new);
out:
	destroy_context();
	return r;
}

static __attribute__ ((noreturn)) void usage(poptContext popt_context,
					     int exitcode, const char *error,
					     const char *more)
{
	poptPrintUsage(popt_context, stderr, 0);
	if (error)
		log_err("%s: %s\n", more, error);
	poptFreeContext(popt_context);
	exit(exitcode);
}

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

static void _dbg_version_and_cmd(int argc, const char **argv)
{
	int i;

	log_std("# %s %s processing \"", PACKAGE_NAME, PACKAGE_VERSION);
	for (i = 0; i < argc; i++) {
		if (i)
			log_std(" ");
		log_std("%s", argv[i]);
	}
	log_std("\"\n");
}

int main(int argc, const char **argv)
{
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,                '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ "version",           '\0', POPT_ARG_NONE, &opt_version_mode,          0, N_("Print package version"), NULL },
		{ "verbose",           'v',  POPT_ARG_NONE, &opt_verbose,               0, N_("Shows more detailed error messages"), NULL },
		{ "debug",             '\0', POPT_ARG_NONE, &opt_debug,                 0, N_("Show debug messages"), NULL },
		{ "block-size",        'B',  POPT_ARG_INT, &opt_bsize,                  0, N_("Reencryption block size"), N_("MB") },
		{ "new-header",        'N',  POPT_ARG_INT, &opt_new,                    0, N_("Create new header, need size on the end of device"), N_("MB") },
		{ "new-crypt",         'f',  POPT_ARG_STRING, &opt_new_file,            0, N_("Log suffix for new reencryption file."), NULL },
		{ "cipher",            'c',  POPT_ARG_STRING, &opt_cipher,              0, N_("The cipher used to encrypt the disk (see /proc/crypto)"), NULL },
		{ "hash",              'h',  POPT_ARG_STRING, &opt_hash,                0, N_("The hash used to create the encryption key from the passphrase"), NULL },
		{ "key-file",          'd',  POPT_ARG_STRING, &opt_key_file,            0, N_("Read the key from a file."), NULL },
		{ "iter-time",         'i',  POPT_ARG_INT, &opt_iteration_time,         0, N_("PBKDF2 iteration time for LUKS (in ms)"), N_("msecs") },
		{ "batch-mode",        'q',  POPT_ARG_NONE, &opt_batch_mode,            0, N_("Do not ask for confirmation"), NULL },
		{ "use-random",        '\0', POPT_ARG_NONE, &opt_random,                0, N_("Use /dev/random for generating volume key."), NULL },
		{ "use-urandom",       '\0', POPT_ARG_NONE, &opt_urandom,               0, N_("Use /dev/urandom for generating volume key."), NULL },
		{ "use-directio",      '\0', POPT_ARG_NONE, &opt_directio,              0, N_("Use direct-io when accesing devices."), NULL },
		{ "write-log",         '\0', POPT_ARG_NONE, &opt_write_log,             0, N_("Update log file after every block."), NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;
	int r;

	crypt_set_log_callback(NULL, _log, NULL);
	log_err("WARNING: this is experimental code, it can completely break your data.\n");

	set_int_block(1);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext(PACKAGE, argc, argv, popt_options, 0);
	poptSetOtherOptionHelp(popt_context,
	                       N_("[OPTION...] <device>]"));

	while((r = poptGetNextOpt(popt_context)) > 0) {
		if (r < 0)
			break;
	}

	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));
	if (opt_version_mode) {
		log_std("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	}

	action_argv = poptGetArgs(popt_context);
	if(!action_argv)
		usage(popt_context, EXIT_FAILURE, _("Argument required."),
		      poptGetInvocationName(popt_context));

	if (opt_random && opt_urandom)
		usage(popt_context, EXIT_FAILURE, _("Only one of --use-[u]random options is allowed."),
		      poptGetInvocationName(popt_context));

	if (opt_new && !opt_new_file)
		usage(popt_context, EXIT_FAILURE, _("You have to use -f with -N."),
		      poptGetInvocationName(popt_context));

	if (opt_debug) {
		opt_verbose = 1;
		crypt_set_debug_level(-1);
		_dbg_version_and_cmd(argc, argv);
	}

	r = run_reencrypt(action_argv[0]);

	poptFreeContext(popt_context);

	/* Translate exit code to simple codes */
	switch (r) {
	case 0: 	r = EXIT_SUCCESS; break;
	case -EEXIST:
	case -EBUSY:	r = 5; break;
	case -ENOTBLK:
	case -ENODEV:	r = 4; break;
	case -ENOMEM:	r = 3; break;
	case -EPERM:	r = 2; break;
	case -EAGAIN: log_err(_("Interrupted by a signal.\n"));
	case -EINVAL:
	case -ENOENT:
	case -ENOSYS:
	default:	r = EXIT_FAILURE;
	}
	return r;
}
