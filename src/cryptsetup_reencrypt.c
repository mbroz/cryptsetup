/*
 * cryptsetup-reencrypt - crypt utility for offline re-encryption
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2014, Milan Broz All rights reserved.
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
#include <sys/ioctl.h>
#include <sys/time.h>
#include <linux/fs.h>
#include <arpa/inet.h>

#define PACKAGE_REENC "crypt_reencrypt"

#define NO_UUID "cafecafe-cafe-cafe-cafe-cafecafeeeee"
#define MAX_BCK_SECTORS 8192

static const char *opt_cipher = NULL;
static const char *opt_hash = NULL;
static const char *opt_key_file = NULL;
static long opt_keyfile_size = 0;
static long opt_keyfile_offset = 0;
static int opt_iteration_time = 1000;
static int opt_version_mode = 0;
static int opt_random = 0;
static int opt_urandom = 0;
static int opt_bsize = 4;
static int opt_directio = 0;
static int opt_fsync = 0;
static int opt_write_log = 0;
static int opt_tries = 3;
static int opt_key_slot = CRYPT_ANY_SLOT;
static int opt_key_size = 0;
static int opt_new = 0;
static int opt_keep_key = 0;

static const char *opt_reduce_size_str = NULL;
static uint64_t opt_reduce_size = 0;

static const char *opt_device_size_str = NULL;
static uint64_t opt_device_size = 0;

static const char **action_argv;

#define MAX_SLOT 8
struct reenc_ctx {
	char *device;
	char *device_uuid;
	uint64_t device_size; /* overrided by parameter */
	uint64_t device_size_real;
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
	char *log_buf;

	struct {
		char *password;
		size_t passwordLen;
	} p[MAX_SLOT];
	int keyslot;

	struct timeval start_time, end_time;
	uint64_t resume_bytes;
};

char MAGIC[]   = {'L','U','K','S', 0xba, 0xbe};
char NOMAGIC[] = {'L','U','K','S', 0xde, 0xad};
int  MAGIC_L = 6;

typedef enum {
	MAKE_UNUSABLE,
	MAKE_USABLE,
	CHECK_UNUSABLE,
	CHECK_OPEN,
} header_magic;

static void _quiet_log(int level, const char *msg, void *usrptr)
{
	if (!opt_debug)
		return;
	tool_log(level, msg, usrptr);
}

/* The difference in seconds between two times in "timeval" format. */
static double time_diff(struct timeval start, struct timeval end)
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

static size_t pagesize(void)
{
	long r = sysconf(_SC_PAGESIZE);
	return r < 0 ? 4096 : (size_t)r;
}

/* Depends on the first two fields of LUKS1 header format, magic and version */
static int device_check(struct reenc_ctx *rc, header_magic set_magic)
{
	char *buf = NULL;
	int r, devfd;
	ssize_t s;
	uint16_t version;
	size_t buf_size = pagesize();

	devfd = open(rc->device, O_RDWR | O_EXCL | O_DIRECT);
	if (devfd == -1) {
		if (errno == EBUSY) {
			log_err(_("Cannot exclusively open %s, device in use.\n"),
				rc->device);
			return -EBUSY;
		}
		log_err(_("Cannot open device %s\n"), rc->device);
		return -EINVAL;
	}

	if (set_magic == CHECK_OPEN) {
		r = 0;
		goto out;
	}

	if (posix_memalign((void *)&buf, alignment(devfd), buf_size)) {
		log_err(_("Allocation of aligned memory failed.\n"));
		r = -ENOMEM;
		goto out;
	}

	s = read(devfd, buf, buf_size);
	if (s < 0 || s != (ssize_t)buf_size) {
		log_err(_("Cannot read device %s.\n"), rc->device);
		r = -EIO;
		goto out;
	}

	/* Be sure that we do not process new version of header */
	memcpy((void*)&version, &buf[MAGIC_L], sizeof(uint16_t));
	version = ntohs(version);

	if (set_magic == MAKE_UNUSABLE && !memcmp(buf, MAGIC, MAGIC_L) &&
	    version == 1) {
		log_verbose(_("Marking LUKS device %s unusable.\n"), rc->device);
		memcpy(buf, NOMAGIC, MAGIC_L);
		r = 0;
	} else if (set_magic == MAKE_USABLE && !memcmp(buf, NOMAGIC, MAGIC_L) &&
		   version == 1) {
		log_verbose(_("Marking LUKS device %s usable.\n"), rc->device);
		memcpy(buf, MAGIC, MAGIC_L);
		r = 0;
	} else if (set_magic == CHECK_UNUSABLE && version == 1) {
		r = memcmp(buf, NOMAGIC, MAGIC_L) ? -EINVAL : 0;
		if (!r)
			rc->device_uuid = strndup(&buf[0xa8], 40);
		goto out;
	} else
		r = -EINVAL;

	if (!r) {
		if (lseek(devfd, 0, SEEK_SET) == -1)
			goto out;
		s = write(devfd, buf, buf_size);
		if (s < 0 || s != (ssize_t)buf_size) {
			log_err(_("Cannot write device %s.\n"), rc->device);
			r = -EIO;
		}
	} else
		log_dbg("LUKS signature check failed for %s.", rc->device);
out:
	if (buf)
		memset(buf, 0, buf_size);
	free(buf);
	close(devfd);
	return r;
}

static int create_empty_header(const char *new_file, const char *old_file,
			       uint64_t data_sector)
{
	struct stat st;
	ssize_t size = 0;
	int fd, r = 0;
	char *buf;

	/* Never create header > 4MiB */
	if (data_sector > MAX_BCK_SECTORS)
		data_sector = MAX_BCK_SECTORS;

	/* new header file of the same size as old backup */
	if (old_file) {
		if (stat(old_file, &st) == -1 ||
		    (st.st_mode & S_IFMT) != S_IFREG ||
		    (st.st_size > 16 * 1024 * 1024))
			return -EINVAL;
		size = st.st_size;
	}

	/*
	 * if requesting key size change, try to use offset
	 * here can be enough space to fit new key.
	 */
	if (opt_key_size)
		size = data_sector * SECTOR_SIZE;

	/* if reducing size, be sure we have enough space */
	if (opt_reduce_size)
		size += opt_reduce_size;

	log_dbg("Creating empty file %s of size %lu.", new_file, (unsigned long)size);

	if (!size || !(buf = malloc(size)))
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

static int write_log(struct reenc_ctx *rc)
{
	ssize_t r;

	memset(rc->log_buf, 0, SECTOR_SIZE);
	snprintf(rc->log_buf, SECTOR_SIZE, "# LUKS reencryption log, DO NOT EDIT OR DELETE.\n"
		"version = %d\nUUID = %s\ndirection = %d\n"
		"offset = %" PRIu64 "\nshift = %" PRIu64 "\n# EOF\n",
		1, rc->device_uuid, rc->reencrypt_direction,
		rc->device_offset, rc->device_shift);

	if (lseek(rc->log_fd, 0, SEEK_SET) == -1)
		return -EIO;

	r = write(rc->log_fd, rc->log_buf, SECTOR_SIZE);
	if (r < 0 || r != SECTOR_SIZE) {
		log_err(_("Cannot write reencryption log file.\n"));
		return -EIO;
	}

	return 0;
}

static int parse_line_log(struct reenc_ctx *rc, const char *line)
{
	uint64_t u64;
	int i;
	char s[64];

	/* whole line is comment */
	if (*line == '#')
		return 0;

	if (sscanf(line, "version = %d", &i) == 1) {
		if (i != 1) {
			log_dbg("Log: Unexpected version = %i", i);
			return -EINVAL;
		}
	} else if (sscanf(line, "UUID = %40s", s) == 1) {
		if (!rc->device_uuid || strcmp(rc->device_uuid, s)) {
			log_dbg("Log: Unexpected UUID %s", s);
			return -EINVAL;
		}
	} else if (sscanf(line, "direction = %d", &i) == 1) {
		log_dbg("Log: direction = %i", i);
		rc->reencrypt_direction = i;
	} else if (sscanf(line, "offset = %" PRIu64, &u64) == 1) {
		log_dbg("Log: offset = %" PRIu64, u64);
		rc->device_offset = u64;
	} else if (sscanf(line, "shift = %" PRIu64, &u64) == 1) {
		log_dbg("Log: shift = %" PRIu64, u64);
		rc->device_shift = u64;
	} else
		return -EINVAL;

	return 0;
}

static int parse_log(struct reenc_ctx *rc)
{
	char *start, *end;
	ssize_t s;

	s = read(rc->log_fd, rc->log_buf, SECTOR_SIZE);
	if (s == -1) {
		log_err(_("Cannot read reencryption log file.\n"));
		return -EIO;
	}

	rc->log_buf[SECTOR_SIZE - 1] = '\0';
	start = rc->log_buf;
	do {
		end = strchr(start, '\n');
		if (end) {
			*end++ = '\0';
			if (parse_line_log(rc, start)) {
				log_err("Wrong log format.\n");
				return -EINVAL;
			}
		}

		start = end;
	} while (start);

	return 0;
}

static void close_log(struct reenc_ctx *rc)
{
	log_dbg("Closing LUKS reencryption log file %s.", rc->log_file);
	if (rc->log_fd != -1)
		close(rc->log_fd);
	free(rc->log_buf);
	rc->log_buf = NULL;
}

static int open_log(struct reenc_ctx *rc)
{
	int flags = opt_directio ? O_DIRECT : 0;

	rc->log_fd = open(rc->log_file, O_RDWR|O_EXCL|O_CREAT|flags, S_IRUSR|S_IWUSR);
	if (rc->log_fd != -1) {
		log_dbg("Created LUKS reencryption log file %s.", rc->log_file);
	} else if (errno == EEXIST) {
		log_std(_("Log file %s exists, resuming reencryption.\n"), rc->log_file);
		rc->log_fd = open(rc->log_file, O_RDWR|flags);
		rc->in_progress = 1;
	}

	if (rc->log_fd == -1)
		return -EINVAL;

	if (posix_memalign((void *)&rc->log_buf, alignment(rc->log_fd), SECTOR_SIZE)) {
		log_err(_("Allocation of aligned memory failed.\n"));
		close_log(rc);
		return -ENOMEM;
	}

	if (!rc->in_progress && write_log(rc) < 0) {
		close_log(rc);
		return -EIO;
	}

	/* Be sure it is correct format */
	return parse_log(rc);
}

static int activate_luks_headers(struct reenc_ctx *rc)
{
	struct crypt_device *cd = NULL, *cd_new = NULL;
	int r;

	log_dbg("Activating LUKS devices from headers.");

	if ((r = crypt_init(&cd, rc->header_file_org)) ||
	    (r = crypt_load(cd, CRYPT_LUKS1, NULL)) ||
	    (r = crypt_set_data_device(cd, rc->device)))
		goto out;

	log_verbose(_("Activating temporary device using old LUKS header.\n"));
	if ((r = crypt_activate_by_passphrase(cd, rc->header_file_org,
		opt_key_slot, rc->p[rc->keyslot].password, rc->p[rc->keyslot].passwordLen,
		CRYPT_ACTIVATE_READONLY|CRYPT_ACTIVATE_PRIVATE)) < 0)
		goto out;

	if ((r = crypt_init(&cd_new, rc->header_file_new)) ||
	    (r = crypt_load(cd_new, CRYPT_LUKS1, NULL)) ||
	    (r = crypt_set_data_device(cd_new, rc->device)))
		goto out;

	log_verbose(_("Activating temporary device using new LUKS header.\n"));
	if ((r = crypt_activate_by_passphrase(cd_new, rc->header_file_new,
		opt_key_slot, rc->p[rc->keyslot].password, rc->p[rc->keyslot].passwordLen,
		CRYPT_ACTIVATE_SHARED|CRYPT_ACTIVATE_PRIVATE)) < 0)
		goto out;
	r = 0;
out:
	crypt_free(cd);
	crypt_free(cd_new);
	if (r < 0)
		log_err(_("Activation of temporary devices failed.\n"));
	return r;
}

static int create_new_header(struct reenc_ctx *rc, const char *cipher,
			     const char *cipher_mode, const char *uuid,
			     const char *key, int key_size,
			     struct crypt_params_luks1 *params)
{
	struct crypt_device *cd_new = NULL;
	int i, r;

	if ((r = crypt_init(&cd_new, rc->header_file_new)))
		goto out;

	if (opt_random)
		crypt_set_rng_type(cd_new, CRYPT_RNG_RANDOM);
	else if (opt_urandom)
		crypt_set_rng_type(cd_new, CRYPT_RNG_URANDOM);

	if (opt_iteration_time)
		crypt_set_iteration_time(cd_new, opt_iteration_time);

	if ((r = crypt_format(cd_new, CRYPT_LUKS1, cipher, cipher_mode,
			      uuid, key, key_size, params)))
		goto out;
	log_verbose(_("New LUKS header for device %s created.\n"), rc->device);

	for (i = 0; i < MAX_SLOT; i++) {
		if (!rc->p[i].password)
			continue;
		if ((r = crypt_keyslot_add_by_volume_key(cd_new, i,
			NULL, 0, rc->p[i].password, rc->p[i].passwordLen)) < 0)
			goto out;
		log_verbose(_("Activated keyslot %i.\n"), r);
		r = 0;
	}
out:
	crypt_free(cd_new);
	return r;
}

static int backup_luks_headers(struct reenc_ctx *rc)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_luks1 params = {0};
	char cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	char *old_key = NULL;
	size_t old_key_size;
	int r;

	log_dbg("Creating LUKS header backup for device %s.", rc->device);

	if ((r = crypt_init(&cd, rc->device)) ||
	    (r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	crypt_set_confirm_callback(cd, NULL, NULL);
	if ((r = crypt_header_backup(cd, CRYPT_LUKS1, rc->header_file_org)))
		goto out;
	log_verbose(_("LUKS header backup of device %s created.\n"), rc->device);

	if ((r = create_empty_header(rc->header_file_new, rc->header_file_org,
		crypt_get_data_offset(cd))))
		goto out;

	params.hash = opt_hash ?: DEFAULT_LUKS1_HASH;
	params.data_alignment = crypt_get_data_offset(cd);
	params.data_alignment += ROUND_SECTOR(opt_reduce_size);
	params.data_device = rc->device;

	if (opt_cipher) {
		r = crypt_parse_name_and_mode(opt_cipher, cipher, NULL, cipher_mode);
		if (r < 0) {
			log_err(_("No known cipher specification pattern detected.\n"));
			goto out;
		}
	}

	if (opt_keep_key) {
		log_dbg("Keeping key from old header.");
		old_key_size  = crypt_get_volume_key_size(cd);
		old_key = crypt_safe_alloc(old_key_size);
		if (!old_key) {
			r = -ENOMEM;
			goto out;
		}
		r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, old_key, &old_key_size,
			rc->p[rc->keyslot].password, rc->p[rc->keyslot].passwordLen);
		if (r < 0)
			goto out;
	}

	r = create_new_header(rc,
		opt_cipher ? cipher : crypt_get_cipher(cd),
		opt_cipher ? cipher_mode : crypt_get_cipher_mode(cd),
		crypt_get_uuid(cd),
		old_key,
		opt_key_size ? opt_key_size / 8 : crypt_get_volume_key_size(cd),
		&params);
out:
	crypt_free(cd);
	crypt_safe_free(old_key);
	if (r)
		log_err(_("Creation of LUKS backup headers failed.\n"));
	return r;
}

/* Create fake header for original device */
static int backup_fake_header(struct reenc_ctx *rc)
{
	struct crypt_device *cd_new = NULL;
	struct crypt_params_luks1 params = {0};
	char cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];

	int r;

	log_dbg("Creating fake (cipher_null) header for original device.");

	if (!opt_key_size)
		opt_key_size = DEFAULT_LUKS1_KEYBITS;

	if (opt_cipher) {
		r = crypt_parse_name_and_mode(opt_cipher, cipher, NULL, cipher_mode);
		if (r < 0) {
			log_err(_("No known cipher specification pattern detected.\n"));
			goto out;
		}
	}

	r = create_empty_header(rc->header_file_org, NULL, 0);
	if (r < 0)
		return r;

	params.hash = opt_hash ?: DEFAULT_LUKS1_HASH;
	params.data_alignment = 0;
	params.data_device = rc->device;

	r = crypt_init(&cd_new, rc->header_file_org);
	if (r < 0)
		return r;

	r = crypt_format(cd_new, CRYPT_LUKS1, "cipher_null", "ecb",
			 NO_UUID, NULL, opt_key_size / 8, &params);
	if (r < 0)
		goto out;

	r = crypt_keyslot_add_by_volume_key(cd_new, rc->keyslot, NULL, 0,
			rc->p[rc->keyslot].password, rc->p[rc->keyslot].passwordLen);
	if (r < 0)
		goto out;

	r = create_empty_header(rc->header_file_new, rc->header_file_org, 0);
	if (r < 0)
		goto out;

	params.data_alignment = ROUND_SECTOR(opt_reduce_size);
	r = create_new_header(rc,
		opt_cipher ? cipher : DEFAULT_LUKS1_CIPHER,
		opt_cipher ? cipher_mode : DEFAULT_LUKS1_MODE,
		NULL, NULL,
		(opt_key_size ? opt_key_size : DEFAULT_LUKS1_KEYBITS) / 8,
		&params);
out:
	crypt_free(cd_new);
	return r;
}

static void remove_headers(struct reenc_ctx *rc)
{
	struct crypt_device *cd = NULL;

	log_dbg("Removing headers.");

	if (crypt_init(&cd, NULL))
		return;
	crypt_set_log_callback(cd, _quiet_log, NULL);
	if (*rc->header_file_org)
		(void)crypt_deactivate(cd, rc->header_file_org);
	if (*rc->header_file_new)
		(void)crypt_deactivate(cd, rc->header_file_new);
	crypt_free(cd);
}

static int restore_luks_header(struct reenc_ctx *rc)
{
	struct crypt_device *cd = NULL;
	int r;

	log_dbg("Restoring header for %s from %s.", rc->device, rc->header_file_new);

	r = crypt_init(&cd, rc->device);
	if (r == 0) {
		crypt_set_confirm_callback(cd, NULL, NULL);
		r = crypt_header_restore(cd, CRYPT_LUKS1, rc->header_file_new);
	}

	crypt_free(cd);
	if (r)
		log_err(_("Cannot restore LUKS header on device %s.\n"), rc->device);
	else
		log_verbose(_("LUKS header on device %s restored.\n"), rc->device);
	return r;
}

static void print_progress(struct reenc_ctx *rc, uint64_t bytes, int final)
{
	unsigned long long mbytes, eta;
	struct timeval now_time;
	double tdiff, mib;

	gettimeofday(&now_time, NULL);
	if (!final && time_diff(rc->end_time, now_time) < 0.5)
		return;

	rc->end_time = now_time;

	if (opt_batch_mode)
		return;

	tdiff = time_diff(rc->start_time, rc->end_time);
	if (!tdiff)
		return;

	mbytes = (bytes - rc->resume_bytes) / 1024 / 1024;
	mib = (double)(mbytes) / tdiff;
	if (!mib)
		return;

	/* FIXME: calculate this from last minute only and remaining space */
	eta = (unsigned long long)(rc->device_size / 1024 / 1024 / mib - tdiff);

	/* vt100 code clear line */
	log_err("\33[2K\r");
	log_err(_("Progress: %5.1f%%, ETA %02llu:%02llu, "
		"%4llu MiB written, speed %5.1f MiB/s%s"),
		(double)bytes / rc->device_size * 100,
		eta / 60, eta % 60, mbytes, mib,
		final ? "\n" :"");
}

static int copy_data_forward(struct reenc_ctx *rc, int fd_old, int fd_new,
			     size_t block_size, void *buf, uint64_t *bytes)
{
	ssize_t s1, s2;

	log_dbg("Reencrypting in forward direction.");

	if (lseek64(fd_old, rc->device_offset, SEEK_SET) < 0 ||
	    lseek64(fd_new, rc->device_offset, SEEK_SET) < 0) {
		log_err(_("Cannot seek to device offset.\n"));
		return -EIO;
	}

	rc->resume_bytes = *bytes = rc->device_offset;

	if (write_log(rc) < 0)
		return -EIO;

	while (!quit && rc->device_offset < rc->device_size) {
		s1 = read(fd_old, buf, block_size);
		if (s1 < 0 || ((size_t)s1 != block_size &&
		    (rc->device_offset + s1) != rc->device_size)) {
			log_dbg("Read error, expecting %d, got %d.",
				(int)block_size, (int)s1);
			return -EIO;
		}

		/* If device_size is forced, never write more than limit */
		if ((s1 + rc->device_offset) > rc->device_size)
			s1 = rc->device_size - rc->device_offset;

		s2 = write(fd_new, buf, s1);
		if (s2 < 0) {
			log_dbg("Write error, expecting %d, got %d.",
				(int)block_size, (int)s2);
			return -EIO;
		}

		rc->device_offset += s1;
		if (opt_write_log && write_log(rc) < 0)
			return -EIO;

		if (opt_fsync && fsync(fd_new) < 0) {
			log_dbg("Write error, fsync.");
			return -EIO;
		}

		*bytes += (uint64_t)s2;
		print_progress(rc, *bytes, 0);
	}

	return quit ? -EAGAIN : 0;
}

static int copy_data_backward(struct reenc_ctx *rc, int fd_old, int fd_new,
			      size_t block_size, void *buf, uint64_t *bytes)
{
	ssize_t s1, s2, working_block;
	off64_t working_offset;

	log_dbg("Reencrypting in backward direction.");

	if (!rc->in_progress) {
		rc->device_offset = rc->device_size;
		rc->resume_bytes = 0;
		*bytes = 0;
	} else {
		rc->resume_bytes = rc->device_size - rc->device_offset;
		*bytes = rc->resume_bytes;
	}

	if (write_log(rc) < 0)
		return -EIO;

	while (!quit && rc->device_offset) {
		if (rc->device_offset < block_size) {
			working_offset = 0;
			working_block = rc->device_offset;
		} else {
			working_offset = rc->device_offset - block_size;
			working_block = block_size;
		}

		if (lseek64(fd_old, working_offset, SEEK_SET) < 0 ||
		    lseek64(fd_new, working_offset, SEEK_SET) < 0) {
			log_err(_("Cannot seek to device offset.\n"));
			return -EIO;
		}

		s1 = read(fd_old, buf, working_block);
		if (s1 < 0 || (s1 != working_block)) {
			log_dbg("Read error, expecting %d, got %d.",
				(int)block_size, (int)s1);
			return -EIO;
		}

		s2 = write(fd_new, buf, working_block);
		if (s2 < 0) {
			log_dbg("Write error, expecting %d, got %d.",
				(int)block_size, (int)s2);
			return -EIO;
		}

		rc->device_offset -= s1;
		if (opt_write_log && write_log(rc) < 0)
			return -EIO;

		if (opt_fsync && fsync(fd_new) < 0) {
			log_dbg("Write error, fsync.");
			return -EIO;
		}

		*bytes += (uint64_t)s2;
		print_progress(rc, *bytes, 0);
	}

	return quit ? -EAGAIN : 0;
}

static int copy_data(struct reenc_ctx *rc)
{
	size_t block_size = opt_bsize * 1024 * 1024;
	int fd_old = -1, fd_new = -1;
	int r = -EINVAL;
	void *buf = NULL;
	uint64_t bytes = 0;

	log_dbg("Data copy preparation.");

	fd_old = open(rc->crypt_path_org, O_RDONLY | (opt_directio ? O_DIRECT : 0));
	if (fd_old == -1) {
		log_err(_("Cannot open temporary LUKS header file.\n"));
		goto out;
	}

	fd_new = open(rc->crypt_path_new, O_WRONLY | (opt_directio ? O_DIRECT : 0));
	if (fd_new == -1) {
		log_err(_("Cannot open temporary LUKS header file.\n"));
		goto out;
	}

	/* Check size */
	if (ioctl(fd_new, BLKGETSIZE64, &rc->device_size_real) < 0) {
		log_err(_("Cannot get device size.\n"));
		goto out;
	}

	rc->device_size = opt_device_size ?: rc->device_size_real;

	if (posix_memalign((void *)&buf, alignment(fd_new), block_size)) {
		log_err(_("Allocation of aligned memory failed.\n"));
		r = -ENOMEM;
		goto out;
	}

	set_int_handler(0);
	gettimeofday(&rc->start_time, NULL);

	if (rc->reencrypt_direction == FORWARD)
		r = copy_data_forward(rc, fd_old, fd_new, block_size, buf, &bytes);
	else
		r = copy_data_backward(rc, fd_old, fd_new, block_size, buf, &bytes);

	set_int_block(1);
	print_progress(rc, bytes, 1);

	if (r == -EAGAIN)
		 log_err(_("Interrupted by a signal.\n"));
	else if (r < 0)
		log_err(_("IO error during reencryption.\n"));

	(void)write_log(rc);
out:
	if (fd_old != -1)
		close(fd_old);
	if (fd_new != -1)
		close(fd_new);
	free(buf);
	return r;
}

static int initialize_uuid(struct reenc_ctx *rc)
{
	struct crypt_device *cd = NULL;
	int r;

	log_dbg("Initialising UUID.");

	if (opt_new) {
		rc->device_uuid = strdup(NO_UUID);
		return 0;
	}

	/* Try to load LUKS from device */
	if ((r = crypt_init(&cd, rc->device)))
		return r;
	crypt_set_log_callback(cd, _quiet_log, NULL);
	r = crypt_load(cd, CRYPT_LUKS1, NULL);
	if (!r)
		rc->device_uuid = strdup(crypt_get_uuid(cd));
	else
		/* Reencryption already in progress - magic header? */
		r = device_check(rc, CHECK_UNUSABLE);

	crypt_free(cd);
	return r;
}

static int init_passphrase1(struct reenc_ctx *rc, struct crypt_device *cd,
			    const char *msg, int slot_to_check, int check)
{
	char *password;
	int r = -EINVAL, retry_count;
	size_t passwordLen;

	retry_count = opt_tries ?: 1;
	while (retry_count--) {
		set_int_handler(0);
		r = crypt_get_key(msg, &password, &passwordLen,
			0, 0, NULL /*opt_key_file*/,
			0, 0, cd);
		if (r < 0)
			return r;
		if (quit)
			return -EAGAIN;

		/* library uses sigint internally, until it is fixed...*/
		set_int_block(1);
		if (check)
			r = crypt_activate_by_passphrase(cd, NULL, slot_to_check,
				password, passwordLen, 0);
		else
			r = (slot_to_check == CRYPT_ANY_SLOT) ? 0 : slot_to_check;

		if (r < 0) {
			crypt_safe_free(password);
			password = NULL;
			passwordLen = 0;
		}
		if (r < 0 && r != -EPERM)
			return r;
		if (r >= 0) {
			rc->keyslot = r;
			rc->p[r].password = password;
			rc->p[r].passwordLen = passwordLen;
			break;
		}
		log_err(_("No key available with this passphrase.\n"));
	}

	password = NULL;
	passwordLen = 0;

	return r;
}

static int init_keyfile(struct reenc_ctx *rc, struct crypt_device *cd, int slot_check)
{
	char *password;
	int r;
	size_t passwordLen;

	r = crypt_get_key(NULL, &password, &passwordLen, opt_keyfile_offset,
			  opt_keyfile_size, opt_key_file, 0, 0, cd);
	if (r < 0)
		return r;

	r = crypt_activate_by_passphrase(cd, NULL, slot_check, password,
					 passwordLen, 0);

	/*
	 * Allow keyslot only if it is last slot or if user explicitly
	 * specify which slot to use (IOW others will be disabled).
	 */
	if (r >= 0 && opt_key_slot == CRYPT_ANY_SLOT &&
	    crypt_keyslot_status(cd, r) != CRYPT_SLOT_ACTIVE_LAST) {
		log_err(_("Key file can be used only with --key-slot or with "
			  "exactly one key slot active.\n"));
		r = -EINVAL;
	}

	if (r < 0) {
		crypt_safe_free(password);
		if (r == -EPERM)
			log_err(_("No key available with this passphrase.\n"));
	} else {
		rc->keyslot = r;
		rc->p[r].password = password;
		rc->p[r].passwordLen = passwordLen;
	}

	password = NULL;
	passwordLen = 0;

	return r;
}

static int initialize_passphrase(struct reenc_ctx *rc, const char *device)
{
	struct crypt_device *cd = NULL;
	crypt_keyslot_info ki;
	char msg[256];
	int i, r;

	log_dbg("Passhrases initialization.");

	if (opt_new && !rc->in_progress) {
		r = init_passphrase1(rc, cd, _("Enter new passphrase: "), opt_key_slot, 0);
		return r > 0 ? 0 : r;
	}

	if ((r = crypt_init(&cd, device)) ||
	    (r = crypt_load(cd, CRYPT_LUKS1, NULL)) ||
	    (r = crypt_set_data_device(cd, rc->device))) {
		crypt_free(cd);
		return r;
	}

	if (opt_key_slot != CRYPT_ANY_SLOT)
		snprintf(msg, sizeof(msg),
			 _("Enter passphrase for key slot %u: "), opt_key_slot);
	else
		snprintf(msg, sizeof(msg), _("Enter any existing passphrase: "));

	if (opt_key_file) {
		r = init_keyfile(rc, cd, opt_key_slot);
	} else if (rc->in_progress || opt_key_slot != CRYPT_ANY_SLOT) {
		r = init_passphrase1(rc, cd, msg, opt_key_slot, 1);
	} else for (i = 0; i < MAX_SLOT; i++) {
		ki = crypt_keyslot_status(cd, i);
		if (ki != CRYPT_SLOT_ACTIVE && ki != CRYPT_SLOT_ACTIVE_LAST)
			continue;

		snprintf(msg, sizeof(msg), _("Enter passphrase for key slot %u: "), i);
		r = init_passphrase1(rc, cd, msg, i, 1);
		if (r < 0)
			break;
	}

	crypt_free(cd);
	return r > 0 ? 0 : r;
}

static int initialize_context(struct reenc_ctx *rc, const char *device)
{
	log_dbg("Initialising reencryption context.");

	rc->log_fd =-1;

	if (!(rc->device = strndup(device, PATH_MAX)))
		return -ENOMEM;

	if (device_check(rc, CHECK_OPEN) < 0)
		return -EINVAL;

	if (initialize_uuid(rc)) {
		log_err(_("Device %s is not a valid LUKS device.\n"), device);
		return -EINVAL;
	}

	/* Prepare device names */
	if (snprintf(rc->log_file, PATH_MAX,
		     "LUKS-%s.log", rc->device_uuid) < 0)
		return -ENOMEM;
	if (snprintf(rc->header_file_org, PATH_MAX,
		     "LUKS-%s.org", rc->device_uuid) < 0)
		return -ENOMEM;
	if (snprintf(rc->header_file_new, PATH_MAX,
		     "LUKS-%s.new", rc->device_uuid) < 0)
		return -ENOMEM;

	/* Paths to encrypted devices */
	if (snprintf(rc->crypt_path_org, PATH_MAX,
		     "%s/%s", crypt_get_dir(), rc->header_file_org) < 0)
		return -ENOMEM;
	if (snprintf(rc->crypt_path_new, PATH_MAX,
		     "%s/%s", crypt_get_dir(), rc->header_file_new) < 0)
		return -ENOMEM;

	remove_headers(rc);

	if (open_log(rc) < 0) {
		log_err(_("Cannot open reencryption log file.\n"));
		return -EINVAL;
	}

	if (!rc->in_progress) {
		if (!opt_reduce_size)
			rc->reencrypt_direction = FORWARD;
		else {
			rc->reencrypt_direction = BACKWARD;
			rc->device_offset = (uint64_t)~0;
		}
	}

	return 0;
}

static void destroy_context(struct reenc_ctx *rc)
{
	int i;

	log_dbg("Destroying reencryption context.");

	close_log(rc);
	remove_headers(rc);

	if ((rc->reencrypt_direction == FORWARD &&
	     rc->device_offset == rc->device_size) ||
	    (rc->reencrypt_direction == BACKWARD &&
	     (rc->device_offset == 0 || rc->device_offset == (uint64_t)~0))) {
		unlink(rc->log_file);
		unlink(rc->header_file_org);
		unlink(rc->header_file_new);
	}

	for (i = 0; i < MAX_SLOT; i++)
		crypt_safe_free(rc->p[i].password);

	free(rc->device);
	free(rc->device_uuid);
}

static int run_reencrypt(const char *device)
{
	int r = -EINVAL;
	static struct reenc_ctx rc = {};

	if (initialize_context(&rc, device))
		goto out;

	log_dbg("Running reencryption.");

	if (!rc.in_progress) {
		if (opt_new) {
			if ((r = initialize_passphrase(&rc, rc.device)) ||
			    (r = backup_fake_header(&rc)))
			goto out;
		} else if ((r = initialize_passphrase(&rc, rc.device)) ||
			   (r = backup_luks_headers(&rc)) ||
			   (r = device_check(&rc, MAKE_UNUSABLE)))
			goto out;
	} else {
		if ((r = initialize_passphrase(&rc, rc.header_file_new)))
			goto out;
	}

	if (!opt_keep_key) {
		log_dbg("Running data area reencryption.");
		if ((r = activate_luks_headers(&rc)))
			goto out;

		if ((r = copy_data(&rc)))
			goto out;
	} else
		log_dbg("Keeping existing key, skipping data area reencryption.");

	r = restore_luks_header(&rc);
out:
	destroy_context(&rc);
	return r;
}

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	if (key->shortName == '?') {
		log_std("%s %s\n", PACKAGE_REENC, PACKAGE_VERSION);
		poptPrintHelp(popt_context, stdout, 0);
		exit(EXIT_SUCCESS);
	} else
		usage(popt_context, EXIT_SUCCESS, NULL, NULL);
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
		{ "block-size",        'B',  POPT_ARG_INT, &opt_bsize,                  0, N_("Reencryption block size"), N_("MiB") },
		{ "cipher",            'c',  POPT_ARG_STRING, &opt_cipher,              0, N_("The cipher used to encrypt the disk (see /proc/crypto)"), NULL },
		{ "key-size",          's',  POPT_ARG_INT, &opt_key_size,               0, N_("The size of the encryption key"), N_("BITS") },
		{ "hash",              'h',  POPT_ARG_STRING, &opt_hash,                0, N_("The hash used to create the encryption key from the passphrase"), NULL },
		{ "keep-key",          '\0', POPT_ARG_NONE, &opt_keep_key,              0, N_("Do not change key, no data area reencryption."), NULL },
		{ "key-file",          'd',  POPT_ARG_STRING, &opt_key_file,            0, N_("Read the key from a file."), NULL },
		{ "iter-time",         'i',  POPT_ARG_INT, &opt_iteration_time,         0, N_("PBKDF2 iteration time for LUKS (in ms)"), N_("msecs") },
		{ "batch-mode",        'q',  POPT_ARG_NONE, &opt_batch_mode,            0, N_("Do not ask for confirmation"), NULL },
		{ "tries",             'T',  POPT_ARG_INT, &opt_tries,                  0, N_("How often the input of the passphrase can be retried"), NULL },
		{ "use-random",        '\0', POPT_ARG_NONE, &opt_random,                0, N_("Use /dev/random for generating volume key."), NULL },
		{ "use-urandom",       '\0', POPT_ARG_NONE, &opt_urandom,               0, N_("Use /dev/urandom for generating volume key."), NULL },
		{ "use-directio",      '\0', POPT_ARG_NONE, &opt_directio,              0, N_("Use direct-io when accessing devices."), NULL },
		{ "use-fsync",         '\0', POPT_ARG_NONE, &opt_fsync,                 0, N_("Use fsync after each block."), NULL },
		{ "write-log",         '\0', POPT_ARG_NONE, &opt_write_log,             0, N_("Update log file after every block."), NULL },
		{ "key-slot",          'S',  POPT_ARG_INT, &opt_key_slot,               0, N_("Use only this slot (others will be disabled)."), NULL },
		{ "keyfile-offset",   '\0',  POPT_ARG_LONG, &opt_keyfile_offset,        0, N_("Number of bytes to skip in keyfile"), N_("bytes") },
		{ "keyfile-size",      'l',  POPT_ARG_LONG, &opt_keyfile_size,          0, N_("Limits the read from keyfile"), N_("bytes") },
		{ "reduce-device-size",'\0', POPT_ARG_STRING, &opt_reduce_size_str,     0, N_("Reduce data device size (move data offset). DANGEROUS!"), N_("bytes") },
		{ "device-size",       '\0', POPT_ARG_STRING, &opt_device_size_str,     0, N_("Use only specified device size (ignore rest of device). DANGEROUS!"), N_("bytes") },
		{ "new",               'N',  POPT_ARG_NONE,&opt_new,                    0, N_("Create new header on not encrypted device."), NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;
	int r;

	crypt_set_log_callback(NULL, tool_log, NULL);

	set_int_block(1);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext(PACKAGE, argc, argv, popt_options, 0);
	poptSetOtherOptionHelp(popt_context,
	                       _("[OPTION...] <device>"));

	while((r = poptGetNextOpt(popt_context)) > 0) ;
	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));

	if (opt_version_mode) {
		log_std("%s %s\n", PACKAGE_REENC, PACKAGE_VERSION);
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	}

	if (!opt_batch_mode) {
		log_std(_("WARNING: this is experimental code, it can completely break your data.\n"));
		log_verbose(_("Reencryption will change: volume key%s%s%s%s.\n"),
			opt_hash   ? _(", set hash to ")  : "", opt_hash   ?: "",
			opt_cipher ? _(", set cipher to "): "", opt_cipher ?: "");
	}

	action_argv = poptGetArgs(popt_context);
	if(!action_argv)
		usage(popt_context, EXIT_FAILURE, _("Argument required."),
		      poptGetInvocationName(popt_context));

	if (opt_random && opt_urandom)
		usage(popt_context, EXIT_FAILURE, _("Only one of --use-[u]random options is allowed."),
		      poptGetInvocationName(popt_context));

	if (opt_bsize < 0 || opt_key_size < 0 || opt_iteration_time < 0 ||
	    opt_tries < 0 || opt_keyfile_offset < 0 || opt_key_size < 0) {
		usage(popt_context, EXIT_FAILURE,
		      _("Negative number for option not permitted."),
		      poptGetInvocationName(popt_context));
	}

	if (opt_bsize < 1 || opt_bsize > 64)
		usage(popt_context, EXIT_FAILURE,
		      _("Only values between 1 MiB and 64 MiB allowed for reencryption block size."),
		      poptGetInvocationName(popt_context));

	if (opt_key_size % 8)
		usage(popt_context, EXIT_FAILURE,
		      _("Key size must be a multiple of 8 bits"),
		      poptGetInvocationName(popt_context));

	if (opt_key_slot != CRYPT_ANY_SLOT &&
	    (opt_key_slot < 0 || opt_key_slot >= crypt_keyslot_max(CRYPT_LUKS1)))
		usage(popt_context, EXIT_FAILURE, _("Key slot is invalid."),
		      poptGetInvocationName(popt_context));

	if (opt_random && opt_urandom)
		usage(popt_context, EXIT_FAILURE, _("Only one of --use-[u]random options is allowed."),
		      poptGetInvocationName(popt_context));

	if (opt_device_size_str &&
	    crypt_string_to_size(NULL, opt_device_size_str, &opt_device_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid device size specification."),
		      poptGetInvocationName(popt_context));

	if (opt_reduce_size_str &&
	    crypt_string_to_size(NULL, opt_reduce_size_str, &opt_reduce_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid device size specification."),
		      poptGetInvocationName(popt_context));
	if (opt_reduce_size > 64 * 1024 * 1024)
		usage(popt_context, EXIT_FAILURE, _("Maximum device reduce size is 64 MiB."),
		      poptGetInvocationName(popt_context));
	if (opt_reduce_size % SECTOR_SIZE)
		usage(popt_context, EXIT_FAILURE, _("Reduce size must be multiple of 512 bytes sector."),
		      poptGetInvocationName(popt_context));

	if (opt_new && !opt_reduce_size)
		usage(popt_context, EXIT_FAILURE, _("Option --new must be used together with --reduce-device-size."),
		      poptGetInvocationName(popt_context));

	if (opt_keep_key && ((!opt_hash && !opt_iteration_time) || opt_cipher || opt_new))
		usage(popt_context, EXIT_FAILURE, _("Option --keep-key can be used only with --hash or --iter-time."),
		      poptGetInvocationName(popt_context));

	if (opt_debug) {
		opt_verbose = 1;
		crypt_set_debug_level(-1);
		dbg_version_and_cmd(argc, argv);
	}

	r = run_reencrypt(action_argv[0]);

	poptFreeContext(popt_context);

	return translate_errno(r);
}
