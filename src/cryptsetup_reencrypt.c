/*
 * cryptsetup-reencrypt - crypt utility for offline re-encryption
 *
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2020 Milan Broz All rights reserved.
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
#include <linux/fs.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>

#define PACKAGE_REENC "cryptsetup-reencrypt"

#define NO_UUID "cafecafe-cafe-cafe-cafe-cafecafeeeee"

static const char *opt_cipher = NULL;
static const char *opt_hash = NULL;
static const char *opt_key_file = NULL;
static const char *opt_master_key_file = NULL;
static const char *opt_uuid = NULL;
static const char *opt_type = "luks";
static long opt_keyfile_size = 0;
static long opt_keyfile_offset = 0;
static int opt_iteration_time = 0;
static const char *opt_pbkdf = NULL;
static long opt_pbkdf_memory = DEFAULT_LUKS2_MEMORY_KB;
static long opt_pbkdf_parallel = DEFAULT_LUKS2_PARALLEL_THREADS;
static long opt_pbkdf_iterations = 0;
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
static int opt_decrypt = 0;
static const char *opt_header_device = NULL;

static const char *opt_reduce_size_str = NULL;
static uint64_t opt_reduce_size = 0;

static const char *opt_device_size_str = NULL;
static uint64_t opt_device_size = 0;

static const char **action_argv;

#define MAX_SLOT 32
#define MAX_TOKEN 32
struct reenc_ctx {
	char *device;
	char *device_header;
	char *device_uuid;
	const char *type;
	uint64_t device_size; /* overridden by parameter */
	uint64_t device_size_new_real;
	uint64_t device_size_org_real;
	uint64_t device_offset;
	uint64_t device_shift;
	uint64_t data_offset;

	unsigned int stained:1;
	unsigned int in_progress:1;
	enum { FORWARD = 0, BACKWARD = 1 } reencrypt_direction;
	enum { REENCRYPT = 0, ENCRYPT = 1, DECRYPT = 2 } reencrypt_mode;

	char header_file_org[PATH_MAX];
	char header_file_tmp[PATH_MAX];
	char header_file_new[PATH_MAX];
	char log_file[PATH_MAX];

	char crypt_path_org[PATH_MAX];
	char crypt_path_new[PATH_MAX];
	int log_fd;
	char log_buf[SECTOR_SIZE];

	struct {
		char *password;
		size_t passwordLen;
	} p[MAX_SLOT];
	int keyslot;

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

static const char *luksType(const char *type)
{
	if (type && !strcmp(type, "luks2"))
		return CRYPT_LUKS2;

	if (type && !strcmp(type, "luks1"))
		return CRYPT_LUKS1;

	if (!type || !strcmp(type, "luks"))
		return crypt_get_default_type();

	return NULL;
}

static const char *hdr_device(const struct reenc_ctx *rc)
{
	return rc->device_header ?: rc->device;
}

static int set_reencrypt_requirement(const struct reenc_ctx *rc)
{
	uint32_t reqs;
	int r = -EINVAL;
	struct crypt_device *cd = NULL;
	struct crypt_params_integrity ip = { 0 };

	if (crypt_init(&cd, hdr_device(rc)) ||
	    crypt_load(cd, CRYPT_LUKS2, NULL) ||
	    crypt_persistent_flags_get(cd, CRYPT_FLAGS_REQUIREMENTS, &reqs))
		goto out;

	/* reencrypt already in-progress */
	if (reqs & CRYPT_REQUIREMENT_OFFLINE_REENCRYPT) {
		log_err(_("Reencryption already in-progress."));
		goto out;
	}

	/* raw integrity info is available since 2.0 */
	if (crypt_get_integrity_info(cd, &ip) || ip.tag_size) {
		log_err(_("Reencryption of device with integrity profile is not supported."));
		r = -ENOTSUP;
		goto out;
	}

	r = crypt_persistent_flags_set(cd, CRYPT_FLAGS_REQUIREMENTS, reqs | CRYPT_REQUIREMENT_OFFLINE_REENCRYPT);
out:
	crypt_free(cd);
	return r;
}

/* Depends on the first two fields of LUKS1 header format, magic and version */
static int device_check(struct reenc_ctx *rc, const char *device, header_magic set_magic)
{
	char *buf = NULL;
	int r, devfd;
	ssize_t s;
	uint16_t version;
	size_t buf_size = pagesize();
	struct stat st;

	if (stat(device, &st)) {
		log_err(_("Cannot open device %s."), device);
		return -EINVAL;
	}

	/* coverity[toctou] */
	devfd = open(device, O_RDWR | (S_ISBLK(st.st_mode) ? O_EXCL : 0));
	if (devfd == -1) {
		if (errno == EBUSY) {
			log_err(_("Cannot exclusively open %s, device in use."),
				device);
			return -EBUSY;
		}
		log_err(_("Cannot open device %s."), device);
		return -EINVAL;
	}

	if (set_magic == CHECK_OPEN) {
		r = 0;
		goto out;
	}

	if (posix_memalign((void *)&buf, alignment(devfd), buf_size)) {
		log_err(_("Allocation of aligned memory failed."));
		r = -ENOMEM;
		goto out;
	}

	s = read(devfd, buf, buf_size);
	if (s < 0 || s != (ssize_t)buf_size) {
		log_err(_("Cannot read device %s."), device);
		r = -EIO;
		goto out;
	}

	/* Be sure that we do not process new version of header */
	memcpy((void*)&version, &buf[MAGIC_L], sizeof(uint16_t));
	version = ntohs(version);

	if (set_magic == MAKE_UNUSABLE && !memcmp(buf, MAGIC, MAGIC_L) &&
	    version == 1) {
		log_verbose(_("Marking LUKS1 device %s unusable."), device);
		memcpy(buf, NOMAGIC, MAGIC_L);
		r = 0;
	} else if (set_magic == MAKE_UNUSABLE && version == 2) {
		log_verbose(_("Setting LUKS2 offline reencrypt flag on device %s."), device);
		r = set_reencrypt_requirement(rc);
		if (!r)
			rc->stained = 1;
	} else if (set_magic == CHECK_UNUSABLE && version == 1) {
		r = memcmp(buf, NOMAGIC, MAGIC_L) ? -EINVAL : 0;
		if (!r)
			rc->device_uuid = strndup(&buf[0xa8], 40);
		goto out;
	} else
		r = -EINVAL;

	if (!r && version == 1) {
		if (lseek(devfd, 0, SEEK_SET) == -1)
			goto out;
		s = write(devfd, buf, buf_size);
		if (s < 0 || s != (ssize_t)buf_size || fsync(devfd) < 0) {
			log_err(_("Cannot write device %s."), device);
			r = -EIO;
		}
		if (s > 0 && set_magic == MAKE_UNUSABLE)
			rc->stained = 1;
	}
	if (r)
		log_dbg("LUKS signature check failed for %s.", device);
out:
	if (buf)
		memset(buf, 0, buf_size);
	free(buf);
	close(devfd);
	return r;
}

static int create_empty_header(const char *new_file)
{
	int fd, r = 0;

	log_dbg("Creating empty file %s of size 4096.", new_file);

	/* coverity[toctou] */
	fd = open(new_file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
	if (fd == -1 || posix_fallocate(fd, 0, 4096))
		r = -EINVAL;
	if (fd >= 0)
		close(fd);

	return r;
}

static int write_log(struct reenc_ctx *rc)
{
	ssize_t r;

	memset(rc->log_buf, 0, SECTOR_SIZE);
	snprintf(rc->log_buf, SECTOR_SIZE, "# LUKS reencryption log, DO NOT EDIT OR DELETE.\n"
		"version = %d\nUUID = %s\ndirection = %d\nmode = %d\n"
		"offset = %" PRIu64 "\nshift = %" PRIu64 "\n# EOF\n",
		2, rc->device_uuid, rc->reencrypt_direction, rc->reencrypt_mode,
		rc->device_offset, rc->device_shift);

	if (lseek(rc->log_fd, 0, SEEK_SET) == -1)
		return -EIO;

	r = write(rc->log_fd, rc->log_buf, SECTOR_SIZE);
	if (r < 0 || r != SECTOR_SIZE) {
		log_err(_("Cannot write reencryption log file."));
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
		if (i < 1 || i > 2) {
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
	} else if (sscanf(line, "mode = %d", &i) == 1) { /* added in v2 */
		log_dbg("Log: mode = %i", i);
		rc->reencrypt_mode = i;
		if (rc->reencrypt_mode != REENCRYPT &&
		    rc->reencrypt_mode != ENCRYPT &&
		    rc->reencrypt_mode != DECRYPT)
			return -EINVAL;
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
		log_err(_("Cannot read reencryption log file."));
		return -EIO;
	}

	rc->log_buf[SECTOR_SIZE - 1] = '\0';
	start = rc->log_buf;
	do {
		end = strchr(start, '\n');
		if (end) {
			*end++ = '\0';
			if (parse_line_log(rc, start)) {
				log_err("Wrong log format.");
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
}

static int open_log(struct reenc_ctx *rc)
{
	int flags = opt_fsync ? O_SYNC : 0;

	rc->log_fd = open(rc->log_file, O_RDWR|O_EXCL|O_CREAT|flags, S_IRUSR|S_IWUSR);
	if (rc->log_fd != -1) {
		log_dbg("Created LUKS reencryption log file %s.", rc->log_file);
		rc->stained = 0;
	} else if (errno == EEXIST) {
		log_std(_("Log file %s exists, resuming reencryption.\n"), rc->log_file);
		rc->log_fd = open(rc->log_file, O_RDWR|flags);
		rc->in_progress = 1;
	}

	if (rc->log_fd == -1)
		return -EINVAL;

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
	const char *pwd_old, *pwd_new, pwd_empty[] = "";
	size_t pwd_old_len, pwd_new_len;
	int r;

	log_dbg("Activating LUKS devices from headers.");

	/* Never use real password for empty header processing */
	if (rc->reencrypt_mode == REENCRYPT) {
		pwd_old = rc->p[rc->keyslot].password;
		pwd_old_len = rc->p[rc->keyslot].passwordLen;
		pwd_new = pwd_old;
		pwd_new_len = pwd_old_len;
	} else if (rc->reencrypt_mode == DECRYPT) {
		pwd_old = rc->p[rc->keyslot].password;
		pwd_old_len = rc->p[rc->keyslot].passwordLen;
		pwd_new = pwd_empty;
		pwd_new_len = 0;
	} else if (rc->reencrypt_mode == ENCRYPT) {
		pwd_old = pwd_empty;
		pwd_old_len = 0;
		pwd_new = rc->p[rc->keyslot].password;
		pwd_new_len = rc->p[rc->keyslot].passwordLen;
	} else
		return -EINVAL;

	if ((r = crypt_init_data_device(&cd, rc->header_file_org, rc->device)) ||
	    (r = crypt_load(cd, CRYPT_LUKS, NULL)))
		goto out;

	log_verbose(_("Activating temporary device using old LUKS header."));
	if ((r = crypt_activate_by_passphrase(cd, rc->header_file_org,
		opt_key_slot, pwd_old, pwd_old_len,
		CRYPT_ACTIVATE_READONLY|CRYPT_ACTIVATE_PRIVATE)) < 0)
		goto out;

	if ((r = crypt_init_data_device(&cd_new, rc->header_file_new, rc->device)) ||
	    (r = crypt_load(cd_new, CRYPT_LUKS, NULL)))
		goto out;

	log_verbose(_("Activating temporary device using new LUKS header."));
	if ((r = crypt_activate_by_passphrase(cd_new, rc->header_file_new,
		opt_key_slot, pwd_new, pwd_new_len,
		CRYPT_ACTIVATE_SHARED|CRYPT_ACTIVATE_PRIVATE)) < 0)
		goto out;
	r = 0;
out:
	crypt_free(cd);
	crypt_free(cd_new);
	if (r < 0)
		log_err(_("Activation of temporary devices failed."));
	return r;
}

static int set_pbkdf_params(struct crypt_device *cd, const char *dev_type)
{
	const struct crypt_pbkdf_type *pbkdf_default;
	struct crypt_pbkdf_type pbkdf = {};

	pbkdf_default = crypt_get_pbkdf_default(dev_type);
	if (!pbkdf_default)
		return -EINVAL;

	pbkdf.type = opt_pbkdf ?: pbkdf_default->type;
	pbkdf.hash = opt_hash ?: pbkdf_default->hash;
	pbkdf.time_ms = (uint32_t)opt_iteration_time ?: pbkdf_default->time_ms;
	if (strcmp(pbkdf.type, CRYPT_KDF_PBKDF2)) {
		pbkdf.max_memory_kb = (uint32_t)opt_pbkdf_memory ?: pbkdf_default->max_memory_kb;
		pbkdf.parallel_threads = (uint32_t)opt_pbkdf_parallel ?: pbkdf_default->parallel_threads;
	}

	if (opt_pbkdf_iterations) {
		pbkdf.iterations = opt_pbkdf_iterations;
		pbkdf.time_ms = 0;
		pbkdf.flags |= CRYPT_PBKDF_NO_BENCHMARK;
	}

	return crypt_set_pbkdf_type(cd, &pbkdf);
}

static int create_new_keyslot(struct reenc_ctx *rc, int keyslot,
			      struct crypt_device *cd_old,
			      struct crypt_device *cd_new)
{
	int r;
	char *key = NULL;
	size_t key_size;

	if (cd_old && crypt_keyslot_status(cd_old, keyslot) == CRYPT_SLOT_UNBOUND) {
		key_size = 4096;
		key = crypt_safe_alloc(key_size);
		if (!key)
			return -ENOMEM;
		r = crypt_volume_key_get(cd_old, keyslot, key, &key_size,
			rc->p[keyslot].password, rc->p[keyslot].passwordLen);
		if (r == keyslot) {
			r = crypt_keyslot_add_by_key(cd_new, keyslot, key, key_size,
				rc->p[keyslot].password, rc->p[keyslot].passwordLen,
				CRYPT_VOLUME_KEY_NO_SEGMENT);
		} else
			r = -EINVAL;
		crypt_safe_free(key);
	} else
		r = crypt_keyslot_add_by_volume_key(cd_new, keyslot, NULL, 0,
			rc->p[keyslot].password, rc->p[keyslot].passwordLen);

	return r;
}

static int create_new_header(struct reenc_ctx *rc, struct crypt_device *cd_old,
			     const char *cipher, const char *cipher_mode,
			     const char *uuid,
			     const char *key, int key_size,
			     const char *type,
			     uint64_t metadata_size,
			     uint64_t keyslots_size,
			     void *params)
{
	struct crypt_device *cd_new = NULL;
	int i, r;

	if ((r = crypt_init(&cd_new, rc->header_file_new)))
		goto out;

	if (opt_random)
		crypt_set_rng_type(cd_new, CRYPT_RNG_RANDOM);
	else if (opt_urandom)
		crypt_set_rng_type(cd_new, CRYPT_RNG_URANDOM);

	r = set_pbkdf_params(cd_new, type);
	if (r) {
		log_err(_("Failed to set pbkdf parameters."));
		goto out;
	}

	r = crypt_set_data_offset(cd_new, rc->data_offset);
	if (r) {
		log_err(_("Failed to set data offset."));
		goto out;
	}

	r = crypt_set_metadata_size(cd_new, metadata_size, keyslots_size);
	if (r) {
		log_err(_("Failed to set metadata size."));
		goto out;
	}

	r = crypt_format(cd_new, type, cipher, cipher_mode, uuid, key, key_size, params);
	check_signal(&r);
	if (r < 0)
		goto out;
	log_verbose(_("New LUKS header for device %s created."), rc->device);

	for (i = 0; i < crypt_keyslot_max(type); i++) {
		if (!rc->p[i].password)
			continue;

		r = create_new_keyslot(rc, i, cd_old, cd_new);
		check_signal(&r);
		if (r < 0)
			goto out;
		tools_keyslot_msg(r, CREATED);
		r = 0;
	}
out:
	crypt_free(cd_new);
	return r;
}

static int isLUKS2(const char *type)
{
	return (type && !strcmp(type, CRYPT_LUKS2));
}

static int luks2_metadata_copy(struct reenc_ctx *rc)
{
	const char *json, *type;
	crypt_token_info ti;
	uint32_t flags;
	int i, r = -EINVAL;
	struct crypt_device *cd_old = NULL, *cd_new = NULL;

	if (crypt_init(&cd_old, rc->header_file_tmp) ||
	    crypt_load(cd_old, CRYPT_LUKS2, NULL))
		goto out;

	if (crypt_init(&cd_new, rc->header_file_new) ||
	    crypt_load(cd_new, CRYPT_LUKS2, NULL))
		goto out;

	/*
	 * we have to erase keyslots missing in new header so that we can
	 * transfer tokens from old header to new one
	 */
	for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS2); i++)
		if (!rc->p[i].password && crypt_keyslot_status(cd_old, i) == CRYPT_SLOT_ACTIVE) {
			r = crypt_keyslot_destroy(cd_old, i);
			if (r < 0)
				goto out;
		}

	for (i = 0; i < MAX_TOKEN; i++) {
		ti = crypt_token_status(cd_old, i, &type);
		switch (ti) {
		case CRYPT_TOKEN_INVALID:
			log_dbg("Internal error.");
			r = -EINVAL;
			goto out;
		case CRYPT_TOKEN_INACTIVE:
			break;
		case CRYPT_TOKEN_INTERNAL_UNKNOWN:
			log_err(_("This version of cryptsetup-reencrypt can't handle new internal token type %s."), type);
			r = -EINVAL;
			goto out;
		case CRYPT_TOKEN_INTERNAL:
			/* fallthrough */
		case CRYPT_TOKEN_EXTERNAL:
			/* fallthrough */
		case CRYPT_TOKEN_EXTERNAL_UNKNOWN:
			if (crypt_token_json_get(cd_old, i, &json) != i) {
				log_dbg("Failed to get %s token (%d).", type, i);
				r = -EINVAL;
				goto out;
			}
			if (crypt_token_json_set(cd_new, i, json) != i) {
				log_dbg("Failed to create %s token (%d).", type, i);
				r = -EINVAL;
				goto out;
			}
		}
	}

	if ((r = crypt_persistent_flags_get(cd_old, CRYPT_FLAGS_ACTIVATION, &flags))) {
		log_err(_("Failed to read activation flags from backup header."));
		goto out;
	}
	if ((r = crypt_persistent_flags_set(cd_new, CRYPT_FLAGS_ACTIVATION, flags))) {
		log_err(_("Failed to write activation flags to new header."));
		goto out;
	}
	if ((r = crypt_persistent_flags_get(cd_old, CRYPT_FLAGS_REQUIREMENTS, &flags))) {
		log_err(_("Failed to read requirements from backup header."));
		goto out;
	}
	if ((r = crypt_persistent_flags_set(cd_new, CRYPT_FLAGS_REQUIREMENTS, flags)))
		log_err(_("Failed to read requirements from backup header."));
out:
	crypt_free(cd_old);
	crypt_free(cd_new);
	unlink(rc->header_file_tmp);

	return r;
}

static int backup_luks_headers(struct reenc_ctx *rc)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_luks1 params = {0};
	struct crypt_params_luks2 params2 = {0};
	struct stat st;
	char cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	char *key = NULL;
	size_t key_size;
	uint64_t mdata_size = 0, keyslots_size = 0;
	int r;

	log_dbg("Creating LUKS header backup for device %s.", hdr_device(rc));

	if ((r = crypt_init(&cd, hdr_device(rc))) ||
	    (r = crypt_load(cd, CRYPT_LUKS, NULL)))
		goto out;

	if ((r = crypt_header_backup(cd, CRYPT_LUKS, rc->header_file_org)))
		goto out;
	if (isLUKS2(rc->type)) {
		if ((r = crypt_header_backup(cd, CRYPT_LUKS2, rc->header_file_tmp)))
			goto out;
		if ((r = stat(rc->header_file_tmp, &st)))
			goto out;
		/* coverity[toctou] */
		if ((r = chmod(rc->header_file_tmp, st.st_mode | S_IWUSR)))
			goto out;
	}
	log_verbose(_("%s header backup of device %s created."), isLUKS2(rc->type) ? "LUKS2" : "LUKS1", rc->device);

	/* For decrypt, new header will be fake one, so we are done here. */
	if (rc->reencrypt_mode == DECRYPT)
		goto out;

	rc->data_offset = crypt_get_data_offset(cd) + ROUND_SECTOR(opt_reduce_size);

	if ((r = create_empty_header(rc->header_file_new)))
		goto out;

	params.hash = opt_hash ?: DEFAULT_LUKS1_HASH;
	params2.data_device = params.data_device = rc->device;
	params2.sector_size = crypt_get_sector_size(cd);

	if (opt_cipher) {
		r = crypt_parse_name_and_mode(opt_cipher, cipher, NULL, cipher_mode);
		if (r < 0) {
			log_err(_("No known cipher specification pattern detected."));
			goto out;
		}
	}

	key_size = opt_key_size ? opt_key_size / 8 : crypt_get_volume_key_size(cd);

	if (opt_keep_key) {
		log_dbg("Keeping key from old header.");
		key_size = crypt_get_volume_key_size(cd);
		key = crypt_safe_alloc(key_size);
		if (!key) {
			r = -ENOMEM;
			goto out;
		}
		r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size,
			rc->p[rc->keyslot].password, rc->p[rc->keyslot].passwordLen);
	} else if (opt_master_key_file) {
		log_dbg("Loading new key from file.");
		r = tools_read_mk(opt_master_key_file, &key, key_size);
	}

	if (r < 0)
		goto out;

	if (isLUKS2(crypt_get_type(cd)) && crypt_get_metadata_size(cd, &mdata_size, &keyslots_size))
		goto out;

	r = create_new_header(rc, cd,
		opt_cipher ? cipher : crypt_get_cipher(cd),
		opt_cipher ? cipher_mode : crypt_get_cipher_mode(cd),
		crypt_get_uuid(cd),
		key,
		key_size,
		rc->type,
		mdata_size,
		keyslots_size,
		isLUKS2(rc->type) ? (void*)&params2 : (void*)&params);

	if (!r && isLUKS2(rc->type))
		r = luks2_metadata_copy(rc);
out:
	crypt_free(cd);
	crypt_safe_free(key);
	if (r)
		log_err(_("Creation of LUKS backup headers failed."));
	return r;
}

/* Create fake header for original device */
static int backup_fake_header(struct reenc_ctx *rc)
{
	struct crypt_device *cd_new = NULL;
	struct crypt_params_luks1 params = {0};
	struct crypt_params_luks2 params2 = {0};
	char cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	const char *header_file_fake;
	int r;

	log_dbg("Creating fake (cipher_null) header for %s device.",
		(rc->reencrypt_mode == DECRYPT) ? "new" : "original");

	header_file_fake = (rc->reencrypt_mode == DECRYPT) ? rc->header_file_new : rc->header_file_org;

	if (!opt_key_size)
		opt_key_size = DEFAULT_LUKS1_KEYBITS;

	if (opt_cipher) {
		r = crypt_parse_name_and_mode(opt_cipher, cipher, NULL, cipher_mode);
		if (r < 0) {
			log_err(_("No known cipher specification pattern detected."));
			goto out;
		}
	}

	r = create_empty_header(header_file_fake);
	if (r < 0)
		return r;

	params.hash = opt_hash ?: DEFAULT_LUKS1_HASH;
	params2.data_alignment = params.data_alignment = 0;
	params2.data_device = params.data_device = rc->device;
	params2.sector_size = crypt_get_sector_size(NULL);
	params2.pbkdf = crypt_get_pbkdf_default(CRYPT_LUKS2);

	r = crypt_init(&cd_new, header_file_fake);
	if (r < 0)
		return r;

	r = crypt_format(cd_new, CRYPT_LUKS1, "cipher_null", "ecb",
			 NO_UUID, NULL, opt_key_size / 8, &params);
	check_signal(&r);
	if (r < 0)
		goto out;

	r = crypt_keyslot_add_by_volume_key(cd_new, rc->keyslot, NULL, 0,
			rc->p[rc->keyslot].password, rc->p[rc->keyslot].passwordLen);
	check_signal(&r);
	if (r < 0)
		goto out;

	/* The real header is backup header created in backup_luks_headers() */
	if (rc->reencrypt_mode == DECRYPT) {
		r = 0;
		goto out;
	}

	r = create_empty_header(rc->header_file_new);
	if (r < 0)
		goto out;

	params2.data_alignment = params.data_alignment = ROUND_SECTOR(opt_reduce_size);
	r = create_new_header(rc, NULL,
		opt_cipher ? cipher : DEFAULT_LUKS1_CIPHER,
		opt_cipher ? cipher_mode : DEFAULT_LUKS1_MODE,
		NULL, NULL,
		(opt_key_size ? opt_key_size : DEFAULT_LUKS1_KEYBITS) / 8,
		rc->type,
		0,
		0,
		isLUKS2(rc->type) ? (void*)&params2 : (void*)&params);
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
	struct stat st;
	struct crypt_device *cd = NULL;
	int fd, r;

	log_dbg("Restoring header for %s from %s.", hdr_device(rc), rc->header_file_new);

	/*
	 * For new encryption and new detached header in file just move it.
	 * For existing file try to ensure we have preallocated space for restore.
	 */
	if (opt_new && rc->device_header) {
		r = stat(rc->device_header, &st);
		if (r == -1) {
			r = rename(rc->header_file_new, rc->device_header);
			goto out;
		} else if ((st.st_mode & S_IFMT) == S_IFREG &&
			stat(rc->header_file_new, &st) != -1) {
			/* coverity[toctou] */
			fd = open(rc->device_header, O_WRONLY);
			if (fd != -1) {
				if (posix_fallocate(fd, 0, st.st_size)) {};
				close(fd);
			}
		}
	}

	r = crypt_init(&cd, hdr_device(rc));
	if (r == 0) {
		r = crypt_header_restore(cd, rc->type, rc->header_file_new);
	}

	crypt_free(cd);
out:
	if (r)
		log_err(_("Cannot restore %s header on device %s."), isLUKS2(rc->type) ? "LUKS2" : "LUKS1", hdr_device(rc));
	else {
		log_verbose(_("%s header on device %s restored."), isLUKS2(rc->type) ? "LUKS2" : "LUKS1", hdr_device(rc));
		rc->stained = 0;
	}
	return r;
}

static ssize_t read_buf(int fd, void *buf, size_t count)
{
	size_t read_size = 0;
	ssize_t s;

	do {
		/* This expects that partial read is aligned in buffer */
		s = read(fd, buf, count - read_size);
		if (s == -1 && errno != EINTR)
			return s;
		if (s == 0)
			return (ssize_t)read_size;
		if (s > 0) {
			if (s != (ssize_t)count)
				log_dbg("Partial read %zd / %zu.", s, count);
			read_size += (size_t)s;
			buf = (uint8_t*)buf + s;
		}
	} while (read_size != count);

	return (ssize_t)count;
}

static int copy_data_forward(struct reenc_ctx *rc, int fd_old, int fd_new,
			     size_t block_size, void *buf, uint64_t *bytes)
{
	ssize_t s1, s2;

	log_dbg("Reencrypting in forward direction.");

	if (lseek64(fd_old, rc->device_offset, SEEK_SET) < 0 ||
	    lseek64(fd_new, rc->device_offset, SEEK_SET) < 0) {
		log_err(_("Cannot seek to device offset."));
		return -EIO;
	}

	rc->resume_bytes = *bytes = rc->device_offset;

	tools_reencrypt_progress(rc->device_size, *bytes, NULL);

	if (write_log(rc) < 0)
		return -EIO;

	while (!quit && rc->device_offset < rc->device_size) {
		s1 = read_buf(fd_old, buf, block_size);
		if (s1 < 0 || ((size_t)s1 != block_size &&
		    (rc->device_offset + s1) != rc->device_size)) {
			log_dbg("Read error, expecting %zu, got %zd.",
				block_size, s1);
			return -EIO;
		}

		/* If device_size is forced, never write more than limit */
		if ((s1 + rc->device_offset) > rc->device_size)
			s1 = rc->device_size - rc->device_offset;

		s2 = write(fd_new, buf, s1);
		if (s2 < 0) {
			log_dbg("Write error, expecting %zu, got %zd.",
				block_size, s2);
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

		tools_reencrypt_progress(rc->device_size, *bytes, NULL);
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

	tools_reencrypt_progress(rc->device_size, *bytes, NULL);

	if (write_log(rc) < 0)
		return -EIO;

	/* dirty the device during ENCRYPT mode */
	rc->stained = 1;

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
			log_err(_("Cannot seek to device offset."));
			return -EIO;
		}

		s1 = read_buf(fd_old, buf, working_block);
		if (s1 < 0 || (s1 != working_block)) {
			log_dbg("Read error, expecting %zu, got %zd.",
				block_size, s1);
			return -EIO;
		}

		s2 = write(fd_new, buf, working_block);
		if (s2 < 0) {
			log_dbg("Write error, expecting %zu, got %zd.",
				block_size, s2);
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

		tools_reencrypt_progress(rc->device_size, *bytes, NULL);
	}

	return quit ? -EAGAIN : 0;
}

static void zero_rest_of_device(int fd, size_t block_size, void *buf,
				uint64_t *bytes, uint64_t offset)
{
	ssize_t s1, s2;

	log_dbg("Zeroing rest of device.");

	if (lseek64(fd, offset, SEEK_SET) < 0) {
		log_dbg("Cannot seek to device offset.");
		return;
	}

	memset(buf, 0, block_size);
	s1 = block_size;

	while (!quit && *bytes) {
		if (*bytes < (uint64_t)s1)
			s1 = *bytes;

		s2 = write(fd, buf, s1);
		if (s2 != s1) {
			log_dbg("Write error, expecting %zd, got %zd.",
				s1, s2);
			return;
		}

		if (opt_fsync && fsync(fd) < 0) {
			log_dbg("Write error, fsync.");
			return;
		}

		*bytes -= s2;
	}
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
		log_err(_("Cannot open temporary LUKS device."));
		goto out;
	}

	fd_new = open(rc->crypt_path_new, O_WRONLY | (opt_directio ? O_DIRECT : 0));
	if (fd_new == -1) {
		log_err(_("Cannot open temporary LUKS device."));
		goto out;
	}

	if (ioctl(fd_old, BLKGETSIZE64, &rc->device_size_org_real) < 0) {
		log_err(_("Cannot get device size."));
		goto out;
	}

	if (ioctl(fd_new, BLKGETSIZE64, &rc->device_size_new_real) < 0) {
		log_err(_("Cannot get device size."));
		goto out;
	}

	if (opt_device_size)
		rc->device_size = opt_device_size;
	else if (rc->reencrypt_mode == DECRYPT)
		rc->device_size = rc->device_size_org_real;
	else
		rc->device_size = rc->device_size_new_real;

	if (posix_memalign((void *)&buf, alignment(fd_new), block_size)) {
		log_err(_("Allocation of aligned memory failed."));
		r = -ENOMEM;
		goto out;
	}

	set_int_handler(0);

	if (rc->reencrypt_direction == FORWARD)
		r = copy_data_forward(rc, fd_old, fd_new, block_size, buf, &bytes);
	else
		r = copy_data_backward(rc, fd_old, fd_new, block_size, buf, &bytes);

	/* Zero (wipe) rest of now plain-only device when decrypting.
	 * (To not leave any sign of encryption here.) */
	if (!r && rc->reencrypt_mode == DECRYPT &&
	    rc->device_size_new_real > rc->device_size_org_real) {
		bytes = rc->device_size_new_real - rc->device_size_org_real;
		zero_rest_of_device(fd_new, block_size, buf, &bytes, rc->device_size_org_real);
	}

	set_int_block(1);

	if (r < 0 && r != -EAGAIN)
		log_err(_("IO error during reencryption."));

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
	uuid_t device_uuid;

	log_dbg("Initialising UUID.");

	if (opt_new) {
		rc->device_uuid = strdup(NO_UUID);
		rc->type = luksType(opt_type);
		return 0;
	}

	if (opt_decrypt && opt_uuid) {
		r = uuid_parse(opt_uuid, device_uuid);
		if (!r)
			rc->device_uuid = strdup(opt_uuid);
		else
			log_err(_("Provided UUID is invalid."));

		return r;
	}

	/* Try to load LUKS from device */
	if ((r = crypt_init(&cd, hdr_device(rc))))
		return r;
	crypt_set_log_callback(cd, _quiet_log, NULL);
	r = crypt_load(cd, CRYPT_LUKS, NULL);
	if (!r)
		rc->device_uuid = strdup(crypt_get_uuid(cd));
	else
		/* Reencryption already in progress - magic header? */
		r = device_check(rc, hdr_device(rc), CHECK_UNUSABLE);

	if (!r)
		rc->type = isLUKS2(crypt_get_type(cd)) ? CRYPT_LUKS2 : CRYPT_LUKS1;

	crypt_free(cd);
	return r;
}

static int init_passphrase1(struct reenc_ctx *rc, struct crypt_device *cd,
			    const char *msg, int slot_to_check, int check, int verify)
{
	crypt_keyslot_info ki;
	char *password;
	int r = -EINVAL, retry_count;
	size_t passwordLen;

	/* mode ENCRYPT call this without header */
	if (cd && slot_to_check != CRYPT_ANY_SLOT) {
		ki = crypt_keyslot_status(cd, slot_to_check);
		if (ki < CRYPT_SLOT_ACTIVE)
			return -ENOENT;
	} else
		ki = CRYPT_SLOT_ACTIVE;

	retry_count = opt_tries ?: 1;
	while (retry_count--) {
		r = tools_get_key(msg,  &password, &passwordLen, 0, 0,
				  NULL /*opt_key_file*/, 0, verify, 0 /*pwquality*/, cd);
		if (r < 0)
			return r;
		if (quit) {
			crypt_safe_free(password);
			password = NULL;
			passwordLen = 0;
			return -EAGAIN;
		}

		if (check)
			r = crypt_activate_by_passphrase(cd, NULL, slot_to_check,
				password, passwordLen, CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY);
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
			tools_keyslot_msg(r, UNLOCKED);
			rc->p[r].password = password;
			rc->p[r].passwordLen = passwordLen;
			if (ki != CRYPT_SLOT_UNBOUND)
				rc->keyslot = r;
			break;
		}
		tools_passphrase_msg(r);
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

	r = tools_get_key(NULL, &password, &passwordLen, opt_keyfile_offset,
			  opt_keyfile_size, opt_key_file, 0, 0, 0, cd);
	if (r < 0)
		return r;

	/* mode ENCRYPT call this without header */
	if (cd) {
		r = crypt_activate_by_passphrase(cd, NULL, slot_check, password,
						 passwordLen, 0);

		/*
		 * Allow keyslot only if it is last slot or if user explicitly
		 * specify which slot to use (IOW others will be disabled).
		 */
		if (r >= 0 && opt_key_slot == CRYPT_ANY_SLOT &&
		    crypt_keyslot_status(cd, r) != CRYPT_SLOT_ACTIVE_LAST) {
			log_err(_("Key file can be used only with --key-slot or with "
				  "exactly one key slot active."));
			r = -EINVAL;
		}
	} else {
		r = slot_check == CRYPT_ANY_SLOT ? 0 : slot_check;
	}

	if (r < 0) {
		crypt_safe_free(password);
		tools_passphrase_msg(r);
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
	char msg[256];
	int i, r;

	log_dbg("Passphrases initialization.");

	if (rc->reencrypt_mode == ENCRYPT && !rc->in_progress) {
		if (opt_key_file)
			r = init_keyfile(rc, NULL, opt_key_slot);
		else
			r = init_passphrase1(rc, NULL, _("Enter new passphrase: "), opt_key_slot, 0, 1);
		return r > 0 ? 0 : r;
	}

	if ((r = crypt_init_data_device(&cd, device, rc->device)) ||
	    (r = crypt_load(cd, CRYPT_LUKS, NULL))) {
		crypt_free(cd);
		return r;
	}

	if (opt_key_slot != CRYPT_ANY_SLOT)
		snprintf(msg, sizeof(msg),
			 _("Enter passphrase for key slot %d: "), opt_key_slot);
	else
		snprintf(msg, sizeof(msg), _("Enter any existing passphrase: "));

	if (opt_key_file) {
		r = init_keyfile(rc, cd, opt_key_slot);
	} else if (rc->in_progress ||
		   opt_key_slot != CRYPT_ANY_SLOT ||
		   rc->reencrypt_mode == DECRYPT) {
		r = init_passphrase1(rc, cd, msg, opt_key_slot, 1, 0);
	} else for (i = 0; i < crypt_keyslot_max(crypt_get_type(cd)); i++) {
		snprintf(msg, sizeof(msg), _("Enter passphrase for key slot %d: "), i);
		r = init_passphrase1(rc, cd, msg, i, 1, 0);
		if (r == -ENOENT) {
			r = 0;
			continue;
		}
		if (r < 0)
			break;
	}

	crypt_free(cd);
	return r > 0 ? 0 : r;
}

static int initialize_context(struct reenc_ctx *rc, const char *device)
{
	log_dbg("Initialising reencryption context.");

	rc->log_fd = -1;

	/* FIXME: replace MAX_KEYSLOT with crypt_keyslot_max(CRYPT_LUKS2) */
	if (crypt_keyslot_max(CRYPT_LUKS2) > MAX_SLOT) {
		log_dbg("Internal error");
		return -EINVAL;
	}

	if (!(rc->device = strndup(device, PATH_MAX)))
		return -ENOMEM;

	if (opt_header_device && !(rc->device_header = strndup(opt_header_device, PATH_MAX)))
		return -ENOMEM;

	if (device_check(rc, rc->device, CHECK_OPEN) < 0)
		return -EINVAL;

	if (initialize_uuid(rc)) {
		log_err(_("Device %s is not a valid LUKS device."), device);
		return -EINVAL;
	}

	if (opt_key_slot != CRYPT_ANY_SLOT &&
	    opt_key_slot >= crypt_keyslot_max(rc->type)) {
		log_err(_("Key slot is invalid."));
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
	if (snprintf(rc->header_file_tmp, PATH_MAX,
		     "LUKS-%s.tmp", rc->device_uuid) < 0)
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
		log_err(_("Cannot open reencryption log file."));
		return -EINVAL;
	}

	if (!rc->in_progress) {
		if (opt_uuid) {
			log_err(_("No decryption in progress, provided UUID can "
			"be used only to resume suspended decryption process."));
			return -EINVAL;
		}

		if (!opt_reduce_size)
			rc->reencrypt_direction = FORWARD;
		else {
			rc->reencrypt_direction = BACKWARD;
			rc->device_offset = (uint64_t)~0;
		}

		if (opt_new)
			rc->reencrypt_mode = ENCRYPT;
		else if (opt_decrypt)
			rc->reencrypt_mode = DECRYPT;
		else
			rc->reencrypt_mode = REENCRYPT;
	}

	return 0;
}

static void destroy_context(struct reenc_ctx *rc)
{
	int i;

	log_dbg("Destroying reencryption context.");

	close_log(rc);
	remove_headers(rc);

	if (!rc->stained) {
		unlink(rc->log_file);
		unlink(rc->header_file_org);
		unlink(rc->header_file_new);
		unlink(rc->header_file_tmp);
	}

	for (i = 0; i < MAX_SLOT; i++)
		crypt_safe_free(rc->p[i].password);

	free(rc->device);
	free(rc->device_header);
	free(rc->device_uuid);
}

static int luks2_change_pbkdf_params(struct reenc_ctx *rc)
{
	int i, r;
	struct crypt_device *cd = NULL;

	if ((r = initialize_passphrase(rc, hdr_device(rc))))
		return r;

	if (crypt_init(&cd, hdr_device(rc)) ||
	    crypt_load(cd, CRYPT_LUKS2, NULL)) {
		r = -EINVAL;
		goto out;
	}

	if ((r = set_pbkdf_params(cd, CRYPT_LUKS2)))
		goto out;

	log_dbg("LUKS2 keyslot pbkdf params change.");

	r = -EINVAL;

	for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS2); i++) {
		if (!rc->p[i].password)
			continue;
		if ((r = crypt_keyslot_change_by_passphrase(cd, i, i,
			rc->p[i].password, rc->p[i].passwordLen,
			rc->p[i].password, rc->p[i].passwordLen)) < 0)
			goto out;
		log_verbose(_("Changed pbkdf parameters in keyslot %i."), r);
		r = 0;
	}

	if (r)
		goto out;

	/* see create_new_header */
	for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS2); i++)
		if (!rc->p[i].password)
			(void)crypt_keyslot_destroy(cd, i);
out:
	crypt_free(cd);
	return r;
}

static int run_reencrypt(const char *device)
{
	int r = -EINVAL;
	static struct reenc_ctx rc = {
		.stained = 1
	};

	set_int_handler(0);

	if (initialize_context(&rc, device))
		goto out;

	/* short-circuit LUKS2 keyslot parameters change */
	if (opt_keep_key && isLUKS2(rc.type)) {
		r = luks2_change_pbkdf_params(&rc);
		goto out;
	}

	log_dbg("Running reencryption.");

	if (!rc.in_progress) {
		if ((r = initialize_passphrase(&rc, hdr_device(&rc))))
			goto out;

		log_dbg("Storing backup of LUKS headers.");
		if (rc.reencrypt_mode == ENCRYPT) {
			/* Create fake header for existing device */
			if ((r = backup_fake_header(&rc)))
				goto out;
		} else {
			if ((r = backup_luks_headers(&rc)))
				goto out;
			/* Create fake header for decrypted device */
			if (rc.reencrypt_mode == DECRYPT &&
			    (r = backup_fake_header(&rc)))
				goto out;
			if ((r = device_check(&rc, hdr_device(&rc), MAKE_UNUSABLE)))
				goto out;
		}
	} else {
		if ((r = initialize_passphrase(&rc, opt_decrypt ? rc.header_file_org : rc.header_file_new)))
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

	// FIXME: fix error path above to not skip this
	if (rc.reencrypt_mode != DECRYPT)
		r = restore_luks_header(&rc);
	else
		rc.stained = 0;
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
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else if (key->shortName == 'V') {
		log_std("%s %s\n", PACKAGE_REENC, PACKAGE_VERSION);
		poptFreeContext(popt_context);
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
		{ "version",'V', POPT_ARG_NONE,     NULL, 0, N_("Print package version"),  NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,                '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ "verbose",           'v',  POPT_ARG_NONE, &opt_verbose,               0, N_("Shows more detailed error messages"), NULL },
		{ "debug",             '\0', POPT_ARG_NONE, &opt_debug,                 0, N_("Show debug messages"), NULL },
		{ "block-size",        'B',  POPT_ARG_INT, &opt_bsize,                  0, N_("Reencryption block size"), N_("MiB") },
		{ "cipher",            'c',  POPT_ARG_STRING, &opt_cipher,              0, N_("The cipher used to encrypt the disk (see /proc/crypto)"), NULL },
		{ "key-size",          's',  POPT_ARG_INT, &opt_key_size,               0, N_("The size of the encryption key"), N_("BITS") },
		{ "hash",              'h',  POPT_ARG_STRING, &opt_hash,                0, N_("The hash used to create the encryption key from the passphrase"), NULL },
		{ "keep-key",          '\0', POPT_ARG_NONE, &opt_keep_key,              0, N_("Do not change key, no data area reencryption"), NULL },
		{ "key-file",          'd',  POPT_ARG_STRING, &opt_key_file,            0, N_("Read the key from a file"), NULL },
		{ "master-key-file",   '\0', POPT_ARG_STRING, &opt_master_key_file,     0, N_("Read new volume (master) key from file"), NULL },
		{ "iter-time",         'i',  POPT_ARG_INT, &opt_iteration_time,         0, N_("PBKDF2 iteration time for LUKS (in ms)"), N_("msecs") },
		{ "batch-mode",        'q',  POPT_ARG_NONE, &opt_batch_mode,            0, N_("Do not ask for confirmation"), NULL },
		{ "progress-frequency",'\0', POPT_ARG_INT, &opt_progress_frequency,     0, N_("Progress line update (in seconds)"), N_("secs") },
		{ "tries",             'T',  POPT_ARG_INT, &opt_tries,                  0, N_("How often the input of the passphrase can be retried"), NULL },
		{ "use-random",        '\0', POPT_ARG_NONE, &opt_random,                0, N_("Use /dev/random for generating volume key"), NULL },
		{ "use-urandom",       '\0', POPT_ARG_NONE, &opt_urandom,               0, N_("Use /dev/urandom for generating volume key"), NULL },
		{ "use-directio",      '\0', POPT_ARG_NONE, &opt_directio,              0, N_("Use direct-io when accessing devices"), NULL },
		{ "use-fsync",         '\0', POPT_ARG_NONE, &opt_fsync,                 0, N_("Use fsync after each block"), NULL },
		{ "write-log",         '\0', POPT_ARG_NONE, &opt_write_log,             0, N_("Update log file after every block"), NULL },
		{ "key-slot",          'S',  POPT_ARG_INT, &opt_key_slot,               0, N_("Use only this slot (others will be disabled)"), NULL },
		{ "keyfile-offset",   '\0',  POPT_ARG_LONG, &opt_keyfile_offset,        0, N_("Number of bytes to skip in keyfile"), N_("bytes") },
		{ "keyfile-size",      'l',  POPT_ARG_LONG, &opt_keyfile_size,          0, N_("Limits the read from keyfile"), N_("bytes") },
		{ "reduce-device-size",'\0', POPT_ARG_STRING, &opt_reduce_size_str,     0, N_("Reduce data device size (move data offset). DANGEROUS!"), N_("bytes") },
		{ "device-size",       '\0', POPT_ARG_STRING, &opt_device_size_str,     0, N_("Use only specified device size (ignore rest of device). DANGEROUS!"), N_("bytes") },
		{ "new",               'N',  POPT_ARG_NONE, &opt_new,                   0, N_("Create new header on not encrypted device"), NULL },
		{ "decrypt",           '\0', POPT_ARG_NONE, &opt_decrypt,               0, N_("Permanently decrypt device (remove encryption)"), NULL },
		{ "uuid",              '\0', POPT_ARG_STRING, &opt_uuid,                0, N_("The UUID used to resume decryption"), NULL },
		{ "type",              '\0', POPT_ARG_STRING, &opt_type,                0, N_("Type of LUKS metadata: luks1, luks2"), NULL },
		{ "pbkdf",             '\0', POPT_ARG_STRING, &opt_pbkdf,               0, N_("PBKDF algorithm (for LUKS2): argon2i, argon2id, pbkdf2"), NULL },
		{ "pbkdf-memory",      '\0', POPT_ARG_LONG, &opt_pbkdf_memory,          0, N_("PBKDF memory cost limit"), N_("kilobytes") },
		{ "pbkdf-parallel",    '\0', POPT_ARG_LONG, &opt_pbkdf_parallel,        0, N_("PBKDF parallel cost"), N_("threads") },
		{ "pbkdf-force-iterations",'\0',POPT_ARG_LONG, &opt_pbkdf_iterations,   0, N_("PBKDF iterations cost (forced, disables benchmark)"), NULL },
		{ "header",            '\0', POPT_ARG_STRING, &opt_header_device,       0, N_("Device or file with separated LUKS header"), NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;
	int r;

	crypt_set_log_callback(NULL, tool_log, NULL);

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

	if (!opt_batch_mode)
		log_verbose(_("Reencryption will change: %s%s%s%s%s%s."),
			opt_keep_key ? "" :  _("volume key"),
			(!opt_keep_key && opt_hash) ? ", " : "",
			opt_hash   ? _("set hash to ")    : "", opt_hash   ?: "",
			opt_cipher ? _(", set cipher to "): "", opt_cipher ?: "");

	action_argv = poptGetArgs(popt_context);
	if(!action_argv)
		usage(popt_context, EXIT_FAILURE, _("Argument required."),
		      poptGetInvocationName(popt_context));

	if (opt_random && opt_urandom)
		usage(popt_context, EXIT_FAILURE, _("Only one of --use-[u]random options is allowed."),
		      poptGetInvocationName(popt_context));

	if (opt_bsize < 0 || opt_key_size < 0 || opt_iteration_time < 0 ||
	    opt_tries < 0 || opt_keyfile_offset < 0 || opt_key_size < 0 ||
	    opt_pbkdf_iterations < 0 || opt_pbkdf_memory < 0 ||
	    opt_pbkdf_parallel < 0) {
		usage(popt_context, EXIT_FAILURE,
		      _("Negative number for option not permitted."),
		      poptGetInvocationName(popt_context));
	}

	if (opt_pbkdf && crypt_parse_pbkdf(opt_pbkdf, &opt_pbkdf))
		usage(popt_context, EXIT_FAILURE,
		_("Password-based key derivation function (PBKDF) can be only pbkdf2 or argon2i/argon2id."),
		poptGetInvocationName(popt_context));

	if (opt_pbkdf_iterations && opt_iteration_time)
		usage(popt_context, EXIT_FAILURE,
		_("PBKDF forced iterations cannot be combined with iteration time option."),
		poptGetInvocationName(popt_context));

	if (opt_bsize < 1 || opt_bsize > 64)
		usage(popt_context, EXIT_FAILURE,
		      _("Only values between 1 MiB and 64 MiB allowed for reencryption block size."),
		      poptGetInvocationName(popt_context));

	if (opt_key_size % 8)
		usage(popt_context, EXIT_FAILURE,
		      _("Key size must be a multiple of 8 bits"),
		      poptGetInvocationName(popt_context));

	if (opt_key_slot != CRYPT_ANY_SLOT &&
	    (opt_key_slot < 0 || opt_key_slot >= crypt_keyslot_max(CRYPT_LUKS2)))
		usage(popt_context, EXIT_FAILURE, _("Key slot is invalid."),
		      poptGetInvocationName(popt_context));

	if (opt_random && opt_urandom)
		usage(popt_context, EXIT_FAILURE, _("Only one of --use-[u]random options is allowed."),
		      poptGetInvocationName(popt_context));

	if (opt_device_size_str &&
	    tools_string_to_size(NULL, opt_device_size_str, &opt_device_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid device size specification."),
		      poptGetInvocationName(popt_context));

	if (opt_reduce_size_str &&
	    tools_string_to_size(NULL, opt_reduce_size_str, &opt_reduce_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid device size specification."),
		      poptGetInvocationName(popt_context));
	if (opt_reduce_size > 64 * 1024 * 1024)
		usage(popt_context, EXIT_FAILURE, _("Maximum device reduce size is 64 MiB."),
		      poptGetInvocationName(popt_context));
	if (opt_reduce_size % SECTOR_SIZE)
		usage(popt_context, EXIT_FAILURE, _("Reduce size must be multiple of 512 bytes sector."),
		      poptGetInvocationName(popt_context));

	if (opt_new && (!opt_reduce_size && !opt_header_device))
		usage(popt_context, EXIT_FAILURE, _("Option --new must be used together with --reduce-device-size or --header."),
		      poptGetInvocationName(popt_context));

	if (opt_keep_key && (opt_cipher || opt_new || opt_master_key_file))
		usage(popt_context, EXIT_FAILURE, _("Option --keep-key can be used only with --hash, --iter-time or --pbkdf-force-iterations."),
		      poptGetInvocationName(popt_context));

	if (opt_new && opt_decrypt)
		usage(popt_context, EXIT_FAILURE, _("Option --new cannot be used together with --decrypt."),
		      poptGetInvocationName(popt_context));

	if (opt_decrypt && (opt_cipher || opt_hash || opt_reduce_size || opt_keep_key || opt_device_size))
		usage(popt_context, EXIT_FAILURE, _("Option --decrypt is incompatible with specified parameters."),
		      poptGetInvocationName(popt_context));

	if (opt_uuid && !opt_decrypt)
		usage(popt_context, EXIT_FAILURE, _("Option --uuid is allowed only together with --decrypt."),
		      poptGetInvocationName(popt_context));

	if (!luksType(opt_type))
		usage(popt_context, EXIT_FAILURE, _("Invalid luks type. Use one of these: 'luks', 'luks1' or 'luks2'."),
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
