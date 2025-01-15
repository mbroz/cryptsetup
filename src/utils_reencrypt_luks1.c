// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup - LUKS1 utility for offline re-encryption
 *
 * Copyright (C) 2012-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2025 Milan Broz
 */

#include <sys/ioctl.h>
#include <linux/fs.h>
#include <uuid/uuid.h>

#include "cryptsetup.h"
#include "cryptsetup_args.h"
#include "utils_luks.h"

#define NO_UUID "cafecafe-cafe-cafe-cafe-cafecafeeeee"

extern int64_t data_shift;

#define MAX_SLOT 8

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

	bool stained;
	bool in_progress;
	enum { FORWARD = 0, BACKWARD = 1 } reencrypt_direction;
	enum { REENCRYPT = 0, ENCRYPT = 1, DECRYPT = 2 } reencrypt_mode;

	char header_file_org[PATH_MAX];
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
	if (!ARG_SET(OPT_DEBUG_ID))
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

static const char *hdr_device(const struct reenc_ctx *rc)
{
	return rc->device_header ?: rc->device;
}

/* Depends on the first two fields of LUKS1 header format, magic and version */
static int device_check(struct reenc_ctx *rc, const char *device, header_magic set_magic, bool exclusive)
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
	devfd = open(device, O_RDWR | ((S_ISBLK(st.st_mode) && exclusive) ? O_EXCL : 0)); /* lgtm[cpp/toctou-race-condition] */
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

	s = read_buffer(devfd, buf, buf_size);
	if (s != (ssize_t)buf_size) {
		log_err(_("Cannot read device %s."), device);
		r = -EIO;
		goto out;
	}

	/* Be sure that we do not process new version of header */
	memcpy((void*)&version, &buf[MAGIC_L], sizeof(uint16_t));
	version = be16_to_cpu(version);

	if (set_magic == MAKE_UNUSABLE && !memcmp(buf, MAGIC, MAGIC_L) &&
	    version == 1) {
		log_verbose(_("Marking LUKS1 device %s unusable."), device);
		memcpy(buf, NOMAGIC, MAGIC_L);
		r = 0;
	} else if (set_magic == CHECK_UNUSABLE && version == 1) {
		r = memcmp(buf, NOMAGIC, MAGIC_L) ? -EINVAL : 0;
		if (rc && !r)
			rc->device_uuid = strndup(&buf[0xa8], 40);
		goto out;
	} else
		r = -EINVAL;

	if (!r && version == 1) {
		if (lseek(devfd, 0, SEEK_SET) == -1)
			goto out;
		s = write_buffer(devfd, buf, buf_size);
		if (s != (ssize_t)buf_size || fsync(devfd) < 0) {
			log_err(_("Cannot write device %s."), device);
			r = -EIO;
		}
		if (rc && s > 0 && set_magic == MAKE_UNUSABLE)
			rc->stained = true;
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
	if (snprintf(rc->log_buf, SECTOR_SIZE, "# LUKS reencryption log, DO NOT EDIT OR DELETE.\n"
	    "version = %d\nUUID = %s\ndirection = %d\nmode = %d\n"
	    "offset = %" PRIu64 "\nshift = %" PRIu64 "\n# EOF\n",
	    2, rc->device_uuid, rc->reencrypt_direction, rc->reencrypt_mode,
	    rc->device_offset, rc->device_shift) < 0)
		return -EINVAL;

	if (lseek(rc->log_fd, 0, SEEK_SET) == -1)
		return -EIO;

	r = write_buffer(rc->log_fd, rc->log_buf, SECTOR_SIZE);
	if (r != SECTOR_SIZE) {
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

	if (lseek(rc->log_fd, 0, SEEK_SET) == -1 ||
	    read_buffer(rc->log_fd, rc->log_buf, SECTOR_SIZE) != SECTOR_SIZE) {
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
				log_err(_("Wrong log format."));
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
	rc->log_fd = -1;
}

static int open_log(struct reenc_ctx *rc)
{
	int flags = ARG_SET(OPT_USE_FSYNC_ID) ? O_SYNC : 0;

	rc->log_fd = open(rc->log_file, O_RDWR|O_EXCL|O_CREAT|flags, S_IRUSR|S_IWUSR);
	if (rc->log_fd != -1) {
		log_dbg("Created LUKS reencryption log file %s.", rc->log_file);
		rc->stained = 0;
	} else if (errno == EEXIST) {
		log_std(_("Log file %s exists, resuming reencryption.\n"), rc->log_file);
		rc->log_fd = open(rc->log_file, O_RDWR|flags);
		rc->in_progress = true;
	}

	if (rc->log_fd == -1)
		return -EINVAL;

	if (!rc->in_progress && write_log(rc) < 0)
		return -EIO;

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
	    (r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	log_verbose(_("Activating temporary device using old LUKS header."));
	if ((r = crypt_activate_by_passphrase(cd, rc->header_file_org,
		ARG_INT32(OPT_KEY_SLOT_ID), pwd_old, pwd_old_len,
		CRYPT_ACTIVATE_READONLY|CRYPT_ACTIVATE_PRIVATE)) < 0)
		goto out;

	if ((r = crypt_init_data_device(&cd_new, rc->header_file_new, rc->device)) ||
	    (r = crypt_load(cd_new, CRYPT_LUKS1, NULL)))
		goto out;

	log_verbose(_("Activating temporary device using new LUKS header."));
	if ((r = crypt_activate_by_passphrase(cd_new, rc->header_file_new,
		ARG_INT32(OPT_KEY_SLOT_ID), pwd_new, pwd_new_len,
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
			     uint64_t metadata_size,
			     uint64_t keyslots_size,
			     void *params)
{
	struct crypt_device *cd_new = NULL;
	int i, r;

	if ((r = crypt_init(&cd_new, rc->header_file_new)))
		goto out;

	if (ARG_SET(OPT_USE_RANDOM_ID))
		crypt_set_rng_type(cd_new, CRYPT_RNG_RANDOM);
	else if (ARG_SET(OPT_USE_URANDOM_ID))
		crypt_set_rng_type(cd_new, CRYPT_RNG_URANDOM);

	r = set_pbkdf_params(cd_new, CRYPT_LUKS1);
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

	r = crypt_format(cd_new, CRYPT_LUKS1, cipher, cipher_mode, uuid, key, key_size, params);
	check_signal(&r);
	if (r < 0)
		goto out;
	log_verbose(_("New LUKS header for device %s created."), rc->device);

	for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS1); i++) {
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

static int backup_luks_headers(struct reenc_ctx *rc)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_luks1 params = {0};
	char cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	char *key = NULL;
	size_t key_size;
	uint64_t mdata_size = 0, keyslots_size = 0;
	int r;

	log_dbg("Creating LUKS header backup for device %s.", hdr_device(rc));

	if ((r = crypt_init(&cd, hdr_device(rc))) ||
	    (r = crypt_load(cd, CRYPT_LUKS1, NULL)))
		goto out;

	if ((r = crypt_header_backup(cd, CRYPT_LUKS1, rc->header_file_org)))
		goto out;

	log_verbose(_("%s header backup of device %s created."), "LUKS1", rc->device);

	/* For decrypt, new header will be fake one, so we are done here. */
	if (rc->reencrypt_mode == DECRYPT)
		goto out;

	rc->data_offset = crypt_get_data_offset(cd) + ROUND_SECTOR(ARG_UINT64(OPT_REDUCE_DEVICE_SIZE_ID));

	if ((r = create_empty_header(rc->header_file_new)))
		goto out;

	params.hash = ARG_STR(OPT_HASH_ID) ?: DEFAULT_LUKS1_HASH;
	params.data_device = rc->device;

	if (ARG_SET(OPT_CIPHER_ID)) {
		r = crypt_parse_name_and_mode(ARG_STR(OPT_CIPHER_ID), cipher, NULL, cipher_mode);
		if (r < 0) {
			log_err(_("No known cipher specification pattern detected."));
			goto out;
		}
	}

	key_size = ARG_SET(OPT_KEY_SIZE_ID) ? ARG_UINT32(OPT_KEY_SIZE_ID) / 8 : (uint32_t)crypt_get_volume_key_size(cd);

	if (ARG_SET(OPT_KEEP_KEY_ID)) {
		log_dbg("Keeping key from old header.");
		key_size = crypt_get_volume_key_size(cd);
		key = crypt_safe_alloc(key_size);
		if (!key) {
			r = -ENOMEM;
			goto out;
		}
		r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, key, &key_size,
			rc->p[rc->keyslot].password, rc->p[rc->keyslot].passwordLen);
	} else if (ARG_SET(OPT_VOLUME_KEY_FILE_ID)) {
		log_dbg("Loading new key from file.");
		r = tools_read_vk(ARG_STR(OPT_VOLUME_KEY_FILE_ID), &key, key_size);
	}

	if (r < 0)
		goto out;

	r = create_new_header(rc, cd,
		ARG_SET(OPT_CIPHER_ID) ? cipher : crypt_get_cipher(cd),
		ARG_SET(OPT_CIPHER_ID) ? cipher_mode : crypt_get_cipher_mode(cd),
		crypt_get_uuid(cd),
		key,
		key_size,
		mdata_size,
		keyslots_size,
		(void*)&params);

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
	char cipher [MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	const char *header_file_fake;
	int r;

	log_dbg("Creating fake (cipher_null) header for %s device.",
		(rc->reencrypt_mode == DECRYPT) ? "new" : "original");

	header_file_fake = (rc->reencrypt_mode == DECRYPT) ? rc->header_file_new : rc->header_file_org;

	if (!ARG_SET(OPT_KEY_SIZE_ID))
		ARG_SET_UINT32(OPT_KEY_SIZE_ID, DEFAULT_LUKS1_KEYBITS);

	if (ARG_SET(OPT_CIPHER_ID)) {
		r = crypt_parse_name_and_mode(ARG_STR(OPT_CIPHER_ID), cipher, NULL, cipher_mode);
		if (r < 0) {
			log_err(_("No known cipher specification pattern detected."));
			goto out;
		}
	}

	r = create_empty_header(header_file_fake);
	if (r < 0)
		return r;

	params.hash = ARG_STR(OPT_HASH_ID) ?: DEFAULT_LUKS1_HASH;
	params.data_alignment = 0;
	params.data_device = rc->device;

	r = crypt_init(&cd_new, header_file_fake);
	if (r < 0)
		return r;

	r = crypt_format(cd_new, CRYPT_LUKS1, "cipher_null", "ecb",
			 NO_UUID, NULL, ARG_UINT32(OPT_KEY_SIZE_ID) / 8, &params);
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

	params.data_alignment = ROUND_SECTOR(ARG_UINT64(OPT_REDUCE_DEVICE_SIZE_ID));
	r = create_new_header(rc, NULL,
		ARG_SET(OPT_CIPHER_ID) ? cipher : DEFAULT_LUKS1_CIPHER,
		ARG_SET(OPT_CIPHER_ID) ? cipher_mode : DEFAULT_LUKS1_MODE,
		NULL, NULL,
		ARG_UINT32(OPT_KEY_SIZE_ID) / 8,
		0,
		0,
		(void*)&params);
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
	if (ARG_SET(OPT_ENCRYPT_ID) && rc->device_header) {
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
		r = crypt_header_restore(cd, CRYPT_LUKS1, rc->header_file_new);
	}

	crypt_free(cd);
out:
	if (r)
		log_err(_("Cannot restore %s header on device %s."), "LUKS1", hdr_device(rc));
	else {
		log_verbose(_("%s header on device %s restored."), "LUKS1", hdr_device(rc));
		rc->stained = false;
	}
	return r;
}

static int copy_data_forward(struct reenc_ctx *rc, int fd_old, int fd_new,
			     size_t block_size, void *buf, uint64_t *bytes)
{
	ssize_t s1, s2;
	int r = -EIO;
	char *backing_file = NULL;
	struct tools_progress_params prog_parms = {
		.frequency = ARG_UINT32(OPT_PROGRESS_FREQUENCY_ID),
		.batch_mode = ARG_SET(OPT_BATCH_MODE_ID),
		.json_output = ARG_SET(OPT_PROGRESS_JSON_ID),
		.interrupt_message = _("\nReencryption interrupted."),
		.device = tools_get_device_name(rc->device, &backing_file)
	};

	assert(rc);
	assert(bytes);
	assert(buf);

	log_dbg("Reencrypting in forward direction.");

	if (lseek(fd_old, rc->device_offset, SEEK_SET) < 0 ||
	    lseek(fd_new, rc->device_offset, SEEK_SET) < 0) {
		log_err(_("Cannot seek to device offset."));
		goto out;
	}

	rc->resume_bytes = *bytes = rc->device_offset;

	tools_progress(rc->device_size, *bytes, &prog_parms);

	if (write_log(rc) < 0)
		goto out;

	while (!quit && rc->device_offset < rc->device_size) {
		if ((rc->device_size - rc->device_offset) < (uint64_t)block_size)
			block_size = rc->device_size - rc->device_offset;
		s1 = read_buffer(fd_old, buf, block_size);
		if (s1 < 0 || ((size_t)s1 != block_size)) {
			log_dbg("Read error, expecting %zu, got %zd.",
				block_size, s1);
			goto out;
		}

		s2 = write_buffer(fd_new, buf, s1);
		if (s2 < 0 || s2 != s1) {
			log_dbg("Write error, expecting %zd, got %zd.",
				s1, s2);
			goto out;
		}

		rc->device_offset += s2;
		if (ARG_SET(OPT_WRITE_LOG_ID) && write_log(rc) < 0)
			goto out;

		if (ARG_SET(OPT_USE_FSYNC_ID) && fsync(fd_new) < 0) {
			log_dbg("Write error, fsync.");
			goto out;
		}

		*bytes += (uint64_t)s2;

		tools_progress(rc->device_size, *bytes, &prog_parms);
	}

	r = 0;
out:
	free(backing_file);
	return quit ? -EAGAIN : r;
}

static int copy_data_backward(struct reenc_ctx *rc, int fd_old, int fd_new,
			      size_t block_size, void *buf, uint64_t *bytes)
{
	ssize_t s1, s2, working_block;
	off_t working_offset;
	int r = -EIO;
	char *backing_file = NULL;
	struct tools_progress_params prog_parms = {
		.frequency = ARG_UINT32(OPT_PROGRESS_FREQUENCY_ID),
		.batch_mode = ARG_SET(OPT_BATCH_MODE_ID),
		.json_output = ARG_SET(OPT_PROGRESS_JSON_ID),
		.interrupt_message = _("\nReencryption interrupted."),
		.device = tools_get_device_name(rc->device, &backing_file)
	};

	log_dbg("Reencrypting in backward direction.");

	if (!rc->in_progress) {
		rc->device_offset = rc->device_size;
		rc->resume_bytes = 0;
		*bytes = 0;
	} else {
		rc->resume_bytes = rc->device_size - rc->device_offset;
		*bytes = rc->resume_bytes;
	}

	tools_progress(rc->device_size, *bytes, &prog_parms);

	if (write_log(rc) < 0)
		goto out;

	/* dirty the device during ENCRYPT mode */
	rc->stained = true;

	while (!quit && rc->device_offset) {
		if (rc->device_offset < block_size) {
			working_offset = 0;
			working_block = rc->device_offset;
		} else {
			working_offset = rc->device_offset - block_size;
			working_block = block_size;
		}

		if (lseek(fd_old, working_offset, SEEK_SET) < 0 ||
		    lseek(fd_new, working_offset, SEEK_SET) < 0) {
			log_err(_("Cannot seek to device offset."));
			goto out;
		}

		s1 = read_buffer(fd_old, buf, working_block);
		if (s1 < 0 || (s1 != working_block)) {
			log_dbg("Read error, expecting %zu, got %zd.",
				block_size, s1);
			goto out;
		}

		s2 = write_buffer(fd_new, buf, s1);
		if (s2 < 0 || s2 != s1) {
			log_dbg("Write error, expecting %zd, got %zd.",
				s1, s2);
			goto out;
		}

		rc->device_offset -= s2;
		if (ARG_SET(OPT_WRITE_LOG_ID) && write_log(rc) < 0)
			goto out;

		if (ARG_SET(OPT_USE_FSYNC_ID) && fsync(fd_new) < 0) {
			log_dbg("Write error, fsync.");
			goto out;
		}

		*bytes += (uint64_t)s2;

		tools_progress(rc->device_size, *bytes, &prog_parms);
	}

	r = 0;
out:
	free(backing_file);
	return quit ? -EAGAIN : r;
}

static int detect_interrupt(uint64_t size __attribute__((unused)),
			  uint64_t offset __attribute__((unused)),
			  void *usrptr __attribute__((unused)))
{
	int r = 0;

	check_signal(&r);

	return r;
}

static int copy_data(struct reenc_ctx *rc)
{
	struct crypt_device *wipe_cd;
	size_t block_size = ARG_UINT32(OPT_BLOCK_SIZE_ID) * 1024 * 1024;
	int fd_old = -1, fd_new = -1;
	int r = -EINVAL;
	void *buf = NULL;
	uint64_t bytes = 0;

	log_dbg("Data copy preparation.");

	fd_old = open(rc->crypt_path_org, O_RDONLY | (ARG_SET(OPT_USE_DIRECTIO_ID) ? O_DIRECT : 0));
	if (fd_old == -1) {
		log_err(_("Cannot open temporary LUKS device."));
		goto out;
	}

	fd_new = open(rc->crypt_path_new, O_WRONLY | (ARG_SET(OPT_USE_DIRECTIO_ID) ? O_DIRECT : 0));
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

	if (ARG_SET(OPT_DEVICE_SIZE_ID))
		rc->device_size = ARG_UINT64(OPT_DEVICE_SIZE_ID);
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
		if (crypt_init(&wipe_cd, rc->crypt_path_new) == 0) {
			log_dbg("Zeroing rest of device.");
			(void)crypt_wipe(wipe_cd, NULL, CRYPT_WIPE_ZERO,
				   rc->device_size_org_real, bytes, block_size,
				   !ARG_SET(OPT_USE_DIRECTIO_ID) ? CRYPT_WIPE_NO_DIRECT_IO : 0,
				   detect_interrupt, NULL);
			crypt_free(wipe_cd);
		}
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

	if (ARG_SET(OPT_ENCRYPT_ID)) {
		rc->device_uuid = strdup(NO_UUID);
		return 0;
	}

	if (ARG_SET(OPT_DECRYPT_ID) && ARG_SET(OPT_UUID_ID)) {
		r = uuid_parse(ARG_STR(OPT_UUID_ID), device_uuid);
		if (!r)
			rc->device_uuid = strdup(ARG_STR(OPT_UUID_ID));
		else
			log_err(_("Provided UUID is invalid."));

		return r;
	}

	/* Try to load LUKS from device */
	if ((r = crypt_init(&cd, hdr_device(rc))))
		return r;
	crypt_set_log_callback(cd, _quiet_log, NULL);
	r = crypt_load(cd, CRYPT_LUKS1, NULL);
	if (!r)
		rc->device_uuid = strdup(crypt_get_uuid(cd));
	else
		/* Reencryption already in progress - magic header? */
		r = device_check(rc, hdr_device(rc), CHECK_UNUSABLE, true);

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

	retry_count = ARG_UINT32(OPT_TRIES_ID) ?: 1;
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

	r = tools_get_key(NULL, &password, &passwordLen, ARG_UINT64(OPT_KEYFILE_OFFSET_ID),
			  ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID), 0, 0, 0, cd);
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
		if (r >= 0 && ARG_INT32(OPT_KEY_SLOT_ID) == CRYPT_ANY_SLOT &&
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
		if (ARG_SET(OPT_KEY_FILE_ID))
			r = init_keyfile(rc, NULL, ARG_INT32(OPT_KEY_SLOT_ID));
		else
			r = init_passphrase1(rc, NULL, _("Enter new passphrase: "), ARG_INT32(OPT_KEY_SLOT_ID), 0, 1);
		return r > 0 ? 0 : r;
	}

	if ((r = crypt_init_data_device(&cd, device, rc->device)) ||
	    (r = crypt_load(cd, CRYPT_LUKS1, NULL))) {
		crypt_free(cd);
		return r;
	}

	if (ARG_INT32(OPT_KEY_SLOT_ID) != CRYPT_ANY_SLOT)
		snprintf(msg, sizeof(msg),
			 _("Enter passphrase for key slot %d: "), ARG_INT32(OPT_KEY_SLOT_ID));
	else
		snprintf(msg, sizeof(msg), _("Enter any existing passphrase: "));

	if (ARG_SET(OPT_KEY_FILE_ID)) {
		r = init_keyfile(rc, cd, ARG_INT32(OPT_KEY_SLOT_ID));
	} else if (rc->in_progress ||
		   ARG_INT32(OPT_KEY_SLOT_ID) != CRYPT_ANY_SLOT ||
		   rc->reencrypt_mode == DECRYPT) {
		r = init_passphrase1(rc, cd, msg, ARG_INT32(OPT_KEY_SLOT_ID), 1, 0);
	} else for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS1); i++) {
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

	memset(rc, 0, sizeof(*rc));

	rc->in_progress = false;
	rc->stained = true;
	rc->log_fd = -1;

	if (!(rc->device = strndup(device, PATH_MAX)))
		return -ENOMEM;

	if (ARG_SET(OPT_HEADER_ID) && !(rc->device_header = strndup(ARG_STR(OPT_HEADER_ID), PATH_MAX)))
		return -ENOMEM;

	if (device_check(rc, rc->device, CHECK_OPEN, true) < 0)
		return -EINVAL;

	if (initialize_uuid(rc)) {
		log_err(_("Device %s is not a valid LUKS device."), device);
		return -EINVAL;
	}

	if (ARG_INT32(OPT_KEY_SLOT_ID) != CRYPT_ANY_SLOT &&
	    ARG_INT32(OPT_KEY_SLOT_ID) >= crypt_keyslot_max(CRYPT_LUKS1)) {
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
		if (ARG_SET(OPT_UUID_ID)) {
			log_err(_("No decryption in progress, provided UUID can "
			"be used only to resume suspended decryption process."));
			return -EINVAL;
		}

		if (!ARG_SET(OPT_REDUCE_DEVICE_SIZE_ID))
			rc->reencrypt_direction = FORWARD;
		else {
			rc->reencrypt_direction = BACKWARD;
			rc->device_offset = (uint64_t)~0;
		}

		if (ARG_SET(OPT_ENCRYPT_ID))
			rc->reencrypt_mode = ENCRYPT;
		else if (ARG_SET(OPT_DECRYPT_ID))
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
	}

	for (i = 0; i < MAX_SLOT; i++)
		crypt_safe_free(rc->p[i].password);

	free(rc->device);
	free(rc->device_header);
	free(rc->device_uuid);
}

int reencrypt_luks1(const char *device)
{
	int r = -EINVAL;
	struct reenc_ctx *rc;

	rc = malloc(sizeof(*rc));
	if (!rc)
		return -ENOMEM;

	if (!ARG_SET(OPT_BATCH_MODE_ID))
		log_verbose(_("Reencryption will change: %s%s%s%s%s%s."),
			ARG_SET(OPT_KEEP_KEY_ID) ? "" :  _("volume key"),
			(!ARG_SET(OPT_KEEP_KEY_ID) && ARG_SET(OPT_HASH_ID)) ? ", " : "",
			ARG_SET(OPT_HASH_ID) ? _("set hash to ") : "", ARG_STR(OPT_HASH_ID) ?: "",
			ARG_SET(OPT_CIPHER_ID) ? _(", set cipher to "): "", ARG_STR(OPT_CIPHER_ID) ?: "");
	/* FIXME: block all non pbkdf2 pkdfs */

	set_int_handler(0);

	if ((r = initialize_context(rc, device)))
		goto out;

	log_dbg("Running reencryption.");

	if (!rc->in_progress) {
		if ((r = initialize_passphrase(rc, hdr_device(rc))))
			goto out;

		log_dbg("Storing backup of LUKS headers.");
		if (rc->reencrypt_mode == ENCRYPT) {
			/* Create fake header for existing device */
			if ((r = backup_fake_header(rc)))
				goto out;
		} else {
			if ((r = backup_luks_headers(rc)))
				goto out;
			/* Create fake header for decrypted device */
			if (rc->reencrypt_mode == DECRYPT &&
			    (r = backup_fake_header(rc)))
				goto out;
			if ((r = device_check(rc, hdr_device(rc), MAKE_UNUSABLE, true)))
				goto out;
		}
	} else {
		if ((r = initialize_passphrase(rc, ARG_SET(OPT_DECRYPT_ID) ? rc->header_file_org : rc->header_file_new)))
			goto out;
	}

	if (!ARG_SET(OPT_KEEP_KEY_ID)) {
		log_dbg("Running data area reencryption.");
		if ((r = activate_luks_headers(rc)))
			goto out;

		if ((r = copy_data(rc)))
			goto out;
	} else
		log_dbg("Keeping existing key, skipping data area reencryption.");

	// FIXME: fix error path above to not skip this
	if (rc->reencrypt_mode != DECRYPT)
		r = restore_luks_header(rc);
	else
		rc->stained = false;
out:
	destroy_context(rc);
	free(rc);

	return r;
}

int reencrypt_luks1_in_progress(const char *device)
{
	struct stat st;

	if (stat(device, &st) || (size_t)st.st_size < pagesize())
		return -EINVAL;

	return device_check(NULL, device, CHECK_UNUSABLE, false);
}
