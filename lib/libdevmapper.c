#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <libdevmapper.h>
#include <fcntl.h>
#include <linux/fs.h>

#include "libcryptsetup.h"
#include "internal.h"
#include "luks.h"

#define DEVICE_DIR		"/dev"
#define DM_UUID_PREFIX		"CRYPT-"
#define DM_UUID_PREFIX_LEN	6
#define DM_UUID_LEN		UUID_STRING_L
#define DM_CRYPT_TARGET		"crypt"
#define RETRY_COUNT		5

static void set_dm_error(int level, const char *file, int line,
                         const char *f, ...)
{
	va_list va;

	if (level > 3)
		return;

	va_start(va, f);
	set_error_va(f, va);
	va_end(va);
}

static int _dm_simple(int task, const char *name);

static int dm_init(void)
{
	dm_log_init(set_dm_error);
	if (!_dm_simple(DM_DEVICE_LIST_VERSIONS, "test")) {
		set_error("Cannot communicate with device-mapper. Is the dm_mod module loaded?");
		return -1;
	}

	return 1;	/* unsafe memory */
}

static void dm_exit(void)
{
	dm_log_init(NULL);
	dm_lib_release();
}

static char *__lookup_dev(char *path, dev_t dev)
{
	struct dirent *entry;
	struct stat st;
	char *ptr;
	char *result = NULL;
	DIR *dir;
	int space;

	path[PATH_MAX - 1] = '\0';
	ptr = path + strlen(path);
	*ptr++ = '/';
	*ptr = '\0';
	space = PATH_MAX - (ptr - path);

	dir = opendir(path);
	if (!dir)
		return NULL;

	while((entry = readdir(dir))) {
		if (entry->d_name[0] == '.' &&
		    (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' &&
		                                  entry->d_name[2] == '\0')))
			continue;

		strncpy(ptr, entry->d_name, space);
		if (lstat(path, &st) < 0)
			continue;

		if (S_ISDIR(st.st_mode)) {
			result = __lookup_dev(path, dev);
			if (result)
				break;
		} else if (S_ISBLK(st.st_mode)) {
			if (st.st_rdev == dev) {
				result = strdup(path);
				break;
			}
		}
	}

	closedir(dir);

	return result;
}

static char *lookup_dev(const char *dev)
{
	uint32_t major, minor;
	char buf[PATH_MAX + 1];

	if (sscanf(dev, "%" PRIu32 ":%" PRIu32, &major, &minor) != 2)
		return NULL;

	strncpy(buf, DEVICE_DIR, PATH_MAX);
	buf[PATH_MAX] = '\0';

	return __lookup_dev(buf, makedev(major, minor));
}

static int _dev_read_ahead(const char *dev, uint32_t *read_ahead)
{
	int fd, r = 0;
	long read_ahead_long;

	if ((fd = open(dev, O_RDONLY)) < 0)
		return 0;

	r = ioctl(fd, BLKRAGET, &read_ahead_long) ? 0 : 1;
	close(fd);

	if (r)
		*read_ahead = (uint32_t) read_ahead_long;

	return r;
}

static char *get_params(struct crypt_options *options, const char *key)
{
	char *params;
	char *hexkey;
	int i;

	hexkey = safe_alloc(options->key_size * 2 + 1);
	if (!hexkey) {
		set_error("Memory allocation problem");
		return NULL;
	}

	for(i = 0; i < options->key_size; i++)
		sprintf(&hexkey[i * 2], "%02x", (unsigned char)key[i]);

	params = safe_alloc(strlen(hexkey) + strlen(options->cipher) +
	                    strlen(options->device) + 64);
	if (!params) {
		set_error("Memory allocation problem");
		goto out;
	}

	sprintf(params, "%s %s %" PRIu64 " %s %" PRIu64,
	        options->cipher, hexkey, options->skip,
	        options->device, options->offset);

out:
	safe_free(hexkey);

	return params;
}

/* DM helpers */
static int _dm_simple(int task, const char *name)
{
	int r = 0;
	struct dm_task *dmt;

	if (!(dmt = dm_task_create(task)))
		return 0;

	if (!dm_task_set_name(dmt, name))
		goto out;

	r = dm_task_run(dmt);

      out:
	dm_task_destroy(dmt);
	return r;
}

static int _error_device(struct crypt_options *options)
{
	struct dm_task *dmt;
	int r = 0;

	if (!(dmt = dm_task_create(DM_DEVICE_RELOAD)))
		return 0;

	if (!dm_task_set_name(dmt, options->name))
		goto error;

	if (!dm_task_add_target(dmt, UINT64_C(0), options->size, "error", ""))
		goto error;

	if (!dm_task_set_ro(dmt))
		goto error;

	if (!dm_task_no_open_count(dmt))
		goto error;

	if (!dm_task_run(dmt))
		goto error;

	if (!_dm_simple(DM_DEVICE_RESUME, options->name)) {
		_dm_simple(DM_DEVICE_CLEAR, options->name);
		goto error;
	}

	r = 1;

error:
	dm_task_destroy(dmt);
	return r;
}

static int _dm_remove(struct crypt_options *options, int force)
{
	int r = -EINVAL;
	int retries = force ? RETRY_COUNT : 1;

	/* If force flag is set, replace device with error, read-only target.
	 * it should stop processes from reading it and also removed underlying
	 * device from mapping, so it is usable again.
	 * Force flag should be used only for temporary devices, which are
	 * intended to work inside cryptsetup only!
	 * Anyway, if some process try to read temporary cryptsetup device,
	 * it is bug - no other process should try touch it (e.g. udev).
	 */
	if (force) {
		 _error_device(options);
		retries = RETRY_COUNT;
	}

	do {
		r = _dm_simple(DM_DEVICE_REMOVE, options->name) ? 0 : -EINVAL;
		if (--retries)
			sleep(1);
	} while (r == -EINVAL && retries);

	dm_task_update_nodes();

	return r;
}

static int dm_create_device(int reload, struct crypt_options *options,
			    const char *key, const char *uuid)
{
	struct dm_task *dmt = NULL;
	struct dm_task *dmt_query = NULL;
	struct dm_info dmi;
	char *params = NULL;
	char *error = NULL;
	char dev_uuid[DM_UUID_PREFIX_LEN + DM_UUID_LEN + 1] = {0};
	int r = -EINVAL;
	uint32_t read_ahead = 0;

	params = get_params(options, key);
	if (!params)
		goto out_no_removal;
 
	if (uuid) {
		strncpy(dev_uuid, DM_UUID_PREFIX, DM_UUID_PREFIX_LEN);
		strncpy(dev_uuid + DM_UUID_PREFIX_LEN, uuid, DM_UUID_LEN);
		dev_uuid[DM_UUID_PREFIX_LEN + DM_UUID_LEN] = '\0';
	}

	if (!(dmt = dm_task_create(reload ? DM_DEVICE_RELOAD
	                                  : DM_DEVICE_CREATE)))
		goto out;
	if (!dm_task_set_name(dmt, options->name))
		goto out;
	if (options->flags & CRYPT_FLAG_READONLY && !dm_task_set_ro(dmt))
                goto out;
	if (!dm_task_add_target(dmt, 0, options->size, DM_CRYPT_TARGET, params))
		goto out;

#ifdef DM_READ_AHEAD_MINIMUM_FLAG
	if (_dev_read_ahead(options->device, &read_ahead) &&
	    !dm_task_set_read_ahead(dmt, read_ahead, DM_READ_AHEAD_MINIMUM_FLAG))
		goto out;
#endif

	if (uuid && !dm_task_set_uuid(dmt, dev_uuid))
		goto out;

	if (!dm_task_run(dmt))
		goto out;

	if (reload) {
		dm_task_destroy(dmt);
		if (!(dmt = dm_task_create(DM_DEVICE_RESUME)))
			goto out;
		if (!dm_task_set_name(dmt, options->name))
			goto out;
		if (uuid && !dm_task_set_uuid(dmt, dev_uuid))
			goto out;
		if (!dm_task_run(dmt))
			goto out;
	}

	if (!dm_task_get_info(dmt, &dmi))
		goto out;
	if (dmi.read_only)
		options->flags |= CRYPT_FLAG_READONLY;

	r = 0;
out:
	if (r < 0 && !reload) {
		if (get_error())
			error = strdup(get_error());

		_dm_remove(options, 0);

		if (error) {
			set_error(error);
			free(error);
		}
	}

out_no_removal:
	if (params)
		safe_free(params);
	if (dmt)
		dm_task_destroy(dmt);
	if(dmt_query)
		dm_task_destroy(dmt_query);
	dm_task_update_nodes();
	return r;
}

static int dm_query_device(int details, struct crypt_options *options,
                           char **key)
{
	struct dm_task *dmt;
	struct dm_info dmi;
	uint64_t start, length;
	char *target_type, *params;
	void *next = NULL;
	int r = -EINVAL;

	if (!(dmt = dm_task_create(details ? DM_DEVICE_TABLE
	                                   : DM_DEVICE_STATUS)))
		goto out;
	if (!dm_task_set_name(dmt, options->name))
		goto out;
	r = -ENODEV;
	if (!dm_task_run(dmt))
		goto out;

	r = -EINVAL;
	if (!dm_task_get_info(dmt, &dmi))
		goto out;

	if (!dmi.exists) {
		r = -ENODEV;
		goto out;
	}

	next = dm_get_next_target(dmt, next, &start, &length,
	                          &target_type, &params);
	if (!target_type || strcmp(target_type, DM_CRYPT_TARGET) != 0 ||
	    start != 0 || next)
		goto out;

	options->hash = NULL;
	options->cipher = NULL;
	options->offset = 0;
	options->skip = 0;
	options->size = length;
	if (details) {
		char *cipher, *key_, *device;
		uint64_t val64;

		set_error("Invalid dm table");

		cipher = strsep(&params, " ");
		key_ = strsep(&params, " ");
		if (!params)
			goto out;

		val64 = strtoull(params, &params, 10);
		if (*params != ' ')
			goto out;
		params++;
		options->skip = val64;

		device = strsep(&params, " ");
		if (!params)
			goto out;

		val64 = strtoull(params, &params, 10);
		if (*params)
			goto out;
		options->offset = val64;

		options->cipher = strdup(cipher);
		options->key_size = strlen(key_) / 2;
		if (key) {
			char buffer[3];
			char *endp;
			int i;

			*key = safe_alloc(options->key_size);
			if (!*key) {
				set_error("Out of memory");
				r = -ENOMEM;
				goto out;
			}

			buffer[2] = '\0';
			for(i = 0; i < options->key_size; i++) {
				memcpy(buffer, &key_[i * 2], 2);
				(*key)[i] = strtoul(buffer, &endp, 16);
				if (endp != &buffer[2]) {
					safe_free(key);
					*key = NULL;
					goto out;
				}
			}
		}
		memset(key_, 0, strlen(key_));
		options->device = lookup_dev(device);

		set_error(NULL);
	}

	r = (dmi.open_count > 0);

out:
	if (dmt)
		dm_task_destroy(dmt);
	if (r >= 0) {
		if (options->device)
			options->flags |= CRYPT_FLAG_FREE_DEVICE;
		if (options->cipher)
			options->flags |= CRYPT_FLAG_FREE_CIPHER;
		options->flags &= ~CRYPT_FLAG_READONLY;
		if (dmi.read_only)
			options->flags |= CRYPT_FLAG_READONLY;
	} else {
		if (options->device) {
			free((char *)options->device);
			options->device = NULL;
			options->flags &= ~CRYPT_FLAG_FREE_DEVICE;
		}
		if (options->cipher) {
			free((char *)options->cipher);
			options->cipher = NULL;
			options->flags &= ~CRYPT_FLAG_FREE_CIPHER;
		}
	}
	return r;
}

static int dm_remove_device(int force, struct crypt_options *options)
{
	if (!options || !options->name)
		return -EINVAL;

	return _dm_remove(options, force);;
}


static const char *dm_get_dir(void)
{
	return dm_dir();
}

struct setup_backend setup_libdevmapper_backend = {
	.name = "dm-crypt",
	.init = dm_init,
	.exit = dm_exit,
	.create = dm_create_device,
	.status = dm_query_device,
	.remove = dm_remove_device,
	.dir = dm_get_dir
};
