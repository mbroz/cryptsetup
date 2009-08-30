#include <sys/ioctl.h>
#include <dirent.h>
#include <errno.h>
#include <libdevmapper.h>
#include <fcntl.h>
#include <linux/fs.h>

#include "internal.h"
#include "luks.h"

#define DEVICE_DIR		"/dev"
#define DM_UUID_PREFIX		"CRYPT-"
#define DM_UUID_PREFIX_LEN	6
#define DM_UUID_LEN		UUID_STRING_L
#define DM_CRYPT_TARGET		"crypt"
#define RETRY_COUNT		5

static int _dm_use_count = 0;
static struct crypt_device *_context = NULL;

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

int dm_init(struct crypt_device *context, int check_kernel)
{
	if (!_dm_use_count++) {
		if (check_kernel && !_dm_simple(DM_DEVICE_LIST_VERSIONS, NULL))
			return -1;
		dm_log_init(set_dm_error);
		dm_log_init_verbose(10);
	}

	if (context)
		_context = context;

	return 1;	/* unsafe memory */
}

void dm_exit(void)
{
	if (_dm_use_count && (!--_dm_use_count)) {
		dm_log_init_verbose(0);
		dm_log_init(NULL);
		dm_lib_release();
		_context = NULL;
	}
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

static char *get_params(const char *device, uint64_t skip, uint64_t offset,
			const char *cipher, size_t key_size, const char *key)
{
	char *params;
	char *hexkey;
	int i;

	hexkey = safe_alloc(key_size * 2 + 1);
	if (!hexkey)
		return NULL;

	for(i = 0; i < key_size; i++)
		sprintf(&hexkey[i * 2], "%02x", (unsigned char)key[i]);

	params = safe_alloc(strlen(hexkey) + strlen(cipher) + strlen(device) + 64);
	if (!params)
		goto out;

	sprintf(params, "%s %s %" PRIu64 " %s %" PRIu64,
	        cipher, hexkey, skip, device, offset);

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

	if (name && !dm_task_set_name(dmt, name))
		goto out;

	r = dm_task_run(dmt);

      out:
	dm_task_destroy(dmt);
	return r;
}

static int _error_device(const char *name, size_t size)
{
	struct dm_task *dmt;
	int r = 0;

	if (!(dmt = dm_task_create(DM_DEVICE_RELOAD)))
		return 0;

	if (!dm_task_set_name(dmt, name))
		goto error;

	if (!dm_task_add_target(dmt, UINT64_C(0), size, "error", ""))
		goto error;

	if (!dm_task_set_ro(dmt))
		goto error;

	if (!dm_task_no_open_count(dmt))
		goto error;

	if (!dm_task_run(dmt))
		goto error;

	if (!_dm_simple(DM_DEVICE_RESUME, name)) {
		_dm_simple(DM_DEVICE_CLEAR, name);
		goto error;
	}

	r = 1;

error:
	dm_task_destroy(dmt);
	return r;
}

int dm_remove_device(const char *name, int force, uint64_t size)
{
	int r = -EINVAL;
	int retries = force ? RETRY_COUNT : 1;

	if (!name || (force && !size))
		return -EINVAL;

	/* If force flag is set, replace device with error, read-only target.
	 * it should stop processes from reading it and also removed underlying
	 * device from mapping, so it is usable again.
	 * Force flag should be used only for temporary devices, which are
	 * intended to work inside cryptsetup only!
	 * Anyway, if some process try to read temporary cryptsetup device,
	 * it is bug - no other process should try touch it (e.g. udev).
	 */
	if (force) {
		 _error_device(name, size);
		retries = RETRY_COUNT;
	}

	do {
		r = _dm_simple(DM_DEVICE_REMOVE, name) ? 0 : -EINVAL;
		if (--retries && r) {
			sleep(1);
		}
	} while (r == -EINVAL && retries);

	dm_task_update_nodes();

	return r;
}

int dm_create_device(const char *name,
		     const char *device,
		     const char *cipher,
		     const char *uuid,
		     uint64_t size,
		     uint64_t skip,
		     uint64_t offset,
		     size_t key_size,
		     const char *key,
		     int read_only,
		     int reload)
{
	struct dm_task *dmt = NULL;
	struct dm_task *dmt_query = NULL;
	struct dm_info dmi;
	char *params = NULL;
	char *error = NULL;
	char dev_uuid[DM_UUID_PREFIX_LEN + DM_UUID_LEN + 1] = {0};
	int r = -EINVAL;
	uint32_t read_ahead = 0;

	params = get_params(device, skip, offset, cipher, key_size, key);
	if (!params)
		goto out_no_removal;
 
	if (uuid) {
		strncpy(dev_uuid, DM_UUID_PREFIX, DM_UUID_PREFIX_LEN);
		strncpy(dev_uuid + DM_UUID_PREFIX_LEN, uuid, DM_UUID_LEN);
		dev_uuid[DM_UUID_PREFIX_LEN + DM_UUID_LEN] = '\0';
	}

	if (!(dmt = dm_task_create(reload ? DM_DEVICE_RELOAD
	                                  : DM_DEVICE_CREATE)))
		goto out_no_removal;
	if (!dm_task_set_name(dmt, name))
		goto out_no_removal;
	if (read_only && !dm_task_set_ro(dmt))
		goto out_no_removal;
	if (!dm_task_add_target(dmt, 0, size, DM_CRYPT_TARGET, params))
		goto out_no_removal;

#ifdef DM_READ_AHEAD_MINIMUM_FLAG
	if (_dev_read_ahead(device, &read_ahead) &&
	    !dm_task_set_read_ahead(dmt, read_ahead, DM_READ_AHEAD_MINIMUM_FLAG))
		goto out_no_removal;
#endif

	if (uuid && !dm_task_set_uuid(dmt, dev_uuid))
		goto out_no_removal;

	if (!dm_task_run(dmt))
		goto out_no_removal;

	if (reload) {
		dm_task_destroy(dmt);
		if (!(dmt = dm_task_create(DM_DEVICE_RESUME)))
			goto out;
		if (!dm_task_set_name(dmt, name))
			goto out;
		if (uuid && !dm_task_set_uuid(dmt, dev_uuid))
			goto out;
		if (!dm_task_run(dmt))
			goto out;
	}

	if (!dm_task_get_info(dmt, &dmi))
		goto out;

	r = 0;
out:
	if (r < 0 && !reload) {
		if (get_error())
			error = strdup(get_error());

		dm_remove_device(name, 0, 0);

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

int dm_status_device(const char *name)
{
	struct dm_task *dmt;
	struct dm_info dmi;
	uint64_t start, length;
	char *target_type, *params;
	void *next = NULL;
	int r = -EINVAL;

	if (!(dmt = dm_task_create(DM_DEVICE_STATUS)))
		return -EINVAL;

	if (!dm_task_set_name(dmt, name)) {
		r = -EINVAL;
		goto out;
	}

	if (!dm_task_run(dmt)) {
		r = -ENODEV;
		goto out;
	}

	if (!dm_task_get_info(dmt, &dmi)) {
		r = -EINVAL;
		goto out;
	}

	if (!dmi.exists) {
		r = -ENODEV;
		goto out;
	}

	next = dm_get_next_target(dmt, next, &start, &length,
	                          &target_type, &params);
	if (!target_type || strcmp(target_type, DM_CRYPT_TARGET) != 0 ||
	    start != 0 || next)
		r = -EINVAL;
	else
		r = (dmi.open_count > 0);
out:
	if (dmt)
		dm_task_destroy(dmt);

	return r;
}

int dm_query_device(const char *name,
		    char **device,
		    uint64_t *size,
		    uint64_t *skip,
		    uint64_t *offset,
		    char **cipher,
		    int *key_size,
		    char **key,
		    int *read_only)
{
	struct dm_task *dmt;
	struct dm_info dmi;
	uint64_t start, length, val64;
	char *target_type, *params, *rcipher, *key_, *rdevice, *endp, buffer[3];
	void *next = NULL;
	int i, r = -EINVAL;

	if (!(dmt = dm_task_create(DM_DEVICE_TABLE)))
		goto out;
	if (!dm_task_set_name(dmt, name))
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

	if (size)
		*size = length;

	rcipher = strsep(&params, " ");
	/* cipher */
	if (cipher)
		*cipher = strdup(rcipher);

	/* skip */
	key_ = strsep(&params, " ");
	if (!params)
		goto out;
	val64 = strtoull(params, &params, 10);
	if (*params != ' ')
		goto out;
	params++;
	if (skip)
		*skip = val64;

	/* device */
	rdevice = strsep(&params, " ");
	if (device)
		*device = lookup_dev(rdevice);

	/*offset */
	if (!params)
		goto out;
	val64 = strtoull(params, &params, 10);
	if (*params)
		goto out;
	if (offset)
		*offset = val64;

	/* key_size */
	if (key_size)
		*key_size = strlen(key_) / 2;

	/* key */
	if (key_size && key) {
		*key = safe_alloc(*key_size);
		if (!*key) {
			r = -ENOMEM;
			goto out;
		}

		buffer[2] = '\0';
		for(i = 0; i < *key_size; i++) {
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

	/* read_only */
	if (read_only)
		*read_only = dmi.read_only;

	r = (dmi.open_count > 0);
out:
	if (dmt)
		dm_task_destroy(dmt);

	return r;
}

const char *dm_get_dir(void)
{
	return dm_dir();
}
