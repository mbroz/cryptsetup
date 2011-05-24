#ifndef _UTILS_DM_H
#define _UTILS_DM_H

/* device-mapper library helpers */
#include <inttypes.h>

struct crypt_device;

/* Device mapper backend - kernel support flags */
#define DM_KEY_WIPE_SUPPORTED (1 << 0)	/* key wipe message */
#define DM_LMK_SUPPORTED      (1 << 1)	/* lmk mode */
#define DM_SECURE_SUPPORTED   (1 << 2)	/* wipe (secure) buffer flag */
#define DM_PLAIN64_SUPPORTED  (1 << 3)	/* plain64 IV */
uint32_t dm_flags(void);

const char *dm_get_dir(void);
int dm_init(struct crypt_device *context, int check_kernel);
void dm_exit(void);
int dm_remove_device(const char *name, int force, uint64_t size);
int dm_status_device(const char *name);
int dm_query_device(const char *name,
		    char **device,
		    uint64_t *size,
		    uint64_t *skip,
		    uint64_t *offset,
		    char **cipher,
		    int *key_size,
		    char **key,
		    int *read_only,
		    int *suspended,
		    char **uuid);
int dm_create_device(const char *name, const char *device, const char *cipher,
		     const char *type, const char *uuid,
		     uint64_t size, uint64_t skip, uint64_t offset,
		     size_t key_size, const char *key,
		     int read_only, int reload);
int dm_suspend_and_wipe_key(const char *name);
int dm_resume_and_reinstate_key(const char *name,
				size_t key_size,
				const char *key);
char *dm_device_path(int major, int minor);
int dm_is_dm_device(int major, int minor);
int dm_is_dm_kernel_name(const char *name);

#endif /* _UTILS_DM_H */
