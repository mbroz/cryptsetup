#ifndef INTERNAL_H
#define INTERNAL_H

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>

#include "nls.h"
#include "utils_crypt.h"
#include "utils_loop.h"

#define SECTOR_SHIFT		9
#define SECTOR_SIZE		(1 << SECTOR_SHIFT)
#define DEFAULT_DISK_ALIGNMENT	1048576 /* 1MiB */
#define DEFAULT_MEM_ALIGNMENT	4096

/* private struct crypt_options flags */

#define	CRYPT_FLAG_FREE_DEVICE	(1 << 24)
#define	CRYPT_FLAG_FREE_CIPHER	(1 << 25)

#define CRYPT_FLAG_PRIVATE_MASK ((unsigned int)-1 << 24)

#define at_least(a, b) ({ __typeof__(a) __at_least = (a); (__at_least >= (b))?__at_least:(b); })

struct crypt_device;

struct hash_type {
	char		*name;
	void		*private;
	int		(*fn)(void *data, int size, char *key,
			      int sizep, const char *passphrase);
};

struct hash_backend {
	const char		*name;
	struct hash_type *	(*get_hashes)(void);
	void			(*free_hashes)(struct hash_type *hashes);
};

struct volume_key {
	size_t keylength;
	char key[];
};

struct volume_key *crypt_alloc_volume_key(unsigned keylength, const char *key);
struct volume_key *crypt_generate_volume_key(struct crypt_device *cd, unsigned keylength);
void crypt_free_volume_key(struct volume_key *vk);

int crypt_confirm(struct crypt_device *cd, const char *msg);

void set_error_va(const char *fmt, va_list va);
void set_error(const char *fmt, ...);
const char *get_error(void);

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

int sector_size_for_device(const char *device);
ssize_t write_blockwise(int fd, const void *buf, size_t count);
ssize_t read_blockwise(int fd, void *_buf, size_t count);
ssize_t write_lseek_blockwise(int fd, const char *buf, size_t count, off_t offset);
int device_ready(struct crypt_device *cd, const char *device, int mode);
int get_device_infos(const char *device,
		     int open_exclusive,
		     int *readonly,
		     uint64_t *size);
int device_check_and_adjust(struct crypt_device *cd,
			    const char *device,
			    int open_exclusive,
			    uint64_t *size,
			    uint64_t *offset,
			    int *read_only);
int wipe_device_header(const char *device, int sectors);

void logger(struct crypt_device *cd, int class, const char *file, int line, const char *format, ...);
#define log_dbg(x...) logger(NULL, CRYPT_LOG_DEBUG, __FILE__, __LINE__, x)
#define log_std(c, x...) logger(c, CRYPT_LOG_NORMAL, __FILE__, __LINE__, x)
#define log_verbose(c, x...) logger(c, CRYPT_LOG_VERBOSE, __FILE__, __LINE__, x)
#define log_err(c, x...) do { \
	logger(c, CRYPT_LOG_ERROR, __FILE__, __LINE__, x); \
	set_error(x); } while(0)

int crypt_get_debug_level(void);
void debug_processes_using_device(const char *name);

int crypt_memlock_inc(struct crypt_device *ctx);
int crypt_memlock_dec(struct crypt_device *ctx);

void get_topology_alignment(const char *device,
			    unsigned long *required_alignment, /* bytes */
			    unsigned long *alignment_offset,   /* bytes */
			    unsigned long default_alignment);

enum { CRYPT_RND_NORMAL = 0, CRYPT_RND_KEY = 1 };
int crypt_random_init(struct crypt_device *ctx);
int crypt_random_get(struct crypt_device *ctx, char *buf, size_t len, int quality);
void crypt_random_exit(void);
int crypt_random_default_key_rng(void);

int crypt_plain_hash(struct crypt_device *ctx,
		     const char *hash_name,
		     char *key, size_t key_size,
		     const char *passphrase, size_t passphrase_size);

#endif /* INTERNAL_H */
