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
#include "utils_dm.h"

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

char *crypt_lookup_dev(const char *dev_id);

int sector_size_for_device(const char *device);
int device_read_ahead(const char *dev, uint32_t *read_ahead);
ssize_t write_blockwise(int fd, void *buf, size_t count);
ssize_t read_blockwise(int fd, void *_buf, size_t count);
ssize_t write_lseek_blockwise(int fd, char *buf, size_t count, off_t offset);
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
