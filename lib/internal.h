#ifndef INTERNAL_H
#define INTERNAL_H

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>

#define SECTOR_SHIFT		9
#define SECTOR_SIZE		(1 << SECTOR_SHIFT)

/* private struct crypt_options flags */

#define	CRYPT_FLAG_FREE_DEVICE	(1 << 24)
#define	CRYPT_FLAG_FREE_CIPHER	(1 << 25)

#define CRYPT_FLAG_PRIVATE_MASK ((unsigned int)-1 << 24)

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

struct setup_backend {
	const char	*name;
	int		(*init)(void);
	void		(*exit)(void);
	int		(*create)(int reload, struct crypt_options *options,
			          const char *key, const char *uuid);
	int		(*status)(int details, struct crypt_options *options,
			          char **key);
	int		(*remove)(int force, struct crypt_options *options);

	const char *	(*dir)(void);
};

void set_error_va(const char *fmt, va_list va);
void set_error(const char *fmt, ...);
const char *get_error(void);
void *safe_alloc(size_t size);
void safe_free(void *data);
void *safe_realloc(void *data, size_t size);
char *safe_strdup(const char *s);

struct hash_backend *get_hash_backend(const char *name);
void put_hash_backend(struct hash_backend *backend);
int hash(const char *backend_name, const char *hash_name,
         char *result, size_t size,
         const char *passphrase, size_t sizep);

struct setup_backend *get_setup_backend(const char *name);
void put_setup_backend(struct setup_backend *backend);

void hexprint(char *d, int n);

int sector_size_for_device(const char *device);
ssize_t write_blockwise(int fd, const void *buf, size_t count);
ssize_t read_blockwise(int fd, void *_buf, size_t count);
ssize_t write_lseek_blockwise(int fd, const char *buf, size_t count, off_t offset);


int get_key(char *prompt, char **key, unsigned int *passLen, int key_size,
            const char *key_file, int passphrase_fd, int timeout, int how2verify);

#endif /* INTERNAL_H */
