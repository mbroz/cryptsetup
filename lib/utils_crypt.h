#ifndef _UTILS_CRYPT_H
#define _UTILS_CRYPT_H

#include <unistd.h>
#include "config.h"

#define MAX_CIPHER_LEN		32
#define MAX_CIPHER_LEN_STR	"32"

struct crypt_device;

int crypt_parse_name_and_mode(const char *s, char *cipher,
			      int *key_nums, char *cipher_mode);

int crypt_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify,
		  struct crypt_device *cd);

void *crypt_safe_alloc(size_t size);
void crypt_safe_free(void *data);
void *crypt_safe_realloc(void *data, size_t size);

#endif /* _UTILS_CRYPT_H */
