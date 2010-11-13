#ifndef _UTILS_CRYPT_H
#define _UTILS_CRYPT_H

#define MAX_CIPHER_LEN		32
#define MAX_CIPHER_LEN_STR	"32"

#define MAX_TTY_PASSWORD_LEN	512

struct crypt_device;

int crypt_parse_name_and_mode(const char *s, char *cipher, char *cipher_mode);

int crypt_get_key(char *prompt, char **key, unsigned int *passLen, int key_size,
		  const char *key_file, int timeout, int how2verify,
		  struct crypt_device *cd);

void *crypt_safe_alloc(size_t size);
void crypt_safe_free(void *data);
void *crypt_safe_realloc(void *data, size_t size);

#endif /* _UTILS_CRYPT_H */
