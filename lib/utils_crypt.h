#ifndef _UTILS_CRYPT_H
#define _UTILS_CRYPT_H

#define MAX_CIPHER_LEN		32
#define MAX_CIPHER_LEN_STR	"32"

int crypt_parse_name_and_mode(const char *s, char *cipher, char *cipher_mode);

void *crypt_safe_alloc(size_t size);
void crypt_safe_free(void *data);
void *crypt_safe_realloc(void *data, size_t size);

#endif /* _UTILS_CRYPT_H */
