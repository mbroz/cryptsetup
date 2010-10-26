#ifndef _UTILS_CRYPT_H
#define _UTILS_CRYPT_H

#define MAX_CIPHER_LEN		32
#define MAX_CIPHER_LEN_STR	"32"

int crypt_parse_name_and_mode(const char *s, char *cipher, char *cipher_mode);

#endif /* _UTILS_CRYPT_H */
