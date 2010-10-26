#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "utils_crypt.h"

int crypt_parse_name_and_mode(const char *s, char *cipher, char *cipher_mode)
{
	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]-%" MAX_CIPHER_LEN_STR "s",
		   cipher, cipher_mode) == 2) {
		return 0;
	}

	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]", cipher) == 1) {
		strncpy(cipher_mode, "cbc-plain", 9);
		return 0;
	}

	return -EINVAL;
}
