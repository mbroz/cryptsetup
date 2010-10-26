#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "internal.h"

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

#if 0
/* Token content stringification, see info cpp/stringification */
#define str(s) #s
#define xstr(s) str(s)
#define scanpattern1 "%" xstr(MAX_CIPHER_LEN) "[^-]-%" xstr(MAX_CIPHER_LEN)  "s"
#define scanpattern2 "%" xstr(MAX_CIPHER_LEN) "[^-]"

	if(sscanf(nameAndMode,scanpattern1, name, mode) != 2) {
		if((r = sscanf(nameAndMode,scanpattern2,name)) == 1)
			strncpy(mode,"cbc-plain",10);
		else
			return -EINVAL;
	}

	return 0;

#undef scanpattern1
#undef scanpattern2
#undef str
#undef xstr
#endif
