#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

#include "libcryptsetup.h"
#include "nls.h"
#include "utils_crypt.h"

struct safe_allocation {
	size_t	size;
	char	data[0];
};

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

/* safe allocations */
void *crypt_safe_alloc(size_t size)
{
	struct safe_allocation *alloc;

	if (!size)
		return NULL;

	alloc = malloc(size + offsetof(struct safe_allocation, data));
	if (!alloc)
		return NULL;

	alloc->size = size;

	return &alloc->data;
}

void crypt_safe_free(void *data)
{
	struct safe_allocation *alloc;

	if (!data)
		return;

	alloc = data - offsetof(struct safe_allocation, data);

	memset(data, 0, alloc->size);

	alloc->size = 0x55aa55aa;
	free(alloc);
}

void *crypt_safe_realloc(void *data, size_t size)
{
	void *new_data;

	new_data = crypt_safe_alloc(size);

	if (new_data && data) {
		struct safe_allocation *alloc;

		alloc = data - offsetof(struct safe_allocation, data);

		if (size > alloc->size)
			size = alloc->size;

		memcpy(new_data, data, size);
	}

	crypt_safe_free(data);
	return new_data;
}
