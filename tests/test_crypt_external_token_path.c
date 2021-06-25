#include <libcryptsetup.h>

const char *crypt_token_external_path(void)
{
	return BUILD_DIR;
}
