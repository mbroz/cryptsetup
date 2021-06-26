#include <libcryptsetup.h>

int main(void)
{
	return crypt_token_external_path() ? 1 : 0;
}
