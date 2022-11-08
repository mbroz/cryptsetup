#include <string.h>
#include <stdlib.h>

extern int tpm2_find_device_auto(int log_level __attribute__((unused)), char **ret)
{
	const char *path = getenv("TPM_PATH");

	if (!path)
		*ret = NULL;
	else
		*ret = strdup(path);

	return 0;
}
