// SPDX-License-Identifier: GPL-2.0-or-later

#include <string.h>
#include <stdlib.h>

/* systemd tpm2-util.h */
int tpm2_find_device_auto(char **ret);

extern int tpm2_find_device_auto(char **ret)
{
	const char *path = getenv("TPM_PATH");

	if (!path)
		*ret = NULL;
	else
		*ret = strdup(path);

	return 0;
}
