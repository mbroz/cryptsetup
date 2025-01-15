// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Password quality check wrapper
 *
 * Copyright (C) 2023-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2023-2025 Ondrej Kozina
 * Copyright (C) 2023-2025 Milan Broz
 */

#include "cryptsetup.h"
#include <assert.h>

int tools_parse_vk_description(const char *key_description, char **ret_key_description)
{
	char *tmp;
	int r;

	assert(key_description);
	assert(ret_key_description);

	/* apply default key type */
	if (*key_description != '%')
		r = asprintf(&tmp, "%%user:%s", key_description) < 0 ? -EINVAL : 0;
	else
		r = (tmp = strdup(key_description)) ? 0 : -ENOMEM;
	if (!r)
		*ret_key_description = tmp;

	return r;
}

static int parse_single_vk_and_keyring_description(
	struct crypt_device *cd,
	char *keyring_key_description, char **keyring_part_out, char
	**key_part_out, char **type_part_out)
{
	int r = -EINVAL;
	char *endp, *sep, *key_part, *type_part = NULL;
	char *key_part_copy = NULL, *type_part_copy = NULL, *keyring_part = NULL;

	if (!cd || !keyring_key_description)
		return -EINVAL;

	/* "::" is separator between keyring specification a key description */
	key_part = strstr(keyring_key_description, "::");
	if (!key_part)
		goto out;

	*key_part = '\0';
	key_part = key_part + 2;

	if (*key_part == '%') {
		type_part = key_part + 1;
		sep = strstr(type_part, ":");
		if (!sep)
			goto out;
		*sep = '\0';

		key_part = sep + 1;
	}

	if (*keyring_key_description == '%') {
		keyring_key_description = strstr(keyring_key_description, ":");
		if (!keyring_key_description)
			goto out;
		log_verbose(_("Type specification in --link-vk-to-keyring keyring specification is ignored."));
		keyring_key_description++;
	}

	(void)strtol(keyring_key_description, &endp, 0);

	r = 0;
	if (*keyring_key_description == '@' || !*endp)
		keyring_part = strdup(keyring_key_description);
	else
		r = asprintf(&keyring_part, "%%:%s", keyring_key_description);

	if (!keyring_part || r < 0) {
		r = -ENOMEM;
		goto out;
	}

	if (!(key_part_copy = strdup(key_part))) {
		r = -ENOMEM;
		goto out;
	}
	if (type_part && !(type_part_copy = strdup(type_part)))
		r = -ENOMEM;

out:
	if (r < 0) {
		free(keyring_part);
		free(key_part_copy);
		free(type_part_copy);
	} else {
		*keyring_part_out = keyring_part;
		*key_part_out = key_part_copy;
		*type_part_out = type_part_copy;
	}

	return r;
}

int tools_parse_vk_and_keyring_description(
	struct crypt_device *cd,
	char **keyring_key_descriptions,
	int keyring_key_links_count)
{
	int r = 0;

	char *keyring_part_out1 = NULL, *key_part_out1 = NULL, *type_part_out1 = NULL;
	char *keyring_part_out2 = NULL, *key_part_out2 = NULL, *type_part_out2 = NULL;

	if (keyring_key_links_count > 0) {
		r = parse_single_vk_and_keyring_description(cd,
				keyring_key_descriptions[0],
				&keyring_part_out1, &key_part_out1,
				&type_part_out1);
		if (r < 0)
			goto out;
	}
	if (keyring_key_links_count > 1) {
		r = parse_single_vk_and_keyring_description(cd,
				keyring_key_descriptions[1],
				&keyring_part_out2, &key_part_out2,
				&type_part_out2);
		if (r < 0)
			goto out;

		if ((type_part_out1 && type_part_out2) && strcmp(type_part_out1, type_part_out2)) {
			log_err(_("Key types have to be the same for both volume keys."));
			r = -EINVAL;
			goto out;
		}
		if ((keyring_part_out1 && keyring_part_out2) && strcmp(keyring_part_out1, keyring_part_out2)) {
			log_err(_("Both volume keys have to be linked to the same keyring."));
			r = -EINVAL;
			goto out;
		}
	}

	if (keyring_key_links_count > 0) {
		r = crypt_set_keyring_to_link(cd, key_part_out1, key_part_out2,
				type_part_out1, keyring_part_out1);
		if (r == -EAGAIN)
			log_err(_("You need to supply more key names."));
	}
out:
	if (r == -EINVAL)
		log_err(_("Invalid --link-vk-to-keyring value."));
	free(keyring_part_out1);
	free(key_part_out1);
	free(type_part_out1);
	free(keyring_part_out2);
	free(key_part_out2);
	free(type_part_out2);

	return r;
}
