/*
 * Example of LUKS2 token handling and token activation
 *
 * Copyright (C) 2016 Ondrej Kozina <okozina@redhat.com>
 *
 * Use:
 *  - generate LUKS device
 *  - add new token using this example
 *  - load passphrase in user key type put in a keyring (see man keyctl, add_key)
 *  - activate device by token using this examle (open option)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include "libcryptsetup.h"

#define TOKEN_NUM 0

static int token_add(const char *device, const char *description)
{
	struct crypt_device *cd = NULL;
	json_object *jobj = NULL, *jobj_keyslots;
	int r;

	if (!description)
		return EXIT_FAILURE;

	r = crypt_init(&cd, device);
	if (r < 0)
		return EXIT_FAILURE;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r < 0) {
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	jobj = json_object_new_object();
	/* use builtin token passing passphrase via kernel key retention service */
	json_object_object_add(jobj, "type", json_object_new_string("keyring")); /* mandatory */

	jobj_keyslots = json_object_new_array();
	json_object_array_add(jobj_keyslots, json_object_new_string("0")); /* assign to first keyslot only */
	json_object_object_add(jobj, "keyslots", jobj_keyslots); /* mandatory array field (may be empty and assigned later */

	json_object_object_add(jobj, "key_length", json_object_new_int(crypt_get_volume_key_size(cd)));

	json_object_object_add(jobj, "key_description", json_object_new_string(description)); /* new mandatory field for keyring token */

	/* libcryptsetup API call */
	r = crypt_token_json_set(cd, TOKEN_NUM, json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN));

	crypt_free(cd);
	json_object_put(jobj);

	return EXIT_SUCCESS;
}

static int open_by_token(const char *device, const char *name)
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_init(&cd, device);
	if (r < 0)
		return EXIT_FAILURE;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r < 0) {
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	/* generic_keyring_token is builtin type, no need to register token handler */

	r = crypt_activate_by_token(cd, name, TOKEN_NUM, NULL, 0);

	crypt_free(cd);
	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void keyslot_help(void)
{
	printf("Use parameters:\n add device key_description\n"
		" open device name\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	crypt_set_debug_level(CRYPT_LOG_DEBUG);

	/* Adding slot to device */
	if (argc == 4 && !strcmp("add", argv[1]))
		return token_add(argv[2], argv[3]);

	/* Key check without activation */
	if (argc == 3 && !strcmp("open", argv[1]))
		return open_by_token(argv[2], NULL);

	/* Key check with activation (requires root) */
	if (argc == 4 && !strcmp("open", argv[1]))
		return open_by_token(argv[2], argv[3]);

	keyslot_help();
	return 1;
}
