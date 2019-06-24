/*
 * Example of LUKS2 keyslot handler, config app
 *
 * Use:
 *    cryptsetup luksFormat --type luks2 <dev>
 *    cryptsetup-sshtest add <dev> host user /home/user/keyfile /home/myuser/.ssh/id_rsa
 *    cryptsetup/cryptsetup-sshtest open test
 *
 * Copyright (C) 2016-2020 Milan Broz <gmazyland@gmail.com>
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
#include <string.h>
#include <json-c/json.h>
#include <libcryptsetup.h>

#define CRYPT_TOKEN_VERSION "CRYPTSETUP_TOKEN_1.0"
#define TOKEN_NUM 0
#define TOKEN_NAME "sshtest"

static int token_add(const char *device, const char *server,
		   const char *user, const char *path, const char *keypath)
{
	struct crypt_device *cd = NULL;
	json_object *jobj = NULL, *jobj_keyslots;
	int r;

	r = crypt_init(&cd, device);
	if (r < 0)
		return EXIT_FAILURE;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r < 0) {
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	jobj = json_object_new_object();
	json_object_object_add(jobj, "type", json_object_new_string(TOKEN_NAME)); /* mandatory */

	jobj_keyslots = json_object_new_array();
	json_object_array_add(jobj_keyslots, json_object_new_string("0")); /* assign to first keyslot only */
	json_object_object_add(jobj, "keyslots", jobj_keyslots); /* mandatory array field (may be empty and assigned later */

	/* custom metadata */
	json_object_object_add(jobj, "ssh_server", json_object_new_string(server));
	json_object_object_add(jobj, "ssh_user", json_object_new_string(user));
	json_object_object_add(jobj, "ssh_path", json_object_new_string(path));
	json_object_object_add(jobj, "ssh_keypath", json_object_new_string(keypath));

	/* libcryptsetup API call */
	r = crypt_token_json_set(cd, TOKEN_NUM, json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN));

	crypt_free(cd);
	json_object_put(jobj);

	return r ? EXIT_FAILURE : EXIT_SUCCESS;
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

	r = crypt_activate_by_token(cd, name, TOKEN_NUM, NULL, 0);

	crypt_free(cd);
	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int dump_by_token(const char *device)
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

	r = crypt_dump(cd);
	crypt_free(cd);

	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}


static void keyslot_help(void)
{
	printf("Use parameters:\n add device server user path sshkeypath\n"
		" open device name\n dump device\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	if (crypt_token_load(TOKEN_NAME)) {
		printf("Cannot find token lib %s.\n", TOKEN_NAME);
		return EXIT_FAILURE;
	}

	crypt_set_debug_level(CRYPT_LOG_DEBUG);

	/* Adding slot to device */
	if (argc == 7 && !strcmp("add", argv[1]))
		return token_add(argv[2], argv[3], argv[4], argv[5], argv[6]);

	/* Key check without activation */
	if (argc == 3 && !strcmp("open", argv[1]))
		return open_by_token(argv[2], NULL);

	/* Key check with activation (requires root) */
	if (argc == 4 && !strcmp("open", argv[1]))
		return open_by_token(argv[2], argv[3]);

	/* Dump with keyslot info */
	if (argc == 3 && !strcmp("dump", argv[1]))
		return dump_by_token(argv[2]);

	keyslot_help();
	return 1;
}
