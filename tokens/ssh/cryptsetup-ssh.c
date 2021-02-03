/*
 * Example of LUKS2 token storing third party metadata (EXPERIMENTAL EXAMPLE)
 *
 * Copyright (C) 2016-2021 Milan Broz <gmazyland@gmail.com>
 *
 * Use:
 *  - generate ssh example token
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

#define TOKEN_NAME "ssh"

#define PASSWORD_LENGTH 8192

#define l_err(cd, x...) crypt_logf(cd, CRYPT_LOG_ERROR, x)
#define l_dbg(cd, x...) crypt_logf(cd, CRYPT_LOG_DEBUG, x)

static int token_add(
		const char *device,
		const char *server,
		const char *user,
		const char *path,
		const char *keypath)

{
	struct crypt_device *cd;
	json_object *jobj = NULL;
	json_object *jobj_keyslots = NULL;
	const char *string_token;
	int r, token;

	r = crypt_init(&cd, device);
	if (r)
		return r;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r)
		goto out;

	r = -EINVAL;
	jobj = json_object_new_object();
	if (!jobj)
		goto out;

	/* type is mandatory field in all tokens and must match handler name member */
	json_object_object_add(jobj, "type", json_object_new_string(TOKEN_NAME));

	jobj_keyslots = json_object_new_array();

	/* mandatory array field (may be empty and assigned later */
	json_object_object_add(jobj, "keyslots", jobj_keyslots);

	/* custom metadata */
	json_object_object_add(jobj, "ssh_server", json_object_new_string(server));
	json_object_object_add(jobj, "ssh_user", json_object_new_string(user));
	json_object_object_add(jobj, "ssh_path", json_object_new_string(path));
	json_object_object_add(jobj, "ssh_keypath", json_object_new_string(keypath));

	string_token = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
	if (!string_token) {
		r = -EINVAL;
		goto out;
	}

	l_dbg(cd, "Token JSON: %s", string_token);

	r = crypt_token_json_set(cd, CRYPT_ANY_TOKEN, string_token);
	if (r < 0) {
		l_err(cd, "Failed to write ssh token json.");
		goto out;
	}

	token = r;
	r = crypt_token_assign_keyslot(cd, token, CRYPT_ANY_SLOT);
	if (r != token) {
		crypt_token_json_set(cd, token, NULL);
		r = -EINVAL;
	}
out:
	json_object_put(jobj);
	crypt_free(cd);
	return r;
}

static void token_help(void)
{
	printf("Use parameters:\n add device server user path keypath\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	// crypt_set_debug_level(CRYPT_LOG_DEBUG);

	/* Adding slot to device */
	if (argc > 6 && !strcmp("add", argv[1]))
		return token_add(argv[2], argv[3], argv[4], argv[5], argv[6]);

	token_help();
	return EXIT_FAILURE;
}
