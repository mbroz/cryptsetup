/*
 * LUKS - Linux Unified Key Setup v2, kernel keyring token
 *
 * Copyright (C) 2016-2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2017, Ondrej Kozina. All rights reserved.
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

#include "luks2_internal.h"

static int keyring_open(struct crypt_device *cd,
				int token,
				char **buffer,
				size_t *buffer_len,
				void *usrptr __attribute__((unused)))
{
	json_object *jobj_token, *jobj_key;
	struct luks2_hdr *hdr;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_token = LUKS2_get_token_jobj(hdr, token);
	if (!jobj_token)
		return -EINVAL;

	json_object_object_get_ex(jobj_token, "key_description", &jobj_key);

	/* TODO: if r == -ENOKEY then instantiate the key? */
	if (keyring_get_passphrase(json_object_get_string(jobj_key), buffer, buffer_len))
		return -EINVAL;

	return 0;
}

static int keyring_validate(struct crypt_device *cd __attribute__((unused)),
				    const char *json)
{
	enum json_tokener_error jerr;
	json_object *jobj_token, *jobj_key;

	log_dbg("Validating keyring token json");

	jobj_token = json_tokener_parse_verbose(json, &jerr);
	if (!jobj_token) {
		log_dbg("Keyring token JSON parse failed.");
		return 1;
	}

	if (!json_object_object_get_ex(jobj_token, "key_description", &jobj_key)) {
		log_dbg("missing key_description field.");
		return 1;
	}

	if (!json_object_is_type(jobj_key, json_type_string)) {
		log_dbg("key_description is not a string.");
		return 1;
	}

	/* TODO: perhaps check that key description is in '%s:%s'
	 * format where both strings are not empty */
	return !strlen(json_object_get_string(jobj_key));
}

static void keyring_dump(struct crypt_device *cd, const char *json)
{
	enum json_tokener_error jerr;
	json_object *jobj_token, *jobj_key;

	jobj_token = json_tokener_parse_verbose(json, &jerr);
	if (!jobj_token)
		return;

	if (!json_object_object_get_ex(jobj_token, "key_description", &jobj_key)) {
		json_object_put(jobj_token);
		return;
	}

	log_std(cd, "\tKey description: %s\n", json_object_get_string(jobj_key));

	json_object_put(jobj_token);
}

const crypt_token_handler keyring_handler = {
	.name = "keyring",
	.open = keyring_open,
	.validate = keyring_validate,
	.dump = keyring_dump
};
