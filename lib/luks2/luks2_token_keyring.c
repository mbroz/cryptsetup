/*
 * LUKS - Linux Unified Key Setup v2, kernel keyring token
 *
 * Copyright (C) 2016-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2020 Ondrej Kozina
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

#include <assert.h>

#include "luks2_internal.h"

static int keyring_open(struct crypt_device *cd,
				int token,
				char **buffer,
				size_t *buffer_len,
				void *usrptr __attribute__((unused)))
{
	json_object *jobj_token, *jobj_key;
	struct luks2_hdr *hdr;
	int r;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_token = LUKS2_get_token_jobj(hdr, token);
	if (!jobj_token)
		return -EINVAL;

	json_object_object_get_ex(jobj_token, "key_description", &jobj_key);

	r = keyring_get_passphrase(json_object_get_string(jobj_key), buffer, buffer_len);
	if (r == -ENOTSUP) {
		log_dbg(cd, "Kernel keyring features disabled.");
		return -EINVAL;
	} else if (r < 0) {
		log_dbg(cd, "keyring_get_passphrase failed (error %d)", r);
		return -EINVAL;
	}

	return 0;
}

static int keyring_validate(struct crypt_device *cd __attribute__((unused)),
				    const char *json)
{
	enum json_tokener_error jerr;
	json_object *jobj_token, *jobj_key;
	int r = 1;

	log_dbg(cd, "Validating keyring token json");

	jobj_token = json_tokener_parse_verbose(json, &jerr);
	if (!jobj_token) {
		log_dbg(cd, "Keyring token JSON parse failed.");
		return r;
	}

	if (json_object_object_length(jobj_token) != 3) {
		log_dbg(cd, "Keyring token is expected to have exactly 3 fields.");
		goto out;
	}

	if (!json_object_object_get_ex(jobj_token, "key_description", &jobj_key)) {
		log_dbg(cd, "missing key_description field.");
		goto out;
	}

	if (!json_object_is_type(jobj_key, json_type_string)) {
		log_dbg(cd, "key_description is not a string.");
		goto out;
	}

	/* TODO: perhaps check that key description is in '%s:%s'
	 * format where both strings are not empty */
	r = !strlen(json_object_get_string(jobj_key));
out:
	json_object_put(jobj_token);
	return r;
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

int LUKS2_token_keyring_json(char *buffer, size_t buffer_size,
	const struct crypt_token_params_luks2_keyring *keyring_params)
{
	snprintf(buffer, buffer_size, "{ \"type\": \"%s\", \"keyslots\":[],\"key_description\":\"%s\"}",
		 LUKS2_TOKEN_KEYRING, keyring_params->key_description);

	return 0;
}

int LUKS2_token_keyring_get(struct crypt_device *cd, struct luks2_hdr *hdr, int token,
	struct crypt_token_params_luks2_keyring *keyring_params)
{
	json_object *jobj_token, *jobj;

	jobj_token = LUKS2_get_token_jobj(hdr, token);
	json_object_object_get_ex(jobj_token, "type", &jobj);
	assert(!strcmp(json_object_get_string(jobj), LUKS2_TOKEN_KEYRING));

	json_object_object_get_ex(jobj_token, "key_description", &jobj);

	keyring_params->key_description = json_object_get_string(jobj);

	return token;
}

const crypt_token_handler keyring_handler = {
	.name = LUKS2_TOKEN_KEYRING,
	.open = keyring_open,
	.validate = keyring_validate,
	.dump = keyring_dump
};
