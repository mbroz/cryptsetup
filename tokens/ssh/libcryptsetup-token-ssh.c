// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Example of LUKS2 ssh token handler (EXPERIMENTAL)
 *
 * Copyright (C) 2016-2025 Milan Broz
 * Copyright (C) 2020-2025 Vojtech Trefny
 *
 * Use:
 *  - generate LUKS device
 *  - store passphrase used in previous step remotely (single line w/o \r\n)
 *  - add new token using this example
 *  - activate device by token
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <json-c/json.h>
#include "libcryptsetup.h"
#include "ssh-utils.h"

#define TOKEN_NAME "ssh"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

#define SERVER_ARG	"plugin-ssh-server"
#define USER_ARG	"plugin-ssh-user"
#define PATH_ARG	"plugin-ssh-path"
#define KEYPATH_ARG	"plugin-ssh-keypath"

#define l_dbg(cd, x...) crypt_logf(cd, CRYPT_LOG_DEBUG, x)


const char *cryptsetup_token_version(void);
int cryptsetup_token_open_pin(struct crypt_device *cd, int token, const char *pin,
	size_t pin_size, char **password, size_t *password_len, void *usrptr);
int cryptsetup_token_open(struct crypt_device *cd, int token,
	char **password, size_t *password_len, void *usrptr);
void cryptsetup_token_dump(struct crypt_device *cd, const char *json);
int cryptsetup_token_validate(struct crypt_device *cd, const char *json);
void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len);

const char *cryptsetup_token_version(void)
{
	return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR;
}

void cryptsetup_token_buffer_free(void *buffer, size_t buffer_len)
{
	/* libcryptsetup API call */
	crypt_safe_memzero(buffer, buffer_len);
	free(buffer);
}

static json_object *get_token_jobj(struct crypt_device *cd, int token)
{
	const char *json_slot;

	/* libcryptsetup API call */
	if (crypt_token_json_get(cd, token, &json_slot))
		return NULL;

	return json_tokener_parse(json_slot);
}

int cryptsetup_token_open_pin(struct crypt_device *cd, int token, const char *pin,
	size_t pin_size __attribute__((unused)), char **password, size_t *password_len,
	void *usrptr __attribute__((unused)))
{
	int r;
	json_object *jobj_server, *jobj_user, *jobj_path, *jobj_token, *jobj_keypath;
	ssh_key pkey;
	ssh_session ssh;

	jobj_token = get_token_jobj(cd, token);
	if (!jobj_token)
		return -ENOMEM;

	json_object_object_get_ex(jobj_token, "ssh_server", &jobj_server);
	json_object_object_get_ex(jobj_token, "ssh_user",   &jobj_user);
	json_object_object_get_ex(jobj_token, "ssh_path",   &jobj_path);
	json_object_object_get_ex(jobj_token, "ssh_keypath",&jobj_keypath);

	r = ssh_pki_import_privkey_file(json_object_get_string(jobj_keypath), pin, NULL, NULL, &pkey);
	if (r != SSH_OK) {
		json_object_put(jobj_token);
		if (r == SSH_EOF) {
			crypt_log(cd, CRYPT_LOG_ERROR, "Failed to open and import private key.\n");
			return -EINVAL;
		}
		crypt_log(cd, CRYPT_LOG_ERROR, "Failed to import private key (password protected?).\n");
		return -EAGAIN;
	}

	ssh = sshplugin_session_init(cd, json_object_get_string(jobj_server),
				   json_object_get_string(jobj_user));
	if (!ssh) {
		json_object_put(jobj_token);
		ssh_key_free(pkey);
		return -EINVAL;
	}

	r = sshplugin_public_key_auth(cd, ssh, pkey);
	ssh_key_free(pkey);

	if (r == SSH_AUTH_SUCCESS)
		r = sshplugin_download_password(cd, ssh, json_object_get_string(jobj_path),
					      password, password_len);

	ssh_disconnect(ssh);
	ssh_free(ssh);
	json_object_put(jobj_token);

	return r ? -EINVAL : r;
}

int cryptsetup_token_open(struct crypt_device *cd, int token,
	char **password, size_t *password_len, void *usrptr)
{
	return cryptsetup_token_open_pin(cd, token, NULL, 0, password, password_len, usrptr);
}

void cryptsetup_token_dump(struct crypt_device *cd, const char *json)
{
	json_object *jobj_token, *jobj_server, *jobj_user, *jobj_path, *jobj_keypath;
	char buf[4096];

	jobj_token = json_tokener_parse(json);
	if (!jobj_token)
		return;

	json_object_object_get_ex(jobj_token, "ssh_server", &jobj_server);
	json_object_object_get_ex(jobj_token, "ssh_user",   &jobj_user);
	json_object_object_get_ex(jobj_token, "ssh_path",   &jobj_path);
	json_object_object_get_ex(jobj_token, "ssh_keypath",&jobj_keypath);

	if (snprintf(buf, sizeof(buf) - 1, "\tssh_server: %s\n\tssh_user: %s\n"
	    "\tssh_path: %s\n\tssh_key_path: %s\n",
	    json_object_get_string(jobj_server),
	    json_object_get_string(jobj_user),
	    json_object_get_string(jobj_path),
	    json_object_get_string(jobj_keypath)) > 0)
		crypt_log(cd, CRYPT_LOG_NORMAL, buf);

	json_object_put(jobj_token);
}

int cryptsetup_token_validate(struct crypt_device *cd, const char *json)
{
	enum json_tokener_error jerr;
	json_object *jobj_token, *jobj;
	int r = -EINVAL;

	jobj_token = json_tokener_parse_verbose(json, &jerr);
	if (!jobj_token)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_token, "ssh_server", &jobj) ||
	    !json_object_is_type(jobj, json_type_string)) {
		l_dbg(cd, "ssh_server element is missing or not string.");
		goto out;
	}

	if (!json_object_object_get_ex(jobj_token, "ssh_user", &jobj) ||
	    !json_object_is_type(jobj, json_type_string)) {
		l_dbg(cd, "ssh_user element is missing or not string.");
		goto out;
	}

	if (!json_object_object_get_ex(jobj_token, "ssh_path", &jobj) ||
	    !json_object_is_type(jobj, json_type_string)) {
		l_dbg(cd, "ssh_path element is missing or not string.");
		goto out;
	}

	if (!json_object_object_get_ex(jobj_token, "ssh_keypath", &jobj) ||
	    !json_object_is_type(jobj, json_type_string)) {
		l_dbg(cd, "ssh_keypath element is missing or not string.");
		goto out;
	}

	r = 0;
out:
	json_object_put(jobj_token);
	return r;
}
