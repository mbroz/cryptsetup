/*
 * Example of LUKS2 ssh token handler (EXPERIMENTAL)
 *
 * Copyright (C) 2016-2021 Milan Broz <gmazyland@gmail.com>
 * Copyright (C) 2020-2021 Vojtech Trefny
 *
 * Use:
 *  - generate LUKS device
 *  - store passphrase used in previous step remotely (single line w/o \r\n)
 *  - add new token using this example
 *  - activate device by token
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
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include "libcryptsetup.h"

#define PASSWORD_LENGTH 8192

#define TOKEN_NAME "ssh"
#define TOKEN_VERSION_MAJOR "1"
#define TOKEN_VERSION_MINOR "0"

#define SERVER_ARG	"plugin-ssh-server"
#define USER_ARG	"plugin-ssh-user"
#define PATH_ARG	"plugin-ssh-path"
#define KEYPATH_ARG	"plugin-ssh-keypath"

#define l_dbg(cd, x...) crypt_logf(cd, CRYPT_LOG_DEBUG, x)

struct sshplugin_context {
	const char *server;
	const char *user;
	const char *path;
	const char *sshkey_path;

	int token;
	int keyslot;

	uint8_t status;

	struct crypt_cli *cli;
};

const char *cryptsetup_token_version(void)
{
	return TOKEN_VERSION_MAJOR "." TOKEN_VERSION_MINOR;
}

static json_object *get_token_jobj(struct crypt_device *cd, int token)
{
	const char *json_slot;

	/* libcryptsetup API call */
	if (crypt_token_json_get(cd, token, &json_slot))
		return NULL;

	return json_tokener_parse(json_slot);
}

static int sshplugin_download_password(struct crypt_device *cd, ssh_session ssh,
	const char *path, char **password, size_t *password_len)
{
	char *pass = NULL;
	size_t pass_len;
	int r;
	sftp_attributes sftp_attr = NULL;
	sftp_session sftp = NULL;
	sftp_file file = NULL;

	sftp = sftp_new(ssh);
	if (!sftp) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot create sftp session: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	r = sftp_init(sftp);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot init sftp session: ");
		goto out;
	}

	file = sftp_open(sftp, path, O_RDONLY, 0);
	if (!file) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot create sftp session: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	sftp_attr = sftp_fstat(file);
	if (!sftp_attr) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot stat sftp file: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	pass_len = sftp_attr->size > PASSWORD_LENGTH ? PASSWORD_LENGTH : sftp_attr->size;
	pass = malloc(pass_len);
	if (!pass) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Not enough memory.\n");
		r = SSH_FX_FAILURE;
		goto out;
	}

	r = sftp_read(file, pass, pass_len);
	if (r < 0 || (size_t)r != pass_len) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot read remote key: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	*password = pass;
	*password_len = pass_len;

	r = SSH_OK;
out:
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
		free(pass);
	}

	if (sftp_attr)
		sftp_attributes_free(sftp_attr);

	if (file)
		sftp_close(file);
	if (sftp)
		sftp_free(sftp);
	return r == SSH_OK ? 0 : -EINVAL;
}

static ssh_session sshplugin_session_init(struct crypt_device *cd,
	const char *host, const char *user)
{
	int r, port = 22;
	ssh_session ssh = ssh_new();
	if (!ssh)
		return NULL;

	ssh_options_set(ssh, SSH_OPTIONS_HOST, host);
	ssh_options_set(ssh, SSH_OPTIONS_USER, user);
	ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);

	crypt_log(cd, CRYPT_LOG_NORMAL, "SSH token initiating ssh session.\n");

	r = ssh_connect(ssh);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Connection failed: ");
		goto out;
	}

	r = ssh_session_is_known_server(ssh);
	if (r != SSH_SERVER_KNOWN_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Server not known: ");
		r = SSH_AUTH_ERROR;
		goto out;
	}

	r = SSH_OK;

	/* initialise list of authentication methods. yes, according to official libssh docs... */
	ssh_userauth_none(ssh, NULL);
out:
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
		ssh_disconnect(ssh);
		ssh_free(ssh);
		ssh = NULL;
	}

	return ssh;
}

static int sshplugin_public_key_auth(struct crypt_device *cd, ssh_session ssh, const ssh_key pkey)
{
	int r;

	crypt_log(cd, CRYPT_LOG_DEBUG, "Trying public key authentication method.\n");

	if (!(ssh_userauth_list(ssh, NULL) & SSH_AUTH_METHOD_PUBLICKEY)) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Public key auth method not allowed on host.\n");
		return SSH_AUTH_ERROR;
	}

	r = ssh_userauth_try_publickey(ssh, NULL, pkey);
	if (r == SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_DEBUG, "Public key method accepted.\n");
		r = ssh_userauth_publickey(ssh, NULL, pkey);
	}

	if (r != SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Public key authentication error: ");
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
	}

	return r;
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
	json_object_object_get_ex(jobj_token, "ssh_server", &jobj_server);
	json_object_object_get_ex(jobj_token, "ssh_user",   &jobj_user);
	json_object_object_get_ex(jobj_token, "ssh_path",   &jobj_path);
	json_object_object_get_ex(jobj_token, "ssh_keypath",&jobj_keypath);

	r = ssh_pki_import_privkey_file(json_object_get_string(jobj_keypath), pin, NULL, NULL, &pkey);
	if (r != SSH_OK) {
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

	snprintf(buf, sizeof(buf) - 1, "\tssh_server: %s\n\tssh_user: %s\n"
		"\tssh_path: %s\n\tssh_key_path: %s\n",
		json_object_get_string(jobj_server),
		json_object_get_string(jobj_user),
		json_object_get_string(jobj_path),
		json_object_get_string(jobj_keypath));

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
