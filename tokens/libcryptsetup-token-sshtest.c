/*
 * Example of LUKS2 keyslot handler, token lib
 *
 * Copyright (C) 2016-2020 Milan Broz <gmazyland@gmail.com>
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

typedef int (*password_cb_func) (char **password);

static json_object *get_token_jobj(struct crypt_device *cd, int token)
{
	const char *json_slot;

	/* libcryptsetup API call */
	if (crypt_token_json_get(cd, token, &json_slot))
		return NULL;

	return json_tokener_parse(json_slot);
}

static int sshtest_download_password(struct crypt_device *cd, ssh_session ssh,
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

static ssh_session sshtest_session_init(struct crypt_device *cd,
	const char *host, const char *user)
{
	int r, port = 22;
	ssh_session ssh = ssh_new();
	if (!ssh)
		return NULL;

	ssh_options_set(ssh, SSH_OPTIONS_HOST, host);
	ssh_options_set(ssh, SSH_OPTIONS_USER, user);
	ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);

	crypt_log(cd, CRYPT_LOG_NORMAL, "SSHTEST token initiating ssh session.\n");

	r = ssh_connect(ssh);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Connection failed: ");
		goto out;
	}

	r = ssh_is_server_known(ssh);
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

static int sshtest_public_key_auth(struct crypt_device *cd, ssh_session ssh, const ssh_key pkey)
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

static int SSHTEST_open_pin(struct crypt_device *cd, int token, const char *pin,
	char **password, size_t *password_len, void *usrptr)
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

	ssh = sshtest_session_init(cd, json_object_get_string(jobj_server),
				   json_object_get_string(jobj_user));
	if (!ssh) {
		ssh_key_free(pkey);
		return -EINVAL;
	}

	r = sshtest_public_key_auth(cd, ssh, pkey);
	ssh_key_free(pkey);

	if (r == SSH_AUTH_SUCCESS)
		r = sshtest_download_password(cd, ssh, json_object_get_string(jobj_path),
					      password, password_len);

	ssh_disconnect(ssh);
	ssh_free(ssh);

	return r ? -EINVAL : r;
}

static int SSHTEST_open(struct crypt_device *cd, int token,
	char **password, size_t *password_len, void *usrptr)
{
	return SSHTEST_open_pin(cd, token, NULL, password, password_len, usrptr);
}

static void SSHTEST_dump(struct crypt_device *cd, const char *json)
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

const crypt_token_handler cryptsetup_token_handler = {
	.name  = "sshtest",
	.open  = SSHTEST_open,
	.open_pin = SSHTEST_open_pin,
	.dump  = SSHTEST_dump,
};
