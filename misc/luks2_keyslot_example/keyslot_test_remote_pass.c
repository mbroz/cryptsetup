/*
 * Example of LUKS2 token storing third party metadata (EXAMPLE)
 *
 * Copyright (C) 2016-2020 Milan Broz <gmazyland@gmail.com>
 *
 * Use:
 *  - generate LUKS device
 *  - store passphrase used in previous step remotely (single line w/o \n\r)
 *  - add new token using this example
 *  - activate device with passphrase recovered remotely using the example
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

#define TOKEN_NUM 0
#define TOKEN_TYPE "sshkeytest"

#define PASSWORD_LENGTH 8192

static json_object *get_token_jobj(struct crypt_device *cd, int token)
{
	const char *json_slot;

	if (crypt_token_json_get(cd, token, &json_slot))
		return NULL;

	return json_tokener_parse(json_slot);
}

static int read_remote_passphrase(struct crypt_device *cd, const char *host,
			   const char *user, const char *path,
			   char *password, size_t password_size)
{
	ssh_session ssh = NULL;
	sftp_session sftp = NULL;
	sftp_file file = NULL;
	ssh_key pkey = NULL;

	int r, port = 22;

	ssh = ssh_new();
	if (!ssh)
		return -EINVAL;

	ssh_options_set(ssh, SSH_OPTIONS_HOST, host);
	ssh_options_set(ssh, SSH_OPTIONS_USER, user);
	ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);

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

	r = ssh_pki_import_privkey_file("/home/user/.ssh/id_rsa", NULL, NULL, NULL, &pkey);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "error\n");
		r = SSH_AUTH_ERROR;
		goto out;
	}

	r = ssh_userauth_publickey(ssh, user, pkey);
	/* or r = ssh_userauth_publickey_auto(ssh, user, NULL); */
	if (r != SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Public key authentication error: ");
		goto out;
	}

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

	r = sftp_read(file, password, password_size);
	if (r < 1 || (size_t)r >= password_size) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Cannot read remote password: ");
		r = SSH_FX_FAILURE;
		goto out;
	}

	r = SSH_OK;
out:
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
	}

	if (pkey)
		ssh_key_free(pkey);

	if (file)
		sftp_close(file);
	if (sftp)
		sftp_free(sftp);
	ssh_disconnect(ssh);
	ssh_free(ssh);
	return r == SSH_OK ? 0 : -EINVAL;
}

static int token_add(const char *device, const char *server,
		   const char *user, const char *path)
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

	/* 'type' is mandatory field */
	json_object_object_add(jobj, "type", json_object_new_string(TOKEN_TYPE));

	/* 'keyslots' is mandatory field (may be empty) */
	jobj_keyslots = json_object_new_array();
	json_object_array_add(jobj_keyslots, json_object_new_string("0"));
	json_object_array_add(jobj_keyslots, json_object_new_string("1"));
	json_object_object_add(jobj, "keyslots", jobj_keyslots);

	/* third party values */
	json_object_object_add(jobj, "ssh_server", json_object_new_string(server));
	json_object_object_add(jobj, "ssh_user", json_object_new_string(user));
	json_object_object_add(jobj, "ssh_path", json_object_new_string(path));

	r = crypt_token_json_set(cd, TOKEN_NUM, json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN));

	crypt_free(cd);
	json_object_put(jobj);

	return EXIT_SUCCESS;
}

static int download_remote_password(struct crypt_device *cd, char *password, size_t password_len)
{
	json_object *jobj_server, *jobj_user, *jobj_path, *jobj_keyslot;

	/* get token json object representation as string */
	jobj_keyslot = get_token_jobj(cd, TOKEN_NUM);
	if (!jobj_keyslot)
		return -EINVAL;


	/* extract third party metadata necessary to extract passphrase remotely */
	json_object_object_get_ex(jobj_keyslot, "ssh_server", &jobj_server);
	json_object_object_get_ex(jobj_keyslot, "ssh_user",   &jobj_user);
	json_object_object_get_ex(jobj_keyslot, "ssh_path",   &jobj_path);

	return read_remote_passphrase(cd, json_object_get_string(jobj_server),
				    json_object_get_string(jobj_user),
				    json_object_get_string(jobj_path),
				    password, password_len);
}

static int open_by_remote_password(const char *device, const char *name)
{
	char password[PASSWORD_LENGTH+1];
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

	/* custom routines to acquire password */
	r = download_remote_password(cd, password, sizeof(password));
	if (r < 0) {
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	password[PASSWORD_LENGTH] = '\0';

	/* open first genuine LUKS2 keyslot available provided the password matches */
	/* for the sake of simplicity password is a string */
	r = crypt_activate_by_passphrase(cd, name, CRYPT_ANY_SLOT, password, strlen(password), 0);

	crypt_free(cd);
	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void keyslot_help(void)
{
	printf("Use parameters:\n add device server user path\n"
		" open device name\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	crypt_set_debug_level(CRYPT_LOG_DEBUG);

	/* Adding slot to device */
	if (argc == 6 && !strcmp("add", argv[1]))
		return token_add(argv[2], argv[3], argv[4], argv[5]);

	/* Password check without activation */
	if (argc == 3 && !strcmp("open", argv[1]))
		return open_by_remote_password(argv[2], NULL);

	/* Password check with activation (requires root) */
	if (argc == 4 && !strcmp("open", argv[1]))
		return open_by_remote_password(argv[2], argv[3]);

	keyslot_help();
	return 1;
}
