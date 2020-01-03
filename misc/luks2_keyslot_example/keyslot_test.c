/*
 * Example of LUKS2 kesylot handler (EXAMPLE)
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

#define TOKEN_NUM 0

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

static int download_remote_password(struct crypt_device *cd, ssh_session ssh,
				    const char *path, char **password,
				    size_t *password_len)
{
	char *pass;
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

static ssh_session ssh_session_init(struct crypt_device *cd,
				    const char *host,
				    const char *user)
{
	int r, port = 22;
	ssh_session ssh = ssh_new();
	if (!ssh)
		return NULL;

	ssh_options_set(ssh, SSH_OPTIONS_HOST, host);
	ssh_options_set(ssh, SSH_OPTIONS_USER, user);
	ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);

	crypt_log(cd, CRYPT_LOG_NORMAL, "Initiating ssh session.\n");

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

static void ssh_session_close(ssh_session ssh)
{
	if (ssh) {
		ssh_disconnect(ssh);
		ssh_free(ssh);
	}
}

static int _public_key_auth(struct crypt_device *cd, ssh_session ssh)
{
	int r;
	ssh_key pkey = NULL;

	crypt_log(cd, CRYPT_LOG_DEBUG, "Trying public key authentication method.\n");

	if (!(ssh_userauth_list(ssh, NULL) & SSH_AUTH_METHOD_PUBLICKEY)) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Public key auth method not allowed on host.\n");
		return SSH_AUTH_ERROR;
	}

	r = ssh_pki_import_privkey_file("/home/user/.ssh/id_rsa", NULL, NULL, NULL, &pkey);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Failed to import private key\n");

		return r;
	}

	r = ssh_userauth_try_publickey(ssh, NULL, pkey);
	if (r == SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_DEBUG, "Public key method accepted.\n");
		r = ssh_userauth_publickey(ssh, NULL, pkey);
	}

	ssh_key_free(pkey);

	if (r != SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Public key authentication error: ");
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
	}

	return r;
}

static int _password_auth(struct crypt_device *cd, ssh_session ssh, password_cb_func pcb)
{
	int r = SSH_AUTH_ERROR;
	char *ssh_password = NULL;

	if (!(ssh_userauth_list(ssh, NULL) & SSH_AUTH_METHOD_PASSWORD)) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Password auth method not allowed on host.\n");
		return r;
	}

	if (pcb(&ssh_password)) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Failed to process password.\n");
		return r;
	}

	r = ssh_userauth_password(ssh, NULL, ssh_password);

	free(ssh_password);

	if (r != SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_ERROR, "Password authentication error: ");
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
	}

	return r;
}

static int SSHTEST_token_open(struct crypt_device *cd,
	int token,
	char **password,
	size_t *password_len,
	void *usrptr)
{
	int r;
	json_object *jobj_server, *jobj_user, *jobj_path, *jobj_token;
	ssh_session ssh;
	password_cb_func pcb = usrptr; /* custom password callback */

	jobj_token = get_token_jobj(cd, token);
	json_object_object_get_ex(jobj_token, "ssh_server", &jobj_server);
	json_object_object_get_ex(jobj_token, "ssh_user",   &jobj_user);
	json_object_object_get_ex(jobj_token, "ssh_path",   &jobj_path);

	ssh = ssh_session_init(cd, json_object_get_string(jobj_server),
			       json_object_get_string(jobj_user));
	if (!ssh)
		return -EINVAL;

	r = _public_key_auth(cd, ssh);

	/* try password method fallback. superficial example use case for an usrptr */
	if (r != SSH_AUTH_SUCCESS && pcb) {
		crypt_log(cd, CRYPT_LOG_DEBUG, "Trying password method instead.\n");
		r = _password_auth(cd, ssh, pcb);
	}

	if (r == SSH_AUTH_SUCCESS)
		r = download_remote_password(cd, ssh, json_object_get_string(jobj_path),
					     password, password_len);

	ssh_session_close(ssh);

	return r ? -EINVAL : r;
}

const crypt_token_handler SSHTEST_token = {
	.name  = "sshkeytest",
	.open  = SSHTEST_token_open,
};

static int token_add(const char *device, const char *server,
		   const char *user, const char *path)
{
	struct crypt_device *cd = NULL;
	json_object *jobj = NULL, *jobj_keyslots;
	int r;

	r = crypt_token_register(&SSHTEST_token);
	if (r < 0)
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
	json_object_object_add(jobj, "type", json_object_new_string(SSHTEST_token.name)); /* mandatory */

	jobj_keyslots = json_object_new_array();
	json_object_array_add(jobj_keyslots, json_object_new_string("0")); /* assign to first keyslot only */
	json_object_object_add(jobj, "keyslots", jobj_keyslots); /* mandatory array field (may be empty and assigned later */

	/* custom metadata */
	json_object_object_add(jobj, "ssh_server", json_object_new_string(server));
	json_object_object_add(jobj, "ssh_user", json_object_new_string(user));
	json_object_object_add(jobj, "ssh_path", json_object_new_string(path));

	/* libcryptsetup API call */
	r = crypt_token_json_set(cd, TOKEN_NUM, json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN));

	crypt_free(cd);
	json_object_put(jobj);

	return EXIT_SUCCESS;
}


/* naive implementation of password prompt. Yes it will print out the password on input :) */
static int ssh_password_callback(char **ssh_password)
{
	ssize_t i;
	char *pass = malloc(512);

	if (!pass)
		return -ENOMEM;

	fprintf(stdout, "Host asks for password:\n");

	i = read(STDIN_FILENO, pass, 512);
	if (i > 0) {
		pass[i-1] = '\0';
		i = 0;
	} else if (i == 0) { /* EOF */
		*pass = '\0';
		i = -1;
	}

	if (!i)
		*ssh_password = pass;
	else
		free(pass);

	return i;
}

static int open_by_token(const char *device, const char *name)
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_token_register(&SSHTEST_token);
	if (r < 0)
		return EXIT_FAILURE;

	r = crypt_init(&cd, device);
	if (r < 0)
		return EXIT_FAILURE;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r < 0) {
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	r = crypt_activate_by_token(cd, name, TOKEN_NUM, ssh_password_callback, 0);

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

	/* Key check without activation */
	if (argc == 3 && !strcmp("open", argv[1]))
		return open_by_token(argv[2], NULL);

	/* Key check with activation (requires root) */
	if (argc == 4 && !strcmp("open", argv[1]))
		return open_by_token(argv[2], argv[3]);

	keyslot_help();
	return 1;
}
