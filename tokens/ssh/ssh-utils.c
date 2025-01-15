// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * ssh plugin utilities
 *
 * Copyright (C) 2016-2025 Milan Broz
 * Copyright (C) 2020-2025 Vojtech Trefny
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <fcntl.h>
#include <libcryptsetup.h>
#include "ssh-utils.h"
#include "../lib/nls.h"

#define KEYFILE_LENGTH_MAX 8192

int sshplugin_download_password(struct crypt_device *cd, ssh_session ssh,
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
		crypt_log(cd, CRYPT_LOG_ERROR, _("Cannot create sftp session: "));
		r = SSH_FX_FAILURE;
		goto out;
	}

	r = sftp_init(sftp);
	if (r != SSH_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, _("Cannot init sftp session: "));
		goto out;
	}

	file = sftp_open(sftp, path, O_RDONLY, 0);
	if (!file) {
		crypt_log(cd, CRYPT_LOG_ERROR, _("Cannot open sftp session: "));
		r = SSH_FX_FAILURE;
		goto out;
	}

	sftp_attr = sftp_fstat(file);
	if (!sftp_attr) {
		crypt_log(cd, CRYPT_LOG_ERROR, _("Cannot stat sftp file: "));
		r = SSH_FX_FAILURE;
		goto out;
	}

	pass_len = sftp_attr->size > KEYFILE_LENGTH_MAX ? KEYFILE_LENGTH_MAX : sftp_attr->size;
	pass = malloc(pass_len);
	if (!pass) {
		crypt_log(cd, CRYPT_LOG_ERROR, _("Not enough memory.\n"));
		r = SSH_FX_FAILURE;
		goto out;
	}

	r = sftp_read(file, pass, pass_len);
	if (r < 0 || (size_t)r != pass_len) {
		crypt_log(cd, CRYPT_LOG_ERROR, _("Cannot read remote key: "));
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

ssh_session sshplugin_session_init(struct crypt_device *cd, const char *host, const char *user)
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
		crypt_log(cd, CRYPT_LOG_ERROR, _("Connection failed: "));
		goto out;
	}

#if HAVE_DECL_SSH_SESSION_IS_KNOWN_SERVER
	r = ssh_session_is_known_server(ssh);
#else
	r = ssh_is_server_known(ssh);
#endif
	if (r != SSH_SERVER_KNOWN_OK) {
		crypt_log(cd, CRYPT_LOG_ERROR, _("Server not known: "));
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

int sshplugin_public_key_auth(struct crypt_device *cd, ssh_session ssh, const ssh_key pkey)
{
	int r;

	crypt_log(cd, CRYPT_LOG_DEBUG, "Trying public key authentication method.\n");

	if (!(ssh_userauth_list(ssh, NULL) & SSH_AUTH_METHOD_PUBLICKEY)) {
		crypt_log(cd, CRYPT_LOG_ERROR, _("Public key auth method not allowed on host.\n"));
		return SSH_AUTH_ERROR;
	}

	r = ssh_userauth_try_publickey(ssh, NULL, pkey);
	if (r == SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_DEBUG, "Public key method accepted.\n");
		r = ssh_userauth_publickey(ssh, NULL, pkey);
	}

	if (r != SSH_AUTH_SUCCESS) {
		crypt_log(cd, CRYPT_LOG_ERROR, _("Public key authentication error: "));
		crypt_log(cd, CRYPT_LOG_ERROR, ssh_get_error(ssh));
		crypt_log(cd, CRYPT_LOG_ERROR, "\n");
	}

	return r;
}
