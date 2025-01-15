// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * ssh plugin utilities
 *
 * Copyright (C) 2016-2025 Milan Broz
 * Copyright (C) 2020-2025 Vojtech Trefny
 */

#ifndef SSH_UTILS_H
#define SSH_UTILS_H

#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <libcryptsetup.h>

int sshplugin_download_password(struct crypt_device *cd, ssh_session ssh,
	const char *path, char **password, size_t *password_len);
ssh_session sshplugin_session_init(struct crypt_device *cd, const char *host, const char *user);
int sshplugin_public_key_auth(struct crypt_device *cd, ssh_session ssh, const ssh_key pkey);

#endif /* SSH_UTILS_H */
