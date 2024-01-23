/*
 * ssh plugin utilities
 *
 * Copyright (C) 2016-2024 Milan Broz
 * Copyright (C) 2020-2024 Vojtech Trefny
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
