/*
 * Helper utilities for LUKS in cryptsetup
 *
 * Copyright (C) 2018-2023 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2023 Milan Broz
 * Copyright (C) 2018-2023 Ondrej Kozina
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

#ifndef UTILS_LUKS_H
#define UTILS_LUKS_H

#include <stdint.h>

const char *luksType(const char *type);

bool isLUKS1(const char *type);

bool isLUKS2(const char *type);

int verify_passphrase(int def);

void set_activation_flags(uint32_t *flags);

int set_pbkdf_params(struct crypt_device *cd, const char *dev_type);

int set_tries_tty(void);

int get_adjusted_key_size(const char *cipher_mode, uint32_t default_size_bits, int integrity_keysize);

int luksFormat(struct crypt_device **r_cd, char **r_password, size_t *r_passwordLen);

int reencrypt(int action_argc, const char **action_argv);

int reencrypt_luks1(const char *device);

int reencrypt_luks1_in_progress(const char *device);

#endif /* UTILS_LUKS_H */
