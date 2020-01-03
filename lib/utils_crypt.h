/*
 * utils_crypt - cipher utilities for cryptsetup
 *
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2020 Milan Broz
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

#ifndef _UTILS_CRYPT_H
#define _UTILS_CRYPT_H

#include <unistd.h>

#define MAX_CIPHER_LEN		32
#define MAX_CIPHER_LEN_STR	"31"
#define MAX_KEYFILES		32

int crypt_parse_name_and_mode(const char *s, char *cipher,
			      int *key_nums, char *cipher_mode);
int crypt_parse_hash_integrity_mode(const char *s, char *integrity);
int crypt_parse_integrity_mode(const char *s, char *integrity,
			       int *integrity_key_size);
int crypt_parse_pbkdf(const char *s, const char **pbkdf);

ssize_t crypt_hex_to_bytes(const char *hex, char **result, int safe_alloc);

#endif /* _UTILS_CRYPT_H */
