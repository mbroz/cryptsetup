/*
 * utils_crypt - cipher utilities for cryptsetup
 *
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2023 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2023 Milan Broz
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

#include <stdbool.h>

struct crypt_device;

#define MAX_CIPHER_LEN       32
#define MAX_CIPHER_LEN_STR   "31"
#define MAX_KEYFILES         32
#define MAX_CAPI_ONE_LEN     2 * MAX_CIPHER_LEN
#define MAX_CAPI_ONE_LEN_STR "63"  /* for sscanf length + '\0' */
#define MAX_CAPI_LEN         144   /* should be enough to fit whole capi string */
#define MAX_INTEGRITY_LEN    64

int crypt_parse_name_and_mode(const char *s, char *cipher,
			      int *key_nums, char *cipher_mode);
int crypt_parse_hash_integrity_mode(const char *s, char *integrity);
int crypt_parse_integrity_mode(const char *s, char *integrity,
			       int *integrity_key_size);
int crypt_parse_pbkdf(const char *s, const char **pbkdf);

ssize_t crypt_hex_to_bytes(const char *hex, char **result, int safe_alloc);
char *crypt_bytes_to_hex(size_t size, const char *bytes);
void crypt_log_hex(struct crypt_device *cd,
		   const char *bytes, size_t size,
		   const char *sep, int numwrap, const char *wrapsep);

bool crypt_is_cipher_null(const char *cipher_spec);

int crypt_capi_to_cipher(char **org_c, char **org_i, const char *c_dm, const char *i_dm);

#endif /* _UTILS_CRYPT_H */
