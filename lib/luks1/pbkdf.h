/*
 * Implementation of Password-Based Cryptography as per PKCS#5
 * Copyright (C) 2002,2003 Simon Josefsson
 * Copyright (C) 2004 Free Software Foundation
 *
 * LUKS code
 * Copyright (C) 2004, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
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
 *
 */

#ifndef INCLUDED_CRYPTSETUP_LUKS_PBKDF_H
#define INCLUDED_CRYPTSETUP_LUKS_PBKDF_H

#include <stddef.h>

int PBKDF2_HMAC(const char *hash,
		const char *password, size_t passwordLen,
		const char *salt, size_t saltLen, unsigned int iterations,
		char *dKey, size_t dKeyLen);


int PBKDF2_performance_check(const char *hash, uint64_t *iter);
int PBKDF2_HMAC_ready(const char *hash);

#endif
