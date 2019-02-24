/*
 * crypto backend implementation
 *
 * Copyright (C) 2010-2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2010-2019 Milan Broz
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
#ifndef _CRYPTO_BACKEND_INTERNAL_H
#define _CRYPTO_BACKEND_INTERNAL_H

#include "crypto_backend.h"

#if USE_INTERNAL_PBKDF2
/* internal PBKDF2 implementation */
int pkcs5_pbkdf2(const char *hash,
		 const char *P, size_t Plen,
		 const char *S, size_t Slen,
		 unsigned int c,
		 unsigned int dkLen, char *DK,
		 unsigned int hash_block_size);
#endif

/* Argon2 implementation wrapper */
int argon2(const char *type, const char *password, size_t password_length,
	   const char *salt, size_t salt_length,
	   char *key, size_t key_length,
	   uint32_t iterations, uint32_t memory, uint32_t parallel);

#endif /* _CRYPTO_BACKEND_INTERNAL_H */
