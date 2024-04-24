/*
 * Safe memory utilities
 *
 * Copyright (C) 2024 Milan Broz
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

#include "crypto_backend_internal.h"

/* Memzero helper (memset on stack can be optimized out) */
void crypt_backend_memzero(void *s, size_t n)
{
#ifdef HAVE_EXPLICIT_BZERO
	explicit_bzero(s, n);
#else
	volatile uint8_t *p = (volatile uint8_t *)s;
	while(n--) *p++ = 0;
#endif
}

/* Internal implementation for constant time memory comparison */
int crypt_internal_memeq(const void *m1, const void *m2, size_t n)
{
	const unsigned char *_m1 = (const unsigned char *) m1;
	const unsigned char *_m2 = (const unsigned char *) m2;
	unsigned char result = 0;
	size_t i;

	for (i = 0; i < n; i++)
		result |= _m1[i] ^ _m2[i];

	return result;
}
