// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Safe memory utilities
 *
 * Copyright (C) 2024-2025 Milan Broz
 */

#include "crypto_backend_internal.h"

#define ATTR_NOINLINE __attribute__ ((noinline))
#define ATTR_ZERO_REGS
#if HAVE_ATTRIBUTE_ZEROCALLUSEDREGS
#    undef ATTR_ZERO_REGS
#    define ATTR_ZERO_REGS __attribute__ ((zero_call_used_regs("used")))
#endif

/* Workaround for https://github.com/google/sanitizers/issues/1507 */
#if defined __has_feature
# if __has_feature (memory_sanitizer)
#   undef HAVE_EXPLICIT_BZERO
# endif
#endif

/* Memzero helper (memset on stack can be optimized out) */
ATTR_NOINLINE ATTR_ZERO_REGS
void crypt_backend_memzero(void *s, size_t n)
{
#if HAVE_EXPLICIT_BZERO
	explicit_bzero(s, n);
#else
	volatile uint8_t *p = (volatile uint8_t *)s;
	while(n--) *p++ = 0;
#endif
}

/* Memcpy helper to avoid spilling sensitive data through additional registers */
ATTR_NOINLINE ATTR_ZERO_REGS
void *crypt_backend_memcpy(void *dst, const void *src, size_t n)
{
	volatile uint8_t *d = (volatile uint8_t *)dst;
	const volatile uint8_t *s = (const volatile uint8_t *)src;

	while(n--) *d++ = *s++;

	return dst;
}

/* Internal implementation for constant time memory comparison */
ATTR_NOINLINE ATTR_ZERO_REGS
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
