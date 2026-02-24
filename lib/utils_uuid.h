// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Portable UUID helpers — always produce lowercase output.
 *
 * Linux libuuid's uuid_unparse() emits lowercase by default, but OSSP
 * uuid (macOS / BSD) emits uppercase.  This wrapper normalises to
 * lowercase so that formatted output is bit-identical across platforms.
 */

#ifndef UTILS_UUID_H
#define UTILS_UUID_H

#include <uuid/uuid.h>
#include <ctype.h>

/*
 * Like uuid_unparse(), but the string representation is guaranteed to
 * be lowercase on every platform.
 */
static inline void crypt_uuid_unparse(const uuid_t uu, char *out)
{
#if HAVE_UUID_UNPARSE_LOWER
	uuid_unparse_lower(uu, out);
#else
	uuid_unparse(uu, out);
	for (char *p = out; *p; p++)
		if (isupper((unsigned char)*p))
			*p = tolower((unsigned char)*p);
#endif
}

#endif /* UTILS_UUID_H */
