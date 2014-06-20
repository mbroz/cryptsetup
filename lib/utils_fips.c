/*
 * FIPS mode utilities
 *
 * Copyright (C) 2011-2013, Red Hat, Inc. All rights reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include "nls.h"
#include "utils_fips.h"

#if !ENABLE_FIPS
int crypt_fips_mode(void) { return 0; }
void crypt_fips_libcryptsetup_check(void) {}
#else
#include <fipscheck.h>

int crypt_fips_mode(void)
{
	return FIPSCHECK_kernel_fips_mode() && !access(FIPS_MODULE_FILE, F_OK);
}

static void crypt_fips_verify(const char *name, const char *function)
{
	if (access(FIPS_MODULE_FILE, F_OK))
		return;

	if (!FIPSCHECK_verify(name, function)) {
		fputs(_("FIPS checksum verification failed.\n"), stderr);
		if (FIPSCHECK_kernel_fips_mode())
			_exit(EXIT_FAILURE);
	}
}

void crypt_fips_libcryptsetup_check(void)
{
	crypt_fips_verify(LIBCRYPTSETUP_VERSION_FIPS, "crypt_init");
}
#endif /* ENABLE_FIPS */
