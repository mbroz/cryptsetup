/*
 * FIPS mode utilities
 *
 * Copyright (C) 2011-2012, Red Hat, Inc. All rights reserved.
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
#include <unistd.h>
#include "libcryptsetup.h"
#include "nls.h"
#include "utils_fips.h"

#if !ENABLE_FIPS
int crypt_fips_mode(void) { return 0; }
void crypt_fips_libcryptsetup_check(struct crypt_device *cd) {}
void crypt_fips_self_check(struct crypt_device *cd) {}
#else
#include <fipscheck.h>

int crypt_fips_mode(void)
{
	return FIPSCHECK_kernel_fips_mode();
}

static void crypt_fips_verify(struct crypt_device *cd,
			       const char *name, const char *function)
{
	if (!crypt_fips_mode())
		return;

	if (!FIPSCHECK_verify(name, function)) {
		crypt_log(cd, CRYPT_LOG_ERROR, _("FIPS checksum verification failed.\n"));
		_exit(EXIT_FAILURE);
	}

	crypt_log(cd, CRYPT_LOG_VERBOSE, _("Running in FIPS mode.\n"));
}

void crypt_fips_libcryptsetup_check(struct crypt_device *cd)
{
	crypt_fips_verify(cd, LIBCRYPTSETUP_VERSION_FIPS, "crypt_init");
}

void crypt_fips_self_check(struct crypt_device *cd)
{
	crypt_fips_verify(cd, NULL, NULL);
}
#endif /* ENABLE_FIPS */
