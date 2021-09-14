/*
 * FIPS mode utilities
 *
 * Copyright (C) 2011-2021 Red Hat, Inc. All rights reserved.
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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "utils_fips.h"

#if !ENABLE_FIPS
bool crypt_fips_mode(void) { return false; }
#else
static bool fips_checked = false;
static bool fips_mode = false;

static bool kernel_fips_mode(void)
{
	int fd;
	char buf[1] = "";

	if ((fd = open("/proc/sys/crypto/fips_enabled", O_RDONLY)) >= 0) {
		while (read(fd, buf, sizeof(buf)) < 0 && errno == EINTR);
		close(fd);
	}

	return (buf[0] == '1');
}

bool crypt_fips_mode(void)
{
	if (fips_checked)
		return fips_mode;

	fips_mode = kernel_fips_mode() && !access("/etc/system-fips", F_OK);
	fips_checked = true;

	return fips_mode;
}
#endif /* ENABLE_FIPS */
