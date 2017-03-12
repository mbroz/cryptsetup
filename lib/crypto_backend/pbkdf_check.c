/*
 * PBKDF performance check
 * Copyright (C) 2012-2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2017, Milan Broz
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

#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "crypto_backend.h"

static long time_ms(struct rusage *start, struct rusage *end)
{
	int count_kernel_time = 0;
	long ms;

	if (crypt_backend_flags() & CRYPT_BACKEND_KERNEL)
		count_kernel_time = 1;

	/*
	 * FIXME: if there is no self usage info, count system time.
	 * This seem like getrusage() bug in some hypervisors...
	 */
	if (!end->ru_utime.tv_sec && !start->ru_utime.tv_sec &&
	    !end->ru_utime.tv_usec && !start->ru_utime.tv_usec)
		count_kernel_time = 1;

	ms = (end->ru_utime.tv_sec - start->ru_utime.tv_sec) * 1000;
	ms += (end->ru_utime.tv_usec - start->ru_utime.tv_usec) / 1000;

	if (count_kernel_time) {
		ms += (end->ru_stime.tv_sec - start->ru_stime.tv_sec) * 1000;
		ms += (end->ru_stime.tv_usec - start->ru_stime.tv_usec) / 1000;
	}

	return ms;
}

/* This code benchmarks PBKDF and returns iterations/second using specified hash */
int crypt_pbkdf_check(const char *kdf, const char *hash,
		      const char *password, size_t password_length,
		      const char *salt, size_t salt_length,
		      size_t key_length, uint64_t *iter_secs)
{
	struct rusage rstart, rend;
	int r = 0, step = 0;
	long ms = 0;
	char *key = NULL;
	unsigned int iterations;

	if (!kdf || !hash || key_length <= 0)
		return -EINVAL;

	key = malloc(key_length);
	if (!key)
		return -ENOMEM;

	iterations = 1 << 15;
	while (1) {
		if (getrusage(RUSAGE_SELF, &rstart) < 0) {
			r = -EINVAL;
			goto out;
		}

		r = crypt_pbkdf(kdf, hash, password, password_length, salt,
				salt_length, key, key_length, iterations);
		if (r < 0)
			goto out;

		if (getrusage(RUSAGE_SELF, &rend) < 0) {
			r = -EINVAL;
			goto out;
		}

		ms = time_ms(&rstart, &rend);
		if (ms > 500)
			break;

		if (ms <= 62)
			iterations <<= 4;
		else if (ms <= 125)
			iterations <<= 3;
		else if (ms <= 250)
			iterations <<= 2;
		else
			iterations <<= 1;

		if (++step > 10 || !iterations) {
			r = -EINVAL;
			goto out;
		}
	}

	if (iter_secs)
		*iter_secs = (iterations * 1000) / ms;
out:
	if (key) {
		crypt_backend_memzero(key, key_length);
		free(key);
	}
	return r;
}
