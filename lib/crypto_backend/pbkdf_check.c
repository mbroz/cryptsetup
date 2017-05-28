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
#include <limits.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "crypto_backend.h"

//#define BENCH_DEBUG

#ifdef BENCH_DEBUG
#include <stdio.h> /* FIXME: debug */
#define bench_log(args...) fprintf(stderr, args)
#else
#define bench_log(args...)
#endif

#define BENCH_MIN_MS 250
#define BENCH_PERCENT_ATLEAST 95
#define BENCH_PERCENT_ATMOST 105

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

static long timespec_ms(struct timespec *start, struct timespec *end)
{
	return (end->tv_sec - start->tv_sec) * 1000 +
	        (end->tv_nsec - start->tv_nsec) / (1000 * 1000);
}

static int measure_argon2(const char *password, size_t password_length,
                          const char *salt, size_t salt_length,
                          char *key, size_t key_length,
                          uint32_t t_cost, uint32_t m_cost, uint32_t parallel,
                          size_t samples, long ms_atleast, long *out_ms)
{
	long ms, ms_min = LONG_MAX;
	int r;
	size_t i;

	for (i = 0; i < samples; i++) {
		struct timespec tstart, tend;

		/*
		 * NOTE: We must use clock_gettime here, because Argon2 can run over
		 * multiple threads, and thus we care about real time, not CPU time!
		 */
		if (clock_gettime(CLOCK_MONOTONIC_RAW, &tstart) < 0)
			return -EINVAL;

		r = crypt_pbkdf("argon2", NULL, password, password_length, salt,
		                salt_length, key, key_length, t_cost, m_cost, parallel);
		if (r < 0)
			return r;

		if (clock_gettime(CLOCK_MONOTONIC_RAW, &tend) < 0)
			return -EINVAL;

		ms = timespec_ms(&tstart, &tend);
		if (ms < 0)
			return -EINVAL;

		if (ms < ms_atleast) {
			/* early exit */
			ms_min = ms;
			break;
		}
		if (ms < ms_min) {
			ms_min = ms;
		}
	}
	*out_ms = ms_min;
	return 0;
}

int crypt_argon2_check(const char *password, size_t password_length,
		      const char *salt, size_t salt_length, size_t key_length,
		      uint32_t min_t_cost, uint32_t max_m_cost, uint32_t parallel,
		      int target_ms,  uint32_t *out_t_cost, uint32_t *out_m_cost)
{
	int r = 0;
	char *key = NULL;
	uint32_t t_cost, m_cost, min_m_cost = 8 * parallel;
	uint64_t num, denom;
	long ms;
	long ms_atleast = (long)target_ms * BENCH_PERCENT_ATLEAST / 100;
	long ms_atmost = (long)target_ms * BENCH_PERCENT_ATMOST / 100;
	struct timespec tstart, tend;

	if (key_length <= 0 || target_ms <= 0)
		return -EINVAL;

	if (max_m_cost < min_m_cost)
		return -EINVAL;

	clock_gettime(CLOCK_MONOTONIC, &tstart);

	key = malloc(key_length);
	if (!key)
		return -ENOMEM;

	t_cost = min_t_cost;
	m_cost = min_m_cost;

	/* 1. Find some small parameters, s. t. ms >= BENCH_MIN_MS: */
	while (1) {
		r = measure_argon2(password, password_length, salt, salt_length,
		                   key, key_length, t_cost, m_cost, parallel,
		                   3, BENCH_MIN_MS, &ms);
		if (r < 0)
			goto out;

		bench_log("Pre-initial parameters: t_cost = %lu; m_cost = %lu; ms = %lu\n",
		          (long unsigned)t_cost, (long unsigned)m_cost, ms);

		if (ms >= BENCH_MIN_MS)
			break;

		if (m_cost == max_m_cost) {
			t_cost = ms ? (t_cost * BENCH_MIN_MS) / (uint32_t)ms : t_cost * 16;
		} else {
			m_cost = ms ? (m_cost * BENCH_MIN_MS) / (uint32_t)ms : m_cost * 16;
			if (m_cost > max_m_cost) {
				m_cost = max_m_cost;
			}
		}
	}
	bench_log("Initial parameters: t_cost = %lu; m_cost = %lu; ms = %lu\n",
	          (long unsigned)t_cost, (long unsigned)m_cost, ms);

	/*
	 * 2. Use the params obtained in (1.) to estimate the target params.
	 * 3. Then repeatedly measure the candidate params and if they fall out of
	 * the acceptance range (+-5 %), try to improve the estimate:
	 */
	do {
		uint32_t new_m_cost;

		num = (uint64_t)m_cost * (uint64_t)target_ms;
		denom = (uint64_t)ms;
		new_m_cost = (uint32_t)(num / denom);
		if (new_m_cost > max_m_cost) {
			num = (uint64_t)t_cost * (uint64_t)m_cost * (uint64_t)target_ms;
			denom = (uint64_t)max_m_cost * (uint64_t)ms;
			t_cost = (uint32_t)(num / denom);
			m_cost = max_m_cost;
			if (t_cost <= min_t_cost) {
				t_cost = min_t_cost;
				break;
			}
		} else if (new_m_cost < min_m_cost) {
			m_cost = min_m_cost;
			break;
		} else {
			m_cost = new_m_cost;
		}

		r = measure_argon2(password, password_length, salt, salt_length,
		                   key, key_length, t_cost, m_cost, parallel,
		                   4, ms_atleast, &ms);
		if (r < 0)
			goto out;

		bench_log("Candidate parameters: t_cost = %lu; m_cost = %lu; ms = %lu\n",
		          (long unsigned)t_cost, (long unsigned)m_cost, ms);
	} while(ms < ms_atleast || ms > ms_atmost);

	bench_log("Accepted parameters: t_cost = %lu; m_cost = %lu\n",
	          (long unsigned)t_cost, (long unsigned)m_cost);

	clock_gettime(CLOCK_MONOTONIC, &tend);

	bench_log("Benchmark took: %ld ms\n", timespec_ms(&tstart, &tend));

	*out_t_cost = t_cost;
	*out_m_cost = m_cost;
out:
	if (key) {
		crypt_backend_memzero(key, key_length);
		free(key);
	}
	return r;
}

/* This code benchmarks PBKDF and returns iterations/second using specified hash */
int crypt_pbkdf_check(const char *kdf, const char *hash,
		      const char *password, size_t password_length,
		      const char *salt, size_t salt_length,
		      size_t key_length, uint32_t *iter_secs)
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
				salt_length, key, key_length, iterations, 0, 0);
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
