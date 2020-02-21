/*
 * PBKDF performance check
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2020 Milan Broz
 * Copyright (C) 2016-2020 Ondrej Mosnacek
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

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#define BENCH_MIN_MS 250
#define BENCH_MIN_MS_FAST 10
#define BENCH_PERCENT_ATLEAST 95
#define BENCH_PERCENT_ATMOST 110
#define BENCH_SAMPLES_FAST 3
#define BENCH_SAMPLES_SLOW 1

/* These PBKDF2 limits must be never violated */
int crypt_pbkdf_get_limits(const char *kdf, struct crypt_pbkdf_limits *limits)
{
	if (!kdf || !limits)
		return -EINVAL;

	if (!strcmp(kdf, "pbkdf2")) {
		limits->min_iterations = 1000; /* recommendation in NIST SP 800-132 */
		limits->max_iterations = UINT32_MAX;
		limits->min_memory     = 0; /* N/A */
		limits->max_memory     = 0; /* N/A */
		limits->min_parallel   = 0; /* N/A */
		limits->max_parallel   = 0; /* N/A */
		return 0;
	} else if (!strcmp(kdf, "argon2i") || !strcmp(kdf, "argon2id")) {
		limits->min_iterations = 4;
		limits->max_iterations = UINT32_MAX;
		limits->min_memory     = 32;
		limits->max_memory     = 4*1024*1024; /* 4GiB */
		limits->min_parallel   = 1;
		limits->max_parallel   = 4;
		return 0;
	}

	return -EINVAL;
}

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

static int measure_argon2(const char *kdf, const char *password, size_t password_length,
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

		r = crypt_pbkdf(kdf, NULL, password, password_length, salt,
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

#define CONTINUE 0
#define FINAL   1
static int next_argon2_params(uint32_t *t_cost, uint32_t *m_cost,
			      uint32_t min_t_cost, uint32_t min_m_cost,
			      uint32_t max_m_cost, long ms, uint32_t target_ms)
{
	uint32_t old_t_cost, old_m_cost, new_t_cost, new_m_cost;
	uint64_t num, denom;

	old_t_cost = *t_cost;
	old_m_cost = *m_cost;

	if ((uint32_t)ms > target_ms) {
		/* decreasing, first try to lower t_cost, then m_cost */
		num = (uint64_t)*t_cost * (uint64_t)target_ms;
		denom = (uint64_t)ms;
		new_t_cost = (uint32_t)(num / denom);
		if (new_t_cost < min_t_cost) {
			num = (uint64_t)*t_cost * (uint64_t)*m_cost *
			      (uint64_t)target_ms;
			denom = (uint64_t)min_t_cost * (uint64_t)ms;
			*t_cost = min_t_cost;
			*m_cost = (uint32_t)(num / denom);
			if (*m_cost < min_m_cost) {
				*m_cost = min_m_cost;
				return FINAL;
			}
		} else {
			*t_cost = new_t_cost;
		}
	} else {
		/* increasing, first try to increase m_cost, then t_cost */
		num = (uint64_t)*m_cost * (uint64_t)target_ms;
		denom = (uint64_t)ms;
		new_m_cost = (uint32_t)(num / denom);
		if (new_m_cost > max_m_cost) {
			num = (uint64_t)*t_cost * (uint64_t)*m_cost *
			      (uint64_t)target_ms;
			denom = (uint64_t)max_m_cost * (uint64_t)ms;
			*t_cost = (uint32_t)(num / denom);
			*m_cost = max_m_cost;
			if (*t_cost <= min_t_cost) {
				*t_cost = min_t_cost;
				return FINAL;
			}
		} else if (new_m_cost < min_m_cost) {
			*m_cost = min_m_cost;
			return FINAL;
		} else {
			*m_cost = new_m_cost;
		}
	}

	/* do not continue if it is the same as in the previous run */
	if (old_t_cost == *t_cost && old_m_cost == *m_cost)
		return FINAL;

	return CONTINUE;
}

static int crypt_argon2_check(const char *kdf, const char *password,
			      size_t password_length, const char *salt,
			      size_t salt_length, size_t key_length,
			      uint32_t min_t_cost, uint32_t min_m_cost, uint32_t max_m_cost,
			      uint32_t parallel, uint32_t target_ms,
			      uint32_t *out_t_cost, uint32_t *out_m_cost,
			      int (*progress)(uint32_t time_ms, void *usrptr),
			      void *usrptr)
{
	int r = 0;
	char *key = NULL;
	uint32_t t_cost, m_cost;
	long ms;
	long ms_atleast = (long)target_ms * BENCH_PERCENT_ATLEAST / 100;
	long ms_atmost = (long)target_ms * BENCH_PERCENT_ATMOST / 100;

	if (key_length <= 0 || target_ms <= 0)
		return -EINVAL;

	if (min_m_cost < (parallel * 8))
		min_m_cost = parallel * 8;

	if (max_m_cost < min_m_cost)
		return -EINVAL;

	key = malloc(key_length);
	if (!key)
		return -ENOMEM;

	t_cost = min_t_cost;
	m_cost = min_m_cost;

	/* 1. Find some small parameters, s. t. ms >= BENCH_MIN_MS: */
	while (1) {
		r = measure_argon2(kdf, password, password_length, salt, salt_length,
		                   key, key_length, t_cost, m_cost, parallel,
		                   BENCH_SAMPLES_FAST, BENCH_MIN_MS, &ms);
		if (!r) {
			/* Update parameters to actual measurement */
			*out_t_cost = t_cost;
			*out_m_cost = m_cost;
			if (progress && progress((uint32_t)ms, usrptr))
				r = -EINTR;
		}

		if (r < 0)
			goto out;

		if (ms >= BENCH_MIN_MS)
			break;

		if (m_cost == max_m_cost) {
			if (ms < BENCH_MIN_MS_FAST)
				t_cost *= 16;
			else {
				uint32_t new = (t_cost * BENCH_MIN_MS) / (uint32_t)ms;
				if (new == t_cost)
					break;

				t_cost = new;
			}
		} else {
			if (ms < BENCH_MIN_MS_FAST)
				m_cost *= 16;
			else {
				uint32_t new = (m_cost * BENCH_MIN_MS) / (uint32_t)ms;
				if (new == m_cost)
					break;

				m_cost = new;
			}
			if (m_cost > max_m_cost) {
				m_cost = max_m_cost;
			}
		}
	}
	/*
	 * 2. Use the params obtained in (1.) to estimate the target params.
	 * 3. Then repeatedly measure the candidate params and if they fall out of
	 * the acceptance range (+-5 %), try to improve the estimate:
	 */
	do {
		if (next_argon2_params(&t_cost, &m_cost, min_t_cost, min_m_cost,
				       max_m_cost, ms, target_ms)) {
			/* Update parameters to final computation */
			*out_t_cost = t_cost;
			*out_m_cost = m_cost;
			break;
		}

		r = measure_argon2(kdf, password, password_length, salt, salt_length,
		                   key, key_length, t_cost, m_cost, parallel,
		                   BENCH_SAMPLES_SLOW, ms_atleast, &ms);

		if (!r) {
			/* Update parameters to actual measurement */
			*out_t_cost = t_cost;
			*out_m_cost = m_cost;
			if (progress && progress((uint32_t)ms, usrptr))
				r = -EINTR;
		}

		if (r < 0)
			break;

	} while (ms < ms_atleast || ms > ms_atmost);
out:
	if (key) {
		crypt_backend_memzero(key, key_length);
		free(key);
	}
	return r;
}

/* This code benchmarks PBKDF and returns iterations/second using specified hash */
static int crypt_pbkdf_check(const char *kdf, const char *hash,
		      const char *password, size_t password_length,
		      const char *salt, size_t salt_length,
		      size_t key_length, uint32_t *iter_secs, uint32_t target_ms,
		      int (*progress)(uint32_t time_ms, void *usrptr), void *usrptr)

{
	struct rusage rstart, rend;
	int r = 0, step = 0;
	long ms = 0;
	char *key = NULL;
	uint32_t iterations;
	double PBKDF2_temp;

	if (!kdf || !hash || key_length <= 0)
		return -EINVAL;

	key = malloc(key_length);
	if (!key)
		return -ENOMEM;

	*iter_secs = 0;
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
		if (ms) {
			PBKDF2_temp = (double)iterations * target_ms / ms;
			if (PBKDF2_temp > UINT32_MAX)
				return -EINVAL;
			*iter_secs = (uint32_t)PBKDF2_temp;
		}

		if (progress && progress((uint32_t)ms, usrptr)) {
			r = -EINTR;
			goto out;
		}

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
out:
	if (key) {
		crypt_backend_memzero(key, key_length);
		free(key);
	}
	return r;
}

int crypt_pbkdf_perf(const char *kdf, const char *hash,
		const char *password, size_t password_size,
		const char *salt, size_t salt_size,
		size_t volume_key_size, uint32_t time_ms,
		uint32_t max_memory_kb, uint32_t parallel_threads,
		uint32_t *iterations_out, uint32_t *memory_out,
		int (*progress)(uint32_t time_ms, void *usrptr), void *usrptr)
{
	struct crypt_pbkdf_limits pbkdf_limits;
	int r = -EINVAL;

	if (!kdf || !iterations_out || !memory_out)
		return -EINVAL;

	/* FIXME: whole limits propagation should be more clear here */
	r = crypt_pbkdf_get_limits(kdf, &pbkdf_limits);
	if (r < 0)
		return r;

	*memory_out = 0;
	*iterations_out = 0;

	if (!strcmp(kdf, "pbkdf2"))
		r = crypt_pbkdf_check(kdf, hash, password, password_size,
				      salt, salt_size, volume_key_size,
				      iterations_out, time_ms, progress, usrptr);

	else if (!strncmp(kdf, "argon2", 6))
		r = crypt_argon2_check(kdf, password, password_size,
				       salt, salt_size, volume_key_size,
				       pbkdf_limits.min_iterations,
				       pbkdf_limits.min_memory,
				       max_memory_kb,
				       parallel_threads, time_ms, iterations_out,
				       memory_out, progress, usrptr);
	return r;
}
