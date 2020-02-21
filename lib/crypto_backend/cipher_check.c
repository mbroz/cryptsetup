/*
 * Cipher performance check
 *
 * Copyright (C) 2018-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2020 Milan Broz
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

#include <errno.h>
#include <time.h>
#include "crypto_backend_internal.h"

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

/*
 * This is not simulating storage, so using disk block causes extreme overhead.
 * Let's use some fixed block size where results are more reliable...
 */
#define CIPHER_BLOCK_BYTES 65536

/*
 * If the measured value is lower, encrypted buffer is probably too small
 * and calculated values are not reliable.
 */
#define CIPHER_TIME_MIN_MS 0.001

/*
 * The whole test depends on Linux kernel usermode crypto API for now.
 * (The same implementations are used in dm-crypt though.)
 */

static int time_ms(struct timespec *start, struct timespec *end, double *ms)
{
	double start_ms, end_ms;

	start_ms = start->tv_sec * 1000.0 + start->tv_nsec / (1000.0 * 1000);
	end_ms   = end->tv_sec * 1000.0 + end->tv_nsec / (1000.0 * 1000);

	*ms = end_ms - start_ms;
	return 0;
}

static int cipher_perf_one(const char *name, const char *mode, char *buffer, size_t buffer_size,
			  const char *key, size_t key_size, const char *iv, size_t iv_size, int enc)
{
	struct crypt_cipher_kernel cipher;
	size_t done = 0, block = CIPHER_BLOCK_BYTES;
	int r;

	if (buffer_size < block)
		block = buffer_size;

	r = crypt_cipher_init_kernel(&cipher, name, mode, key, key_size);
	if (r < 0)
		return r;

	while (done < buffer_size) {
		if ((done + block) > buffer_size)
			block = buffer_size - done;

		if (enc)
			r = crypt_cipher_encrypt_kernel(&cipher, &buffer[done], &buffer[done],
						 block, iv, iv_size);
		else
			r = crypt_cipher_decrypt_kernel(&cipher, &buffer[done], &buffer[done],
						 block, iv, iv_size);
		if (r < 0)
			break;

		done += block;
	}

	crypt_cipher_destroy_kernel(&cipher);

	return r;
}
static int cipher_measure(const char *name, const char *mode, char *buffer, size_t buffer_size,
			  const char *key, size_t key_size, const char *iv, size_t iv_size,
			  int encrypt, double *ms)
{
	struct timespec start, end;
	int r;

	/*
	 * Using getrusage would be better here but the precision
	 * is not adequate, so better stick with CLOCK_MONOTONIC
	 */
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &start) < 0)
		return -EINVAL;

	r = cipher_perf_one(name, mode, buffer, buffer_size, key, key_size, iv, iv_size, encrypt);
	if (r < 0)
		return r;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &end) < 0)
		return -EINVAL;

	r = time_ms(&start, &end, ms);
	if (r < 0)
		return r;

	if (*ms < CIPHER_TIME_MIN_MS)
		return -ERANGE;

	return 0;
}

static double speed_mbs(unsigned long bytes, double ms)
{
	double speed = bytes, s = ms / 1000.;

	return speed / (1024 * 1024) / s;
}

int crypt_cipher_perf_kernel(const char *name, const char *mode, char *buffer, size_t buffer_size,
			     const char *key, size_t key_size, const char *iv, size_t iv_size,
			     double *encryption_mbs, double *decryption_mbs)
{
	double ms_enc, ms_dec, ms;
	int r, repeat_enc, repeat_dec;

	ms_enc = 0.0;
	repeat_enc = 1;
	while (ms_enc < 1000.0) {
		r = cipher_measure(name, mode, buffer, buffer_size, key, key_size, iv, iv_size, 1, &ms);
		if (r < 0)
			return r;
		ms_enc += ms;
		repeat_enc++;
	}

	ms_dec = 0.0;
	repeat_dec = 1;
	while (ms_dec < 1000.0) {
		r = cipher_measure(name, mode, buffer, buffer_size, key, key_size, iv, iv_size, 0, &ms);
		if (r < 0)
			return r;
		ms_dec += ms;
		repeat_dec++;
	}

	*encryption_mbs = speed_mbs(buffer_size * repeat_enc, ms_enc);
	*decryption_mbs = speed_mbs(buffer_size * repeat_dec, ms_dec);

	return  0;
}
