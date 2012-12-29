/*
 * libcryptsetup - cryptsetup library, cipher bechmark
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012, Milan Broz
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
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "internal.h"

/*
 * This is not simulating storage, so using disk block causes extreme overhead.
 * Let's use some fixed block size where results are more reliable...
 */
#define CIPHER_BLOCK_BYTES 65536

/*
 * The whole test depends on Linux kernel usermode crypto API for now.
 * (The same implementations are used in dm-crypt though.)
 */

struct cipher_perf {
	char name[32];
	char mode[32];
	char *key;
	size_t key_length;
	char *iv;
	size_t iv_length;
	size_t buffer_size;
};

static long time_ms(struct rusage *start, struct rusage *end)
{
	long ms = 0;

	/* For kernel backend, we need to measure only tim in kernel.
	ms = (end->ru_utime.tv_sec - start->ru_utime.tv_sec) * 1000;
	ms += (end->ru_utime.tv_usec - start->ru_utime.tv_usec) / 1000;
	*/

	ms += (end->ru_stime.tv_sec - start->ru_stime.tv_sec) * 1000;
	ms += (end->ru_stime.tv_usec - start->ru_stime.tv_usec) / 1000;

	return ms;
}

static int cipher_perf_one(struct cipher_perf *cp, char *buf,
			   size_t buf_size, int enc)
{
	struct crypt_cipher *cipher = NULL;
	size_t done = 0, block = CIPHER_BLOCK_BYTES;
	int r;

	if (buf_size < block)
		block = buf_size;

	r = crypt_cipher_init(&cipher, cp->name, cp->mode, cp->key, cp->key_length);
	if (r < 0) {
		log_dbg("Cannot initialise cipher %s, mode %s.", cp->name, cp->mode);
		return r;
	}

	while (done < buf_size) {
		if ((done + block) > buf_size)
			block = buf_size - done;

		if (enc)
			r = crypt_cipher_encrypt(cipher, &buf[done], &buf[done],
						 block, cp->iv, cp->iv_length);
		else
			r = crypt_cipher_decrypt(cipher, &buf[done], &buf[done],
						 block, cp->iv, cp->iv_length);
		if (r < 0)
			break;

		done += block;
	}

	crypt_cipher_destroy(cipher);

	return r;
}
static long cipher_measure(struct cipher_perf *cp, char *buf,
			   size_t buf_size, int encrypt)
{
	struct rusage rstart, rend;
	int r;

	if (getrusage(RUSAGE_SELF, &rstart) < 0)
		return -EINVAL;

	r = cipher_perf_one(cp, buf, buf_size, encrypt);
	if (r < 0)
		return r;

	if (getrusage(RUSAGE_SELF, &rend) < 0)
		return -EINVAL;

	return time_ms(&rstart, &rend);
}

static double speed_mbs(unsigned long bytes, unsigned long ms)
{
	double speed = bytes, s = ms / 1000.;

	return speed / (1024 * 1024) / s;
}

static int cipher_perf(struct cipher_perf *cp,
	double *encryption_mbs, double *decryption_mbs)
{
	long ms_enc, ms_dec, ms;
	int repeat_enc, repeat_dec;
	void *buf = NULL;

	if (posix_memalign(&buf, crypt_getpagesize(), cp->buffer_size))
		return -ENOMEM;

	ms_enc = 0;
	repeat_enc = 1;
	while (ms_enc < 1000) {
		ms = cipher_measure(cp, buf, cp->buffer_size, 1);
		if (ms < 0) {
			free(buf);
			return (int)ms;
		}
		ms_enc += ms;
		repeat_enc++;
	}

	ms_dec = 0;
	repeat_dec = 1;
	while (ms_dec < 1000) {
		ms = cipher_measure(cp, buf, cp->buffer_size, 0);
		if (ms < 0) {
			free(buf);
			return (int)ms;
		}
		ms_dec += ms;
		repeat_dec++;
	}

	free(buf);

	*encryption_mbs = speed_mbs(cp->buffer_size * repeat_enc, ms_enc);
	*decryption_mbs = speed_mbs(cp->buffer_size * repeat_dec, ms_dec);

	return  0;
}

int crypt_benchmark(struct crypt_device *cd,
	const char *cipher,
	const char *cipher_mode,
	size_t volume_key_size,
	size_t iv_size,
	size_t buffer_size,
	double *encryption_mbs,
	double *decryption_mbs)
{
	struct cipher_perf cp = {
		.key_length = volume_key_size,
		.iv_length = iv_size,
		.buffer_size = buffer_size,
	};
	char *c;
	int r;

	if (!cipher || !cipher_mode || !volume_key_size)
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = -ENOMEM;
	if (iv_size) {
		cp.iv = malloc(iv_size);
		if (!cp.iv)
			goto out;
		crypt_random_get(cd, cp.iv, iv_size, CRYPT_RND_NORMAL);
	}

	cp.key = malloc(volume_key_size);
	if (!cp.key)
		goto out;

	crypt_random_get(cd, cp.key, volume_key_size, CRYPT_RND_NORMAL);
	strncpy(cp.name, cipher, sizeof(cp.name)-1);
	strncpy(cp.mode, cipher_mode, sizeof(cp.mode)-1);

	/* Ignore IV generator */
	if ((c  = strchr(cp.mode, '-')))
		*c = '\0';

	r = cipher_perf(&cp, encryption_mbs, decryption_mbs);
out:
	free(cp.key);
	free(cp.iv);
	return r;
}

int crypt_benchmark_kdf(struct crypt_device *cd,
	const char *kdf,
	const char *hash,
	const char *password,
	size_t password_size,
	const char *salt,
	size_t salt_size,
	uint64_t *iterations_sec)
{
	int r;

	if (!iterations_sec)
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	if (!strncmp(kdf, "pbkdf2", 6))
		r = crypt_pbkdf_check(kdf, hash, password, password_size,
				      salt, salt_size, iterations_sec);
	else
		r = -EINVAL;

	if (!r)
		log_dbg("KDF %s, hash %s: %" PRIu64 " iterations per second.",
			kdf, hash, *iterations_sec);
	return r;
}
