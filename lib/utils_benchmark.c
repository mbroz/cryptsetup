/*
 * libcryptsetup - cryptsetup library, cipher benchmark
 *
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2020 Milan Broz
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

#include "internal.h"

int crypt_benchmark(struct crypt_device *cd,
	const char *cipher,
	const char *cipher_mode,
	size_t volume_key_size,
	size_t iv_size,
	size_t buffer_size,
	double *encryption_mbs,
	double *decryption_mbs)
{
	void *buffer = NULL;
	char *iv = NULL, *key = NULL, mode[MAX_CIPHER_LEN], *c;
	int r;

	if (!cipher || !cipher_mode || !volume_key_size || !encryption_mbs || !decryption_mbs)
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	r = -ENOMEM;
	if (posix_memalign(&buffer, crypt_getpagesize(), buffer_size))
		goto out;

	r = crypt_cipher_ivsize(cipher, cipher_mode);
	if (r >= 0 && iv_size != (size_t)r) {
		log_dbg(cd, "IV length for benchmark adjusted to %i bytes (requested %zu).", r, iv_size);
		iv_size = r;
	}

	if (iv_size) {
		iv = malloc(iv_size);
		if (!iv)
			goto out;
		crypt_random_get(cd, iv, iv_size, CRYPT_RND_NORMAL);
	}

	key = malloc(volume_key_size);
	if (!key)
		goto out;

	crypt_random_get(cd, key, volume_key_size, CRYPT_RND_NORMAL);

	strncpy(mode, cipher_mode, sizeof(mode)-1);
	/* Ignore IV generator */
	if ((c  = strchr(mode, '-')))
		*c = '\0';

	r = crypt_cipher_perf_kernel(cipher, cipher_mode, buffer, buffer_size, key, volume_key_size,
				     iv, iv_size, encryption_mbs, decryption_mbs);

	if (r == -ERANGE)
		log_dbg(cd, "Measured cipher runtime is too low.");
	else if (r)
		log_dbg(cd, "Cannot initialize cipher %s, mode %s, key size %zu, IV size %zu.",
			cipher, cipher_mode, volume_key_size, iv_size);
out:
	free(buffer);
	free(key);
	free(iv);

	return r;
}

int crypt_benchmark_pbkdf(struct crypt_device *cd,
	struct crypt_pbkdf_type *pbkdf,
	const char *password,
	size_t password_size,
	const char *salt,
	size_t salt_size,
	size_t volume_key_size,
	int (*progress)(uint32_t time_ms, void *usrptr),
	void *usrptr)
{
	int r;
	const char *kdf_opt;

	if (!pbkdf || (!password && password_size))
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	kdf_opt = !strcmp(pbkdf->type, CRYPT_KDF_PBKDF2) ? pbkdf->hash : "";

	log_dbg(cd, "Running %s(%s) benchmark.", pbkdf->type, kdf_opt);

	r = crypt_pbkdf_perf(pbkdf->type, pbkdf->hash, password, password_size,
			     salt, salt_size, volume_key_size, pbkdf->time_ms,
			     pbkdf->max_memory_kb, pbkdf->parallel_threads,
			     &pbkdf->iterations, &pbkdf->max_memory_kb, progress, usrptr);

	if (!r)
		log_dbg(cd, "Benchmark returns %s(%s) %u iterations, %u memory, %u threads (for %zu-bits key).",
			pbkdf->type, kdf_opt, pbkdf->iterations, pbkdf->max_memory_kb,
			pbkdf->parallel_threads, volume_key_size * 8);
	return r;
}

struct benchmark_usrptr {
	struct crypt_device *cd;
	struct crypt_pbkdf_type *pbkdf;
};

static int benchmark_callback(uint32_t time_ms, void *usrptr)
{
	struct benchmark_usrptr *u = usrptr;

	log_dbg(u->cd, "PBKDF benchmark: memory cost = %u, iterations = %u, "
		"threads = %u (took %u ms)", u->pbkdf->max_memory_kb,
		u->pbkdf->iterations, u->pbkdf->parallel_threads, time_ms);

	return 0;
}

/*
 * Used in internal places to benchmark crypt_device context PBKDF.
 * Once requested parameters are benchmarked, iterations attribute is set,
 * and the benchmarked values can be reused.
 * Note that memory cost can be changed after benchmark (if used).
 * NOTE: You need to check that you are benchmarking for the same key size.
 */
int crypt_benchmark_pbkdf_internal(struct crypt_device *cd,
				   struct crypt_pbkdf_type *pbkdf,
				   size_t volume_key_size)
{
	struct crypt_pbkdf_limits pbkdf_limits;
	double PBKDF2_tmp;
	uint32_t ms_tmp;
	int r = -EINVAL;
	struct benchmark_usrptr u = {
		.cd = cd,
		.pbkdf = pbkdf
	};

	r = crypt_pbkdf_get_limits(pbkdf->type, &pbkdf_limits);
	if (r)
		return r;

	if (pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK) {
		if (pbkdf->iterations) {
			log_dbg(cd, "Reusing PBKDF values (no benchmark flag is set).");
			return 0;
		}
		log_err(cd, _("PBKDF benchmark disabled but iterations not set."));
		return -EINVAL;
	}

	/* For PBKDF2 run benchmark always. Also note it depends on volume_key_size! */
	if (!strcmp(pbkdf->type, CRYPT_KDF_PBKDF2)) {
		/*
		 * For PBKDF2 it is enough to run benchmark for only 1 second
		 * and interpolate final iterations value from it.
		 */
		ms_tmp = pbkdf->time_ms;
		pbkdf->time_ms = 1000;
		pbkdf->parallel_threads = 0; /* N/A in PBKDF2 */
		pbkdf->max_memory_kb = 0; /* N/A in PBKDF2 */

		r = crypt_benchmark_pbkdf(cd, pbkdf, "foo", 3, "bar", 3,
					volume_key_size, &benchmark_callback, &u);
		pbkdf->time_ms = ms_tmp;
		if (r < 0) {
			log_err(cd, _("Not compatible PBKDF2 options (using hash algorithm %s)."),
				pbkdf->hash);
			return r;
		}

		PBKDF2_tmp = ((double)pbkdf->iterations * pbkdf->time_ms / 1000.);
		if (PBKDF2_tmp > (double)UINT32_MAX)
			return -EINVAL;
		pbkdf->iterations = at_least((uint32_t)PBKDF2_tmp, pbkdf_limits.min_iterations);
	} else {
		/* Already benchmarked */
		if (pbkdf->iterations) {
			log_dbg(cd, "Reusing PBKDF values.");
			return 0;
		}

		r = crypt_benchmark_pbkdf(cd, pbkdf, "foo", 3,
			"0123456789abcdef0123456789abcdef", 32,
			volume_key_size, &benchmark_callback, &u);
		if (r < 0)
			log_err(cd, _("Not compatible PBKDF options."));
	}

	return r;
}
