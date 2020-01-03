/*
 * utils_pbkdf - PBKDF settings for libcryptsetup
 *
 * Copyright (C) 2009-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2020 Milan Broz
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

const struct crypt_pbkdf_type default_pbkdf2 = {
	.type = CRYPT_KDF_PBKDF2,
	.hash = DEFAULT_LUKS1_HASH,
	.time_ms = DEFAULT_LUKS1_ITER_TIME
};

const struct crypt_pbkdf_type default_argon2i = {
	.type = CRYPT_KDF_ARGON2I,
	.hash = DEFAULT_LUKS1_HASH,
	.time_ms = DEFAULT_LUKS2_ITER_TIME,
	.max_memory_kb = DEFAULT_LUKS2_MEMORY_KB,
	.parallel_threads = DEFAULT_LUKS2_PARALLEL_THREADS
};

const struct crypt_pbkdf_type default_argon2id = {
	.type = CRYPT_KDF_ARGON2ID,
	.hash = DEFAULT_LUKS1_HASH,
	.time_ms = DEFAULT_LUKS2_ITER_TIME,
	.max_memory_kb = DEFAULT_LUKS2_MEMORY_KB,
	.parallel_threads = DEFAULT_LUKS2_PARALLEL_THREADS
};

const struct crypt_pbkdf_type *crypt_get_pbkdf_type_params(const char *pbkdf_type)
{
	if (!pbkdf_type)
		return NULL;

	if (!strcmp(pbkdf_type, CRYPT_KDF_PBKDF2))
		return &default_pbkdf2;
	else if (!strcmp(pbkdf_type, CRYPT_KDF_ARGON2I))
		return &default_argon2i;
	else if (!strcmp(pbkdf_type, CRYPT_KDF_ARGON2ID))
		return &default_argon2id;

	return NULL;
}

static uint32_t adjusted_phys_memory(void)
{
	uint64_t memory_kb = crypt_getphysmemory_kb();

	/* Ignore bogus value */
	if (memory_kb < (128 * 1024) || memory_kb > UINT32_MAX)
		return DEFAULT_LUKS2_MEMORY_KB;

	/*
	 * Never use more than half of physical memory.
	 * OOM killer is too clever...
	 */
	memory_kb /= 2;

	return memory_kb;
}

/*
 * PBKDF configuration interface
 */
int verify_pbkdf_params(struct crypt_device *cd,
			const struct crypt_pbkdf_type *pbkdf)
{
	struct crypt_pbkdf_limits pbkdf_limits;
	const char *pbkdf_type;
	int r;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	if (!pbkdf->type ||
	    (!pbkdf->hash && !strcmp(pbkdf->type, "pbkdf2")))
		return -EINVAL;

	if (!pbkdf->time_ms && !(pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK)) {
		log_err(cd, _("Requested PBKDF target time cannot be zero."));
		return -EINVAL;
	}

	r = crypt_parse_pbkdf(pbkdf->type, &pbkdf_type);
	if (r < 0) {
		log_err(cd, _("Unknown PBKDF type %s."), pbkdf->type);
		return r;
	}

	if (pbkdf->hash && crypt_hash_size(pbkdf->hash) < 0) {
		log_err(cd, _("Requested hash %s is not supported."), pbkdf->hash);
		return -EINVAL;
	}

	r = crypt_pbkdf_get_limits(pbkdf->type, &pbkdf_limits);
	if (r < 0)
		return r;

	if (crypt_get_type(cd) &&
	    !strcmp(crypt_get_type(cd), CRYPT_LUKS1) &&
	    strcmp(pbkdf_type, CRYPT_KDF_PBKDF2)) {
		log_err(cd, _("Requested PBKDF type is not supported for LUKS1."));
		return -EINVAL;
	}

	if (!strcmp(pbkdf_type, CRYPT_KDF_PBKDF2)) {
		if (pbkdf->max_memory_kb || pbkdf->parallel_threads) {
			log_err(cd, _("PBKDF max memory or parallel threads must not be set with pbkdf2."));
			return -EINVAL;
		}
		if (pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK &&
		    pbkdf->iterations < pbkdf_limits.min_iterations) {
			log_err(cd, _("Forced iteration count is too low for %s (minimum is %u)."),
				pbkdf_type, pbkdf_limits.min_iterations);
			return -EINVAL;
		}
		return 0;
	}

	/* TODO: properly define minimal iterations and also minimal memory values */
	if (pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK) {
		if (pbkdf->iterations < pbkdf_limits.min_iterations) {
			log_err(cd, _("Forced iteration count is too low for %s (minimum is %u)."),
				pbkdf_type, pbkdf_limits.min_iterations);
			r = -EINVAL;
		}
		if (pbkdf->max_memory_kb < pbkdf_limits.min_memory) {
			log_err(cd, _("Forced memory cost is too low for %s (minimum is %u kilobytes)."),
				pbkdf_type, pbkdf_limits.min_memory);
			r = -EINVAL;
		}
	}

	if (pbkdf->max_memory_kb > pbkdf_limits.max_memory) {
		log_err(cd, _("Requested maximum PBKDF memory cost is too high (maximum is %d kilobytes)."),
			pbkdf_limits.max_memory);
		r = -EINVAL;
	}
	if (!pbkdf->max_memory_kb) {
		log_err(cd, _("Requested maximum PBKDF memory cannot be zero."));
		r = -EINVAL;
	}
	if (!pbkdf->parallel_threads) {
		log_err(cd, _("Requested PBKDF parallel threads cannot be zero."));
		r = -EINVAL;
	}

	return r;
}

int init_pbkdf_type(struct crypt_device *cd,
		    const struct crypt_pbkdf_type *pbkdf,
		    const char *dev_type)
{
	struct crypt_pbkdf_type *cd_pbkdf = crypt_get_pbkdf(cd);
	struct crypt_pbkdf_limits pbkdf_limits;
	const char *hash, *type;
	unsigned cpus;
	uint32_t old_flags, memory_kb;
	int r;

	if (crypt_fips_mode()) {
		if (pbkdf && strcmp(pbkdf->type, CRYPT_KDF_PBKDF2)) {
			log_err(cd, _("Only PBKDF2 is supported in FIPS mode."));
			return -EINVAL;
		}
		if (!pbkdf)
			pbkdf = crypt_get_pbkdf_type_params(CRYPT_KDF_PBKDF2);
	}

	if (!pbkdf && dev_type && !strcmp(dev_type, CRYPT_LUKS2))
		pbkdf = crypt_get_pbkdf_type_params(DEFAULT_LUKS2_PBKDF);
	else if (!pbkdf)
		pbkdf = crypt_get_pbkdf_type_params(CRYPT_KDF_PBKDF2);

	r = verify_pbkdf_params(cd, pbkdf);
	if (r)
		return r;

	r = crypt_pbkdf_get_limits(pbkdf->type, &pbkdf_limits);
	if (r < 0)
		return r;

	type = strdup(pbkdf->type);
	hash = pbkdf->hash ? strdup(pbkdf->hash) : NULL;

	if (!type || (!hash && pbkdf->hash)) {
		free(CONST_CAST(void*)type);
		free(CONST_CAST(void*)hash);
		return -ENOMEM;
	}

	free(CONST_CAST(void*)cd_pbkdf->type);
	free(CONST_CAST(void*)cd_pbkdf->hash);
	cd_pbkdf->type = type;
	cd_pbkdf->hash = hash;

	old_flags = cd_pbkdf->flags;
	cd_pbkdf->flags = pbkdf->flags;

	/* Reset iteration count so benchmark must run again. */
	if (cd_pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK)
		cd_pbkdf->iterations = pbkdf->iterations;
	else
		cd_pbkdf->iterations = 0;

	if (old_flags & CRYPT_PBKDF_ITER_TIME_SET)
		cd_pbkdf->flags |= CRYPT_PBKDF_ITER_TIME_SET;
	else
		cd_pbkdf->time_ms = pbkdf->time_ms;

	cd_pbkdf->max_memory_kb = pbkdf->max_memory_kb;
	cd_pbkdf->parallel_threads = pbkdf->parallel_threads;

	if (cd_pbkdf->parallel_threads > pbkdf_limits.max_parallel) {
		log_dbg(cd, "Maximum PBKDF threads is %d (requested %d).",
			pbkdf_limits.max_parallel, cd_pbkdf->parallel_threads);
		cd_pbkdf->parallel_threads = pbkdf_limits.max_parallel;
	}

	if (cd_pbkdf->parallel_threads) {
		cpus = crypt_cpusonline();
		if (cd_pbkdf->parallel_threads > cpus) {
			log_dbg(cd, "Only %u active CPUs detected, "
				"PBKDF threads decreased from %d to %d.",
				cpus, cd_pbkdf->parallel_threads, cpus);
			cd_pbkdf->parallel_threads = cpus;
		}
	}

	if (cd_pbkdf->max_memory_kb) {
		memory_kb = adjusted_phys_memory();
		if (cd_pbkdf->max_memory_kb > memory_kb) {
			log_dbg(cd, "Not enough physical memory detected, "
				"PBKDF max memory decreased from %dkB to %dkB.",
				cd_pbkdf->max_memory_kb, memory_kb);
			cd_pbkdf->max_memory_kb = memory_kb;
		}
	}

	if (!strcmp(pbkdf->type, CRYPT_KDF_PBKDF2))
		log_dbg(cd, "PBKDF %s-%s, time_ms %u (iterations %u).",
			cd_pbkdf->type, cd_pbkdf->hash, cd_pbkdf->time_ms, cd_pbkdf->iterations);
	else
		log_dbg(cd, "PBKDF %s, time_ms %u (iterations %u), max_memory_kb %u, parallel_threads %u.",
			cd_pbkdf->type, cd_pbkdf->time_ms, cd_pbkdf->iterations,
			cd_pbkdf->max_memory_kb, cd_pbkdf->parallel_threads);

	return 0;
}

/* Libcryptsetup API */

int crypt_set_pbkdf_type(struct crypt_device *cd, const struct crypt_pbkdf_type *pbkdf)
{
	if (!cd)
		return -EINVAL;

	if (!pbkdf)
		log_dbg(cd, "Resetting pbkdf type to default");

	crypt_get_pbkdf(cd)->flags = 0;

	return init_pbkdf_type(cd, pbkdf, crypt_get_type(cd));
}

const struct crypt_pbkdf_type *crypt_get_pbkdf_type(struct crypt_device *cd)
{
	if (!cd)
		return NULL;

	return crypt_get_pbkdf(cd)->type ? crypt_get_pbkdf(cd) : NULL;
}

const struct crypt_pbkdf_type *crypt_get_pbkdf_default(const char *type)
{
	if (!type)
		return NULL;

	if (!strcmp(type, CRYPT_LUKS1) || crypt_fips_mode())
		return crypt_get_pbkdf_type_params(CRYPT_KDF_PBKDF2);
	else if (!strcmp(type, CRYPT_LUKS2))
		return crypt_get_pbkdf_type_params(DEFAULT_LUKS2_PBKDF);

	return NULL;
}

void crypt_set_iteration_time(struct crypt_device *cd, uint64_t iteration_time_ms)
{
	struct crypt_pbkdf_type *pbkdf;
	uint32_t old_time_ms;

	if (!cd || iteration_time_ms > UINT32_MAX)
		return;

	pbkdf = crypt_get_pbkdf(cd);
	old_time_ms = pbkdf->time_ms;
	pbkdf->time_ms = (uint32_t)iteration_time_ms;

	if (pbkdf->type && verify_pbkdf_params(cd, pbkdf)) {
		pbkdf->time_ms = old_time_ms;
		log_dbg(cd, "Invalid iteration time.");
		return;
	}

	pbkdf->flags |= CRYPT_PBKDF_ITER_TIME_SET;

	/* iterations must be benchmarked now */
	pbkdf->flags &= ~(CRYPT_PBKDF_NO_BENCHMARK);
	pbkdf->iterations = 0;

	log_dbg(cd, "Iteration time set to %" PRIu64 " milliseconds.", iteration_time_ms);
}
