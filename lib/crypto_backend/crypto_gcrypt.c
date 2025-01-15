// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * GCRYPT crypto backend implementation
 *
 * Copyright (C) 2010-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2010-2025 Milan Broz
 */

#include <stdio.h>
#include <errno.h>
#include <strings.h>
#include <gcrypt.h>
#include <pthread.h>
#include "crypto_backend_internal.h"

static int crypto_backend_initialised = 0;
static int crypto_backend_secmem = 1;
static int crypto_backend_whirlpool_bug = -1;
static char version[64];

struct crypt_hash {
	gcry_md_hd_t hd;
	int hash_id;
	int hash_len;
};

struct crypt_hmac {
	gcry_md_hd_t hd;
	int hash_id;
	int hash_len;
};

struct crypt_cipher {
	bool use_kernel;
	union {
	struct crypt_cipher_kernel kernel;
	gcry_cipher_hd_t hd;
	} u;
};

struct hash_alg {
	const char *name;
	const char *gcrypt_name;
};

/*
 * Test for wrong Whirlpool variant,
 * Ref: https://lists.gnupg.org/pipermail/gcrypt-devel/2014-January/002889.html
 */
static void crypt_hash_test_whirlpool_bug(void)
{
	struct crypt_hash *h;
	char buf[2] = "\0\0", hash_out1[64], hash_out2[64];

	if (crypto_backend_whirlpool_bug >= 0)
		return;

	crypto_backend_whirlpool_bug = 0;
	if (crypt_hash_init(&h, "whirlpool"))
		return;

	/* One shot */
	if (crypt_hash_write(h, &buf[0], 2) ||
	    crypt_hash_final(h, hash_out1, 64)) {
		crypt_hash_destroy(h);
		return;
	}

	/* Split buf (crypt_hash_final resets hash state) */
	if (crypt_hash_write(h, &buf[0], 1) ||
	    crypt_hash_write(h, &buf[1], 1) ||
	    crypt_hash_final(h, hash_out2, 64)) {
		crypt_hash_destroy(h);
		return;
	}

	crypt_hash_destroy(h);

	if (memcmp(hash_out1, hash_out2, 64))
		crypto_backend_whirlpool_bug = 1;
}

int crypt_backend_init(bool fips __attribute__((unused)))
{
	int r;

	if (crypto_backend_initialised)
		return 0;

	if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
		if (!gcry_check_version (GCRYPT_REQ_VERSION)) {
			return -ENOSYS;
		}

/* If gcrypt compiled to support POSIX 1003.1e capabilities,
 * it drops all privileges during secure memory initialisation.
 * For now, the only workaround is to disable secure memory in gcrypt.
 * cryptsetup always need at least cap_sys_admin privilege for dm-ioctl
 * and it locks its memory space anyway.
 */
#if 0
		gcry_control (GCRYCTL_DISABLE_SECMEM);
		crypto_backend_secmem = 0;
#else

		gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
		gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
		gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
#endif
		gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	}

	crypto_backend_initialised = 1;
	crypt_hash_test_whirlpool_bug();

	r = snprintf(version, sizeof(version), "gcrypt %s%s%s%s",
		 gcry_check_version(NULL),
		 crypto_backend_secmem ? "" : ", secmem disabled",
		 crypto_backend_whirlpool_bug > 0 ? ", flawed whirlpool" : "",
		 crypt_backend_flags() & CRYPT_BACKEND_ARGON2 ? ", argon2" : "");
	if (r < 0 || (size_t)r >= sizeof(version))
		return -EINVAL;

	return 0;
}

void crypt_backend_destroy(void)
{
	if (crypto_backend_initialised)
		gcry_control(GCRYCTL_TERM_SECMEM);

	crypto_backend_initialised = 0;
}

const char *crypt_backend_version(void)
{
	return crypto_backend_initialised ? version : "";
}

uint32_t crypt_backend_flags(void)
{
	uint32_t flags = 0;
#if HAVE_DECL_GCRY_KDF_ARGON2 && !USE_INTERNAL_ARGON2
	flags |= CRYPT_BACKEND_ARGON2;
#endif
	return flags;
}

static const char *crypt_hash_compat_name(const char *name, unsigned int *flags)
{
	const char *hash_name = name;
	int i;
	static struct hash_alg hash_algs[] = {
	{ "blake2b-160", "blake2b_160" },
	{ "blake2b-256", "blake2b_256" },
	{ "blake2b-384", "blake2b_384" },
	{ "blake2b-512", "blake2b_512" },
	{ "blake2s-128", "blake2s_128" },
	{ "blake2s-160", "blake2s_160" },
	{ "blake2s-224", "blake2s_224" },
	{ "blake2s-256", "blake2s_256" },
	{ NULL,          NULL,         }};

	if (!name)
		return NULL;

	/* "whirlpool_gcryptbug" is out shortcut to flawed whirlpool
	 * in libgcrypt < 1.6.0 */
	if (!strcasecmp(name, "whirlpool_gcryptbug")) {
#if GCRYPT_VERSION_NUMBER >= 0x010601
		if (flags)
			*flags |= GCRY_MD_FLAG_BUGEMU1;
#endif
		hash_name = "whirlpool";
	}

	i = 0;
	while (hash_algs[i].name) {
		if (!strcasecmp(name, hash_algs[i].name)) {
			hash_name =  hash_algs[i].gcrypt_name;
			break;
		}
		i++;
	}

	return hash_name;
}

/* HASH */
int crypt_hash_size(const char *name)
{
	int hash_id;

	assert(crypto_backend_initialised);

	hash_id = gcry_md_map_name(crypt_hash_compat_name(name, NULL));
	if (!hash_id)
		return -EINVAL;

	return gcry_md_get_algo_dlen(hash_id);
}

int crypt_hash_init(struct crypt_hash **ctx, const char *name)
{
	struct crypt_hash *h;
	unsigned int flags = 0;

	assert(crypto_backend_initialised);

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->hash_id = gcry_md_map_name(crypt_hash_compat_name(name, &flags));
	if (!h->hash_id) {
		free(h);
		return -EINVAL;
	}

	if (gcry_md_open(&h->hd, h->hash_id, flags)) {
		free(h);
		return -EINVAL;
	}

	h->hash_len = gcry_md_get_algo_dlen(h->hash_id);
	*ctx = h;
	return 0;
}

static void crypt_hash_restart(struct crypt_hash *ctx)
{
	gcry_md_reset(ctx->hd);
}

int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length)
{
	gcry_md_write(ctx->hd, buffer, length);
	return 0;
}

int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length)
{
	unsigned char *hash;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	hash = gcry_md_read(ctx->hd, ctx->hash_id);
	if (!hash)
		return -EINVAL;

	crypt_backend_memcpy(buffer, hash, length);
	crypt_hash_restart(ctx);

	return 0;
}

void crypt_hash_destroy(struct crypt_hash *ctx)
{
	gcry_md_close(ctx->hd);
	free(ctx);
}

/* HMAC */
int crypt_hmac_size(const char *name)
{
	return crypt_hash_size(name);
}

int crypt_hmac_init(struct crypt_hmac **ctx, const char *name,
		    const void *key, size_t key_length)
{
	struct crypt_hmac *h;
	unsigned int flags = GCRY_MD_FLAG_HMAC;

	assert(crypto_backend_initialised);

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	h->hash_id = gcry_md_map_name(crypt_hash_compat_name(name, &flags));
	if (!h->hash_id) {
		free(h);
		return -EINVAL;
	}

	if (gcry_md_open(&h->hd, h->hash_id, flags)) {
		free(h);
		return -EINVAL;
	}

	if (gcry_md_setkey(h->hd, key, key_length)) {
		gcry_md_close(h->hd);
		free(h);
		return -EINVAL;
	}

	h->hash_len = gcry_md_get_algo_dlen(h->hash_id);
	*ctx = h;
	return 0;
}

static void crypt_hmac_restart(struct crypt_hmac *ctx)
{
	gcry_md_reset(ctx->hd);
}

int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length)
{
	gcry_md_write(ctx->hd, buffer, length);
	return 0;
}

int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length)
{
	unsigned char *hash;

	if (length > (size_t)ctx->hash_len)
		return -EINVAL;

	hash = gcry_md_read(ctx->hd, ctx->hash_id);
	if (!hash)
		return -EINVAL;

	crypt_backend_memcpy(buffer, hash, length);
	crypt_hmac_restart(ctx);

	return 0;
}

void crypt_hmac_destroy(struct crypt_hmac *ctx)
{
	gcry_md_close(ctx->hd);
	free(ctx);
}

/* RNG */
int crypt_backend_rng(char *buffer, size_t length, int quality, int fips __attribute__((unused)))
{
	switch(quality) {
	case CRYPT_RND_NORMAL:
		gcry_randomize(buffer, length, GCRY_STRONG_RANDOM);
		break;
	case CRYPT_RND_SALT:
	case CRYPT_RND_KEY:
	default:
		gcry_randomize(buffer, length, GCRY_VERY_STRONG_RANDOM);
		break;
	}
	return 0;
}

static int pbkdf2(const char *hash,
		  const char *password, size_t password_length,
		  const char *salt, size_t salt_length,
		  char *key, size_t key_length,
		  uint32_t iterations)
{
	const char *hash_name = crypt_hash_compat_name(hash, NULL);

#if USE_INTERNAL_PBKDF2
	return pkcs5_pbkdf2(hash_name, password, password_length, salt, salt_length,
			    iterations, key_length, key, 0);
#else /* USE_INTERNAL_PBKDF2 */
	int hash_id = gcry_md_map_name(hash_name);

	if (!hash_id)
		return -EINVAL;

	if (gcry_kdf_derive(password, password_length, GCRY_KDF_PBKDF2, hash_id,
	    salt, salt_length, iterations, key_length, key))
		return -EINVAL;

	return 0;
#endif /* USE_INTERNAL_PBKDF2 */
}

#if HAVE_DECL_GCRY_KDF_ARGON2 && !USE_INTERNAL_ARGON2
struct gcrypt_thread_job
{
	pthread_t thread;
	struct job_thread_param {
		gcry_kdf_job_fn_t job;
		void *p;
	} work;
};

struct gcrypt_threads
{
	pthread_attr_t attr;
	unsigned int num_threads;
	unsigned int max_threads;
	struct gcrypt_thread_job *jobs_ctx;
};

static void *gcrypt_job_thread(void *p)
{
	struct job_thread_param *param = p;
	param->job(param->p);
	pthread_exit(NULL);
}

static int gcrypt_wait_all_jobs(void *ctx)
{
	unsigned int i;
	struct gcrypt_threads *threads = ctx;

	for (i = 0; i < threads->num_threads; i++) {
		pthread_join(threads->jobs_ctx[i].thread, NULL);
		threads->jobs_ctx[i].thread = 0;
	}

	threads->num_threads = 0;
	return 0;
}

static int gcrypt_dispatch_job(void *ctx, gcry_kdf_job_fn_t job, void *p)
{
	struct gcrypt_threads *threads = ctx;

	if (threads->num_threads >= threads->max_threads)
		return -1;

	threads->jobs_ctx[threads->num_threads].work.job = job;
	threads->jobs_ctx[threads->num_threads].work.p = p;

	if (pthread_create(&threads->jobs_ctx[threads->num_threads].thread, &threads->attr,
			   gcrypt_job_thread, &threads->jobs_ctx[threads->num_threads].work))
		return -1;

	threads->num_threads++;
	return 0;
}

static int gcrypt_argon2(const char *type,
	const char *password, size_t password_length,
	const char *salt, size_t salt_length,
	char *key, size_t key_length,
	uint32_t iterations, uint32_t memory, uint32_t parallel)
{
	gcry_kdf_hd_t hd;
	int atype, r = -EINVAL;
	unsigned long param[4];
	struct gcrypt_threads threads = {
		.max_threads = parallel,
		.num_threads = 0
	};
	const gcry_kdf_thread_ops_t ops = {
		.jobs_context = &threads,
		.dispatch_job = gcrypt_dispatch_job,
		.wait_all_jobs = gcrypt_wait_all_jobs
	};
	gpg_error_t err;

	if (!strcmp(type, "argon2i"))
		atype = GCRY_KDF_ARGON2I;
	else if (!strcmp(type, "argon2id"))
		atype = GCRY_KDF_ARGON2ID;
	else
		return -EINVAL;

	param[0] = key_length;
	param[1] = iterations;
	param[2] = memory;
	param[3] = parallel;

	err = gcry_kdf_open(&hd, GCRY_KDF_ARGON2, atype, param, 4,
			password, password_length, salt, salt_length,
			NULL, 0, NULL, 0);
	if (err)
		return ((err & GPG_ERR_CODE_MASK) == GPG_ERR_ENOMEM) ? -ENOMEM : -EINVAL;

	if (parallel == 1) {
		/* Do not use threads here */
		if (gcry_kdf_compute(hd, NULL))
			goto out;
	} else {
		threads.jobs_ctx = calloc(threads.max_threads,
				      sizeof(struct gcrypt_thread_job));
		if (!threads.jobs_ctx)
			goto out;

		if (pthread_attr_init(&threads.attr))
			goto out;

		if (gcry_kdf_compute(hd, &ops))
			goto out;
	}

	if (gcry_kdf_final(hd, key_length, key))
		goto out;
	r = 0;
out:
	gcry_kdf_close(hd);
	pthread_attr_destroy(&threads.attr);
	free(threads.jobs_ctx);

	return r;
}
#endif

/* PBKDF */
int crypt_pbkdf(const char *kdf, const char *hash,
		const char *password, size_t password_length,
		const char *salt, size_t salt_length,
		char *key, size_t key_length,
		uint32_t iterations, uint32_t memory, uint32_t parallel)
{
	if (!kdf)
		return -EINVAL;

	if (!strcmp(kdf, "pbkdf2"))
		return pbkdf2(hash, password, password_length, salt, salt_length,
			      key, key_length, iterations);
	else if (!strncmp(kdf, "argon2", 6))
#if HAVE_DECL_GCRY_KDF_ARGON2 && !USE_INTERNAL_ARGON2
		return gcrypt_argon2(kdf, password, password_length, salt, salt_length,
				     key, key_length, iterations, memory, parallel);
#else
		return argon2(kdf, password, password_length, salt, salt_length,
			      key, key_length, iterations, memory, parallel);
#endif
	return -EINVAL;
}

/* Block ciphers */
static int _cipher_init(gcry_cipher_hd_t *hd, const char *name,
			const char *mode, const void *buffer, size_t length)
{
	int cipher_id, mode_id;

	cipher_id = gcry_cipher_map_name(name);
	if (cipher_id == GCRY_CIPHER_MODE_NONE)
		return -ENOENT;

	if (!strcmp(mode, "ecb"))
		mode_id = GCRY_CIPHER_MODE_ECB;
	else if (!strcmp(mode, "cbc"))
		mode_id = GCRY_CIPHER_MODE_CBC;
#if HAVE_DECL_GCRY_CIPHER_MODE_XTS
	else if (!strcmp(mode, "xts"))
		mode_id = GCRY_CIPHER_MODE_XTS;
#endif
	else
		return -ENOENT;

	if (gcry_cipher_open(hd, cipher_id, mode_id, 0))
		return -EINVAL;

	if (gcry_cipher_setkey(*hd, buffer, length)) {
		gcry_cipher_close(*hd);
		return -EINVAL;
	}

	return 0;
}

int crypt_cipher_init(struct crypt_cipher **ctx, const char *name,
		    const char *mode, const void *key, size_t key_length)
{
	struct crypt_cipher *h;
	int r;

	h = malloc(sizeof(*h));
	if (!h)
		return -ENOMEM;

	if (!_cipher_init(&h->u.hd, name, mode, key, key_length)) {
		h->use_kernel = false;
		*ctx = h;
		return 0;
	}

	r = crypt_cipher_init_kernel(&h->u.kernel, name, mode, key, key_length);
	if (r < 0) {
		free(h);
		return r;
	}

	h->use_kernel = true;
	*ctx = h;
	return 0;
}

void crypt_cipher_destroy(struct crypt_cipher *ctx)
{
	if (ctx->use_kernel)
		crypt_cipher_destroy_kernel(&ctx->u.kernel);
	else
		gcry_cipher_close(ctx->u.hd);
	free(ctx);
}

int crypt_cipher_encrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	if (ctx->use_kernel)
		return crypt_cipher_encrypt_kernel(&ctx->u.kernel, in, out, length, iv, iv_length);

	if (iv && gcry_cipher_setiv(ctx->u.hd, iv, iv_length))
		return -EINVAL;

	if (gcry_cipher_encrypt(ctx->u.hd, out, length, in, length))
		return -EINVAL;

	return 0;
}

int crypt_cipher_decrypt(struct crypt_cipher *ctx,
			 const char *in, char *out, size_t length,
			 const char *iv, size_t iv_length)
{
	if (ctx->use_kernel)
		return crypt_cipher_decrypt_kernel(&ctx->u.kernel, in, out, length, iv, iv_length);

	if (iv && gcry_cipher_setiv(ctx->u.hd, iv, iv_length))
		return -EINVAL;

	if (gcry_cipher_decrypt(ctx->u.hd, out, length, in, length))
		return -EINVAL;

	return 0;
}

bool crypt_cipher_kernel_only(struct crypt_cipher *ctx)
{
	return ctx->use_kernel;
}

int crypt_bitlk_decrypt_key(const void *key, size_t key_length,
			    const char *in, char *out, size_t length,
			    const char *iv, size_t iv_length,
			    const char *tag, size_t tag_length)
{
#ifdef GCRY_CCM_BLOCK_LEN
	gcry_cipher_hd_t hd;
	uint64_t l[3];
	int r = -EINVAL;

	if (gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CCM, 0))
		return -EINVAL;

	if (gcry_cipher_setkey(hd, key, key_length))
		goto out;

	if (gcry_cipher_setiv(hd, iv, iv_length))
		goto out;

	l[0] = length;
	l[1] = 0;
	l[2] = tag_length;
	if (gcry_cipher_ctl(hd, GCRYCTL_SET_CCM_LENGTHS, l, sizeof(l)))
		goto out;

	if (gcry_cipher_decrypt(hd, out, length, in, length))
		goto out;

	if (gcry_cipher_checktag(hd, tag, tag_length))
		goto out;

	r = 0;
out:
	gcry_cipher_close(hd);
	return r;
#else
	return -ENOTSUP;
#endif
}

int crypt_backend_memeq(const void *m1, const void *m2, size_t n)
{
	return crypt_internal_memeq(m1, m2, n);
}

#if !ENABLE_FIPS
bool crypt_fips_mode(void) { return false; }
#else
bool crypt_fips_mode(void)
{
	static bool fips_mode = false, fips_checked = false;

	if (fips_checked)
		return fips_mode;

	if (crypt_backend_init(false /* ignored */))
		return false;

	fips_mode = gcry_fips_mode_active();
	fips_checked = true;

	return fips_mode;
}
#endif /* ENABLE FIPS */
