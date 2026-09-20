// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Linux kernel cipher generic utilities
 *
 * Copyright (C) 2018-2026 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2026 Milan Broz
 */

#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include "crypto_backend.h"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct cipher_alg {
	const char *name;
	const char *mode;
	int blocksize;
	bool wrapped_key;
};

static const struct cipher_alg cipher_algs[] = {
	{ "cipher_null", NULL, 16, false },
	{ "aes",         NULL, 16, false },
	{ "serpent",     NULL, 16, false },
	{ "twofish",     NULL, 16, false },
	{ "anubis",      NULL, 16, false },
	{ "blowfish",    NULL,  8, false },
	{ "camellia",    NULL, 16, false },
	{ "cast5",       NULL,  8, false },
	{ "cast6",       NULL, 16, false },
	{ "des",         NULL,  8, false },
	{ "des3_ede",    NULL,  8, false },
	{ "khazad",      NULL,  8, false },
	{ "seed",        NULL, 16, false },
	{ "tea",         NULL,  8, false },
	{ "xtea",        NULL,  8, false },
	{ "paes",        NULL, 16,  true }, /* protected AES, s390 wrapped key scheme */
	{ "xchacha12,aes", "adiantum", 32, false },
	{ "xchacha20,aes", "adiantum", 32, false },
	{ "sm4",         NULL, 16, false },
	{ "aria",        NULL, 16, false },
	{ NULL,          NULL,  0, false }
};

struct cipher_aead_alg {
	const char *name;
	const char *mode;
	const char *integrity;
	size_t key_bytes;
};

static const struct cipher_aead_alg cipher_aead_algs[] = {
	{ "aes",      "gcm", "aead", 16 },
	{ "aes",      "gcm", "aead", 24 },
	{ "aes",      "gcm", "aead", 32 },
	{ "aes",      "ccm", "aead", 16 + 3 }, // CCM used as RFC 4309, 3 bytes for fixed salt
	{ "aes",      "ccm", "aead", 24 + 3 },
	{ "aes",      "ccm", "aead", 32 + 3 },
	{ "serpent",  "gcm", "aead", 16 },
	{ "serpent",  "gcm", "aead", 24 },
	{ "serpent",  "gcm", "aead", 32 },
	{ "serpent",  "ccm", "aead", 16 + 3 },
	{ "serpent",  "ccm", "aead", 24 + 3 },
	{ "serpent",  "ccm", "aead", 32 + 3 },
	{ "twofish",  "gcm", "aead", 16 },
	{ "twofish",  "gcm", "aead", 24 },
	{ "twofish",  "gcm", "aead", 32 },
	{ "twofish",  "ccm", "aead", 16 + 3 },
	{ "twofish",  "ccm", "aead", 24 + 3 },
	{ "twofish",  "ccm", "aead", 32 + 3 },
	{ "aria",     "gcm", "aead", 16 },
	{ "aria",     "gcm", "aead", 24 },
	{ "aria",     "gcm", "aead", 32 },
	{ "aria",     "ccm", "aead", 16 + 3 },
	{ "aria",     "ccm", "aead", 24 + 3 },
	{ "aria",     "ccm", "aead", 32 + 3 },
	{ "camellia", "gcm", "aead", 16 },
	{ "camellia", "gcm", "aead", 24 },
	{ "camellia", "gcm", "aead", 32 },
	{ "camellia", "ccm", "aead", 16 + 3 },
	{ "camellia", "ccm", "aead", 24 + 3 },
	{ "camellia", "ccm", "aead", 32 + 3 },
	{ "sm4",      "gcm", "aead", 16 },
	{ "sm4",      "ccm", "aead", 16 + 3 },
	{ "aegis128", NULL,  "aead", 16 },
	{ "chacha20", NULL,  "poly1305", 32 }, // Used as RFC 7539
};

static const struct cipher_alg *_get_alg(const char *name, const char *mode)
{
	int i = 0;

	while (name && cipher_algs[i].name) {
		if (!strcasecmp(name, cipher_algs[i].name))
			if (!mode || !cipher_algs[i].mode ||
			    !strncasecmp(mode, cipher_algs[i].mode, strlen(cipher_algs[i].mode)))
				return &cipher_algs[i];
		i++;
	}
	return NULL;
}

static bool aead_iv_known(const char *iv)
{
	if (!iv)
		return false;

	if (!strcasecmp(iv, "random"))
		return true;

	/* These are not secure for AEAD, but sometimes used */
	if (!strcasecmp(iv, "plain64") || !strcasecmp(iv, "plain64be"))
		return true;

	return false;
}

bool crypt_cipher_aead_known(const char *name, const char *mode, const char *integrity, size_t key_bytes)
{
	size_t i, mode_len;

	if (!name || !mode || !integrity)
		return false;

	for (i = 0; i < ARRAY_SIZE(cipher_aead_algs); i++) {
		if (strcasecmp(name, cipher_aead_algs[i].name))
			continue;

		if (strcasecmp(integrity, cipher_aead_algs[i].integrity))
			continue;

		/* Compare only mode for ciphers that use a mode */
		if (cipher_aead_algs[i].mode) {
			mode_len = strlen(cipher_aead_algs[i].mode);
			if (strncasecmp(mode, cipher_aead_algs[i].mode, mode_len))
				continue;
			if (mode[mode_len] != '-')
				continue;
			if (!aead_iv_known(&mode[mode_len + 1]))
				continue;
		} else if (!aead_iv_known(mode)) /* no mode, only IV */
				continue;

		if (key_bytes != cipher_aead_algs[i].key_bytes)
			continue;

		return true;
	}

	return false;
}

int crypt_cipher_ivsize(const char *name, const char *mode)
{
	const struct cipher_alg *ca = _get_alg(name, mode);

	if (!ca)
		return -EINVAL;

	if (mode && !strcasecmp(mode, "hctr2"))
		return 32;

	if (mode && !strcasecmp(mode, "ecb"))
		return 0;

	return ca->blocksize;
}

int crypt_cipher_wrapped_key(const char *name, const char *mode)
{
	const struct cipher_alg *ca = _get_alg(name, mode);

	return ca ? (int)ca->wrapped_key : 0;
}

bool crypt_fips_mode_kernel(void)
{
	int fd;
	char buf = 0;

	fd = open("/proc/sys/crypto/fips_enabled", O_RDONLY);

	if (fd < 0)
		return false;

	if (read(fd, &buf, 1) != 1)
		buf = '0';

	close(fd);

	return (buf == '1');
}
