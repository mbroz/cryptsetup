// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Test utility checking availability of crypto primitive in crypto backend.
 *
 * Copyright (C) 2024-2026 Milan Broz
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef NO_CRYPT_BACKEND
#include "crypto_backend/crypto_backend.h"

static int check_cipher(const char *alg, const char *mode, unsigned long key_bits)
{
	struct crypt_cipher *cipher;
	char key[256];

	if (key_bits % 8 || (key_bits / 8) > sizeof(key))
		return EXIT_FAILURE;

	crypt_backend_rng(key, sizeof(key), CRYPT_RND_NORMAL, 0);
	if (crypt_cipher_init(&cipher, alg, mode, key, key_bits / 8))
		return EXIT_FAILURE;
	crypt_cipher_destroy(cipher);

	return EXIT_SUCCESS;
}

static int check_cipher_kernel(const char *alg, const char *mode, unsigned long key_bits)
{
	if (key_bits % 8)
		return EXIT_FAILURE;

	if (crypt_cipher_check_kernel(alg, mode, NULL, key_bits / 8))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static int check_hash(const char *hash)
{
	struct crypt_hash *h;

	if (crypt_hash_size(hash) < 0)
		return EXIT_FAILURE;

	if (crypt_hash_init(&h, hash))
		return EXIT_FAILURE;

	crypt_hash_destroy(h);
	return EXIT_SUCCESS;
}

static int check_pbkdf(const char *pbkdf)
{
	const char *hash;
	uint32_t iterations, memory, parallel;
	char out[32];

	if (!strcmp(pbkdf, "pbkdf2")) {
		hash = "sha256";
		iterations = 1000;
		memory = 0;
		parallel = 0;
	} else if (!strncmp(pbkdf, "argon2", 6)) {
		hash = NULL;
		iterations = 3;
		memory = 256;
		parallel = 1;
	} else
		return EXIT_FAILURE;

	if (!crypt_pbkdf(pbkdf, hash, "01234567890abcdef01234567890abcdef", 32,
	    "11234567890abcdef11234567890abcdef", 32, out, sizeof(out),
	    iterations, memory, parallel))
		return EXIT_SUCCESS;

	return EXIT_FAILURE;
}
#else /* NO_CRYPT_BACKEND */
/*
 * All default backends should work with options hardcoded here
 */
static int crypt_backend_init(void) { return 0; };
static void crypt_backend_destroy(void) {};
static const char *crypt_backend_version(void) { return "none"; };
static bool crypt_fips_mode(void) { return false; };
static bool crypt_fips_mode_kernel(void) { return false; };

static int check_cipher(const char *alg, const char *mode, unsigned long key_bits)
{
	if (strcmp(alg, "aes"))
		return EXIT_FAILURE;

	if (!strcmp(mode, "cbc") && (key_bits == 128 || key_bits == 256))
		return EXIT_SUCCESS;

	if (!strcmp(mode, "xts") && (key_bits == 256 || key_bits == 512))
		return EXIT_SUCCESS;

	return EXIT_FAILURE;
}

static int check_cipher_kernel(const char *alg, const char *mode, unsigned long key_bits)
{
	/* Expect AF_ALG not available */
	return  EXIT_FAILURE;
}

static int check_hash(const char *hash)
{
	if (!strcmp(hash, "sha512") || !strcmp(hash, "sha256") || !strcmp(hash, "sha1"))
		return EXIT_SUCCESS;

	return EXIT_FAILURE;
}

static int check_pbkdf(const char *pbkdf)
{
	return EXIT_SUCCESS;
}
#endif

static void __attribute__((noreturn)) exit_help(bool destroy_backend)
{
	printf("Use: crypto_check version | fips_mode | fips_mode_kernel | hash <alg> | cipher[-kernel] <alg> <mode> [key_bits] | pbkdf <alg>\n");
	if (destroy_backend)
		crypt_backend_destroy();
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int r = EXIT_FAILURE;

	if (argc < 2)
		exit_help(false);

	if (!strcmp(argv[1], "fips_mode"))
		return crypt_fips_mode() ? EXIT_SUCCESS : EXIT_FAILURE;

	if (!strcmp(argv[1], "fips_mode_kernel"))
		return crypt_fips_mode_kernel() ? EXIT_SUCCESS : EXIT_FAILURE;

	if (crypt_backend_init()) {
		printf("Crypto backend init error.");
		return EXIT_FAILURE;
	}

	if (!strcmp(argv[1], "version")) {
		printf("%s%s%s\n", crypt_backend_version(),
		       crypt_fips_mode() ? " (FIPS mode)" : "",
		       crypt_fips_mode_kernel() ? " (FIPS kernel)" : "");
		r = EXIT_SUCCESS;
	} else if (!strcmp(argv[1], "hash")) {
		if (argc != 3)
			exit_help(true);
		r = check_hash(argv[2]);
	} else if (!strcmp(argv[1], "cipher") || !strcmp(argv[1], "cipher-kernel")) {
		unsigned long ul = 256;
		char *ptr;
		if (argc < 4 || argc > 5)
			exit_help(true);
		if (argc == 5) {
			ul = strtoul(argv[4], &ptr, 10);
			if (*ptr)
				exit_help(true);
		}
		if (strcmp(argv[1], "cipher-kernel"))
			r = check_cipher(argv[2], argv[3], ul);
		else
			r = check_cipher_kernel(argv[2], argv[3], ul);
	} else if (!strcmp(argv[1], "pbkdf")) {
		if (argc != 3)
			exit_help(true);
		r = check_pbkdf(argv[2]);
	}

	crypt_backend_destroy();
	return r;
}
