// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Test utility checking availability of crypto primitive in crypto backend.
 *
 * Copyright (C) 2024-2025 Milan Broz
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "crypto_backend/crypto_backend.h"

static int check_cipher(const char *alg, const char *mode, unsigned long key_bits)
{
	struct crypt_cipher *cipher;
	char key[256];

	if (key_bits % 8 || (key_bits / 8) > sizeof(key))
		return EXIT_FAILURE;

	/* Userspace crypto */
	crypt_backend_rng(key, sizeof(key), CRYPT_RND_NORMAL, 0);
	if (crypt_cipher_init(&cipher, alg, mode, key, key_bits / 8))
		return EXIT_FAILURE;
	crypt_cipher_destroy(cipher);

	/* Kernel crypto */
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

static void __attribute__((noreturn)) exit_help(bool destroy_backend)
{
	printf("Use: crypto_check version | fips_mode | fips_mode_kernel | hash <alg> | cipher <alg> <mode> [key_bits]\n");
	if (destroy_backend)
		crypt_backend_destroy();
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int r = EXIT_SUCCESS;

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
	} else if (!strcmp(argv[1], "hash")) {
		if (argc != 3)
			exit_help(true);
		r = check_hash(argv[2]);
	} else if (!strcmp(argv[1], "cipher")) {
		unsigned long ul = 256;
		char *ptr;
		if (argc < 4 || argc > 5)
			exit_help(true);
		if (argc == 5) {
			ul = strtoul(argv[4], &ptr, 10);
			if (*ptr)
				exit_help(true);
		}
		r = check_cipher(argv[2], argv[3], ul);
	}

	crypt_backend_destroy();
	return r;
}
