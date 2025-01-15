// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * unit test helper for crypt_wipe API call
 *
 * Copyright (C) 2022-2025 Milan Broz
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>

#include "libcryptsetup.h"

const char *test_file;
uint64_t test_offset, test_length, test_block;
uint32_t flags;
crypt_wipe_pattern pattern;

static void usage(void)
{
	fprintf(stderr, "Use:\tunit-wipe file/device zero|random|special offset length bsize [no-dio].\n");
}

static bool parse_u64(const char *arg, uint64_t *u64)
{
	unsigned long long ull;
	char *end;

	ull = strtoull(arg, &end, 10);
	if (*end || !*arg || errno == ERANGE)
		return false;

	if (ull % 512)
		return false;

	*u64 = ull;
	return true;
}

static bool parse_input_params(int argc, char **argv)
{
	struct stat st;

	if (argc < 6 || argc > 7) {
		usage();
		return false;
	}

	if (stat(argv[1], &st)) {
		fprintf(stderr, "File/device %s is missing?\n", argv[1]);
		return false;
	}
	test_file = argv[1];

	if (!strcmp(argv[2], "random"))
		pattern = CRYPT_WIPE_RANDOM;
	else if (!strcmp(argv[2], "zero"))
		pattern = CRYPT_WIPE_ZERO;
	else if (!strcmp(argv[2], "special"))
		pattern = CRYPT_WIPE_SPECIAL;
	else {
		fprintf(stderr, "Wrong pattern specification.\n");
		return false;
	}

	if (!parse_u64(argv[3], &test_offset)) {
		fprintf(stderr, "Wrong offset specification.\n");
		return false;
	}

	if (!parse_u64(argv[4], &test_length)) {
		fprintf(stderr, "Wrong length specification.\n");
		return false;
	}

	if (!parse_u64(argv[5], &test_block)) {
		fprintf(stderr, "Wrong block length specification.\n");
		return false;
	}

	if (argc > 6) {
		if (!strcmp(argv[6], "no-dio"))
			flags = CRYPT_WIPE_NO_DIRECT_IO;
		else {
			fprintf(stderr, "Wrong flags specification.\n");
			return false;
		}
	}

	return true;
}

int main(int argc, char **argv)
{
	struct crypt_device *cd;
	int r;

#ifndef NO_CRYPTSETUP_PATH
	if (getenv("CRYPTSETUP_PATH")) {
		printf("Cannot run this test with CRYPTSETUP_PATH set.\n");
		exit(77);
	}
#endif

	if (!parse_input_params(argc, argv))
		return EXIT_FAILURE;

	r = crypt_init(&cd, NULL);
	if (r < 0) {
		fprintf(stderr, "Context init failure %i.\n", r);
		return EXIT_FAILURE;
	}

	r = crypt_wipe(cd, test_file, pattern, test_offset, test_length,
		       test_block, flags, NULL, NULL);
	crypt_free(cd);

	if (r)
		fprintf(stderr, "Failure %i\n", r);

	return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
