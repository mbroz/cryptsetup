/*
 * unit test helper for crypt_wipe API call
 *
 * Copyright (C) 2022 Milan Broz
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
