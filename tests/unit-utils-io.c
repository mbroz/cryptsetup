/*
 * simple unit test for utils_io.c (blockwise low level functions)
 *
 * Copyright (C) 2018-2020 Red Hat, Inc. All rights reserved.
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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils_io.h"

enum fn_enum {
	READ_BUFFER = 0,
	WRITE_BUFFER,
	READ_BLOCKWISE,
	WRITE_BLOCKWISE,
	READ_LSEEK_BLOCKWISE,
	WRITE_LSEEK_BLOCKWISE
} test_fn;

char		*test_file;
size_t		test_bsize;
size_t		test_alignment;
size_t		test_length;
off_t		test_offset; //FIXME: check for proper 64bit support (and test it!)
size_t		test_mem_alignment = 4096;

static int test_read_buffer(void)
{
	void *buffer = NULL;
	int fd = -1;
	ssize_t ret = -EINVAL;

	//printf("Entering test_read_buffer\n");

	if (posix_memalign(&buffer, test_mem_alignment, test_length)) {
		fprintf(stderr, "Failed to allocate aligned buffer.\n");
		goto out;
	}

	fd = open(test_file, O_RDONLY | O_DIRECT);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s.\n", test_file);
		goto out;
	}

	ret = read_buffer(fd, buffer, test_length);
	if (ret < 0)
		goto out;

	ret = (size_t) ret == test_length ? 0 : -EIO;
out:
	if (fd >= 0)
		close(fd);
	free(buffer);
	return ret;
}

static int test_write_buffer(void)
{
	void *buffer = NULL;
	int fd = -1;
	ssize_t ret = -EINVAL;

	//printf("Entering test_write_buffer\n");

	if (posix_memalign(&buffer, test_mem_alignment, test_length)) {
		fprintf(stderr, "Failed to allocate aligned buffer.\n");
		goto out;
	}

	fd = open(test_file, O_WRONLY | O_DIRECT);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s.\n", test_file);
		goto out;
	}

	ret = write_buffer(fd, buffer, test_length);
	if (ret < 0)
		goto out;

	return (size_t) ret == test_length ? 0 : -EIO;
out:
	if (fd >= 0)
		close(fd);
	free(buffer);
	return ret;
}

static int test_read_blockwise(void)
{
	void *buffer = NULL;
	int fd = -1;
	ssize_t ret = -EINVAL;

	//printf("Entering test_read_blockwise ");
	//printf("test_bsize: %zu, test_length: %zu\n", test_bsize, test_length);

	if (posix_memalign(&buffer, test_mem_alignment, test_length)) {
		fprintf(stderr, "Failed to allocate aligned buffer.\n");
		goto out;
	}

	fd = open(test_file, O_RDONLY | O_DIRECT);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s.\n", test_file);
		goto out;
	}


	ret = read_blockwise(fd, test_bsize, test_mem_alignment, buffer, test_length);
	if (ret < 0)
		goto out;

	ret = (size_t) ret == test_length ? 0 : -EIO;
out:
	if (fd >= 0)
		close(fd);
	free(buffer);
	return ret;
}

static int test_write_blockwise(void)
{
	void *buffer = NULL;
	int fd = -1;
	ssize_t ret = -EINVAL;

	//printf("Entering test_write_blockwise\n");

	if (posix_memalign(&buffer, test_mem_alignment, test_length)) {
		fprintf(stderr, "Failed to allocate aligned buffer.\n");
		goto out;
	}

	fd = open(test_file, O_RDWR | O_DIRECT);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s.\n", test_file);
		goto out;
	}

	ret = write_blockwise(fd, test_bsize, test_mem_alignment, buffer, test_length);
	if (ret < 0)
		goto out;

	ret = (size_t) ret == test_length ? 0 : -EIO;
out:
	if (fd >= 0)
		close(fd);
	free(buffer);
	return ret;
}

static int test_read_lseek_blockwise(void)
{
	void *buffer = NULL;
	int fd = -1;
	ssize_t ret = -EINVAL;

	//printf("Entering test_read_lseek_blockwise\n");

	if (posix_memalign(&buffer, test_mem_alignment, test_length)) {
		fprintf(stderr, "Failed to allocate aligned buffer.\n");
		goto out;
	}

	fd = open(test_file, O_RDONLY | O_DIRECT);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s.\n", test_file);
		goto out;
	}

	ret = read_lseek_blockwise(fd, test_bsize, test_mem_alignment, buffer, test_length, test_offset);
	if (ret < 0)
		goto out;

	ret = (size_t) ret == test_length ? 0 : -EIO;
out:
	if (fd >= 0)
		close(fd);
	free(buffer);
	return ret;
}

static int test_write_lseek_blockwise(void)
{
	void *buffer = NULL;
	int fd = -1;
	ssize_t ret = -EINVAL;

	//printf("Entering test_write_lseek_blockwise\n");

	if (posix_memalign(&buffer, test_mem_alignment, test_length)) {
		fprintf(stderr, "Failed to allocate aligned buffer.\n");
		goto out;
	}

	fd = open(test_file, O_RDWR | O_DIRECT);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s.\n", test_file);
		goto out;
	}

	ret = write_lseek_blockwise(fd, test_bsize, test_mem_alignment, buffer, test_length, test_offset);
	if (ret < 0)
		goto out;

	ret = (size_t) ret == test_length ? 0 : -EIO;
out:
	if (fd >= 0)
		close(fd);
	free(buffer);
	return ret;
}

static void usage(void)
{
	fprintf(stderr, "Use:\tunit-utils-io file/device blockwise_fn length  [bsize] [offset].\n");
}

static int parse_input_params(int argc, char **argv)
{
	struct stat st;
	unsigned long offset;

	if (argc < 4) {
		usage();
		return 1;
	}

	if (stat(argv[1], &st)) {
		fprintf(stderr, "File/device %s is missing?\n", argv[1]);
		return 1;
	}
	test_file = argv[1];
	if (sscanf(argv[3], "%zu", &test_length) != 1)
		return 1;
	if (argc >= 5 && sscanf(argv[4], "%zu", &test_bsize) != 1)
		return 1;
	if (argc >= 6) {
		if (sscanf(argv[5], "%ld", &offset) != 1)
			return 1;
		test_offset = offset;
	}

	if (!strcmp(argv[2], "read_buffer"))
		test_fn = READ_BUFFER;
	else if (!strcmp(argv[2], "write_buffer"))
		test_fn = WRITE_BUFFER;
	else if (!strcmp(argv[2], "read_blockwise")) {
		if (argc < 5) {
			usage();
			return 1;
		}
		test_fn = READ_BLOCKWISE;
	} else if (!strcmp(argv[2], "write_blockwise")) {
		if (argc < 5) {
			usage();
			return 1;
		}
		test_fn = WRITE_BLOCKWISE;
	} else if (!strcmp(argv[2], "read_lseek_blockwise")) {
		if (argc < 6) {
			usage();
			return 1;
		}
		test_fn = READ_LSEEK_BLOCKWISE;
	} else if (!strcmp(argv[2], "write_lseek_blockwise")) {
		if (argc < 6) {
			usage();
			return 1;
		}
		test_fn = WRITE_LSEEK_BLOCKWISE;
	} else {
		usage();
		return 1;
	}

	/* printf("function '%s': length %zu", argv[2], test_length);
	if (argc >= 5)
		printf(", bsize %zu", test_bsize);
	if (argc >= 6)
		printf(", offset %llu", test_offset);
	printf("\n"); */

	return 0;
}

int main(int argc, char **argv)
{
	long ps;
	int r = EXIT_FAILURE;

	if (parse_input_params(argc, argv))
		return r;

	ps = sysconf(_SC_PAGESIZE);
	if (ps > 0)
		test_mem_alignment = (size_t)ps;

	switch (test_fn) {
	case READ_BUFFER:
		r = test_read_buffer();
		break;
	case WRITE_BUFFER:
		r = test_write_buffer();
		break;
	case READ_BLOCKWISE:
		r = test_read_blockwise();
		break;
	case WRITE_BLOCKWISE:
		r = test_write_blockwise();
		break;
	case READ_LSEEK_BLOCKWISE:
		r = test_read_lseek_blockwise();
		break;
	case WRITE_LSEEK_BLOCKWISE:
		r = test_write_lseek_blockwise();
		break;
	default :
		fprintf(stderr, "Internal test error.\n");
		return r;
	}

	return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
