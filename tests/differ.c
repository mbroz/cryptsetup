/*
 * cryptsetup file differ check (rewritten Clemens' fileDiffer in Python)
 *
 * Copyright (C) 2010-2012 Red Hat, Inc. All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/mman.h>

struct ffile {
	char *name;
	int fd;
	unsigned char *addr;
	size_t size;
};

enum df { OK , FAIL };

static void print_diff(off_t from, int max,
		       const unsigned char *o,
		       const unsigned char *n)
{
	int i, len = max;

	if (len > 16)
		len = 16;

	printf("OLD:");
	for (i = 0; i < len; i++)
		printf(" %02x", o[from + i]);
	printf("%s\n    ", max != len ? " ..." : "");
	for (i = 0; i < len; i++)
		printf(" %2c", o[from + i] > ' ' ? o[from + i]: '.');
	printf("\nNEW:");
	for (i = 0; i < len; i++)
		printf(" %02x", n[from + i]);
	printf("%s\n    ", max != len ? " ..." : "");
	for (i = 0; i < len; i++)
		printf(" %2c", n[from + i] > ' ' ? n[from + i]: '.');
	printf("\n");
}

/*
 * Xfrom-to (e.g. R10-15)
 * A - change allowed
 * S - change required, semantic
 * R - change required, random
 * F - change forbidden
 */
static enum df check(const char *range, unsigned char *o, unsigned char *n)
{
	char strict;
	unsigned long long from, to;
	enum df ret;

	if (sscanf(range, "%c%llu-%llu", &strict, &from, &to) != 3) {
		printf("Unknown range format %s.\n", range);
		return FAIL;
	}

	switch (toupper(strict)) {
	case 'A':
		ret = OK;
		break;
	case 'S':
		ret = memcmp(&o[from], &n[from], to - from + 1) != 0 ? OK : FAIL;
		break;
	case 'R': /* FIXME - random test */
		ret = memcmp(&o[from], &n[from], to - from + 1) != 0 ? OK : FAIL;
		break;
	case 'F':
		ret = memcmp(&o[from], &n[from], to - from + 1) == 0 ? OK : FAIL;
		break;
	default:
		ret = FAIL;
		break;
	}

	if (ret == FAIL)
		print_diff(from,  to - from + 1, o, n);

	return ret;
}

static int open_mmap(struct ffile *f)
{
	struct stat st;

	f->fd = open(f->name, O_RDONLY);
	if (f->fd == -1 || fstat(f->fd, &st) == -1)
		return 0;

	f->size = st.st_size;
	f->addr = mmap(NULL, f->size, PROT_READ, MAP_PRIVATE, f->fd, 0);

	return (f->addr == MAP_FAILED) ? 0 : 1;
}

static void close_mmap(struct ffile *f)
{
	if (f->addr != MAP_FAILED && !munmap(f->addr, f->size))
		f->addr = MAP_FAILED;

	if (f->fd != -1 && !close(f->fd))
		f->fd = -1;
}

int main(int argc, char *argv[])
{
	int i, r = 1;
	struct ffile file_old = {
		.fd = -1,
		.addr = MAP_FAILED,
	};
	struct ffile file_new = {
		.fd = -1,
		.addr = MAP_FAILED,
	};

	if (argc < 3) {
		printf("Use: differ old_file new_file change_list.\n");
		goto bad;
	}

	file_old.name = argv[1];
	if (!open_mmap(&file_old))
		goto bad;

	file_new.name = argv[2];
	if (!open_mmap(&file_new))
		goto bad;

	for (i = 3; i < argc; i++)
		if (check(argv[i], file_old.addr, file_new.addr) == FAIL) {
			printf ("FAILED for %s\n", argv[i]);
			r = 1;
			goto bad;
		}

	r = 0;
bad:
	close_mmap(&file_new);
	close_mmap(&file_old);

	return r;
}
