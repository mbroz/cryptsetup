/*
 * cryptsetup LUKS2 fuzz target
 *
 * Copyright (C) 2022 Daniel Zatovic <daniel.zatovic@gmail.com>
 * Copyright (C) 2022 Red Hat, Inc. All rights reserved.
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

extern "C" {
#define FILESIZE (16777216)
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <err.h>

#include "crypto_backend/crypto_backend.h"
#include <luks2/luks2.h>
#include <libcryptsetup.h>
#include <src/cryptsetup.h>
#include "FuzzerInterface.h"

static int calculate_checksum(const uint8_t* data, size_t size) {
	struct crypt_hash *hd = NULL;
	struct luks2_hdr_disk *hdr = NULL;
	int hash_size;
	uint64_t hdr_size1, hdr_size2;
	int r = 0;

	// primary header
	if (sizeof(struct luks2_hdr_disk) > size)
		return 0;
	hdr = CONST_CAST(struct luks2_hdr_disk *) data;

	hdr_size1 = be64_to_cpu(hdr->hdr_size);
	if (hdr_size1 > size)
		return 0;
	memset(&hdr->csum, 0, LUKS2_CHECKSUM_L);
	if ((r = crypt_hash_init(&hd, "sha256")))
		goto out;
	if ((r = crypt_hash_write(hd, CONST_CAST(char*) data, hdr_size1)))
		goto out;
	hash_size = crypt_hash_size("sha256");
	if (hash_size <= 0) {
		r = 1;
		goto out;
	}
	if ((r = crypt_hash_final(hd, (char*)&hdr->csum, (size_t)hash_size)))
		goto out;
	crypt_hash_destroy(hd);

	// secondary header
	if (hdr_size1 < sizeof(struct luks2_hdr_disk))
		hdr_size1 = sizeof(struct luks2_hdr_disk);

	if (hdr_size1 + sizeof(struct luks2_hdr_disk) > size)
		return 0;
	hdr = CONST_CAST(struct luks2_hdr_disk *) (data + hdr_size1);

	hdr_size2 = be64_to_cpu(hdr->hdr_size);
	if (hdr_size1 + hdr_size2 > size)
		return 0;

	memset(&hdr->csum, 0, LUKS2_CHECKSUM_L);
	if ((r = crypt_hash_init(&hd, "sha256")))
		goto out;
	if ((r = crypt_hash_write(hd, (char*) hdr, hdr_size2)))
		goto out;
	if ((r = crypt_hash_final(hd, (char*)&hdr->csum, (size_t)hash_size)))
		goto out;

out:
	if (hd)
		crypt_hash_destroy(hd);
	return r;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	int fd;
	struct crypt_device *cd;
	int result;
	int r = 0;

	char name[] = "/tmp/test-script-fuzz.XXXXXX";

	if ((r = calculate_checksum(data, size)))
		return r;

	fd = mkostemp(name, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC);
	if (fd < 0)
		err(EXIT_FAILURE, "mkostemp() failed");

	result = lseek(fd, FILESIZE-1, SEEK_SET);
	if (result == -1) {
		r = 1;
		goto out;
	}
	result = write(fd, "\0", 1);
	if (result != 1) {
		r = 1;
		goto out;
	}
	result = lseek(fd, 0, SEEK_SET);
	if (result == -1) {
		r = 1;
		goto out;
	}

	if (write_buffer(fd, data, size) != (ssize_t)size) {
		r = 1;
		goto out;
	}

//	crypt_set_debug_level(CRYPT_DEBUG_ALL);

	r = crypt_init(&cd, name);
	if (r < 0 ) {
		r = 0;
		goto out;
	}

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	crypt_free(cd);
	if (r < 0) {
		r = 0;
		goto out;
	}

out:
	close(fd);
	unlink(name);
	return r;
}
}
