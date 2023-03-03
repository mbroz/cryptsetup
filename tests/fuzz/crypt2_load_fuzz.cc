/*
 * cryptsetup LUKS2 fuzz target
 *
 * Copyright (C) 2022-2023 Daniel Zatovic <daniel.zatovic@gmail.com>
 * Copyright (C) 2022-2023 Red Hat, Inc. All rights reserved.
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
#include "src/cryptsetup.h"
#include <err.h>
#include "luks2/luks2.h"
#include "crypto_backend/crypto_backend.h"
#include "FuzzerInterface.h"

#define CHKSUM_ALG "sha256"
#define CHKSUM_SIZE 32

static int calculate_checksum(const uint8_t* data, size_t size) {
	struct crypt_hash *hd = NULL;
	struct luks2_hdr_disk *hdr = NULL;
	uint64_t hdr_size1, hdr_size2;
	int r;

	/* primary header */
	if (sizeof(struct luks2_hdr_disk) > size)
		return 0;
	hdr = CONST_CAST(struct luks2_hdr_disk *) data;

	hdr_size1 = be64_to_cpu(hdr->hdr_size);
	if (hdr_size1 > size || hdr_size1 <= sizeof(struct luks2_hdr_disk))
		return 0;
	memset(&hdr->csum, 0, LUKS2_CHECKSUM_L);
	if ((r = crypt_hash_init(&hd, CHKSUM_ALG)))
		goto out;
	if ((r = crypt_hash_write(hd, CONST_CAST(char*) data, hdr_size1)))
		goto out;
	if ((r = crypt_hash_final(hd, (char*)&hdr->csum, CHKSUM_SIZE)))
		goto out;
	crypt_hash_destroy(hd);
	hd = NULL;

	/* secondary header */
	if (hdr_size1 + sizeof(struct luks2_hdr_disk) > size)
		return 0;
	hdr = CONST_CAST(struct luks2_hdr_disk *) (data + hdr_size1);

	hdr_size2 = be64_to_cpu(hdr->hdr_size);
	if (hdr_size2 > size || (hdr_size1 + hdr_size2) > size ||
	    hdr_size2 <= sizeof(struct luks2_hdr_disk))
		return 0;

	memset(&hdr->csum, 0, LUKS2_CHECKSUM_L);
	if ((r = crypt_hash_init(&hd, CHKSUM_ALG)))
		goto out;
	if ((r = crypt_hash_write(hd, (char*) hdr, hdr_size2)))
		goto out;
	if ((r = crypt_hash_final(hd, (char*)&hdr->csum, CHKSUM_SIZE)))
		goto out;
out:
	if (hd)
		crypt_hash_destroy(hd);
	return r;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	int fd;
	struct crypt_device *cd = NULL;
	char name[] = "/tmp/test-script-fuzz.XXXXXX";

	if (calculate_checksum(data, size))
		return 0;

	fd = mkostemp(name, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC);
	if (fd == -1)
		err(EXIT_FAILURE, "mkostemp() failed");

	/* enlarge header */
	if (ftruncate(fd, FILESIZE) == -1)
		goto out;

	if (write_buffer(fd, data, size) != (ssize_t)size)
		goto out;

	if (crypt_init(&cd, name) == 0)
		(void)crypt_load(cd, CRYPT_LUKS2, NULL);
	crypt_free(cd);
out:
	close(fd);
	unlink(name);
	return 0;
}
}
