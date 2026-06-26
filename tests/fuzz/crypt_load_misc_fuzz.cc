// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup VERITY, INTEGRITY fuzz target
 */

extern "C" {
#define FILESIZE (16777216)
#include "src/cryptsetup.h"
#include <err.h>
#include "verity/verity.h"
#include "integrity/integrity.h"
#include "crypto_backend/crypto_backend.h"
#include "FuzzerInterface.h"

static void empty_log(int level, const char *msg, void *usrptr) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	int fd, r;
	struct crypt_device *cd = NULL;
	char name[] = "/tmp/test-script-fuzz.XXXXXX";

	fd = mkostemp(name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC);
	if (fd == -1)
		err(EXIT_FAILURE, "mkostemp() failed");

	/* enlarge header */
	if (ftruncate(fd, FILESIZE) == -1)
		goto out;

	if (write_buffer(fd, data, size) != (ssize_t) size)
		goto out;

	crypt_set_log_callback(NULL, empty_log, NULL);

	if (crypt_init(&cd, name) == 0) {
		r = crypt_load(cd, CRYPT_VERITY, NULL);
		if (r == 0)
			goto out;

		(void) crypt_load(cd, CRYPT_INTEGRITY, NULL);
	}
out:
	crypt_free(cd);
	close(fd);
	unlink(name);
	return 0;
}
}
