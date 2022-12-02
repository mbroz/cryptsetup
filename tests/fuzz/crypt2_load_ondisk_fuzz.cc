/*
 * cryptsetup LUKS1, FileVault, BitLocker fuzz target
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
#include "luks1/luks.h"
#include "crypto_backend/crypto_backend.h"
#include "FuzzerInterface.h"

void empty_log(int level, const char *msg, void *usrptr) {}

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
		r = crypt_load(cd, CRYPT_LUKS1, NULL);
		if (r == 0)
			goto out;

		r = crypt_load(cd, CRYPT_FVAULT2, NULL);
		if (r == 0)
			goto out;

		(void) crypt_load(cd, CRYPT_BITLK, NULL);
	}
out:
	crypt_free(cd);
	close(fd);
	unlink(name);
	return 0;
}
}
