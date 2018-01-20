/*
 * Prototype LUKS2 utility for keyslots unassigned to volume
 *
 * Copyright (C) 2017-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2017-2018, Ondrej Kozina <okozina@redhat.com>
 *
 * Use:
 *  - generate LUKS2 device
 *  - add new keyslot unassigned to segment using this example
 *    (it'll generate random key with same size as volume key)
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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libcryptsetup.h"

int main(int argc, char **argv)
{
	int r;
	struct crypt_device *cd;

	if (argc < 3)
		return EXIT_FAILURE;

	if (crypt_init(&cd, argv[1])) {
		fprintf(stderr, "Failed to init device %s.\n", argv[1]);
		return EXIT_FAILURE;
	}

	if (crypt_load(cd, CRYPT_LUKS2, NULL)) {
		fprintf(stderr, "Failed to load luks2 device %s.\n", argv[1]);
		crypt_free(cd);
		return EXIT_FAILURE;
	}

	r = crypt_keyslot_add_by_key(cd, CRYPT_ANY_SLOT, NULL,
				     crypt_get_volume_key_size(cd), argv[2],
				     strlen(argv[2]),
				     CRYPT_VOLUME_KEY_NO_SEGMENT);
	if (r < 0)
		fprintf(stderr, "Failed to load luks2 device %s.\n", argv[1]);

	crypt_free(cd);
	return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
