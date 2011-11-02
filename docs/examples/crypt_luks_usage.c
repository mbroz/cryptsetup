/*
 * An example of using LUKS device through libcryptsetup API
 *
 * Copyright (C) 2011, Red Hat, Inc. All rights reserved.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <libcryptsetup.h>

static int format_and_add_keyslots(const char *path)
{
	struct crypt_device *cd;
	struct crypt_params_luks1 params;
	int r;

	/*
	 * crypt_init() call precedes most of operations of cryptsetup API. The call is used
	 * to initialize crypt device context stored in structure referenced by _cd_ in
	 * the example. Second parameter is used to pass underlaying device path.
	 *
	 * Note:
	 * If path refers to a regular file it'll be attached to a first free loop device.
	 * crypt_init() operation fails in case there's no more loop device available.
	 * Also, loop device will have the AUTOCLEAR flag set, so the file loopback will
	 * be detached automatically.
	 */

	r = crypt_init(&cd, path);
	if (r < 0 ) {
		printf("crypt_init() failed for %s.\n", path);
		return r;
	}

	printf("Context is attached to block device %s.\n", crypt_get_device_name(cd));

	/*
	 * So far no data were written on your device. This will change with call of
	 * crypt_format() only if you specify CRYPT_LUKS1 as device type.
	 */
	printf("Device %s will be formatted to LUKS device after 5 seconds.\n"
	       "Press CTRL+C now if you want to cancel this operation.\n", path);
	sleep(5);


	/*
	 * Prepare LUKS format parameters
	 *
	 * hash parameter defines PBKDF2 hash algorithm used in LUKS header.
	 * For compatibility reason we use SHA1 here.
	 */
	params.hash = "sha1";

	/*
	 * data_alignment parameter is relevant only in case of the luks header
	 * and the payload are both stored on same device.
	 *
	 * if you set data_alignment = 0, cryptsetup will autodetect
	 * data_alignment according to underlaying device topology.
	 */
	params.data_alignment = 0;

	/*
	 * data_device parameter defines that no external device
	 * for luks header will be used
	 */
	params.data_device = NULL;

	/*
	 * NULLs for uuid and volume_key means that these attributes will be
	 * generated during crypt_format(). Volume key is generated with respect
	 * to key size parameter passed to function.
	 *
	 * crypt_format() checks device size (LUKS header must fit there).
	 */
	r = crypt_format(cd,		/* crypt context */
			 CRYPT_LUKS1,	/* LUKS1 is standard LUKS header */
			 "aes",		/* used cipher */
			 "xts-plain64",	/* used block mode and IV generator*/
			 NULL,		/* generate UUID */
			 NULL,		/* generate volume key from RNG */
			 256 / 8,	/* 256bit key - here AES-128 in XTS mode, size is in bytes */
			 &params);	/* parameters above */

	if(r < 0) {
		printf("crypt_format() failed on device %s\n", crypt_get_device_name(cd));
		crypt_free(cd);
		return r;
	}

	/*
	 * The device now contains LUKS1 header, but there is
	 * no active keyslot with encrypted volume key yet.
	 */

	/*
	 * cryptt_kesylot_add_* call stores volume_key in encrypted form into keyslot.
	 * Without keyslot you can't manipulate with LUKS device after the context will be freed.
	 *
	 * To create a new keyslot you need to supply the existing one (to get the volume key from) or
	 * you need to supply the volume key.
	 *
	 * After format, we have volume key stored internally in context so add new keyslot
	 * using this internal volume key.
	 */
	r = crypt_keyslot_add_by_volume_key(cd,			/* crypt context */
					    CRYPT_ANY_SLOT,	/* just use first free slot */
					    NULL,		/* use internal volume key */
					    0,			/* unused (size of volume key) */
					    "foo",		/* passphrase - NULL means query*/
					    3);			/* size of passphrase */

	if (r < 0) {
		printf("Adding keyslot failed.\n");
		crypt_free(cd);
		return r;
	}

	printf("The first keyslot is initialized.\n");

	/*
	 * Add another keyslot, now using the first keyslot.
	 * It will decrypt volume key from the first keyslot and creates new one with another passphrase.
	 */
	r = crypt_keyslot_add_by_passphrase(cd,			/* crypt context */
					    CRYPT_ANY_SLOT,	/* just use first free slot */
					    "foo", 3,		/* passphrase for the old keyslot */
					    "bar", 3);		/* passphrase for the new kesylot */
	if (r < 0) {
		printf("Adding keyslot failed.\n");
		crypt_free(cd);
		return r;
	}

	printf("The second keyslot is initialized.\n");

	crypt_free(cd);
	return 0;
}

static int activate_and_check_status(const char *path, const char *device_name)
{
	struct crypt_device *cd;
	struct crypt_active_device cad;
	int r;

	/*
	 * LUKS device activation example.
	 * It's sequence of sub-steps: device initialization, LUKS header load
	 * and the device activation itself.
	 */
	r = crypt_init(&cd, path);
	if (r < 0 ) {
		printf("crypt_init() failed for %s.\n", path);
		return r;
	}

	/*
	 * crypt_load() is used to load the LUKS header from block device
	 * into crypt_device context.
	 */
	r = crypt_load(cd,		/* crypt context */
		       CRYPT_LUKS1,	/* requested type */
		       NULL);		/* additional parameters (not used) */

	if (r < 0) {
		printf("crypt_load() failed on device %s.\n", crypt_get_device_name(cd));
		crypt_free(cd);
		return r;
	}

	/*
	 * Device activation creates device-mapper devie mapping with name device_name.
	 */
	r = crypt_activate_by_passphrase(cd,		/* crypt context */
					 device_name,	/* device name to activate */
					 CRYPT_ANY_SLOT,/* which slot use (ANY - try all) */
					 "foo", 3,	/* passphrase */
					 CRYPT_ACTIVATE_READONLY); /* flags */
	if (r < 0) {
		printf("Device %s activation failed.\n", device_name);
		crypt_free(cd);
		return r;
	}

	printf("LUKS device %s/%s is active.\n", crypt_get_dir(), device_name);
	printf("\tcipher used: %s\n", crypt_get_cipher(cd));
	printf("\tcipher mode: %s\n", crypt_get_cipher_mode(cd));
	printf("\tdevice UUID: %s\n", crypt_get_uuid(cd));

	/*
	 * Get info about active device (query DM backend)
	 */
	r = crypt_get_active_device(cd, device_name, &cad);
	if (r < 0) {
		printf("Get info about active device %s failed.\n", device_name);
		crypt_deactivate(cd, device_name);
		crypt_free(cd);
		return r;
	}

	printf("Active device parameters for %s:\n"
		"\tDevice offset (in sectors): %" PRIu64 "\n"
		"\tIV offset (in sectors)    : %" PRIu64 "\n"
		"\tdevice size (in sectors)  : %" PRIu64 "\n"
		"\tread-only flag            : %s\n",
		device_name, cad.offset, cad.iv_offset, cad.size,
		cad.flags & CRYPT_ACTIVATE_READONLY ? "1" : "0");

	crypt_free(cd);
	return 0;
}

static int handle_active_device(const char *device_name)
{
	struct crypt_device *cd;
	int r;

	/*
	 * crypt_init_by_name() initializes device context and loads LUKS header from backing device
	 */
	r = crypt_init_by_name(&cd, device_name);
	if (r < 0) {
		printf("crypt_init_by_name() failed for %s.\n", device_name);
		return r;
	}

	if (crypt_status(cd, device_name) == CRYPT_ACTIVE)
		printf("Device %s is still active.\n", device_name);
	else {
		printf("Something failed perhaps, device %s is not active.\n", device_name);
		crypt_free(cd);
		return -1;
	}

	/*
	 * crypt_deactivate() is used to deactivate device
	 */
	r = crypt_deactivate(cd, device_name);
	if (r < 0) {
		printf("crypt_deactivate() failed.\n");
		crypt_free(cd);
		return r;
	}

	printf("Device %s is now deactivated.\n", device_name);

	crypt_free(cd);
	return 0;
}

int main(int argc, char **argv)
{
	if (geteuid()) {
		printf("Using of libcryptsetup requires super user privileges.\n");
		return 1;
	}

	if (argc != 2) {
		printf("usage: ./crypt_luks_usage <path>\n"
			"<path> refers to either a regular file or a block device.\n"
			"       WARNING: the file or device will be wiped.\n");
		return 2;
	}

	if (format_and_add_keyslots(argv[1]))
		return 3;

	if (activate_and_check_status(argv[1], "example_device"))
		return 4;

	if (handle_active_device("example_device"))
		return 5;

	return 0;
}
