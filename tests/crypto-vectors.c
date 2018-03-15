/*
 * cryptsetup crypto backend test vectors
 *
 * Copyright (C) 2018, Milan Broz
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
#include <errno.h>

#include "crypto_backend.h"

static void printhex(const char *s, const char *buf, size_t len)
{
	size_t i;

	printf("%s: ", s);
	for (i = 0; i < len; i++)
		printf(" %02x", (unsigned char)buf[i]);
	printf("\n");
	fflush(stdout);
}

/*
 * KDF tests
 */
struct kdf_test_vector {
	const char *type;
	const char *hash;
	unsigned int hash_block_length;
	unsigned int iterations;
	unsigned int memory;
	unsigned int parallelism;
	const char *password;
	unsigned int password_length;
	const char *salt;
	unsigned int salt_length;
//	const char *key;
//	unsigned int key_length;
//	const char *ad;
//	unsigned int ad_length;
	const char *output;
	unsigned int output_length;
};

struct kdf_test_vector kdf_test_vectors[] = {
	/* Argon2 RFC (without key and ad values) */
	{
		"argon2i", NULL, 0, 3, 32, 4,
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01", 32,
		"\x02\x02\x02\x02\x02\x02\x02\x02"
		"\x02\x02\x02\x02\x02\x02\x02\x02", 16,
//		"\x03\x03\x03\x03\x03\x03\x03\x03", 8,
//		"\x04\x04\x04\x04\x04\x04\x04\x04"
//		"\x04\x04\x04\x04", 12,
		"\xa9\xa7\x51\x0e\x6d\xb4\xd5\x88"
		"\xba\x34\x14\xcd\x0e\x09\x4d\x48"
		"\x0d\x68\x3f\x97\xb9\xcc\xb6\x12"
		"\xa5\x44\xfe\x8e\xf6\x5b\xa8\xe0", 32
//		"\xc8\x14\xd9\xd1\xdc\x7f\x37\xaa"
//		"\x13\xf0\xd7\x7f\x24\x94\xbd\xa1"
//		"\xc8\xde\x6b\x01\x6d\xd3\x88\xd2"
//		"\x99\x52\xa4\xc4\x67\x2b\x6c\xe8", 32
	},
	{
		"argon2id", NULL, 0, 3, 32, 4,
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01"
		"\x01\x01\x01\x01\x01\x01\x01\x01", 32,
		"\x02\x02\x02\x02\x02\x02\x02\x02"
		"\x02\x02\x02\x02\x02\x02\x02\x02", 16,
//		"\x03\x03\x03\x03\x03\x03\x03\x03", 8,
//		"\x04\x04\x04\x04\x04\x04\x04\x04"
//		"\x04\x04\x04\x04", 12,
		"\x03\xaa\xb9\x65\xc1\x20\x01\xc9"
		"\xd7\xd0\xd2\xde\x33\x19\x2c\x04"
		"\x94\xb6\x84\xbb\x14\x81\x96\xd7"
		"\x3c\x1d\xf1\xac\xaf\x6d\x0c\x2e", 32
//		"\x0d\x64\x0d\xf5\x8d\x78\x76\x6c"
//		"\x08\xc0\x37\xa3\x4a\x8b\x53\xc9"
//		"\xd0\x1e\xf0\x45\x2d\x75\xb6\x5e"
//		"\xb5\x25\x20\xe9\x6b\x01\xe6\x59", 32
	},
	/* RFC 3962 */
	{
		"pbkdf2", "sha1", 64, 1, 0, 0,
		"password", 8,
		"ATHENA.MIT.EDUraeburn", 21,
		"\xcd\xed\xb5\x28\x1b\xb2\xf8\x01"
		"\x56\x5a\x11\x22\xb2\x56\x35\x15"
		"\x0a\xd1\xf7\xa0\x4b\xb9\xf3\xa3"
		"\x33\xec\xc0\xe2\xe1\xf7\x08\x37", 32
	}, {
		"pbkdf2", "sha1", 64, 2, 0, 0,
		"password", 8,
		"ATHENA.MIT.EDUraeburn", 21,
		"\x01\xdb\xee\x7f\x4a\x9e\x24\x3e"
		"\x98\x8b\x62\xc7\x3c\xda\x93\x5d"
		"\xa0\x53\x78\xb9\x32\x44\xec\x8f"
		"\x48\xa9\x9e\x61\xad\x79\x9d\x86", 32
	}, {
		"pbkdf2", "sha1", 64, 1200, 0, 0,
		"password", 8,
		"ATHENA.MIT.EDUraeburn", 21,
		"\x5c\x08\xeb\x61\xfd\xf7\x1e\x4e"
		"\x4e\xc3\xcf\x6b\xa1\xf5\x51\x2b"
		"\xa7\xe5\x2d\xdb\xc5\xe5\x14\x2f"
		"\x70\x8a\x31\xe2\xe6\x2b\x1e\x13", 32
	}, {
		"pbkdf2", "sha1", 64, 5, 0, 0,
		"password", 8,
		"\0224VxxV4\022", 8, // "\x1234567878563412
		"\xd1\xda\xa7\x86\x15\xf2\x87\xe6"
		"\xa1\xc8\xb1\x20\xd7\x06\x2a\x49"
		"\x3f\x98\xd2\x03\xe6\xbe\x49\xa6"
		"\xad\xf4\xfa\x57\x4b\x6e\x64\xee", 32
	}, {
		"pbkdf2", "sha1", 64, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 64,
		"pass phrase equals block size", 29,
		"\x13\x9c\x30\xc0\x96\x6b\xc3\x2b"
		"\xa5\x5f\xdb\xf2\x12\x53\x0a\xc9"
		"\xc5\xec\x59\xf1\xa4\x52\xf5\xcc"
		"\x9a\xd9\x40\xfe\xa0\x59\x8e\xd1", 32
	}, {
		"pbkdf2", "sha1", 64, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 65,
		"pass phrase exceeds block size", 30,
		"\x9c\xca\xd6\xd4\x68\x77\x0c\xd5"
		"\x1b\x10\xe6\xa6\x87\x21\xbe\x61"
		"\x1a\x8b\x4d\x28\x26\x01\xdb\x3b"
		"\x36\xbe\x92\x46\x91\x5e\xc8\x2a", 32
	}, {
		"pbkdf2", "sha1", 64, 50, 0, 0,
		"\360\235\204\236", 4, // g-clef ("\xf09d849e)
		"EXAMPLE.COMpianist", 18,
		"\x6b\x9c\xf2\x6d\x45\x45\x5a\x43"
		"\xa5\xb8\xbb\x27\x6a\x40\x3b\x39"
		"\xe7\xfe\x37\xa0\xc4\x1e\x02\xc2"
		"\x81\xff\x30\x69\xe1\xe9\x4f\x52", 32
	}, {
	/* RFC-6070 */
		"pbkdf2", "sha1", 64, 1, 0, 0,
		"password", 8,
		"salt", 4,
		"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9"
		"\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6", 20
	}, {
		"pbkdf2", "sha1", 64, 2, 0, 0,
		"password", 8,
		"salt", 4,
		"\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e"
		"\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57", 20
	}, {
		"pbkdf2", "sha1", 64, 4096, 0, 0,
		"password", 8,
		"salt", 4,
		"\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad"
		"\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1", 20
	}, {
		"pbkdf2", "sha1", 64, 16777216, 0, 0,
		"password", 8,
		"salt", 4,
		"\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94"
		"\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84", 20
	}, {
		"pbkdf2", "sha1", 64, 4096, 0, 0,
		"passwordPASSWORDpassword", 24,
		"saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
		"\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8"
		"\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96"
		"\x4c\xf2\xf0\x70\x38", 25
	}, {
		"pbkdf2", "sha1", 64, 4096, 0, 0,
		"pass\0word", 9,
		"sa\0lt", 5,
		"\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37"
		"\xd7\xf0\x34\x25\xe0\xc3", 16
	}, {
	/* empty password test */
		"pbkdf2", "sha1", 64, 2, 0, 0,
		"", 0,
		"salt", 4,
		"\x13\x3a\x4c\xe8\x37\xb4\xd2\x52\x1e\xe2"
		"\xbf\x03\xe1\x1c\x71\xca\x79\x4e\x07\x97", 20
	}, {
	/* Password exceeds block size test */
		"pbkdf2", "sha256", 64, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 65,
		"pass phrase exceeds block size", 30,
		"\x22\x34\x4b\xc4\xb6\xe3\x26\x75"
		"\xa8\x09\x0f\x3e\xa8\x0b\xe0\x1d"
		"\x5f\x95\x12\x6a\x2c\xdd\xc3\xfa"
		"\xcc\x4a\x5e\x6d\xca\x04\xec\x58", 32
	}, {
		"pbkdf2", "sha512", 128, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 129,
		"pass phrase exceeds block size", 30,
		"\x0f\xb2\xed\x2c\x0e\x6e\xfb\x7d"
		"\x7d\x8e\xdd\x58\x01\xb4\x59\x72"
		"\x99\x92\x16\x30\x5e\xa4\x36\x8d"
		"\x76\x14\x80\xf3\xe3\x7a\x22\xb9", 32
	}, {
		"pbkdf2", "whirlpool", 64, 1200, 0, 0,
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
		"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 65,
		"pass phrase exceeds block size", 30,
		"\x9c\x1c\x74\xf5\x88\x26\xe7\x6a"
		"\x53\x58\xf4\x0c\x39\xe7\x80\x89"
		"\x07\xc0\x31\x19\x9a\x50\xa2\x48"
		"\xf1\xd9\xfe\x78\x64\xe5\x84\x50", 32
	}
};

static int pbkdf_test_vectors(void)
{
	char result[256];
	unsigned int i;
	struct kdf_test_vector *vec;

	for (i = 0; i < (sizeof(kdf_test_vectors) / sizeof(*kdf_test_vectors)); i++) {
		vec = &kdf_test_vectors[i];
		printf("PBKDF vector %02d %s ", i, vec->type);
		if (crypt_pbkdf(vec->type, vec->hash,
		    vec->password, vec->password_length,
		    vec->salt, vec->salt_length,
		    result, vec->output_length,
		    vec->iterations, vec->memory, vec->parallelism)) {
			printf("crypto backend [FAILED].\n");
			return -EINVAL;
		}
		if (memcmp(result, vec->output, vec->output_length)) {
			printf("expected output [FAILED].\n");
			printhex(" got", result, vec->output_length);
			printhex("want", vec->output, vec->output_length);
			return -EINVAL;
		}
		printf("[OK]\n");
		memset(result, 0, sizeof(result));
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if (crypt_backend_init(NULL)) {
		printf("Crypto backend init error.\n");
		exit(EXIT_FAILURE);
	}
	printf("Test vectors using %s crypto backend.\n", crypt_backend_version());

	if (pbkdf_test_vectors())
		exit(EXIT_FAILURE);

	crypt_backend_destroy();
	exit(EXIT_SUCCESS);
}
