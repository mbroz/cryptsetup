// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup crypto name and hex conversion helper test vectors
 *
 * Copyright (C) 2022-2025 Milan Broz
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils_crypt.h"
#include "libcryptsetup.h"

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/*
 * Cryptsetup/dm-crypt algorithm naming conversion test
 */
struct mode_test_vector {
	const char *input;
	const char *cipher;
	const char *mode;
	int keys;
};
static struct mode_test_vector mode_test_vectors[] = {
	{ "aes-xts-plain", "aes", "xts-plain", 1 },
	{ "aes-xts-plain64", "aes", "xts-plain64", 1 },
	{ "aes-cbc-plain", "aes", "cbc-plain", 1 },
	{ "aes-cbc-plain64", "aes", "cbc-plain64", 1 },
	{ "aes-cbc-essiv:sha256", "aes", "cbc-essiv:sha256", 1 },
	{ "aes", "aes", "cbc-plain", 1 },
	{ "twofish", "twofish", "cbc-plain", 1 },
	{ "cipher_null", "cipher_null", "ecb", 0 },
	{ "null", "cipher_null", "ecb", 0 },
	{ "xchacha12,aes-adiantum-plain64", "xchacha12,aes", "adiantum-plain64", 1 },
	{ "xchacha20,aes-adiantum-plain64", "xchacha20,aes", "adiantum-plain64", 1 },
	{ "aes:64-cbc-lmk", "aes:64", "cbc-lmk", 64 },
	{ "des3_ede-cbc-tcw", "des3_ede" ,"cbc-tcw", 1 },
	{ "aes-lrw-benbi", "aes","lrw-benbi", 1 },
};

static int test_parse_mode(void)
{
	char cipher[MAX_CIPHER_LEN], mode[MAX_CIPHER_LEN];
	unsigned int i;
	int keys;

	printf("MODECONV:");
	for (i = 0; i < ARRAY_SIZE(mode_test_vectors); i++) {
		if (i && !(i % 8))
			printf("\n");
		keys = -1;
		memset(cipher, 0, sizeof(cipher));
		memset(mode, 0, sizeof(mode));
		printf("[%s]", mode_test_vectors[i].input ?: "NULL");
		if (crypt_parse_name_and_mode(mode_test_vectors[i].input, cipher, &keys, mode) < 0 ||
			strcmp(mode_test_vectors[i].cipher, cipher) ||
			strcmp(mode_test_vectors[i].mode, mode) ||
			mode_test_vectors[i].keys != keys) {
			printf("[FAILED (%s / %s / %i)]\n", cipher, mode, keys);
			return EXIT_FAILURE;
		}
	}
	printf("[OK]\n");

	return EXIT_SUCCESS;
}

/*
 * Cryptsetup/dm-crypt/dm-integrity algorithm naming conversion test
 */
struct integrity_test_vector {
	bool int_mode; /* non-null if it is supported as integrity mode for LUKS2 */
	const char *input;
	const char *integrity;
	int key_size;
};
static struct integrity_test_vector integrity_test_vectors[] = {
	{ true, "aead", "aead", 0 },
	{ true, "poly1305", "poly1305", 0 },
	{ true, "none", "none", 0 },
	{ false, "crc32", "crc32", 0 },
	{ true, "hmac-sha1", "hmac(sha1)", 20 },
	{ true, "hmac-sha256", "hmac(sha256)", 32 },
	{ true, "hmac-sha512", "hmac(sha512)", 64 },
	{ true, "cmac-aes", "cmac(aes)", 16 },
	{ false, "blake2b-256", "blake2b-256", 0 },
};

static int test_parse_integrity_mode(void)
{
	char integrity[MAX_CIPHER_LEN];
	unsigned int i;
	int key_size;

	printf("INTEGRITYCONV:");
	for (i = 0; i < ARRAY_SIZE(integrity_test_vectors); i++) {
		memset(integrity, 0, sizeof(integrity));
		printf("[%s,%i]", integrity_test_vectors[i].input ?: "NULL", integrity_test_vectors[i].key_size);
		if (crypt_parse_hash_integrity_mode(integrity_test_vectors[i].input, integrity) < 0 ||
			strcmp(integrity_test_vectors[i].integrity, integrity)) {
			printf("[FAILED (%s)]\n", integrity);
			return EXIT_FAILURE;
		}
		key_size = -1;
		memset(integrity, 0, sizeof(integrity));
		if (integrity_test_vectors[i].int_mode &&
		    (crypt_parse_integrity_mode(integrity_test_vectors[i].input, integrity, &key_size, 0) < 0 ||
			strcmp(integrity_test_vectors[i].integrity, integrity) ||
			integrity_test_vectors[i].key_size != key_size)) {
			printf("[FAILED (%s / %i)]\n", integrity, key_size);
			return EXIT_FAILURE;
		}
	}
	printf("[OK]\n");

	return EXIT_SUCCESS;
}

/*
 * Cryptsetup null cipher bypass algorithm name
 */
struct null_test_vector {
	const char *cipher;
	bool ok;
};
static struct null_test_vector null_test_vectors[] = {
	{ "cipher_null-ecb", true },
	{ "cipher_null", true },
	{ "null", true },
	{ "cipher-null", false },
	{ "aes-ecb", false },
	{ NULL, false },
};

static int test_cipher_null(void)
{
	unsigned int i;

	printf("NULLCONV:");
	for (i = 0; i < ARRAY_SIZE(null_test_vectors); i++) {
		printf("[%s]", null_test_vectors[i].cipher ?: "NULL");
		if (crypt_is_cipher_null(null_test_vectors[i].cipher) !=
			null_test_vectors[i].ok) {
			printf("[FAILED]\n");
			return EXIT_FAILURE;
		}
	}
	printf("[OK]\n");

	return EXIT_SUCCESS;
}

struct hex_test_vector {
	const char *hex;
	const char *bytes;
	ssize_t bytes_size;
	bool ok;
};
static struct hex_test_vector hex_test_vectors[] = {
	{ "0000000000000000", "\x00\x00\x00\x00\x00\x00\x00\x00", 8, true },
	{ "abcdef0123456789", "\xab\xcd\xef\x01\x23\x45\x67\x89", 8, true },
	{ "aBCDef0123456789", "\xab\xcd\xef\x01\x23\x45\x67\x89", 8, true },
	{ "ff", "\xff", 1, true },
	{ "f", NULL , 1, false },
	{ "a-cde", NULL, 2, false },
	{ "FAKE", NULL, 2, false },
	{ "\x01\x02\xff", NULL, 3, false },
	{ NULL, NULL, 1, false },
	{ "fff", NULL, 2, false },
	{ "fg", NULL, 1, false },
};

/*
 * Hexa conversion test (also should be constant time)
 */
static int test_hex_conversion(void)
{
	char *bytes, *hex;
	ssize_t len;
	unsigned int i;

	printf("HEXCONV:");
	for (i = 0; i < ARRAY_SIZE(hex_test_vectors); i++) {
		bytes = NULL;
		hex = NULL;
		if (hex_test_vectors[i].hex && *hex_test_vectors[i].hex >= '0')
			printf("[%s]", hex_test_vectors[i].hex);
		else
			printf("[INV:%i]", i);
		len = crypt_hex_to_bytes(hex_test_vectors[i].hex, &bytes, 1);
		if ((hex_test_vectors[i].ok && len != hex_test_vectors[i].bytes_size) ||
		   (!hex_test_vectors[i].ok && len >= 0)) {
			printf("[FAILED]\n");
			crypt_safe_free(bytes);
			return EXIT_FAILURE;
		}
		crypt_safe_free(bytes);
		hex = crypt_bytes_to_hex(hex_test_vectors[i].bytes_size, hex_test_vectors[i].bytes);
		if ((hex_test_vectors[i].ok && strcasecmp(hex, hex_test_vectors[i].hex)) ||
		   (!hex_test_vectors[i].ok && hex)) {
			printf("[FAILED]\n");
			crypt_safe_free(hex);
			return EXIT_FAILURE;
		}
		crypt_safe_free(hex);
	}
	printf("[OK]\n");

	return EXIT_SUCCESS;
}

static void __attribute__((noreturn)) exit_test(const char *msg, int r)
{
	if (msg)
		printf("%s\n", msg);
	exit(r);
}

int main(__attribute__ ((unused)) int argc, __attribute__ ((unused))char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);

#ifndef NO_CRYPTSETUP_PATH
	if (getenv("CRYPTSETUP_PATH")) {
		printf("Cannot run this test with CRYPTSETUP_PATH set.\n");
		exit(77);
	}
#endif
	if (test_parse_mode())
		exit_test("Parse mode test failed.", EXIT_FAILURE);

	if (test_parse_integrity_mode())
		exit_test("Parse integrity mode test failed.", EXIT_FAILURE);

	if (test_cipher_null())
		exit_test("CIPHER null test failed.", EXIT_FAILURE);

	if (test_hex_conversion())
		exit_test("HEX conversion test failed.", EXIT_FAILURE);

	exit_test(NULL, EXIT_SUCCESS);
}
