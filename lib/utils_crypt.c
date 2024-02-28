// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * utils_crypt - cipher utilities for cryptsetup
 *
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "libcryptsetup.h"
#include "utils_crypt.h"

#define MAX_CAPI_LEN_STR "143" /* for sscanf of crypto API string + 16  + \0 */

int crypt_parse_name_and_mode(const char *s, char *cipher, int *key_nums,
			      char *cipher_mode)
{
	if (!s || !cipher || !cipher_mode)
		return -EINVAL;

	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]-%" MAX_CIPHER_LEN_STR "s",
		   cipher, cipher_mode) == 2) {
		if (!strncmp(cipher, "capi:", 5)) {
			/* CAPI must not use internal cipher driver names with dash */
			if (strchr(cipher_mode, ')'))
				return -EINVAL;
			if (key_nums)
				*key_nums = 1;
			return 0;
		}
		if (!strcmp(cipher_mode, "plain"))
			strcpy(cipher_mode, "cbc-plain");
		if (key_nums) {
			char *tmp = strchr(cipher, ':');
			*key_nums = tmp ? atoi(++tmp) : 1;
			if (!*key_nums)
				return -EINVAL;
		}

		return 0;
	}

	/* Short version for "empty" cipher */
	if (!strcmp(s, "null") || !strcmp(s, "cipher_null")) {
		strcpy(cipher, "cipher_null");
		strcpy(cipher_mode, "ecb");
		if (key_nums)
			*key_nums = 0;
		return 0;
	}

	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]", cipher) == 1) {
		if (!strncmp(cipher, "capi:", 5))
			strcpy(cipher_mode, "");
		else
			strcpy(cipher_mode, "cbc-plain");
		if (key_nums)
			*key_nums = 1;
		return 0;
	}

	return -EINVAL;
}

int crypt_parse_hash_integrity_mode(const char *s, char *integrity)
{
	char mode[MAX_CIPHER_LEN], hash[MAX_CIPHER_LEN];
	int r;

	if (!s || !integrity || strchr(s, '(') || strchr(s, ')'))
		return -EINVAL;

	r = sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]-%" MAX_CIPHER_LEN_STR "s", mode, hash);
	if (r == 2 && !isdigit(hash[0]))
		r = snprintf(integrity, MAX_CIPHER_LEN, "%s(%s)", mode, hash);
	else if (r == 2)
		r = snprintf(integrity, MAX_CIPHER_LEN, "%s-%s", mode, hash);
	else if (r == 1)
		r = snprintf(integrity, MAX_CIPHER_LEN, "%s", mode);
	else
		return -EINVAL;

	if (r < 0 || r >= MAX_CIPHER_LEN)
		return -EINVAL;

	return 0;
}

int crypt_parse_integrity_mode(const char *s, char *integrity,
			       int *integrity_key_size, int required_key_size)
{
	int ks = 0, r = 0;

	if (!s || !integrity)
		return -EINVAL;

	/* AEAD modes */
	if (!strcmp(s, "aead") ||
	    !strcmp(s, "poly1305") ||
	    !strcmp(s, "none")) {
		strncpy(integrity, s, MAX_CIPHER_LEN);
		ks = 0;
		if (required_key_size != ks)
			r = -EINVAL;
	} else if (!strcmp(s, "hmac-sha1")) {
		strncpy(integrity, "hmac(sha1)", MAX_CIPHER_LEN);
		ks = required_key_size ?: 20;
	} else if (!strcmp(s, "hmac-sha256")) {
		strncpy(integrity, "hmac(sha256)", MAX_CIPHER_LEN);
		ks = required_key_size ?: 32;
	} else if (!strcmp(s, "hmac-sha512")) {
		strncpy(integrity, "hmac(sha512)", MAX_CIPHER_LEN);
		ks = required_key_size ?: 64;
	} else if (!strcmp(s, "phmac-sha1")) {
		strncpy(integrity, "phmac(sha1)", MAX_CIPHER_LEN);
		ks = required_key_size;
		if (!required_key_size)
			r = -EINVAL;
	} else if (!strcmp(s, "phmac-sha256")) {
		strncpy(integrity, "phmac(sha256)", MAX_CIPHER_LEN);
		ks = required_key_size;
		if (!required_key_size)
			r = -EINVAL;
	} else if (!strcmp(s, "phmac-sha512")) {
		strncpy(integrity, "phmac(sha512)", MAX_CIPHER_LEN);
		ks = required_key_size;
		if (!required_key_size)
			r = -EINVAL;
	} else if (!strcmp(s, "cmac-aes")) {
		strncpy(integrity, "cmac(aes)", MAX_CIPHER_LEN);
		ks = 16;
		if (required_key_size && required_key_size != ks)
			r = -EINVAL;
	} else
		r = -EINVAL;

	if (integrity_key_size)
		*integrity_key_size = ks;

	return r;
}

int crypt_parse_pbkdf(const char *s, const char **pbkdf)
{
	const char *tmp = NULL;

	if (!s)
		return -EINVAL;

	if (!strcasecmp(s, CRYPT_KDF_PBKDF2))
		tmp = CRYPT_KDF_PBKDF2;
	else if (!strcasecmp(s, CRYPT_KDF_ARGON2I))
		tmp = CRYPT_KDF_ARGON2I;
	else if (!strcasecmp(s, CRYPT_KDF_ARGON2ID))
		tmp = CRYPT_KDF_ARGON2ID;

	if (!tmp)
		return -EINVAL;

	if (pbkdf)
		*pbkdf = tmp;

	return 0;
}

/*
 * Thanks Mikulas Patocka for these two char converting functions.
 *
 * This function is used to load cryptographic keys, so it is coded in such a
 * way that there are no conditions or memory accesses that depend on data.
 *
 * Explanation of the logic:
 * (ch - '9' - 1) is negative if ch <= '9'
 * ('0' - 1 - ch) is negative if ch >= '0'
 * we "and" these two values, so the result is negative if ch is in the range
 * '0' ... '9'
 * we are only interested in the sign, so we do a shift ">> 8"; note that right
 * shift of a negative value is implementation-defined, so we cast the
 * value to (unsigned) before the shift --- we have 0xffffff if ch is in
 * the range '0' ... '9', 0 otherwise
 * we "and" this value with (ch - '0' + 1) --- we have a value 1 ... 10 if ch is
 * in the range '0' ... '9', 0 otherwise
 * we add this value to -1 --- we have a value 0 ... 9 if ch is in the range '0'
 * ... '9', -1 otherwise
 * the next line is similar to the previous one, but we need to decode both
 * uppercase and lowercase letters, so we use (ch & 0xdf), which converts
 * lowercase to uppercase
 */
static int hex_to_bin(unsigned char ch)
{
	unsigned char cu = ch & 0xdf;
	return -1 +
		((ch - '0' +  1) & (unsigned)((ch - '9' - 1) & ('0' - 1 - ch)) >> 8) +
		((cu - 'A' + 11) & (unsigned)((cu - 'F' - 1) & ('A' - 1 - cu)) >> 8);
}

static char hex2asc(unsigned char c)
{
	return c + '0' + ((unsigned)(9 - c) >> 4 & 0x27);
}

ssize_t crypt_hex_to_bytes(const char *hex, char **result, int safe_alloc)
{
	char *bytes;
	size_t i, len;
	int bl, bh;

	if (!hex || !result)
		return -EINVAL;

	len = strlen(hex);
	if (len % 2)
		return -EINVAL;
	len /= 2;

	bytes = safe_alloc ? crypt_safe_alloc(len) : malloc(len);
	if (!bytes)
		return -ENOMEM;

	for (i = 0; i < len; i++) {
		bh = hex_to_bin(hex[i * 2]);
		bl = hex_to_bin(hex[i * 2 + 1]);
		if (bh == -1 || bl == -1) {
			safe_alloc ? crypt_safe_free(bytes) : free(bytes);
			return -EINVAL;
		}
		bytes[i] = (bh << 4) | bl;
	}
	*result = bytes;
	return i;
}

char *crypt_bytes_to_hex(size_t size, const char *bytes)
{
	unsigned i;
	char *hex;

	if (size && !bytes)
		return NULL;

	/* Alloc adds trailing \0 */
	if (size == 0)
		hex = crypt_safe_alloc(2);
	else
		hex = crypt_safe_alloc(size * 2 + 1);
	if (!hex)
		return NULL;

	if (size == 0)
		hex[0] = '-';
	else for (i = 0; i < size; i++) {
		hex[i * 2]     = hex2asc((const unsigned char)bytes[i] >> 4);
		hex[i * 2 + 1] = hex2asc((const unsigned char)bytes[i] & 0xf);
	}

	return hex;
}

void crypt_log_hex(struct crypt_device *cd,
		   const char *bytes, size_t size,
		   const char *sep, int numwrap, const char *wrapsep)
{
	unsigned i;

	for (i = 0; i < size; i++) {
		if (wrapsep && numwrap && i && !(i % numwrap))
			crypt_logf(cd, CRYPT_LOG_NORMAL, wrapsep);
		crypt_logf(cd, CRYPT_LOG_NORMAL, "%c%c%s",
			   hex2asc((const unsigned char)bytes[i] >> 4),
			   hex2asc((const unsigned char)bytes[i] & 0xf), sep);
	}
}

bool crypt_is_cipher_null(const char *cipher_spec)
{
	if (!cipher_spec)
		return false;
	return (strstr(cipher_spec, "cipher_null") || !strcmp(cipher_spec, "null"));
}

int crypt_capi_to_cipher(char **org_c, char **org_i, const char *c_dm, const char *i_dm)
{
	char cipher[MAX_CAPI_ONE_LEN], mode[MAX_CAPI_ONE_LEN], iv[MAX_CAPI_ONE_LEN],
	     auth[MAX_CAPI_ONE_LEN], tmp[MAX_CAPI_LEN], dmcrypt_tmp[MAX_CAPI_LEN*2],
	     capi[MAX_CAPI_LEN+1];
	size_t len;
	int i;

	if (!c_dm)
		return -EINVAL;

	/* legacy mode */
	if (strncmp(c_dm, "capi:", 4)) {
		if (!(*org_c = strdup(c_dm)))
			return -ENOMEM;
		if (i_dm) {
			if (!(*org_i = strdup(i_dm))) {
				free(*org_c);
				*org_c = NULL;
				return -ENOMEM;
			}
		} else
			*org_i = NULL;
		return 0;
	}

	/* modes with capi: prefix */
	i = sscanf(c_dm, "capi:%" MAX_CAPI_LEN_STR "[^-]-%" MAX_CAPI_ONE_LEN_STR "s", tmp, iv);
	if (i != 2)
		return -EINVAL;

	/* non-cryptsetup compatible mode (generic driver with dash?) */
	if (strrchr(iv, ')')) {
		if (i_dm)
			return -EINVAL;
		if (!(*org_c = strdup(c_dm)))
			return -ENOMEM;
		return 0;
	}

	len = strlen(tmp);
	if (len < 2)
		return -EINVAL;

	if (tmp[len-1] == ')')
		tmp[len-1] = '\0';

	if (sscanf(tmp, "rfc4309(%" MAX_CAPI_LEN_STR "s", capi) == 1) {
		if (!(*org_i = strdup("aead")))
			return -ENOMEM;
	} else if (sscanf(tmp, "rfc7539(%" MAX_CAPI_LEN_STR "[^,],%" MAX_CAPI_ONE_LEN_STR "s", capi, auth) == 2) {
		if (!(*org_i = strdup(auth)))
			return -ENOMEM;
	} else if (sscanf(tmp, "authenc(%" MAX_CAPI_ONE_LEN_STR "[^,],%" MAX_CAPI_LEN_STR "s", auth, capi) == 2) {
		if (!(*org_i = strdup(auth)))
			return -ENOMEM;
	} else {
		if (i_dm) {
			if (!(*org_i = strdup(i_dm)))
				return -ENOMEM;
		} else
			*org_i = NULL;
		memset(capi, 0, sizeof(capi));
		strncpy(capi, tmp, sizeof(capi)-1);
	}

	i = sscanf(capi, "%" MAX_CAPI_ONE_LEN_STR "[^(](%" MAX_CAPI_ONE_LEN_STR "[^)])", mode, cipher);
	if (i == 2)
		i = snprintf(dmcrypt_tmp, sizeof(dmcrypt_tmp), "%s-%s-%s", cipher, mode, iv);
	else
		i = snprintf(dmcrypt_tmp, sizeof(dmcrypt_tmp), "%s-%s", capi, iv);
	if (i < 0 || (size_t)i >= sizeof(dmcrypt_tmp)) {
		free(*org_i);
		*org_i = NULL;
		return -EINVAL;
	}

	if (!(*org_c = strdup(dmcrypt_tmp))) {
		free(*org_i);
		*org_i = NULL;
		return -ENOMEM;
	}

	return 0;
}
