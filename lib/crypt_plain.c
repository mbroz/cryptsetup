// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup plain device helper functions
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2010-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2010-2025 Milan Broz
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "libcryptsetup.h"
#include "internal.h"

static int hash(const char *hash_name, size_t key_size, char *key,
		size_t passphrase_size, const char *passphrase)
{
	struct crypt_hash *md = NULL;
	size_t len;
	int round, i, r = 0;

	if (crypt_hash_init(&md, hash_name))
		return -ENOENT;

	len = crypt_hash_size(hash_name);

	for(round = 0; key_size && !r; round++) {
		/* hack from hashalot to avoid null bytes in key */
		for(i = 0; i < round; i++)
			if (crypt_hash_write(md, "A", 1))
				r = 1;

		if (crypt_hash_write(md, passphrase, passphrase_size))
			r = 1;

		if (len > key_size)
			len = key_size;

		if (crypt_hash_final(md, key, len))
			r = 1;

		key += len;
		key_size -= len;
	}

	crypt_hash_destroy(md);
	return r;
}

#define PLAIN_HASH_LEN_MAX 256

int crypt_plain_hash(struct crypt_device *cd,
		     const char *hash_name,
		     char *key, size_t key_size,
		     const char *passphrase, size_t passphrase_size)
{
	char hash_name_buf[PLAIN_HASH_LEN_MAX], *s;
	size_t hash_size, pad_size;
	int r;

	log_dbg(cd, "Plain: hashing passphrase using %s.", hash_name);

	if (strlen(hash_name) >= PLAIN_HASH_LEN_MAX)
		return -EINVAL;
	strncpy(hash_name_buf, hash_name, PLAIN_HASH_LEN_MAX);
	hash_name_buf[PLAIN_HASH_LEN_MAX - 1] = '\0';

	/* hash[:hash_length] */
	if ((s = strchr(hash_name_buf, ':'))) {
		*s = '\0';
		s++;
		if (!*s || sscanf(s, "%zd", &hash_size) != 1) {
			log_dbg(cd, "Hash length is not a number");
			return -EINVAL;
		}
		if (hash_size > key_size) {
			log_dbg(cd, "Hash length %zd > key length %zd",
				hash_size, key_size);
			return -EINVAL;
		}
		pad_size = key_size - hash_size;
	} else {
		hash_size = key_size;
		pad_size = 0;
	}

	/* No hash, copy passphrase directly */
	if (!strcmp(hash_name_buf, "plain")) {
		if (passphrase_size < hash_size) {
			log_dbg(cd, "Too short plain passphrase.");
			return -EINVAL;
		}
		crypt_safe_memcpy(key, passphrase, hash_size);
		r = 0;
	} else
		r = hash(hash_name_buf, hash_size, key, passphrase_size, passphrase);

	if (r == 0 && pad_size)
		memset(key + hash_size, 0, pad_size);

	return r;
}
