/*
 * cryptsetup plain device helper functions
 *
 * Copyright (C) 2004 Christophe Saout <christophe@saout.de>
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "internal.h"
#include "crypto_backend.h"

static int hash(const char *hash_name, int size, char *key,
		int sizep, const char *passphrase)
{
	struct crypt_hash *md = NULL;
	size_t slen;
	int len = crypt_hash_size(hash_name);
	int round, i;

	if (crypt_hash_init(&md, hash_name))
		return -ENOENT;

	for(round = 0; size; round++) {
		/* hack from hashalot to avoid null bytes in key */
		for(i = 0; i < round; i++)
			crypt_hash_write(md, "A", 1);

		crypt_hash_write(md, passphrase, sizep);

		if (len > size)
			len = size;
		slen = len;
		crypt_hash_final(md, key, slen);
		// FIXME: if slen != len

		key += len;
		size -= len;
		if (size)
			crypt_hash_restart(md);
	}

	crypt_hash_destroy(md);
	return 0;
}

int crypt_plain_hash(struct crypt_device *ctx, const char *hash_name,
		     char *result, size_t size,
		     const char *passphrase, size_t sizep)
{
	char hash_name_buf[256], *s;
	size_t hlen, pad = 0;
	int r;

	if (strlen(hash_name) >= sizeof(hash_name_buf))
		return -EINVAL;

	if ((s = strchr(hash_name, ':'))) {
		strcpy(hash_name_buf, hash_name);
		hash_name_buf[s-hash_name] = '\0';
		hash_name = hash_name_buf;
		hlen = atoi(++s);
		if (hlen > size) {
			log_err(ctx, "Requested hash length (%zd) > key length (%zd)\n", hlen, size);
			return -EINVAL;
		}
		pad = size-hlen;
		size = hlen;
	}

	r = hash(hash_name, size, result, sizep, passphrase);
	if (r < 0)
		log_err(ctx, "Hash algorithm %s not supported.\n", hash_name);

	if (r == 0 && pad)
		memset(result+size, 0, pad);

	return r;
}
