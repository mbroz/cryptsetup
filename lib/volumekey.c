/*
 * cryptsetup volume key implementation
 *
 * Copyright (C) 2004-2006, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2010-2018, Red Hat, Inc. All rights reserved.
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

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "internal.h"

struct volume_key *crypt_alloc_volume_key(size_t keylength, const char *key)
{
	struct volume_key *vk;

	if (keylength > (SIZE_MAX - sizeof(*vk)))
		return NULL;

	vk = malloc(sizeof(*vk) + keylength);
	if (!vk)
		return NULL;

	vk->key_description = NULL;
	vk->keylength = keylength;

	/* keylength 0 is valid => no key */
	if (vk->keylength) {
		if (key)
			memcpy(&vk->key, key, keylength);
		else
			crypt_memzero(&vk->key, keylength);
	}

	return vk;
}

int crypt_volume_key_set_description(struct volume_key *vk, const char *key_description)
{
	if (!vk)
		return -EINVAL;

	free(CONST_CAST(void*)vk->key_description);
	vk->key_description = NULL;
	if (key_description && !(vk->key_description = strdup(key_description)))
		return -ENOMEM;

	return 0;
}

void crypt_free_volume_key(struct volume_key *vk)
{
	if (vk) {
		crypt_memzero(vk->key, vk->keylength);
		vk->keylength = 0;
		free(CONST_CAST(void*)vk->key_description);
		free(vk);
	}
}

struct volume_key *crypt_generate_volume_key(struct crypt_device *cd, size_t keylength)
{
	int r;
	struct volume_key *vk;

	vk = crypt_alloc_volume_key(keylength, NULL);
	if (!vk)
		return NULL;

	r = crypt_random_get(cd, vk->key, keylength, CRYPT_RND_KEY);
	if(r < 0) {
		crypt_free_volume_key(vk);
		return NULL;
	}
	return vk;
}
