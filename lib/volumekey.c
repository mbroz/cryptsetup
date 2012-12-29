/*
 * cryptsetup volume key implementation
 *
 * Copyright (C) 2004-2006, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2010-2012, Red Hat, Inc. All rights reserved.
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
#include <stdlib.h>

#include "internal.h"

struct volume_key *crypt_alloc_volume_key(unsigned keylength, const char *key)
{
	struct volume_key *vk = malloc(sizeof(*vk) + keylength);

	if (!vk)
		return NULL;

	vk->keylength = keylength;
	if (key)
		memcpy(&vk->key, key, keylength);
	else
		memset(&vk->key, 0, keylength);

	return vk;
}

void crypt_free_volume_key(struct volume_key *vk)
{
	if (vk) {
		memset(vk->key, 0, vk->keylength);
		vk->keylength = 0;
		free(vk);
	}
}

struct volume_key *crypt_generate_volume_key(struct crypt_device *cd, unsigned keylength)
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
