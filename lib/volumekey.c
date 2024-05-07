// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup volume key implementation
 *
 * Copyright (C) 2004-2006 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2010-2024 Red Hat, Inc. All rights reserved.
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
	vk->id = KEY_NOT_VERIFIED;
	vk->next = NULL;

	/* keylength 0 is valid => no key */
	if (vk->keylength) {
		if (key)
			crypt_safe_memcpy(&vk->key, key, keylength);
		else
			crypt_safe_memzero(&vk->key, keylength);
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

void crypt_volume_key_set_id(struct volume_key *vk, int id)
{
	if (vk && id >= 0)
		vk->id = id;
}

int crypt_volume_key_get_id(const struct volume_key *vk)
{
	return vk ? vk->id : -1;
}

struct volume_key *crypt_volume_key_by_id(struct volume_key *vks, int id)
{
	struct volume_key *vk = vks;

	if (id < 0)
		return NULL;

	while (vk && vk->id != id)
		vk = vk->next;

	return vk;
}

void crypt_volume_key_add_next(struct volume_key **vks, struct volume_key *vk)
{
	struct volume_key *tmp;

	if (!vks)
		return;

	if (!*vks) {
		*vks = vk;
		return;
	}

	tmp = *vks;

	while (tmp->next)
		tmp = tmp->next;

	tmp->next = vk;
}

struct volume_key *crypt_volume_key_next(struct volume_key *vk)
{
	return vk ? vk->next : NULL;
}

void crypt_free_volume_key(struct volume_key *vk)
{
	struct volume_key *vk_next;

	while (vk) {
		crypt_safe_memzero(vk->key, vk->keylength);
		vk->keylength = 0;
		free(CONST_CAST(void*)vk->key_description);
		vk_next = vk->next;
		free(vk);
		vk = vk_next;
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
