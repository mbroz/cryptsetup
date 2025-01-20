// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup volume key implementation
 *
 * Copyright (C) 2004-2006 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2010-2025 Red Hat, Inc. All rights reserved.
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

	vk = crypt_safe_alloc(sizeof(*vk) + keylength);
	if (!vk)
		return NULL;

	vk->key_description = NULL;
	vk->keyring_key_type = INVALID_KEY;
	vk->keylength = keylength;
	vk->uploaded = false;
	vk->has_key_data = false;
	vk->id = KEY_NOT_VERIFIED;
	vk->next = NULL;

	/* keylength 0 is valid => no key */
	if (vk->keylength) {
		if (key) {
			crypt_safe_memcpy(&vk->key, key, keylength);
			vk->has_key_data = true;
		} else
			crypt_safe_memzero(&vk->key, keylength);
	}

	return vk;
}

int crypt_volume_key_set_description(struct volume_key *vk,
				     const char *key_description, key_type_t keyring_key_type)
{
	if (!vk)
		return -EINVAL;

	free(CONST_CAST(void*)vk->key_description);
	vk->key_description = NULL;
	vk->keyring_key_type = keyring_key_type;
	if (key_description && !(vk->key_description = strdup(key_description)))
		return -ENOMEM;

	return 0;
}

int crypt_volume_key_set_description_by_name(struct volume_key *vk, const char *key_name)
{
	const char *key_description = NULL;
	key_type_t keyring_key_type = keyring_type_and_name(key_name, &key_description);

	if (keyring_key_type == INVALID_KEY)
		return -EINVAL;

	return crypt_volume_key_set_description(vk, key_description, keyring_key_type);
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
		free(CONST_CAST(void*)vk->key_description);
		vk_next = vk->next;
		crypt_safe_free(vk);
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
	vk->has_key_data = true;
	return vk;
}

void crypt_volume_key_set_key(struct volume_key *vk, const char *key, size_t key_length)
{
	assert(vk && vk->keylength >= key_length);

	crypt_safe_memcpy(vk->key, key, key_length);

	vk->has_key_data = true;
}

int crypt_volume_key_set_key_from_hexbyte(struct volume_key *vk,
					  const char *hexkey_string)
{
	char *endp, buffer[3];
	size_t i;
	int r = -EINVAL;

	if (!vk || !hexkey_string)
		return r;

	buffer[2] = '\0';
	for (i = 0; i < vk->keylength; i++) {
		crypt_safe_memcpy(buffer, &hexkey_string[i * 2], 2);
		vk->key[i] = strtoul(buffer, &endp, 16);
		if (endp != &buffer[2])
			goto out;
	}

       if (hexkey_string[i*2] != '\0')
               goto out;

	vk->has_key_data = true;
	r = 0;
out:
	if (r < 0) {
		vk->has_key_data = false;
		crypt_safe_memzero(vk->key, vk->keylength);
	}

	return r;
}

bool crypt_volume_key_has_data(const struct volume_key *vk)
{
	return vk && vk->has_key_data;
}
