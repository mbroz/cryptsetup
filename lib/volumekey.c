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

struct volume_key {
	int id;
	size_t keylength; /* length in bytes */
	const char *key_description; /* keyring key name/description */
	key_type_t keyring_key_type; /* kernel keyring key type */
	key_serial_t key_id; /* kernel key id of volume key representation linked in thread keyring */
	struct volume_key *next;
	char *key;
};

struct volume_key *crypt_alloc_volume_key(size_t keylength, const char *key)
{
	struct volume_key *vk;

	if (keylength > (SIZE_MAX - sizeof(*vk)))
		return NULL;

	vk = crypt_zalloc(sizeof(*vk));
	if (!vk)
		return NULL;

	vk->keyring_key_type = INVALID_KEY;
	vk->key_id = -1;
	vk->keylength = keylength;
	vk->id = KEY_NOT_VERIFIED;

	/* keylength 0 is valid => no key */
	if (vk->keylength && key) {
		vk->key = crypt_safe_alloc(keylength);
		if (!vk->key) {
			free(vk);
			return NULL;
		}
		crypt_safe_memcpy(vk->key, key, keylength);
	}

	return vk;
}

struct volume_key *crypt_alloc_volume_key_by_safe_alloc(void **safe_alloc)
{
	size_t keylength;
	struct volume_key *vk;

	if (!safe_alloc)
		return NULL;

	keylength = crypt_safe_alloc_size(*safe_alloc);
	if (!keylength)
		return NULL;

	vk = crypt_alloc_volume_key(keylength, NULL);
	if (!vk)
		return NULL;

	vk->key = *safe_alloc;
	*safe_alloc = NULL;

	return vk;
}

void crypt_volume_key_pass_safe_alloc(struct volume_key *vk, void **safe_alloc)
{
	assert(vk);
	assert(vk->keylength);
	assert(safe_alloc);
	assert(crypt_safe_alloc_size(*safe_alloc) == vk->keylength);

	crypt_safe_free(vk->key);
	vk->key = *safe_alloc;
	*safe_alloc = NULL;
}

const char *crypt_volume_key_get_key(const struct volume_key *vk)
{
	assert(vk && vk->key);

	return vk->key;
}

size_t crypt_volume_key_length(const struct volume_key *vk)
{
	assert(vk);

	return vk->keylength;
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

const char *crypt_volume_key_description(const struct volume_key *vk)
{
	assert(vk);

	return vk->key_description;
}


key_type_t crypt_volume_key_kernel_key_type(const struct volume_key *vk)
{
	assert(vk);

	return vk->keyring_key_type;
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
		crypt_safe_free(vk->key);
		vk_next = vk->next;
		free(vk);
		vk = vk_next;
	}
}

struct volume_key *crypt_generate_volume_key(struct crypt_device *cd, size_t keylength,
					     key_quality_info quality)
{
	int r;
	void *key;
	struct volume_key *vk = NULL;

	key = crypt_safe_alloc(keylength);
	if (!key)
		return NULL;

	switch (quality) {
	case KEY_QUALITY_KEY:
		r = crypt_random_get(cd, key, keylength, CRYPT_RND_KEY);
		break;
	case KEY_QUALITY_NORMAL:
		r = crypt_random_get(cd, key, keylength, CRYPT_RND_NORMAL);
		break;
	case KEY_QUALITY_EMPTY:
		r = 0;
		break;
	default:
		abort();
	}

	if (!r)
		vk = crypt_alloc_volume_key(keylength, NULL);
	if (vk)
		vk->key = key;
	else
		crypt_safe_free(key);

	return vk;
}

bool crypt_volume_key_is_set(const struct volume_key *vk)
{
	return vk && vk->key;
}

bool crypt_volume_key_upload_kernel_key(struct volume_key *vk)
{
	key_serial_t kid;

	assert(vk && vk->key && vk->key_description && vk->keyring_key_type != INVALID_KEY);

	kid = keyring_add_key_in_thread_keyring(vk->keyring_key_type, vk->key_description,
					 vk->key, vk->keylength);
	if (kid >= 0) {
		vk->key_id = kid;
		return true;
	}

	return false;
}

void crypt_volume_key_drop_kernel_key(struct crypt_device *cd, struct volume_key *vk)
{
	assert(vk);
	assert(vk->key_description || vk->keyring_key_type == INVALID_KEY);
	assert(!vk->key_description || vk->keyring_key_type != INVALID_KEY);

	crypt_unlink_key_by_description_from_thread_keyring(cd,
							    vk->key_description,
							    vk->keyring_key_type);
}

void crypt_volume_key_drop_uploaded_kernel_key(struct crypt_device *cd, struct volume_key *vk)
{
	assert(vk);

	if (vk->key_id < 0)
		return;

	crypt_unlink_key_from_thread_keyring(cd, vk->key_id);
	vk->key_id = -1;
}
