// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup volume key implementation
 *
 * Copyright (C) 2004-2006 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2010-2024 Red Hat, Inc. All rights reserved.
 */

#include <string.h>
#include <stdio.h>
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
	vk->keyring_key_type = INVALID_KEY;
	vk->keylength = keylength;
	vk->uploaded = false;
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

struct volume_key *crypt_generate_trusted_volume_key(struct crypt_device *cd, const char *key_string, int *out_key_size)
{
	int kid;
	struct volume_key *vk = NULL;
	int key_size;
	char *key_type = NULL, *key_desc = NULL;
	char *buf = NULL;
	size_t bufsize = 0;

	assert(key_string);
	assert(out_key_size);

	/*
	 * parse the whole keystring, to primarily get to the actual
	 * volume_key_size which is used later during the format step.
	 */
	if (keyring_parse_keystring(key_string, &key_size, &key_type, &key_desc))
		goto out;

	if (!strstr(key_type, "trusted")) {
		log_err(cd, "expected a 'trusted' kernel key_string");
		goto out;
	}

	/* check that the keyring doesn't already hold a key with the user-supplied name*/
	kid = keyring_find_key_id_by_name(key_string);
	if (kid > 0) {
		log_err(cd, "The keyring already has the key: \"%s\", cant create the same.", key_string);
		goto out;
	} else {
		log_dbg(cd, "Generating new trusted key, with size: %i.", key_size);
		kid = keyring_new_trusted_key(key_size, key_desc);
		log_dbg(cd, "new kid = %i, size=%i", kid, key_size);
	}

	/* read back the bin2hex <keyblob> */
	keyring_read_key(kid, &buf, &bufsize);
	if (bufsize == 0) {
		log_err(cd, "Couldn't read keyblobl from trusted kernel keyring.");
		goto out;
	}
	log_dbg(cd, "Read back keyblob for kid: %i, keyblob[%zu] %s", kid, bufsize, buf);

	/*
	 * store the '<keystring>::<keyblob>' as the key data
	 * as it is needed to later reconstruct the trusted key during
	 * other actions like 'open'.
	*/
	bufsize = strlen(key_string) + 2 + bufsize;
	vk = crypt_alloc_volume_key(bufsize, NULL);
	if (!vk) {
		log_err(cd, "Failed to allocate a volume key for the key_string: '%s'", key_string);
		goto out;
	}
	bufsize = snprintf(vk->key, bufsize + 1, "%s::%s", key_string, buf);

	/* now that the key has been succesfully created in the keyring, return the
	 * actual keysize that was requested as part of the key_string
	 */
	*out_key_size = key_size;

	/* %trusted: keys are not directly accessible, and can't be verified */
	vk->id = KEY_VERIFIED;

	/* keep the kernel key-string as volume-key.description,
	 * so that libdevmapper passes it into the dmsetup table
	 */
	vk->key_description = strdup(key_string);

out:
	if (key_desc)
		free(key_desc);
	if (key_type)
		free(key_type);
	crypt_safe_free(buf);
	return vk;
}
