/*
 * LUKS - Linux Unified Key Setup v2, keyslot handling
 *
 * Copyright (C) 2015-2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2019 Milan Broz
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

#include "luks2_internal.h"

/* Internal implementations */
extern const keyslot_handler luks2_keyslot;
extern const keyslot_handler reenc_keyslot;

static const keyslot_handler *keyslot_handlers[LUKS2_KEYSLOTS_MAX] = {
	&luks2_keyslot,
	&reenc_keyslot,
	NULL
};

static const keyslot_handler
*LUKS2_keyslot_handler_type(struct crypt_device *cd, const char *type)
{
	int i;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX && keyslot_handlers[i]; i++) {
		if (!strcmp(keyslot_handlers[i]->name, type))
			return keyslot_handlers[i];
	}

	return NULL;
}

static const keyslot_handler
*LUKS2_keyslot_handler(struct crypt_device *cd, int keyslot)
{
	struct luks2_hdr *hdr;
	json_object *jobj1, *jobj2;

	if (keyslot < 0)
		return NULL;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return NULL;

	if (!(jobj1 = LUKS2_get_keyslot_jobj(hdr, keyslot)))
		return NULL;

	if (!json_object_object_get_ex(jobj1, "type", &jobj2))
		return NULL;

	return LUKS2_keyslot_handler_type(cd, json_object_get_string(jobj2));
}

int LUKS2_keyslot_find_empty(struct luks2_hdr *hdr)
{
	int i;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++)
		if (!LUKS2_get_keyslot_jobj(hdr, i))
			return i;

	return -EINVAL;
}

/* Check if a keyslot is asssigned to specific segment */
static int _keyslot_for_segment(struct luks2_hdr *hdr, int keyslot, int segment)
{
	int keyslot_digest, segment_digest, s, count = 0;

	keyslot_digest = LUKS2_digest_by_keyslot(hdr, keyslot);
	if (keyslot_digest < 0)
		return keyslot_digest;

	if (segment >= 0) {
		segment_digest = LUKS2_digest_by_segment(hdr, segment);
		return segment_digest == keyslot_digest;
	}
	for (s = 0; s < 3; s++) {
		segment_digest = LUKS2_digest_by_segment(hdr, s);
		if (segment_digest == keyslot_digest)
			count++;
	}

	return count;
}

static int _keyslot_for_digest(struct luks2_hdr *hdr, int keyslot, int digest)
{
	int r = -EINVAL;

	r = LUKS2_digest_by_keyslot(hdr, keyslot);
	if (r < 0)
		return r;
	return r == digest ? 0 : -ENOENT;
}

int LUKS2_keyslot_for_segment(struct luks2_hdr *hdr, int keyslot, int segment)
{
	int r = -EINVAL;

	/* no need to check anything */
	if (segment == CRYPT_ANY_SEGMENT)
		return 0; /* ok */
	if (segment == CRYPT_DEFAULT_SEGMENT) {
		segment = LUKS2_get_default_segment(hdr);
		if (segment < 0)
			return segment;
	}

	r = _keyslot_for_segment(hdr, keyslot, segment);
	if (r < 0)
		return r;

	if (segment == CRYPT_ONE_SEGMENT)
		log_dbg(NULL, "At least one segment variant");

	return r >= 1 ? 0 : -ENOENT;
}

/* Number of keyslots assigned to a segment or all keyslots for CRYPT_ANY_SEGMENT */
int LUKS2_keyslot_active_count(struct luks2_hdr *hdr, int segment)
{
	int num = 0;
	json_object *jobj_keyslots;

	json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots);

	json_object_object_foreach(jobj_keyslots, slot, val) {
		UNUSED(val);
		if (!LUKS2_keyslot_for_segment(hdr, atoi(slot), segment))
			num++;
	}

	return num;
}

int LUKS2_keyslot_cipher_incompatible(struct crypt_device *cd, const char *cipher_spec)
{
	char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];

	if (!cipher_spec || !strcmp(cipher_spec, "null") || !strcmp(cipher_spec, "cipher_null"))
		return 1;

	if (crypt_parse_name_and_mode(cipher_spec, cipher, NULL, cipher_mode) < 0)
		return 1;

	/* Keyslot is already authenticated; we cannot use integrity tags here */
	if (crypt_get_integrity_tag_size(cd))
		return 1;

	/* Wrapped key schemes cannot be used for keyslot encryption */
	if (crypt_cipher_wrapped_key(cipher, cipher_mode))
		return 1;

	/* Check if crypto backend can use the cipher */
	if (crypt_cipher_ivsize(cipher, cipher_mode) < 0)
		return 1;

	return 0;
}

int LUKS2_keyslot_params_default(struct crypt_device *cd, struct luks2_hdr *hdr,
				 struct luks2_keyslot_params *params)
{
	const struct crypt_pbkdf_type *pbkdf = crypt_get_pbkdf_type(cd);
	const char *cipher_spec;
	size_t key_size;
	int r;

	if (!hdr || !pbkdf || !params)
		return -EINVAL;

	/*
	 * set keyslot area encryption parameters
	 */
	params->area_type = LUKS2_KEYSLOT_AREA_RAW;
	cipher_spec = crypt_keyslot_get_encryption(cd, CRYPT_ANY_SLOT, &key_size);
	if (!cipher_spec || !key_size)
		return -EINVAL;

	params->area.raw.key_size = key_size;
	r = snprintf(params->area.raw.encryption, sizeof(params->area.raw.encryption), "%s", cipher_spec);
	if (r < 0 || (size_t)r >= sizeof(params->area.raw.encryption))
		return -EINVAL;

	/*
	 * set keyslot AF parameters
	 */
	params->af_type = LUKS2_KEYSLOT_AF_LUKS1;
	/* currently we use hash for AF from pbkdf settings */
	r = snprintf(params->af.luks1.hash, sizeof(params->af.luks1.hash), "%s", pbkdf->hash);
	if (r < 0 || (size_t)r >= sizeof(params->af.luks1.hash))
		return -EINVAL;
	params->af.luks1.stripes = 4000;

	return 0;
}

int LUKS2_keyslot_pbkdf(struct luks2_hdr *hdr, int keyslot, struct crypt_pbkdf_type *pbkdf)
{
	json_object *jobj_keyslot, *jobj_kdf, *jobj;

	if (!hdr || !pbkdf)
		return -EINVAL;

	if (LUKS2_keyslot_info(hdr, keyslot) == CRYPT_SLOT_INVALID)
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -ENOENT;

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf))
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_kdf, "type", &jobj))
		return -EINVAL;

	memset(pbkdf, 0, sizeof(*pbkdf));

	pbkdf->type = json_object_get_string(jobj);
	if (json_object_object_get_ex(jobj_kdf, "hash", &jobj))
		pbkdf->hash = json_object_get_string(jobj);
	if (json_object_object_get_ex(jobj_kdf, "iterations", &jobj))
		pbkdf->iterations = json_object_get_int(jobj);
	if (json_object_object_get_ex(jobj_kdf, "time", &jobj))
		pbkdf->iterations = json_object_get_int(jobj);
	if (json_object_object_get_ex(jobj_kdf, "memory", &jobj))
		pbkdf->max_memory_kb = json_object_get_int(jobj);
	if (json_object_object_get_ex(jobj_kdf, "cpus", &jobj))
		pbkdf->parallel_threads = json_object_get_int(jobj);

	return 0;
}

static int LUKS2_keyslot_unbound(struct luks2_hdr *hdr, int keyslot)
{
	json_object *jobj_digest, *jobj_segments;
	int digest = LUKS2_digest_by_keyslot(hdr, keyslot);

	if (digest < 0)
		return 0;

	if (!(jobj_digest = LUKS2_get_digest_jobj(hdr, digest)))
		return 0;

	json_object_object_get_ex(jobj_digest, "segments", &jobj_segments);
	if (!jobj_segments || !json_object_is_type(jobj_segments, json_type_array) ||
	    json_object_array_length(jobj_segments) == 0)
		return 1;

	return 0;
}

crypt_keyslot_info LUKS2_keyslot_info(struct luks2_hdr *hdr, int keyslot)
{
	if(keyslot >= LUKS2_KEYSLOTS_MAX || keyslot < 0)
		return CRYPT_SLOT_INVALID;

	if (!LUKS2_get_keyslot_jobj(hdr, keyslot))
		return CRYPT_SLOT_INACTIVE;

	if (LUKS2_keyslot_unbound(hdr, keyslot))
		return CRYPT_SLOT_UNBOUND;

	if (LUKS2_keyslot_active_count(hdr, CRYPT_DEFAULT_SEGMENT) == 1 &&
	    !LUKS2_keyslot_for_segment(hdr, keyslot, CRYPT_DEFAULT_SEGMENT))
		return CRYPT_SLOT_ACTIVE_LAST;

	return CRYPT_SLOT_ACTIVE;
}

int LUKS2_keyslot_area(struct luks2_hdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length)
{
	json_object *jobj_keyslot, *jobj_area, *jobj;

	if(LUKS2_keyslot_info(hdr, keyslot) == CRYPT_SLOT_INVALID)
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -ENOENT;

	if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_area, "offset", &jobj))
		return -EINVAL;
	*offset = json_object_get_uint64(jobj);

	if (!json_object_object_get_ex(jobj_area, "size", &jobj))
		return -EINVAL;
	*length = json_object_get_uint64(jobj);

	return 0;
}

static int LUKS2_open_and_verify_by_digest(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int digest,
	const char *password,
	size_t password_len,
	struct volume_key **vk)
{
	const keyslot_handler *h;
	int key_size, r;

	if (!(h = LUKS2_keyslot_handler(cd, keyslot)))
		return -ENOENT;

	r = _keyslot_for_digest(hdr, keyslot, digest);
	if (r) {
		if (r == -ENOENT)
			log_dbg(cd, "Keyslot %d unusable for digest %d.", keyslot, digest);
		return r;
	}

	key_size = LUKS2_get_keyslot_stored_key_size(hdr, keyslot);
	if (key_size < 0)
		return -EINVAL;

	*vk = crypt_alloc_volume_key(key_size, NULL);
	if (!*vk)
		return -ENOMEM;

	r = h->open(cd, keyslot, password, password_len, (*vk)->key, (*vk)->keylength);
	if (r < 0)
		log_dbg(cd, "Keyslot %d (%s) open failed with %d.", keyslot, h->name, r);
	else
		r = LUKS2_digest_verify(cd, hdr, *vk, keyslot);

	if (r < 0) {
		crypt_free_volume_key(*vk);
		*vk = NULL;
	}

	return r < 0 ? r : keyslot;
}

static int LUKS2_open_and_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int segment,
	const char *password,
	size_t password_len,
	struct volume_key **vk)
{
	const keyslot_handler *h;
	int key_size, r;

	if (!(h = LUKS2_keyslot_handler(cd, keyslot)))
		return -ENOENT;

	r = h->validate(cd, LUKS2_get_keyslot_jobj(hdr, keyslot));
	if (r) {
		log_dbg(cd, "Keyslot %d validation failed.", keyslot);
		return r;
	}

	r = LUKS2_keyslot_for_segment(hdr, keyslot, segment);
	if (r) {
		if (r == -ENOENT)
			log_dbg(cd, "Keyslot %d unusable for segment %d.", keyslot, segment);
		return r;
	}

	key_size = LUKS2_get_volume_key_size(hdr, segment);
	if (key_size < 0)
		key_size = LUKS2_get_keyslot_stored_key_size(hdr, keyslot);
	if (key_size < 0)
		return -EINVAL;

	*vk = crypt_alloc_volume_key(key_size, NULL);
	if (!*vk)
		return -ENOMEM;

	r = h->open(cd, keyslot, password, password_len, (*vk)->key, (*vk)->keylength);
	if (r < 0)
		log_dbg(cd, "Keyslot %d (%s) open failed with %d.", keyslot, h->name, r);
	else
		r = LUKS2_digest_verify(cd, hdr, *vk, keyslot);

	if (r < 0) {
		crypt_free_volume_key(*vk);
		*vk = NULL;
	} else
		crypt_volume_key_set_id(*vk, r);

	return r < 0 ? r : keyslot;
}

static int LUKS2_keyslot_open_priority_digest(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	crypt_keyslot_priority priority,
	const char *password,
	size_t password_len,
	int digest,
	struct volume_key **vk)
{
	json_object *jobj_keyslots, *jobj;
	crypt_keyslot_priority slot_priority;
	int keyslot, r = -ENOENT;

	json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots);

	json_object_object_foreach(jobj_keyslots, slot, val) {
		if (!json_object_object_get_ex(val, "priority", &jobj))
			slot_priority = CRYPT_SLOT_PRIORITY_NORMAL;
		else
			slot_priority = json_object_get_int(jobj);

		keyslot = atoi(slot);
		if (slot_priority != priority) {
			log_dbg(cd, "Keyslot %d priority %d != %d (required), skipped.",
				keyslot, slot_priority, priority);
			continue;
		}

		r = LUKS2_open_and_verify_by_digest(cd, hdr, keyslot, digest, password, password_len, vk);

		/* Do not retry for errors that are no -EPERM or -ENOENT,
		   former meaning password wrong, latter key slot unusable for segment */
		if ((r != -EPERM) && (r != -ENOENT))
			break;
	}

	return r;
}

static int LUKS2_keyslot_open_priority(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	crypt_keyslot_priority priority,
	const char *password,
	size_t password_len,
	int segment,
	struct volume_key **vk)
{
	json_object *jobj_keyslots, *jobj;
	crypt_keyslot_priority slot_priority;
	int keyslot, r = -ENOENT;

	json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots);

	json_object_object_foreach(jobj_keyslots, slot, val) {
		if (!json_object_object_get_ex(val, "priority", &jobj))
			slot_priority = CRYPT_SLOT_PRIORITY_NORMAL;
		else
			slot_priority = json_object_get_int(jobj);

		keyslot = atoi(slot);
		if (slot_priority != priority) {
			log_dbg(cd, "Keyslot %d priority %d != %d (required), skipped.",
				keyslot, slot_priority, priority);
			continue;
		}

		r = LUKS2_open_and_verify(cd, hdr, keyslot, segment, password, password_len, vk);

		/* Do not retry for errors that are no -EPERM or -ENOENT,
		   former meaning password wrong, latter key slot unusable for segment */
		if ((r != -EPERM) && (r != -ENOENT))
			break;
	}

	return r;
}

static int LUKS2_keyslot_open_by_digest(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int digest,
	const char *password,
	size_t password_len,
	struct volume_key **vk)
{
	int r_prio, r = -EINVAL;

	if (digest < 0)
		return r;

	if (keyslot == CRYPT_ANY_SLOT) {
		r_prio = LUKS2_keyslot_open_priority_digest(cd, hdr, CRYPT_SLOT_PRIORITY_PREFER,
			password, password_len, digest, vk);
		if (r_prio >= 0)
			r = r_prio;
		else if (r_prio != -EPERM && r_prio != -ENOENT)
			r = r_prio;
		else
			r = LUKS2_keyslot_open_priority_digest(cd, hdr, CRYPT_SLOT_PRIORITY_NORMAL,
				password, password_len, digest, vk);
		/* Prefer password wrong to no entry from priority slot */
		if (r_prio == -EPERM && r == -ENOENT)
			r = r_prio;
	} else
		r = LUKS2_open_and_verify_by_digest(cd, hdr, keyslot, digest, password, password_len, vk);

	return r;
}

int LUKS2_keyslot_open_all_segments(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	const char *password,
	size_t password_len,
	struct volume_key **vks)
{
	struct volume_key *vk;
	int digest_old, digest_new, r = -EINVAL;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	digest_old = LUKS2_reencrypt_digest_old(hdr);
	if (digest_old >= 0) {
		log_dbg(cd, "Trying to unlock volume key (digest: %d) using keyslot %d.", digest_old, keyslot_old);
		r = LUKS2_keyslot_open_by_digest(cd, hdr, keyslot_old, digest_old, password, password_len, &vk);
		if (r < 0)
			goto out;
		crypt_volume_key_set_id(vk, digest_old);
		crypt_volume_key_add_next(vks, vk);
	}

	digest_new = LUKS2_reencrypt_digest_new(hdr);
	if (digest_new >= 0 && digest_old != digest_new) {
		log_dbg(cd, "Trying to unlock volume key (digest: %d) using keyslot %d.", digest_new, keyslot_new);
		r = LUKS2_keyslot_open_by_digest(cd, hdr, keyslot_new, digest_new, password, password_len, &vk);
		if (r < 0)
			goto out;
		crypt_volume_key_set_id(vk, digest_new);
		crypt_volume_key_add_next(vks, vk);
	}
out:
	if (r < 0) {
		crypt_free_volume_key(*vks);
		*vks = NULL;
	}
	return r;
}

int LUKS2_keyslot_open(struct crypt_device *cd,
	int keyslot,
	int segment,
	const char *password,
	size_t password_len,
	struct volume_key **vk)
{
	struct luks2_hdr *hdr;
	int r_prio, r = -EINVAL;

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	if (keyslot == CRYPT_ANY_SLOT) {
		r_prio = LUKS2_keyslot_open_priority(cd, hdr, CRYPT_SLOT_PRIORITY_PREFER,
			password, password_len, segment, vk);
		if (r_prio >= 0)
			r = r_prio;
		else if (r_prio != -EPERM && r_prio != -ENOENT)
			r = r_prio;
		else
			r = LUKS2_keyslot_open_priority(cd, hdr, CRYPT_SLOT_PRIORITY_NORMAL,
				password, password_len, segment, vk);
		/* Prefer password wrong to no entry from priority slot */
		if (r_prio == -EPERM && r == -ENOENT)
			r = r_prio;
	} else
		r = LUKS2_open_and_verify(cd, hdr, keyslot, segment, password, password_len, vk);

	return r;
}

int LUKS2_keyslot_reencrypt_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const struct crypt_params_reencrypt *params)
{
	const keyslot_handler *h;
	int r;

	if (keyslot == CRYPT_ANY_SLOT)
		return -EINVAL;

	/* FIXME: find keyslot by type */
	h = LUKS2_keyslot_handler_type(cd, "reencrypt");
	if (!h)
		return -EINVAL;

	r = reenc_keyslot_alloc(cd, hdr, keyslot, params);
	if (r < 0)
		return r;

	r = LUKS2_keyslot_priority_set(cd, hdr, keyslot, CRYPT_SLOT_PRIORITY_IGNORE, 0);
	if (r < 0)
		return r;

	r = h->validate(cd, LUKS2_get_keyslot_jobj(hdr, keyslot));
	if (r) {
		log_dbg(cd, "Keyslot validation failed.");
		return r;
	}

	if (LUKS2_hdr_validate(cd, hdr->jobj, hdr->hdr_size - LUKS2_HDR_BIN_LEN))
		return -EINVAL;

	return 0;
}

int LUKS2_keyslot_reencrypt_store(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const void *buffer,
	size_t buffer_length)
{
	const keyslot_handler *h;
	int r;

	if (!(h = LUKS2_keyslot_handler(cd, keyslot)) || strcmp(h->name, "reencrypt"))
		return -EINVAL;

	r = h->validate(cd, LUKS2_get_keyslot_jobj(hdr, keyslot));
	if (r) {
		log_dbg(cd, "Keyslot validation failed.");
		return r;
	}

	return h->store(cd, keyslot, NULL, 0,
			buffer, buffer_length);
}

int LUKS2_keyslot_store(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	const char *password,
	size_t password_len,
	const struct volume_key *vk,
	const struct luks2_keyslot_params *params)
{
	const keyslot_handler *h;
	int r;

	if (keyslot == CRYPT_ANY_SLOT)
		return -EINVAL;

	if (!LUKS2_get_keyslot_jobj(hdr, keyslot)) {
		/* Try to allocate default and empty keyslot type */
		h = LUKS2_keyslot_handler_type(cd, "luks2");
		if (!h)
			return -EINVAL;

		r = h->alloc(cd, keyslot, vk->keylength, params);
		if (r)
			return r;
	} else {
		if (!(h = LUKS2_keyslot_handler(cd, keyslot)))
			return -EINVAL;

		r = h->update(cd, keyslot, params);
		if (r) {
			log_dbg(cd, "Failed to update keyslot %d json.", keyslot);
			return r;
		}
	}

	r = h->validate(cd, LUKS2_get_keyslot_jobj(hdr, keyslot));
	if (r) {
		log_dbg(cd, "Keyslot validation failed.");
		return r;
	}

	if (LUKS2_hdr_validate(cd, hdr->jobj, hdr->hdr_size - LUKS2_HDR_BIN_LEN))
		return -EINVAL;

	return h->store(cd, keyslot, password, password_len,
			vk->key, vk->keylength);
}

int LUKS2_keyslot_wipe(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	int wipe_area_only)
{
	struct device *device = crypt_metadata_device(cd);
	uint64_t area_offset, area_length;
	int r;
	json_object *jobj_keyslot, *jobj_keyslots;
	const keyslot_handler *h;

	h = LUKS2_keyslot_handler(cd, keyslot);

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -ENOENT;

	if (wipe_area_only)
		log_dbg(cd, "Wiping keyslot %d area only.", keyslot);

	/* Just check that nobody uses the metadata now */
	r = device_write_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s."),
			device_path(device));
		return r;
	}
	device_write_unlock(cd, device);

	/* secure deletion of possible key material in keyslot area */
	r = crypt_keyslot_area(cd, keyslot, &area_offset, &area_length);
	if (r && r != -ENOENT)
		return r;

	/* We can destroy the binary keyslot area now without lock */
	if (!r) {
		r = crypt_wipe_device(cd, device, CRYPT_WIPE_SPECIAL, area_offset,
			      area_length, area_length, NULL, NULL);
		if (r) {
			if (r == -EACCES) {
				log_err(cd, _("Cannot write to device %s, permission denied."),
					device_path(device));
				r = -EINVAL;
			} else
				log_err(cd, _("Cannot wipe device %s."), device_path(device));
			return r;
		}
	}

	if (wipe_area_only)
		return r;

	/* Slot specific wipe */
	if (h) {
		r = h->wipe(cd, keyslot);
		if (r < 0)
			return r;
	} else
		log_dbg(cd, "Wiping keyslot %d without specific-slot handler loaded.", keyslot);

	json_object_object_del_by_uint(jobj_keyslots, keyslot);

	return LUKS2_hdr_write(cd, hdr);
}

int LUKS2_keyslot_dump(struct crypt_device *cd, int keyslot)
{
	const keyslot_handler *h;

	if (!(h = LUKS2_keyslot_handler(cd, keyslot)))
		return -EINVAL;

	return h->dump(cd, keyslot);
}

crypt_keyslot_priority LUKS2_keyslot_priority_get(struct crypt_device *cd,
	  struct luks2_hdr *hdr, int keyslot)
{
	json_object *jobj_keyslot, *jobj_priority;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return CRYPT_SLOT_PRIORITY_INVALID;

	if (!json_object_object_get_ex(jobj_keyslot, "priority", &jobj_priority))
		return CRYPT_SLOT_PRIORITY_NORMAL;

	return json_object_get_int(jobj_priority);
}

int LUKS2_keyslot_priority_set(struct crypt_device *cd, struct luks2_hdr *hdr,
			       int keyslot, crypt_keyslot_priority priority, int commit)
{
	json_object *jobj_keyslot;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	if (priority == CRYPT_SLOT_PRIORITY_NORMAL)
		json_object_object_del(jobj_keyslot, "priority");
	else
		json_object_object_add(jobj_keyslot, "priority", json_object_new_int(priority));

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

int placeholder_keyslot_alloc(struct crypt_device *cd,
	int keyslot,
	uint64_t area_offset,
	uint64_t area_length,
	size_t volume_key_len)
{
	struct luks2_hdr *hdr;
	json_object *jobj_keyslots, *jobj_keyslot, *jobj_area;

	log_dbg(cd, "Allocating placeholder keyslot %d for LUKS1 down conversion.", keyslot);

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	if (keyslot < 0 || keyslot >= LUKS2_KEYSLOTS_MAX)
		return -EINVAL;

	if (LUKS2_get_keyslot_jobj(hdr, keyslot))
		return -EINVAL;

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	jobj_keyslot = json_object_new_object();
	json_object_object_add(jobj_keyslot, "type", json_object_new_string("placeholder"));
	/*
	 * key_size = -1 makes placeholder keyslot impossible to pass validation.
	 * It's a safeguard against accidentally storing temporary conversion
	 * LUKS2 header.
	 */
	json_object_object_add(jobj_keyslot, "key_size", json_object_new_int(-1));

	/* Area object */
	jobj_area = json_object_new_object();
	json_object_object_add(jobj_area, "offset", json_object_new_uint64(area_offset));
	json_object_object_add(jobj_area, "size", json_object_new_uint64(area_length));
	json_object_object_add(jobj_keyslot, "area", jobj_area);

	json_object_object_add_by_uint(jobj_keyslots, keyslot, jobj_keyslot);

	return 0;
}

static unsigned LUKS2_get_keyslot_digests_count(json_object *hdr_jobj, int keyslot)
{
	char num[16];
	json_object *jobj_digests, *jobj_keyslots;
	unsigned count = 0;

	if (!json_object_object_get_ex(hdr_jobj, "digests", &jobj_digests))
		return 0;

	if (snprintf(num, sizeof(num), "%u", keyslot) < 0)
		return 0;

	json_object_object_foreach(jobj_digests, key, val) {
		UNUSED(key);
		json_object_object_get_ex(val, "keyslots", &jobj_keyslots);
		if (LUKS2_array_jobj(jobj_keyslots, num))
			count++;
	}

	return count;
}

/* run only on header that passed basic format validation */
int LUKS2_keyslots_validate(struct crypt_device *cd, json_object *hdr_jobj)
{
	const keyslot_handler *h;
	int keyslot;
	json_object *jobj_keyslots, *jobj_type;

	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	json_object_object_foreach(jobj_keyslots, slot, val) {
		keyslot = atoi(slot);
		json_object_object_get_ex(val, "type", &jobj_type);
		h = LUKS2_keyslot_handler_type(cd, json_object_get_string(jobj_type));
		if (!h)
			continue;
		if (h->validate && h->validate(cd, val)) {
			log_dbg(cd, "Keyslot type %s validation failed on keyslot %d.", h->name, keyslot);
			return -EINVAL;
		}

		if (!strcmp(h->name, "luks2") && LUKS2_get_keyslot_digests_count(hdr_jobj, keyslot) != 1) {
			log_dbg(cd, "Keyslot %d is not assigned to exactly 1 digest.", keyslot);
			return -EINVAL;
		}
	}

	return 0;
}

void LUKS2_keyslots_repair(struct crypt_device *cd, json_object *jobj_keyslots)
{
	const keyslot_handler *h;
	json_object *jobj_type;

	json_object_object_foreach(jobj_keyslots, slot, val) {
		UNUSED(slot);
		if (!json_object_is_type(val, json_type_object) ||
		    !json_object_object_get_ex(val, "type", &jobj_type) ||
		    !json_object_is_type(jobj_type, json_type_string))
			continue;

		h = LUKS2_keyslot_handler_type(cd, json_object_get_string(jobj_type));
		if (h && h->repair)
			h->repair(cd, val);
	}
}

/* assumes valid header */
int LUKS2_find_keyslot(struct luks2_hdr *hdr, const char *type)
{
	int i;
	json_object *jobj_keyslot, *jobj_type;

	if (!type)
		return -EINVAL;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++) {
		jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, i);
		if (!jobj_keyslot)
			continue;

		json_object_object_get_ex(jobj_keyslot, "type", &jobj_type);
		if (!strcmp(json_object_get_string(jobj_type), type))
			return i;
	}

	return -ENOENT;
}

int LUKS2_find_keyslot_for_segment(struct luks2_hdr *hdr, int segment, const char *type)
{
	int i;
	json_object *jobj_keyslot, *jobj_type;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++) {
		jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, i);
		if (!jobj_keyslot)
			continue;

		json_object_object_get_ex(jobj_keyslot, "type", &jobj_type);
		if (strcmp(json_object_get_string(jobj_type), type))
			continue;

		if (!LUKS2_keyslot_for_segment(hdr, i, segment))
			return i;
	}

	return -EINVAL;
}
