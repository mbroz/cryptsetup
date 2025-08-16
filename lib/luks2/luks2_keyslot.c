// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2, keyslot handling
 *
 * Copyright (C) 2015-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2025 Milan Broz
 */

#include "luks2_internal.h"
#include "keyslot_context.h"

/* Internal implementations */
extern const keyslot_handler luks2_keyslot;
extern const keyslot_handler reenc_keyslot;

static const keyslot_handler *keyslot_handlers[LUKS2_KEYSLOTS_MAX] = {
	&luks2_keyslot,
#if USE_LUKS2_REENCRYPTION
	&reenc_keyslot,
#endif
	NULL
};

static const keyslot_handler
*LUKS2_keyslot_handler_type(const char *type)
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

	return LUKS2_keyslot_handler_type(json_object_get_string(jobj2));
}

int LUKS2_keyslot_find_empty(struct crypt_device *cd, struct luks2_hdr *hdr, size_t keylength)
{
	int i;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++)
		if (!LUKS2_get_keyslot_jobj(hdr, i))
			break;

	if (i == LUKS2_KEYSLOTS_MAX)
		return -EINVAL;

	/* Check also there is a space for the key in keyslots area */
	if (keylength && LUKS2_find_area_gap(cd, hdr, keylength, NULL, NULL) < 0)
		return -ENOSPC;

	return i;
}

/* Check if a keyslot is assigned to specific segment */
static int _keyslot_for_segment(struct luks2_hdr *hdr, int keyslot, int segment)
{
	json_object *jobj_keyslots, *jobj;
	crypt_keyslot_priority slot_priority;
	unsigned s;
	int keyslot_digest, count = 0;

	/*
	 * Must not be called with both keyslot == CRYPT_ANY_SLOT
	 * and segment == CRYPT_ONE_SEGMENT. The CRYPT_DEFAULT_SEGMENT
	 * and CRYPT_ANY_SEGMENT are handled properly in upper layer.
	 */
	assert(keyslot >= 0 || segment >= 0);

	if (keyslot == CRYPT_ANY_SLOT) {
		json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots);

		json_object_object_foreach(jobj_keyslots, slot, val) {
			if (!json_object_object_get_ex(val, "priority", &jobj))
				slot_priority = CRYPT_SLOT_PRIORITY_NORMAL;
			else
				slot_priority = json_object_get_int(jobj);

			if (slot_priority < CRYPT_SLOT_PRIORITY_NORMAL)
				continue;

			keyslot_digest = LUKS2_digest_by_keyslot(hdr, atoi(slot));
			if (keyslot_digest >= 0 &&
			    keyslot_digest == LUKS2_digest_by_segment(hdr, segment))
				return 1;
		}

		return 0;
	}

	keyslot_digest = LUKS2_digest_by_keyslot(hdr, keyslot);
	if (keyslot_digest < 0)
		return keyslot_digest;

	if (segment >= 0)
		return keyslot_digest == LUKS2_digest_by_segment(hdr, segment);

	for (s = 0; s < json_segments_count(LUKS2_get_segments_jobj(hdr)); s++) {
		if (keyslot_digest == LUKS2_digest_by_segment(hdr, s))
			count++;
	}

	return count;
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

	if (!cipher_spec)
		return 1;

	/*
	 * Do not allow capi format for keyslots
	 * Note: It always failed in ivsize check later anyway.
	 */
	if (!strncmp(cipher_spec, "capi:", 5))
		return 1;

	if (crypt_is_cipher_null(cipher_spec))
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
	r = snprintf(params->af.luks1.hash, sizeof(params->af.luks1.hash), "%s", pbkdf->hash ?: DEFAULT_LUKS1_HASH);
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

	if (LUKS2_digest_by_keyslot(hdr, keyslot) < 0 ||
	    LUKS2_keyslot_unbound(hdr, keyslot))
		return CRYPT_SLOT_UNBOUND;

	if (LUKS2_keyslot_active_count(hdr, CRYPT_DEFAULT_SEGMENT) == 1 &&
	    !LUKS2_keyslot_for_segment(hdr, keyslot, CRYPT_DEFAULT_SEGMENT))
		return CRYPT_SLOT_ACTIVE_LAST;

	return CRYPT_SLOT_ACTIVE;
}

int LUKS2_keyslot_jobj_area(json_object *jobj_keyslot, uint64_t *offset, uint64_t *length)
{
	json_object *jobj_area, *jobj;

	if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_area, "offset", &jobj))
		return -EINVAL;
	*offset = crypt_jobj_get_uint64(jobj);

	if (!json_object_object_get_ex(jobj_area, "size", &jobj))
		return -EINVAL;
	*length = crypt_jobj_get_uint64(jobj);

	return 0;
}

int LUKS2_keyslot_area(struct luks2_hdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length)
{
	json_object *jobj_keyslot;

	if (LUKS2_keyslot_info(hdr, keyslot) == CRYPT_SLOT_INVALID)
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -ENOENT;

	return LUKS2_keyslot_jobj_area(jobj_keyslot, offset, length);
}

static int _open_and_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const keyslot_handler *h,
	int keyslot,
	const char *password,
	size_t password_len,
	struct volume_key **r_vk)
{
	int r, key_size = LUKS2_get_keyslot_stored_key_size(hdr, keyslot);
	struct volume_key *vk = NULL;
	void *key = NULL;

	if (key_size < 0)
		return -EINVAL;

	key = crypt_safe_alloc(key_size);
	if (!key)
		return -ENOMEM;

	r = h->open(cd, keyslot, password, password_len, key, key_size);
	if (r < 0) {
		log_dbg(cd, "Keyslot %d (%s) open failed with %d.", keyslot, h->name, r);
		goto err;
	}

	vk = crypt_alloc_volume_key_by_safe_alloc(&key);
	if (!vk) {
		r = -ENOMEM;
		goto err;
	}

	r = LUKS2_digest_verify(cd, hdr, vk, keyslot);
	if (r < 0)
		goto err;

	crypt_volume_key_set_id(vk, r);
	*r_vk = vk;
	return keyslot;
err:
	crypt_safe_free(key);
	crypt_free_volume_key(vk);

	return r;
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
	int r;

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

	return _open_and_verify(cd, hdr, h, keyslot, password, password_len, vk);
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
	int keyslot, r = -ENOENT, r_old;

	json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots);

	json_object_object_foreach(jobj_keyslots, slot, val) {
		r_old = r;

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
		/* If a previous keyslot failed with EPERM (bad password) prefer it */
		if (r_old == -EPERM && r == -ENOENT)
			r = -EPERM;
	}

	return r;
}

static int keyslot_context_open_all_segments(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	struct crypt_keyslot_context *kc_old,
	struct crypt_keyslot_context *kc_new,
	struct volume_key **r_vks)
{
	int segment_old, segment_new, digest_old = -1, digest_new = -1, r = -ENOENT;
	struct luks2_hdr *hdr;
	struct volume_key *vk = NULL;

	assert(cd);
	assert(!kc_old || kc_old->get_luks2_key);
	assert(!kc_new || kc_new->get_luks2_key);
	assert(r_vks);

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	segment_old = LUKS2_reencrypt_segment_old(hdr);
	segment_new = LUKS2_reencrypt_segment_new(hdr);

	if (segment_old < 0 || segment_new < 0)
		return -EINVAL;

	digest_old = LUKS2_digest_by_segment(hdr, segment_old);
	digest_new = LUKS2_digest_by_segment(hdr, segment_new);

	if (digest_old >= 0 && digest_new >= 0 && digest_old != digest_new && (!kc_old || !kc_new))
		return -ESRCH;

	if (digest_old >= 0 && kc_old) {
		log_dbg(cd, "Checking current volume key (digest %d, segment: %d) using keyslot %d.",
			    digest_old, segment_old, keyslot_old);

		/* key and key in keyring types do not have association with any keyslot */
		if (kc_old->type != CRYPT_KC_TYPE_KEY && kc_old->type != CRYPT_KC_TYPE_VK_KEYRING) {
			r = LUKS2_keyslot_for_segment(hdr, keyslot_old, segment_old);
			if (r < 0)
				goto out;
		}

		r = kc_old->get_luks2_key(cd, kc_old, keyslot_old, segment_old, &vk);
		if (r < 0)
			goto out;
		crypt_volume_key_add_next(r_vks, vk);
		if (crypt_volume_key_get_id(vk) < 0 && LUKS2_digest_verify_by_digest(cd, digest_old, vk) == digest_old)
			crypt_volume_key_set_id(vk, digest_old);
		if (crypt_volume_key_get_id(vk) != digest_old) {
			r = -EPERM;
			goto out;
		}
	}

	if (digest_new >= 0 && digest_old != digest_new && kc_new) {
		log_dbg(cd, "Checking new volume key (digest %d, segment: %d) using keyslot %d.",
			    digest_new, segment_new, keyslot_new);

		/* key and key in keyring types do not have association with any keyslot */
		if (kc_new->type != CRYPT_KC_TYPE_KEY && kc_new->type != CRYPT_KC_TYPE_VK_KEYRING) {
			r = LUKS2_keyslot_for_segment(hdr, keyslot_new, segment_new);
			if (r < 0)
				goto out;
		}

		r = kc_new->get_luks2_key(cd, kc_new, keyslot_new, segment_new, &vk);
		if (r < 0)
			goto out;
		crypt_volume_key_add_next(r_vks, vk);
		if (crypt_volume_key_get_id(vk) < 0 && LUKS2_digest_verify_by_digest(cd, digest_new, vk) == digest_new)
			crypt_volume_key_set_id(vk, digest_new);
		if (crypt_volume_key_get_id(vk) != digest_new)
			r = -EPERM;
	}
out:
	if (r < 0) {
		crypt_free_volume_key(*r_vks);
		*r_vks = NULL;

		if (r == -ENOMEM)
			log_err(cd, _("Not enough available memory to open a keyslot."));
		else if (r != -EPERM && r != -ENOENT)
			log_err(cd, _("Keyslot open failed."));
	}
	return r;
}

int LUKS2_keyslot_context_open_all_segments(struct crypt_device *cd,
	int keyslot1,
	int keyslot2,
	struct crypt_keyslot_context *kc1,
	struct crypt_keyslot_context *kc2,
	struct volume_key **r_vks)
{
	int r, r2;

	r = keyslot_context_open_all_segments(cd, keyslot1, keyslot2, kc1, kc2, r_vks);
	if (r == -EPERM || r == -ENOENT) {
		r2 = keyslot_context_open_all_segments(cd, keyslot2, keyslot1, kc2, kc1, r_vks);
		if (r2 != -ENOENT)
			r = r2;
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
	if (!hdr)
		return -EINVAL;

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

	if (r < 0) {
		if (r == -ENOMEM)
			log_err(cd, _("Not enough available memory to open a keyslot."));
		else if (r != -EPERM && r != -ENOENT)
			log_err(cd, _("Keyslot open failed."));
	}

	return r;
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
		h = LUKS2_keyslot_handler_type("luks2");
		if (!h)
			return -EINVAL;

		r = h->alloc(cd, keyslot, crypt_volume_key_length(vk), params);
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
			crypt_volume_key_get_key(vk), crypt_volume_key_length(vk));
}

int LUKS2_keyslot_wipe(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot)
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

	r = LUKS2_device_write_lock(cd, hdr, device);
	if (r)
		return r;

	/* secure deletion of possible key material in keyslot area */
	r = crypt_keyslot_area(cd, keyslot, &area_offset, &area_length);
	if (r && r != -ENOENT)
		goto out;

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
			goto out;
		}
	}

	/* Slot specific wipe */
	if (h) {
		r = h->wipe(cd, keyslot);
		if (r < 0)
			goto out;
	} else
		log_dbg(cd, "Wiping keyslot %d without specific-slot handler loaded.", keyslot);

	json_object_object_del_by_uint(jobj_keyslots, keyslot);

	r = LUKS2_hdr_write(cd, hdr);
out:
	device_write_unlock(cd, crypt_metadata_device(cd));
	return r;
}

int LUKS2_keyslot_dump(struct crypt_device *cd, int keyslot)
{
	const keyslot_handler *h;

	if (!(h = LUKS2_keyslot_handler(cd, keyslot)))
		return -EINVAL;

	return h->dump(cd, keyslot);
}

crypt_keyslot_priority LUKS2_keyslot_priority_get(struct luks2_hdr *hdr, int keyslot)
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
	uint64_t area_length)
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
	if (!jobj_keyslot)
		return -ENOMEM;

	json_object_object_add(jobj_keyslot, "type", json_object_new_string("placeholder"));
	/*
	 * key_size = -1 makes placeholder keyslot impossible to pass validation.
	 * It's a safeguard against accidentally storing temporary conversion
	 * LUKS2 header.
	 */
	json_object_object_add(jobj_keyslot, "key_size", json_object_new_int(-1));

	/* Area object */
	jobj_area = json_object_new_object();
	if (!jobj_area) {
		json_object_put(jobj_keyslot);
		return -ENOMEM;
	}

	json_object_object_add(jobj_area, "offset", crypt_jobj_new_uint64(area_offset));
	json_object_object_add(jobj_area, "size", crypt_jobj_new_uint64(area_length));
	json_object_object_add(jobj_keyslot, "area", jobj_area);

	if (json_object_object_add_by_uint(jobj_keyslots, keyslot, jobj_keyslot)) {
		json_object_put(jobj_keyslot);
		return -EINVAL;
	}

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
	uint32_t reqs, reencrypt_count = 0;
	struct luks2_hdr dummy = {
		.jobj = hdr_jobj
	};

	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	LUKS2_config_get_requirements(cd, &dummy, &reqs);

	json_object_object_foreach(jobj_keyslots, slot, val) {
		keyslot = atoi(slot);
		json_object_object_get_ex(val, "type", &jobj_type);
		h = LUKS2_keyslot_handler_type(json_object_get_string(jobj_type));
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

		if (!strcmp(h->name, "reencrypt"))
			reencrypt_count++;
	}

	if ((reqs & CRYPT_REQUIREMENT_ONLINE_REENCRYPT) && reencrypt_count == 0) {
		log_dbg(cd, "Missing reencryption keyslot.");
		return -EINVAL;
	}

	if (reencrypt_count && !LUKS2_reencrypt_requirement_candidate(&dummy)) {
		log_dbg(cd, "Missing reencryption requirement flag.");
		return -EINVAL;
	}

	if (reencrypt_count > 1) {
		log_dbg(cd, "Too many reencryption keyslots.");
		return -EINVAL;
	}

	return 0;
}

void LUKS2_keyslots_repair(struct crypt_device *cd __attribute__((unused)), json_object *jobj_keyslots)
{
	const keyslot_handler *h;
	json_object *jobj_type;

	json_object_object_foreach(jobj_keyslots, slot, val) {
		UNUSED(slot);
		if (!json_object_is_type(val, json_type_object) ||
		    !json_object_object_get_ex(val, "type", &jobj_type) ||
		    !json_object_is_type(jobj_type, json_type_string))
			continue;

		h = LUKS2_keyslot_handler_type(json_object_get_string(jobj_type));
		if (h && h->repair)
			h->repair(val);
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

/* assumes valid header, it does not move references in tokens/digests etc! */
int LUKS2_keyslot_swap(struct crypt_device *cd, struct luks2_hdr *hdr,
	int keyslot, int keyslot2)
{
	json_object *jobj_keyslots, *jobj_keyslot, *jobj_keyslot2;
	int r;

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	jobj_keyslot2 = LUKS2_get_keyslot_jobj(hdr, keyslot2);
	if (!jobj_keyslot2)
		return -EINVAL;

	/* This transfer owner of object, no need for json_object_put */
	json_object_get(jobj_keyslot);
	json_object_get(jobj_keyslot2);

	json_object_object_del_by_uint(jobj_keyslots, keyslot);
	r = json_object_object_add_by_uint(jobj_keyslots, keyslot, jobj_keyslot2);
	if (r < 0) {
		json_object_put(jobj_keyslot2);
		log_dbg(cd, "Failed to swap keyslot %d.", keyslot);
		return r;
	}

	json_object_object_del_by_uint(jobj_keyslots, keyslot2);
	r = json_object_object_add_by_uint(jobj_keyslots, keyslot2, jobj_keyslot);
	if (r < 0) {
		json_object_put(jobj_keyslot);
		log_dbg(cd, "Failed to swap keyslot2 %d.", keyslot2);
	}

	return r;
}
