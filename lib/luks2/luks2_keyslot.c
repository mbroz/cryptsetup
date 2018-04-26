/*
 * LUKS - Linux Unified Key Setup v2, keyslot handling
 *
 * Copyright (C) 2015-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2018, Milan Broz. All rights reserved.
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

static const keyslot_handler *keyslot_handlers[LUKS2_KEYSLOTS_MAX] = {
	&luks2_keyslot,
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

int LUKS2_keyslot_find_empty(struct luks2_hdr *hdr, const char *type)
{
	int i;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++)
		if (!LUKS2_get_keyslot_jobj(hdr, i))
			return i;

	return -EINVAL;
}

/* Check if a keyslot is asssigned to specific segment */
int LUKS2_keyslot_for_segment(struct luks2_hdr *hdr, int keyslot, int segment)
{
	int keyslot_digest, segment_digest;

	/* no need to check anything */
	if (segment == CRYPT_ANY_SEGMENT)
		return 0;

	keyslot_digest = LUKS2_digest_by_keyslot(NULL, hdr, keyslot);
	if (keyslot_digest < 0)
		return -EINVAL;

	segment_digest = LUKS2_digest_by_segment(NULL, hdr, segment);
	if (segment_digest < 0)
		return -EINVAL;

	return segment_digest == keyslot_digest ? 0 : -ENOENT;
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

int LUKS2_keyslot_cipher_incompatible(struct crypt_device *cd)
{
	const char *cipher = crypt_get_cipher(cd);

	/* Keyslot is already authenticated; we cannot use integrity tags here */
	if (crypt_get_integrity_tag_size(cd) || !cipher)
		return 1;

	/* Wrapped key schemes cannot be used for keyslot encryption */
	if (crypt_cipher_wrapped_key(cipher))
		return 1;

	return 0;
}

int LUKS2_keyslot_params_default(struct crypt_device *cd, struct luks2_hdr *hdr,
	size_t key_size, struct luks2_keyslot_params *params)
{
	int r, integrity_key_size = crypt_get_integrity_key_size(cd);
	const struct crypt_pbkdf_type *pbkdf = crypt_get_pbkdf_type(cd);

	if (!hdr || !pbkdf || !params)
		return -EINVAL;

	params->af_type   = LUKS2_KEYSLOT_AF_LUKS1;
	params->area_type = LUKS2_KEYSLOT_AREA_RAW;

	/* set keyslot AF parameters */
	/* currently we use hash for AF from pbkdf settings */
	r = snprintf(params->af.luks1.hash, sizeof(params->af.luks1.hash),
		     "%s", pbkdf->hash);
	if (r < 0 || (size_t)r >= sizeof(params->af.luks1.hash))
		return -EINVAL;

	params->af.luks1.stripes = 4000;

	/* set keyslot area encryption parameters */
	/* short circuit authenticated encryption hardcoded defaults */
	if (LUKS2_keyslot_cipher_incompatible(cd) || key_size == 0) {
		// FIXME: fixed cipher and key size can be wrong
		snprintf(params->area.raw.encryption, sizeof(params->area.raw.encryption),
			 "aes-xts-plain64");
		params->area.raw.key_size = 32;
		return 0;
	}

	r = snprintf(params->area.raw.encryption, sizeof(params->area.raw.encryption),
		     "%s", LUKS2_get_cipher(hdr, CRYPT_DEFAULT_SEGMENT));
	if (r < 0 || (size_t)r >= sizeof(params->area.raw.encryption))
		return -EINVAL;

	/* Slot encryption tries to use the same key size as for the main algorithm */
	if ((size_t)integrity_key_size > key_size)
		return -EINVAL;
	params->area.raw.key_size = key_size - integrity_key_size;

	return 0;
}

static int LUKS2_keyslot_unbound(struct luks2_hdr *hdr, int keyslot)
{
	json_object *jobj_digest, *jobj_segments;
	int digest = LUKS2_digest_by_keyslot(NULL, hdr, keyslot);

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
	*offset = json_object_get_int64(jobj);

	if (!json_object_object_get_ex(jobj_area, "size", &jobj))
		return -EINVAL;
	*length = json_object_get_int64(jobj);

	return 0;
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
		log_dbg("Keyslot %d validation failed.", keyslot);
		return r;
	}

	r = LUKS2_keyslot_for_segment(hdr, keyslot, segment);
	if (r) {
		if (r == -ENOENT)
			log_dbg("Keyslot %d unusable for segment %d.", keyslot, segment);
		return r;
	}

	key_size = LUKS2_get_volume_key_size(hdr, segment);
	if (key_size < 0)
		key_size = LUKS2_get_keyslot_key_size(hdr, keyslot);
	if (key_size < 0)
		return -EINVAL;

	*vk = crypt_alloc_volume_key(key_size, NULL);
	if (!*vk)
		return -ENOMEM;

	r = h->open(cd, keyslot, password, password_len, (*vk)->key, (*vk)->keylength);
	if (r < 0)
		log_dbg("Keyslot %d (%s) open failed with %d.", keyslot, h->name, r);
	else
		r = LUKS2_digest_verify(cd, hdr, *vk, keyslot);

	if (r < 0) {
		crypt_free_volume_key(*vk);
		*vk = NULL;
	}

	return r < 0 ? r : keyslot;
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
			log_dbg("Keyslot %d priority %d != %d (required), skipped.",
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
			log_dbg("Failed to update keyslot %d json.", keyslot);
			return r;
		}
	}

	r = h->validate(cd, LUKS2_get_keyslot_jobj(hdr, keyslot));
	if (r) {
		log_dbg("Keyslot validation failed.");
		return r;
	}

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
	char num[16];
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
		log_dbg("Wiping keyslot %d area only.", keyslot);

	/* Just check that nobody uses the metadata now */
	r = device_write_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s."),
			device_path(device));
		return r;
	}
	device_write_unlock(device);

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
		log_dbg("Wiping keyslot %d without specific-slot handler loaded.", keyslot);

	snprintf(num, sizeof(num), "%d", keyslot);
	json_object_object_del(jobj_keyslots, num);

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
	char num[16];
	json_object *jobj_keyslots, *jobj_keyslot, *jobj_area;

	log_dbg("Allocating placeholder keyslot %d for LUKS1 down conversion.", keyslot);

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
	 * It's a safeguard against accidentaly storing temporary conversion
	 * LUKS2 header.
	 */
	json_object_object_add(jobj_keyslot, "key_size", json_object_new_int(-1));

	/* Area object */
	jobj_area = json_object_new_object();
	json_object_object_add(jobj_area, "offset", json_object_new_uint64(area_offset));
	json_object_object_add(jobj_area, "size", json_object_new_uint64(area_length));
	json_object_object_add(jobj_keyslot, "area", jobj_area);

	snprintf(num, sizeof(num), "%d", keyslot);

	json_object_object_add(jobj_keyslots, num, jobj_keyslot);

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
int LUKS2_keyslots_validate(json_object *hdr_jobj)
{
	const keyslot_handler *h;
	int keyslot;
	json_object *jobj_keyslots, *jobj_type;

	if (!json_object_object_get_ex(hdr_jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	json_object_object_foreach(jobj_keyslots, slot, val) {
		keyslot = atoi(slot);
		json_object_object_get_ex(val, "type", &jobj_type);
		h = LUKS2_keyslot_handler_type(NULL, json_object_get_string(jobj_type));
		if (!h)
			continue;
		if (h->validate && h->validate(NULL, val)) {
			log_dbg("Keyslot type %s validation failed on keyslot %d.", h->name, keyslot);
			return -EINVAL;
		}

		if (!strcmp(h->name, "luks2") && LUKS2_get_keyslot_digests_count(hdr_jobj, keyslot) != 1) {
			log_dbg("Keyslot %d is not assigned to exactly 1 digest.", keyslot);
			return -EINVAL;
		}
	}

	return 0;
}

void LUKS2_keyslots_repair(json_object *jobj_keyslots)
{
	const keyslot_handler *h;
	json_object *jobj_type;

	json_object_object_foreach(jobj_keyslots, slot, val) {
		UNUSED(slot);
		if (!json_object_is_type(val, json_type_object) ||
		    !json_object_object_get_ex(val, "type", &jobj_type) ||
		    !json_object_is_type(jobj_type, json_type_string))
			continue;

		h = LUKS2_keyslot_handler_type(NULL, json_object_get_string(jobj_type));
		if (h && h->repair)
			h->repair(NULL, val);
	}
}
