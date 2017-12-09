/*
 * LUKS - Linux Unified Key Setup v2, digest handling
 *
 * Copyright (C) 2015-2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2017, Milan Broz. All rights reserved.
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

extern const digest_handler PBKDF2_digest;

static const digest_handler *digest_handlers[LUKS2_DIGEST_MAX] = {
	&PBKDF2_digest,
	NULL
};

int crypt_digest_register(const digest_handler *handler)
{
	int i;

	for (i = 0; i < LUKS2_DIGEST_MAX && digest_handlers[i]; i++) {
		if (!strcmp(digest_handlers[i]->name, handler->name))
			return -EINVAL;
	}

	if (i == LUKS2_DIGEST_MAX)
		return -EINVAL;

	digest_handlers[i] = handler;
	return 0;
}

const digest_handler *LUKS2_digest_handler_type(struct crypt_device *cd, const char *type)
{
	int i;

	for (i = 0; i < LUKS2_DIGEST_MAX && digest_handlers[i]; i++) {
		if (!strcmp(digest_handlers[i]->name, type))
			return digest_handlers[i];
	}

	return NULL;
}

static const digest_handler *LUKS2_digest_handler(struct crypt_device *cd, int digest)
{
	struct luks2_hdr *hdr;
	json_object *jobj1, *jobj2;

	if (digest < 0)
		return NULL;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return NULL;

	if (!(jobj1 = LUKS2_get_digest_jobj(hdr, digest)))
		return NULL;

	if (!json_object_object_get_ex(jobj1, "type", &jobj2))
		return NULL;

	return LUKS2_digest_handler_type(cd, json_object_get_string(jobj2));
}

static int LUKS2_digest_find_free(struct crypt_device *cd, struct luks2_hdr *hdr)
{
	int digest = 0;

	while (LUKS2_get_digest_jobj(hdr, digest) && digest < LUKS2_DIGEST_MAX)
		digest++;

	return digest < LUKS2_DIGEST_MAX ? digest : -1;
}

int LUKS2_digest_create(struct crypt_device *cd,
	const char *type,
	struct luks2_hdr *hdr,
	const struct volume_key *vk)
{
	int digest;
	const digest_handler *dh;

	dh = LUKS2_digest_handler_type(cd, type);
	if (!dh)
		return -EINVAL;

	digest = LUKS2_digest_find_free(cd, hdr);
	if (digest < 0)
		return -EINVAL;

	log_dbg("Creating new digest %d (%s).", digest, type);

	return dh->store(cd, digest, vk->key, vk->keylength) ?: digest;
}

int LUKS2_digests_by_keyslot(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot,
	digests_t digests)
{
	char keyslot_name[16];
	int i = 0;
	json_object *jobj_digests, *jobj_digest_keyslots;

	if (snprintf(keyslot_name, sizeof(keyslot_name), "%u", keyslot) < 1)
		return -ENOMEM;

	json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

	json_object_object_foreach(jobj_digests, key, val) {
		json_object_object_get_ex(val, "keyslots", &jobj_digest_keyslots);
		if (LUKS2_array_jobj(jobj_digest_keyslots, keyslot_name))
			digests[i++] = atoi(key);
	}

	if (i < LUKS2_DIGEST_MAX)
		digests[i] = -1;

	return i ? 0 : -ENOENT;
}

int LUKS2_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct volume_key *vk,
	int keyslot)
{
	const digest_handler *h;
	digests_t digests;
	int i, r;

	r = LUKS2_digests_by_keyslot(cd, hdr, keyslot, digests);
	if (r == -ENOENT)
		return 0;
	if (r < 0)
		return r;

	for (i = 0; i < LUKS2_DIGEST_MAX && digests[i] != -1 ; i++) {
		log_dbg("Verifying key from keyslot %d, digest %d.",
			keyslot, digests[i]);
		h = LUKS2_digest_handler(cd, digests[i]);
		if (!h)
			return -EINVAL;

		r = h->verify(cd, digests[i], vk->key, vk->keylength);
		if (r < 0) {
			log_dbg("Digest %d (%s) verify failed with %d.",
				digests[i], h->name, r);
			return r;
		}
	}

	return 0;
}

int LUKS2_digest_dump(struct crypt_device *cd, int digest)
{
	const digest_handler *h;

	if (!(h = LUKS2_digest_handler(cd, digest)))
		return -EINVAL;

	return h->dump(cd, digest);
}

int LUKS2_digests_verify_by_segment(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment,
	const struct volume_key *vk,
	digests_t digests)
{
	const digest_handler *h;
	digests_t tmp;
	int *digest, r, i = 0;

	digest = digests ? digests : tmp;

	r = LUKS2_digests_by_segment(cd, hdr, segment, digest);
	if (r)
		return r;

	while (i < LUKS2_DIGEST_MAX && digest[i] != -1) {
		log_dbg("Verifying key digest %d.", digest[i]);

		h = LUKS2_digest_handler(cd, digest[i]);
		if (!h)
			return -EINVAL;

		r = h->verify(cd, digest[i], vk->key, vk->keylength);
		if (r < 0) {
			log_dbg("Digest %d (%s) verify failed with %d.", digest[i], h->name, r);
			return r;
		}

		i++;
	}

	return 0;
}

int LUKS2_digests_by_segment(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment,
	digests_t digests)
{
	char segment_name[16];
	json_object *jobj_digests, *jobj_digest_segments;
	int i = 0;

	json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

	if (snprintf(segment_name, sizeof(segment_name), "%u", segment) < 1)
		return -EINVAL;

	json_object_object_foreach(jobj_digests, key, val) {
		json_object_object_get_ex(val, "segments", &jobj_digest_segments);
		if (!LUKS2_array_jobj(jobj_digest_segments, segment_name))
			continue;

		digests[i++] = atoi(key);
	}

	if (i < LUKS2_DIGEST_MAX)
		digests[i] = -1;

	return i ? 0 : -ENOENT;
}

static int assign_one_digest(struct crypt_device *cd, struct luks2_hdr *hdr,
			     int keyslot, int digest, int assign)
{
	json_object *jobj1, *jobj_digest, *jobj_digest_keyslots;
	char num[16];

	log_dbg("Keyslot %i %s digest %i.", keyslot, assign ? "assigned to" : "unassigned from", digest);

	jobj_digest = LUKS2_get_digest_jobj(hdr, digest);
	if (!jobj_digest)
		return -EINVAL;

	json_object_object_get_ex(jobj_digest, "keyslots", &jobj_digest_keyslots);
	if (!jobj_digest_keyslots)
		return -EINVAL;

	snprintf(num, sizeof(num), "%d", keyslot);
	if (assign) {
		jobj1 = LUKS2_array_jobj(jobj_digest_keyslots, num);
		if (!jobj1)
			json_object_array_add(jobj_digest_keyslots, json_object_new_string(num));
	} else {
		jobj1 = LUKS2_array_remove(jobj_digest_keyslots, num);
		if (jobj1)
			json_object_object_add(jobj_digest, "keyslots", jobj1);
	}

	return 0;
}

int LUKS2_digests_assign(struct crypt_device *cd, struct luks2_hdr *hdr,
			int keyslot, digests_t digests, int assign, int commit)
{
	int i, r;

	for (i = 0; i < LUKS2_DIGEST_MAX && digests[i] != -1; i++) {
		r = LUKS2_digest_assign(cd, hdr, keyslot, digests[i], assign, 0);
		if (r < 0)
			return r;
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

int LUKS2_digest_assign(struct crypt_device *cd, struct luks2_hdr *hdr,
			int keyslot, int digest, int assign, int commit)
{
	json_object *jobj_digests;
	int r = 0;

	if (digest == CRYPT_ANY_DIGEST) {
		json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

		json_object_object_foreach(jobj_digests, key, val) {
			UNUSED(val);
			r = assign_one_digest(cd, hdr, keyslot, atoi(key), assign);
			if (r < 0)
				break;
		}
	} else
		r = assign_one_digest(cd, hdr, keyslot, digest, assign);

	if (r < 0)
		return r;

	// FIXME: do not write header in nothing changed
	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

static int assign_one_segment(struct crypt_device *cd, struct luks2_hdr *hdr,
			     int segment, int digest, int assign)
{
	json_object *jobj1, *jobj_digest, *jobj_digest_segments;
	char num[16];

	log_dbg("Segment %i %s digest %i.", segment, assign ? "assigned to" : "unassigned from", digest);

	jobj_digest = LUKS2_get_digest_jobj(hdr, digest);
	if (!jobj_digest)
		return -EINVAL;

	json_object_object_get_ex(jobj_digest, "segments", &jobj_digest_segments);
	if (!jobj_digest_segments)
		return -EINVAL;

	snprintf(num, sizeof(num), "%d", segment);
	if (assign) {
		jobj1 = LUKS2_array_jobj(jobj_digest_segments, num);
		if (!jobj1)
			json_object_array_add(jobj_digest_segments, json_object_new_string(num));
	} else {
		jobj1 = LUKS2_array_remove(jobj_digest_segments, num);
		if (jobj1)
			json_object_object_add(jobj_digest, "segments", jobj1);
	}

	return 0;
}

int LUKS2_digest_segment_assign(struct crypt_device *cd, struct luks2_hdr *hdr,
			int segment, int digest, int assign, int commit)
{
	json_object *jobj_digests;
	int r = 0;

	if (digest == CRYPT_ANY_DIGEST) {
		json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

		json_object_object_foreach(jobj_digests, key, val) {
			UNUSED(val);
			r = assign_one_segment(cd, hdr, segment, atoi(key), assign);
			if (r < 0)
				break;
		}
	} else
		r = assign_one_segment(cd, hdr, segment, digest, assign);

	if (r < 0)
		return r;

	// FIXME: do not write header in nothing changed
	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

static int digest_unused(json_object *jobj_digest)
{
	json_object *jobj;

	json_object_object_get_ex(jobj_digest, "segments", &jobj);
	if (!jobj || !json_object_is_type(jobj, json_type_array) || json_object_array_length(jobj))
		return 0;

	json_object_object_get_ex(jobj_digest, "keyslots", &jobj);
	if (!jobj || !json_object_is_type(jobj, json_type_array))
		return 0;

	return json_object_array_length(jobj) ? 0 : 1;
}

void LUKS2_digests_erase_unused(struct crypt_device *cd,
	struct luks2_hdr *hdr)
{
	json_object *jobj_digests;

	json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);
	if (!jobj_digests || !json_object_is_type(jobj_digests, json_type_object))
		return;

	json_object_object_foreach(jobj_digests, key, val) {
		if (digest_unused(val)) {
			log_dbg("Erasing unused digest %d.", atoi(key));
			json_object_object_del(jobj_digests, key);
		}
	}
}
