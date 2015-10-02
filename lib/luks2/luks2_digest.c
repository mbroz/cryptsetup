/*
 * LUKS - Linux Unified Key Setup v2, digest handling
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

extern const digest_handler PBKDF2_digest;

static const digest_handler *digest_handlers[LUKS2_DIGEST_MAX] = {
	&PBKDF2_digest,
	NULL
};

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

	log_dbg(cd, "Creating new digest %d (%s).", digest, type);

	return dh->store(cd, digest, vk->key, vk->keylength) ?: digest;
}

int LUKS2_digest_by_keyslot(struct luks2_hdr *hdr, int keyslot)
{
	char keyslot_name[16];
	json_object *jobj_digests, *jobj_digest_keyslots;

	if (snprintf(keyslot_name, sizeof(keyslot_name), "%u", keyslot) < 1)
		return -ENOMEM;

	json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

	json_object_object_foreach(jobj_digests, key, val) {
		json_object_object_get_ex(val, "keyslots", &jobj_digest_keyslots);
		if (LUKS2_array_jobj(jobj_digest_keyslots, keyslot_name))
			return atoi(key);
	}

	return -ENOENT;
}

int LUKS2_digest_verify_by_digest(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int digest,
	const struct volume_key *vk)
{
	const digest_handler *h;
	int r;

	h = LUKS2_digest_handler(cd, digest);
	if (!h)
		return -EINVAL;

	r = h->verify(cd, digest, vk->key, vk->keylength);
	if (r < 0) {
		log_dbg(cd, "Digest %d (%s) verify failed with %d.", digest, h->name, r);
		return r;
	}

	return digest;
}

int LUKS2_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	int keyslot)
{
	int digest;

	digest = LUKS2_digest_by_keyslot(hdr, keyslot);
	if (digest < 0)
		return digest;

	log_dbg(cd, "Verifying key from keyslot %d, digest %d.", keyslot, digest);

	return LUKS2_digest_verify_by_digest(cd, hdr, digest, vk);
}

int LUKS2_digest_dump(struct crypt_device *cd, int digest)
{
	const digest_handler *h;

	if (!(h = LUKS2_digest_handler(cd, digest)))
		return -EINVAL;

	return h->dump(cd, digest);
}

int LUKS2_digest_any_matching(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct volume_key *vk)
{
	int digest;

	for (digest = 0; digest < LUKS2_DIGEST_MAX; digest++)
		if (LUKS2_digest_verify_by_digest(cd, hdr, digest, vk) == digest)
			return digest;

	return -ENOENT;
}

int LUKS2_digest_verify_by_segment(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment,
	const struct volume_key *vk)
{
	return LUKS2_digest_verify_by_digest(cd, hdr, LUKS2_digest_by_segment(hdr, segment), vk);
}

/* FIXME: segment can have more digests */
int LUKS2_digest_by_segment(struct luks2_hdr *hdr, int segment)
{
	char segment_name[16];
	json_object *jobj_digests, *jobj_digest_segments;

	if (segment == CRYPT_DEFAULT_SEGMENT)
		segment = LUKS2_get_default_segment(hdr);

	json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

	if (snprintf(segment_name, sizeof(segment_name), "%u", segment) < 1)
		return -EINVAL;

	json_object_object_foreach(jobj_digests, key, val) {
		json_object_object_get_ex(val, "segments", &jobj_digest_segments);
		if (!LUKS2_array_jobj(jobj_digest_segments, segment_name))
			continue;

		return atoi(key);
	}

	return -ENOENT;
}

static int assign_one_digest(struct crypt_device *cd, struct luks2_hdr *hdr,
			     int keyslot, int digest, int assign)
{
	json_object *jobj1, *jobj_digest, *jobj_digest_keyslots;
	char num[16];

	log_dbg(cd, "Keyslot %i %s digest %i.", keyslot, assign ? "assigned to" : "unassigned from", digest);

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

static int assign_all_segments(struct crypt_device *cd, struct luks2_hdr *hdr,
			     int digest, int assign)
{
	json_object *jobj1, *jobj_digest, *jobj_digest_segments;

	jobj_digest = LUKS2_get_digest_jobj(hdr, digest);
	if (!jobj_digest)
		return -EINVAL;

	json_object_object_get_ex(jobj_digest, "segments", &jobj_digest_segments);
	if (!jobj_digest_segments)
		return -EINVAL;

	if (assign) {
		json_object_object_foreach(LUKS2_get_segments_jobj(hdr), key, value) {
			UNUSED(value);
			jobj1 = LUKS2_array_jobj(jobj_digest_segments, key);
			if (!jobj1)
				json_object_array_add(jobj_digest_segments, json_object_new_string(key));
		}
	} else {
		jobj1 = json_object_new_array();
		if (!jobj1)
			return -ENOMEM;
		json_object_object_add(jobj_digest, "segments", jobj1);
	}

	return 0;
}

static int assign_one_segment(struct crypt_device *cd, struct luks2_hdr *hdr,
			     int segment, int digest, int assign)
{
	json_object *jobj1, *jobj_digest, *jobj_digest_segments;
	char num[16];

	log_dbg(cd, "Segment %i %s digest %i.", segment, assign ? "assigned to" : "unassigned from", digest);

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

	if (segment == CRYPT_DEFAULT_SEGMENT)
		segment = LUKS2_get_default_segment(hdr);

	if (digest == CRYPT_ANY_DIGEST) {
		json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

		json_object_object_foreach(jobj_digests, key, val) {
			UNUSED(val);
			if (segment == CRYPT_ANY_SEGMENT)
				r = assign_all_segments(cd, hdr, atoi(key), assign);
			else
				r = assign_one_segment(cd, hdr, segment, atoi(key), assign);
			if (r < 0)
				break;
		}
	} else {
		if (segment == CRYPT_ANY_SEGMENT)
			r = assign_all_segments(cd, hdr, digest, assign);
		else
			r = assign_one_segment(cd, hdr, segment, digest, assign);
	}

	if (r < 0)
		return r;

	// FIXME: do not write header in nothing changed
	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

static int digest_unused(json_object *jobj_digest)
{
	json_object *jobj;

	json_object_object_get_ex(jobj_digest, "segments", &jobj);
	if (!jobj || !json_object_is_type(jobj, json_type_array) || json_object_array_length(jobj) > 0)
		return 0;

	json_object_object_get_ex(jobj_digest, "keyslots", &jobj);
	if (!jobj || !json_object_is_type(jobj, json_type_array))
		return 0;

	return json_object_array_length(jobj) > 0 ? 0 : 1;
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
			log_dbg(cd, "Erasing unused digest %d.", atoi(key));
			json_object_object_del(jobj_digests, key);
		}
	}
}

/* Key description helpers */
static char *get_key_description_by_digest(struct crypt_device *cd, int digest)
{
	char *desc, digest_str[3];
	int r;
	size_t len;

	if (!crypt_get_uuid(cd))
		return NULL;

	r = snprintf(digest_str, sizeof(digest_str), "d%u", digest);
	if (r < 0 || (size_t)r >= sizeof(digest_str))
		return NULL;

	/* "cryptsetup:<uuid>-<digest_str>" + \0 */
	len = strlen(crypt_get_uuid(cd)) + strlen(digest_str) + 13;

	desc = malloc(len);
	if (!desc)
	       return NULL;

	r = snprintf(desc, len, "%s:%s-%s", "cryptsetup", crypt_get_uuid(cd), digest_str);
	if (r < 0 || (size_t)r >= len) {
	       free(desc);
	       return NULL;
	}

	return desc;
}

char *LUKS2_key_description_by_digest(struct crypt_device *cd, int digest)
{
	return get_key_description_by_digest(cd, digest);
}

int LUKS2_key_description_by_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int segment)
{
	char *desc = get_key_description_by_digest(cd, LUKS2_digest_by_segment(hdr, segment));
	int r;

	r = crypt_volume_key_set_description(vk, desc);
	free(desc);
	return r;
}

int LUKS2_volume_key_load_in_keyring_by_keyslot(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int keyslot)
{
	char *desc = get_key_description_by_digest(cd, LUKS2_digest_by_keyslot(hdr, keyslot));
	int r;

	r = crypt_volume_key_set_description(vk, desc);
	if (!r)
		r = crypt_volume_key_load_in_keyring(cd, vk);

	free(desc);
	return r;
}

int LUKS2_volume_key_load_in_keyring_by_digest(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int digest)
{
	char *desc = get_key_description_by_digest(cd, digest);
	int r;

	r = crypt_volume_key_set_description(vk, desc);
	if (!r)
		r = crypt_volume_key_load_in_keyring(cd, vk);

	free(desc);
	return r;
}
