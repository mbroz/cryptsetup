// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2, digest handling
 *
 * Copyright (C) 2015-2026 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2026 Milan Broz
 */

#include "luks2_internal.h"

extern const digest_handler PBKDF2_digest;

static const digest_handler *digest_handlers[LUKS2_DIGEST_MAX] = {
	&PBKDF2_digest,
	NULL
};

static const digest_handler *LUKS2_digest_handler_type(const char *type)
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

	return LUKS2_digest_handler_type(json_object_get_string(jobj2));
}

static int LUKS2_digest_find_free(struct luks2_hdr *hdr)
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

	dh = LUKS2_digest_handler_type(type);
	if (!dh)
		return -EINVAL;

	digest = LUKS2_digest_find_free(hdr);
	if (digest < 0)
		return -EINVAL;

	log_dbg(cd, "Creating new digest %d (%s).", digest, type);

	return dh->store(cd, digest, crypt_volume_key_get_key(vk), crypt_volume_key_length(vk)) ?: digest;
}

int LUKS2_digest_by_keyslot(struct luks2_hdr *hdr, int keyslot)
{
	char keyslot_name[16];
	json_object *jobj_digests, *jobj_digest_keyslots;
	int digest;

	if (snprintf(keyslot_name, sizeof(keyslot_name), "%u", keyslot) < 1)
		return -ENOMEM;

	json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

	json_object_object_foreach(jobj_digests, key, val) {
		json_object_object_get_ex(val, "keyslots", &jobj_digest_keyslots);
		if (LUKS2_array_jobj(jobj_digest_keyslots, keyslot_name))
			return crypt_str_to_int(key, &digest) < 0 ? -EINVAL : digest;
	}

	return -ENOENT;
}

/*
 * The digest assigned to OPAL segment is calculated from the volume key together
 * with the segment metadata. Legacy OPAL metadata (digest of the volume key only)
 * triggers warning or rejects it completely, see LUKS2_split_crypt_and_opal_keys().
 */
static int digest_opal_data(struct luks2_hdr *hdr,
	int digest,
	const struct volume_key *vk,
	struct volume_key **r_data)
{
	uint8_t version;

	*r_data = NULL;

	if (!LUKS2_segment_is_hw_opal(hdr, CRYPT_DEFAULT_SEGMENT) ||
	    LUKS2_digest_by_segment(hdr, CRYPT_DEFAULT_SEGMENT) != digest ||
	    LUKS2_config_get_opal_version(hdr, &version) ||
	    version < LUKS2_OPAL_BASE_REQ_VERSION)
		return 0;

	return LUKS2_opal_assembly_verification_data(hdr, vk, version, r_data);
}

static int digest_verify(struct crypt_device *cd,
	const digest_handler *h,
	int digest,
	const struct volume_key *vk)
{
	int r;
	struct volume_key *opal_data;

	r = digest_opal_data(crypt_get_hdr(cd, CRYPT_LUKS2), digest, vk, &opal_data);
	if (r < 0)
		return r;

	if (opal_data)
		vk = opal_data;

	r = h->verify(cd, digest, crypt_volume_key_get_key(vk), crypt_volume_key_length(vk));
	crypt_free_volume_key(opal_data);
	if (r < 0) {
		log_dbg(cd, "Digest %d (%s) verify failed with %d.", digest, h->name, r);
		return r;
	}

	return digest;
}

/*
 * Recalculates the digest assigned to OPAL segment so that it covers also
 * the segment metadata. The digest id and its assignments are preserved.
 */
int LUKS2_digest_opal_update(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk)
{
	const digest_handler *h;
	int digest, r;
	json_object *jobj_digest, *jobj_keyslots, *jobj_segments;
	struct volume_key *opal_data;

	digest = LUKS2_digest_by_segment(hdr, CRYPT_DEFAULT_SEGMENT);
	if (digest < 0)
		return digest;

	h = LUKS2_digest_handler(cd, digest);
	if (!h)
		return -EINVAL;

	r = digest_opal_data(hdr, digest, vk, &opal_data);
	if (r < 0)
		return r;
	if (!opal_data)
		return -EINVAL;

	/* digest store resets keyslots and segments assignments, keep them */
	jobj_digest = LUKS2_get_digest_jobj(hdr, digest);
	if (!json_object_object_get_ex(jobj_digest, "keyslots", &jobj_keyslots) ||
	    !json_object_object_get_ex(jobj_digest, "segments", &jobj_segments)) {
		crypt_free_volume_key(opal_data);
		return -EINVAL;
	}
	json_object_get(jobj_keyslots);
	json_object_get(jobj_segments);

	log_dbg(cd, "Updating digest %d (%s) assigned to OPAL segment.", digest, h->name);

	r = h->store(cd, digest, crypt_volume_key_get_key(opal_data),
		     crypt_volume_key_length(opal_data));
	crypt_free_volume_key(opal_data);

	json_object_object_add(jobj_digest, "keyslots", jobj_keyslots);
	json_object_object_add(jobj_digest, "segments", jobj_segments);

	return r;
}

int LUKS2_digest_verify_by_digest(struct crypt_device *cd,
	int digest,
	const struct volume_key *vk)
{
	const digest_handler *h;
	int key_size, r;

	h = LUKS2_digest_handler(cd, digest);
	if (!h)
		return -EINVAL;

	r = digest_verify(cd, h, digest, vk);
	if (r < 0)
		return r;

	key_size = LUKS2_get_volume_key_size_by_digest(crypt_get_hdr(cd, CRYPT_LUKS2), digest);

	if (key_size > 0 && (size_t)key_size != crypt_volume_key_length(vk))
		return -EPERM;

	return r;
}

static int digest_verify_by_keyslot(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	int keyslot,
	bool check_key_size)
{
	const digest_handler *h;
	int digest, key_size, r;

	digest = LUKS2_digest_by_keyslot(hdr, keyslot);
	if (digest < 0)
		return digest;

	h = LUKS2_digest_handler(cd, digest);
	if (!h)
		return -EINVAL;

	log_dbg(cd, "Verifying key from keyslot %d, digest %d.", keyslot, digest);

	r = digest_verify(cd, h, digest, vk);
	if (r < 0 || !check_key_size)
		return r;

	key_size = LUKS2_get_keyslot_stored_key_size(hdr, keyslot);
	if (key_size < 0)
		return -EINVAL;

	if ((size_t)key_size != crypt_volume_key_length(vk))
		return -EPERM;

	return r;
}

int LUKS2_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	int keyslot)
{
	return digest_verify_by_keyslot(cd, hdr, vk, keyslot, /* check_key_size= */ true);
}

int LUKS2_reencrypt_keyslot_digest_verify(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	int keyslot)
{
	return digest_verify_by_keyslot(cd, hdr, vk, keyslot, /* check_key_size= */ false);
}

int LUKS2_digest_dump(struct crypt_device *cd, int digest)
{
	const digest_handler *h;

	if (!(h = LUKS2_digest_handler(cd, digest)))
		return -EINVAL;

	return h->dump(cd, digest);
}

int LUKS2_digest_verify_by_any_matching(struct crypt_device *cd,
		const struct volume_key *vk,
		bool exclude_default_segment)
{
	int digest, default_segment_digest = -1;

	if (exclude_default_segment)
		default_segment_digest = LUKS2_digest_by_segment(crypt_get_hdr(cd, CRYPT_LUKS2), CRYPT_DEFAULT_SEGMENT);

	for (digest = 0; digest < LUKS2_DIGEST_MAX; digest++) {
		if (digest != default_segment_digest &&
		    LUKS2_digest_verify_by_digest(cd, digest, vk) == digest)
			return digest;
	}

	return -ENOENT;
}

int LUKS2_digest_verify_by_segment(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int segment,
	const struct volume_key *vk)
{
	const digest_handler *h;
	int digest, key_size, r;
	unsigned s;

	if (segment == CRYPT_ANY_SEGMENT) {
		for (s = 0; s < json_segments_count(LUKS2_get_segments_jobj(hdr)); s++) {
			if ((r = LUKS2_digest_verify_by_segment(cd, hdr, s, vk)) >= 0)
				return r;
		}

		return -EPERM;
	}

	digest = LUKS2_digest_by_segment(hdr, segment);
	if (digest < 0)
		return digest;

	h = LUKS2_digest_handler(cd, digest);
	if (!h)
		return -EINVAL;

	r = digest_verify(cd, h, digest, vk);
	if (r < 0)
		return r;

	if (segment == CRYPT_DEFAULT_SEGMENT)
		/* use default segment key size or fallback to the cached key size */
		key_size = crypt_get_volume_key_size(cd);
	else
		key_size = LUKS2_get_volume_key_size(hdr, segment);

	if (key_size > 0 && (size_t)key_size != crypt_volume_key_length(vk))
		return -EPERM;

	return r;
}

/* FIXME: segment can have more digests */
int LUKS2_digest_by_segment(struct luks2_hdr *hdr, int segment)
{
	char segment_name[16];
	json_object *jobj_digests, *jobj_digest_segments;
	int digest;

	if (segment == CRYPT_DEFAULT_SEGMENT)
		segment = LUKS2_get_default_segment(hdr);

	json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

	if (snprintf(segment_name, sizeof(segment_name), "%u", segment) < 1)
		return -EINVAL;

	json_object_object_foreach(jobj_digests, key, val) {
		json_object_object_get_ex(val, "segments", &jobj_digest_segments);
		if (!LUKS2_array_jobj(jobj_digest_segments, segment_name))
			continue;

		return crypt_str_to_int(key, &digest) < 0 ? -EINVAL : digest;
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

	if (snprintf(num, sizeof(num), "%d", keyslot) < 0)
		return -EINVAL;

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
	int d, r = 0;

	if (digest == CRYPT_ANY_DIGEST) {
		json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

		json_object_object_foreach(jobj_digests, key, val) {
			UNUSED(val);
			r = crypt_str_to_int(key, &d);
			if (r == 0)
				r = assign_one_digest(cd, hdr, keyslot, d, assign);
			if (r < 0)
				break;
		}
	} else
		r = assign_one_digest(cd, hdr, keyslot, digest, assign);

	if (r < 0)
		return r;

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

static int assign_all_segments(struct luks2_hdr *hdr, int digest, int assign)
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

	if (snprintf(num, sizeof(num), "%d", segment) < 0)
		return -EINVAL;

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
	int d, r = 0;

	if (segment == CRYPT_DEFAULT_SEGMENT)
		segment = LUKS2_get_default_segment(hdr);

	if (digest == CRYPT_ANY_DIGEST) {
		json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);

		json_object_object_foreach(jobj_digests, key, val) {
			UNUSED(val);
			r = crypt_str_to_int(key, &d);
			if (r == 0) {
				if (segment == CRYPT_ANY_SEGMENT)
					r = assign_all_segments(hdr, d, assign);
				else
					r = assign_one_segment(cd, hdr, segment, d, assign);
			}
			if (r < 0)
				break;
		}
	} else {
		if (segment == CRYPT_ANY_SEGMENT)
			r = assign_all_segments(hdr, digest, assign);
		else
			r = assign_one_segment(cd, hdr, segment, digest, assign);
	}

	if (r < 0)
		return r;

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
			log_dbg(cd, "Erasing unused digest %s.", key);
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

int LUKS2_key_description_by_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr, struct volume_key *vk, int segment)
{
	char *desc = get_key_description_by_digest(cd, LUKS2_digest_by_segment(hdr, segment));
	int r;

	r = crypt_volume_key_set_description(vk, desc, LOGON_KEY);
	free(desc);
	return r;
}

int LUKS2_volume_key_load_in_keyring_by_digest(struct crypt_device *cd,
		struct volume_key *vk, int digest)
{
	char *desc = get_key_description_by_digest(cd, digest);
	int r;

	r = crypt_volume_key_set_description(vk, desc, LOGON_KEY);
	if (!r)
		r = crypt_volume_key_load_in_keyring(cd, vk);

	free(desc);
	return r;
}
