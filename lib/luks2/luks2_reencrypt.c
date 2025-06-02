// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2, reencryption helpers
 *
 * Copyright (C) 2015-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2025 Ondrej Kozina
 */

#include "luks2_internal.h"
#include "utils_device_locking.h"
#include "keyslot_context.h"

struct luks2_reencrypt {
	/* reencryption window attributes */
	uint64_t offset;
	uint64_t progress;
	uint64_t length;
	uint64_t device_size;
	bool online;
	bool fixed_length;
	crypt_reencrypt_direction_info direction;
	crypt_reencrypt_mode_info mode;

	char *device_name;
	char *hotzone_name;
	char *overlay_name;
	uint32_t flags;

	/* reencryption window persistence attributes */
	struct reenc_protection rp;
	struct reenc_protection rp_moved_segment;

	int reenc_keyslot;

	/* already running reencryption */
	json_object *jobj_segs_hot;
	struct json_object *jobj_segs_post;

	/* backup segments */
	json_object *jobj_segment_new;
	int digest_new;
	json_object *jobj_segment_old;
	int digest_old;
	json_object *jobj_segment_moved;

	struct volume_key *vks;

	void *reenc_buffer;
	ssize_t read;

	struct crypt_storage_wrapper *cw1;
	struct crypt_storage_wrapper *cw2;

	uint32_t wflags1;
	uint32_t wflags2;

	struct crypt_lock_handle *reenc_lock;
};
#if USE_LUKS2_REENCRYPTION
static uint64_t data_shift_value(struct reenc_protection *rp)
{
	return rp->type == REENC_PROTECTION_DATASHIFT ? rp->p.ds.data_shift : 0;
}

static json_object *reencrypt_segment(struct luks2_hdr *hdr, unsigned new)
{
	return LUKS2_get_segment_by_flag(hdr, new ? "backup-final" : "backup-previous");
}

static json_object *reencrypt_segment_new(struct luks2_hdr *hdr)
{
	return reencrypt_segment(hdr, 1);
}

static json_object *reencrypt_segment_old(struct luks2_hdr *hdr)
{
	return reencrypt_segment(hdr, 0);
}

static json_object *reencrypt_segments_old(struct luks2_hdr *hdr)
{
	json_object *jobj_segments, *jobj = NULL;

	if (json_object_copy(reencrypt_segment_old(hdr), &jobj))
		return NULL;

	json_segment_remove_flag(jobj, "backup-previous");

	jobj_segments = json_object_new_object();
	if (!jobj_segments) {
		json_object_put(jobj);
		return NULL;
	}

	if (json_object_object_add_by_uint(jobj_segments, 0, jobj)) {
		json_object_put(jobj);
		json_object_put(jobj_segments);
		return NULL;
	}

	return jobj_segments;
}

static const char *reencrypt_segment_cipher_new(struct luks2_hdr *hdr)
{
	return json_segment_get_cipher(reencrypt_segment(hdr, 1));
}

static const char *reencrypt_segment_cipher_old(struct luks2_hdr *hdr)
{
	return json_segment_get_cipher(reencrypt_segment(hdr, 0));
}

static uint32_t reencrypt_get_sector_size_new(struct luks2_hdr *hdr)
{
	return json_segment_get_sector_size(reencrypt_segment(hdr, 1));
}

static uint32_t reencrypt_get_sector_size_old(struct luks2_hdr *hdr)
{
	return json_segment_get_sector_size(reencrypt_segment(hdr, 0));
}

static uint64_t reencrypt_data_offset(struct luks2_hdr *hdr, unsigned new)
{
	json_object *jobj = reencrypt_segment(hdr, new);
	if (jobj)
		return json_segment_get_offset(jobj, 0);

	return LUKS2_get_data_offset(hdr) << SECTOR_SHIFT;
}

static uint64_t LUKS2_reencrypt_get_data_offset_moved(struct luks2_hdr *hdr)
{
	json_object *jobj_segment = LUKS2_get_segment_by_flag(hdr, "backup-moved-segment");

	if (!jobj_segment)
		return 0;

	return json_segment_get_offset(jobj_segment, 0);
}

static uint64_t reencrypt_get_data_offset_new(struct luks2_hdr *hdr)
{
	return reencrypt_data_offset(hdr, 1);
}

static uint64_t reencrypt_get_data_offset_old(struct luks2_hdr *hdr)
{
	return reencrypt_data_offset(hdr, 0);
}
#endif

static int reencrypt_digest(struct luks2_hdr *hdr, unsigned new)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, new ? "backup-final" : "backup-previous");

	if (segment < 0)
		return segment;

	return LUKS2_digest_by_segment(hdr, segment);
}

int LUKS2_reencrypt_digest_new(struct luks2_hdr *hdr)
{
	return reencrypt_digest(hdr, 1);
}

int LUKS2_reencrypt_digest_old(struct luks2_hdr *hdr)
{
	return reencrypt_digest(hdr, 0);
}

int LUKS2_reencrypt_segment_new(struct luks2_hdr *hdr)
{
	return LUKS2_get_segment_id_by_flag(hdr, "backup-final");
}

int LUKS2_reencrypt_segment_old(struct luks2_hdr *hdr)
{
	return LUKS2_get_segment_id_by_flag(hdr, "backup-previous");
}

unsigned LUKS2_reencrypt_vks_count(struct luks2_hdr *hdr)
{
	int digest_old, digest_new;
	unsigned vks_count = 0;

	if ((digest_new = LUKS2_reencrypt_digest_new(hdr)) >= 0)
		vks_count++;
	if ((digest_old = LUKS2_reencrypt_digest_old(hdr)) >= 0) {
		if (digest_old != digest_new)
			vks_count++;
	}

	return vks_count;
}

/* none, checksums, journal or shift */
static const char *reencrypt_resilience_type(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return NULL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return NULL;

	return json_object_get_string(jobj_type);
}

static const char *reencrypt_resilience_hash(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type, *jobj_hash;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return NULL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return NULL;
	if (strcmp(json_object_get_string(jobj_type), "checksum"))
		return NULL;
	if (!json_object_object_get_ex(jobj_area, "hash", &jobj_hash))
		return NULL;

	return json_object_get_string(jobj_hash);
}
#if USE_LUKS2_REENCRYPTION
static json_object *_enc_create_segments_shift_after(struct luks2_reencrypt *rh, uint64_t data_offset)
{
	int reenc_seg, i = 0;
	json_object *jobj, *jobj_copy = NULL, *jobj_seg_new = NULL, *jobj_segs_post = json_object_new_object();
	uint64_t tmp;

	if (!rh->jobj_segs_hot || !jobj_segs_post)
		goto err;

	if (json_segments_count(rh->jobj_segs_hot) == 0)
		return jobj_segs_post;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_hot);
	if (reenc_seg < 0)
		goto err;

	while (i < reenc_seg) {
		jobj_copy = json_segments_get_segment(rh->jobj_segs_hot, i);
		if (!jobj_copy || json_object_object_add_by_uint(jobj_segs_post, i++, json_object_get(jobj_copy)))
			goto err;
	}
	jobj_copy = NULL;

	jobj = json_segments_get_segment(rh->jobj_segs_hot, reenc_seg + 1);
	if (!jobj) {
		jobj = json_segments_get_segment(rh->jobj_segs_hot, reenc_seg);
		if (!jobj || json_object_copy(jobj, &jobj_seg_new))
			goto err;
		json_segment_remove_flag(jobj_seg_new, "in-reencryption");
		tmp = rh->length;
	} else {
		if (json_object_copy(jobj, &jobj_seg_new))
			goto err;
		json_object_object_add(jobj_seg_new, "offset", crypt_jobj_new_uint64(rh->offset + data_offset));
		json_object_object_add(jobj_seg_new, "iv_tweak", crypt_jobj_new_uint64(rh->offset >> SECTOR_SHIFT));
		tmp = json_segment_get_size(jobj_seg_new, 0) + rh->length;
	}

	/* alter size of new segment, reenc_seg == 0 we're finished */
	json_object_object_add(jobj_seg_new, "size", reenc_seg > 0 ? crypt_jobj_new_uint64(tmp) : json_object_new_string("dynamic"));
	if (!json_object_object_add_by_uint(jobj_segs_post, reenc_seg, jobj_seg_new))
		return jobj_segs_post;

err:
	json_object_put(jobj_seg_new);
	json_object_put(jobj_copy);
	json_object_put(jobj_segs_post);
	return NULL;
}

static json_object *reencrypt_make_hot_segments_encrypt_shift(struct luks2_hdr *hdr,
	struct luks2_reencrypt *rh,
	uint64_t data_offset)
{
	int sg, crypt_seg, i = 0;
	uint64_t segment_size;
	json_object *jobj_seg_shrunk = NULL, *jobj_seg_new = NULL, *jobj_copy = NULL, *jobj_enc_seg = NULL,
		     *jobj_segs_hot = json_object_new_object();

	if (!jobj_segs_hot)
		return NULL;

	crypt_seg = LUKS2_segment_by_type(hdr, "crypt");

	/* FIXME: This is hack. Find proper way to fix it. */
	sg = LUKS2_last_segment_by_type(hdr, "linear");
	if (rh->offset && sg < 0)
		goto err;
	if (sg < 0)
		return jobj_segs_hot;

	jobj_enc_seg = json_segment_create_crypt(data_offset + rh->offset,
						      rh->offset >> SECTOR_SHIFT,
						      &rh->length,
						      reencrypt_segment_cipher_new(hdr),
						      NULL, 0, /* integrity */
						      reencrypt_get_sector_size_new(hdr),
						      1);

	while (i < sg) {
		jobj_copy = LUKS2_get_segment_jobj(hdr, i);
		if (!jobj_copy || json_object_object_add_by_uint(jobj_segs_hot, i++, json_object_get(jobj_copy)))
			goto err;
	}
	jobj_copy = NULL;

	segment_size = LUKS2_segment_size(hdr, sg, 0);
	if (segment_size > rh->length) {
		if (json_object_copy(LUKS2_get_segment_jobj(hdr, sg), &jobj_seg_shrunk))
			goto err;
		json_object_object_add(jobj_seg_shrunk, "size", crypt_jobj_new_uint64(segment_size - rh->length));
		if (json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_seg_shrunk))
			goto err;
	}

	if (json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_enc_seg))
		goto err;

	/* first crypt segment after encryption ? */
	if (crypt_seg >= 0) {
		jobj_seg_new = LUKS2_get_segment_jobj(hdr, crypt_seg);
		if (!jobj_seg_new || json_object_object_add_by_uint(jobj_segs_hot, sg, json_object_get(jobj_seg_new)))
			goto err;
	}

	return jobj_segs_hot;
err:
	json_object_put(jobj_copy);
	json_object_put(jobj_seg_new);
	json_object_put(jobj_seg_shrunk);
	json_object_put(jobj_enc_seg);
	json_object_put(jobj_segs_hot);

	return NULL;
}

static json_object *reencrypt_make_segment_new(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct luks2_reencrypt *rh,
		uint64_t data_offset,
		uint64_t segment_offset,
		uint64_t iv_offset,
		const uint64_t *segment_length)
{
	switch (rh->mode) {
	case CRYPT_REENCRYPT_REENCRYPT:
	case CRYPT_REENCRYPT_ENCRYPT:
		return json_segment_create_crypt(data_offset + segment_offset,
						  crypt_get_iv_offset(cd) + (iv_offset >> SECTOR_SHIFT),
						  segment_length,
						  reencrypt_segment_cipher_new(hdr),
						  NULL, 0, /* integrity */
						  reencrypt_get_sector_size_new(hdr), 0);
	case CRYPT_REENCRYPT_DECRYPT:
		return json_segment_create_linear(data_offset + segment_offset, segment_length, 0);
	}

	return NULL;
}

static json_object *reencrypt_make_post_segments_forward(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reencrypt *rh,
	uint64_t data_offset)
{
	int reenc_seg;
	json_object *jobj_old_seg, *jobj_new_seg_after = NULL, *jobj_old_seg_copy = NULL,
		    *jobj_segs_post = json_object_new_object();
	uint64_t fixed_length = rh->offset + rh->length;

	if (!rh->jobj_segs_hot || !jobj_segs_post)
		goto err;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_hot);
	if (reenc_seg < 0)
		goto err;

	jobj_old_seg = json_segments_get_segment(rh->jobj_segs_hot, reenc_seg + 1);

	/*
	 * if there's no old segment after reencryption, we're done.
	 * Set size to 'dynamic' again.
	 */
	jobj_new_seg_after = reencrypt_make_segment_new(cd, hdr, rh, data_offset, 0, 0, jobj_old_seg ? &fixed_length : NULL);
	if (!jobj_new_seg_after || json_object_object_add_by_uint_by_ref(jobj_segs_post, 0, &jobj_new_seg_after))
		goto err;

	if (jobj_old_seg) {
		if (rh->fixed_length) {
			if (json_object_copy(jobj_old_seg, &jobj_old_seg_copy))
				goto err;
			fixed_length = rh->device_size - fixed_length;
			json_object_object_add(jobj_old_seg_copy, "size", crypt_jobj_new_uint64(fixed_length));
		} else
			jobj_old_seg_copy = json_object_get(jobj_old_seg);

		if (json_object_object_add_by_uint_by_ref(jobj_segs_post, 1, &jobj_old_seg_copy))
			goto err;
	}

	return jobj_segs_post;
err:
	json_object_put(jobj_new_seg_after);
	json_object_put(jobj_old_seg_copy);
	json_object_put(jobj_segs_post);
	return NULL;
}

static json_object *reencrypt_make_post_segments_backward(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reencrypt *rh,
	uint64_t data_offset)
{
	int reenc_seg;
	uint64_t fixed_length;

	json_object *jobj_new_seg_after = NULL, *jobj_old_seg = NULL,
		    *jobj_segs_post = json_object_new_object();

	if (!rh->jobj_segs_hot || !jobj_segs_post)
		goto err;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_hot);
	if (reenc_seg < 0)
		goto err;

	jobj_old_seg = json_segments_get_segment(rh->jobj_segs_hot, reenc_seg - 1);
	if (jobj_old_seg) {
		json_object_get(jobj_old_seg);
		if (json_object_object_add_by_uint_by_ref(jobj_segs_post, reenc_seg - 1, &jobj_old_seg))
			goto err;
	}

	if (rh->fixed_length && rh->offset) {
		fixed_length = rh->device_size - rh->offset;
		jobj_new_seg_after = reencrypt_make_segment_new(cd, hdr, rh, data_offset, rh->offset, rh->offset, &fixed_length);
	} else
		jobj_new_seg_after = reencrypt_make_segment_new(cd, hdr, rh, data_offset, rh->offset, rh->offset, NULL);

	if (jobj_new_seg_after && !json_object_object_add_by_uint(jobj_segs_post, reenc_seg, jobj_new_seg_after))
		return jobj_segs_post;
err:
	json_object_put(jobj_new_seg_after);
	json_object_put(jobj_old_seg);
	json_object_put(jobj_segs_post);
	return NULL;
}

static json_object *reencrypt_make_segment_reencrypt(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct luks2_reencrypt *rh,
		uint64_t data_offset,
		uint64_t segment_offset,
		uint64_t iv_offset,
		const uint64_t *segment_length)
{
	switch (rh->mode) {
	case CRYPT_REENCRYPT_REENCRYPT:
	case CRYPT_REENCRYPT_ENCRYPT:
		return json_segment_create_crypt(data_offset + segment_offset,
				crypt_get_iv_offset(cd) + (iv_offset >> SECTOR_SHIFT),
				segment_length,
				reencrypt_segment_cipher_new(hdr),
			        NULL, 0, /* integrity */
				reencrypt_get_sector_size_new(hdr), 1);
	case CRYPT_REENCRYPT_DECRYPT:
		return json_segment_create_linear(data_offset + segment_offset, segment_length, 1);
	}

	return NULL;
}

static json_object *reencrypt_make_segment_old(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct luks2_reencrypt *rh,
		uint64_t data_offset,
		uint64_t segment_offset,
		const uint64_t *segment_length)
{
	json_object *jobj_old_seg = NULL;

	switch (rh->mode) {
	case CRYPT_REENCRYPT_REENCRYPT:
	case CRYPT_REENCRYPT_DECRYPT:
		jobj_old_seg = json_segment_create_crypt(data_offset + segment_offset,
						    crypt_get_iv_offset(cd) + (segment_offset >> SECTOR_SHIFT),
						    segment_length,
						    reencrypt_segment_cipher_old(hdr),
						    NULL, 0, /* integrity */
						    reencrypt_get_sector_size_old(hdr),
						    0);
		break;
	case CRYPT_REENCRYPT_ENCRYPT:
		jobj_old_seg = json_segment_create_linear(data_offset + segment_offset, segment_length, 0);
	}

	return jobj_old_seg;
}

static json_object *reencrypt_make_hot_segments_forward(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	uint64_t fixed_length, tmp = rh->offset + rh->length;
	json_object *jobj_segs_hot = json_object_new_object(), *jobj_reenc_seg = NULL,
		    *jobj_old_seg = NULL, *jobj_new_seg = NULL;
	unsigned int sg = 0;

	if (!jobj_segs_hot)
		return NULL;

	if (rh->offset) {
		jobj_new_seg = reencrypt_make_segment_new(cd, hdr, rh, data_offset, 0, 0, &rh->offset);
		if (!jobj_new_seg || json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_new_seg))
			goto err;
	}

	jobj_reenc_seg = reencrypt_make_segment_reencrypt(cd, hdr, rh, data_offset, rh->offset, rh->offset, &rh->length);
	if (!jobj_reenc_seg)
		goto err;

	if (json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_reenc_seg))
		goto err;

	if (tmp < device_size) {
		fixed_length = device_size - tmp;
		jobj_old_seg = reencrypt_make_segment_old(cd, hdr, rh, data_offset + data_shift_value(&rh->rp),
							  rh->offset + rh->length, rh->fixed_length ? &fixed_length : NULL);
		if (!jobj_old_seg || json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg, &jobj_old_seg))
			goto err;
	}

	return jobj_segs_hot;
err:
	json_object_put(jobj_reenc_seg);
	json_object_put(jobj_old_seg);
	json_object_put(jobj_new_seg);
	json_object_put(jobj_segs_hot);
	return NULL;
}

static json_object *reencrypt_make_hot_segments_decrypt_shift(struct crypt_device *cd,
	struct luks2_hdr *hdr, struct luks2_reencrypt *rh,
	uint64_t device_size, uint64_t data_offset)
{
	uint64_t fixed_length, tmp = rh->offset + rh->length, linear_length = rh->progress;
	json_object *jobj, *jobj_segs_hot = json_object_new_object(), *jobj_reenc_seg = NULL,
		    *jobj_old_seg = NULL, *jobj_new_seg = NULL;
	unsigned int sg = 0;

	if (!jobj_segs_hot)
		return NULL;

	if (rh->offset) {
		jobj = LUKS2_get_segment_jobj(hdr, 0);
		if (!jobj)
			goto err;

		jobj_new_seg = json_object_get(jobj);
		if (json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_new_seg))
			goto err;

		if (linear_length) {
			jobj_new_seg = reencrypt_make_segment_new(cd, hdr, rh,
								  data_offset,
								  json_segment_get_size(jobj, 0),
								  0,
								  &linear_length);
			if (!jobj_new_seg || json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_new_seg))
				goto err;
		}
	}

	jobj_reenc_seg = reencrypt_make_segment_reencrypt(cd, hdr, rh, data_offset,
							  rh->offset,
							  rh->offset,
							  &rh->length);
	if (!jobj_reenc_seg || json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_reenc_seg))
		goto err;

	if (!rh->offset && (jobj = LUKS2_get_segment_jobj(hdr, 1)) &&
	    !json_segment_is_backup(jobj)) {
		jobj_new_seg = json_object_get(jobj);
		if (json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_new_seg))
			goto err;
	} else if (tmp < device_size) {
		fixed_length = device_size - tmp;
		jobj_old_seg = reencrypt_make_segment_old(cd, hdr, rh,
							  data_offset + data_shift_value(&rh->rp),
							  rh->offset + rh->length,
							  rh->fixed_length ? &fixed_length : NULL);
		if (!jobj_old_seg || json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg, &jobj_old_seg))
			goto err;
	}

	return jobj_segs_hot;
err:
	json_object_put(jobj_reenc_seg);
	json_object_put(jobj_old_seg);
	json_object_put(jobj_new_seg);
	json_object_put(jobj_segs_hot);
	return NULL;
}

static json_object *_dec_create_segments_shift_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reencrypt *rh,
	uint64_t data_offset)
{
	int reenc_seg, i = 0;
	json_object *jobj_seg_old, *jobj_copy = NULL, *jobj_seg_old_copy = NULL, *jobj_seg_new = NULL,
		    *jobj_segs_post = json_object_new_object();
	unsigned segs;
	uint64_t tmp;

	if (!rh->jobj_segs_hot || !jobj_segs_post)
		goto err;

	segs = json_segments_count(rh->jobj_segs_hot);
	if (segs == 0)
		return jobj_segs_post;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_hot);
	if (reenc_seg < 0)
		goto err;

	if (reenc_seg == 0) {
		jobj_seg_new = reencrypt_make_segment_new(cd, hdr, rh, data_offset, 0, 0, NULL);
		if (!jobj_seg_new || json_object_object_add_by_uint(jobj_segs_post, 0, jobj_seg_new))
			goto err;

		return jobj_segs_post;
	}

	jobj_copy = json_segments_get_segment(rh->jobj_segs_hot, 0);
	if (!jobj_copy)
		goto err;
	json_object_get(jobj_copy);
	if (json_object_object_add_by_uint_by_ref(jobj_segs_post, i++, &jobj_copy))
		goto err;

	if ((jobj_seg_old = json_segments_get_segment(rh->jobj_segs_hot, reenc_seg + 1)))
		jobj_seg_old_copy = json_object_get(jobj_seg_old);

	tmp = rh->length + rh->progress;
	jobj_seg_new = reencrypt_make_segment_new(cd, hdr, rh, data_offset,
						  json_segment_get_size(rh->jobj_segment_moved, 0),
						  data_shift_value(&rh->rp),
						  jobj_seg_old ? &tmp : NULL);
	if (!jobj_seg_new || json_object_object_add_by_uint_by_ref(jobj_segs_post, i++, &jobj_seg_new))
		goto err;

	if (jobj_seg_old_copy && json_object_object_add_by_uint(jobj_segs_post, i, jobj_seg_old_copy))
		goto err;

	return jobj_segs_post;
err:
	json_object_put(jobj_copy);
	json_object_put(jobj_seg_old_copy);
	json_object_put(jobj_seg_new);
	json_object_put(jobj_segs_post);
	return NULL;
}

static json_object *reencrypt_make_hot_segments_backward(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	uint64_t fixed_length, tmp = rh->offset + rh->length;
	json_object *jobj_reenc_seg = NULL, *jobj_new_seg = NULL, *jobj_old_seg = NULL,
		    *jobj_segs_hot = json_object_new_object();
	int sg = 0;

	if (!jobj_segs_hot)
		return NULL;

	if (rh->offset) {
		if (json_object_copy(LUKS2_get_segment_jobj(hdr, 0), &jobj_old_seg))
			goto err;
		json_object_object_add(jobj_old_seg, "size", crypt_jobj_new_uint64(rh->offset));

		if (json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_old_seg))
			goto err;
	}

	jobj_reenc_seg = reencrypt_make_segment_reencrypt(cd, hdr, rh, data_offset, rh->offset, rh->offset, &rh->length);
	if (!jobj_reenc_seg || json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg++, &jobj_reenc_seg))
		goto err;

	if (tmp < device_size) {
		fixed_length = device_size - tmp;
		jobj_new_seg = reencrypt_make_segment_new(cd, hdr, rh, data_offset, rh->offset + rh->length,
							  rh->offset + rh->length, rh->fixed_length ? &fixed_length : NULL);
		if (!jobj_new_seg || json_object_object_add_by_uint_by_ref(jobj_segs_hot, sg, &jobj_new_seg))
			goto err;
	}

	return jobj_segs_hot;
err:
	json_object_put(jobj_reenc_seg);
	json_object_put(jobj_new_seg);
	json_object_put(jobj_old_seg);
	json_object_put(jobj_segs_hot);
	return NULL;
}

static int reencrypt_make_hot_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	rh->jobj_segs_hot = NULL;

	if (rh->mode == CRYPT_REENCRYPT_ENCRYPT && rh->direction == CRYPT_REENCRYPT_BACKWARD &&
	    rh->rp.type == REENC_PROTECTION_DATASHIFT && rh->jobj_segment_moved) {
		log_dbg(cd, "Calculating hot segments for encryption with data move.");
		rh->jobj_segs_hot = reencrypt_make_hot_segments_encrypt_shift(hdr, rh, data_offset);
	} else if (rh->mode == CRYPT_REENCRYPT_DECRYPT && rh->direction == CRYPT_REENCRYPT_FORWARD &&
		   rh->rp.type == REENC_PROTECTION_DATASHIFT && rh->jobj_segment_moved) {
		log_dbg(cd, "Calculating hot segments for decryption with data move.");
		rh->jobj_segs_hot = reencrypt_make_hot_segments_decrypt_shift(cd, hdr, rh, device_size, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_FORWARD) {
		log_dbg(cd, "Calculating hot segments (forward direction).");
		rh->jobj_segs_hot = reencrypt_make_hot_segments_forward(cd, hdr, rh, device_size, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_BACKWARD) {
		log_dbg(cd, "Calculating hot segments (backward direction).");
		rh->jobj_segs_hot = reencrypt_make_hot_segments_backward(cd, hdr, rh, device_size, data_offset);
	}

	return rh->jobj_segs_hot ? 0 : -EINVAL;
}

static int reencrypt_make_post_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh,
		uint64_t data_offset)
{
	rh->jobj_segs_post = NULL;

	if (rh->mode == CRYPT_REENCRYPT_ENCRYPT && rh->direction == CRYPT_REENCRYPT_BACKWARD &&
	    rh->rp.type == REENC_PROTECTION_DATASHIFT && rh->jobj_segment_moved) {
		log_dbg(cd, "Calculating post segments for encryption with data move.");
		rh->jobj_segs_post = _enc_create_segments_shift_after(rh, data_offset);
	} else if (rh->mode == CRYPT_REENCRYPT_DECRYPT && rh->direction == CRYPT_REENCRYPT_FORWARD &&
		   rh->rp.type == REENC_PROTECTION_DATASHIFT && rh->jobj_segment_moved) {
		log_dbg(cd, "Calculating post segments for decryption with data move.");
		rh->jobj_segs_post = _dec_create_segments_shift_after(cd, hdr, rh, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_FORWARD) {
		log_dbg(cd, "Calculating post segments (forward direction).");
		rh->jobj_segs_post = reencrypt_make_post_segments_forward(cd, hdr, rh, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_BACKWARD) {
		log_dbg(cd, "Calculating segments (backward direction).");
		rh->jobj_segs_post = reencrypt_make_post_segments_backward(cd, hdr, rh, data_offset);
	}

	return rh->jobj_segs_post ? 0 : -EINVAL;
}
#endif

static uint64_t reencrypt_data_shift(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_data_shift;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return 0;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "shift_size", &jobj_data_shift))
		return 0;

	return crypt_jobj_get_uint64(jobj_data_shift);
}

static crypt_reencrypt_mode_info reencrypt_mode(struct luks2_hdr *hdr)
{
	const char *mode;
	crypt_reencrypt_mode_info mi = CRYPT_REENCRYPT_REENCRYPT;
	json_object *jobj_keyslot, *jobj_mode;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, LUKS2_find_keyslot(hdr, "reencrypt"));
	if (!jobj_keyslot)
		return mi;

	json_object_object_get_ex(jobj_keyslot, "mode", &jobj_mode);
	mode = json_object_get_string(jobj_mode);

	/* validation enforces allowed values */
	if (!strcmp(mode, "encrypt"))
		mi = CRYPT_REENCRYPT_ENCRYPT;
	else if (!strcmp(mode, "decrypt"))
		mi = CRYPT_REENCRYPT_DECRYPT;

	return mi;
}

static crypt_reencrypt_direction_info reencrypt_direction(struct luks2_hdr *hdr)
{
	const char *value;
	json_object *jobj_keyslot, *jobj_mode;
	crypt_reencrypt_direction_info di = CRYPT_REENCRYPT_FORWARD;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, LUKS2_find_keyslot(hdr, "reencrypt"));
	if (!jobj_keyslot)
		return di;

	json_object_object_get_ex(jobj_keyslot, "direction", &jobj_mode);
	value = json_object_get_string(jobj_mode);

	/* validation enforces allowed values */
	if (strcmp(value, "forward"))
		di = CRYPT_REENCRYPT_BACKWARD;

	return di;
}

typedef enum { REENC_OK = 0, REENC_ERR, REENC_ROLLBACK, REENC_FATAL } reenc_status_t;

void LUKS2_reencrypt_protection_erase(struct reenc_protection *rp)
{
	if (!rp || rp->type != REENC_PROTECTION_CHECKSUM)
		return;

	if (rp->p.csum.ch) {
		crypt_hash_destroy(rp->p.csum.ch);
		rp->p.csum.ch = NULL;
	}

	if (rp->p.csum.checksums) {
		crypt_safe_memzero(rp->p.csum.checksums, rp->p.csum.checksums_len);
		free(rp->p.csum.checksums);
		rp->p.csum.checksums = NULL;
	}
}

void LUKS2_reencrypt_free(struct crypt_device *cd, struct luks2_reencrypt *rh)
{
	if (!rh)
		return;

	LUKS2_reencrypt_protection_erase(&rh->rp);
	LUKS2_reencrypt_protection_erase(&rh->rp_moved_segment);

	json_object_put(rh->jobj_segs_hot);
	rh->jobj_segs_hot = NULL;
	json_object_put(rh->jobj_segs_post);
	rh->jobj_segs_post = NULL;
	json_object_put(rh->jobj_segment_old);
	rh->jobj_segment_old = NULL;
	json_object_put(rh->jobj_segment_new);
	rh->jobj_segment_new = NULL;
	json_object_put(rh->jobj_segment_moved);
	rh->jobj_segment_moved = NULL;

	free(rh->reenc_buffer);
	rh->reenc_buffer = NULL;
	crypt_storage_wrapper_destroy(rh->cw1);
	rh->cw1 = NULL;
	crypt_storage_wrapper_destroy(rh->cw2);
	rh->cw2 = NULL;

	free(rh->device_name);
	free(rh->overlay_name);
	free(rh->hotzone_name);
	crypt_drop_uploaded_keyring_key(cd, rh->vks);
	crypt_free_volume_key(rh->vks);
	device_release_excl(cd, crypt_data_device(cd));
	crypt_unlock_internal(cd, rh->reenc_lock);
	free(rh);
}

#if USE_LUKS2_REENCRYPTION
int LUKS2_reencrypt_max_hotzone_size(struct crypt_device *cd __attribute__((unused)),
	struct luks2_hdr *hdr,
	const struct reenc_protection *rp,
	int reencrypt_keyslot,
	uint64_t *r_length)
{
	int r;
	uint64_t dummy, area_length;

	assert(hdr);
	assert(rp);
	assert(r_length);

	if (rp->type <= REENC_PROTECTION_NONE) {
		*r_length = LUKS2_REENCRYPT_MAX_HOTZONE_LENGTH;
		return 0;
	}

	if (rp->type == REENC_PROTECTION_DATASHIFT) {
		*r_length = rp->p.ds.data_shift;
		return 0;
	}

	r = LUKS2_keyslot_area(hdr, reencrypt_keyslot, &dummy, &area_length);
	if (r < 0)
		return -EINVAL;

	if (rp->type == REENC_PROTECTION_JOURNAL) {
		*r_length = area_length;
		return 0;
	}

	if (rp->type == REENC_PROTECTION_CHECKSUM) {
		*r_length = (area_length / rp->p.csum.hash_size) * rp->p.csum.block_size;
		return 0;
	}

	return -EINVAL;
}

static size_t reencrypt_get_alignment(struct crypt_device *cd,
		struct luks2_hdr *hdr)
{
	size_t ss, alignment = device_block_size(cd, crypt_data_device(cd));

	ss = reencrypt_get_sector_size_old(hdr);
	if (ss > alignment)
		alignment = ss;
	ss = reencrypt_get_sector_size_new(hdr);
	if (ss > alignment)
		alignment = ss;

	return alignment;
}

/* returns void because it must not fail on valid LUKS2 header */
static void _load_backup_segments(struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, "backup-final");

	if (segment >= 0) {
		rh->jobj_segment_new = json_object_get(LUKS2_get_segment_jobj(hdr, segment));
		rh->digest_new = LUKS2_digest_by_segment(hdr, segment);
	} else {
		rh->jobj_segment_new = NULL;
		rh->digest_new = -ENOENT;
	}

	segment = LUKS2_get_segment_id_by_flag(hdr, "backup-previous");
	if (segment >= 0) {
		rh->jobj_segment_old = json_object_get(LUKS2_get_segment_jobj(hdr, segment));
		rh->digest_old = LUKS2_digest_by_segment(hdr, segment);
	} else {
		rh->jobj_segment_old = NULL;
		rh->digest_old = -ENOENT;
	}

	segment = LUKS2_get_segment_id_by_flag(hdr, "backup-moved-segment");
	if (segment >= 0)
		rh->jobj_segment_moved = json_object_get(LUKS2_get_segment_jobj(hdr, segment));
	else
		rh->jobj_segment_moved = NULL;
}

static int reencrypt_offset_backward_moved(struct luks2_hdr *hdr, json_object *jobj_segments,
					   uint64_t *reencrypt_length, uint64_t data_shift, uint64_t *offset)
{
	uint64_t tmp, linear_length = 0;
	int sg, segs = json_segments_count(jobj_segments);

	/* find reencrypt offset with data shift */
	for (sg = 0; sg < segs; sg++)
		if (LUKS2_segment_is_type(hdr, sg, "linear"))
			linear_length += LUKS2_segment_size(hdr, sg, 0);

	/* all active linear segments length */
	if (linear_length && segs > 1) {
		if (linear_length < data_shift)
			return -EINVAL;
		tmp = linear_length - data_shift;
		if (tmp && tmp < data_shift) {
			*offset = data_shift;
			*reencrypt_length = tmp;
		} else
			*offset = tmp;
		return 0;
	}

	if (segs == 1) {
		*offset = 0;
		return 0;
	}

	/* should be unreachable */

	return -EINVAL;
}

static int reencrypt_offset_forward_moved(struct luks2_hdr *hdr,
	uint64_t data_shift,
	uint64_t *offset)
{
	int last_crypt = LUKS2_last_segment_by_type(hdr, "crypt");

	/* if last crypt segment exists and it's first one, just return offset = 0 */
	if (last_crypt <= 0) {
		*offset = 0;
		return 0;
	}

	*offset = LUKS2_segment_offset(hdr, last_crypt, 0) - data_shift;
	return 0;
}

static int _offset_forward(json_object *jobj_segments, uint64_t *offset)
{
	int segs = json_segments_count(jobj_segments);

	if (segs == 1)
		*offset = 0;
	else if (segs == 2) {
		*offset = json_segment_get_size(json_segments_get_segment(jobj_segments, 0), 0);
		if (!*offset)
			return -EINVAL;
	} else
		return -EINVAL;

	return 0;
}

static int _offset_backward(json_object *jobj_segments, uint64_t device_size, uint64_t *length, uint64_t *offset)
{
	int segs = json_segments_count(jobj_segments);
	uint64_t tmp;

	if (segs == 1) {
		if (device_size < *length)
			*length = device_size;
		*offset = device_size - *length;
	} else if (segs == 2) {
		tmp = json_segment_get_size(json_segments_get_segment(jobj_segments, 0), 0);
		if (tmp < *length)
			*length = tmp;
		*offset =  tmp - *length;
	} else
		return -EINVAL;

	return 0;
}

/* must be always relative to data offset */
/* the LUKS2 header MUST be valid */
static int reencrypt_offset(struct luks2_hdr *hdr,
		crypt_reencrypt_direction_info di,
		uint64_t device_size,
		uint64_t *reencrypt_length,
		uint64_t *offset)
{
	int r, sg;
	json_object *jobj_segments;
	uint64_t data_shift = reencrypt_data_shift(hdr);

	if (!offset)
		return -EINVAL;

	/* if there's segment in reencryption return directly offset of it */
	json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments);
	sg = json_segments_segment_in_reencrypt(jobj_segments);
	if (sg >= 0) {
		*offset = LUKS2_segment_offset(hdr, sg, 0) - (reencrypt_get_data_offset_new(hdr));
		return 0;
	}

	if (di == CRYPT_REENCRYPT_FORWARD) {
		if (reencrypt_mode(hdr) == CRYPT_REENCRYPT_DECRYPT &&
		    LUKS2_get_segment_id_by_flag(hdr, "backup-moved-segment") >= 0) {
			r = reencrypt_offset_forward_moved(hdr, data_shift, offset);
			if (!r && *offset > device_size)
				*offset = device_size;
			return r;
		}
		return _offset_forward(jobj_segments, offset);
	} else if (di == CRYPT_REENCRYPT_BACKWARD) {
		if (reencrypt_mode(hdr) == CRYPT_REENCRYPT_ENCRYPT &&
		    LUKS2_get_segment_id_by_flag(hdr, "backup-moved-segment") >= 0)
			return reencrypt_offset_backward_moved(hdr, jobj_segments, reencrypt_length, data_shift, offset);
		return _offset_backward(jobj_segments, device_size, reencrypt_length, offset);
	}

	return -EINVAL;
}

static uint64_t reencrypt_length(struct crypt_device *cd,
		struct reenc_protection *rp,
		uint64_t keyslot_area_length,
		uint64_t length_max,
		size_t alignment)
{
	unsigned long dummy, optimal_alignment;
	uint64_t length, soft_mem_limit;

	if (rp->type == REENC_PROTECTION_NONE)
		length = length_max ?: LUKS2_DEFAULT_NONE_REENCRYPTION_LENGTH;
	else if (rp->type == REENC_PROTECTION_CHECKSUM)
		length = (keyslot_area_length / rp->p.csum.hash_size) * rp->p.csum.block_size;
	else if (rp->type == REENC_PROTECTION_DATASHIFT)
		return rp->p.ds.data_shift;
	else
		length = keyslot_area_length;

	/* hard limit */
	if (length > LUKS2_REENCRYPT_MAX_HOTZONE_LENGTH)
		length = LUKS2_REENCRYPT_MAX_HOTZONE_LENGTH;

	/* soft limit is 1/4 of system memory */
	soft_mem_limit = crypt_getphysmemory_kb() << 8; /* multiply by (1024/4) */

	if (soft_mem_limit && length > soft_mem_limit)
		length = soft_mem_limit;

	if (length_max && length > length_max)
		length = length_max;

	length -= (length % alignment);

	/* Emits error later */
	if (!length)
		return length;

	device_topology_alignment(cd, crypt_data_device(cd), &optimal_alignment, &dummy, length);

	/* we have to stick with encryption sector size alignment */
	if (optimal_alignment % alignment)
		return length;

	/* align to opt-io size only if remaining size allows it */
	if (length > optimal_alignment)
		length -= (length % optimal_alignment);

	return length;
}

static int reencrypt_context_init(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reencrypt *rh,
	uint64_t device_size,
	uint64_t max_hotzone_size,
	uint64_t fixed_device_size)
{
	int r;
	size_t alignment;
	uint64_t dummy, area_length;

	rh->reenc_keyslot = LUKS2_find_keyslot(hdr, "reencrypt");
	if (rh->reenc_keyslot < 0)
		return -EINVAL;
	if (LUKS2_keyslot_area(hdr, rh->reenc_keyslot, &dummy, &area_length) < 0)
		return -EINVAL;

	rh->mode = reencrypt_mode(hdr);

	rh->direction = reencrypt_direction(hdr);

	r = LUKS2_keyslot_reencrypt_load(cd, hdr, rh->reenc_keyslot, &rh->rp, true);
	if (r < 0)
		return r;

	if (rh->rp.type == REENC_PROTECTION_CHECKSUM)
		alignment = rh->rp.p.csum.block_size;
	else
		alignment = reencrypt_get_alignment(cd, hdr);

	if (!alignment)
		return -EINVAL;

	if ((max_hotzone_size << SECTOR_SHIFT) % alignment) {
		log_err(cd, _("Hotzone size must be multiple of calculated zone alignment (%zu bytes)."), alignment);
		return -EINVAL;
	}

	if ((fixed_device_size << SECTOR_SHIFT) % alignment) {
		log_err(cd, _("Device size must be multiple of calculated zone alignment (%zu bytes)."), alignment);
		return -EINVAL;
	}

	if (fixed_device_size) {
		log_dbg(cd, "Switching reencryption to fixed size mode.");
		device_size = fixed_device_size << SECTOR_SHIFT;
		rh->fixed_length = true;
	} else
		rh->fixed_length = false;

	rh->length = reencrypt_length(cd, &rh->rp, area_length, max_hotzone_size << SECTOR_SHIFT, alignment);
	if (!rh->length) {
		log_dbg(cd, "Invalid reencryption length.");
		return -EINVAL;
	}

	if (reencrypt_offset(hdr, rh->direction, device_size, &rh->length, &rh->offset)) {
		log_dbg(cd, "Failed to get reencryption offset.");
		return -EINVAL;
	}

	if (rh->offset > device_size)
		return -EINVAL;
	if (rh->length > device_size - rh->offset)
		rh->length = device_size - rh->offset;

	_load_backup_segments(hdr, rh);

	r = LUKS2_keyslot_reencrypt_load(cd, hdr, rh->reenc_keyslot, &rh->rp_moved_segment, false);
	if (r < 0)
		return r;

	if (rh->rp_moved_segment.type == REENC_PROTECTION_NOT_SET)
		log_dbg(cd, "No moved segment resilience configured.");

	if (rh->direction == CRYPT_REENCRYPT_BACKWARD)
		rh->progress = device_size - rh->offset - rh->length;
	else if (rh->jobj_segment_moved && rh->direction == CRYPT_REENCRYPT_FORWARD) {
		if (rh->offset == json_segment_get_offset(LUKS2_get_segment_by_flag(hdr, "backup-moved-segment"), false))
			rh->progress = device_size - json_segment_get_size(LUKS2_get_segment_by_flag(hdr, "backup-moved-segment"), false);
		else
			rh->progress = rh->offset - json_segment_get_size(rh->jobj_segment_moved, 0);
	} else
		rh->progress = rh->offset;

	log_dbg(cd, "reencrypt-direction: %s", rh->direction == CRYPT_REENCRYPT_FORWARD ? "forward" : "backward");
	log_dbg(cd, "backup-previous digest id: %d", rh->digest_old);
	log_dbg(cd, "backup-final digest id: %d", rh->digest_new);
	log_dbg(cd, "reencrypt length: %" PRIu64, rh->length);
	log_dbg(cd, "reencrypt offset: %" PRIu64, rh->offset);
	log_dbg(cd, "reencrypt shift: %s%" PRIu64,
		(rh->rp.type == REENC_PROTECTION_DATASHIFT && rh->direction == CRYPT_REENCRYPT_BACKWARD ? "-" : ""),
		data_shift_value(&rh->rp));
	log_dbg(cd, "reencrypt alignment: %zu", alignment);
	log_dbg(cd, "reencrypt progress: %" PRIu64, rh->progress);

	rh->device_size = device_size;

	return rh->length < 512 ? -EINVAL : 0;
}

static size_t reencrypt_buffer_length(struct luks2_reencrypt *rh)
{
	if (rh->rp.type == REENC_PROTECTION_DATASHIFT)
		return data_shift_value(&rh->rp);
	return rh->length;
}

static int reencrypt_load_clean(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint64_t device_size,
	uint64_t max_hotzone_size,
	uint64_t fixed_device_size,
	struct luks2_reencrypt **rh)
{
	int r;
	struct luks2_reencrypt *tmp = crypt_zalloc(sizeof (*tmp));

	if (!tmp)
		return -ENOMEM;

	log_dbg(cd, "Loading stored reencryption context.");

	r = reencrypt_context_init(cd, hdr, tmp, device_size, max_hotzone_size, fixed_device_size);
	if (r)
		goto err;

	if (posix_memalign(&tmp->reenc_buffer, device_alignment(crypt_data_device(cd)),
			   reencrypt_buffer_length(tmp))) {
		r = -ENOMEM;
		goto err;
	}

	*rh = tmp;

	return 0;
err:
	LUKS2_reencrypt_free(cd, tmp);

	return r;
}

static int reencrypt_make_segments(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reencrypt *rh,
	uint64_t device_size)
{
	int r;
	uint64_t data_offset = reencrypt_get_data_offset_new(hdr);

	log_dbg(cd, "Calculating segments.");

	r = reencrypt_make_hot_segments(cd, hdr, rh, device_size, data_offset);
	if (!r) {
		r = reencrypt_make_post_segments(cd, hdr, rh, data_offset);
		if (r)
			json_object_put(rh->jobj_segs_hot);
	}

	if (r)
		log_dbg(cd, "Failed to make reencryption segments.");

	return r;
}

static int reencrypt_make_segments_crashed(struct crypt_device *cd,
				struct luks2_hdr *hdr,
			        struct luks2_reencrypt *rh)
{
	int r;
	uint64_t data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;

	if (!rh)
		return -EINVAL;

	rh->jobj_segs_hot = json_object_new_object();
	if (!rh->jobj_segs_hot)
		return -ENOMEM;

	json_object_object_foreach(LUKS2_get_segments_jobj(hdr), key, val) {
		if (json_segment_is_backup(val))
			continue;
		json_object_object_add(rh->jobj_segs_hot, key, json_object_get(val));
	}

	r = reencrypt_make_post_segments(cd, hdr, rh, data_offset);
	if (r) {
		json_object_put(rh->jobj_segs_hot);
		rh->jobj_segs_hot = NULL;
	}

	return r;
}

static int reencrypt_load_crashed(struct crypt_device *cd,
	struct luks2_hdr *hdr, uint64_t device_size, struct luks2_reencrypt **rh)
{
	bool dynamic;
	uint64_t required_device_size;
	int r, reenc_seg;

	if (LUKS2_get_data_size(hdr, &required_device_size, &dynamic))
		return -EINVAL;

	if (dynamic)
		required_device_size = 0;
	else
		required_device_size >>= SECTOR_SHIFT;

	r = reencrypt_load_clean(cd, hdr, device_size, 0, required_device_size, rh);

	if (!r) {
		reenc_seg = json_segments_segment_in_reencrypt(LUKS2_get_segments_jobj(hdr));
		if (reenc_seg < 0)
			r = -EINVAL;
		else
			(*rh)->length = LUKS2_segment_size(hdr, reenc_seg, 0);
	}

	if (!r)
		r = reencrypt_make_segments_crashed(cd, hdr, *rh);

	if (r) {
		LUKS2_reencrypt_free(cd, *rh);
		*rh = NULL;
	}
	return r;
}

static int reencrypt_init_storage_wrappers(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh,
		struct volume_key *vks)
{
	int r;
	struct volume_key *vk;
	uint32_t wrapper_flags = (getuid() || geteuid()) ? 0 : DISABLE_KCAPI;

	vk = crypt_volume_key_by_id(vks, rh->digest_old);
	r = crypt_storage_wrapper_init(cd, &rh->cw1, crypt_data_device(cd),
			reencrypt_get_data_offset_old(hdr),
			crypt_get_iv_offset(cd),
			reencrypt_get_sector_size_old(hdr),
			reencrypt_segment_cipher_old(hdr),
			vk, wrapper_flags | OPEN_READONLY);
	if (r) {
		log_err(cd, _("Failed to initialize old segment storage wrapper."));
		return r;
	}
	rh->wflags1 = wrapper_flags | OPEN_READONLY;
	log_dbg(cd, "Old cipher storage wrapper type: %d.", crypt_storage_wrapper_get_type(rh->cw1));

	vk = crypt_volume_key_by_id(vks, rh->digest_new);
	r = crypt_storage_wrapper_init(cd, &rh->cw2, crypt_data_device(cd),
			reencrypt_get_data_offset_new(hdr),
			crypt_get_iv_offset(cd),
			reencrypt_get_sector_size_new(hdr),
			reencrypt_segment_cipher_new(hdr),
			vk, wrapper_flags);
	if (r) {
		log_err(cd, _("Failed to initialize new segment storage wrapper."));
		return r;
	}
	rh->wflags2 = wrapper_flags;
	log_dbg(cd, "New cipher storage wrapper type: %d", crypt_storage_wrapper_get_type(rh->cw2));

	return 0;
}

static int reencrypt_context_set_names(struct luks2_reencrypt *rh, const char *name)
{
	if (!rh || !name)
		return -EINVAL;

	if (*name == '/') {
		if (!(rh->device_name = dm_device_name(name)))
			return -EINVAL;
	} else if (!(rh->device_name = strdup(name)))
		return -ENOMEM;

	if (asprintf(&rh->hotzone_name, "%s-hotzone-%s", rh->device_name,
		     rh->direction == CRYPT_REENCRYPT_FORWARD ? "forward" : "backward") < 0) {
		rh->hotzone_name = NULL;
		return -ENOMEM;
	}
	if (asprintf(&rh->overlay_name, "%s-overlay", rh->device_name) < 0) {
		rh->overlay_name = NULL;
		return -ENOMEM;
	}

	rh->online = true;
	return 0;
}

static int modify_offset(uint64_t *offset, uint64_t data_shift, crypt_reencrypt_direction_info di)
{
	int r = -EINVAL;

	if (!offset)
		return r;

	if (di == CRYPT_REENCRYPT_FORWARD) {
		if (*offset >= data_shift) {
			*offset -= data_shift;
			r = 0;
		}
	} else if (di == CRYPT_REENCRYPT_BACKWARD) {
		*offset += data_shift;
		r = 0;
	}

	return r;
}

static int reencrypt_update_flag(struct crypt_device *cd, uint8_t version,
	bool enable, bool commit)
{
	uint32_t reqs;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	if (enable) {
		log_dbg(cd, "Going to store reencryption requirement flag (version: %u).", version);
		return LUKS2_config_set_requirement_version(cd, hdr, CRYPT_REQUIREMENT_ONLINE_REENCRYPT, version, commit);
	}

	LUKS2_config_get_requirements(cd, hdr, &reqs);

	reqs &= ~CRYPT_REQUIREMENT_ONLINE_REENCRYPT;

	log_dbg(cd, "Going to wipe reencryption requirement flag.");

	return LUKS2_config_set_requirements(cd, hdr, reqs, commit);
}

static int reencrypt_hotzone_protect_ready(struct crypt_device *cd,
	struct reenc_protection *rp)
{
	assert(rp);

	if (rp->type == REENC_PROTECTION_NOT_SET)
		return -EINVAL;

	if (rp->type != REENC_PROTECTION_CHECKSUM)
		return 0;

	if (!rp->p.csum.checksums) {
		log_dbg(cd, "Allocating buffer for storing resilience checksums.");
		if (posix_memalign(&rp->p.csum.checksums, device_alignment(crypt_metadata_device(cd)),
				   rp->p.csum.checksums_len))
			return -ENOMEM;
	}

	return 0;
}

static int reencrypt_recover_segment(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reencrypt *rh,
	struct volume_key *vks)
{
	struct volume_key *vk_old, *vk_new;
	size_t count, s;
	ssize_t read, w;
	struct reenc_protection *rp;
	int devfd, r, new_sector_size, old_sector_size, rseg;
	uint64_t area_offset, area_length, area_length_read, crash_iv_offset,
		 data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;
	char *checksum_tmp = NULL, *data_buffer = NULL;
	struct crypt_storage_wrapper *cw1 = NULL, *cw2 = NULL;

	assert(hdr);
	assert(rh);
	assert(vks);

	rseg = json_segments_segment_in_reencrypt(rh->jobj_segs_hot);
	if (rh->offset == 0 && rh->rp_moved_segment.type > REENC_PROTECTION_NOT_SET) {
		log_dbg(cd, "Recovery using moved segment protection.");
		rp = &rh->rp_moved_segment;
	} else
		rp = &rh->rp;

	if (rseg < 0 || rh->length < 512)
		return -EINVAL;

	r = reencrypt_hotzone_protect_ready(cd, rp);
	if (r) {
		log_err(cd, _("Failed to initialize hotzone protection."));
		return -EINVAL;
	}

	vk_new = crypt_volume_key_by_id(vks, rh->digest_new);
	if (!vk_new && rh->mode != CRYPT_REENCRYPT_DECRYPT)
		return -EINVAL;
	vk_old = crypt_volume_key_by_id(vks, rh->digest_old);
	if (!vk_old && rh->mode != CRYPT_REENCRYPT_ENCRYPT)
		return -EINVAL;
	old_sector_size = json_segment_get_sector_size(reencrypt_segment_old(hdr));
	new_sector_size = json_segment_get_sector_size(reencrypt_segment_new(hdr));
	if (rh->mode == CRYPT_REENCRYPT_DECRYPT)
		crash_iv_offset = rh->offset >> SECTOR_SHIFT; /* TODO: + old iv_tweak */
	else
		crash_iv_offset = json_segment_get_iv_offset(json_segments_get_segment(rh->jobj_segs_hot, rseg));

	log_dbg(cd, "crash_offset: %" PRIu64 ", crash_length: %" PRIu64 ",  crash_iv_offset: %" PRIu64,
		data_offset + rh->offset, rh->length, crash_iv_offset);

	r = crypt_storage_wrapper_init(cd, &cw2, crypt_data_device(cd),
			data_offset + rh->offset, crash_iv_offset, new_sector_size,
			reencrypt_segment_cipher_new(hdr), vk_new, 0);
	if (r) {
		log_err(cd, _("Failed to initialize new segment storage wrapper."));
		return r;
	}

	if (LUKS2_keyslot_area(hdr, rh->reenc_keyslot, &area_offset, &area_length)) {
		r = -EINVAL;
		goto out;
	}

	if (posix_memalign((void**)&data_buffer, device_alignment(crypt_data_device(cd)), rh->length)) {
		r = -ENOMEM;
		goto out;
	}

	switch (rp->type) {
	case  REENC_PROTECTION_CHECKSUM:
		log_dbg(cd, "Checksums based recovery.");

		r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
				data_offset + rh->offset, crash_iv_offset, old_sector_size,
				reencrypt_segment_cipher_old(hdr), vk_old, 0);
		if (r) {
			log_err(cd, _("Failed to initialize old segment storage wrapper."));
			goto out;
		}

		count = rh->length / rp->p.csum.block_size;
		area_length_read = count * rp->p.csum.hash_size;
		if (area_length_read > area_length) {
			log_dbg(cd, "Internal error in calculated area_length.");
			r = -EINVAL;
			goto out;
		}

		checksum_tmp = malloc(rp->p.csum.hash_size);
		if (!checksum_tmp) {
			r = -ENOMEM;
			goto out;
		}

		/* TODO: lock for read */
		devfd = device_open(cd, crypt_metadata_device(cd), O_RDONLY);
		if (devfd < 0)
			goto out;

		/* read old data checksums */
		read = read_lseek_blockwise(devfd, device_block_size(cd, crypt_metadata_device(cd)),
					device_alignment(crypt_metadata_device(cd)), rp->p.csum.checksums, area_length_read, area_offset);
		if (read < 0 || (size_t)read != area_length_read) {
			log_err(cd, _("Failed to read checksums for current hotzone."));
			r = -EINVAL;
			goto out;
		}

		read = crypt_storage_wrapper_read(cw2, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_err(cd, _("Failed to read hotzone area starting at %" PRIu64 "."), rh->offset + data_offset);
			r = -EINVAL;
			goto out;
		}

		for (s = 0; s < count; s++) {
			if (crypt_hash_write(rp->p.csum.ch, data_buffer + (s * rp->p.csum.block_size), rp->p.csum.block_size)) {
				log_dbg(cd, "Failed to write hash.");
				r = EINVAL;
				goto out;
			}
			if (crypt_hash_final(rp->p.csum.ch, checksum_tmp, rp->p.csum.hash_size)) {
				log_dbg(cd, "Failed to finalize hash.");
				r = EINVAL;
				goto out;
			}
			if (!memcmp(checksum_tmp, (char *)rp->p.csum.checksums + (s * rp->p.csum.hash_size), rp->p.csum.hash_size)) {
				log_dbg(cd, "Sector %zu (size %zu, offset %zu) needs recovery", s, rp->p.csum.block_size, s * rp->p.csum.block_size);
				if (crypt_storage_wrapper_decrypt(cw1, s * rp->p.csum.block_size, data_buffer + (s * rp->p.csum.block_size), rp->p.csum.block_size)) {
					log_err(cd, _("Failed to decrypt sector %zu."), s);
					r = -EINVAL;
					goto out;
				}
				w = crypt_storage_wrapper_encrypt_write(cw2, s * rp->p.csum.block_size, data_buffer + (s * rp->p.csum.block_size), rp->p.csum.block_size);
				if (w < 0 || (size_t)w != rp->p.csum.block_size) {
					log_err(cd, _("Failed to recover sector %zu."), s);
					r = -EINVAL;
					goto out;
				}
			}
		}

		r = 0;
		break;
	case  REENC_PROTECTION_JOURNAL:
		log_dbg(cd, "Journal based recovery.");

		/* FIXME: validation candidate */
		if (rh->length > area_length) {
			r = -EINVAL;
			log_dbg(cd, "Invalid journal size.");
			goto out;
		}

		/* TODO locking */
		r = crypt_storage_wrapper_init(cd, &cw1, crypt_metadata_device(cd),
				area_offset, crash_iv_offset, old_sector_size,
				reencrypt_segment_cipher_old(hdr), vk_old, 0);
		if (r) {
			log_err(cd, _("Failed to initialize old segment storage wrapper."));
			goto out;
		}
		read = crypt_storage_wrapper_read_decrypt(cw1, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "Failed to read journaled data.");
			r = -EIO;
			/* may content plaintext */
			crypt_safe_memzero(data_buffer, rh->length);
			goto out;
		}
		read = crypt_storage_wrapper_encrypt_write(cw2, 0, data_buffer, rh->length);
		/* may content plaintext */
		crypt_safe_memzero(data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "recovery write failed.");
			r = -EINVAL;
			goto out;
		}

		r = 0;
		break;
	case  REENC_PROTECTION_DATASHIFT:
		log_dbg(cd, "Data shift based recovery.");

		if (rseg == 0) {
			r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
					json_segment_get_offset(rh->jobj_segment_moved, 0), 0,
					reencrypt_get_sector_size_old(hdr),
					reencrypt_segment_cipher_old(hdr), vk_old, 0);
		} else {
			if (rh->direction == CRYPT_REENCRYPT_FORWARD)
				data_offset = data_offset + rh->offset + data_shift_value(rp);
			else
				data_offset = data_offset + rh->offset - data_shift_value(rp);
			r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
					data_offset,
					crash_iv_offset,
					reencrypt_get_sector_size_old(hdr),
					reencrypt_segment_cipher_old(hdr), vk_old, 0);
		}
		if (r) {
			log_err(cd, _("Failed to initialize old segment storage wrapper."));
			goto out;
		}

		read = crypt_storage_wrapper_read_decrypt(cw1, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "Failed to read data.");
			r = -EIO;
			/* may content plaintext */
			crypt_safe_memzero(data_buffer, rh->length);
			goto out;
		}

		read = crypt_storage_wrapper_encrypt_write(cw2, 0, data_buffer, rh->length);
		/* may content plaintext */
		crypt_safe_memzero(data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "recovery write failed.");
			r = -EINVAL;
			goto out;
		}
		r = 0;
		break;
	default:
		r = -EINVAL;
	}

	if (!r)
		rh->read = rh->length;
out:
	free(data_buffer);
	free(checksum_tmp);
	crypt_storage_wrapper_destroy(cw1);
	crypt_storage_wrapper_destroy(cw2);

	return r;
}

static int reencrypt_add_moved_segment(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reencrypt *rh)
{
	int digest = rh->digest_old, s = LUKS2_segment_first_unused_id(hdr);

	if (!rh->jobj_segment_moved)
		return 0;

	if (s < 0)
		return s;

	if (json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), s, json_object_get(rh->jobj_segment_moved))) {
		json_object_put(rh->jobj_segment_moved);
		return -EINVAL;
	}

	if (!strcmp(json_segment_type(rh->jobj_segment_moved), "crypt"))
		return LUKS2_digest_segment_assign(cd, hdr, s, digest, 1, 0);

	return 0;
}

static int reencrypt_add_backup_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh,
		unsigned final)
{
	int digest, s = LUKS2_segment_first_unused_id(hdr);
	json_object *jobj;

	if (s < 0)
		return s;

	digest = final ? rh->digest_new : rh->digest_old;
	jobj = final ? rh->jobj_segment_new : rh->jobj_segment_old;

	if (json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), s, json_object_get(jobj))) {
		json_object_put(jobj);
		return -EINVAL;
	}

	if (strcmp(json_segment_type(jobj), "crypt"))
		return 0;

	return LUKS2_digest_segment_assign(cd, hdr, s, digest, 1, 0);
}

static int reencrypt_assign_segments_simple(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reencrypt *rh,
	unsigned hot,
	unsigned commit)
{
	int r, sg;

	if (hot && json_segments_count(rh->jobj_segs_hot) > 0) {
		log_dbg(cd, "Setting 'hot' segments.");

		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_hot, 0);
		if (!r)
			rh->jobj_segs_hot = NULL;
	} else if (!hot && json_segments_count(rh->jobj_segs_post) > 0) {
		log_dbg(cd, "Setting 'post' segments.");
		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_post, 0);
		if (!r)
			rh->jobj_segs_post = NULL;
	} else {
		log_dbg(cd, "No segments to set.");
		return -EINVAL;
	}

	if (r) {
		log_dbg(cd, "Failed to assign new enc segments.");
		return r;
	}

	r = reencrypt_add_backup_segment(cd, hdr, rh, 0);
	if (r) {
		log_dbg(cd, "Failed to assign reencryption previous backup segment.");
		return r;
	}

	r = reencrypt_add_backup_segment(cd, hdr, rh, 1);
	if (r) {
		log_dbg(cd, "Failed to assign reencryption final backup segment.");
		return r;
	}

	r = reencrypt_add_moved_segment(cd, hdr, rh);
	if (r) {
		log_dbg(cd, "Failed to assign reencryption moved backup segment.");
		return r;
	}

	for (sg = 0; sg < LUKS2_segments_count(hdr); sg++) {
		if (LUKS2_segment_is_type(hdr, sg, "crypt") &&
		    LUKS2_digest_segment_assign(cd, hdr, sg, rh->mode == CRYPT_REENCRYPT_ENCRYPT ? rh->digest_new : rh->digest_old, 1, 0)) {
			log_dbg(cd, "Failed to assign digest %u to segment %u.", rh->digest_new, sg);
			return -EINVAL;
		}
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

static int reencrypt_assign_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh,
		unsigned hot,
		unsigned commit)
{
	bool forward;
	int rseg, scount, r = -EINVAL;

	/* FIXME: validate in reencrypt context load */
	if (rh->digest_new < 0 && rh->mode != CRYPT_REENCRYPT_DECRYPT)
		return -EINVAL;

	if (LUKS2_digest_segment_assign(cd, hdr, CRYPT_ANY_SEGMENT, CRYPT_ANY_DIGEST, 0, 0))
		return -EINVAL;

	if (rh->mode == CRYPT_REENCRYPT_ENCRYPT || rh->mode == CRYPT_REENCRYPT_DECRYPT)
		return reencrypt_assign_segments_simple(cd, hdr, rh, hot, commit);

	if (hot && rh->jobj_segs_hot) {
		log_dbg(cd, "Setting 'hot' segments.");

		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_hot, 0);
		if (!r)
			rh->jobj_segs_hot = NULL;
	} else if (!hot && rh->jobj_segs_post) {
		log_dbg(cd, "Setting 'post' segments.");
		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_post, 0);
		if (!r)
			rh->jobj_segs_post = NULL;
	}

	if (r)
		return r;

	scount = LUKS2_segments_count(hdr);

	/* segment in reencryption has to hold reference on both digests */
	rseg = json_segments_segment_in_reencrypt(LUKS2_get_segments_jobj(hdr));
	if (rseg < 0 && hot)
		return -EINVAL;

	if (rseg >= 0) {
		LUKS2_digest_segment_assign(cd, hdr, rseg, rh->digest_new, 1, 0);
		LUKS2_digest_segment_assign(cd, hdr, rseg, rh->digest_old, 1, 0);
	}

	forward = (rh->direction == CRYPT_REENCRYPT_FORWARD);
	if (hot) {
		if (rseg > 0)
			LUKS2_digest_segment_assign(cd, hdr, 0, forward ? rh->digest_new : rh->digest_old, 1, 0);
		if (scount > rseg + 1)
			LUKS2_digest_segment_assign(cd, hdr, rseg + 1, forward ? rh->digest_old : rh->digest_new, 1, 0);
	} else {
		LUKS2_digest_segment_assign(cd, hdr, 0, forward || scount == 1 ? rh->digest_new : rh->digest_old, 1, 0);
		if (scount > 1)
			LUKS2_digest_segment_assign(cd, hdr, 1, forward ? rh->digest_old : rh->digest_new, 1, 0);
	}

	r = reencrypt_add_backup_segment(cd, hdr, rh, 0);
	if (r) {
		log_dbg(cd, "Failed to assign hot reencryption backup segment.");
		return r;
	}
	r = reencrypt_add_backup_segment(cd, hdr, rh, 1);
	if (r) {
		log_dbg(cd, "Failed to assign post reencryption backup segment.");
		return r;
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

static int reencrypt_set_encrypt_segments(struct crypt_device *cd, struct luks2_hdr *hdr,
					  uint64_t dev_size, uint64_t data_size, uint64_t data_shift, bool move_first_segment,
					  crypt_reencrypt_direction_info di)
{
	int r;
	uint64_t first_segment_offset, first_segment_length,
		 second_segment_offset, second_segment_length,
		 data_offset = LUKS2_get_data_offset(hdr) << SECTOR_SHIFT;
	json_object *jobj_segment_first = NULL, *jobj_segment_second = NULL, *jobj_segments;

	if (dev_size < data_shift)
		return -EINVAL;

	if (data_shift && (di == CRYPT_REENCRYPT_FORWARD))
		return -ENOTSUP;

	if (move_first_segment) {
		/*
		 * future data_device layout:
		 * [future LUKS2 header (data shift size)][second data segment][gap (data shift size)][first data segment (data shift size)]
		 */
		first_segment_offset = dev_size;
		if (data_size < data_shift) {
			first_segment_length = data_size;
			second_segment_length = second_segment_offset = 0;
		} else {
			first_segment_length = data_shift;
			second_segment_offset = data_shift;
			second_segment_length = data_size - data_shift;
		}
	} else if (data_shift) {
		first_segment_offset = data_offset;
		first_segment_length = dev_size;
	} else {
		/* future data_device layout with detached header: [first data segment] */
		first_segment_offset = data_offset;
		first_segment_length = 0; /* dynamic */
	}

	jobj_segments = json_object_new_object();
	if (!jobj_segments)
		return -ENOMEM;

	r = -EINVAL;
	if (move_first_segment) {
		jobj_segment_first =  json_segment_create_linear(first_segment_offset, &first_segment_length, 0);
		if (second_segment_length &&
		    !(jobj_segment_second = json_segment_create_linear(second_segment_offset, &second_segment_length, 0))) {
			log_dbg(cd, "Failed generate 2nd segment.");
			return r;
		}
	} else
		jobj_segment_first =  json_segment_create_linear(first_segment_offset, first_segment_length ? &first_segment_length : NULL, 0);

	if (!jobj_segment_first) {
		log_dbg(cd, "Failed generate 1st segment.");
		return r;
	}

	json_object_object_add(jobj_segments, "0", jobj_segment_first);
	if (jobj_segment_second)
		json_object_object_add(jobj_segments, "1", jobj_segment_second);

	r = LUKS2_digest_segment_assign(cd, hdr, CRYPT_ANY_SEGMENT, CRYPT_ANY_DIGEST, 0, 0);

	return r ?: LUKS2_segments_set(cd, hdr, jobj_segments, 0);
}

static int reencrypt_set_decrypt_shift_segments(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint64_t dev_size,
	uint64_t moved_segment_length,
	crypt_reencrypt_direction_info di)
{
	int digest, r;
	uint64_t data_offset = LUKS2_get_data_offset(hdr) << SECTOR_SHIFT;
	json_object *jobj_segment_first = NULL, *jobj_segment_second = NULL, *jobj_segments;

	if (di == CRYPT_REENCRYPT_BACKWARD)
		return -ENOTSUP;

	digest = LUKS2_digest_by_segment(hdr, CRYPT_DEFAULT_SEGMENT);
	if (digest < 0)
		return -EINVAL;

	/*
	 * future data_device layout:
	 * [encrypted first segment (max data shift size)][gap (data shift size)][second encrypted data segment]
	 */
	jobj_segments = json_object_new_object();
	if (!jobj_segments)
		return -ENOMEM;

	r = -EINVAL;
	jobj_segment_first = json_segment_create_crypt(0, crypt_get_iv_offset(cd),
				&moved_segment_length, crypt_get_cipher_spec(cd),
				NULL, 0, crypt_get_sector_size(cd), 0);

	if (!jobj_segment_first) {
		log_dbg(cd, "Failed generate 1st segment.");
		goto err;
	}

	r = json_object_object_add_by_uint_by_ref(jobj_segments, 0, &jobj_segment_first);
	if (r)
		goto err;

	if (dev_size > moved_segment_length) {
		jobj_segment_second = json_segment_create_crypt(data_offset + moved_segment_length,
								crypt_get_iv_offset(cd) + (moved_segment_length >> SECTOR_SHIFT),
								NULL,
								crypt_get_cipher_spec(cd),
								NULL, 0, /* integrity */
								crypt_get_sector_size(cd), 0);
		if (!jobj_segment_second) {
			r = -EINVAL;
			log_dbg(cd, "Failed generate 2nd segment.");
			goto err;
		}

		r = json_object_object_add_by_uint_by_ref(jobj_segments, 1, &jobj_segment_second);
		if (r)
			goto err;
	}

	if (!(r = LUKS2_segments_set(cd, hdr, jobj_segments, 0)))
		return LUKS2_digest_segment_assign(cd, hdr, CRYPT_ANY_SEGMENT, digest, 1, 0);
err:
	json_object_put(jobj_segment_first);
	json_object_put(jobj_segment_second);
	json_object_put(jobj_segments);
	return r;
}

static int reencrypt_make_targets(struct crypt_device *cd,
				struct luks2_hdr *hdr,
				struct device *hz_device,
				struct volume_key *vks,
				struct dm_target *result,
				uint64_t size)
{
	bool reenc_seg;
	struct volume_key *vk;
	uint64_t segment_size, segment_offset, segment_start = 0;
	int r;
	int s = 0;
	json_object *jobj, *jobj_segments = LUKS2_get_segments_jobj(hdr);

	while (result) {
		jobj = json_segments_get_segment(jobj_segments, s);
		if (!jobj) {
			log_dbg(cd, "Internal error. Segment %u is null.", s);
			return -EINVAL;
		}

		reenc_seg = (s == json_segments_segment_in_reencrypt(jobj_segments));

		segment_offset = json_segment_get_offset(jobj, 1);
		segment_size = json_segment_get_size(jobj, 1);
		/* 'dynamic' length allowed in last segment only */
		if (!segment_size && !result->next)
			segment_size = (size >> SECTOR_SHIFT) - segment_start;
		if (!segment_size) {
			log_dbg(cd, "Internal error. Wrong segment size %u", s);
			return -EINVAL;
		}

		if (reenc_seg)
			segment_offset -= crypt_get_data_offset(cd);

		if (!strcmp(json_segment_type(jobj), "crypt")) {
			vk = crypt_volume_key_by_id(vks, reenc_seg ? LUKS2_reencrypt_digest_new(hdr) : LUKS2_digest_by_segment(hdr, s));
			if (!vk) {
				log_err(cd, _("Missing key for dm-crypt segment %u"), s);
				return -EINVAL;
			}

			r = dm_crypt_target_set(result, segment_start, segment_size,
						reenc_seg ? hz_device : crypt_data_device(cd),
						vk,
						json_segment_get_cipher(jobj),
						json_segment_get_iv_offset(jobj),
						segment_offset,
						"none", 0, 0,
						json_segment_get_sector_size(jobj));
			if (r) {
				log_err(cd, _("Failed to set dm-crypt segment."));
				return r;
			}
		} else if (!strcmp(json_segment_type(jobj), "linear")) {
			r = dm_linear_target_set(result, segment_start, segment_size, reenc_seg ? hz_device : crypt_data_device(cd), segment_offset);
			if (r) {
				log_err(cd, _("Failed to set dm-linear segment."));
				return r;
			}
		} else
			return EINVAL;

		segment_start += segment_size;
		s++;
		result = result->next;
	}

	return s;
}

/* GLOBAL FIXME: audit function names and parameters names */

/* FIXME:
 * 	1) audit log routines
 * 	2) can't we derive hotzone device name from crypt context? (unlocked name, device uuid, etc?)
 */
static int reencrypt_load_overlay_device(struct crypt_device *cd, struct luks2_hdr *hdr,
	const char *overlay, const char *hotzone, struct volume_key *vks, uint64_t size,
	uint32_t flags)
{
	char hz_path[PATH_MAX];
	int r;

	struct device *hz_dev = NULL;
	struct crypt_dm_active_device dmd = {
		.flags = flags,
	};

	log_dbg(cd, "Loading new table for overlay device %s.", overlay);

	r = snprintf(hz_path, PATH_MAX, "%s/%s", dm_get_dir(), hotzone);
	if (r < 0 || r >= PATH_MAX) {
		r = -EINVAL;
		goto out;
	}

	r = device_alloc(cd, &hz_dev, hz_path);
	if (r)
		goto out;

	r = dm_targets_allocate(&dmd.segment, LUKS2_segments_count(hdr));
	if (r)
		goto out;

	r = reencrypt_make_targets(cd, hdr, hz_dev, vks, &dmd.segment, size);
	if (r < 0)
		goto out;

	r = dm_reload_device(cd, overlay, &dmd, 0, 0);

	/* what else on error here ? */
out:
	dm_targets_free(cd, &dmd);
	device_free(cd, hz_dev);

	return r;
}

static int reencrypt_replace_device(struct crypt_device *cd, const char *target, const char *source, uint32_t flags)
{
	int r, exists = 1;
	struct crypt_dm_active_device dmd_source, dmd_target = {};
	uint64_t dmflags = DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH;

	log_dbg(cd, "Replacing table in device %s with table from device %s.", target, source);

	/* check only whether target device exists */
	r = dm_status_device(cd, target);
	if (r < 0) {
		if (r == -ENODEV)
			exists = 0;
		else
			return r;
	}

	r = dm_query_device(cd, source, DM_ACTIVE_DEVICE | DM_ACTIVE_CRYPT_CIPHER |
			    DM_ACTIVE_CRYPT_KEYSIZE | DM_ACTIVE_CRYPT_KEY, &dmd_source);

	if (r < 0)
		return r;

	if (exists && ((r = dm_query_device(cd, target, 0, &dmd_target)) < 0))
		goto out;

	dmd_source.flags |= flags;
	dmd_source.uuid = crypt_get_uuid(cd);

	if (exists) {
		if (dmd_target.size != dmd_source.size) {
			log_err(cd, _("Source and target device sizes don't match. Source %" PRIu64 ", target: %" PRIu64 "."),
				dmd_source.size, dmd_target.size);
			r = -EINVAL;
			goto out;
		}
		r = dm_reload_device(cd, target, &dmd_source, 0, 0);
		if (!r) {
			log_dbg(cd, "Resuming device %s", target);
			r = dm_resume_device(cd, target, dmflags | act2dmflags(dmd_source.flags));
		}
	} else
		r = dm_create_device(cd, target, CRYPT_SUBDEV, &dmd_source);
out:
	dm_targets_free(cd, &dmd_source);
	dm_targets_free(cd, &dmd_target);

	return r;
}

static int reencrypt_swap_backing_device(struct crypt_device *cd, const char *name,
			      const char *new_backend_name)
{
	int r;
	struct device *overlay_dev = NULL;
	char overlay_path[PATH_MAX] = { 0 };
	struct crypt_dm_active_device dmd = {};

	log_dbg(cd, "Redirecting %s mapping to new backing device: %s.", name, new_backend_name);

	r = snprintf(overlay_path, PATH_MAX, "%s/%s", dm_get_dir(), new_backend_name);
	if (r < 0 || r >= PATH_MAX) {
		r = -EINVAL;
		goto out;
	}

	r = device_alloc(cd, &overlay_dev, overlay_path);
	if (r)
		goto out;

	r = device_block_adjust(cd, overlay_dev, DEV_OK,
				0, &dmd.size, &dmd.flags);
	if (r)
		goto out;

	r = dm_linear_target_set(&dmd.segment, 0, dmd.size, overlay_dev, 0);
	if (r)
		goto out;

	r = dm_reload_device(cd, name, &dmd, 0, 0);
	if (!r) {
		log_dbg(cd, "Resuming device %s", name);
		r = dm_resume_device(cd, name, DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH);
	}

out:
	dm_targets_free(cd, &dmd);
	device_free(cd, overlay_dev);

	return r;
}

static int reencrypt_activate_hotzone_device(struct crypt_device *cd, const char *name, uint64_t device_size, uint32_t flags)
{
	int r;
	uint64_t new_offset = reencrypt_get_data_offset_new(crypt_get_hdr(cd, CRYPT_LUKS2)) >> SECTOR_SHIFT;

	struct crypt_dm_active_device dmd = {
		.flags = flags,
		.uuid = crypt_get_uuid(cd),
		.size = device_size >> SECTOR_SHIFT
	};

	log_dbg(cd, "Activating hotzone device %s.", name);

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				new_offset, &dmd.size, &dmd.flags);
	if (r)
		goto out;

	r = dm_linear_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd), new_offset);
	if (r)
		goto out;

	r = dm_create_device(cd, name, CRYPT_SUBDEV, &dmd);
out:
	dm_targets_free(cd, &dmd);

	return r;
}

static int reencrypt_init_device_stack(struct crypt_device *cd,
		                     const struct luks2_reencrypt *rh)
{
	int r;

	/* Activate hotzone device 1:1 linear mapping to data_device */
	r = reencrypt_activate_hotzone_device(cd, rh->hotzone_name, rh->device_size, CRYPT_ACTIVATE_PRIVATE);
	if (r) {
		log_err(cd, _("Failed to activate hotzone device %s."), rh->hotzone_name);
		return r;
	}

	/*
	 * Activate overlay device with exactly same table as original 'name' mapping.
	 * Note that within this step the 'name' device may already include a table
	 * constructed from more than single dm-crypt segment. Therefore transfer
	 * mapping as is.
	 *
	 * If we're about to resume reencryption orig mapping has to be already validated for
	 * abrupt shutdown and rchunk_offset has to point on next chunk to reencrypt!
	 *
	 * TODO: in crypt_activate_by*
	 */
	r = reencrypt_replace_device(cd, rh->overlay_name, rh->device_name, CRYPT_ACTIVATE_PRIVATE);
	if (r) {
		log_err(cd, _("Failed to activate overlay device %s with actual origin table."), rh->overlay_name);
		goto err;
	}

	/* swap origin mapping to overlay device */
	r = reencrypt_swap_backing_device(cd, rh->device_name, rh->overlay_name);
	if (r) {
		log_err(cd, _("Failed to load new mapping for device %s."), rh->device_name);
		goto err;
	}

	/*
	 * Now the 'name' (unlocked luks) device is mapped via dm-linear to an overlay dev.
	 * The overlay device has a original live table of 'name' device in-before the swap.
	 */

	return 0;
err:
	/* TODO: force error helper devices on error path */
	dm_remove_device(cd, rh->overlay_name, 0);
	dm_remove_device(cd, rh->hotzone_name, 0);

	return r;
}

/* TODO:
 * 	1) audit error path. any error in this routine is fatal and should be unlikely.
 * 	   usually it would hint some collision with another userspace process touching
 * 	   dm devices directly.
 */
static int reenc_refresh_helper_devices(struct crypt_device *cd, const char *overlay, const char *hotzone)
{
	int r;

	/*
	 * we have to explicitly suspend the overlay device before suspending
	 * the hotzone one. Resuming overlay device (aka switching tables) only
	 * after suspending the hotzone may lead to deadlock.
	 *
	 * In other words: always suspend the stack from top to bottom!
	 */
	r = dm_suspend_device(cd, overlay, DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH);
	if (r) {
		log_err(cd, _("Failed to suspend device %s."), overlay);
		return r;
	}

	/* suspend HZ device */
	r = dm_suspend_device(cd, hotzone, DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH);
	if (r) {
		log_err(cd, _("Failed to suspend device %s."), hotzone);
		return r;
	}

	/* resume overlay device: inactive table (with hotozne) -> live */
	r = dm_resume_device(cd, overlay, DM_RESUME_PRIVATE);
	if (r)
		log_err(cd, _("Failed to resume device %s."), overlay);

	return r;
}

static int reencrypt_refresh_overlay_devices(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const char *overlay,
		const char *hotzone,
		struct volume_key *vks,
		uint64_t device_size,
		uint32_t flags)
{
	int r = reencrypt_load_overlay_device(cd, hdr, overlay, hotzone, vks, device_size, flags);
	if (r) {
		log_err(cd, _("Failed to reload device %s."), overlay);
		return REENC_ERR;
	}

	r = reenc_refresh_helper_devices(cd, overlay, hotzone);
	if (r) {
		log_err(cd, _("Failed to refresh reencryption devices stack."));
		return REENC_ROLLBACK;
	}

	return REENC_OK;
}

static int reencrypt_move_data(struct crypt_device *cd,
	int devfd,
	uint64_t data_shift,
	crypt_reencrypt_mode_info mode)
{
	void *buffer;
	int r;
	ssize_t ret;
	uint64_t buffer_len, offset,
		 read_offset = (mode == CRYPT_REENCRYPT_ENCRYPT ? 0 : data_shift);
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	offset = json_segment_get_offset(LUKS2_get_segment_jobj(hdr, 0), 0);
	buffer_len = json_segment_get_size(LUKS2_get_segment_jobj(hdr, 0), 0);
	if (!buffer_len || buffer_len > data_shift)
		return -EINVAL;

	if (posix_memalign(&buffer, device_alignment(crypt_data_device(cd)), buffer_len))
		return -ENOMEM;

	ret = read_lseek_blockwise(devfd,
			device_block_size(cd, crypt_data_device(cd)),
			device_alignment(crypt_data_device(cd)),
			buffer, buffer_len, read_offset);
	if (ret < 0 || (uint64_t)ret != buffer_len) {
		log_dbg(cd, "Failed to read data at offset %" PRIu64 " (size: %zu)",
			read_offset, buffer_len);
		r = -EIO;
		goto out;
	}

	log_dbg(cd, "Going to write %" PRIu64 " bytes read at offset %" PRIu64 " to new offset %" PRIu64,
		buffer_len, read_offset, offset);
	ret = write_lseek_blockwise(devfd,
			device_block_size(cd, crypt_data_device(cd)),
			device_alignment(crypt_data_device(cd)),
			buffer, buffer_len, offset);
	if (ret < 0 || (uint64_t)ret != buffer_len) {
		log_dbg(cd, "Failed to write data at offset %" PRIu64 " (size: %zu)",
			offset, buffer_len);
		r = -EIO;
		goto out;
	}

	r = 0;
out:
	crypt_safe_memzero(buffer, buffer_len);
	free(buffer);
	return r;
}

static int reencrypt_make_backup_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		int digest_new,
		const char *cipher,
		uint64_t data_offset,
		const struct crypt_params_reencrypt *params)
{
	const char *type;
	int r, segment, moved_segment = -1, digest_old = -1;
	json_object *jobj_tmp, *jobj_segment_new = NULL, *jobj_segment_old = NULL, *jobj_segment_bcp = NULL;
	uint32_t sector_size = params->luks2 ? params->luks2->sector_size : SECTOR_SIZE;
	uint64_t segment_offset, tmp, data_shift = params->data_shift << SECTOR_SHIFT,
		 device_size = params->device_size << SECTOR_SHIFT;

	if (params->mode != CRYPT_REENCRYPT_DECRYPT && digest_new < 0)
		return -EINVAL;

	if (params->mode != CRYPT_REENCRYPT_ENCRYPT) {
		digest_old = LUKS2_digest_by_segment(hdr, CRYPT_DEFAULT_SEGMENT);
		if (digest_old < 0)
			return -EINVAL;
	}

	segment = LUKS2_segment_first_unused_id(hdr);
	if (segment < 0)
		return -EINVAL;

	if (params->flags & CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT) {
		if (json_object_copy(LUKS2_get_segment_jobj(hdr, 0), &jobj_segment_bcp)) {
			r = -EINVAL;
			goto err;
		}
		r = LUKS2_segment_set_flag(jobj_segment_bcp, "backup-moved-segment");
		if (r)
			goto err;
		moved_segment = segment++;
		r = json_object_object_add_by_uint_by_ref(LUKS2_get_segments_jobj(hdr), moved_segment, &jobj_segment_bcp);
		if (r)
			goto err;

		if (!(type = json_segment_type(LUKS2_get_segment_jobj(hdr, moved_segment)))) {
			r = -EINVAL;
			goto err;
		}

		if (!strcmp(type, "crypt") && ((r = LUKS2_digest_segment_assign(cd, hdr, moved_segment, digest_old, 1, 0))))
			goto err;
	}

	/* FIXME: Add detection for case (digest old == digest new && old segment == new segment) */
	if (digest_old >= 0) {
		if (params->flags & CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT) {
			jobj_tmp = LUKS2_get_segment_jobj(hdr, 0);
			if (!jobj_tmp) {
				r = -EINVAL;
				goto err;
			}

			jobj_segment_old = json_segment_create_crypt(data_offset,
						json_segment_get_iv_offset(jobj_tmp),
						device_size ? &device_size : NULL,
						json_segment_get_cipher(jobj_tmp),
						NULL, 0, /* integrity */
						json_segment_get_sector_size(jobj_tmp),
						0);
		} else {
			if (json_object_copy(LUKS2_get_segment_jobj(hdr, CRYPT_DEFAULT_SEGMENT), &jobj_segment_old)) {
				r = -EINVAL;
				goto err;
			}
		}
	} else if (params->mode == CRYPT_REENCRYPT_ENCRYPT) {
		r = LUKS2_get_data_size(hdr, &tmp, NULL);
		if (r)
			goto err;

		if (params->flags & CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT)
			jobj_segment_old = json_segment_create_linear(0, tmp ? &tmp : NULL, 0);
		else
			jobj_segment_old = json_segment_create_linear(data_offset, tmp ? &tmp : NULL, 0);
	}

	if (!jobj_segment_old) {
		r = -EINVAL;
		goto err;
	}

	r = LUKS2_segment_set_flag(jobj_segment_old, "backup-previous");
	if (r)
		goto err;

	r = json_object_object_add_by_uint_by_ref(LUKS2_get_segments_jobj(hdr), segment, &jobj_segment_old);
	if (r)
		goto err;

	if (digest_old >= 0 && (r = LUKS2_digest_segment_assign(cd, hdr, segment, digest_old, 1, 0)))
		goto err;

	segment++;

	if (digest_new >= 0) {
		segment_offset = data_offset;
		if (params->mode != CRYPT_REENCRYPT_ENCRYPT &&
		    modify_offset(&segment_offset, data_shift, params->direction)) {
			r = -EINVAL;
			goto err;
		}
		jobj_segment_new = json_segment_create_crypt(segment_offset,
							crypt_get_iv_offset(cd),
							NULL, cipher, NULL, 0, sector_size, 0);
	} else if (params->mode == CRYPT_REENCRYPT_DECRYPT) {
		segment_offset = data_offset;
		if (modify_offset(&segment_offset, data_shift, params->direction)) {
			r = -EINVAL;
			goto err;
		}
		jobj_segment_new = json_segment_create_linear(segment_offset, NULL, 0);
	}

	if (!jobj_segment_new) {
		r = -EINVAL;
		goto err;
	}

	r = LUKS2_segment_set_flag(jobj_segment_new, "backup-final");
	if (r)
		goto err;

	r = json_object_object_add_by_uint_by_ref(LUKS2_get_segments_jobj(hdr), segment, &jobj_segment_new);
	if (r)
		goto err;

	if (digest_new >= 0 && (r = LUKS2_digest_segment_assign(cd, hdr, segment, digest_new, 1, 0)))
		goto err;

	/* FIXME: also check occupied space by keyslot in shrunk area */
	if (params->direction == CRYPT_REENCRYPT_FORWARD && data_shift &&
	    crypt_metadata_device(cd) == crypt_data_device(cd) &&
	    LUKS2_set_keyslots_size(hdr, json_segment_get_offset(reencrypt_segment_new(hdr), 0))) {
		log_err(cd, _("Failed to set new keyslots area size."));
		r = -EINVAL;
		goto err;
	}

	return 0;
err:
	json_object_put(jobj_segment_new);
	json_object_put(jobj_segment_old);
	json_object_put(jobj_segment_bcp);
	return r;
}

static int reencrypt_verify_single_key(struct crypt_device *cd, int digest, struct volume_key *vks)
{
	struct volume_key *vk;

	vk = crypt_volume_key_by_id(vks, digest);
	if (!vk)
		return -ENOENT;

	if (LUKS2_digest_verify_by_digest(cd, digest, vk) != digest)
		return -EINVAL;

	return 0;
}

static int reencrypt_verify_keys(struct crypt_device *cd,
	int digest_old,
	int digest_new,
	struct volume_key *vks)
{
	int r;

	if (digest_new >= 0 && (r = reencrypt_verify_single_key(cd, digest_new, vks)))
		return r;

	if (digest_old >= 0 && (r = reencrypt_verify_single_key(cd, digest_old, vks)))
		return r;

	return 0;
}

static int reencrypt_upload_single_key(struct crypt_device *cd,
	int digest,
	struct volume_key *vks)
{
	struct volume_key *vk;

	vk = crypt_volume_key_by_id(vks, digest);
	if (!vk)
		return -EINVAL;

	return LUKS2_volume_key_load_in_keyring_by_digest(cd, vk, digest);
}

static int reencrypt_upload_keys(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int digest_old,
	int digest_new,
	struct volume_key *vks)
{
	int r;

	if (!crypt_use_keyring_for_vk(cd))
		return 0;

	if (digest_new >= 0 && !crypt_is_cipher_null(reencrypt_segment_cipher_new(hdr)) &&
	    (r = reencrypt_upload_single_key(cd, digest_new, vks)))
		return r;

	if (digest_old >= 0 && !crypt_is_cipher_null(reencrypt_segment_cipher_old(hdr)) &&
	    (r = reencrypt_upload_single_key(cd, digest_old, vks))) {
		crypt_drop_uploaded_keyring_key(cd, vks);
		return r;
	}

	return 0;
}

static int reencrypt_verify_and_upload_keys(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int digest_old,
	int digest_new,
	struct volume_key *vks)
{
	int r;

	r = reencrypt_verify_keys(cd, digest_old, digest_new, vks);
	if (r)
		return r;

	r = reencrypt_upload_keys(cd, hdr, digest_old, digest_new, vks);
	if (r)
		return r;

	return 0;
}

static int reencrypt_verify_checksum_params(struct crypt_device *cd,
		const struct crypt_params_reencrypt *params)
{
	size_t len;
	struct crypt_hash *ch;

	assert(params);

	if (!params->hash)
		return -EINVAL;

	len = strlen(params->hash);
	if (!len || len > (LUKS2_CHECKSUM_ALG_L - 1))
		return -EINVAL;

	if (crypt_hash_size(params->hash) <= 0)
		return -EINVAL;

	if (crypt_hash_init(&ch, params->hash)) {
		log_err(cd, _("Hash algorithm %s is not available."), params->hash);
		return -EINVAL;
	}
	/* We just check for alg availability */
	crypt_hash_destroy(ch);

	return 0;
}

static int reencrypt_verify_datashift_params(struct crypt_device *cd,
		const struct crypt_params_reencrypt *params,
		uint32_t sector_size)
{
	assert(params);

	if (!params->data_shift)
		return -EINVAL;
	if (MISALIGNED(params->data_shift, sector_size >> SECTOR_SHIFT)) {
		log_err(cd, _("Data shift value is not aligned to encryption sector size (%" PRIu32 " bytes)."),
			sector_size);
		return -EINVAL;
	}

	return 0;
}

static int reencrypt_verify_resilience_params(struct crypt_device *cd,
		const struct crypt_params_reencrypt *params,
		uint32_t sector_size, bool move_first_segment)
{
	/* no change requested */
	if (!params || !params->resilience)
		return 0;

	if (!strcmp(params->resilience, "journal"))
		return (params->data_shift || move_first_segment) ? -EINVAL : 0;
	else if (!strcmp(params->resilience, "none"))
		return (params->data_shift || move_first_segment) ? -EINVAL : 0;
	else if (!strcmp(params->resilience, "datashift"))
		return reencrypt_verify_datashift_params(cd, params, sector_size);
	else if (!strcmp(params->resilience, "checksum")) {
		if (params->data_shift || move_first_segment)
			return -EINVAL;
		return reencrypt_verify_checksum_params(cd, params);
	} else if (!strcmp(params->resilience, "datashift-checksum")) {
		if (!move_first_segment ||
		     reencrypt_verify_datashift_params(cd, params, sector_size))
			return -EINVAL;
		return reencrypt_verify_checksum_params(cd, params);
	} else if (!strcmp(params->resilience, "datashift-journal")) {
		if (!move_first_segment)
			return -EINVAL;
		return reencrypt_verify_datashift_params(cd, params, sector_size);
	}

	log_err(cd, _("Unsupported resilience mode %s"), params->resilience);
	return -EINVAL;
}

static int reencrypt_decrypt_with_datashift_init(struct crypt_device *cd,
		const char *name,
		struct luks2_hdr *hdr,
		int reencrypt_keyslot,
		uint32_t sector_size,
		uint64_t data_size,
		uint64_t data_offset,
		struct crypt_keyslot_context *kc_old,
		int keyslot_old,
		const struct crypt_params_reencrypt *params,
		struct volume_key **vks)
{
	bool clear_table = false;
	int r, devfd = -1;
	uint64_t data_shift, max_moved_segment_length, moved_segment_length;
	struct reenc_protection check_rp = {};
	struct crypt_dm_active_device dmd_target, dmd_source = {
		.uuid = crypt_get_uuid(cd),
		.flags = CRYPT_ACTIVATE_SHARED /* turn off exclusive open checks */
	};
	json_object *jobj_segments_old;

	assert(hdr);
	assert(params);
	assert(params->resilience);
	assert(params->data_shift);
	assert(vks);

	if (!data_offset)
		return -EINVAL;

	if (params->max_hotzone_size > params->data_shift) {
		log_err(cd, _("Moved segment size can not be greater than data shift value."));
		return -EINVAL;
	}

	log_dbg(cd, "Initializing decryption with datashift.");

	data_shift = params->data_shift << SECTOR_SHIFT;

	/*
	 * In offline mode we must perform data move with exclusively opened data
	 * device in order to exclude LUKS2 decryption process and filesystem mount.
	 */
	if (name)
		devfd = device_open(cd, crypt_data_device(cd), O_RDWR);
	else
		devfd = device_open_excl(cd, crypt_data_device(cd), O_RDWR);
	if (devfd < 0)
		return -EINVAL;

	/* in-memory only */
	moved_segment_length = params->max_hotzone_size << SECTOR_SHIFT;
	if (!moved_segment_length)
		moved_segment_length = data_shift < LUKS2_DEFAULT_NONE_REENCRYPTION_LENGTH ?
				       data_shift : LUKS2_DEFAULT_NONE_REENCRYPTION_LENGTH;

	if (moved_segment_length > data_size)
		moved_segment_length = data_size;

	r = reencrypt_set_decrypt_shift_segments(cd, hdr, data_size,
						 moved_segment_length,
						 params->direction);
	if (r)
		goto out;

	r = reencrypt_make_backup_segments(cd, hdr, CRYPT_ANY_DIGEST, NULL, data_offset, params);
	if (r) {
		log_dbg(cd, "Failed to create reencryption backup device segments.");
		goto out;
	}

	r = reencrypt_verify_resilience_params(cd, params, sector_size, true);
	if (r < 0) {
		log_err(cd, _("Invalid reencryption resilience parameters."));
		goto out;
	}

	r = LUKS2_keyslot_reencrypt_allocate(cd, hdr, reencrypt_keyslot,
					   params, reencrypt_get_alignment(cd, hdr));
	if (r < 0)
		goto out;

	r = LUKS2_keyslot_reencrypt_load(cd, hdr, reencrypt_keyslot, &check_rp, false);
	if (r < 0)
		goto out;

	r = LUKS2_reencrypt_max_hotzone_size(cd, hdr, &check_rp,
					     reencrypt_keyslot,
					     &max_moved_segment_length);
	if (r < 0)
		goto out;

	LUKS2_reencrypt_protection_erase(&check_rp);

	if (moved_segment_length > max_moved_segment_length) {
		log_err(cd, _("Moved segment too large. Requested size %" PRIu64 ", available space for: %" PRIu64 "."),
			moved_segment_length, max_moved_segment_length);
		r = -EINVAL;
		goto out;
	}

	r = LUKS2_keyslot_context_open_all_segments(cd, keyslot_old, CRYPT_ANY_SLOT,
						    kc_old, NULL, vks);
	if (r < 0)
		goto out;

	r = LUKS2_keyslot_reencrypt_digest_create(cd, hdr, LUKS2_DECRYPT_DATASHIFT_REQ_VERSION, *vks);
	if (r < 0)
		goto out;

	if (name) {
		r = reencrypt_verify_and_upload_keys(cd, hdr,
						     LUKS2_reencrypt_digest_old(hdr),
						     LUKS2_reencrypt_digest_new(hdr),
						     *vks);
		if (r)
			goto out;

		r = dm_query_device(cd, name, DM_ACTIVE_UUID | DM_ACTIVE_DEVICE |
				    DM_ACTIVE_CRYPT_KEYSIZE | DM_ACTIVE_CRYPT_KEY |
				    DM_ACTIVE_CRYPT_CIPHER, &dmd_target);
		if (r < 0)
			goto out;

		jobj_segments_old = reencrypt_segments_old(hdr);
		if (!jobj_segments_old) {
			dm_targets_free(cd, &dmd_target);
			free(CONST_CAST(void*)dmd_target.uuid);
			r = -EINVAL;
			goto out;
		}
		r = LUKS2_assembly_multisegment_dmd(cd, hdr, *vks, jobj_segments_old, &dmd_source);
		if (!r) {
			r = crypt_compare_dm_devices(cd, &dmd_source, &dmd_target);
			if (r)
				log_err(cd, _("Mismatching parameters on device %s."), name);
		}
		json_object_put(jobj_segments_old);

		dm_targets_free(cd, &dmd_source);
		dm_targets_free(cd, &dmd_target);
		free(CONST_CAST(void*)dmd_target.uuid);

		if (r)
			goto out;

		dmd_source.size = dmd_target.size;
		r = LUKS2_assembly_multisegment_dmd(cd, hdr, *vks, LUKS2_get_segments_jobj(hdr), &dmd_source);
		if (!r) {
			r = dm_reload_device(cd, name, &dmd_source, dmd_target.flags, 0);
			if (r)
				log_err(cd, _("Failed to reload device %s."), name);
			else
				clear_table = true;
		}

		dm_targets_free(cd, &dmd_source);

		if (r)
			goto out;
	}

	if (name) {
		r = dm_suspend_device(cd, name, DM_SUSPEND_SKIP_LOCKFS);
		if (r) {
			log_err(cd, _("Failed to suspend device %s."), name);
			goto out;
		}
	}

	if (reencrypt_move_data(cd, devfd, data_shift, params->mode)) {
		r = -EIO;
		goto out;
	}

	/* This must be first and only write in LUKS2 metadata during _reencrypt_init */
	r = reencrypt_update_flag(cd, LUKS2_DECRYPT_DATASHIFT_REQ_VERSION, true, true);
	if (r) {
		log_dbg(cd, "Failed to set online-reencryption requirement.");
		r = -EINVAL;
	} else
		r = reencrypt_keyslot;
out:
	if (r < 0 && clear_table && dm_clear_device(cd, name))
		log_err(cd, _("Failed to clear table."));
	else if (clear_table && dm_resume_device(cd, name, DM_SUSPEND_SKIP_LOCKFS))
		log_err(cd, _("Failed to resume device %s."), name);

	device_release_excl(cd, crypt_data_device(cd));
	if (r < 0 && LUKS2_hdr_rollback(cd, hdr) < 0)
		log_dbg(cd, "Failed to rollback LUKS2 metadata after failure.");

	return r;
}

/* This function must be called with metadata lock held */
static int reencrypt_init(struct crypt_device *cd,
		const char *name,
		struct luks2_hdr *hdr,
		struct crypt_keyslot_context *kc_old,
		struct crypt_keyslot_context *kc_new,
		int keyslot_old,
		int keyslot_new,
		const char *cipher,
		const char *cipher_mode,
		const struct crypt_params_reencrypt *params,
		struct volume_key **vks)
{
	bool move_first_segment;
	char _cipher[128];
	uint32_t check_sector_size, new_sector_size, old_sector_size;
	int digest_new, r, reencrypt_keyslot, devfd = -1;
	uint64_t data_offset_bytes, data_size_bytes, data_shift_bytes, device_size_bytes;
	struct volume_key *vk;
	struct crypt_dm_active_device dmd_target, dmd_source = {
		.uuid = crypt_get_uuid(cd),
		.flags = CRYPT_ACTIVATE_SHARED /* turn off exclusive open checks */
	};

	assert(cd);
	assert(hdr);

	if (!params || !params->resilience || params->mode > CRYPT_REENCRYPT_DECRYPT)
		return -EINVAL;

	if (params->mode != CRYPT_REENCRYPT_DECRYPT &&
	    (!params->luks2 || !(cipher && cipher_mode) ||
	     (keyslot_new < 0 && !(params->flags & CRYPT_REENCRYPT_CREATE_NEW_DIGEST))))
		return -EINVAL;

	log_dbg(cd, "Initializing reencryption (mode: %s) in LUKS2 metadata.",
		    crypt_reencrypt_mode_to_str(params->mode));

	move_first_segment = (params->flags & CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT);

	old_sector_size = LUKS2_get_sector_size(hdr);

	/* implicit sector size 512 for decryption */
	new_sector_size = params->luks2 ? params->luks2->sector_size : SECTOR_SIZE;
	if (new_sector_size < SECTOR_SIZE || new_sector_size > MAX_SECTOR_SIZE ||
	    NOTPOW2(new_sector_size)) {
		log_err(cd, _("Unsupported encryption sector size."));
		return -EINVAL;
	}
	/* check the larger encryption sector size only */
	check_sector_size = new_sector_size > old_sector_size ? new_sector_size : old_sector_size;

	if (!cipher_mode || *cipher_mode == '\0')
		r = snprintf(_cipher, sizeof(_cipher), "%s", cipher);
	else
		r = snprintf(_cipher, sizeof(_cipher), "%s-%s", cipher, cipher_mode);
	if (r < 0 || (size_t)r >= sizeof(_cipher))
		return -EINVAL;

	data_offset_bytes = LUKS2_get_data_offset(hdr) << SECTOR_SHIFT;

	r = device_check_access(cd, crypt_data_device(cd), DEV_OK);
	if (r)
		return r;

	r = device_check_size(cd, crypt_data_device(cd), data_offset_bytes, 1);
	if (r)
		return r;

	r = device_size(crypt_data_device(cd), &device_size_bytes);
	if (r)
		return r;

	if (move_first_segment && params->mode == CRYPT_REENCRYPT_ENCRYPT &&
	    params->data_shift < LUKS2_get_data_offset(hdr)) {
		log_err(cd, _("Data shift (%" PRIu64 " sectors) is less than future data offset (%" PRIu64 " sectors)."),
			params->data_shift, LUKS2_get_data_offset(hdr));
		return -EINVAL;
	}

	device_size_bytes -= data_offset_bytes;
	data_shift_bytes = params->data_shift << SECTOR_SHIFT;
	data_size_bytes = params->device_size << SECTOR_SHIFT;

	if (device_size_bytes < data_shift_bytes && params->direction == CRYPT_REENCRYPT_BACKWARD) {
		log_err(cd, _("Device %s is too small."), device_path(crypt_data_device(cd)));
		return -EINVAL;
	}

	if (data_size_bytes > device_size_bytes) {
		log_err(cd, _("Reduced data size is larger than real device size."));
		return -EINVAL;
	}

	if (data_size_bytes && params->mode == CRYPT_REENCRYPT_ENCRYPT &&
	    move_first_segment && data_shift_bytes) {
		if (data_size_bytes > device_size_bytes - data_shift_bytes) {
			log_err(cd, _("Reduced data size is larger than real device size."));
			return -EINVAL;
		}
	} else if (!data_size_bytes && params->mode == CRYPT_REENCRYPT_ENCRYPT &&
	    move_first_segment && data_shift_bytes)
		data_size_bytes = device_size_bytes - data_shift_bytes;
	else if (!data_size_bytes)
		data_size_bytes = device_size_bytes;

	if (MISALIGNED(data_size_bytes, check_sector_size)) {
		log_err(cd, _("Data device is not aligned to encryption sector size (%" PRIu32 " bytes)."), check_sector_size);
		return -EINVAL;
	}

	reencrypt_keyslot = LUKS2_keyslot_find_empty(cd, hdr, 0);
	if (reencrypt_keyslot < 0) {
		log_err(cd, _("All key slots full."));
		return -EINVAL;
	}

	if (params->mode == CRYPT_REENCRYPT_DECRYPT && data_shift_bytes && move_first_segment)
		return reencrypt_decrypt_with_datashift_init(cd, name, hdr,
							     reencrypt_keyslot,
							     check_sector_size,
							     data_size_bytes,
							     data_offset_bytes,
							     kc_old,
							     keyslot_old,
							     params,
							     vks);

	/*
	 * We must perform data move with exclusive open data device
	 * to exclude another cryptsetup process to colide with
	 * encryption initialization (or mount)
	 */
	if (move_first_segment) {
		devfd = device_open_excl(cd, crypt_data_device(cd), O_RDWR);
		if (devfd < 0) {
			if (devfd == -EBUSY)
				log_err(cd,_("Failed to open %s in exclusive mode (already mapped or mounted)."),
					device_path(crypt_data_device(cd)));
			return -EINVAL;
		}
	}

	if (params->mode == CRYPT_REENCRYPT_ENCRYPT) {
		/* in-memory only */
		r = reencrypt_set_encrypt_segments(cd, hdr, device_size_bytes, data_size_bytes,
						   data_shift_bytes,
						   move_first_segment,
						   params->direction);
		if (r)
			goto out;
	}

	if (params->flags & CRYPT_REENCRYPT_CREATE_NEW_DIGEST) {
		assert(kc_new->get_luks2_key);
		r = kc_new->get_luks2_key(cd, kc_new, CRYPT_ANY_SLOT, CRYPT_ANY_SEGMENT, &vk);
		if (r < 0)
			goto out;

		/* do not create new digest in case it matches the current one */
		r = LUKS2_digest_verify_by_segment(cd, hdr, CRYPT_DEFAULT_SEGMENT, vk);
		if (r == -EPERM || r == -ENOENT)
			r = LUKS2_digest_create(cd, "pbkdf2", hdr, vk);

		crypt_free_volume_key(vk);
		if (r < 0)
			goto out;
		digest_new = r;
	} else
		digest_new = LUKS2_digest_by_keyslot(hdr, keyslot_new);

	r = reencrypt_make_backup_segments(cd, hdr, digest_new, _cipher, data_offset_bytes, params);
	if (r) {
		log_dbg(cd, "Failed to create reencryption backup device segments.");
		goto out;
	}

	r = reencrypt_verify_resilience_params(cd, params, check_sector_size, move_first_segment);
	if (r < 0)
		goto out;

	r = LUKS2_keyslot_reencrypt_allocate(cd, hdr, reencrypt_keyslot, params,
			reencrypt_get_alignment(cd, hdr));
	if (r < 0)
		goto out;

	r = LUKS2_keyslot_context_open_all_segments(cd, keyslot_old, keyslot_new, kc_old, kc_new, vks);
	if (r < 0)
		goto out;

	r = LUKS2_keyslot_reencrypt_digest_create(cd, hdr, LUKS2_REENCRYPT_REQ_VERSION, *vks);
	if (r < 0)
		goto out;

	if (name && params->mode != CRYPT_REENCRYPT_ENCRYPT) {
		r = reencrypt_verify_and_upload_keys(cd, hdr, LUKS2_reencrypt_digest_old(hdr), LUKS2_reencrypt_digest_new(hdr), *vks);
		if (r)
			goto out;

		r = dm_query_device(cd, name, DM_ACTIVE_UUID | DM_ACTIVE_DEVICE |
				    DM_ACTIVE_CRYPT_KEYSIZE | DM_ACTIVE_CRYPT_KEY |
				    DM_ACTIVE_CRYPT_CIPHER, &dmd_target);
		if (r < 0)
			goto out;

		r = LUKS2_assembly_multisegment_dmd(cd, hdr, *vks, LUKS2_get_segments_jobj(hdr), &dmd_source);
		if (!r) {
			r = crypt_compare_dm_devices(cd, &dmd_source, &dmd_target);
			if (r)
				log_err(cd, _("Mismatching parameters on device %s."), name);
		}

		dm_targets_free(cd, &dmd_source);
		dm_targets_free(cd, &dmd_target);
		free(CONST_CAST(void*)dmd_target.uuid);

		if (r)
			goto out;
	}

	if (move_first_segment && reencrypt_move_data(cd, devfd, data_shift_bytes, params->mode)) {
		r = -EIO;
		goto out;
	}

	/* This must be first and only write in LUKS2 metadata during reencrypt_init */
	r = reencrypt_update_flag(cd, LUKS2_REENCRYPT_REQ_VERSION, true, true);
	if (r) {
		log_dbg(cd, "Failed to set online-reencryption requirement.");
		r = -EINVAL;
	} else
		r = reencrypt_keyslot;
out:
	device_release_excl(cd, crypt_data_device(cd));
	if (r < 0 && LUKS2_hdr_rollback(cd, hdr) < 0)
		log_dbg(cd, "Failed to rollback LUKS2 metadata after failure.");

	return r;
}

static int reencrypt_hotzone_protect_final(struct crypt_device *cd,
	struct luks2_hdr *hdr, int reencrypt_keyslot,
	const struct reenc_protection *rp,
	const void *buffer, size_t buffer_len)
{
	const void *pbuffer;
	size_t data_offset, len;
	int r;

	assert(hdr);
	assert(rp);

	if (rp->type == REENC_PROTECTION_NONE)
		return 0;

	if (rp->type == REENC_PROTECTION_CHECKSUM) {
		log_dbg(cd, "Checksums hotzone resilience.");

		for (data_offset = 0, len = 0; data_offset < buffer_len; data_offset += rp->p.csum.block_size, len += rp->p.csum.hash_size) {
			if (crypt_hash_write(rp->p.csum.ch, (const char *)buffer + data_offset, rp->p.csum.block_size)) {
				log_dbg(cd, "Failed to hash sector at offset %zu.", data_offset);
				return -EINVAL;
			}
			if (crypt_hash_final(rp->p.csum.ch, (char *)rp->p.csum.checksums + len, rp->p.csum.hash_size)) {
				log_dbg(cd, "Failed to finalize hash.");
				return -EINVAL;
			}
		}
		pbuffer = rp->p.csum.checksums;
	} else if (rp->type == REENC_PROTECTION_JOURNAL) {
		log_dbg(cd, "Journal hotzone resilience.");
		len = buffer_len;
		pbuffer = buffer;
	} else if (rp->type == REENC_PROTECTION_DATASHIFT) {
		log_dbg(cd, "Data shift hotzone resilience.");
		return LUKS2_hdr_write(cd, hdr);
	} else
		return -EINVAL;

	log_dbg(cd, "Going to store %zu bytes in reencrypt keyslot.", len);

	r = LUKS2_keyslot_reencrypt_store(cd, hdr, reencrypt_keyslot, pbuffer, len);

	return r > 0 ? 0 : r;
}

static int reencrypt_context_update(struct crypt_device *cd,
	struct luks2_reencrypt *rh)
{
	if (rh->read < 0)
		return -EINVAL;

	if (rh->direction == CRYPT_REENCRYPT_BACKWARD) {
		if (rh->rp.type == REENC_PROTECTION_DATASHIFT && rh->mode == CRYPT_REENCRYPT_ENCRYPT) {
			if (rh->offset)
				rh->offset -= data_shift_value(&rh->rp);
			if (rh->offset && (rh->offset < data_shift_value(&rh->rp))) {
				rh->length = rh->offset;
				rh->offset = data_shift_value(&rh->rp);
			}
			if (!rh->offset)
				rh->length = data_shift_value(&rh->rp);
		} else {
			if (rh->offset < rh->length)
				rh->length = rh->offset;
			rh->offset -= rh->length;
		}
	} else if (rh->direction == CRYPT_REENCRYPT_FORWARD) {
		rh->offset += (uint64_t)rh->read;
		if (rh->device_size == rh->offset &&
		    rh->jobj_segment_moved &&
		    rh->mode == CRYPT_REENCRYPT_DECRYPT &&
		    rh->rp.type == REENC_PROTECTION_DATASHIFT) {
			rh->offset = 0;
			rh->length = json_segment_get_size(rh->jobj_segment_moved, 0);
		}
		/* it fails in-case of device_size < rh->offset later */
		else if (rh->device_size - rh->offset < rh->length)
			rh->length = rh->device_size - rh->offset;
	} else
		return -EINVAL;

	if (rh->device_size < rh->offset) {
		log_dbg(cd, "Calculated reencryption offset %" PRIu64 " is beyond device size %" PRIu64 ".", rh->offset, rh->device_size);
		return -EINVAL;
	}

	rh->progress += (uint64_t)rh->read;

	return 0;
}

static int reencrypt_load(struct crypt_device *cd, struct luks2_hdr *hdr,
		uint64_t device_size,
		uint64_t max_hotzone_size,
		uint64_t required_device_size,
		struct volume_key *vks,
		struct luks2_reencrypt **rh)
{
	int r;
	struct luks2_reencrypt *tmp = NULL;
	crypt_reencrypt_info ri = LUKS2_reencrypt_status(hdr);

	if (ri == CRYPT_REENCRYPT_NONE) {
		log_err(cd, _("Device not marked for LUKS2 reencryption."));
		return -EINVAL;
	} else if (ri == CRYPT_REENCRYPT_INVALID)
		return -EINVAL;

	r = LUKS2_reencrypt_digest_verify(cd, hdr, vks);
	if (r < 0)
		return r;

	if (ri == CRYPT_REENCRYPT_CLEAN)
		r = reencrypt_load_clean(cd, hdr, device_size, max_hotzone_size, required_device_size, &tmp);
	else if (ri == CRYPT_REENCRYPT_CRASH)
		r = reencrypt_load_crashed(cd, hdr, device_size, &tmp);
	else
		r = -EINVAL;

	if (r < 0 || !tmp) {
		log_err(cd, _("Failed to load LUKS2 reencryption context."));
		return r < 0 ? r : -EINVAL;
	}

	*rh = tmp;

	return 0;
}
#else
int LUKS2_reencrypt_max_hotzone_size(struct crypt_device *cd __attribute__((unused)),
	struct luks2_hdr *hdr __attribute__((unused)),
	const struct reenc_protection *rp __attribute__((unused)),
	int reencrypt_keyslot __attribute__((unused)),
	uint64_t *r_length __attribute__((unused)))
{
	return -ENOTSUP;
}
#endif

static int reencrypt_lock_internal(struct crypt_device *cd, const char *uuid, struct crypt_lock_handle **reencrypt_lock)
{
	int r;
	char *lock_resource;

	if (!crypt_metadata_locking_enabled()) {
		*reencrypt_lock = NULL;
		return 0;
	}

	r = asprintf(&lock_resource, "LUKS2-reencryption-%s", uuid);
	if (r < 0)
		return -ENOMEM;
	if (r < 20) {
		free(lock_resource);
		return -EINVAL;
	}

	r = crypt_write_lock(cd, lock_resource, false, reencrypt_lock);

	free(lock_resource);

	return r;
}

/* internal only */
int LUKS2_reencrypt_lock_by_dm_uuid(struct crypt_device *cd, const char *dm_uuid,
	struct crypt_lock_handle **reencrypt_lock)
{
	int r;
	char hdr_uuid[37];
	const char *uuid = crypt_get_uuid(cd);

	if (!dm_uuid)
		return -EINVAL;

	if (!uuid) {
		r = snprintf(hdr_uuid, sizeof(hdr_uuid), "%.8s-%.4s-%.4s-%.4s-%.12s",
			 dm_uuid + 6, dm_uuid + 14, dm_uuid + 18, dm_uuid + 22, dm_uuid + 26);
		if (r < 0 || (size_t)r != (sizeof(hdr_uuid) - 1))
			return -EINVAL;
	} else if (dm_uuid_cmp(dm_uuid, uuid))
		return -EINVAL;

	return reencrypt_lock_internal(cd, uuid, reencrypt_lock);
}

/* internal only */
int LUKS2_reencrypt_lock(struct crypt_device *cd, struct crypt_lock_handle **reencrypt_lock)
{
	if (!cd || !crypt_get_type(cd) || strcmp(crypt_get_type(cd), CRYPT_LUKS2))
		return -EINVAL;

	return reencrypt_lock_internal(cd, crypt_get_uuid(cd), reencrypt_lock);
}

/* internal only */
void LUKS2_reencrypt_unlock(struct crypt_device *cd, struct crypt_lock_handle *reencrypt_lock)
{
	crypt_unlock_internal(cd, reencrypt_lock);
}
#if USE_LUKS2_REENCRYPTION
static int reencrypt_lock_and_verify(struct crypt_device *cd, struct luks2_hdr *hdr,
		struct crypt_lock_handle **reencrypt_lock)
{
	int r;
	crypt_reencrypt_info ri;
	struct crypt_lock_handle *h;

	ri = LUKS2_reencrypt_status(hdr);
	if (ri == CRYPT_REENCRYPT_INVALID)
		return -EINVAL;
	if (ri < CRYPT_REENCRYPT_CLEAN) {
		log_err(cd, _("Device is not in reencryption."));
		return -EINVAL;
	}

	r = LUKS2_reencrypt_lock(cd, &h);
	if (r < 0) {
		if (r == -EBUSY)
			log_err(cd, _("Reencryption process is already running."));
		else
			log_err(cd, _("Failed to acquire reencryption lock."));
		return r;
	}

	/* With reencryption lock held, reload device context and verify metadata state */
	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r) {
		LUKS2_reencrypt_unlock(cd, h);
		return r;
	}

	ri = LUKS2_reencrypt_status(hdr);
	if (ri == CRYPT_REENCRYPT_CLEAN) {
		*reencrypt_lock = h;
		return 0;
	}

	LUKS2_reencrypt_unlock(cd, h);
	log_err(cd, _("Cannot proceed with reencryption. Run reencryption recovery first."));
	return -EINVAL;
}

static int reencrypt_load_by_keyslot_context(struct crypt_device *cd,
		const char *name,
		struct crypt_keyslot_context *kc_old,
		struct crypt_keyslot_context *kc_new,
		int keyslot_old,
		int keyslot_new,
		struct volume_key **vks,
		const struct crypt_params_reencrypt *params)
{
	int r, reencrypt_slot;
	struct luks2_hdr *hdr;
	struct crypt_lock_handle *reencrypt_lock;
	struct luks2_reencrypt *rh;
	const struct volume_key *vk;
	size_t alignment;
	uint32_t old_sector_size, new_sector_size, sector_size;
	struct crypt_dm_active_device dmd_target, dmd_source = {
		.uuid = crypt_get_uuid(cd),
		.flags = CRYPT_ACTIVATE_SHARED /* turn off exclusive open checks */
	};
	uint64_t minimal_size, device_size, mapping_size = 0, required_size = 0,
		 max_hotzone_size = 0;
	bool dynamic;
	uint32_t flags = 0;

	assert(cd);

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
	if (!hdr)
		return -EINVAL;

	log_dbg(cd, "Loading LUKS2 reencryption context.");

	old_sector_size = reencrypt_get_sector_size_old(hdr);
	new_sector_size = reencrypt_get_sector_size_new(hdr);
	sector_size = new_sector_size > old_sector_size ? new_sector_size : old_sector_size;

	r = reencrypt_verify_resilience_params(cd, params, sector_size,
					       LUKS2_get_segment_id_by_flag(hdr, "backup-moved-segment") >= 0);
	if (r < 0)
		return r;

	if (params) {
		required_size = params->device_size;
		max_hotzone_size = params->max_hotzone_size;
	}

	rh = crypt_get_luks2_reencrypt(cd);
	if (rh) {
		LUKS2_reencrypt_free(cd, rh);
		crypt_set_luks2_reencrypt(cd, NULL);
		rh = NULL;
	}

	r = reencrypt_lock_and_verify(cd, hdr, &reencrypt_lock);
	if (r)
		return r;

	reencrypt_slot = LUKS2_find_keyslot(hdr, "reencrypt");
	if (reencrypt_slot < 0) {
		r = -EINVAL;
		goto err;
	}

	/* From now on we hold reencryption lock */

	if (LUKS2_get_data_size(hdr, &minimal_size, &dynamic)) {
		r = -EINVAL;
		goto err;
	}

	/* some configurations provides fixed device size */
	r = LUKS2_reencrypt_check_device_size(cd, hdr, minimal_size, &device_size, false, dynamic);
	if (r) {
		r = -EINVAL;
		goto err;
	}

	minimal_size >>= SECTOR_SHIFT;

	r = reencrypt_verify_keys(cd, LUKS2_reencrypt_digest_old(hdr), LUKS2_reencrypt_digest_new(hdr), *vks);
	if (r == -ENOENT) {
		log_dbg(cd, "Keys are not ready. Unlocking all volume keys.");
		r = LUKS2_keyslot_context_open_all_segments(cd, keyslot_old, keyslot_new,
							    kc_old, kc_new, vks);
	}

	if (r < 0)
		goto err;

	if (name) {
		r = reencrypt_upload_keys(cd, hdr, LUKS2_reencrypt_digest_old(hdr), LUKS2_reencrypt_digest_new(hdr), *vks);
		if (r < 0)
			goto err;

		r = dm_query_device(cd, name, DM_ACTIVE_UUID | DM_ACTIVE_DEVICE |
				    DM_ACTIVE_CRYPT_KEYSIZE | DM_ACTIVE_CRYPT_KEY |
				    DM_ACTIVE_CRYPT_CIPHER, &dmd_target);
		if (r < 0)
			goto err;
		flags = dmd_target.flags;

		/*
		 * By default reencryption code aims to retain flags from existing dm device.
		 * The keyring activation flag can not be inherited if original cipher is null.
		 *
		 * In this case override the flag based on decision made in reencrypt_upload_keys
		 * above. The code checks if new VK is eligible for keyring.
		 */
		vk = crypt_volume_key_by_id(*vks, LUKS2_reencrypt_digest_new(hdr));
		if (vk && crypt_volume_key_description(vk) && crypt_is_cipher_null(reencrypt_segment_cipher_old(hdr))) {
			flags |= CRYPT_ACTIVATE_KEYRING_KEY;
			dmd_source.flags |= CRYPT_ACTIVATE_KEYRING_KEY;
		}

		r = LUKS2_assembly_multisegment_dmd(cd, hdr, *vks, LUKS2_get_segments_jobj(hdr), &dmd_source);
		if (!r) {
			r = crypt_compare_dm_devices(cd, &dmd_source, &dmd_target);
			if (r)
				log_err(cd, _("Mismatching parameters on device %s."), name);
		}

		dm_targets_free(cd, &dmd_source);
		dm_targets_free(cd, &dmd_target);
		free(CONST_CAST(void*)dmd_target.uuid);
		if (r)
			goto err;
		mapping_size = dmd_target.size;
	}

	r = -EINVAL;
	if (required_size && mapping_size && (required_size != mapping_size)) {
		log_err(cd, _("Active device size and requested reencryption size don't match."));
		goto err;
	}

	if (mapping_size)
		required_size = mapping_size;

	if (required_size) {
		/* TODO: Add support for changing fixed minimal size in reencryption mda where possible */
		if ((minimal_size && (required_size < minimal_size)) ||
		    (required_size > (device_size >> SECTOR_SHIFT)) ||
		    (!dynamic && (required_size != minimal_size)) ||
		    (old_sector_size > 0 && MISALIGNED(required_size, old_sector_size >> SECTOR_SHIFT)) ||
		    (new_sector_size > 0 && MISALIGNED(required_size, new_sector_size >> SECTOR_SHIFT))) {
			log_err(cd, _("Illegal device size requested in reencryption parameters."));
			goto err;
		}
	}

	alignment = reencrypt_get_alignment(cd, hdr);

	r = LUKS2_keyslot_reencrypt_update_needed(cd, hdr, reencrypt_slot, params, alignment);
	if (r > 0) /* metadata update needed */
		r = LUKS2_keyslot_reencrypt_update(cd, hdr, reencrypt_slot, params, alignment, *vks);
	if (r < 0)
		goto err;

	r = reencrypt_load(cd, hdr, device_size, max_hotzone_size, required_size, *vks, &rh);
	if (r < 0 || !rh)
		goto err;

	if (name && (r = reencrypt_context_set_names(rh, name)))
		goto err;

	/* Reassure device is not mounted and there's no dm mapping active */
	if (!name && (device_open_excl(cd, crypt_data_device(cd), O_RDONLY) < 0)) {
		log_err(cd,_("Failed to open %s in exclusive mode (already mapped or mounted)."), device_path(crypt_data_device(cd)));
		r = -EBUSY;
		goto err;
	}
	device_release_excl(cd, crypt_data_device(cd));

	/* There's a race for dm device activation not managed by cryptsetup.
	 *
	 * 1) excl close
	 * 2) rogue dm device activation
	 * 3) one or more dm-crypt based wrapper activation
	 * 4) next excl open gets skipped due to 3) device from 2) remains undetected.
	 */
	r = reencrypt_init_storage_wrappers(cd, hdr, rh, *vks);
	if (r)
		goto err;

	/* If one of wrappers is based on dmcrypt fallback it already blocked mount */
	if (!name && crypt_storage_wrapper_get_type(rh->cw1) != DMCRYPT &&
	    crypt_storage_wrapper_get_type(rh->cw2) != DMCRYPT) {
		if (device_open_excl(cd, crypt_data_device(cd), O_RDONLY) < 0) {
			log_err(cd,_("Failed to open %s in exclusive mode (already mapped or mounted)."), device_path(crypt_data_device(cd)));
			r = -EBUSY;
			goto err;
		}
	}

	rh->flags = flags;

	MOVE_REF(rh->vks, *vks);
	MOVE_REF(rh->reenc_lock, reencrypt_lock);

	crypt_set_luks2_reencrypt(cd, rh);

	return 0;
err:
	LUKS2_reencrypt_unlock(cd, reencrypt_lock);
	LUKS2_reencrypt_free(cd, rh);
	return r;
}

static int reencrypt_locked_recovery(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	struct crypt_keyslot_context *kc_old,
	struct crypt_keyslot_context *kc_new,
	struct volume_key **r_vks)
{
	int keyslot, r = -EINVAL;
	struct volume_key *_vks = NULL;

	r = LUKS2_keyslot_context_open_all_segments(cd, keyslot_old, keyslot_new,
						    kc_old, kc_new, &_vks);
	if (r < 0)
		return r;
	keyslot = r;

	r = LUKS2_reencrypt_locked_recovery_by_vks(cd, _vks);
	if (!r && r_vks)
		MOVE_REF(*r_vks, _vks);

	crypt_free_volume_key(_vks);

	return r < 0 ? r : keyslot;
}

static int reencrypt_recovery_by_keyslot_context(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int keyslot_old,
	int keyslot_new,
	struct crypt_keyslot_context *kc_old,
	struct crypt_keyslot_context *kc_new)
{
	int r;
	crypt_reencrypt_info ri;
	struct crypt_lock_handle *reencrypt_lock;

	r = LUKS2_reencrypt_lock(cd, &reencrypt_lock);
	if (r) {
		if (r == -EBUSY)
			log_err(cd, _("Reencryption in-progress. Cannot perform recovery."));
		else
			log_err(cd, _("Failed to get reencryption lock."));
		return r;
	}

	if ((r = crypt_load(cd, CRYPT_LUKS2, NULL))) {
		LUKS2_reencrypt_unlock(cd, reencrypt_lock);
		return r;
	}

	ri = LUKS2_reencrypt_status(hdr);
	if (ri == CRYPT_REENCRYPT_INVALID) {
		LUKS2_reencrypt_unlock(cd, reencrypt_lock);
		return -EINVAL;
	}

	if (ri == CRYPT_REENCRYPT_CRASH) {
		r = reencrypt_locked_recovery(cd, keyslot_old, keyslot_new,
						    kc_old, kc_new, NULL);
		if (r < 0)
			log_err(cd, _("LUKS2 reencryption recovery failed."));
	} else {
		log_dbg(cd, "No LUKS2 reencryption recovery needed.");
		r = 0;
	}

	LUKS2_reencrypt_unlock(cd, reencrypt_lock);
	return r;
}

static int reencrypt_repair(
		struct crypt_device *cd,
		struct luks2_hdr *hdr,
		int keyslot_old,
		int keyslot_new,
		struct crypt_keyslot_context *kc_old,
		struct crypt_keyslot_context *kc_new)
{
	int r;
	struct crypt_lock_handle *reencrypt_lock;
	struct luks2_reencrypt *rh;
	crypt_reencrypt_info ri;
	uint8_t requirement_version;
	const char *resilience;
	struct volume_key *vks = NULL;

	log_dbg(cd, "Loading LUKS2 reencryption context for metadata repair.");

	rh = crypt_get_luks2_reencrypt(cd);
	if (rh) {
		LUKS2_reencrypt_free(cd, rh);
		crypt_set_luks2_reencrypt(cd, NULL);
		rh = NULL;
	}

	ri = LUKS2_reencrypt_status(hdr);
	if (ri == CRYPT_REENCRYPT_INVALID)
		return -EINVAL;

	if (ri < CRYPT_REENCRYPT_CLEAN) {
		log_err(cd, _("Device is not in reencryption."));
		return -EINVAL;
	}

	r = LUKS2_reencrypt_lock(cd, &reencrypt_lock);
	if (r < 0) {
		if (r == -EBUSY)
			log_err(cd, _("Reencryption process is already running."));
		else
			log_err(cd, _("Failed to acquire reencryption lock."));
		return r;
	}

	/* With reencryption lock held, reload device context and verify metadata state */
	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r)
		goto out;

	ri = LUKS2_reencrypt_status(hdr);
	if (ri == CRYPT_REENCRYPT_INVALID) {
		r = -EINVAL;
		goto out;
	}
	if (ri == CRYPT_REENCRYPT_NONE) {
		r = 0;
		goto out;
	}

	resilience = reencrypt_resilience_type(hdr);
	if (!resilience) {
		r = -EINVAL;
		goto out;
	}

	if (reencrypt_mode(hdr) == CRYPT_REENCRYPT_DECRYPT &&
	    !strncmp(resilience, "datashift-", 10) &&
	    LUKS2_get_segment_id_by_flag(hdr, "backup-moved-segment") >= 0)
		requirement_version = LUKS2_DECRYPT_DATASHIFT_REQ_VERSION;
	else
		requirement_version = LUKS2_REENCRYPT_REQ_VERSION;

	r = LUKS2_keyslot_context_open_all_segments(cd, keyslot_old, keyslot_new, kc_old, kc_new, &vks);
	if (r < 0)
		goto out;

	r = LUKS2_keyslot_reencrypt_digest_create(cd, hdr, requirement_version, vks);
	crypt_free_volume_key(vks);
	vks = NULL;
	if (r < 0)
		goto out;

	/* replaces old online-reencrypt flag with updated version and commits metadata */
	r = reencrypt_update_flag(cd, requirement_version, true, true);
out:
	LUKS2_reencrypt_unlock(cd, reencrypt_lock);
	crypt_free_volume_key(vks);
	return r;

}

static int reencrypt_init_by_keyslot_context(struct crypt_device *cd,
	const char *name,
	struct crypt_keyslot_context *kc_old,
	struct crypt_keyslot_context *kc_new,
	int keyslot_old,
	int keyslot_new,
	const char *cipher,
	const char *cipher_mode,
	const struct crypt_params_reencrypt *params)
{
	int r;
	crypt_reencrypt_info ri;
	size_t key_length;
	struct volume_key *vks = NULL;
	uint32_t flags = params ? params->flags : 0;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	if (params && (params->flags & CRYPT_REENCRYPT_CREATE_NEW_DIGEST) &&
	    (!kc_new || !kc_new->get_luks2_key || !kc_new->get_key_size ||
	     (params->flags & CRYPT_REENCRYPT_RESUME_ONLY)))
		return -EINVAL;

	/* short-circuit in reencryption metadata update and finish immediately. */
	if (flags & CRYPT_REENCRYPT_REPAIR_NEEDED)
		return reencrypt_repair(cd, hdr, keyslot_old, keyslot_new, kc_old, kc_new);

	/* short-circuit in recovery and finish immediately. */
	if (flags & CRYPT_REENCRYPT_RECOVERY)
		return reencrypt_recovery_by_keyslot_context(cd, hdr, keyslot_old, keyslot_new, kc_old, kc_new);

	if (name && !device_direct_io(crypt_data_device(cd))) {
		log_dbg(cd, "Device %s does not support direct I/O.", device_path(crypt_data_device(cd)));
		/* FIXME: Add more specific error message for translation later. */
		log_err(cd, _("Failed to initialize reencryption device stack."));
		return -EINVAL;
	}

	if (cipher && !crypt_cipher_wrapped_key(cipher, cipher_mode)) {
		if (keyslot_new == CRYPT_ANY_SLOT && kc_new && kc_new->get_key_size)
			r = kc_new->get_key_size(cd, kc_new, &key_length);
		else {
			r = crypt_keyslot_get_key_size(cd, keyslot_new);
			if (r >= 0)
				key_length = r;
		}
		if (r < 0)
			return r;
		r = LUKS2_check_cipher(cd, key_length, cipher, cipher_mode);
		if (r < 0) {
			log_err(cd, _("Unable to use cipher specification %s-%s for LUKS2."), cipher, cipher_mode);
			return r;
		}
	}

	r = LUKS2_device_write_lock(cd, hdr, crypt_metadata_device(cd));
	if (r)
		return r;

	ri = LUKS2_reencrypt_status(hdr);
	if (ri == CRYPT_REENCRYPT_INVALID) {
		device_write_unlock(cd, crypt_metadata_device(cd));
		return -EINVAL;
	}

	if ((ri > CRYPT_REENCRYPT_NONE) && (flags & CRYPT_REENCRYPT_INITIALIZE_ONLY)) {
		device_write_unlock(cd, crypt_metadata_device(cd));
		log_err(cd, _("LUKS2 reencryption already initialized in metadata."));
		return -EBUSY;
	}

	if (ri == CRYPT_REENCRYPT_NONE && !(flags & CRYPT_REENCRYPT_RESUME_ONLY)) {
		r = reencrypt_init(cd, name, hdr, kc_old, kc_new, keyslot_old,
				   keyslot_new, cipher, cipher_mode, params, &vks);
		if (r < 0)
			log_err(cd, _("Failed to initialize LUKS2 reencryption in metadata."));
	} else if (ri > CRYPT_REENCRYPT_NONE) {
		log_dbg(cd, "LUKS2 reencryption already initialized.");
		r = 0;
	}

	device_write_unlock(cd, crypt_metadata_device(cd));

	if (r < 0 || (flags & CRYPT_REENCRYPT_INITIALIZE_ONLY))
		goto out;

	r = reencrypt_load_by_keyslot_context(cd, name, kc_old, kc_new, keyslot_old,
					      keyslot_new, &vks, params);
out:
	if (r < 0)
		crypt_drop_uploaded_keyring_key(cd, vks);
	crypt_free_volume_key(vks);
	return r < 0 ? r : LUKS2_find_keyslot(hdr, "reencrypt");
}
#else
static int reencrypt_init_by_keyslot_context(struct crypt_device *cd,
	const char *name __attribute__((unused)),
	struct crypt_keyslot_context *kc_old __attribute__((unused)),
	struct crypt_keyslot_context *kc_new __attribute__((unused)),
	int keyslot_old __attribute__((unused)),
	int keyslot_new __attribute__((unused)),
	const char *cipher __attribute__((unused)),
	const char *cipher_mode __attribute__((unused)),
	const struct crypt_params_reencrypt *params __attribute__((unused)))
{
	log_err(cd, _("This operation is not supported for this device type."));
	return -ENOTSUP;
}
#endif

int crypt_reencrypt_init_by_keyring(struct crypt_device *cd,
	const char *name,
	const char *passphrase_description,
	int keyslot_old,
	int keyslot_new,
	const char *cipher,
	const char *cipher_mode,
	const struct crypt_params_reencrypt *params)
{
	int r;
	struct crypt_keyslot_context kc = {0};

	if (onlyLUKS2reencrypt(cd) || !passphrase_description)
		return -EINVAL;
	if (params && (params->flags & CRYPT_REENCRYPT_INITIALIZE_ONLY) && (params->flags & CRYPT_REENCRYPT_RESUME_ONLY))
		return -EINVAL;

	if (device_is_dax(crypt_data_device(cd)) > 0) {
		log_err(cd, _("Reencryption is not supported for DAX (persistent memory) devices."));
		return -EINVAL;
	}

	crypt_keyslot_context_init_by_keyring_internal(&kc, passphrase_description);
	r = reencrypt_init_by_keyslot_context(cd, name, &kc, &kc, keyslot_old,
					      keyslot_new, cipher, cipher_mode, params);

	crypt_keyslot_context_destroy_internal(&kc);

	return r;
}

int crypt_reencrypt_init_by_passphrase(struct crypt_device *cd,
	const char *name,
	const char *passphrase,
	size_t passphrase_size,
	int keyslot_old,
	int keyslot_new,
	const char *cipher,
	const char *cipher_mode,
	const struct crypt_params_reencrypt *params)
{
	int r;
	struct crypt_keyslot_context kc = {0};

	if (onlyLUKS2reencrypt(cd) || !passphrase)
		return -EINVAL;
	if (params && (params->flags & CRYPT_REENCRYPT_INITIALIZE_ONLY) && (params->flags & CRYPT_REENCRYPT_RESUME_ONLY))
		return -EINVAL;

	if (device_is_dax(crypt_data_device(cd)) > 0) {
		log_err(cd, _("Reencryption is not supported for DAX (persistent memory) devices."));
		return -EINVAL;
	}

	crypt_keyslot_context_init_by_passphrase_internal(&kc, passphrase, passphrase_size);

	r = reencrypt_init_by_keyslot_context(cd, name, &kc, &kc, keyslot_old,
					      keyslot_new, cipher, cipher_mode, params);

	crypt_keyslot_context_destroy_internal(&kc);

	return r;
}

int crypt_reencrypt_init_by_keyslot_context(struct crypt_device *cd,
	const char *name,
	struct crypt_keyslot_context *kc_old,
	struct crypt_keyslot_context *kc_new,
	int keyslot_old,
	int keyslot_new,
	const char *cipher,
	const char *cipher_mode,
	const struct crypt_params_reencrypt *params)
{
	if (onlyLUKS2reencrypt(cd) || (!kc_old && !kc_new))
		return -EINVAL;
	if (params && (params->flags & CRYPT_REENCRYPT_INITIALIZE_ONLY) && (params->flags & CRYPT_REENCRYPT_RESUME_ONLY))
		return -EINVAL;

	if (device_is_dax(crypt_data_device(cd)) > 0) {
		log_err(cd, _("Reencryption is not supported for DAX (persistent memory) devices."));
		return -EINVAL;
	}

	return reencrypt_init_by_keyslot_context(cd, name, kc_old, kc_new, keyslot_old, keyslot_new, cipher, cipher_mode, params);
}

#if USE_LUKS2_REENCRYPTION
static reenc_status_t reencrypt_step(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh,
		uint64_t device_size,
		bool online)
{
	int r;
	struct reenc_protection *rp;

	assert(hdr);
	assert(rh);

	rp = &rh->rp;

	/* in memory only */
	r = reencrypt_make_segments(cd, hdr, rh, device_size);
	if (r)
		return REENC_ERR;

	r = reencrypt_assign_segments(cd, hdr, rh, 1, 0);
	if (r) {
		log_err(cd, _("Failed to set device segments for next reencryption hotzone."));
		return REENC_ERR;
	}

	log_dbg(cd, "Reencrypting chunk starting at offset: %" PRIu64 ", size :%" PRIu64 ".", rh->offset, rh->length);
	log_dbg(cd, "data_offset: %" PRIu64, crypt_get_data_offset(cd) << SECTOR_SHIFT);

	if (!rh->offset && rp->type == REENC_PROTECTION_DATASHIFT && rh->jobj_segment_moved) {
		crypt_storage_wrapper_destroy(rh->cw1);
		log_dbg(cd, "Reinitializing old segment storage wrapper for moved segment.");
		r = crypt_storage_wrapper_init(cd, &rh->cw1, crypt_data_device(cd),
				LUKS2_reencrypt_get_data_offset_moved(hdr),
				crypt_get_iv_offset(cd),
				reencrypt_get_sector_size_old(hdr),
				reencrypt_segment_cipher_old(hdr),
				crypt_volume_key_by_id(rh->vks, rh->digest_old),
				rh->wflags1);
		if (r) {
			log_err(cd, _("Failed to initialize old segment storage wrapper."));
			return REENC_ROLLBACK;
		}

		if (rh->rp_moved_segment.type != REENC_PROTECTION_NOT_SET) {
			log_dbg(cd, "Switching to moved segment resilience type.");
			rp = &rh->rp_moved_segment;
		}
	}

	r = reencrypt_hotzone_protect_ready(cd, rp);
	if (r) {
		log_err(cd, _("Failed to initialize hotzone protection."));
		return REENC_ROLLBACK;
	}

	if (online) {
		r = reencrypt_refresh_overlay_devices(cd, hdr, rh->overlay_name, rh->hotzone_name, rh->vks, rh->device_size, rh->flags);
		/* Teardown overlay devices with dm-error. None bio shall pass! */
		if (r != REENC_OK)
			return r;
	}

	rh->read = crypt_storage_wrapper_read(rh->cw1, rh->offset, rh->reenc_buffer, rh->length);
	if (rh->read < 0) {
		/* severity normal */
		log_err(cd, _("Failed to read hotzone area starting at %" PRIu64 "."), rh->offset);
		return REENC_ROLLBACK;
	}

	/* metadata commit point */
	r = reencrypt_hotzone_protect_final(cd, hdr, rh->reenc_keyslot, rp, rh->reenc_buffer, rh->read);
	if (r < 0) {
		/* severity normal */
		log_err(cd, _("Failed to write reencryption resilience metadata."));
		return REENC_ROLLBACK;
	}

	r = crypt_storage_wrapper_decrypt(rh->cw1, rh->offset, rh->reenc_buffer, rh->read);
	if (r) {
		/* severity normal */
		log_err(cd, _("Decryption failed."));
		return REENC_ROLLBACK;
	}
	if (rh->read != crypt_storage_wrapper_encrypt_write(rh->cw2, rh->offset, rh->reenc_buffer, rh->read)) {
		/* severity fatal */
		log_err(cd, _("Failed to write hotzone area starting at %" PRIu64 "."), rh->offset);
		return REENC_FATAL;
	}

	if (rp->type != REENC_PROTECTION_NONE && crypt_storage_wrapper_datasync(rh->cw2)) {
		log_err(cd, _("Failed to sync data."));
		return REENC_FATAL;
	}

	/* metadata commit safe point */
	r = reencrypt_assign_segments(cd, hdr, rh, 0, rp->type != REENC_PROTECTION_NONE);
	if (r) {
		/* severity fatal */
		log_err(cd, _("Failed to update metadata after current reencryption hotzone completed."));
		return REENC_FATAL;
	}

	if (online) {
		/* severity normal */
		log_dbg(cd, "Resuming device %s", rh->hotzone_name);
		r = dm_resume_device(cd, rh->hotzone_name, DM_RESUME_PRIVATE);
		if (r) {
			log_err(cd, _("Failed to resume device %s."), rh->hotzone_name);
			return REENC_ERR;
		}
	}

	return REENC_OK;
}

static int reencrypt_erase_backup_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, "backup-previous");
	if (segment >= 0) {
		if (LUKS2_digest_segment_assign(cd, hdr, segment, CRYPT_ANY_DIGEST, 0, 0))
			return -EINVAL;
		json_object_object_del_by_uint(LUKS2_get_segments_jobj(hdr), segment);
	}
	segment = LUKS2_get_segment_id_by_flag(hdr, "backup-final");
	if (segment >= 0) {
		if (LUKS2_digest_segment_assign(cd, hdr, segment, CRYPT_ANY_DIGEST, 0, 0))
			return -EINVAL;
		json_object_object_del_by_uint(LUKS2_get_segments_jobj(hdr), segment);
	}
	segment = LUKS2_get_segment_id_by_flag(hdr, "backup-moved-segment");
	if (segment >= 0) {
		if (LUKS2_digest_segment_assign(cd, hdr, segment, CRYPT_ANY_DIGEST, 0, 0))
			return -EINVAL;
		json_object_object_del_by_uint(LUKS2_get_segments_jobj(hdr), segment);
	}

	return 0;
}

static int reencrypt_wipe_unused_device_area(struct crypt_device *cd, struct luks2_reencrypt *rh)
{
	uint64_t offset, length, dev_size;
	int r = 0;

	assert(cd);
	assert(rh);

	if (rh->jobj_segment_moved && rh->mode == CRYPT_REENCRYPT_ENCRYPT) {
		offset = json_segment_get_offset(rh->jobj_segment_moved, 0);
		length = json_segment_get_size(rh->jobj_segment_moved, 0);
		log_dbg(cd, "Wiping %" PRIu64 " bytes of backup segment data at offset %" PRIu64,
			length, offset);
		r = crypt_wipe_device(cd, crypt_data_device(cd), CRYPT_WIPE_RANDOM,
				offset, length, 1024 * 1024, NULL, NULL);
	}

	if (r < 0)
		return r;

	if (rh->rp.type == REENC_PROTECTION_DATASHIFT && rh->direction == CRYPT_REENCRYPT_FORWARD) {
		r = device_size(crypt_data_device(cd), &dev_size);
		if (r < 0)
			return r;

		if (dev_size < data_shift_value(&rh->rp))
			return -EINVAL;

		offset = dev_size - data_shift_value(&rh->rp);
		length = data_shift_value(&rh->rp);
		log_dbg(cd, "Wiping %" PRIu64 " bytes of data at offset %" PRIu64,
			length, offset);
		r = crypt_wipe_device(cd, crypt_data_device(cd), CRYPT_WIPE_RANDOM,
				offset, length, 1024 * 1024, NULL, NULL);
	}

	return r;
}

static int reencrypt_teardown_ok(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reencrypt *rh)
{
	int i, r;
	uint64_t dmt_flags;
	bool finished = !(rh->device_size > rh->progress);

	if (rh->rp.type == REENC_PROTECTION_NONE &&
	    LUKS2_hdr_write(cd, hdr)) {
		log_err(cd, _("Failed to write LUKS2 metadata."));
		return -EINVAL;
	}

	if (rh->online) {
		r = LUKS2_reload(cd, rh->device_name, rh->vks, rh->device_size, rh->flags);
		if (r)
			log_err(cd, _("Failed to reload device %s."), rh->device_name);
		if (!r) {
			r = dm_resume_device(cd, rh->device_name, DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH);
			if (r)
				log_err(cd, _("Failed to resume device %s."), rh->device_name);
		}
		dm_remove_device(cd, rh->overlay_name, 0);
		dm_remove_device(cd, rh->hotzone_name, 0);

		if (!r && finished && rh->mode == CRYPT_REENCRYPT_DECRYPT &&
		    !dm_flags(cd, DM_LINEAR, &dmt_flags) && (dmt_flags & DM_DEFERRED_SUPPORTED))
		    dm_remove_device(cd, rh->device_name, CRYPT_DEACTIVATE_DEFERRED);
	}

	if (finished) {
		if (reencrypt_wipe_unused_device_area(cd, rh))
			log_err(cd, _("Failed to wipe unused data device area."));
		if (reencrypt_get_data_offset_new(hdr) && LUKS2_set_keyslots_size(hdr, reencrypt_get_data_offset_new(hdr)))
			log_dbg(cd, "Failed to set new keyslots area size.");
		if (rh->digest_old >= 0 && rh->digest_new != rh->digest_old)
			for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++)
				if (LUKS2_digest_by_keyslot(hdr, i) == rh->digest_old && crypt_keyslot_destroy(cd, i))
					log_err(cd, _("Failed to remove unused (unbound) keyslot %d."), i);

		if (reencrypt_erase_backup_segments(cd, hdr))
			log_dbg(cd, "Failed to erase backup segments");

		if (reencrypt_update_flag(cd, 0, false, false))
			log_dbg(cd, "Failed to disable reencryption requirement flag.");

		/* metadata commit point also removing reencryption flag on-disk */
		if (crypt_keyslot_destroy(cd, rh->reenc_keyslot)) {
			log_err(cd, _("Failed to remove reencryption keyslot."));
			return -EINVAL;
		}
	}

	return 0;
}

static void reencrypt_teardown_fatal(struct crypt_device *cd, struct luks2_reencrypt *rh)
{
	log_err(cd, _("Fatal error while reencrypting chunk starting at %" PRIu64 ", %" PRIu64 " sectors long."),
		(rh->offset >> SECTOR_SHIFT) + crypt_get_data_offset(cd), rh->length >> SECTOR_SHIFT);

	if (rh->online) {
		log_err(cd, _("Online reencryption failed."));
		if (dm_status_suspended(cd, rh->hotzone_name) > 0) {
			log_dbg(cd, "Hotzone device %s suspended, replacing with dm-error.", rh->hotzone_name);
			if (dm_error_device(cd, rh->hotzone_name)) {
				log_err(cd, _("Failed to replace suspended device %s with dm-error target."), rh->hotzone_name);
				log_err(cd, _("Do not resume the device unless replaced with error target manually."));
			}
		}
	}
}

static int reencrypt_teardown(struct crypt_device *cd, struct luks2_hdr *hdr,
		struct luks2_reencrypt *rh, reenc_status_t rs, bool interrupted,
		int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
		void *usrptr)
{
	int r;

	switch (rs) {
	case REENC_OK:
		if (progress && !interrupted)
			progress(rh->device_size, rh->progress, usrptr);
		r = reencrypt_teardown_ok(cd, hdr, rh);
		break;
	case REENC_FATAL:
		reencrypt_teardown_fatal(cd, rh);
		/* fall-through */
	default:
		r = -EIO;
	}

	/* this frees reencryption lock */
	LUKS2_reencrypt_free(cd, rh);
	crypt_set_luks2_reencrypt(cd, NULL);

	return r;
}

int crypt_reencrypt_run(
	struct crypt_device *cd,
	int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
	void *usrptr)
{
	int r;
	crypt_reencrypt_info ri;
	struct luks2_hdr *hdr;
	struct luks2_reencrypt *rh;
	reenc_status_t rs;
	bool quit = false;

	if (onlyLUKS2reencrypt(cd))
		return -EINVAL;

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	ri = LUKS2_reencrypt_status(hdr);
	if (ri > CRYPT_REENCRYPT_CLEAN) {
		log_err(cd, _("Cannot proceed with reencryption. Unexpected reencryption status."));
		return -EINVAL;
	}

	rh = crypt_get_luks2_reencrypt(cd);
	if (!rh || (!rh->reenc_lock && crypt_metadata_locking_enabled())) {
		log_err(cd, _("Missing or invalid reencrypt context."));
		return -EINVAL;
	}

	log_dbg(cd, "Resuming LUKS2 reencryption.");

	if (rh->online) {
		/* This is last resort to avoid data corruption. Abort is justified here. */
		assert(device_direct_io(crypt_data_device(cd)));

		if (reencrypt_init_device_stack(cd, rh)) {
			log_err(cd, _("Failed to initialize reencryption device stack."));
			return -EINVAL;
		}
	}

	log_dbg(cd, "Progress %" PRIu64 ", device_size %" PRIu64, rh->progress, rh->device_size);

	rs = REENC_OK;

	if (progress && progress(rh->device_size, rh->progress, usrptr))
		quit = true;

	while (!quit && (rh->device_size > rh->progress)) {
		rs = reencrypt_step(cd, hdr, rh, rh->device_size, rh->online);
		if (rs != REENC_OK)
			break;

		log_dbg(cd, "Progress %" PRIu64 ", device_size %" PRIu64, rh->progress, rh->device_size);
		if (progress && progress(rh->device_size, rh->progress, usrptr))
			quit = true;

		r = reencrypt_context_update(cd, rh);
		if (r) {
			log_err(cd, _("Failed to update reencryption context."));
			rs = REENC_ERR;
			break;
		}

		log_dbg(cd, "Next reencryption offset will be %" PRIu64 " sectors.", rh->offset);
		log_dbg(cd, "Next reencryption chunk size will be %" PRIu64 " sectors).", rh->length);
	}

	r = reencrypt_teardown(cd, hdr, rh, rs, quit, progress, usrptr);
	return r;
}


static int reencrypt_recovery(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		uint64_t device_size,
		struct volume_key *vks)
{
	int r;
	struct luks2_reencrypt *rh = NULL;

	r = reencrypt_load(cd, hdr, device_size, 0, 0, vks, &rh);
	if (r < 0) {
		log_err(cd, _("Failed to load LUKS2 reencryption context."));
		return r;
	}

	r = reencrypt_recover_segment(cd, hdr, rh, vks);
	if (r < 0)
		goto out;

	if ((r = reencrypt_assign_segments(cd, hdr, rh, 0, 0)))
		goto out;

	r = reencrypt_context_update(cd, rh);
	if (r) {
		log_err(cd, _("Failed to update reencryption context."));
		goto out;
	}

	r = reencrypt_teardown_ok(cd, hdr, rh);
	if (!r)
		r = LUKS2_hdr_write(cd, hdr);
out:
	LUKS2_reencrypt_free(cd, rh);

	return r;
}
#else /* USE_LUKS2_REENCRYPTION */
int crypt_reencrypt_run(
	struct crypt_device *cd,
	int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
	void *usrptr)
{
	UNUSED(progress);
	UNUSED(usrptr);

	log_err(cd, _("This operation is not supported for this device type."));
	return -ENOTSUP;
}
#endif

int crypt_reencrypt(
	struct crypt_device *cd,
	int (*progress)(uint64_t size, uint64_t offset, void *usrptr))
{
	return crypt_reencrypt_run(cd, progress, NULL);
}

/*
 * use only for calculation of minimal data device size.
 * The real data offset is taken directly from segments!
 */
int LUKS2_reencrypt_data_offset(struct luks2_hdr *hdr, bool blockwise)
{
	crypt_reencrypt_info ri = LUKS2_reencrypt_status(hdr);
	uint64_t data_offset = LUKS2_get_data_offset(hdr);

	if (ri == CRYPT_REENCRYPT_CLEAN && reencrypt_direction(hdr) == CRYPT_REENCRYPT_FORWARD)
		data_offset += reencrypt_data_shift(hdr) >> SECTOR_SHIFT;

	return blockwise ? data_offset : data_offset << SECTOR_SHIFT;
}

/* internal only */
int LUKS2_reencrypt_check_device_size(struct crypt_device *cd, struct luks2_hdr *hdr,
	uint64_t check_size, uint64_t *dev_size, bool device_exclusive_check, bool dynamic)
{
	int r;
	uint64_t data_offset, real_size = 0;

	if (reencrypt_direction(hdr) == CRYPT_REENCRYPT_BACKWARD &&
	    (LUKS2_get_segment_by_flag(hdr, "backup-moved-segment") || dynamic))
		check_size += reencrypt_data_shift(hdr);

	r = device_check_access(cd, crypt_data_device(cd),
				device_exclusive_check ? DEV_EXCL : DEV_OK);
	if (r)
		return r;

	data_offset = LUKS2_reencrypt_data_offset(hdr, false);

	r = device_check_size(cd, crypt_data_device(cd), data_offset, 1);
	if (r)
		return r;

	r = device_size(crypt_data_device(cd), &real_size);
	if (r)
		return r;

	log_dbg(cd, "Required minimal device size: %" PRIu64 " (%" PRIu64 " sectors)"
		    ", real device size: %" PRIu64 " (%" PRIu64 " sectors) "
		    "calculated device size: %" PRIu64 " (%" PRIu64 " sectors)",
		    check_size, check_size >> SECTOR_SHIFT, real_size, real_size >> SECTOR_SHIFT,
		    real_size - data_offset, (real_size - data_offset) >> SECTOR_SHIFT);

	if (real_size < data_offset || (check_size && real_size < check_size)) {
		log_err(cd, _("Device %s is too small."), device_path(crypt_data_device(cd)));
		return -EINVAL;
	}

	*dev_size = real_size - data_offset;

	return 0;
}
#if USE_LUKS2_REENCRYPTION
/* returns keyslot number on success (>= 0) or negative errnor otherwise */
int LUKS2_reencrypt_locked_recovery_by_vks(struct crypt_device *cd,
	struct volume_key *vks)
{
	uint64_t minimal_size, device_size;
	int r = -EINVAL;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	log_dbg(cd, "Entering reencryption crash recovery.");

	if (LUKS2_get_data_size(hdr, &minimal_size, NULL))
		return r;
	if (LUKS2_reencrypt_check_device_size(cd, hdr, minimal_size, &device_size, true, false))
		goto out;

	r = reencrypt_recovery(cd, hdr, device_size, vks);

out:
	if (r < 0)
		crypt_drop_uploaded_keyring_key(cd, vks);
	return r;
}
#endif
crypt_reencrypt_info LUKS2_reencrypt_get_params(struct luks2_hdr *hdr,
	struct crypt_params_reencrypt *params)
{
	crypt_reencrypt_info ri;
	int digest;
	uint8_t version;

	if (params)
		memset(params, 0, sizeof(*params));

	ri = LUKS2_reencrypt_status(hdr);
	if (ri == CRYPT_REENCRYPT_NONE || ri == CRYPT_REENCRYPT_INVALID || !params)
		return ri;

	digest = LUKS2_digest_by_keyslot(hdr, LUKS2_find_keyslot(hdr, "reencrypt"));
	if (digest < 0 && digest != -ENOENT)
		return CRYPT_REENCRYPT_INVALID;

	/*
	 * In case there's an old "online-reencrypt" requirement or reencryption
	 * keyslot digest is missing inform caller reencryption metadata requires repair.
	 */
	if (!LUKS2_config_get_reencrypt_version(hdr, &version) &&
	    (version < 2 || digest == -ENOENT)) {
		params->flags |= CRYPT_REENCRYPT_REPAIR_NEEDED;
		return ri;
	}

	params->mode = reencrypt_mode(hdr);
	params->direction = reencrypt_direction(hdr);
	params->resilience = reencrypt_resilience_type(hdr);
	params->hash = reencrypt_resilience_hash(hdr);
	params->data_shift = reencrypt_data_shift(hdr) >> SECTOR_SHIFT;
	params->max_hotzone_size = 0;
	if (LUKS2_get_segment_id_by_flag(hdr, "backup-moved-segment") >= 0)
		params->flags |= CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT;

	return ri;
}
