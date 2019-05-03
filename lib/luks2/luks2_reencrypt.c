/*
 * LUKS - Linux Unified Key Setup v2, reencryption helpers
 *
 * Copyright (C) 2015-2019, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2019, Ondrej Kozina
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
#include "utils_device_locking.h"

static json_object *reencrypt_segment(struct luks2_hdr *hdr, unsigned new)
{
	return LUKS2_get_segment_by_flag(hdr, new ? "backup-final" : "backup-previous");
}

static json_object *LUKS2_reencrypt_segment_new(struct luks2_hdr *hdr)
{
	return reencrypt_segment(hdr, 1);
}

static json_object *LUKS2_reencrypt_segment_old(struct luks2_hdr *hdr)
{
	return reencrypt_segment(hdr, 0);
}

static const char *LUKS2_reencrypt_segment_cipher_new(struct luks2_hdr *hdr)
{
	return json_segment_get_cipher(reencrypt_segment(hdr, 1));
}

static const char *LUKS2_reencrypt_segment_cipher_old(struct luks2_hdr *hdr)
{
	return json_segment_get_cipher(reencrypt_segment(hdr, 0));
}

static int LUKS2_reencrypt_get_sector_size_new(struct luks2_hdr *hdr)
{
	return json_segment_get_sector_size(reencrypt_segment(hdr, 1));
}

static int LUKS2_reencrypt_get_sector_size_old(struct luks2_hdr *hdr)
{
	return json_segment_get_sector_size(reencrypt_segment(hdr, 0));
}

static uint64_t _reencrypt_data_offset(struct luks2_hdr *hdr, unsigned new)
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

static uint64_t LUKS2_reencrypt_get_data_offset_new(struct luks2_hdr *hdr)
{
	return _reencrypt_data_offset(hdr, 1);
}

static uint64_t LUKS2_reencrypt_get_data_offset_old(struct luks2_hdr *hdr)
{
	return _reencrypt_data_offset(hdr, 0);
}

static int _reencrypt_digest(struct luks2_hdr *hdr, unsigned new)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, new ? "backup-final" : "backup-previous");

	if (segment < 0)
		return segment;

	return LUKS2_digest_by_segment(hdr, segment);
}

int LUKS2_reencrypt_digest_new(struct luks2_hdr *hdr)
{
	return _reencrypt_digest(hdr, 1);
}

int LUKS2_reencrypt_digest_old(struct luks2_hdr *hdr)
{
	return _reencrypt_digest(hdr, 0);
}

/* none, checksums, journal or shift */
const char *LUKS2_reencrypt_protection_type(struct luks2_hdr *hdr)
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

const char *LUKS2_reencrypt_protection_hash(struct luks2_hdr *hdr)
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

static uint32_t LUKS2_reencrypt_protection_sector_size(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type, *jobj_hash, *jobj_sector_size;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return 0;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return 0;
	if (strcmp(json_object_get_string(jobj_type), "checksum"))
		return 0;
	if (!json_object_object_get_ex(jobj_area, "hash", &jobj_hash))
		return 0;
	if (!json_object_object_get_ex(jobj_area, "sector_size", &jobj_sector_size))
		return 0;

	return json_object_get_uint32(jobj_sector_size);
}

static json_object *_enc_create_segments_shift_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int reenc_seg, i = 0;
	json_object *jobj_copy, *jobj_seg_new = NULL, *jobj_segs_after = json_object_new_object();
	uint64_t tmp;

	if (!rh->jobj_segs_pre || !jobj_segs_after)
		goto err;

	if (json_segments_count(rh->jobj_segs_pre) == 0)
		return jobj_segs_after;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre);
	if (reenc_seg < 0)
		goto err;

	while (i < reenc_seg) {
		jobj_copy = json_segments_get_segment(rh->jobj_segs_pre, i);
		if (!jobj_copy)
			goto err;
		json_object_object_add_by_uint(jobj_segs_after, i++, json_object_get(jobj_copy));
	}

	if (json_object_copy(json_segments_get_segment(rh->jobj_segs_pre, reenc_seg + 1), &jobj_seg_new)) {
		if (json_object_copy(json_segments_get_segment(rh->jobj_segs_pre, reenc_seg), &jobj_seg_new))
			goto err;
		json_segment_remove_flag(jobj_seg_new, "in-reencryption");
		tmp = rh->length;
	} else {
		json_object_object_add(jobj_seg_new, "offset", json_object_new_uint64(rh->offset + data_offset));
		json_object_object_add(jobj_seg_new, "iv_tweak", json_object_new_uint64(rh->offset >> SECTOR_SHIFT));
		tmp = json_segment_get_size(jobj_seg_new, 0) + rh->length;
	}

	/* alter size of new segment, reenc_seg == 0 we're finished */
	json_object_object_add(jobj_seg_new, "size", reenc_seg > 0 ? json_object_new_uint64(tmp) : json_object_new_string("dynamic"));
	JSON_DBG(cd, jobj_seg_new, "jobj_new_seg_after:");
	json_object_object_add_by_uint(jobj_segs_after, reenc_seg, jobj_seg_new);

	return jobj_segs_after;
err:
	json_object_put(jobj_segs_after);
	return NULL;
}

static json_object *_enc_create_segments_shift_pre(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int sg, crypt_seg, i = 0;
	uint64_t segment_size;
	json_object *jobj_seg_shrunk, *jobj_seg_new, *jobj_copy, *jobj_enc_seg = NULL,
		     *jobj_segs_pre = json_object_new_object();

	if (!jobj_segs_pre)
		return NULL;

	crypt_seg = LUKS2_segment_by_type(hdr, "crypt");

	/* FIXME: This is hack. Find proper way to fix it. */
	sg = LUKS2_last_segment_by_type(hdr, "linear");
	if (rh->offset && sg < 0)
		goto err;
	if (sg < 0)
		return jobj_segs_pre;

	jobj_enc_seg = json_segment_create_crypt(data_offset + rh->offset,
						      rh->offset >> SECTOR_SHIFT,
						      &rh->length,
						      LUKS2_reencrypt_segment_cipher_new(hdr),
						      LUKS2_reencrypt_get_sector_size_new(hdr),
						      1);
	JSON_DBG(cd, jobj_enc_seg, "jobj_enc_seg:");

	while (i < sg) {
		jobj_copy = LUKS2_get_segment_jobj(hdr, i);
		if (!jobj_copy)
			goto err;
		json_object_object_add_by_uint(jobj_segs_pre, i++, json_object_get(jobj_copy));
	}

	segment_size = LUKS2_segment_size(hdr, sg, 0);
	if (segment_size > rh->length) {
		jobj_seg_shrunk = NULL;
		if (json_object_copy(LUKS2_get_segment_jobj(hdr, sg), &jobj_seg_shrunk))
			goto err;
		json_object_object_add(jobj_seg_shrunk, "size", json_object_new_uint64(segment_size - rh->length));
		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_seg_shrunk);
		JSON_DBG(cd, jobj_seg_shrunk, "jobj_seg_shrunk:");
	}

	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_enc_seg);
	jobj_enc_seg = NULL; /* see err: label */

	/* first crypt segment after encryption ? */
	if (crypt_seg >= 0) {
		jobj_seg_new = LUKS2_get_segment_jobj(hdr, crypt_seg);
		if (!jobj_seg_new)
			goto err;
		json_object_object_add_by_uint(jobj_segs_pre, sg, json_object_get(jobj_seg_new));
		JSON_DBG(cd, jobj_seg_new, "jobj_seg_new:");
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_enc_seg);
	json_object_put(jobj_segs_pre);

	return NULL;
}

static json_object *LUKS2_create_segment_new(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct luks2_reenc_context *rh,
		uint64_t data_offset,
		uint64_t segment_offset,
		uint64_t iv_offset,
		const uint64_t *segment_length)
{
	switch (rh->type) {
	case REENCRYPT:
	case ENCRYPT:
		return json_segment_create_crypt(data_offset + segment_offset,
						  crypt_get_iv_offset(cd) + (iv_offset >> SECTOR_SHIFT),
						  segment_length,
						  LUKS2_reencrypt_segment_cipher_new(hdr),
						  LUKS2_reencrypt_get_sector_size_new(hdr), 0);
	case DECRYPT:
		return json_segment_create_linear(data_offset + segment_offset, segment_length, 0);
	}

	return NULL;
}

static json_object *_reenc_segments_forward_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int reenc_seg;
	json_object *jobj_new_seg_after, *jobj_old_seg,
		    *jobj_segs_after = json_object_new_object();
	uint64_t tmp = rh->offset + rh->length;

	if (!rh->jobj_segs_pre || !jobj_segs_after)
		goto err;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre);
	if (reenc_seg < 0)
		return NULL;

	jobj_old_seg = json_segments_get_segment(rh->jobj_segs_pre, reenc_seg + 1);

	/*
	 * if there's no old segment after reencryption, we're done.
	 * Set size to 'dynamic' again.
	 */
	jobj_new_seg_after = LUKS2_create_segment_new(cd, hdr, rh, data_offset, 0, 0, jobj_old_seg ? &tmp : NULL);
	if (!jobj_new_seg_after)
		goto err;
	JSON_DBG(cd, jobj_new_seg_after, "jobj_new_seg_after:");
	json_object_object_add_by_uint(jobj_segs_after, 0, jobj_new_seg_after);

	if (jobj_old_seg)
		json_object_object_add_by_uint(jobj_segs_after, 1, json_object_get(jobj_old_seg));

	return jobj_segs_after;
err:
	json_object_put(jobj_segs_after);
	return NULL;
}

static json_object *_reenc_segments_backward_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int reenc_seg;
	json_object *jobj_new_seg_after, *jobj_old_seg,
		    *jobj_segs_after = json_object_new_object();

	if (!rh->jobj_segs_pre || !jobj_segs_after)
		goto err;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre);
	if (reenc_seg < 0)
		return NULL;

	jobj_old_seg = json_segments_get_segment(rh->jobj_segs_pre, reenc_seg - 1);
	if (jobj_old_seg)
		json_object_object_add_by_uint(jobj_segs_after, reenc_seg - 1, json_object_get(jobj_old_seg));
	jobj_new_seg_after = LUKS2_create_segment_new(cd, hdr, rh, data_offset, rh->offset, rh->offset, NULL);
	if (!jobj_new_seg_after)
		goto err;
	JSON_DBG(cd, jobj_new_seg_after, "jobj_new_seg_after:");
	json_object_object_add_by_uint(jobj_segs_after, reenc_seg, jobj_new_seg_after);

	return jobj_segs_after;
err:
	json_object_put(jobj_segs_after);
	return NULL;
}

static json_object *LUKS2_create_segment_reenc(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct luks2_reenc_context *rh,
		uint64_t data_offset,
		uint64_t segment_offset,
		uint64_t iv_offset,
		const uint64_t *segment_length)
{
	switch (rh->type) {
	case REENCRYPT:
	case ENCRYPT:
		return json_segment_create_crypt(data_offset + segment_offset,
				crypt_get_iv_offset(cd) + (iv_offset >> SECTOR_SHIFT),
				segment_length,
				LUKS2_reencrypt_segment_cipher_new(hdr),
				LUKS2_reencrypt_get_sector_size_new(hdr), 1);
	case DECRYPT:
		return json_segment_create_linear(data_offset + segment_offset, segment_length, 1);
	}

	return NULL;
}

static json_object *LUKS2_create_segment_old(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct luks2_reenc_context *rh,
		uint64_t data_offset,
		uint64_t segment_offset,
		const uint64_t *segment_length)
{
	json_object *jobj_old_seg = NULL;

	switch (rh->type) {
	case REENCRYPT:
	case DECRYPT:
		jobj_old_seg = json_segment_create_crypt(data_offset + segment_offset,
						    crypt_get_iv_offset(cd) + (segment_offset >> SECTOR_SHIFT),
						    segment_length,
						    LUKS2_reencrypt_segment_cipher_old(hdr),
						    LUKS2_reencrypt_get_sector_size_old(hdr),
						    0);
		break;
	case ENCRYPT:
		jobj_old_seg = json_segment_create_linear(data_offset + segment_offset, segment_length, 0);
	}

	return jobj_old_seg;
}

static json_object *_reenc_segments_forward_pre(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	json_object *jobj_segs_pre, *jobj_reenc_seg, *jobj_old_seg, *jobj_new_seg;
	unsigned int sg = 0;
	uint64_t tmp = rh->offset + rh->length;

	jobj_segs_pre = json_object_new_object();
	if (!jobj_segs_pre)
		return NULL;

	if (rh->offset) {
		jobj_new_seg = LUKS2_create_segment_new(cd, hdr, rh, data_offset, 0, 0, &rh->offset);
		if (!jobj_new_seg)
			goto err;
		JSON_DBG(cd, jobj_new_seg, "jobj_new_seg:");
		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_new_seg);
	}

	jobj_reenc_seg = LUKS2_create_segment_reenc(cd, hdr, rh, data_offset, rh->offset, rh->offset, &rh->length);
	if (!jobj_reenc_seg)
		goto err;

	JSON_DBG(cd, jobj_reenc_seg, "jobj_reenc_seg:");

	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_reenc_seg);

	if (tmp < device_size) {
		jobj_old_seg = LUKS2_create_segment_old(cd, hdr, rh, data_offset + rh->data_shift, rh->offset + rh->length, NULL);
		if (!jobj_old_seg)
			goto err;
		JSON_DBG(cd, jobj_old_seg, "jobj_old_seg:");
		json_object_object_add_by_uint(jobj_segs_pre, sg, jobj_old_seg);
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_segs_pre);
	return NULL;
}

static json_object *_reenc_segments_backward_pre(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	json_object *jobj_reenc_seg, *jobj_new_seg, *jobj_old_seg = NULL,
		    *jobj_segs_pre = json_object_new_object();
	int sg = 0;
	uint64_t tmp = rh->offset + rh->length;

	if (!jobj_segs_pre)
		return NULL;

	if (rh->offset) {
		if (json_object_copy(LUKS2_get_segment_jobj(hdr, 0), &jobj_old_seg))
			goto err;
		json_object_object_add(jobj_old_seg, "size", json_object_new_uint64(rh->offset));

		JSON_DBG(cd, jobj_old_seg, "jobj_old_seg:");

		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_old_seg);
	}

	jobj_reenc_seg = LUKS2_create_segment_reenc(cd, hdr, rh, data_offset, rh->offset, rh->offset, &rh->length);
	if (!jobj_reenc_seg)
		goto err;

	JSON_DBG(cd, jobj_reenc_seg, "jobj_reenc_seg:");
	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_reenc_seg);

	if (tmp < device_size) {
		jobj_new_seg = LUKS2_create_segment_new(cd, hdr, rh, data_offset, rh->offset + rh->length, rh->offset + rh->length, NULL);
		if (!jobj_new_seg)
			goto err;
		JSON_DBG(cd, jobj_new_seg, "jobj_new_seg:");
		json_object_object_add_by_uint(jobj_segs_pre, sg, jobj_new_seg);
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_segs_pre);
	return NULL;
}

static int LUKS2_reenc_create_segments_pre(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	rh->jobj_segs_pre = NULL;

	if (rh->type == ENCRYPT && rh->direction == CRYPT_REENCRYPT_BACKWARD && rh->data_shift && rh->jobj_segment_moved) {
		log_dbg(cd, "Calculating hot segments for encryption with data move.");
		rh->jobj_segs_pre = _enc_create_segments_shift_pre(cd, hdr, rh, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_FORWARD) {
		log_dbg(cd, "Calculating hot segments (forward direction).");
		rh->jobj_segs_pre = _reenc_segments_forward_pre(cd, hdr, rh, device_size, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_BACKWARD) {
		log_dbg(cd, "Calculating hot segments (backward direction).");
		rh->jobj_segs_pre = _reenc_segments_backward_pre(cd, hdr, rh, device_size, data_offset);
	}

	return rh->jobj_segs_pre ? 0 : -EINVAL;
}

static int LUKS2_reenc_create_segments_after(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t data_offset)
{
	rh->jobj_segs_after = NULL;

	if (rh->type == ENCRYPT && rh->direction == CRYPT_REENCRYPT_BACKWARD && rh->data_shift && rh->jobj_segment_moved) {
		log_dbg(cd, "Calculating 'after' segments for encryption with data move.");
		rh->jobj_segs_after = _enc_create_segments_shift_after(cd, hdr, rh, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_FORWARD) {
		log_dbg(cd, "Calculating 'after' segments (forward direction).");
		rh->jobj_segs_after = _reenc_segments_forward_after(cd, hdr, rh, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_BACKWARD) {
		log_dbg(cd, "Calculating 'after' segments (backward direction).");
		rh->jobj_segs_after = _reenc_segments_backward_after(cd, hdr, rh, data_offset);
	}

	return rh->jobj_segs_after ? 0 : -EINVAL;
}

static int LUKS2_reenc_create_segments(struct crypt_device *cd,
				struct luks2_hdr *hdr,
			        struct luks2_reenc_context *rh,
				uint64_t device_size)
{
	int r;
	//uint64_t data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;
	uint64_t data_offset = LUKS2_reencrypt_get_data_offset_new(hdr);

	if ((r = LUKS2_reenc_create_segments_pre(cd, hdr, rh, device_size, data_offset)))
		return r;

	if ((r = LUKS2_reenc_create_segments_after(cd, hdr, rh, data_offset)))
		json_object_put(rh->jobj_segs_pre);

	return r;
}

uint64_t LUKS2_reencrypt_data_shift(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_data_shift;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return 0;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "shift_size", &jobj_data_shift))
		return 0;

	return json_object_get_uint64(jobj_data_shift);
}

const char *LUKS2_reencrypt_mode(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_mode;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return NULL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);
	json_object_object_get_ex(jobj_keyslot, "mode", &jobj_mode);

	return json_object_get_string(jobj_mode);
}

static int LUKS2_reencrypt_direction(struct luks2_hdr *hdr, crypt_reencrypt_direction_info *di)
{
	const char *value;
	json_object *jobj_keyslot, *jobj_mode;
	int r, ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);
	json_object_object_get_ex(jobj_keyslot, "direction", &jobj_mode);

	value = json_object_get_string(jobj_mode);

	if (!strcmp(value, "forward")) {
		*di = CRYPT_REENCRYPT_FORWARD;
		r = 0;
	} else if (!strcmp(value, "backward")) {
		*di = CRYPT_REENCRYPT_BACKWARD;
		r = 0;
	} else
		r = -EINVAL;

	return r;
}

typedef enum { REENC_OK = 0, REENC_ERR, REENC_ROLLBACK, REENC_FATAL } reenc_status_t;

void LUKS2_reenc_context_free(struct crypt_device *cd, struct luks2_reenc_context *rh)
{
	if (!rh)
		return;

	if (rh->rp.type == REENC_PROTECTION_CHECKSUM) {
		if (rh->rp.p.csum.ch) {
			crypt_hash_destroy(rh->rp.p.csum.ch);
			rh->rp.p.csum.ch = NULL;
		}
		if (rh->rp.p.csum.checksums) {
			memset(rh->rp.p.csum.checksums, 0, rh->rp.p.csum.checksums_len);
			free(rh->rp.p.csum.checksums);
			rh->rp.p.csum.checksums = NULL;
		}
	}

	json_object_put(rh->jobj_segs_pre);
	rh->jobj_segs_pre = NULL;
	json_object_put(rh->jobj_segs_after);
	rh->jobj_segs_after = NULL;
	json_object_put(rh->jobj_segment_old);
	rh->jobj_segment_old = NULL;
	json_object_put(rh->jobj_segment_new);
	rh->jobj_segment_new = NULL;

	free(rh->reenc_buffer);
	rh->reenc_buffer = NULL;
	crypt_storage_wrapper_destroy(rh->cw1);
	rh->cw1 = NULL;
	crypt_storage_wrapper_destroy(rh->cw2);
	rh->cw2 = NULL;

	free(rh->device_name);
	free(rh->overlay_name);
	free(rh->hotzone_name);
	crypt_drop_keyring_key(cd, rh->vks);
	crypt_free_volume_key(rh->vks);
	crypt_unlock_internal(cd, rh->reenc_lock);
	free(rh);
}

static size_t _reenc_alignment(struct crypt_device *cd,
		struct luks2_hdr *hdr)
{
	int ss;
	/* FIXME: logical block size would make better sense */
	size_t alignment = device_block_size(cd, crypt_data_device(cd));

	log_dbg(cd, "data device sector size: %zu", alignment);

	ss = LUKS2_reencrypt_get_sector_size_old(hdr);
	log_dbg(cd, "Old sector size: %d", ss);
	if (ss > 0 && (size_t)ss > alignment)
		alignment = ss;
	ss = LUKS2_reencrypt_get_sector_size_new(hdr);
	log_dbg(cd, "New sector size: %d", ss);
	if (ss > 0 && (size_t)ss > alignment)
		alignment = (size_t)ss;

	return alignment;
}

/* returns void because it must not fail on valid LUKS2 header */
static void _load_backup_segments(struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh)
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

static int _offset_backward_moved(struct luks2_hdr *hdr, json_object *jobj_segments, uint64_t *reencrypt_length, uint64_t data_shift, uint64_t *offset)
{
	uint64_t tmp, linear_length = 0;
	int sg, segs = json_segments_count(jobj_segments);

	/* find reencrypt offset with data shift */
	for (sg = 0; sg < segs; sg++)
		if (LUKS2_segment_is_type(hdr, sg, "linear"))
			linear_length += LUKS2_segment_size(hdr, sg, 0);

	/* all active linear segments length */
	if (linear_length) {
		log_dbg(NULL, "linear length: %" PRIu64, linear_length);
		/* this must not happen. first linear segment is exaclty data offset long */
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

static int _offset_forward(struct luks2_hdr *hdr, json_object *jobj_segments, uint64_t *offset)
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

static int _offset_backward(struct luks2_hdr *hdr, json_object *jobj_segments, uint64_t device_size, uint64_t *length, uint64_t *offset)
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
static int LUKS2_get_reencrypt_offset(struct luks2_hdr *hdr, crypt_reencrypt_direction_info di, uint64_t device_size, uint64_t *reencrypt_length, uint64_t *offset)
{
	int sg;
	json_object *jobj_segments;
	uint64_t data_shift = LUKS2_reencrypt_data_shift(hdr);

	if (!offset)
		return -EINVAL;

	/* if there's segment in reencryption return directly offset of it */
	json_object_object_get_ex(hdr->jobj, "segments", &jobj_segments);
	sg = json_segments_segment_in_reencrypt(jobj_segments);
	if (sg >= 0) {
		*offset = LUKS2_segment_offset(hdr, sg, 0) - (LUKS2_reencrypt_get_data_offset_new(hdr));
		return 0;
	}

	if (di == CRYPT_REENCRYPT_FORWARD)
		return _offset_forward(hdr, jobj_segments, offset);
	else if (di == CRYPT_REENCRYPT_BACKWARD) {
		if (!strcmp(LUKS2_reencrypt_mode(hdr), "encrypt") && LUKS2_get_segment_id_by_flag(hdr, "backup-moved-segment") >= 0)
			return _offset_backward_moved(hdr, jobj_segments, reencrypt_length, data_shift, offset);
		return _offset_backward(hdr, jobj_segments, device_size, reencrypt_length, offset);
	}

	return -EINVAL;
}

static uint64_t LUKS2_get_reencrypt_length(struct luks2_hdr *hdr, struct luks2_reenc_context *rh, uint64_t keyslot_area_length, uint64_t length_max)
{
	uint64_t length;

	if (rh->rp.type == REENC_PROTECTION_NOOP)
		length = length_max;
	else if (rh->rp.type == REENC_PROTECTION_CHECKSUM)
		length = (keyslot_area_length / rh->rp.p.csum.hash_size) * rh->alignment;
	else if (rh->rp.type == REENC_PROTECTION_DATASHIFT)
		return LUKS2_reencrypt_data_shift(hdr);
	else
		length = keyslot_area_length;

	if (length_max && length > length_max)
		length = length_max;

	length -= (length % rh->alignment);

	return length;
}

static int _reenc_load(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, uint64_t device_size, const struct crypt_params_reencrypt *params)
{
	int r;
	uint64_t dummy, area_length;

	rh->reenc_keyslot = LUKS2_find_keyslot(hdr, "reencrypt");
	if (rh->reenc_keyslot < 0)
		return -EINVAL;
	if (LUKS2_keyslot_area(hdr, rh->reenc_keyslot, &dummy, &area_length) < 0)
		return -EINVAL;

	if (!strcmp(LUKS2_reencrypt_mode(hdr), "reencrypt"))
		rh->type = REENCRYPT;
	else if (!strcmp(LUKS2_reencrypt_mode(hdr), "encrypt"))
		rh->type = ENCRYPT;
	else if (!strcmp(LUKS2_reencrypt_mode(hdr), "decrypt")) {
		rh->type = DECRYPT;
	} else
		return -ENOTSUP;

	rh->alignment = _reenc_alignment(cd, hdr);
	if (!rh->alignment)
		return -EINVAL;

	r = LUKS2_reencrypt_direction(hdr, &rh->direction);
	if (r)
		return r;

	if (!strcmp(params->resilience, "datashift")) {
		log_dbg(cd, "Initializaing reencryption context with data_shift resilience.");
		rh->rp.type = REENC_PROTECTION_DATASHIFT;
		rh->data_shift = LUKS2_reencrypt_data_shift(hdr);
	} else if (!strcmp(params->resilience, "journal")) {
		log_dbg(cd, "Initializaing reencryption context with journal resilience.");
		rh->rp.type = REENC_PROTECTION_JOURNAL;
	} else if (!strcmp(params->resilience, "checksum")) {
		log_dbg(cd, "Initializaing reencryption context with checksum resilience.");
		rh->rp.type = REENC_PROTECTION_CHECKSUM;

		r = snprintf(rh->rp.p.csum.hash,
			sizeof(rh->rp.p.csum.hash), "%s", params->hash);
		if (r < 0 || (size_t)r >= sizeof(rh->rp.p.csum.hash)) {
			log_dbg(cd, "Invalid hash parameter");
			return -EINVAL;
		}

		if (crypt_hash_init(&rh->rp.p.csum.ch, params->hash)) {
			log_dbg(cd, "Failed to initialize checksum resilience hash %s", params->hash);
			return -EINVAL;
		}

		r = crypt_hash_size(params->hash);
		if (r < 1) {
			log_dbg(cd, "Invalid hash size");
			return -EINVAL;
		}
		rh->rp.p.csum.hash_size = r;

		rh->rp.p.csum.checksums_len = area_length;
		if (posix_memalign(&rh->rp.p.csum.checksums, device_alignment(crypt_metadata_device(cd)),
				   rh->rp.p.csum.checksums_len))
			return -ENOMEM;
	} else if (!strcmp(params->resilience, "none")) {
		log_dbg(cd, "Initializaing reencryption context with none resilience.");
		if (!params->max_hotzone_size)
			return -EINVAL;
		rh->rp.type = REENC_PROTECTION_NOOP;
	} else {
		log_err(cd, _("Unsupported resilience mode %s"), params->resilience);
		return -EINVAL;
	}

	rh->length = LUKS2_get_reencrypt_length(hdr, rh, area_length, params->max_hotzone_size);
	if (LUKS2_get_reencrypt_offset(hdr, rh->direction, device_size, &rh->length, &rh->offset)) {
		log_err(cd, _("Failed to get reencryption offset."));
		return -EINVAL;
	}

	if (rh->offset > device_size)
		return -EINVAL;
	if (rh->length > device_size - rh->offset)
		rh->length = device_size - rh->offset;

	log_dbg(cd, "reencrypt-direction: %s", rh->direction == CRYPT_REENCRYPT_FORWARD ? "forward" : "backward");

	_load_backup_segments(hdr, rh);

	if (rh->direction == CRYPT_REENCRYPT_BACKWARD)
		rh->progress = device_size - rh->offset - rh->length;
	else
		rh->progress = rh->offset;

	log_dbg(cd, "backup-previous digest id: %d", rh->digest_old);
	if (rh->jobj_segment_old)
		JSON_DBG(cd, rh->jobj_segment_old, "backup-previous segment:");
	else
		log_dbg(cd, "backup-previous segment: <missing>");
	log_dbg(cd, "backup-final digest id: %d", rh->digest_new);
	if (rh->jobj_segment_new)
		JSON_DBG(cd, rh->jobj_segment_new, "backup-final segment:");
	else
		log_dbg(cd, "backup-final segment: <missing>");

	log_dbg(cd, "reencrypt length: %" PRIu64, rh->length);
	log_dbg(cd, "reencrypt offset: %" PRIu64, rh->offset);
	log_dbg(cd, "reencrypt shift: %s%" PRIu64, (rh->data_shift && rh->direction == CRYPT_REENCRYPT_BACKWARD ? "-" : ""), rh->data_shift);
	log_dbg(cd, "reencrypt alignemnt: %zu", rh->alignment);
	log_dbg(cd, "reencrypt progress: %" PRIu64, rh->progress);

	rh->device_size = device_size;

	return rh->length < 512 ? -EINVAL : 0;
}

static size_t LUKS2_get_reencrypt_buffer_length(struct luks2_reenc_context *rh)
{
	if (rh->data_shift)
		return rh->data_shift;
	return rh->length;
}

static int _LUKS2_reenc_load(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	uint64_t device_size,
	struct luks2_reenc_context **rh,
	const struct crypt_params_reencrypt *params)
{
	int r;
	const struct crypt_params_reencrypt hdr_reenc_params = {
		.resilience = LUKS2_reencrypt_protection_type(hdr),
		.hash = LUKS2_reencrypt_protection_hash(hdr),
		.max_hotzone_size = LUKS2_DEFAULT_REENCRYPTION_LENGTH
	};
	struct luks2_reenc_context *tmp = calloc(1, sizeof (*tmp));

	if (!tmp)
		return -ENOMEM;

	if (!hdr_reenc_params.resilience) {
		r = -EINVAL;
		goto err;
	}

	/* skip context update if data shift is detected in header */
	if (!strcmp(hdr_reenc_params.resilience, "datashift"))
		params = NULL;

	log_dbg(cd, "Initializing reencryption context (%s).", params ? "update" : "load");

	if (!params)
		params = &hdr_reenc_params;

	r = _reenc_load(cd, hdr, tmp, device_size, params);
	if (r)
		goto err;

	if (posix_memalign(&tmp->reenc_buffer, device_alignment(crypt_data_device(cd)),
			   LUKS2_get_reencrypt_buffer_length(tmp))) {
		r = -ENOMEM;
		goto err;
	}

	*rh = tmp;

	return 0;
err:
	LUKS2_reenc_context_free(cd, tmp);

	return r;
}

static int _load_segments(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, uint64_t device_size)
{
	int r;

	log_dbg(cd, "Calculating segments.");

	r = LUKS2_reenc_create_segments(cd, hdr, rh, device_size);
	if (r) {
		log_err(cd, _("Failed to create reencryption segments."));
		return r;
	}

	return r;
}

static int _load_segments_crashed(struct crypt_device *cd,
				struct luks2_hdr *hdr,
			        struct luks2_reenc_context *rh)
{
	int r;
	uint64_t data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;

	if (!rh)
		return -EINVAL;

	rh->jobj_segs_pre = json_object_new_object();
	if (!rh->jobj_segs_pre)
		return -ENOMEM;

	json_object_object_foreach(LUKS2_get_segments_jobj(hdr), key, val) {
		if (json_segment_is_backup(val))
			continue;
		json_object_object_add(rh->jobj_segs_pre, key, json_object_get(val));
	}

	r = LUKS2_reenc_create_segments_after(cd, hdr, rh, data_offset);
	if (r) {
		json_object_put(rh->jobj_segs_pre);
		rh->jobj_segs_pre = NULL;
	}

	return r;
}

static int LUKS2_reenc_load_crashed(struct crypt_device *cd,
	struct luks2_hdr *hdr, uint64_t device_size, struct luks2_reenc_context **rh)
{
	int r, reenc_seg;

	r = _LUKS2_reenc_load(cd, hdr, device_size, rh, NULL);

	if (!r) {
		reenc_seg = json_segments_segment_in_reencrypt(LUKS2_get_segments_jobj(hdr));
		if (reenc_seg < 0)
			r = -EINVAL;
		else
			(*rh)->length = LUKS2_segment_size(hdr, reenc_seg, 0);
	}

	if (!r && ((*rh)->rp.type == REENC_PROTECTION_CHECKSUM)) {
		/* we have to override calculated alignment with value stored in mda */
		(*rh)->alignment = LUKS2_reencrypt_protection_sector_size(hdr);
		if (!(*rh)->alignment) {
			log_dbg(cd, "Failed to get read resilience sector_size from metadata.");
			r = -EINVAL;
		}
	}

	if (!r)
		r = _load_segments_crashed(cd, hdr, *rh);

	if (r) {
		LUKS2_reenc_context_free(cd, *rh);
		*rh = NULL;
	}
	return r;
}

static int _init_storage_wrappers(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		struct volume_key *vks)
{
	int r;
	struct volume_key *vk;
	uint32_t wrapper_flags = DISABLE_KCAPI;

	vk = crypt_volume_key_by_id(vks, rh->digest_old);
	r = crypt_storage_wrapper_init(cd, &rh->cw1, crypt_data_device(cd),
			LUKS2_reencrypt_get_data_offset_old(hdr),
			crypt_get_iv_offset(cd),
			LUKS2_reencrypt_get_sector_size_old(hdr),
			LUKS2_reencrypt_segment_cipher_old(hdr),
			vk, wrapper_flags | OPEN_READONLY);
	if (r) {
		log_dbg(cd, "Failed to initialize storage wrapper for old cipher.");
		return r;
	}
	rh->wflags1 = wrapper_flags | OPEN_READONLY;
	log_dbg(cd, "Old cipher storage wrapper type: %d.", crypt_storage_wrapper_get_type(rh->cw1));

	vk = crypt_volume_key_by_id(vks, rh->digest_new);
	r = crypt_storage_wrapper_init(cd, &rh->cw2, crypt_data_device(cd),
			LUKS2_reencrypt_get_data_offset_new(hdr),
			crypt_get_iv_offset(cd),
			LUKS2_reencrypt_get_sector_size_new(hdr),
			LUKS2_reencrypt_segment_cipher_new(hdr),
			vk, wrapper_flags);
	if (r) {
		log_dbg(cd, "Failed to initialize storage wrapper for new cipher.");
		return r;
	}
	rh->wflags2 = wrapper_flags;
	log_dbg(cd, "New cipher storage wrapper type: %d", crypt_storage_wrapper_get_type(rh->cw2));

	return 0;
}

static int LUKS2_reenc_context_set_name(struct luks2_reenc_context *rh, const char *name)
{
	if (!rh | !name)
		return -EINVAL;

	if (!(rh->device_name = strdup(name)))
		return -ENOMEM;
	if (asprintf(&rh->hotzone_name, "%s-hotzone", name) < 0) {
		rh->hotzone_name = NULL;
		return -ENOMEM;
	}
	if (asprintf(&rh->overlay_name, "%s-overlay", name) < 0) {
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
		*offset += data_shift;
		r = 0;
	} else if (di == CRYPT_REENCRYPT_BACKWARD) {
		if (*offset >= data_shift) {
			*offset -= data_shift;
			r = 0;
		}
	}

	return r;
}

int LUKS2_reenc_recover(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	struct volume_key *vks)
{
	struct volume_key *vk_old, *vk_new;
	size_t count, s;
	ssize_t read, w;
	unsigned resilience;
	uint64_t area_offset, area_length, area_length_read, crash_iv_offset,
		 data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;
	int r, new_sector_size, old_sector_size, rseg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre), fd = -1;
	char *checksum_tmp = NULL, *data_buffer = NULL;
	struct crypt_storage_wrapper *cw1 = NULL, *cw2 = NULL;

	resilience = rh->rp.type;

	if (rseg < 0 || rh->length < 512)
		return -EINVAL;

	vk_new = crypt_volume_key_by_id(vks, rh->digest_new);
	if (!vk_new && rh->type != DECRYPT)
		return -EINVAL;
	vk_old = crypt_volume_key_by_id(vks, rh->digest_old);
	if (!vk_old && rh->type != ENCRYPT)
		return -EINVAL;
	old_sector_size = json_segment_get_sector_size(LUKS2_reencrypt_segment_old(hdr));
	new_sector_size = json_segment_get_sector_size(LUKS2_reencrypt_segment_new(hdr));
	if (rh->type == DECRYPT)
		crash_iv_offset = rh->offset >> SECTOR_SHIFT; /* TODO: + old iv_tweak */
	else
		crash_iv_offset = json_segment_get_iv_offset(json_segments_get_segment(rh->jobj_segs_pre, rseg));

	log_dbg(cd, "crash_offset: %" PRIu64 ", crash_length: %" PRIu64 ",  crash_iv_offset: %" PRIu64, data_offset + rh->offset, rh->length, crash_iv_offset);

	r = crypt_storage_wrapper_init(cd, &cw2, crypt_data_device(cd),
			data_offset + rh->offset, crash_iv_offset, new_sector_size,
			LUKS2_reencrypt_segment_cipher_new(hdr), vk_new, 0);
	if (r) {
		log_err(cd, _("Failed to initialize new key storage wrapper."));
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

	switch (resilience) {
	case  REENC_PROTECTION_CHECKSUM:
		log_dbg(cd, "Checksums based recovery.");

		r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
				data_offset + rh->offset, crash_iv_offset, old_sector_size,
				LUKS2_reencrypt_segment_cipher_old(hdr), vk_old, 0);
		if (r) {
			log_err(cd, _("Failed to initialize old segment storage wrapper."));
			goto out;
		}

		count = rh->length / rh->alignment;
		area_length_read = count * rh->rp.p.csum.hash_size;
		if (area_length_read > area_length) {
			log_dbg(cd, "Internal error in calculated area_length.");
			r = -EINVAL;
			goto out;
		}

		checksum_tmp = malloc(rh->rp.p.csum.hash_size);
		if (!checksum_tmp) {
			r = -ENOMEM;
			goto out;
		}

		/* TODO: lock for read */
		fd = device_open(cd, crypt_metadata_device(cd), O_RDONLY);
		if (fd < 0) {
			log_err(cd, _("Failed to open mdata device."));
			goto out;
		}

		/* read old data checksums */
		read = read_lseek_blockwise(fd, device_block_size(cd, crypt_metadata_device(cd)),
					device_alignment(crypt_metadata_device(cd)), rh->rp.p.csum.checksums, area_length_read, area_offset);
		close(fd);
		if (read < 0 || (size_t)read != area_length_read) {
			log_err(cd, _("Failed to read checksums."));
			r = -EINVAL;
			goto out;
		}

		read = crypt_storage_wrapper_read(cw2, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_err(cd, _("Failed to read hotzone area."));
			r = -EINVAL;
			goto out;
		}

		for (s = 0; s < count; s++) {
			if (crypt_hash_write(rh->rp.p.csum.ch, data_buffer + (s * rh->alignment), rh->alignment)) {
				log_err(cd, _("Failed to write hash."));
				r = EINVAL;
				goto out;
			}
			if (crypt_hash_final(rh->rp.p.csum.ch, checksum_tmp, rh->rp.p.csum.hash_size)) {
				log_err(cd, _("Failed to finalize hash."));
				r = EINVAL;
				goto out;
			}
			if (!memcmp(checksum_tmp, (char *)rh->rp.p.csum.checksums + (s * rh->rp.p.csum.hash_size), rh->rp.p.csum.hash_size)) {
				log_dbg(cd, "Sector %zu (size %zu, offset %zu) needs recovery", s, rh->alignment, s * rh->alignment);
				if (crypt_storage_wrapper_decrypt(cw1, s * rh->alignment, data_buffer + (s * rh->alignment), rh->alignment)) {
					log_err(cd, _("Failed to decrypt sector %zu."), s);
					r = -EINVAL;
					goto out;
				}
				w = crypt_storage_wrapper_encrypt_write(cw2, s * rh->alignment, data_buffer + (s * rh->alignment), rh->alignment);
				if (w < 0 || (size_t)w != rh->alignment) {
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
			log_err(cd, _("Invalid resilience parameters (internal error)."));
			goto out;
		}

		/* TODO locking */
		r = crypt_storage_wrapper_init(cd, &cw1, crypt_metadata_device(cd),
				area_offset, crash_iv_offset, old_sector_size,
				LUKS2_reencrypt_segment_cipher_old(hdr), vk_old, 0);
		if (r) {
			log_err(cd, _("Failed to initialize old key storage wrapper."));
			goto out;
		}
		read = crypt_storage_wrapper_read_decrypt(cw1, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "Failed to read journaled data.");
			r = -EIO;
			/* may content plaintext */
			crypt_memzero(data_buffer, rh->length);
			goto out;
		}
		read = crypt_storage_wrapper_encrypt_write(cw2, 0, data_buffer, rh->length);
		/* may content plaintext */
		crypt_memzero(data_buffer, rh->length);
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
					json_segment_get_offset(rh->jobj_segment_moved, 0), 0, 0,
					LUKS2_reencrypt_segment_cipher_old(hdr), NULL, 0);
		} else
			r = crypt_storage_wrapper_init(cd, &cw1, crypt_data_device(cd),
					data_offset + rh->offset - rh->data_shift, 0, 0,
					LUKS2_reencrypt_segment_cipher_old(hdr), NULL, 0);
		if (r) {
			log_err(cd, _("Failed to initialize old key storage wrapper."));
			goto out;
		}

		read = crypt_storage_wrapper_read_decrypt(cw1, 0, data_buffer, rh->length);
		if (read < 0 || (size_t)read != rh->length) {
			log_dbg(cd, "Failed to read data.");
			r = -EIO;
			/* may content plaintext */
			crypt_memzero(data_buffer, rh->length);
			goto out;
		}

		read = crypt_storage_wrapper_encrypt_write(cw2, 0, data_buffer, rh->length);
		/* may content plaintext */
		crypt_memzero(data_buffer, rh->length);
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
out:
	free(data_buffer);
	free(checksum_tmp);
	crypt_storage_wrapper_destroy(cw1);
	crypt_storage_wrapper_destroy(cw2);

	return r;
}

static int _add_moved_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh)
{
	int s = LUKS2_segment_first_unused_id(hdr);

	if (!rh->jobj_segment_moved)
		return 0;

	if (s < 0)
		return s;

	if (json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), s, json_object_get(rh->jobj_segment_moved))) {
		json_object_put(rh->jobj_segment_moved);
		return -EINVAL;
	}

	return 0;
}

static int _add_backup_segment(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
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

static int _assign_segments_simple(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	unsigned pre,
	unsigned commit)
{
	int r, sg;

	if (pre && json_segments_count(rh->jobj_segs_pre) > 0) {
		log_dbg(cd, "Setting 'pre' segments.");

		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_pre, 0);
		if (!r)
			rh->jobj_segs_pre = NULL;
	} else if (!pre && json_segments_count(rh->jobj_segs_after) > 0) {
		log_dbg(cd, "Setting 'after' segments.");
		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_after, 0);
		if (!r)
			rh->jobj_segs_after = NULL;
	} else {
		log_dbg(cd, "No segments to set.");
		return -EINVAL;
	}

	if (r) {
		log_err(cd, _("Failed to assign new enc segments."));
		return r;
	}

	r = _add_backup_segment(cd, hdr, rh, 0);
	if (r) {
		log_dbg(cd, "Failed to assign reencryption previous backup segment.");
		return r;
	}

	r = _add_backup_segment(cd, hdr, rh, 1);
	if (r) {
		log_dbg(cd, "Failed to assign reencryption final backup segment.");
		return r;
	}

	r = _add_moved_segment(cd, hdr, rh);
	if (r) {
		log_dbg(cd, "Failed to assign reencryption moved backup segment.");
		return r;
	}

	for (sg = 0; sg < LUKS2_segments_count(hdr); sg++) {
		if (LUKS2_segment_is_type(hdr, sg, "crypt") &&
		    LUKS2_digest_segment_assign(cd, hdr, sg, rh->type == ENCRYPT ? rh->digest_new : rh->digest_old, 1, 0)) {
			log_err(cd, _("Failed to assign digest %u to segment %u."), rh->digest_new, sg);
			return -EINVAL;
		}
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

static int reenc_assign_segments(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, unsigned pre, unsigned commit)
{
	int r, rseg, scount;

	/* FIXME: validate in reencrypt context load */
	if (rh->digest_new < 0 && rh->type != DECRYPT)
		return -EINVAL;

	if (LUKS2_digest_segment_assign(cd, hdr, CRYPT_ANY_SEGMENT, CRYPT_ANY_DIGEST, 0, 0))
		return -EINVAL;

	if (rh->type == ENCRYPT || rh->type == DECRYPT)
		return _assign_segments_simple(cd, hdr, rh, pre, commit);

	if (pre && rh->jobj_segs_pre) {
		log_dbg(cd, "Setting 'pre' segments.");

		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_pre, 0);
		if (!r)
			rh->jobj_segs_pre = NULL;
	} else if (!pre && rh->jobj_segs_after) {
		log_dbg(cd, "Setting 'after' segments.");
		r = LUKS2_segments_set(cd, hdr, rh->jobj_segs_after, 0);
		if (!r)
			rh->jobj_segs_after = NULL;
	} else
		return -EINVAL;

	scount = LUKS2_segments_count(hdr);

	/* segment in reencryption has to hold reference on both digests */
	rseg = json_segments_segment_in_reencrypt(LUKS2_get_segments_jobj(hdr));
	if (rseg < 0 && pre)
		return -EINVAL;

	if (rseg >= 0) {
		LUKS2_digest_segment_assign(cd, hdr, rseg, rh->digest_new, 1, 0);
		LUKS2_digest_segment_assign(cd, hdr, rseg, rh->digest_old, 1, 0);
	}

	if (pre) {
		if (rseg > 0)
			LUKS2_digest_segment_assign(cd, hdr, 0, rh->digest_new, 1, 0);
		if (scount > rseg + 1)
			LUKS2_digest_segment_assign(cd, hdr, rseg + 1, rh->digest_old, 1, 0);
	} else {
		LUKS2_digest_segment_assign(cd, hdr, 0, rh->digest_new, 1, 0);
		if (scount > 1)
			LUKS2_digest_segment_assign(cd, hdr, 1, rh->digest_old, 1, 0);
	}

	if (r) {
		log_err(cd, _("Failed to set segments."));
		return r;
	}

	r = _add_backup_segment(cd, hdr, rh, 0);
	if (r) {
		log_err(cd, _("Failed to assign reencrypt previous backup segment."));
		return r;
	}
	r = _add_backup_segment(cd, hdr, rh, 1);
	if (r) {
		log_err(cd, _("Failed to assign reencrypt final backup segment."));
		return r;
	}

	return commit ? LUKS2_hdr_write(cd, hdr) : 0;
}

int LUKS2_reenc_update_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh)
{
	return reenc_assign_segments(cd, hdr, rh, 0, 1);
}

/* FIXME: seems to be temporary and for encryption initialization only */
static int _encrypt_set_segments(struct crypt_device *cd, struct luks2_hdr *hdr, uint64_t dev_size, uint64_t data_shift, bool move_first_segment, crypt_reencrypt_direction_info di)
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
		/* future data_device layout: [future LUKS2 header][+shift][second data segment][luks2size+shift][first data segment] */
		first_segment_offset = dev_size;
		first_segment_length = data_shift;
		second_segment_offset = data_shift;
		second_segment_length = dev_size - 2 * data_shift;
	} else if (data_shift) {
		first_segment_offset = data_offset;
		first_segment_length = dev_size;
	} else {
		/* future data_device layout with deatached header: [first data segment] */
		first_segment_offset = data_offset;
		first_segment_length = 0; /* dynamic */
	}

	jobj_segments = json_object_new_object();
	if (!jobj_segments)
		return -ENOMEM;

	r = -EINVAL;
	if (move_first_segment) {
		jobj_segment_first =  json_segment_create_linear(first_segment_offset, &first_segment_length, 0);
		jobj_segment_second = json_segment_create_linear(second_segment_offset, &second_segment_length, 0);
		if (!jobj_segment_second) {
			log_err(cd, _("Failed generate 2nd segment."));
			goto err;
		}
	} else
		jobj_segment_first =  json_segment_create_linear(first_segment_offset, first_segment_length ? &first_segment_length : NULL, 0);

	if (!jobj_segment_first) {
		log_err(cd, _("Failed generate 1st segment."));
		goto err;
	}

	json_object_object_add(jobj_segments, "0", jobj_segment_first);
	if (jobj_segment_second)
		json_object_object_add(jobj_segments, "1", jobj_segment_second);

	r = LUKS2_digest_segment_assign(cd, hdr, CRYPT_ANY_SEGMENT, CRYPT_ANY_DIGEST, 0, 0);

	if (!r)
		r = LUKS2_segments_set(cd, hdr, jobj_segments, 0);
err:
	return r;
}

static int reenc_setup_segments(struct crypt_device *cd,
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
			r = -EINVAL;
			goto out;
		}

		reenc_seg = (s == json_segments_segment_in_reencrypt(jobj_segments));

		segment_offset = json_segment_get_offset(jobj, 1);
		segment_size = json_segment_get_size(jobj, 1);
		/* 'dynamic' length allowed in last segment only */
		if (!segment_size && !result->next)
			segment_size = (size >> SECTOR_SHIFT) - segment_start;
		if (!segment_size) {
			log_dbg(cd, "Internal error. Wrong segment size %u", s);
			r = -EINVAL;
			goto out;
		}

		if (!strcmp(json_segment_type(jobj), "crypt")) {
			vk = crypt_volume_key_by_id(vks, reenc_seg ? LUKS2_reencrypt_digest_new(hdr) : LUKS2_digest_by_segment(hdr, s));
			if (!vk) {
				log_err(cd, _("Missing key for dm-crypt segment %d"), s);
				r = -EINVAL;
				goto out;
			}

			if (reenc_seg)
				segment_offset -= crypt_get_data_offset(cd);

			r = dm_crypt_target_set(result, segment_start, segment_size,
						reenc_seg ? hz_device : crypt_data_device(cd),
						vk,
						json_segment_get_cipher(jobj),
						json_segment_get_iv_offset(jobj),
						segment_offset,
						"none",
						0,
						json_segment_get_sector_size(jobj));
			if (r) {
				log_err(cd, _("Failed to set dm-crypt segment."));
				goto out;
			}
		} else if (!strcmp(json_segment_type(jobj), "linear")) {
			r = dm_linear_target_set(result, segment_start, segment_size, reenc_seg ? hz_device : crypt_data_device(cd), segment_offset);
			if (r) {
				log_err(cd, _("Failed to set dm-linear segment."));
				goto out;
			}
		} else {
			r = -EINVAL;
			goto out;
		}

		segment_start += segment_size;
		s++;
		result = result->next;
	}

	return s;
out:
	return r;
}

/* GLOBAL FIXME: audit function names and parameters names */

/* FIXME:
 * 	1) audit log routines
 * 	2) can't we derive hotzone device name from crypt context? (unlocked name, device uuid, etc?)
 */
static int reenc_load_overlay_device(struct crypt_device *cd, struct luks2_hdr *hdr,
	const char *overlay, const char *hotzone, struct volume_key *vks, uint64_t size)
{
	char hz_path[PATH_MAX];
	int r;

	struct device *hz_dev = NULL;
	struct crypt_dm_active_device dmd = {
		.flags = CRYPT_ACTIVATE_KEYRING_KEY,
	};

	log_dbg(cd, "Loading new table for overlay device %s.", overlay);

	r = snprintf(hz_path, PATH_MAX, "%s/%s", dm_get_dir(), hotzone);
	if (r < 0 || r >= PATH_MAX) {
		r = -EINVAL;
		goto out;
	}

	r = device_alloc(cd, &hz_dev, hz_path);
	if (r) {
		log_err(cd, _("Failed to alocate device %s."), hz_path);
		goto out;
	}

	r = dm_targets_allocate(&dmd.segment, LUKS2_segments_count(hdr));
	if (r) {
		log_err(cd, _("Failed to allocate dm segments."));
		goto out;
	}

	r = reenc_setup_segments(cd, hdr, hz_dev, vks, &dmd.segment, size);
	if (r < 0) {
		log_err(cd, _("Failed to create dm segments."));
		goto out;
	}

	r = dm_reload_device(cd, overlay, &dmd, 0, 0);

	/* what else on error here ? */
out:
	dm_targets_free(cd, &dmd);
	device_free(cd, hz_dev);

	return r;
}

/* FIXME:
 *	remove completely. the device should be read from header directly
 *
 * 	1) audit log functions
 * 	2) check flags
 */
static int reenc_replace_device(struct crypt_device *cd, const char *target, const char *source, uint32_t flags)
{
	int r, exists = 1;
	uint64_t size = 0;
	struct crypt_dm_active_device dmd_source, dmd_target = {};
	uint32_t dmflags = DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH;

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

	dmd_source.flags |= flags;
	dmd_source.uuid = crypt_get_uuid(cd);

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				crypt_get_data_offset(cd), &size, &dmd_source.flags);

	if (r)
		goto err;

	if (exists && size != dmd_source.size) {
		log_err(cd, _("Source and target device sizes don't match. Source %" PRIu64 ", target: %" PRIu64 "."),
			dmd_source.size, size);
		r = -EINVAL;
		goto err;
	}

	if (exists) {
		r = dm_reload_device(cd, target, &dmd_source, 0, 0);
		if (!r) {
			log_dbg(cd, "Resuming device %s", target);
			r = dm_resume_device(cd, target, dmflags | act2dmflags(dmd_source.flags));
		}
	} else
		r = dm_create_device(cd, target, "TEMP", &dmd_source);
err:
	dm_targets_free(cd, &dmd_source);
	dm_targets_free(cd, &dmd_target);

	return r;
}

static int reenc_swap_backing_device(struct crypt_device *cd, const char *name,
			      const char *new_backend_name, uint32_t flags)
{
	int r;
	struct device *overlay_dev = NULL;
	char overlay_path[PATH_MAX] = { 0 };

	struct crypt_dm_active_device dmd = {
		.flags = flags,
	};

	log_dbg(cd, "Redirecting %s mapping to new backing device: %s.", name, new_backend_name);

	r = snprintf(overlay_path, PATH_MAX, "%s/%s", dm_get_dir(), new_backend_name);
	if (r < 0 || r >= PATH_MAX) {
		r = -EINVAL;
		goto out;
	}

	r = device_alloc(cd, &overlay_dev, overlay_path);
	if (r) {
		log_err(cd, _("Failed to allocate device for new backing device."));
		goto out;
	}

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
		r = dm_resume_device(cd, name, dmd.flags);
	}

out:
	dm_targets_free(cd, &dmd);
	device_free(cd, overlay_dev);

	return r;
}

static int reenc_activate_hotzone_device(struct crypt_device *cd, const char *name, uint32_t flags)
{
	int r;
	uint64_t new_offset = LUKS2_reencrypt_get_data_offset_new(crypt_get_hdr(cd, CRYPT_LUKS2)) >> SECTOR_SHIFT;

	struct crypt_dm_active_device dmd = {
		.flags = flags,
		.uuid = crypt_get_uuid(cd)
	};

	log_dbg(cd, "Activating hotzone device %s.", name);

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				new_offset, &dmd.size, &dmd.flags);
	if (r)
		goto err;

	r = dm_linear_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd), new_offset);
	if (r)
		goto err;

	r = dm_create_device(cd, name, "TEMP", &dmd);
err:
	dm_targets_free(cd, &dmd);

	return r;
}

/* pass reenc context instead? */
static int reenc_init_helper_devices(struct crypt_device *cd,
				     const char *name,
				     const char *hotzone,
				     const char *overlay)
{
	int r;

	/* Activate hotzone device 1:1 linear mapping to data_device */
	r = reenc_activate_hotzone_device(cd, hotzone, CRYPT_ACTIVATE_PRIVATE);
	if (r) {
		log_err(cd, _("Failed to activate hotzone device %s."), hotzone);
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
	r = reenc_replace_device(cd, overlay, name, CRYPT_ACTIVATE_PRIVATE);
	if (r) {
		log_err(cd, _("Failed to activate overlay device %s with actual origin table."), overlay);
		goto err;
	}

	/* swap origin mapping to overlay device */
	r = reenc_swap_backing_device(cd, name, overlay, CRYPT_ACTIVATE_KEYRING_KEY);
	if (r) {
		log_err(cd, _("Failed to load new maping for device %s."), name);
		goto err;
	}

	/*
	 * Now the 'name' (unlocked luks) device is mapped via dm-linear to an overlay dev.
	 * The overlay device has a original live table of 'name' device in-before the swap.
	 */

	return 0;
err:
	/* TODO: force error helper devices on error path */
	dm_remove_device(cd, overlay, 0);
	dm_remove_device(cd, hotzone, 0);

	return r;
}

/* TODO:
 * 	1) audit error path. any error in this routine is fatal and should be unlikely.
 * 	   usualy it would hint some collision with another userspace process touching
 * 	   dm devices directly.
 */
static int reenc_refresh_helper_devices(struct crypt_device *cd, const char *overlay, const char *hotzone)
{
	int r;

	/*
	 * we have to explicitely suspend the overlay device before suspending
	 * the hotzone one. Resuming overlay device (aka switching tables) only
	 * after suspending the hotzone may lead to deadlock.
	 *
	 * In other words: always suspend the stack from top to bottom!
	 */
	r = dm_suspend_device(cd, overlay, DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH);
	if (r) {
		log_err(cd, _("Failed to suspend %s."), overlay);
		return r;
	}

	log_dbg(cd, "Suspended device %s",  overlay);

	/* suspend HZ device */
	r = dm_suspend_device(cd, hotzone, DM_SUSPEND_SKIP_LOCKFS | DM_SUSPEND_NOFLUSH);
	if (r) {
		log_err(cd, _("Failed to suspend %s."), hotzone);
		return r;
	}

	log_dbg(cd, "Suspended device %s",  hotzone);

	/* resume overlay device: inactive table (with hotozne) -> live */
	r = dm_resume_device(cd, overlay, DM_RESUME_PRIVATE);
	if (r)
		log_err(cd, _("Failed to resume device %s."), overlay);
	else
		log_dbg(cd, "Resume device %s.", overlay);

	return r;
}

static int reenc_refresh_overlay_devices(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const char *overlay,
		const char *hotzone,
		struct volume_key *vks,
		uint64_t device_size)
{
	int r = reenc_load_overlay_device(cd, hdr, overlay, hotzone, vks, device_size);
	if (r) {
		log_err(cd, _("Failed to reload overlay device %s."), overlay);
		return REENC_ERR;
	}

	r = reenc_refresh_helper_devices(cd, overlay, hotzone);
	if (r) {
		log_err(cd, _("Failed to refresh helper devices."));
		return REENC_ROLLBACK;
	}

	return REENC_OK;
}

static int move_data(struct crypt_device *cd, int devfd, uint64_t data_shift)
{
	void *buffer;
	int r;
	ssize_t ret;
	uint64_t buffer_len, offset;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	log_dbg(cd, "Going to move data from head of data device.");

	buffer_len = data_shift;
	if (!buffer_len)
		return -EINVAL;

	offset = json_segment_get_offset(LUKS2_get_segment_jobj(hdr, 0), 0);

	/* this is nonsense anyway */
	if (buffer_len != json_segment_get_size(LUKS2_get_segment_jobj(hdr, 0), 0)) {
		log_dbg(cd, "buffer_len %" PRIu64", segment size %" PRIu64, buffer_len, json_segment_get_size(LUKS2_get_segment_jobj(hdr, 0), 0));
		return -EINVAL;
	}

	if (posix_memalign(&buffer, device_alignment(crypt_data_device(cd)), buffer_len))
		return -ENOMEM;

	ret = read_lseek_blockwise(devfd,
			device_block_size(cd, crypt_data_device(cd)),
			device_alignment(crypt_data_device(cd)),
			buffer, buffer_len, 0);
	if (ret < 0 || (uint64_t)ret != buffer_len) {
		r = -EIO;
		goto err;
	}

	log_dbg(cd, "Going to write %" PRIu64 " bytes at offset %" PRIu64, buffer_len, offset);
	ret = write_lseek_blockwise(devfd,
			device_block_size(cd, crypt_data_device(cd)),
			device_alignment(crypt_data_device(cd)),
			buffer, buffer_len, offset);
	if (ret < 0 || (uint64_t)ret != buffer_len) {
		r = -EIO;
		goto err;
	}

	r = 0;
err:
	memset(buffer, 0, buffer_len);
	free(buffer);
	return r;
}

int update_reencryption_flag(struct crypt_device *cd, int enable, bool commit)
{
	uint32_t reqs;
	struct luks2_hdr *hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	if (LUKS2_config_get_requirements(cd, hdr, &reqs))
		return -EINVAL;

	/* nothing to do */
	if (enable && (reqs & CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return -EINVAL;

	/* nothing to do */
	if (!enable && !(reqs & CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return -EINVAL;

	if (enable)
		reqs |= CRYPT_REQUIREMENT_ONLINE_REENCRYPT;
	else
		reqs &= ~CRYPT_REQUIREMENT_ONLINE_REENCRYPT;

	log_dbg(cd, "Going to %s reencryption requirement flag.", enable ? "store" : "wipe");

	return LUKS2_config_set_requirements(cd, hdr, reqs, commit);
}

static int _create_backup_segments(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		int keyslot_new,
		const char *cipher,
		uint64_t data_offset,
		const struct crypt_params_reencrypt *params)
{
	int r, segment, moved_segment = -1, digest_old = -1, digest_new = -1;
	json_object *jobj_segment_new = NULL, *jobj_segment_old = NULL, *jobj_segment_bcp = NULL;
	uint32_t sector_size = params->luks2 ? params->luks2->sector_size : SECTOR_SIZE;
	uint64_t segment_offset, tmp, data_shift = params->data_shift << SECTOR_SHIFT;

	if (strcmp(params->mode, "decrypt")) {
		digest_new = LUKS2_digest_by_keyslot(hdr, keyslot_new);
		if (digest_new < 0)
			return -EINVAL;
	}

	if (strcmp(params->mode, "encrypt")) {
		digest_old = LUKS2_digest_by_segment(hdr, CRYPT_DEFAULT_SEGMENT);
		if (digest_old < 0)
			return -EINVAL;
	}

	segment = LUKS2_segment_first_unused_id(hdr);
	if (segment < 0)
		return -EINVAL;

	if (!strcmp(params->mode, "encrypt") && segment > 1) {
		json_object_copy(LUKS2_get_segment_jobj(hdr, 0), &jobj_segment_bcp);
		r = LUKS2_segment_set_flag(jobj_segment_bcp, "backup-moved-segment");
		if (r)
			goto err;
		moved_segment = segment++;
		json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), moved_segment, jobj_segment_bcp);
	}

	/* FIXME: Add detection for case (digest old == digest new && old segment == new segment) */
	if (digest_old >= 0)
		json_object_copy(LUKS2_get_segment_jobj(hdr, CRYPT_DEFAULT_SEGMENT), &jobj_segment_old);
	else if (!strcmp(params->mode, "encrypt")) {
		r = LUKS2_get_data_size(hdr, &tmp);
		if (r)
			goto err;
		jobj_segment_old = json_segment_create_linear(0, tmp ? &tmp : NULL, 0);
	}

	if (!jobj_segment_old) {
		r = -EINVAL;
		goto err;
	}

	r = LUKS2_segment_set_flag(jobj_segment_old, "backup-previous");
	if (r)
		goto err;
	json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), segment, jobj_segment_old);
	jobj_segment_old = NULL;
	if (digest_old >= 0)
		LUKS2_digest_segment_assign(cd, hdr, segment, digest_old, 1, 0);
	segment++;

	if (digest_new >= 0) {
		segment_offset = data_offset * SECTOR_SIZE;
		if (strcmp(params->mode, "encrypt") && modify_offset(&segment_offset, data_shift, params->direction)) {
			r = -EINVAL;
			goto err;
		}
		jobj_segment_new = json_segment_create_crypt(segment_offset,
							crypt_get_iv_offset(cd),
							NULL, cipher, sector_size, 0);
	} else if (!strcmp(params->mode, "decrypt")) {
		segment_offset = data_offset * SECTOR_SIZE;
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
	json_object_object_add_by_uint(LUKS2_get_segments_jobj(hdr), segment, jobj_segment_new);
	jobj_segment_new = NULL;
	if (digest_new >= 0)
		LUKS2_digest_segment_assign(cd, hdr, segment, digest_new, 1, 0);

	/* FIXME: also check occupied space by keyslot in shrunk area */
	if (data_shift && (crypt_metadata_device(cd) == crypt_data_device(cd))
	    && LUKS2_set_keyslots_size(cd, hdr, json_segment_get_offset(jobj_segment_new, 0))) {
		log_err(cd, _("Failed to set new keyslots size."));
		r = -EINVAL;
		goto err;
	}

	return 0;
err:
	json_object_put(jobj_segment_new);
	json_object_put(jobj_segment_old);
	return r;
}

static int parse_reencryption_mode(const char *mode)
{
	return (!mode ||
		(strcmp(mode, "reencrypt") && strcmp(mode, "encrypt") && strcmp(mode, "decrypt")));
}

static int atomic_get_reencryption_flag(struct crypt_device *cd)
{
	int r;
	crypt_reencrypt_info ri;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r)
		return r;

	ri = LUKS2_reenc_status(crypt_get_hdr(cd, CRYPT_LUKS2));
	if (ri > CRYPT_REENCRYPT_NONE)
		return -EBUSY;

	return 0;
}

/* This function must be called with metadata lock held */
static int _reencrypt_init(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const char *passphrase,
		size_t passphrase_size,
		int keyslot_old,
		int keyslot_new,
		const char *cipher,
		const char *cipher_mode,
		const struct crypt_params_reencrypt *params,
		struct volume_key **vks)
{
	bool move_first_segment;
	char _cipher[128];
	uint32_t sector_size;
	int r, reencrypt_keyslot, devfd = -1;
	uint64_t data_offset, dev_size = 0;

	if (!params || parse_reencryption_mode(params->mode))
		return -EINVAL;

	if (strcmp(params->mode, "decrypt") && (!params->luks2 || !(cipher && cipher_mode) || keyslot_new < 0))
		return -EINVAL;

	log_dbg(cd, "Initializing reencryption (mode: %s) in LUKS2 metadata.", params->mode);

	move_first_segment = (params->flags & CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT);

	/* implicit sector size 512 for decryption */
	sector_size = params->luks2 ? params->luks2->sector_size : SECTOR_SIZE;
	if (sector_size < SECTOR_SIZE || sector_size > MAX_SECTOR_SIZE ||
	    NOTPOW2(sector_size)) {
		log_err(cd, _("Unsupported encryption sector size."));
		return -EINVAL;
	}

	if (!cipher_mode || *cipher_mode == '\0')
		snprintf(_cipher, sizeof(_cipher), "%s", cipher);
	else
		snprintf(_cipher, sizeof(_cipher), "%s-%s", cipher, cipher_mode);

	if (MISALIGNED(params->data_shift, sector_size >> SECTOR_SHIFT)) {
		log_err(cd, _("Data shift is not aligned to requested encryption sector size (%" PRIu32 " bytes)."), sector_size);
		return -EINVAL;
	}

	data_offset = LUKS2_get_data_offset(hdr);

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				data_offset, &dev_size, NULL);
	if (r)
		return r;

	if (MISALIGNED(dev_size, sector_size >> SECTOR_SHIFT)) {
		log_err(cd, _("Data device is not aligned to requested encryption sector size (%" PRIu32 " bytes)."), sector_size);
		return -EINVAL;
	}

	reencrypt_keyslot = LUKS2_keyslot_find_empty(hdr);
	if (reencrypt_keyslot < 0) {
		log_err(cd, _("All key slots full."));
		return -EINVAL;
	}

	/*
	 * We must perform data move with exclusive open data device
	 * to exclude another cryptsetup process to colide with
	 * encryption initialization (or mount)
	 */
	if (move_first_segment) {
		/* TODO: api test */
		if (params->data_shift < LUKS2_get_data_offset(hdr)) {
			log_err(cd, _("Data shift (%" PRIu64 " sectors) is less than future data offset (%" PRIu64 " sectors)."), params->data_shift, LUKS2_get_data_offset(hdr));
			return -EINVAL;
		}
		devfd = device_open_excl(cd, crypt_data_device(cd), O_RDWR);
		if (devfd < 0) {
			log_err(cd, _("Failed to open %s in exclusive mode (perhaps already mapped or mounted)."),
				device_path(crypt_data_device(cd)));
			return -EINVAL;
		}
	}

	if (!strcmp(params->mode, "encrypt")) {
		/* in-memory only */
		r = _encrypt_set_segments(cd, hdr, dev_size << SECTOR_SHIFT, params->data_shift << SECTOR_SHIFT, move_first_segment, params->direction);
		if (r)
			goto err;
	}

	r = LUKS2_keyslot_reencrypt_create(cd, hdr, reencrypt_keyslot,
					   params);
	if (r < 0)
		goto err;

	r = _create_backup_segments(cd, hdr, keyslot_new, _cipher, data_offset, params);
	if (r) {
		log_err(cd, _("Failed to create reencryption backup segments."));
		goto err;
	}

	r = LUKS2_keyslot_open_all_segments(cd, keyslot_old, keyslot_new, passphrase, passphrase_size, vks);
	if (r < 0)
		goto err;

	if (move_first_segment && move_data(cd, devfd, params->data_shift << SECTOR_SHIFT)) {
		r = -EIO;
		goto err;
	}

	/* This must be first and only metadata write in LUKS2 in _reencrypt_init */
	r = update_reencryption_flag(cd, 1, true);
	if (r) {
		log_err(cd, _("Failed to set online-reencryption requirement."));
		r = -EINVAL;
	} else
		r = reencrypt_keyslot;
err:
	if (devfd >= 0)
		close(devfd);

	if (r < 0)
		crypt_load(cd, CRYPT_LUKS2, NULL);

	return r;
}

static int reencrypt_hotzone_protect_final(struct crypt_device *cd,
	struct luks2_hdr *hdr, struct luks2_reenc_context *rh,
	const void *buffer, size_t buffer_len)
{
	const void *pbuffer;
	size_t data_offset, len;
	int r;

	if (rh->rp.type == REENC_PROTECTION_NOOP)
		return 0;

	if (rh->rp.type == REENC_PROTECTION_CHECKSUM) {
		log_dbg(cd, "Checksums hotzone resilience.");

		for (data_offset = 0, len = 0; data_offset < buffer_len; data_offset += rh->alignment, len += rh->rp.p.csum.hash_size) {
			if (crypt_hash_write(rh->rp.p.csum.ch, (const char *)buffer + data_offset, rh->alignment)) {
				log_err(cd, _("Failed to hash sector at offset %zu."), data_offset);
				return -EINVAL;
			}
			if (crypt_hash_final(rh->rp.p.csum.ch, (char *)rh->rp.p.csum.checksums + len, rh->rp.p.csum.hash_size)) {
				log_err(cd, _("Failed to read sector hash."));
				return -EINVAL;
			}
		}
		pbuffer = rh->rp.p.csum.checksums;
	} else if (rh->rp.type == REENC_PROTECTION_JOURNAL) {
		log_dbg(cd, "Journal hotzone resilience.");
		len = buffer_len;
		pbuffer = buffer;
	} else if (rh->rp.type == REENC_PROTECTION_DATASHIFT) {
		log_dbg(cd, "Data shift hotzone resilience.");
		return LUKS2_hdr_write(cd, hdr);
	} else
		return -EINVAL;

	log_dbg(cd, "Going to store %zu bytes in reencrypt keyslot.", len);

	r = LUKS2_keyslot_reencrypt_store(cd, hdr, rh->reenc_keyslot, pbuffer, len);

	return r > 0 ? 0 : r;
}

static int continue_reencryption(struct crypt_device *cd, struct luks2_reenc_context *rh, uint64_t device_size)
{
	log_dbg(cd, "rh->progress: %" PRIu64 ", device_size %" PRIu64, rh->progress, device_size);
	return device_size > rh->progress;
}

static int _update_reencrypt_context(struct crypt_device *cd,
	struct luks2_reenc_context *rh)
{
	if (rh->read < 0)
		return -EINVAL;

	if (rh->direction == CRYPT_REENCRYPT_BACKWARD) {
		if (rh->data_shift && rh->type == ENCRYPT /* && moved segment */) {
			if (rh->offset)
				rh->offset -= rh->data_shift;
			if (rh->offset && (rh->offset < rh->data_shift)) {
				rh->length = rh->offset;
				rh->offset = rh->data_shift;
			}
			if (!rh->offset)
				rh->length = rh->data_shift;
		} else {
			if (rh->offset < rh->length)
				rh->length = rh->offset;
			rh->offset -= rh->length;
		}
	} else if (rh->direction == CRYPT_REENCRYPT_FORWARD) {
		rh->offset += (uint64_t)rh->read;
		/* it fails in-case of device_size < rh->offset later */
		if (rh->device_size - rh->offset < rh->length)
			rh->length = rh->device_size - rh->offset;
	} else
		return -EINVAL;

	if (rh->device_size < rh->offset) {
		log_err(cd, _("Error: Calculated reencryption offset %" PRIu64 " is beyond device size %" PRIu64 "."), rh->offset, rh->device_size);
		return -EINVAL;
	}

	rh->progress += (uint64_t)rh->read;

	return 0;
}

int LUKS2_verify_and_upload_keys(struct crypt_device *cd, struct luks2_hdr *hdr, int digest_old, int digest_new, struct volume_key *vks)
{
	int r;
	struct volume_key *vk;

	if (digest_new >= 0) {
		vk = crypt_volume_key_by_id(vks, digest_new);
		if (!vk)
			return -ENOENT;
		else {
			if (LUKS2_digest_verify_by_digest(cd, hdr, digest_new, vk) != digest_new)
				return -EINVAL;
			r = LUKS2_volume_key_load_in_keyring_by_digest(cd, hdr, vk, crypt_volume_key_get_id(vk));
			if (r)
				return r;
		}
	}

	if (digest_old >= 0 && digest_old != digest_new) {
		vk = crypt_volume_key_by_id(vks, digest_old);
		if (!vk) {
			r = -ENOENT;
			goto err;
		} else {
			if (LUKS2_digest_verify_by_digest(cd, hdr, digest_old, vk) != digest_old) {
				r = -EINVAL;
				goto err;
			}
			r = LUKS2_volume_key_load_in_keyring_by_digest(cd, hdr, vk, crypt_volume_key_get_id(vk));
			if (r)
				goto err;
		}
	}

	return 0;
err:
	crypt_drop_keyring_key(cd, vks);
	return r;
}

int LUKS2_reenc_load(struct crypt_device *cd, struct luks2_hdr *hdr,
		uint64_t device_size,
		const struct crypt_params_reencrypt *params,
		struct luks2_reenc_context **rh)
{
	int r;
	struct luks2_reenc_context *tmp = NULL;
	crypt_reencrypt_info ri = LUKS2_reenc_status(hdr);

	if (ri == CRYPT_REENCRYPT_CLEAN)
		r = _LUKS2_reenc_load(cd, hdr, device_size, &tmp, params);
	else if (ri == CRYPT_REENCRYPT_CRASH)
		r = LUKS2_reenc_load_crashed(cd, hdr, device_size, &tmp);
	else
		r = -EINVAL;

	if (r < 0 || !tmp) {
		log_err(cd, _("Failed to load reenc context."));
		return r;
	}

	*rh = tmp;

	return 0;
}

/* internal only */
int crypt_reencrypt_lock(struct crypt_device *cd, const char *uuid, struct crypt_lock_handle **reencrypt_lock)
{
	int r;
	char *lock_resource;
	const char *tmp = crypt_get_uuid(cd);

	if (!tmp && !uuid)
		return -EINVAL;
	if (!uuid)
		uuid = tmp;
	if (!tmp)
		 tmp = uuid;
	if (strcmp(uuid, tmp))
		return -EINVAL;

	r = asprintf(&lock_resource, "LUKS2-reencryption-%s", uuid);
	if (r < 0)
		return -ENOMEM;
	if (r < 20) {
		r = -EINVAL;
		goto out;
	}

	r = crypt_write_lock(cd, lock_resource, false, reencrypt_lock);
out:
	free(lock_resource);

	return r;
}

/* internal only */
void crypt_reencrypt_unlock(struct crypt_device *cd, struct crypt_lock_handle *reencrypt_lock)
{
	crypt_unlock_internal(cd, reencrypt_lock);
}

static int reencrypt_lock_and_verify(struct crypt_device *cd, struct luks2_hdr *hdr,
		struct crypt_lock_handle **reencrypt_lock)
{
	int r;
	crypt_reencrypt_info ri;
	struct crypt_lock_handle *h;

	ri = LUKS2_reenc_status(hdr);
	if (ri == CRYPT_REENCRYPT_INVALID) {
		log_err(cd, _("Failed to read reencryption state."));
		return -EINVAL;
	}
	if (ri < CRYPT_REENCRYPT_CLEAN) {
		log_err(cd, _("Device is not in reencryption."));
		return -EINVAL;
	}

	r = crypt_reencrypt_lock(cd, NULL, &h);
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
		crypt_reencrypt_unlock(cd, h);
		return r;
	}

	ri = LUKS2_reenc_status(hdr);
	if (ri == CRYPT_REENCRYPT_CLEAN) {
		*reencrypt_lock = h;
		return 0;
	}

	crypt_reencrypt_unlock(cd, h);
	log_err(cd, _("Device is not in clean reencryption state."));
	return -EINVAL;
}

static int _reencrypt_load(struct crypt_device *cd,
		const char *name,
		const char *passphrase,
		size_t passphrase_size,
		int keyslot_old,
		int keyslot_new,
		struct volume_key **vks,
		const struct crypt_params_reencrypt *params)
{
	int r;
	struct luks2_hdr *hdr;
	struct crypt_lock_handle *reencrypt_lock;
	struct luks2_reenc_context *rh;
	uint64_t device_size;

	log_dbg(cd, "Loading LUKS2 reencryption context.");

	rh = crypt_get_reenc_context(cd);
	if (rh) {
		LUKS2_reenc_context_free(cd, rh);
		crypt_set_reenc_context(cd, NULL);
		rh = NULL;
	}

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	r = reencrypt_lock_and_verify(cd, hdr, &reencrypt_lock);
	if (r)
		return r;

	/* From now on we hold reencryption lock */

	/* some configurations provides fixed device size */
	if ((r = luks2_check_device_size(cd, hdr, &device_size, false))) {
		r = -EINVAL;
		goto err;
	}

	r = LUKS2_reenc_load(cd, hdr, device_size, params, &rh);
	if (r < 0 || !rh) {
		log_err(cd, _("Failed to load reenc context."));
		goto err;
	}

	r = LUKS2_verify_and_upload_keys(cd, hdr, rh->digest_old, rh->digest_new, *vks);
	if (r == -ENOENT) {
		log_dbg(cd, "Keys are not ready. Unlocking all volume keys.");
		r = LUKS2_keyslot_open_all_segments(cd, keyslot_old, keyslot_new, passphrase, passphrase_size, vks);
		if (r < 0)
			goto err;
		r = LUKS2_verify_and_upload_keys(cd, hdr, rh->digest_old, rh->digest_new, *vks);
	}

	if (r < 0)
		goto err;

	if (name && (r = LUKS2_reenc_context_set_name(rh, name)))
		goto err;

	r = _init_storage_wrappers(cd, hdr, rh, *vks);
	if (r)
		goto err;

	MOVE_REF(rh->vks, *vks);
	MOVE_REF(rh->reenc_lock, reencrypt_lock);

	crypt_set_reenc_context(cd, rh);

	return 0;
err:
	crypt_reencrypt_unlock(cd, reencrypt_lock);
	LUKS2_reenc_context_free(cd, rh);
	return r;
}

static int _reencrypt_init_by_passphrase(struct crypt_device *cd,
	const char *name,
	const char *passphrase,
	size_t passphrase_size,
	int keyslot_old,
	int keyslot_new,
	const char *cipher,
	const char *cipher_mode,
	const struct crypt_params_reencrypt *params)
{
	struct luks2_hdr *hdr;
	int r;
	struct volume_key *vks = NULL;
	uint32_t flags = params ? params->flags : 0;

	if (cipher) {
		r = LUKS2_check_cipher(cd, crypt_keyslot_get_key_size(cd, keyslot_new),
			       cipher, cipher_mode);
		if (r < 0)
			return r;
	}

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	r = device_write_lock(cd, crypt_metadata_device(cd));
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s."),
			device_path(crypt_metadata_device(cd)));
		return r;
	}

	r = atomic_get_reencryption_flag(cd);

	if (r && (flags & CRYPT_REENCRYPT_INITIALIZE_ONLY)) {
		device_write_unlock(cd, crypt_metadata_device(cd));
		log_err(cd, _("LUKS2 reencryption already initialized."));
		return r;
	}

	/* r == 0, proceed with initialization */
	/* r == -EBUSY, skip initialization and proceed with reencrypt load */

	if (!r)
		r = _reencrypt_init(cd, hdr, passphrase, passphrase_size, keyslot_old, keyslot_new, cipher, cipher_mode, params, &vks);
	else if (r == -EBUSY) {
		log_dbg(cd, "LUKS2 reencryption already initialized.");
		r = 0;
	}

	device_write_unlock(cd, crypt_metadata_device(cd));

	if (r < 0 || (flags & CRYPT_REENCRYPT_INITIALIZE_ONLY))
		goto out;

	r = _reencrypt_load(cd, name, passphrase, passphrase_size, keyslot_old, keyslot_new, &vks, params);
out:
	if (r < 0)
		crypt_drop_keyring_key(cd, vks);
	crypt_free_volume_key(vks);
	return r < 0 ? r : LUKS2_find_keyslot(hdr, "reencrypt");
}

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
	char *passphrase;
	size_t passphrase_size;

	if (onlyLUKS2mask(cd, CRYPT_REQUIREMENT_ONLINE_REENCRYPT) || !passphrase_description)
		return -EINVAL;

	r = keyring_get_passphrase(passphrase_description, &passphrase, &passphrase_size);
	if (r < 0) {
		log_err(cd, _("Failed to read passphrase from keyring (error %d)."), r);
		return -EINVAL;
	}

	r = _reencrypt_init_by_passphrase(cd, name, passphrase, passphrase_size, keyslot_old, keyslot_new, cipher, cipher_mode, params);

	crypt_memzero(passphrase, passphrase_size);
	free(passphrase);

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
	if (onlyLUKS2mask(cd, CRYPT_REQUIREMENT_ONLINE_REENCRYPT) || !passphrase)
		return -EINVAL;

	return _reencrypt_init_by_passphrase(cd, name, passphrase, passphrase_size, keyslot_old, keyslot_new, cipher, cipher_mode, params);
}

static reenc_status_t _reencrypt_step(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		bool online)
{
	int r;

	/* update reencrypt keyslot protection parameters in memory only */
	r = reenc_keyslot_update(cd, rh);
	if (r < 0) {
		log_dbg(cd, "Keyslot update failed.");
		return REENC_ERR;
	}

	/* in memory only */
	r = _load_segments(cd, hdr, rh, device_size);
	if (r) {
		log_err(cd, _("Failed to calculate new segments."));
		return REENC_ERR;
	}

	JSON_DBG(cd, LUKS2_get_segments_jobj(hdr), "Actual luks2 header segments:");

	r = reenc_assign_segments(cd, hdr, rh, 1, 0);
	if (r) {
		log_err(cd, _("Failed to assign pre reenc segments."));
		return REENC_ERR;
	}

	JSON_DBG(cd, LUKS2_get_segments_jobj(hdr), "Actual header segments post pre assign:");

	if (online) {
		r = reenc_refresh_overlay_devices(cd, hdr, rh->overlay_name, rh->hotzone_name, rh->vks, rh->device_size);
		/* Teardown overlay devices with dm-error. None bio shall pass! */
		if (r != REENC_OK)
			return r;
	}

	log_dbg(cd, "Reencrypting chunk starting at offset: %" PRIu64 ", size :%" PRIu64 ".", rh->offset, rh->length);
	log_dbg(cd, "data_offset: %" PRIu64, crypt_get_data_offset(cd) << SECTOR_SHIFT);

	/* FIXME: moved segment only case */
	if (!rh->offset && rh->type == ENCRYPT && rh->data_shift && rh->jobj_segment_moved) {
		crypt_storage_wrapper_destroy(rh->cw1);
		r = crypt_storage_wrapper_init(cd, &rh->cw1, crypt_data_device(cd),
				LUKS2_reencrypt_get_data_offset_moved(hdr),
				crypt_get_iv_offset(cd),
				LUKS2_reencrypt_get_sector_size_old(hdr),
				LUKS2_reencrypt_segment_cipher_old(hdr),
				crypt_volume_key_by_id(rh->vks, rh->digest_old),
				rh->wflags1);
		if (r) {
			log_err(cd, _("Failed to reinitialize storage wrapper."));
			return REENC_ROLLBACK;
		}
		log_dbg(cd, "This will be encryption last step.");
	}

	rh->read = crypt_storage_wrapper_read(rh->cw1, rh->offset, rh->reenc_buffer, rh->length);
	if (rh->read < 0) {
		/* severity normal */
		log_err(cd, _("Failed to read chunk starting at %" PRIu64 "."), rh->offset);
		return REENC_ROLLBACK;
	}

	/* metadata commit point */
	r = reencrypt_hotzone_protect_final(cd, hdr, rh, rh->reenc_buffer, rh->read);
	if (r < 0) {
		/* severity normal */
		log_err(cd, _("Failed finalize hotzone resilience, retval = %d"), r);
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
		log_err(cd, _("Failed to write data."));
		return REENC_FATAL;
	}

	if (rh->rp.type != REENC_PROTECTION_NOOP && crypt_storage_wrapper_datasync(rh->cw2)) {
		log_err(cd, _("Failed to sync data."));
		return REENC_FATAL;
	}

	/* metadata commit safe point */
	r = reenc_assign_segments(cd, hdr, rh, 0, rh->rp.type != REENC_PROTECTION_NOOP);
	if (r) {
		/* severity fatal */
		log_err(cd, _("Failed to update metadata or reassign device segments."));
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

static int _reencrypt_teardown_ok(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh)
{
	int i, r;
	bool finished = (!continue_reencryption(cd, rh, rh->device_size));

	if (rh->rp.type == REENC_PROTECTION_NOOP &&
	    LUKS2_hdr_write(cd, hdr)) {
		log_err(cd, _("Failed to write LUKS2 metadata."));
		return -EINVAL;
	}

	if (rh->online) {
		r = LUKS2_reload(cd, rh->device_name, rh->vks, CRYPT_ACTIVATE_KEYRING_KEY | CRYPT_ACTIVATE_SHARED);
		if (r)
			log_err(cd, _("Failed to reload %s device."), rh->device_name);
		if (!r) {
			r = dm_resume_device(cd, rh->device_name, 0);
			if (r)
				log_err(cd, _("Failed to resume %s device."), rh->device_name);
		}
		dm_remove_device(cd, rh->overlay_name, 0);
		dm_remove_device(cd, rh->hotzone_name, 0);
	}

	if (finished) {
		if (LUKS2_reencrypt_get_data_offset_new(hdr) && LUKS2_set_keyslots_size(cd, hdr, LUKS2_reencrypt_get_data_offset_new(hdr)))
			log_err(cd, _("Failed to set new keyslots_size after reencryption"));
		if (rh->digest_old >= 0 && rh->digest_new != rh->digest_old)
			for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++)
				if (LUKS2_digest_by_keyslot(hdr, i) == rh->digest_old)
					crypt_keyslot_destroy(cd, i);
		crypt_keyslot_destroy(cd, rh->reenc_keyslot);
		if (reenc_erase_backup_segments(cd, hdr))
			log_err(cd, _("Failed to erase backup segments"));

		/* do we need atomic erase? */
		if (update_reencryption_flag(cd, 0, true))
			log_err(cd, _("Failed to disable reencryption requirement flag."));
	}

	/* this frees reencryption lock */
	LUKS2_reenc_context_free(cd, rh);
	crypt_set_reenc_context(cd, NULL);

	return 0;
}

static void _reencrypt_teardown_fatal(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh)
{
	log_err(cd, _("Fatal error while reencrypting chunk starting at %" PRIu64 ", %" PRIu64 " sectors long."),
		(rh->offset >> SECTOR_SHIFT) + crypt_get_data_offset(cd), rh->length >> SECTOR_SHIFT);

	if (rh->online) {
		log_err(cd, "Reencryption was run in online mode.");
		if (dm_status_suspended(cd, rh->hotzone_name) > 0) {
			log_dbg(cd, "Hotzone device %s suspended, replacing with dm-error.", rh->hotzone_name);
			if (dm_error_device(cd, rh->hotzone_name)) {
				log_err(cd, _("Failed to replace hotzone device %s with error target.\n" \
					      "Do not resume the device unless replaced with error target manually."), rh->hotzone_name);
				goto out;
			}
		}
	}
out:
	/* this frees reencryption lock */
	LUKS2_reenc_context_free(cd, rh);
	crypt_set_reenc_context(cd, NULL);
}

static int _reencrypt_free(struct crypt_device *cd, struct luks2_hdr *hdr, struct luks2_reenc_context *rh, reenc_status_t rs,
		    int (*progress)(uint64_t size, uint64_t offset, void *usrptr))
{
	switch (rs) {
	case REENC_OK:
		if (progress)
			progress(rh->device_size, rh->progress, NULL);
		return _reencrypt_teardown_ok(cd, hdr, rh);
	case REENC_FATAL:
		_reencrypt_teardown_fatal(cd, hdr, rh);
		/* fall-through */
	default:
		return -EIO;
	}
}

int crypt_reencrypt(struct crypt_device *cd,
		    int (*progress)(uint64_t size, uint64_t offset, void *usrptr))
{
	int r, excl_devfd = -1;
	crypt_reencrypt_info ri;
	struct luks2_hdr *hdr;
	struct luks2_reenc_context *rh;
	reenc_status_t rs;
	bool quit = false;

	if (onlyLUKS2mask(cd, CRYPT_REQUIREMENT_ONLINE_REENCRYPT))
		return -EINVAL;

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	ri = LUKS2_reenc_status(hdr);
	if (ri > CRYPT_REENCRYPT_CLEAN) {
		log_err(cd, _("Can't resume reencryption. Unexpected reencryption status."));
		return -EINVAL;
	}

	rh = crypt_get_reenc_context(cd);
	if (!rh || !rh->reenc_lock) {
		log_err(cd, _("Missing or invalid reencrypt context."));
		return -EINVAL;
	}

	log_dbg(cd, "Resuming LUKS2 reencryption.");

	if (rh->online) {
		r = reenc_init_helper_devices(cd, rh->device_name, rh->hotzone_name, rh->overlay_name);
		if (r) {
			log_err(cd, _("Failed to initalize reencryption device stack."));
			return -EINVAL;
		}
	} else {
		if (crypt_storage_wrapper_get_type(rh->cw1) != DMCRYPT &&
		    crypt_storage_wrapper_get_type(rh->cw2) != DMCRYPT) {
			excl_devfd = device_open_excl(cd, crypt_data_device(cd), O_RDONLY);
			if (excl_devfd < 0) {
				log_err(cd, _("Failed to open device %s in exclusive mode. Already mounted?."), device_path(crypt_data_device(cd)));
				return -EBUSY;
			}
		}
	}

	log_dbg(cd, "Progress %" PRIu64 ", device_size %" PRIu64, rh->progress, rh->device_size);
	if (progress && progress(rh->device_size, rh->progress, NULL))
		quit = true;

	rs = REENC_OK;

	while (!quit && continue_reencryption(cd, rh, rh->device_size)) {
		rs = _reencrypt_step(cd, hdr, rh, rh->device_size, rh->online);
		if (rs != REENC_OK)
			break;

		log_dbg(cd, "Progress %" PRIu64 ", device_size %" PRIu64, rh->progress, rh->device_size);
		if (progress && progress(rh->device_size, rh->progress, NULL))
			quit = true;

		r = _update_reencrypt_context(cd, rh);
		if (r) {
			log_err(cd, _("Failed to update reencryption context."));
			rs = REENC_ERR;
			break;
		}

		log_dbg(cd, "Next reencryption offset will be %" PRIu64 " sectors.", rh->offset);
		log_dbg(cd, "Next reencryption chunk size will be %" PRIu64 " sectors).", rh->length);
	}

	r = _reencrypt_free(cd, hdr, rh, rs, progress);
	if (excl_devfd >= 0)
		close(excl_devfd);
	return r;
}

int reenc_erase_backup_segments(struct crypt_device *cd,
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

/* internal only */
int luks2_check_device_size(struct crypt_device *cd, struct luks2_hdr *hdr, uint64_t *device_size, bool activation)
{
	int r;
	int64_t data_shift;
	uint64_t check_size, real_size = 0;

	/*
	 * Calculate sum of all segments. The last dynamic segment adds one encryption sector to the sum
	 * If there's only single dynamic segment it returns 0 which later reads data device size (minus offset)
	 */
	if (LUKS2_get_data_size(hdr, &check_size))
		return -EINVAL;

	data_shift = LUKS2_reencrypt_data_shift(hdr);
	/* initial data device reduction must be extended for spare space for data shift
	 * layout looks like:
	 * [LUKS2 hdr (data offset)][segment s with fixed size] [spare space for shift] [moved segment]
	 */
	if (LUKS2_get_segment_id_by_flag(hdr, "backup-moved-segment") >= 0)
		check_size += data_shift;

	check_size >>= SECTOR_SHIFT;

	/* Here we check minimal size */
	r = device_block_adjust(cd, crypt_data_device(cd), activation ? DEV_EXCL : DEV_OK,
				crypt_get_data_offset(cd), &check_size, NULL);

	if (r)
		return r;

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_OK,
				crypt_get_data_offset(cd), &real_size, NULL);
	if (r)
		return r;

	*device_size = real_size << SECTOR_SHIFT;

	return r;
}
