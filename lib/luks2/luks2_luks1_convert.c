/*
 * LUKS - Linux Unified Key Setup v2, LUKS1 conversion code
 *
 * Copyright (C) 2015-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2018, Ondrej Kozina. All rights reserved.
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
#include "../luks1/luks.h"
#include "../luks1/af.h"

static int json_luks1_keyslot(const struct luks_phdr *hdr_v1, int keyslot, struct json_object **keyslot_object)
{
	char *base64_str, cipher[LUKS_CIPHERNAME_L+LUKS_CIPHERMODE_L];
	size_t base64_len;
	struct json_object *keyslot_obj, *field, *jobj_kdf, *jobj_af, *jobj_area;
	uint64_t offset, area_size, offs_a, offs_b, length;

	keyslot_obj = json_object_new_object();
	json_object_object_add(keyslot_obj, "type", json_object_new_string("luks2"));
	json_object_object_add(keyslot_obj, "key_size", json_object_new_int64(hdr_v1->keyBytes));

	/* KDF */
	jobj_kdf = json_object_new_object();
	json_object_object_add(jobj_kdf, "type", json_object_new_string(CRYPT_KDF_PBKDF2));
	json_object_object_add(jobj_kdf, "hash", json_object_new_string(hdr_v1->hashSpec));
	json_object_object_add(jobj_kdf, "iterations", json_object_new_int64(hdr_v1->keyblock[keyslot].passwordIterations));
	/* salt field */
	base64_len = base64_encode_alloc(hdr_v1->keyblock[keyslot].passwordSalt, LUKS_SALTSIZE, &base64_str);
	if (!base64_str) {
		json_object_put(keyslot_obj);
		json_object_put(jobj_kdf);
		if (!base64_len)
			return -EINVAL;
		return -ENOMEM;
	}
	field = json_object_new_string_len(base64_str, base64_len);
	free(base64_str);
	json_object_object_add(jobj_kdf, "salt", field);
	json_object_object_add(keyslot_obj, "kdf", jobj_kdf);

	/* AF */
	jobj_af = json_object_new_object();
	json_object_object_add(jobj_af, "type", json_object_new_string("luks1"));
	json_object_object_add(jobj_af, "hash", json_object_new_string(hdr_v1->hashSpec));
	/* stripes field ignored, fixed to LUKS_STRIPES (4000) */
	json_object_object_add(jobj_af, "stripes", json_object_new_int(4000));
	json_object_object_add(keyslot_obj, "af", jobj_af);

	/* Area */
	jobj_area = json_object_new_object();
	json_object_object_add(jobj_area, "type", json_object_new_string("raw"));

	/* encryption algorithm field */
	if (*hdr_v1->cipherMode != '\0') {
		(void) snprintf(cipher, sizeof(cipher), "%s-%s", hdr_v1->cipherName, hdr_v1->cipherMode);
		json_object_object_add(jobj_area, "encryption", json_object_new_string(cipher));
	} else
		json_object_object_add(jobj_area, "encryption", json_object_new_string(hdr_v1->cipherName));

	/* area */
	if (LUKS_keyslot_area(hdr_v1, 0, &offs_a, &length) ||
	    LUKS_keyslot_area(hdr_v1, 1, &offs_b, &length) ||
	    LUKS_keyslot_area(hdr_v1, keyslot, &offset, &length)) {
		json_object_put(keyslot_obj);
		json_object_put(jobj_area);
		return -EINVAL;
	}
	area_size = offs_b - offs_a;
	json_object_object_add(jobj_area, "key_size", json_object_new_int(hdr_v1->keyBytes));
	json_object_object_add(jobj_area, "offset", json_object_new_uint64(offset));
	json_object_object_add(jobj_area, "size", json_object_new_uint64(area_size));
	json_object_object_add(keyslot_obj, "area", jobj_area);

	*keyslot_object = keyslot_obj;
	return 0;
}

static int json_luks1_keyslots(const struct luks_phdr *hdr_v1, struct json_object **keyslots_object)
{
	char keyslot_str[2];
	int key_slot, r;
	struct json_object *keyslot_obj, *field;

	keyslot_obj = json_object_new_object();
	if (!keyslot_obj)
		return -ENOMEM;

	for (key_slot = 0; key_slot < LUKS_NUMKEYS; key_slot++) {
		if (hdr_v1->keyblock[key_slot].active != LUKS_KEY_ENABLED)
			continue;
		r = json_luks1_keyslot(hdr_v1, key_slot, &field);
		if (r) {
			json_object_put(keyslot_obj);
			return r;
		}
		(void) snprintf(keyslot_str, sizeof(keyslot_str), "%d", key_slot);
		json_object_object_add(keyslot_obj, keyslot_str, field);
	}

	*keyslots_object = keyslot_obj;
	return 0;
}

static int json_luks1_segment(const struct luks_phdr *hdr_v1, struct json_object **segment_object)
{
	const char *c;
	char cipher[LUKS_CIPHERNAME_L+LUKS_CIPHERMODE_L];
	struct json_object *segment_obj, *field;
	uint64_t number;

	segment_obj = json_object_new_object();
	if (!segment_obj)
		return -ENOMEM;

	/* type field */
	field = json_object_new_string("crypt");
	if (!field) {
		json_object_put(segment_obj);
		return -ENOMEM;
	}
	json_object_object_add(segment_obj, "type", field);

	/* offset field */
	number = (uint64_t)hdr_v1->payloadOffset * SECTOR_SIZE;

	field = json_object_new_uint64(number);
	if (!field) {
		json_object_put(segment_obj);
		return -ENOMEM;
	}
	json_object_object_add(segment_obj, "offset", field);

	/* iv_tweak field */
	field = json_object_new_string("0");
	if (!field) {
		json_object_put(segment_obj);
		return -ENOMEM;
	}
	json_object_object_add(segment_obj, "iv_tweak", field);

	/* length field */
	field = json_object_new_string("dynamic");
	if (!field) {
		json_object_put(segment_obj);
		return -ENOMEM;
	}
	json_object_object_add(segment_obj, "size", field);

	/* cipher field */
	if (*hdr_v1->cipherMode != '\0') {
		(void) snprintf(cipher, sizeof(cipher), "%s-%s", hdr_v1->cipherName, hdr_v1->cipherMode);
		c = cipher;
	} else
		c = hdr_v1->cipherName;

	field = json_object_new_string(c);
	if (!field) {
		json_object_put(segment_obj);
		return -ENOMEM;
	}
	json_object_object_add(segment_obj, "encryption", field);

	/* block field */
	field = json_object_new_int(SECTOR_SIZE);
	if (!field) {
		json_object_put(segment_obj);
		return -ENOMEM;
	}
	json_object_object_add(segment_obj, "sector_size", field);

	*segment_object = segment_obj;
	return 0;
}

static int json_luks1_segments(const struct luks_phdr *hdr_v1, struct json_object **segments_object)
{
	char num[16];
	int r;
	struct json_object *segments_obj, *field;

	segments_obj = json_object_new_object();
	if (!segments_obj)
		return -ENOMEM;

	r = json_luks1_segment(hdr_v1, &field);
	if (r) {
		json_object_put(segments_obj);
		return r;
	}
	snprintf(num, sizeof(num), "%u", CRYPT_DEFAULT_SEGMENT);
	json_object_object_add(segments_obj, num, field);

	*segments_object = segments_obj;
	return 0;
}

static int json_luks1_digest(const struct luks_phdr *hdr_v1, struct json_object **digest_object)
{
	char keyslot_str[2], *base64_str;
	int ks;
	size_t base64_len;
	struct json_object *digest_obj, *array, *field;

	digest_obj = json_object_new_object();
	if (!digest_obj)
		return -ENOMEM;

	/* type field */
	field = json_object_new_string("pbkdf2");
	if (!field) {
		json_object_put(digest_obj);
		return -ENOMEM;
	}
	json_object_object_add(digest_obj, "type", field);

	/* keyslots array */
	array = json_object_new_array();
	if (!array) {
		json_object_put(digest_obj);
		return -ENOMEM;
	}
	json_object_object_add(digest_obj, "keyslots", json_object_get(array));

	for (ks = 0; ks < LUKS_NUMKEYS; ks++) {
		if (hdr_v1->keyblock[ks].active != LUKS_KEY_ENABLED)
			continue;
		(void) snprintf(keyslot_str, sizeof(keyslot_str), "%d", ks);

		field = json_object_new_string(keyslot_str);
		if (!field || json_object_array_add(array, field) < 0) {
			json_object_put(field);
			json_object_put(array);
			json_object_put(digest_obj);
			return -ENOMEM;
		}
	}

	json_object_put(array);

	/* segments array */
	array = json_object_new_array();
	if (!array) {
		json_object_put(digest_obj);
		return -ENOMEM;
	}
	json_object_object_add(digest_obj, "segments", json_object_get(array));

	field = json_object_new_string("0");
	if (!field || json_object_array_add(array, field) < 0) {
		json_object_put(field);
		json_object_put(array);
		json_object_put(digest_obj);
		return -ENOMEM;
	}

	json_object_put(array);

	/* hash field */
	field = json_object_new_string(hdr_v1->hashSpec);
	if (!field) {
		json_object_put(digest_obj);
		return -ENOMEM;
	}
	json_object_object_add(digest_obj, "hash", field);

	/* salt field */
	base64_len = base64_encode_alloc(hdr_v1->mkDigestSalt, LUKS_SALTSIZE, &base64_str);
	if (!base64_str) {
		json_object_put(digest_obj);
		if (!base64_len)
			return -EINVAL;
		return -ENOMEM;
	}

	field = json_object_new_string_len(base64_str, base64_len);
	free(base64_str);
	if (!field) {
		json_object_put(digest_obj);
		return -ENOMEM;
	}
	json_object_object_add(digest_obj, "salt", field);

	/* digest field */
	base64_len = base64_encode_alloc(hdr_v1->mkDigest, LUKS_DIGESTSIZE, &base64_str);
	if (!base64_str) {
		json_object_put(digest_obj);
		if (!base64_len)
			return -EINVAL;
		return -ENOMEM;
	}

	field = json_object_new_string_len(base64_str, base64_len);
	free(base64_str);
	if (!field) {
		json_object_put(digest_obj);
		return -ENOMEM;
	}
	json_object_object_add(digest_obj, "digest", field);

	/* iterations field */
	field = json_object_new_int64(hdr_v1->mkDigestIterations);
	if (!field) {
		json_object_put(digest_obj);
		return -ENOMEM;
	}
	json_object_object_add(digest_obj, "iterations", field);

	*digest_object = digest_obj;
	return 0;
}

static int json_luks1_digests(const struct luks_phdr *hdr_v1, struct json_object **digests_object)
{
	int r;
	struct json_object *digests_obj, *field;

	digests_obj = json_object_new_object();
	if (!digests_obj)
		return -ENOMEM;

	r = json_luks1_digest(hdr_v1, &field);
	if (r) {
		json_object_put(digests_obj);
		return r;
	}
	json_object_object_add(digests_obj, "0", field);

	*digests_object = digests_obj;
	return 0;
}

static int json_luks1_object(struct luks_phdr *hdr_v1, struct json_object **luks1_object, uint64_t keyslots_size)
{
	int r;
	struct json_object *luks1_obj, *field;
	uint64_t json_size;

	luks1_obj = json_object_new_object();
	if (!luks1_obj)
		return -ENOMEM;

	/* keyslots field */
	r = json_luks1_keyslots(hdr_v1, &field);
	if (r) {
		json_object_put(luks1_obj);
		return r;
	}
	json_object_object_add(luks1_obj, "keyslots", field);

	/* tokens field */
	field = json_object_new_object();
	if (!field) {
		json_object_put(luks1_obj);
		return -ENOMEM;
	}
	json_object_object_add(luks1_obj, "tokens", field);

	/* segments field */
	r = json_luks1_segments(hdr_v1, &field);
	if (r) {
		json_object_put(luks1_obj);
		return r;
	}
	json_object_object_add(luks1_obj, "segments", field);

	/* digests field */
	r = json_luks1_digests(hdr_v1, &field);
	if (r) {
		json_object_put(luks1_obj);
		return r;
	}
	json_object_object_add(luks1_obj, "digests", field);

	/* config field */
	/* anything else? */
	field = json_object_new_object();
	if (!field) {
		json_object_put(luks1_obj);
		return -ENOMEM;
	}
	json_object_object_add(luks1_obj, "config", field);

	json_size = LUKS2_HDR_16K_LEN - LUKS2_HDR_BIN_LEN;
	json_object_object_add(field, "json_size", json_object_new_uint64(json_size));
	json_object_object_add(field, "keyslots_size", json_object_new_uint64(keyslots_size));

	*luks1_object = luks1_obj;
	return 0;
}

static void move_keyslot_offset(json_object *jobj, int offset_add)
{
	json_object *jobj1, *jobj2, *jobj_area;
	uint64_t offset = 0;

	json_object_object_get_ex(jobj, "keyslots", &jobj1);
	json_object_object_foreach(jobj1, key, val) {
		UNUSED(key);
		json_object_object_get_ex(val, "area", &jobj_area);
		json_object_object_get_ex(jobj_area, "offset", &jobj2);
		offset = json_object_get_uint64(jobj2) + offset_add;
		json_object_object_add(jobj_area, "offset", json_object_new_uint64(offset));
	}
}

/* FIXME: return specific error code for partial write error (aka keyslots are gone) */
static int move_keyslot_areas(struct crypt_device *cd, off_t offset_from,
			      off_t offset_to, size_t buf_size)
{
	struct device *device = crypt_metadata_device(cd);
	void *buf = NULL;
	int devfd = -1;

	log_dbg("Moving keyslot areas of size %zu from %jd to %jd.",
		buf_size, (intmax_t)offset_from, (intmax_t)offset_to);

	// FIXME: export aligned_malloc from utils
	if (posix_memalign(&buf, crypt_getpagesize(), buf_size))
		return -ENOMEM;

	devfd = device_open(device, O_RDWR);
	if (devfd == -1) {
		log_dbg("Cannot open device %s.", device_path(device));
		free(buf);
		return -EIO;
	}

	if (read_lseek_blockwise(devfd, device_block_size(device),
				 device_alignment(device), buf, buf_size,
				 offset_from)!= (ssize_t)buf_size) {
		close(devfd);
		free(buf);
		return -EIO;
	}

	if (write_lseek_blockwise(devfd, device_block_size(device),
				  device_alignment(device), buf, buf_size,
				  offset_to) != (ssize_t)buf_size) {
		close(devfd);
		free(buf);
		return -EIO;
	}

	close(devfd);
	crypt_memzero(buf, buf_size);
	free(buf);

	return 0;
}

static int luks_header_in_use(struct crypt_device *cd)
{
	int r;

	r = lookup_dm_dev_by_uuid(crypt_get_uuid(cd), crypt_get_type(cd));
	if (r < 0)
		log_err(cd, _("Can not check status of device with uuid: %s.\n"), crypt_get_uuid(cd));

	return r;
}

/* Convert LUKS1 -> LUKS2 */
int LUKS2_luks1_to_luks2(struct crypt_device *cd, struct luks_phdr *hdr1, struct luks2_hdr *hdr2)
{
	int r;
	json_object *jobj = NULL;
	size_t buf_size, buf_offset, luks1_size, luks1_shift = 2 * LUKS2_HDR_16K_LEN - LUKS_ALIGN_KEYSLOTS;
	uint64_t max_size = crypt_get_data_offset(cd) * SECTOR_SIZE;

	/* for detached headers max size == device size */
	if (!max_size && (r = device_size(crypt_metadata_device(cd), &max_size)))
		return r;

	luks1_size = LUKS_device_sectors(hdr1) << SECTOR_SHIFT;
	if (!luks1_size)
		return -EINVAL;

	if (LUKS_keyslots_offset(hdr1) != (LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE)) {
		log_dbg("Unsupported keyslots material offset: %zu.", LUKS_keyslots_offset(hdr1));
		return -EINVAL;
	}

	log_dbg("Max size: %" PRIu64 ", LUKS1 (full) header size %zu , required shift: %zu",
		max_size, luks1_size, luks1_shift);
	if ((max_size - luks1_size) < luks1_shift) {
		log_err(cd, _("Unable to move keyslot materials. Not enough space\n"));
		return -EINVAL;
	}

	r = json_luks1_object(hdr1, &jobj, max_size - 2 * LUKS2_HDR_16K_LEN);
	if (r < 0)
		return r;

	move_keyslot_offset(jobj, luks1_shift);

	// fill hdr2
	memset(hdr2, 0, sizeof(*hdr2));
	hdr2->hdr_size = LUKS2_HDR_16K_LEN;
	hdr2->seqid = 1;
	hdr2->version = 2;
	strncpy(hdr2->checksum_alg, "sha256", LUKS2_CHECKSUM_ALG_L);
	crypt_random_get(cd, (char*)hdr2->salt1, sizeof(hdr2->salt1), CRYPT_RND_SALT);
	crypt_random_get(cd, (char*)hdr2->salt2, sizeof(hdr2->salt2), CRYPT_RND_SALT);
	strncpy(hdr2->uuid, crypt_get_uuid(cd), LUKS2_UUID_L-1); /* UUID should be max 36 chars */
	hdr2->jobj = jobj;

	/*
	 * It duplicates check in LUKS2_hdr_write() but we don't want to move
	 * keyslot areas in case it would fail later
	 */
	if (max_size < LUKS2_hdr_and_areas_size(hdr2->jobj)) {
		r = -EINVAL;
		goto out;
	}

	if ((r = luks_header_in_use(cd))) {
		if (r > 0)
			r = -EBUSY;
		goto out;
	}

	// move keyslots 4k -> 32k offset
	buf_offset = 2 * LUKS2_HDR_16K_LEN;
	buf_size   = luks1_size - LUKS_ALIGN_KEYSLOTS;
	if ((r = move_keyslot_areas(cd, 8 * SECTOR_SIZE, buf_offset, buf_size)) < 0)
		goto out;

	// Write JSON hdr2
	r = LUKS2_hdr_write(cd, hdr2);
out:
	LUKS2_hdr_free(hdr2);

	return r;
}

static int keyslot_LUKS1_compatible(struct luks2_hdr *hdr, int keyslot, uint32_t key_size)
{
	json_object *jobj_keyslot, *jobj, *jobj_kdf, *jobj_af;
	uint64_t l2_offset, l2_length;
	int ks_key_size;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return 1;

	if (!json_object_object_get_ex(jobj_keyslot, "type", &jobj) ||
	    strcmp(json_object_get_string(jobj), "luks2"))
		return 0;

	/* Using PBKDF2, this implies memory and parallel is not used. */
	jobj = NULL;
	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf) ||
	    !json_object_object_get_ex(jobj_kdf, "type", &jobj) ||
	    strcmp(json_object_get_string(jobj), CRYPT_KDF_PBKDF2))
		return 0;

	jobj = NULL;
	if (!json_object_object_get_ex(jobj_keyslot, "af", &jobj_af) ||
	    !json_object_object_get_ex(jobj_af, "stripes", &jobj) ||
	    json_object_get_int(jobj) != LUKS_STRIPES)
		return 0;

	jobj = NULL;
	if (!json_object_object_get_ex(jobj_af, "hash", &jobj) ||
	    crypt_hash_size(json_object_get_string(jobj)) < 0)
		return 0;

	/* FIXME: should this go to validation code instead (aka invalid luks2 header if assigned to segment 0)? */
	ks_key_size = LUKS2_get_keyslot_key_size(hdr, keyslot);
	if (ks_key_size < 0 || (int)key_size != LUKS2_get_keyslot_key_size(hdr, keyslot)) {
		log_dbg("Key length in keyslot %d is different from volume key length", keyslot);
		return 0;
	}

	if (LUKS2_keyslot_area(hdr, keyslot, &l2_offset, &l2_length))
		return 0;

	if (l2_length != (size_round_up(AF_split_sectors(key_size, LUKS_STRIPES) * SECTOR_SIZE, 4096))) {
		log_dbg("Area length in LUKS2 keyslot (%d) is not compatible with LUKS1", keyslot);
		return 0;
	}

	return 1;
}

/* Convert LUKS2 -> LUKS1 */
int LUKS2_luks2_to_luks1(struct crypt_device *cd, struct luks2_hdr *hdr2, struct luks_phdr *hdr1)
{
	size_t buf_size, buf_offset;
	char cipher[LUKS_CIPHERNAME_L], cipher_mode[LUKS_CIPHERMODE_L];
	char digest[LUKS_DIGESTSIZE], digest_salt[LUKS_SALTSIZE];
	size_t len;
	json_object *jobj_keyslot, *jobj_digest, *jobj_segment, *jobj_kdf, *jobj_area, *jobj1, *jobj2;
	uint32_t key_size;
	int i, r, last_active = 0;
	uint64_t offset, area_length;
	struct luks2_keyslot_params params;
	char buf[256], luksMagic[] = LUKS_MAGIC;

	jobj_digest  = LUKS2_get_digest_jobj(hdr2, 0);
	if (!jobj_digest)
		return -EINVAL;

	jobj_segment = LUKS2_get_segment_jobj(hdr2, CRYPT_DEFAULT_SEGMENT);
	if (!jobj_segment)
		return -EINVAL;

	json_object_object_get_ex(hdr2->jobj, "digests", &jobj1);
	if (!json_object_object_get_ex(jobj_digest, "type", &jobj2) ||
	    strcmp(json_object_get_string(jobj2), "pbkdf2") ||
	    json_object_object_length(jobj1) != 1) {
		log_err(cd, _("Cannot convert to LUKS1 format - key slot digests are not LUKS1 compatible.\n"));
		return -EINVAL;
	}

	/* We really do not care about params later except keys_size */
	r = LUKS2_keyslot_params_default(cd, hdr2, 0, &params);
	if (r < 0)
		return -EINVAL;

	r = LUKS2_get_volume_key_size(hdr2, 0);
	if (r < 0)
		return -EINVAL;
	key_size = r;
	params.area.raw.key_size = key_size;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++) {
		if (LUKS2_keyslot_info(hdr2, i) == CRYPT_SLOT_INACTIVE)
			continue;

		if (LUKS2_keyslot_info(hdr2, i) == CRYPT_SLOT_INVALID) {
			log_err(cd, _("Cannot convert to LUKS1 format - keyslot %u is in invalid state.\n"), i);
			return -EINVAL;
		}

		if (i >= LUKS_NUMKEYS) {
			log_err(cd, _("Cannot convert to LUKS1 format - slot %u (over maximum slots) is still active.\n"), i);
			return -EINVAL;
		}

		if (!keyslot_LUKS1_compatible(hdr2, i, key_size)) {
			log_err(cd, _("Cannot convert to LUKS1 format - keyslot %u is not LUKS1 compatible.\n"), i);
			return -EINVAL;
		}
	}

	memset(hdr1, 0, sizeof(*hdr1));

	for (i = 0; i < LUKS_NUMKEYS; i++) {
		hdr1->keyblock[i].active = LUKS_KEY_DISABLED;
		hdr1->keyblock[i].stripes = LUKS_STRIPES;

		jobj_keyslot = LUKS2_get_keyslot_jobj(hdr2, i);

		if (jobj_keyslot) {
			if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
				return -EINVAL;
			if (!json_object_object_get_ex(jobj_area, "offset", &jobj1))
				return -EINVAL;
			offset = json_object_get_uint64(jobj1);
		} else {
			if (LUKS2_find_area_gap(cd, hdr2, key_size, &offset, &area_length))
				return -EINVAL;
			/* FIXME: luks2 reload is required! */
			if (luks2_keyslot_alloc(cd, i, key_size, &params))
				return -EINVAL;
		}

		offset /= SECTOR_SIZE;
		if (offset > UINT32_MAX)
			return -EINVAL;

		hdr1->keyblock[i].keyMaterialOffset = offset;
		hdr1->keyblock[i].keyMaterialOffset -=
				((2 * LUKS2_HDR_16K_LEN - LUKS_ALIGN_KEYSLOTS) / SECTOR_SIZE);

		if (!jobj_keyslot)
			continue;

		hdr1->keyblock[i].active = LUKS_KEY_ENABLED;
		last_active = i;

		if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf))
			continue;

		if (!json_object_object_get_ex(jobj_kdf, "iterations", &jobj1))
			continue;
		hdr1->keyblock[i].passwordIterations = json_object_get_uint32(jobj1);

		if (!json_object_object_get_ex(jobj_kdf, "salt", &jobj1))
			continue;
		len = sizeof(buf);
		memset(buf, 0, len);
		if (!base64_decode(json_object_get_string(jobj1),
				   json_object_get_string_len(jobj1), buf, &len))
			continue;
		if (len > 0 && len != LUKS_SALTSIZE)
			continue;
		memcpy(hdr1->keyblock[i].passwordSalt, buf, LUKS_SALTSIZE);
	}

	if (!jobj_keyslot) {
		jobj_keyslot = LUKS2_get_keyslot_jobj(hdr2, last_active);
		if (!jobj_keyslot)
			return -EINVAL;
	}

	if (!json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;
	if (!json_object_object_get_ex(jobj_area, "encryption", &jobj1))
		return -EINVAL;
	r = crypt_parse_name_and_mode(json_object_get_string(jobj1), cipher, NULL, cipher_mode);
	if (r < 0)
		return r;

	strncpy(hdr1->cipherName, cipher, sizeof(hdr1->cipherName) - 1);
	strncpy(hdr1->cipherMode, cipher_mode, sizeof(hdr1->cipherMode) - 1);

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf))
		return -EINVAL;
	if (!json_object_object_get_ex(jobj_kdf, "hash", &jobj1))
		return -EINVAL;
	strncpy(hdr1->hashSpec, json_object_get_string(jobj1), sizeof(hdr1->hashSpec) - 1);

	hdr1->keyBytes = key_size;

	if (!json_object_object_get_ex(jobj_digest, "iterations", &jobj1))
		return -EINVAL;
	hdr1->mkDigestIterations = json_object_get_uint32(jobj1);

	if (!json_object_object_get_ex(jobj_digest, "digest", &jobj1))
		return -EINVAL;
	len = sizeof(digest);
	if (!base64_decode(json_object_get_string(jobj1),
			   json_object_get_string_len(jobj1), digest, &len))
		return -EINVAL;
	/* We can store full digest here, not only sha1 length */
	if (len < LUKS_DIGESTSIZE)
		return -EINVAL;
	memcpy(hdr1->mkDigest, digest, LUKS_DIGESTSIZE);

	if (!json_object_object_get_ex(jobj_digest, "salt", &jobj1))
		return -EINVAL;
	len = sizeof(digest_salt);
	if (!base64_decode(json_object_get_string(jobj1),
			   json_object_get_string_len(jobj1), digest_salt, &len))
		return -EINVAL;
	if (len != LUKS_SALTSIZE)
		return -EINVAL;
	memcpy(hdr1->mkDigestSalt, digest_salt, LUKS_SALTSIZE);

	if (!json_object_object_get_ex(jobj_segment, "offset", &jobj1))
		return -EINVAL;
	offset = json_object_get_uint64(jobj1) / SECTOR_SIZE;
	if (offset > UINT32_MAX)
		return -EINVAL;
	/* FIXME: LUKS1 requires offset == 0 || offset >= luks1_hdr_size */
	hdr1->payloadOffset = offset;

	strncpy(hdr1->uuid, hdr2->uuid, UUID_STRING_L - 1); /* max 36 chars */

	memcpy(hdr1->magic, luksMagic, LUKS_MAGIC_L);

	hdr1->version = 1;

	r = luks_header_in_use(cd);
	if (r)
		return r > 0 ? -EBUSY : r;

	// move keyslots 32k -> 4k offset
	buf_offset = 2 * LUKS2_HDR_16K_LEN;
	buf_size   = LUKS2_keyslots_size(hdr2->jobj);
	r = move_keyslot_areas(cd, buf_offset, 8 * SECTOR_SIZE, buf_size);
	if (r < 0)
		return r;

	crypt_wipe_device(cd, crypt_metadata_device(cd), CRYPT_WIPE_ZERO, 0,
			  8 * SECTOR_SIZE, 8 * SECTOR_SIZE, NULL, NULL);

	// Write LUKS1 hdr
	return LUKS_write_phdr(hdr1, cd);
}
