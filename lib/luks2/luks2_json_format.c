// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2, LUKS2 header format code
 *
 * Copyright (C) 2015-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2025 Milan Broz
 */

#include "luks2_internal.h"
#include <uuid/uuid.h>

struct area {
	uint64_t offset;
	uint64_t length;
};

static size_t get_area_size(size_t keylength)
{
	/* for now it is AF_split_sectors */
	return size_round_up(keylength * 4000, 4096);
}

static size_t get_min_offset(struct luks2_hdr *hdr)
{
	return 2 * hdr->hdr_size;
}

static size_t get_max_offset(struct luks2_hdr *hdr)
{
	return LUKS2_hdr_and_areas_size(hdr);
}

int LUKS2_find_area_max_gap(struct crypt_device *cd, struct luks2_hdr *hdr,
			uint64_t *area_offset, uint64_t *area_length)
{
	struct area areas[LUKS2_KEYSLOTS_MAX], sorted_areas[LUKS2_KEYSLOTS_MAX+1] = {};
	int i, j, k, area_i;
	size_t valid_offset, offset, length;

	/* fill area offset + length table */
	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++) {
		if (!LUKS2_keyslot_area(hdr, i, &areas[i].offset, &areas[i].length))
			continue;
		areas[i].length = 0;
		areas[i].offset = 0;
	}

	/* sort table */
	k = 0; /* index in sorted table */
	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++) {
		offset = get_max_offset(hdr) ?: UINT64_MAX;
		area_i = -1;
		/* search for the smallest offset in table */
		for (j = 0; j < LUKS2_KEYSLOTS_MAX; j++)
			if (areas[j].offset && areas[j].offset <= offset) {
				area_i = j;
				offset = areas[j].offset;
			}

		if (area_i >= 0) {
			sorted_areas[k].length = areas[area_i].length;
			sorted_areas[k].offset = areas[area_i].offset;
			areas[area_i].length = 0;
			areas[area_i].offset = 0;
			k++;
		}
	}

	sorted_areas[LUKS2_KEYSLOTS_MAX].offset = get_max_offset(hdr);
	sorted_areas[LUKS2_KEYSLOTS_MAX].length = 1;

	/* search for the gap we can use */
	length = valid_offset = 0;
	offset = get_min_offset(hdr);
	for (i = 0; i < LUKS2_KEYSLOTS_MAX+1; i++) {
		/* skip empty */
		if (sorted_areas[i].offset == 0 || sorted_areas[i].length == 0)
			continue;

		/* found bigger gap than the last one */
		if ((offset < sorted_areas[i].offset) && (sorted_areas[i].offset - offset) > length) {
			length = sorted_areas[i].offset - offset;
			valid_offset = offset;
		}

		/* move beyond allocated area */
		offset = sorted_areas[i].offset + sorted_areas[i].length;
	}

	/* this search 'algorithm' does not work with unaligned areas */
	assert(length == size_round_up(length, 4096));
	assert(valid_offset == size_round_up(valid_offset, 4096));

	if (!length) {
		log_dbg(cd, "Not enough space in header keyslot area.");
		return -EINVAL;
	}

	log_dbg(cd, "Found largest free area %zu -> %zu", valid_offset, length + valid_offset);

	*area_offset = valid_offset;
	*area_length = length;

	return 0;
}

int LUKS2_find_area_gap(struct crypt_device *cd, struct luks2_hdr *hdr,
			size_t keylength, uint64_t *area_offset, uint64_t *area_length)
{
	struct area areas[LUKS2_KEYSLOTS_MAX], sorted_areas[LUKS2_KEYSLOTS_MAX] = {};
	int i, j, k, area_i;
	size_t offset, length;

	/* fill area offset + length table */
	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++) {
		if (!LUKS2_keyslot_area(hdr, i, &areas[i].offset, &areas[i].length))
			continue;
		areas[i].length = 0;
		areas[i].offset = 0;
	}

	/* sort table */
	k = 0; /* index in sorted table */
	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++) {
		offset = get_max_offset(hdr) ?: UINT64_MAX;
		area_i = -1;
		/* search for the smallest offset in table */
		for (j = 0; j < LUKS2_KEYSLOTS_MAX; j++)
			if (areas[j].offset && areas[j].offset <= offset) {
				area_i = j;
				offset = areas[j].offset;
			}

		if (area_i >= 0) {
			sorted_areas[k].length = areas[area_i].length;
			sorted_areas[k].offset = areas[area_i].offset;
			areas[area_i].length = 0;
			areas[area_i].offset = 0;
			k++;
		}
	}

	/* search for the gap we can use */
	offset = get_min_offset(hdr);
	length = get_area_size(keylength);
	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++) {
		/* skip empty */
		if (sorted_areas[i].offset == 0 || sorted_areas[i].length == 0)
			continue;

		/* enough space before the used area */
		if ((offset < sorted_areas[i].offset) && ((offset + length) <= sorted_areas[i].offset))
			break;

		/* both offset and length are already aligned to 4096 bytes */
		offset = sorted_areas[i].offset + sorted_areas[i].length;
	}

	if ((offset + length) > get_max_offset(hdr)) {
		log_dbg(cd, "Not enough space in header keyslot area.");
		return -EINVAL;
	}

	log_dbg(cd, "Found area %zu -> %zu", offset, length + offset);

	if (area_offset)
		*area_offset = offset;
	if (area_length)
		*area_length = length;

	return 0;
}

int LUKS2_check_metadata_area_size(uint64_t metadata_size)
{
	/* see LUKS2_HDR2_OFFSETS */
	return (metadata_size != 0x004000 &&
		metadata_size != 0x008000 && metadata_size != 0x010000 &&
		metadata_size != 0x020000 && metadata_size != 0x040000 &&
		metadata_size != 0x080000 && metadata_size != 0x100000 &&
		metadata_size != 0x200000 && metadata_size != 0x400000);
}

int LUKS2_check_keyslots_area_size(uint64_t keyslots_size)
{
	return (MISALIGNED_4K(keyslots_size) ||
		keyslots_size > LUKS2_MAX_KEYSLOTS_SIZE);
}

int LUKS2_generate_hdr(
	struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const struct volume_key *vk,
	const char *cipher_spec,
	const char *integrity,
	uint32_t integrity_key_size, /* in bytes, only if separate (HMAC) */
	const char *uuid,
	unsigned int sector_size,  /* in bytes */
	uint64_t data_offset,      /* in bytes */
	uint64_t metadata_size_bytes,
	uint64_t keyslots_size_bytes,
	uint64_t device_size_bytes,
	uint32_t opal_segment_number,
	uint32_t opal_key_size)
{
	struct json_object *jobj_segment, *jobj_keyslots, *jobj_segments, *jobj_config;
	uuid_t partitionUuid;
	int r, digest;

	assert(cipher_spec || (opal_key_size > 0 && device_size_bytes));

	hdr->hdr_size = metadata_size_bytes;

	log_dbg(cd, "Formatting LUKS2 with JSON metadata area %" PRIu64
		" bytes and keyslots area %" PRIu64 " bytes.",
		metadata_size_bytes - LUKS2_HDR_BIN_LEN, keyslots_size_bytes);

	if (keyslots_size_bytes < (LUKS2_HDR_OFFSET_MAX - 2*LUKS2_HDR_16K_LEN))
		log_std(cd, _("WARNING: keyslots area (%" PRIu64 " bytes) is very small,"
			" available LUKS2 keyslot count is very limited.\n"),
			keyslots_size_bytes);

	hdr->seqid = 1;
	hdr->version = 2;
	memset(hdr->label, 0, LUKS2_LABEL_L);
	strcpy(hdr->checksum_alg, "sha256");
	crypt_random_get(cd, (char*)hdr->salt1, LUKS2_SALT_L, CRYPT_RND_SALT);
	crypt_random_get(cd, (char*)hdr->salt2, LUKS2_SALT_L, CRYPT_RND_SALT);

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(cd, _("Wrong LUKS UUID format provided."));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	uuid_unparse(partitionUuid, hdr->uuid);

	hdr->jobj = json_object_new_object();
	if (!hdr->jobj) {
		r = -ENOMEM;
		goto err;
	}

	jobj_keyslots = json_object_new_object();
	if (!jobj_keyslots) {
		r = -ENOMEM;
		goto err;
	}

	json_object_object_add(hdr->jobj, "keyslots", jobj_keyslots);
	json_object_object_add(hdr->jobj, "tokens", json_object_new_object());
	jobj_segments = json_object_new_object();
	if (!jobj_segments) {
		r = -ENOMEM;
		goto err;
	}

	json_object_object_add(hdr->jobj, "segments", jobj_segments);
	json_object_object_add(hdr->jobj, "digests", json_object_new_object());
	jobj_config = json_object_new_object();
	if (!jobj_config) {
		r = -ENOMEM;
		goto err;
	}

	json_object_object_add(hdr->jobj, "config", jobj_config);

	digest = LUKS2_digest_create(cd, "pbkdf2", hdr, vk);
	if (digest < 0) {
		r = -EINVAL;
		goto err;
	}

	if (LUKS2_digest_segment_assign(cd, hdr, 0, digest, 1, 0) < 0) {
		r = -EINVAL;
		goto err;
	}

	if (!opal_key_size)
		jobj_segment = json_segment_create_crypt(data_offset, 0,
							 NULL, cipher_spec,
							 integrity, integrity_key_size,
							 sector_size, 0);
	else if (opal_key_size && cipher_spec)
		jobj_segment = json_segment_create_opal_crypt(data_offset, &device_size_bytes,
							      opal_segment_number, opal_key_size, 0,
							      cipher_spec, integrity,
							      sector_size, 0);
	else
		jobj_segment = json_segment_create_opal(data_offset, &device_size_bytes,
							opal_segment_number, opal_key_size);

	if (!jobj_segment) {
		r = -EINVAL;
		goto err;
	}

	if (json_object_object_add_by_uint(jobj_segments, 0, jobj_segment)) {
		json_object_put(jobj_segment);
		r = -ENOMEM;
		goto err;
	}

	json_object_object_add(jobj_config, "json_size", crypt_jobj_new_uint64(metadata_size_bytes - LUKS2_HDR_BIN_LEN));
	json_object_object_add(jobj_config, "keyslots_size", crypt_jobj_new_uint64(keyslots_size_bytes));

	JSON_DBG(cd, hdr->jobj, "Header JSON:");
	return 0;
err:
	json_object_put(hdr->jobj);
	hdr->jobj = NULL;
	return r;
}

int LUKS2_wipe_header_areas(struct crypt_device *cd,
	struct luks2_hdr *hdr)
{
	int r;
	uint64_t device_size_bytes, length, offset;
	size_t wipe_block = 1024 * 1024;

	if (!hdr || LUKS2_hdr_validate(cd, hdr->jobj, hdr->hdr_size - LUKS2_HDR_BIN_LEN))
		return -EINVAL;

	r = device_size(crypt_metadata_device(cd), &device_size_bytes);
	if (r < 0)
		return -EINVAL;

	/* Wipe up to maximal allowed metadata size, but do not write beyond data offset. */
	length = LUKS2_get_data_offset(hdr) * SECTOR_SIZE;
	if (!length || length > LUKS2_HDR_MAX_MDA_SIZE)
		length = LUKS2_HDR_MAX_MDA_SIZE;

	/* Also do not extend the device size yet (file backends) */
	if (length > device_size_bytes)
		length = device_size_bytes;

	log_dbg(cd, "Wiping LUKS areas (0x%06" PRIx64 " - 0x%06" PRIx64") with zeroes.",
		0ULL, length);

	r = crypt_wipe_device(cd, crypt_metadata_device(cd), CRYPT_WIPE_ZERO, 0,
			      length, wipe_block, NULL, NULL);
	if (r < 0)
		return r;

	/* Allocate at least actual LUKS2 metadata size */
	r = device_check_size(cd, crypt_metadata_device(cd),
			      LUKS2_hdr_and_areas_size(hdr), 1);
	if (r)
		return r;

	/* Wipe keyslot area */
	offset = get_min_offset(hdr);
	length = LUKS2_keyslots_size(hdr);

	/*
	 * Skip keyslots area wipe in case it is not defined.
	 * Otherwise we would wipe whole data device (length == 0)
	 * starting at offset get_min_offset(hdr).
	 */
	if (!length)
		return 0;

	log_dbg(cd, "Wiping keyslots area (0x%06" PRIx64 " - 0x%06" PRIx64") with random data.",
		offset, length + offset);

	return crypt_wipe_device(cd, crypt_metadata_device(cd), CRYPT_WIPE_RANDOM,
				 offset, length, wipe_block, NULL, NULL);
}

int LUKS2_set_keyslots_size(struct luks2_hdr *hdr, uint64_t data_offset)
{
	json_object *jobj_config;
	uint64_t keyslots_size;

	if (data_offset < get_min_offset(hdr))
		return 1;

	keyslots_size = data_offset - get_min_offset(hdr);

	/* keep keyslots_size reasonable for custom data alignments */
	if (keyslots_size > LUKS2_MAX_KEYSLOTS_SIZE)
		keyslots_size = LUKS2_MAX_KEYSLOTS_SIZE;

	/* keyslots size has to be 4 KiB aligned */
	keyslots_size -= (keyslots_size % 4096);

	if (!json_object_object_get_ex(hdr->jobj, "config", &jobj_config))
		return 1;

	json_object_object_add(jobj_config, "keyslots_size", crypt_jobj_new_uint64(keyslots_size));
	return 0;
}

int LUKS2_hdr_get_storage_params(struct crypt_device *cd,
			    uint64_t alignment_offset_bytes,
			    uint64_t alignment_bytes,
			    uint64_t *ret_metadata_size_bytes,
			    uint64_t *ret_keyslots_size_bytes,
			    uint64_t *ret_data_offset_bytes)
{
	uint64_t data_offset_bytes, keyslots_size_bytes, metadata_size_bytes, mdev_size_bytes;

	assert(cd);
	assert(ret_metadata_size_bytes);
	assert(ret_keyslots_size_bytes);
	assert(ret_data_offset_bytes);

	metadata_size_bytes = crypt_get_metadata_size_bytes(cd);
	keyslots_size_bytes = crypt_get_keyslots_size_bytes(cd);
	data_offset_bytes = crypt_get_data_offset_sectors(cd) * SECTOR_SIZE;

	if (!metadata_size_bytes)
		metadata_size_bytes = LUKS2_HDR_16K_LEN;

	if (data_offset_bytes && data_offset_bytes < 2 * metadata_size_bytes) {
		log_err(cd, _("Requested data offset is too small."));
		return -EINVAL;
	}

	/* Increase keyslot size according to data offset */
	if (!keyslots_size_bytes && data_offset_bytes)
		keyslots_size_bytes = data_offset_bytes - 2 * metadata_size_bytes;

	/* keyslots size has to be 4 KiB aligned */
	keyslots_size_bytes -= (keyslots_size_bytes % 4096);

	if (keyslots_size_bytes > LUKS2_MAX_KEYSLOTS_SIZE)
		keyslots_size_bytes = LUKS2_MAX_KEYSLOTS_SIZE;

	if (!keyslots_size_bytes) {
		assert(LUKS2_DEFAULT_HDR_SIZE > 2 * LUKS2_HDR_OFFSET_MAX);
		keyslots_size_bytes = LUKS2_DEFAULT_HDR_SIZE - 2 * metadata_size_bytes;
		/* Decrease keyslots_size due to metadata device being too small */
		if (!device_size(crypt_metadata_device(cd), &mdev_size_bytes) &&
		    ((keyslots_size_bytes + 2 * metadata_size_bytes) > mdev_size_bytes) &&
		    device_fallocate(crypt_metadata_device(cd), keyslots_size_bytes + 2 * metadata_size_bytes) &&
		    ((2 * metadata_size_bytes) <= mdev_size_bytes))
			keyslots_size_bytes = mdev_size_bytes - 2 * metadata_size_bytes;
	}

	/* Decrease keyslots_size if we have smaller data_offset */
	if (data_offset_bytes && (keyslots_size_bytes + 2 * metadata_size_bytes) > data_offset_bytes) {
		keyslots_size_bytes = data_offset_bytes - 2 * metadata_size_bytes;
		log_dbg(cd, "Decreasing keyslot area size to %" PRIu64
			" bytes due to the requested data offset %"
			PRIu64 " bytes.", keyslots_size_bytes, data_offset_bytes);
	}

	/* Data offset has priority */
	if (!data_offset_bytes && alignment_bytes) {
		data_offset_bytes = size_round_up(2 * metadata_size_bytes + keyslots_size_bytes,
					    (size_t)alignment_bytes);
		data_offset_bytes += alignment_offset_bytes;
	}

	if (crypt_get_metadata_size_bytes(cd) && (crypt_get_metadata_size_bytes(cd) != metadata_size_bytes))
		log_std(cd, _("WARNING: LUKS2 metadata size changed to %" PRIu64 " bytes.\n"),
			metadata_size_bytes);

	if (crypt_get_keyslots_size_bytes(cd) && (crypt_get_keyslots_size_bytes(cd) != keyslots_size_bytes))
		log_std(cd, _("WARNING: LUKS2 keyslots area size changed to %" PRIu64 " bytes.\n"),
			keyslots_size_bytes);

	*ret_metadata_size_bytes = metadata_size_bytes;
	*ret_keyslots_size_bytes = keyslots_size_bytes;
	*ret_data_offset_bytes = data_offset_bytes;

	return 0;
}
