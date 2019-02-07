/*
 * LUKS - Linux Unified Key Setup v2, LUKS2 header format code
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
#include <uuid/uuid.h>
#include <assert.h>

struct area {
	uint64_t offset;
	uint64_t length;
};

static size_t get_area_size(size_t keylength)
{
	//FIXME: calculate this properly, for now it is AF_split_sectors
	return size_round_up(keylength * 4000, 4096);
}

static size_t get_min_offset(struct luks2_hdr *hdr)
{
	return 2 * hdr->hdr_size;
}

static size_t get_max_offset(struct crypt_device *cd)
{
	return crypt_get_data_offset(cd) * SECTOR_SIZE;
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
		offset = get_max_offset(cd) ?: UINT64_MAX;
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

	if (get_max_offset(cd) && (offset + length) > get_max_offset(cd)) {
		log_err(cd, _("No space for new keyslot."));
		return -EINVAL;
	}

	log_dbg(cd, "Found area %zu -> %zu", offset, length + offset);
/*
	log_dbg("Area offset min: %zu, max %zu, slots max %u",
	       get_min_offset(hdr), get_max_offset(cd), LUKS2_KEYSLOTS_MAX);
	for (i = 0; i < LUKS2_KEYSLOTS_MAX; i++)
		log_dbg("SLOT[%02i]: %-8" PRIu64 " -> %-8" PRIu64, i,
			sorted_areas[i].offset,
			sorted_areas[i].length + sorted_areas[i].offset);
*/
	*area_offset = offset;
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
	const char *cipherName,
	const char *cipherMode,
	const char *integrity,
	const char *uuid,
	unsigned int sector_size,  /* in bytes */
	uint64_t data_offset,      /* in bytes */
	uint64_t align_offset,     /* in bytes */
	uint64_t required_alignment,
	uint64_t metadata_size,
	uint64_t keyslots_size)
{
	struct json_object *jobj_segment, *jobj_integrity, *jobj_keyslots, *jobj_segments, *jobj_config;
	char cipher[128];
	uuid_t partitionUuid;
	int digest;

	if (!metadata_size)
		metadata_size = LUKS2_HDR_16K_LEN;
	hdr->hdr_size = metadata_size;

	if (data_offset && data_offset < get_min_offset(hdr)) {
		log_err(cd, _("Requested data offset is too small."));
		return -EINVAL;
	}

	/* Increase keyslot size according to data offset */
	if (!keyslots_size && data_offset)
		keyslots_size = data_offset - get_min_offset(hdr);

	/* keyslots size has to be 4 KiB aligned */
	keyslots_size -= (keyslots_size % 4096);

	if (keyslots_size > LUKS2_MAX_KEYSLOTS_SIZE)
		keyslots_size = LUKS2_MAX_KEYSLOTS_SIZE;

	if (!keyslots_size) {
		assert(LUKS2_DEFAULT_HDR_SIZE > 2 * LUKS2_HDR_OFFSET_MAX);
		keyslots_size = LUKS2_DEFAULT_HDR_SIZE - get_min_offset(hdr);
	}

	/* Decrease keyslots_size if we have smaller data_offset */
	if (data_offset && (keyslots_size + get_min_offset(hdr)) > data_offset) {
		keyslots_size = data_offset - get_min_offset(hdr);
		log_dbg(cd, "Decreasing keyslot area size to %" PRIu64
			" bytes due to the requested data offset %"
			PRIu64 " bytes.", keyslots_size, data_offset);
	}

	/* Data offset has priority */
	if (!data_offset && required_alignment) {
		data_offset = size_round_up(get_min_offset(hdr) + keyslots_size,
					    (size_t)required_alignment);
		data_offset += align_offset;
	}

	log_dbg(cd, "Formatting LUKS2 with JSON metadata area %" PRIu64
		" bytes and keyslots area %" PRIu64 " bytes.",
		metadata_size - LUKS2_HDR_BIN_LEN, keyslots_size);

	if (keyslots_size < (LUKS2_HDR_OFFSET_MAX - 2*LUKS2_HDR_16K_LEN))
		log_std(cd, _("WARNING: keyslots area (%" PRIu64 " bytes) is very small,"
			" available LUKS2 keyslot count is very limited.\n"),
			keyslots_size);

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

	if (*cipherMode != '\0')
		snprintf(cipher, sizeof(cipher), "%s-%s", cipherName, cipherMode);
	else
		snprintf(cipher, sizeof(cipher), "%s", cipherName);

	hdr->jobj = json_object_new_object();

	jobj_keyslots = json_object_new_object();
	json_object_object_add(hdr->jobj, "keyslots", jobj_keyslots);
	json_object_object_add(hdr->jobj, "tokens", json_object_new_object());
	jobj_segments = json_object_new_object();
	json_object_object_add(hdr->jobj, "segments", jobj_segments);
	json_object_object_add(hdr->jobj, "digests", json_object_new_object());
	jobj_config = json_object_new_object();
	json_object_object_add(hdr->jobj, "config", jobj_config);

	digest = LUKS2_digest_create(cd, "pbkdf2", hdr, vk);
	if (digest < 0) {
		json_object_put(hdr->jobj);
		hdr->jobj = NULL;
		return -EINVAL;
	}

	if (LUKS2_digest_segment_assign(cd, hdr, CRYPT_DEFAULT_SEGMENT, digest, 1, 0) < 0) {
		json_object_put(hdr->jobj);
		hdr->jobj = NULL;
		return -EINVAL;
	}

	jobj_segment = json_object_new_object();
	json_object_object_add(jobj_segment, "type", json_object_new_string("crypt"));
	json_object_object_add(jobj_segment, "offset", json_object_new_uint64(data_offset));
	json_object_object_add(jobj_segment, "iv_tweak", json_object_new_string("0"));
	json_object_object_add(jobj_segment, "size", json_object_new_string("dynamic"));
	json_object_object_add(jobj_segment, "encryption", json_object_new_string(cipher));
	json_object_object_add(jobj_segment, "sector_size", json_object_new_int(sector_size));

	if (integrity) {
		jobj_integrity = json_object_new_object();
		json_object_object_add(jobj_integrity, "type", json_object_new_string(integrity));
		json_object_object_add(jobj_integrity, "journal_encryption", json_object_new_string("none"));
		json_object_object_add(jobj_integrity, "journal_integrity", json_object_new_string("none"));
		json_object_object_add(jobj_segment, "integrity", jobj_integrity);
	}

	json_object_object_add_by_uint(jobj_segments, CRYPT_DEFAULT_SEGMENT, jobj_segment);

	json_object_object_add(jobj_config, "json_size", json_object_new_uint64(metadata_size - LUKS2_HDR_BIN_LEN));
	json_object_object_add(jobj_config, "keyslots_size", json_object_new_uint64(keyslots_size));

	JSON_DBG(cd, hdr->jobj, "Header JSON:");
	return 0;
}

int LUKS2_wipe_header_areas(struct crypt_device *cd,
	struct luks2_hdr *hdr)
{
	int r;
	uint64_t offset, length;
	size_t wipe_block;

	/* Wipe complete header, keyslots and padding areas with zeroes. */
	offset = 0;
	length = LUKS2_get_data_offset(hdr) * SECTOR_SIZE;
	wipe_block = 1024 * 1024;

	if (LUKS2_hdr_validate(cd, hdr->jobj, hdr->hdr_size - LUKS2_HDR_BIN_LEN))
		return -EINVAL;

	/* On detached header wipe at least the first 4k */
	if (length == 0) {
		length = 4096;
		wipe_block = 4096;
	}

	log_dbg(cd, "Wiping LUKS areas (0x%06" PRIx64 " - 0x%06" PRIx64") with zeroes.",
		offset, length + offset);

	r = crypt_wipe_device(cd, crypt_metadata_device(cd), CRYPT_WIPE_ZERO,
			      offset, length, wipe_block, NULL, NULL);
	if (r < 0)
		return r;

	/* Wipe keyslot area */
	wipe_block = 1024 * 1024;
	offset = get_min_offset(hdr);
	length = LUKS2_keyslots_size(hdr->jobj);

	log_dbg(cd, "Wiping keyslots area (0x%06" PRIx64 " - 0x%06" PRIx64") with random data.",
		offset, length + offset);

	return crypt_wipe_device(cd, crypt_metadata_device(cd), CRYPT_WIPE_RANDOM,
				 offset, length, wipe_block, NULL, NULL);
}
