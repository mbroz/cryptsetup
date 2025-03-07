// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup v2
 *
 * Copyright (C) 2015-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2025 Milan Broz
 */

#include "luks2_internal.h"

/*
 * Helper functions
 */
static json_object *parse_json_len(struct crypt_device *cd, const char *json_area,
			    uint64_t max_length, int *json_len)
{
	json_object *jobj;
	struct json_tokener *jtok;

	 /* INT32_MAX is internal (json-c) json_tokener_parse_ex() limit */
	if (!json_area || max_length > INT32_MAX)
		return NULL;

	jtok = json_tokener_new();
	if (!jtok) {
		log_dbg(cd, "ERROR: Failed to init json tokener");
		return NULL;
	}

	jobj = json_tokener_parse_ex(jtok, json_area, max_length);
	if (!jobj)
		log_dbg(cd, "ERROR: Failed to parse json data (%d): %s",
			json_tokener_get_error(jtok),
			json_tokener_error_desc(json_tokener_get_error(jtok)));
	else
		*json_len = jtok->char_offset;

	json_tokener_free(jtok);

	return jobj;
}

static void log_dbg_checksum(struct crypt_device *cd,
			     const uint8_t *csum, const char *csum_alg, const char *info)
{
	char csum_txt[2*LUKS2_CHECKSUM_L+1];
	int i;

	for (i = 0; i < crypt_hash_size(csum_alg); i++)
		if (snprintf(&csum_txt[i*2], 3, "%02hhx", (const char)csum[i]) != 2)
			return;

	log_dbg(cd, "Checksum:%s (%s)", &csum_txt[0], info);
}

/*
 * Calculate hash (checksum) of |LUKS2_bin|LUKS2_JSON_area| from in-memory structs.
 * LUKS2 on-disk header contains uniques salt both for primary and secondary header.
 * Checksum is always calculated with zeroed checksum field in binary header.
 */
static int hdr_checksum_calculate(const char *alg, struct luks2_hdr_disk *hdr_disk,
				  const char *json_area, size_t json_len)
{
	struct crypt_hash *hd = NULL;
	int hash_size, r;

	hash_size = crypt_hash_size(alg);
	if (hash_size <= 0 || crypt_hash_init(&hd, alg))
		return -EINVAL;

	/* Binary header, csum zeroed. */
	r = crypt_hash_write(hd, (char*)hdr_disk, LUKS2_HDR_BIN_LEN);

	/* JSON area (including unused space) */
	if (!r)
		r = crypt_hash_write(hd, json_area, json_len);

	if (!r)
		r = crypt_hash_final(hd, (char*)hdr_disk->csum, (size_t)hash_size);

	crypt_hash_destroy(hd);
	return r;
}

/*
 * Compare hash (checksum) of on-disk and in-memory header.
 */
static int hdr_checksum_check(struct crypt_device *cd,
			      const char *alg, struct luks2_hdr_disk *hdr_disk,
			      const char *json_area, size_t json_len)
{
	struct luks2_hdr_disk hdr_tmp;
	int hash_size, r;

	hash_size = crypt_hash_size(alg);
	if (hash_size <= 0)
		return -EINVAL;

	/* Copy header and zero checksum. */
	memcpy(&hdr_tmp, hdr_disk, LUKS2_HDR_BIN_LEN);
	memset(&hdr_tmp.csum, 0, sizeof(hdr_tmp.csum));

	r = hdr_checksum_calculate(alg, &hdr_tmp, json_area, json_len);
	if (r < 0)
		return r;

	log_dbg_checksum(cd, hdr_disk->csum, alg, "on-disk");
	log_dbg_checksum(cd, hdr_tmp.csum, alg, "in-memory");

	if (memcmp(hdr_tmp.csum, hdr_disk->csum, (size_t)hash_size))
		return -EINVAL;

	return 0;
}

/*
 * Convert header from on-disk format to in-memory struct
 */
static void hdr_from_disk(struct luks2_hdr_disk *hdr_disk1,
			  struct luks2_hdr_disk *hdr_disk2,
			  struct luks2_hdr *hdr,
			  int secondary)
{
	hdr->version  = be16_to_cpu(hdr_disk1->version);
	hdr->hdr_size = be64_to_cpu(hdr_disk1->hdr_size);
	hdr->seqid    = be64_to_cpu(hdr_disk1->seqid);

	memcpy(hdr->label, hdr_disk1->label, LUKS2_LABEL_L);
	hdr->label[LUKS2_LABEL_L - 1] = '\0';
	memcpy(hdr->subsystem, hdr_disk1->subsystem, LUKS2_LABEL_L);
	hdr->subsystem[LUKS2_LABEL_L - 1] = '\0';
	memcpy(hdr->checksum_alg, hdr_disk1->checksum_alg, LUKS2_CHECKSUM_ALG_L);
	hdr->checksum_alg[LUKS2_CHECKSUM_ALG_L - 1] = '\0';
	memcpy(hdr->uuid, hdr_disk1->uuid, LUKS2_UUID_L);
	hdr->uuid[LUKS2_UUID_L - 1] = '\0';

	if (secondary) {
		memcpy(hdr->salt1, hdr_disk2->salt, LUKS2_SALT_L);
		memcpy(hdr->salt2, hdr_disk1->salt, LUKS2_SALT_L);
	} else {
		memcpy(hdr->salt1, hdr_disk1->salt, LUKS2_SALT_L);
		memcpy(hdr->salt2, hdr_disk2->salt, LUKS2_SALT_L);
	}
}

/*
 * Convert header from in-memory struct to on-disk format
 */
static void hdr_to_disk(struct luks2_hdr *hdr,
			struct luks2_hdr_disk *hdr_disk,
			int secondary, uint64_t offset)
{
	assert(((char*)&(hdr_disk->_padding4096) - (char*)&(hdr_disk->magic)) == 512);

	memset(hdr_disk, 0, LUKS2_HDR_BIN_LEN);

	memcpy(&hdr_disk->magic, secondary ? LUKS2_MAGIC_2ND : LUKS2_MAGIC_1ST, LUKS2_MAGIC_L);
	hdr_disk->version     = cpu_to_be16(hdr->version);
	hdr_disk->hdr_size    = cpu_to_be64(hdr->hdr_size);
	hdr_disk->hdr_offset  = cpu_to_be64(offset);
	hdr_disk->seqid       = cpu_to_be64(hdr->seqid);

	memcpy(hdr_disk->label, hdr->label, MIN(strlen(hdr->label), LUKS2_LABEL_L));
	hdr_disk->label[LUKS2_LABEL_L - 1] = '\0';
	memcpy(hdr_disk->subsystem, hdr->subsystem, MIN(strlen(hdr->subsystem), LUKS2_LABEL_L));
	hdr_disk->subsystem[LUKS2_LABEL_L - 1] = '\0';
	memcpy(hdr_disk->checksum_alg, hdr->checksum_alg, MIN(strlen(hdr->checksum_alg), LUKS2_CHECKSUM_ALG_L));
	hdr_disk->checksum_alg[LUKS2_CHECKSUM_ALG_L - 1] = '\0';
	memcpy(hdr_disk->uuid, hdr->uuid, MIN(strlen(hdr->uuid), LUKS2_UUID_L));
	hdr_disk->uuid[LUKS2_UUID_L - 1] = '\0';

	memcpy(hdr_disk->salt, secondary ? hdr->salt2 : hdr->salt1, LUKS2_SALT_L);
}

/*
 * Sanity checks before checksum is validated
 */
static int hdr_disk_sanity_check_pre(struct crypt_device *cd,
				     struct luks2_hdr_disk *hdr,
				     size_t *hdr_json_size, int secondary,
				     uint64_t offset)
{
	uint64_t hdr_size;

	if (memcmp(hdr->magic, secondary ? LUKS2_MAGIC_2ND : LUKS2_MAGIC_1ST, LUKS2_MAGIC_L))
		return -EINVAL;

	if (be16_to_cpu(hdr->version) != 2) {
		log_dbg(cd, "Unsupported LUKS2 header version %u.", be16_to_cpu(hdr->version));
		return -EINVAL;
	}

	if (offset != be64_to_cpu(hdr->hdr_offset)) {
		log_dbg(cd, "LUKS2 offset 0x%04" PRIx64 " on device differs to expected offset 0x%04" PRIx64 ".",
			be64_to_cpu(hdr->hdr_offset), offset);
		return -EINVAL;
	}

	hdr_size = be64_to_cpu(hdr->hdr_size);

	if (hdr_size < LUKS2_HDR_16K_LEN || hdr_size > LUKS2_HDR_OFFSET_MAX) {
		log_dbg(cd, "LUKS2 header has bogus size 0x%04" PRIx64 ".", hdr_size);
		return -EINVAL;
	}

	if (secondary && (offset != hdr_size)) {
		log_dbg(cd, "LUKS2 offset 0x%04" PRIx64 " in secondary header does not match size 0x%04" PRIx64 ".",
			offset, hdr_size);
		return -EINVAL;
	}

	/* FIXME: sanity check checksum alg. */

	log_dbg(cd, "LUKS2 header version %u of size %" PRIu64 " bytes, checksum %s.",
		be16_to_cpu(hdr->version), hdr_size,
		hdr->checksum_alg);

	*hdr_json_size = hdr_size - LUKS2_HDR_BIN_LEN;
	return 0;
}

/*
 * Read LUKS2 header from disk at specific offset.
 */
static int hdr_read_disk(struct crypt_device *cd,
			 struct device *device, struct luks2_hdr_disk *hdr_disk,
			 char **json_area, uint64_t offset, int secondary)
{
	size_t hdr_json_size = 0;
	int devfd, r;

	log_dbg(cd, "Trying to read %s LUKS2 header at offset 0x%" PRIx64 ".",
		secondary ? "secondary" : "primary", offset);

	devfd = device_open_locked(cd, device, O_RDONLY);
	if (devfd < 0)
		return devfd == -1 ? -EIO : devfd;

	/*
	 * Read binary header and run sanity check before reading
	 * JSON area and validating checksum.
	 */
	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
				 device_alignment(device), hdr_disk,
				 LUKS2_HDR_BIN_LEN, offset) != LUKS2_HDR_BIN_LEN) {
		memset(hdr_disk, 0, LUKS2_HDR_BIN_LEN);
		return -EIO;
	}

	/*
	 * hdr_json_size is validated if this call succeeds
	 */
	r = hdr_disk_sanity_check_pre(cd, hdr_disk, &hdr_json_size, secondary, offset);
	if (r < 0)
		return r;

	/*
	 * Allocate and read JSON area. Always the whole area must be read.
	 */
	*json_area = malloc(hdr_json_size);
	if (!*json_area)
		return -ENOMEM;

	if (read_lseek_blockwise(devfd, device_block_size(cd, device),
				 device_alignment(device), *json_area, hdr_json_size,
				 offset + LUKS2_HDR_BIN_LEN) != (ssize_t)hdr_json_size) {
		free(*json_area);
		*json_area = NULL;
		return -EIO;
	}

	/*
	 * Calculate and validate checksum and zero it afterwards.
	 */
	if (hdr_checksum_check(cd, hdr_disk->checksum_alg, hdr_disk,
				*json_area, hdr_json_size)) {
		log_dbg(cd, "LUKS2 header checksum error (offset %" PRIu64 ").", offset);
		free(*json_area);
		*json_area = NULL;
		r = -EINVAL;
	}
	memset(hdr_disk->csum, 0, LUKS2_CHECKSUM_L);

	return r;
}

/*
 * Write LUKS2 header to disk at specific offset.
 */
static int hdr_write_disk(struct crypt_device *cd,
			  struct device *device, struct luks2_hdr *hdr,
			  const char *json_area, int secondary)
{
	struct luks2_hdr_disk hdr_disk;
	uint64_t offset = secondary ? hdr->hdr_size : 0;
	size_t hdr_json_len;
	int devfd, r;

	log_dbg(cd, "Trying to write LUKS2 header (%zu bytes) at offset %" PRIu64 ".",
		hdr->hdr_size, offset);

	devfd = device_open_locked(cd, device, O_RDWR);
	if (devfd < 0)
		return devfd == -1 ? -EINVAL : devfd;

	hdr_json_len = hdr->hdr_size - LUKS2_HDR_BIN_LEN;

	hdr_to_disk(hdr, &hdr_disk, secondary, offset);

	/*
	 * Write header without checksum but with proper seqid.
	 */
	if (write_lseek_blockwise(devfd, device_block_size(cd, device),
				  device_alignment(device), (char *)&hdr_disk,
				  LUKS2_HDR_BIN_LEN, offset) < (ssize_t)LUKS2_HDR_BIN_LEN) {
		return -EIO;
	}

	/*
	 * Write json area.
	 */
	if (write_lseek_blockwise(devfd, device_block_size(cd, device),
				  device_alignment(device),
				  CONST_CAST(char*)json_area, hdr_json_len,
				  LUKS2_HDR_BIN_LEN + offset) < (ssize_t)hdr_json_len) {
		return -EIO;
	}

	/*
	 * Calculate checksum and write header with checksum.
	 */
	r = hdr_checksum_calculate(hdr_disk.checksum_alg, &hdr_disk,
				   json_area, hdr_json_len);
	if (r < 0) {
		return r;
	}
	log_dbg_checksum(cd, hdr_disk.csum, hdr_disk.checksum_alg, "in-memory");

	if (write_lseek_blockwise(devfd, device_block_size(cd, device),
				  device_alignment(device), (char *)&hdr_disk,
				  LUKS2_HDR_BIN_LEN, offset) < (ssize_t)LUKS2_HDR_BIN_LEN)
		r = -EIO;

	device_sync(cd, device);
	return r;
}

static int LUKS2_check_sequence_id(struct crypt_device *cd, struct luks2_hdr *hdr, struct device *device)
{
	int devfd;
	struct luks2_hdr_disk dhdr;

	if (!hdr)
		return -EINVAL;

	devfd = device_open_locked(cd, device, O_RDONLY);
	if (devfd < 0)
		return devfd == -1 ? -EINVAL : devfd;

	/* we need only first 512 bytes, see luks2_hdr_disk structure */
	if ((read_lseek_blockwise(devfd, device_block_size(cd, device),
	     device_alignment(device), &dhdr, 512, 0) != 512))
		return -EIO;

	/* there's nothing to check if there's no LUKS2 header */
	if ((be16_to_cpu(dhdr.version) != 2) ||
	    memcmp(dhdr.magic, LUKS2_MAGIC_1ST, LUKS2_MAGIC_L) ||
	    strcmp(dhdr.uuid, hdr->uuid))
		return 0;

	return hdr->seqid != be64_to_cpu(dhdr.seqid);
}

int LUKS2_device_write_lock(struct crypt_device *cd, struct luks2_hdr *hdr, struct device *device)
{
	int r = device_write_lock(cd, device);

	if (r < 0) {
		log_err(cd, _("Failed to acquire write lock on device %s."), device_path(device));
		return r;
	}

	/* run sequence id check only on first write lock (r == 1) and w/o LUKS2 reencryption in-progress */
	if (r == 1 && !crypt_get_luks2_reencrypt(cd)) {
		log_dbg(cd, "Checking context sequence id matches value stored on disk.");
		if (LUKS2_check_sequence_id(cd, hdr, device)) {
			device_write_unlock(cd, device);
			log_err(cd, _("Detected attempt for concurrent LUKS2 metadata update. Aborting operation."));
			return -EINVAL;
		}
	}

	return 0;
}

/*
 * Convert in-memory LUKS2 header and write it to disk.
 * This will increase sequence id, write both header copies and calculate checksum.
 */
int LUKS2_disk_hdr_write(struct crypt_device *cd, struct luks2_hdr *hdr, struct device *device, bool seqid_check)
{
	char *json_area;
	const char *json_text;
	size_t json_area_len;
	int r;

	if (hdr->version != 2) {
		log_dbg(cd, "Unsupported LUKS2 header version (%u).", hdr->version);
		return -EINVAL;
	}

	r = device_check_size(cd, crypt_metadata_device(cd), LUKS2_hdr_and_areas_size(hdr), 1);
	if (r)
		return r;

	/*
	 * Allocate and zero JSON area (of proper header size).
	 */
	json_area_len = hdr->hdr_size - LUKS2_HDR_BIN_LEN;
	json_area = crypt_zalloc(json_area_len);
	if (!json_area)
		return -ENOMEM;

	/*
	 * Generate text space-efficient JSON representation to json area.
	 */
	json_text = crypt_jobj_to_string_on_disk(hdr->jobj);
	if (!json_text || !*json_text) {
		log_dbg(cd, "Cannot parse JSON object to text representation.");
		free(json_area);
		return -ENOMEM;
	}
	if (strlen(json_text) > (json_area_len - 1)) {
		log_dbg(cd, "JSON is too large (%zu > %zu).", strlen(json_text), json_area_len);
		free(json_area);
		return -EINVAL;
	}
	strncpy(json_area, json_text, json_area_len);

	if (seqid_check)
		r = LUKS2_device_write_lock(cd, hdr, device);
	else
		r = device_write_lock(cd, device);
	if (r < 0) {
		free(json_area);
		return r;
	}

	/* Increase sequence id before writing it to disk. */
	hdr->seqid++;

	/* Write primary and secondary header */
	r = hdr_write_disk(cd, device, hdr, json_area, 0);
	if (!r)
		r = hdr_write_disk(cd, device, hdr, json_area, 1);

	if (r)
		log_dbg(cd, "LUKS2 header write failed (%d).", r);

	device_write_unlock(cd, device);

	free(json_area);
	return r;
}
static int validate_json_area(struct crypt_device *cd, const char *json_area,
			      uint64_t json_len, uint64_t max_length)
{
	char c;

	/* Enforce there are no needless opening bytes */
	if (*json_area != '{') {
		log_dbg(cd, "ERROR: Opening character must be left curly bracket: '{'.");
		return -EINVAL;
	}

	if (json_len >= max_length) {
		log_dbg(cd, "ERROR: Missing trailing null byte beyond parsed json data string.");
		return -EINVAL;
	}

	/*
	 * TODO:
	 *	validate there are legal json format characters between
	 *	'json_area' and 'json_area + json_len'
	 */

	do {
		c = *(json_area + json_len);
		if (c != '\0') {
			log_dbg(cd, "ERROR: Forbidden ascii code 0x%02hhx found beyond json data string at offset %" PRIu64,
				c, json_len);
			return -EINVAL;
		}
	} while (++json_len < max_length);

	return 0;
}

static int validate_luks2_json_object(struct crypt_device *cd, json_object *jobj_hdr, uint64_t length)
{
	int r;

	/* we require top level object to be of json_type_object */
	r = !json_object_is_type(jobj_hdr, json_type_object);
	if (r) {
		log_dbg(cd, "ERROR: Resulting object is not a json object type");
		return r;
	}

	r = LUKS2_hdr_validate(cd, jobj_hdr, length);
	if (r) {
		log_dbg(cd, "Repairing JSON metadata.");
		/* try to correct known glitches */
		LUKS2_hdr_repair(cd, jobj_hdr);

		/* run validation again */
		r = LUKS2_hdr_validate(cd, jobj_hdr, length);
	}

	if (r)
		log_dbg(cd, "ERROR: LUKS2 validation failed");

	return r;
}

static json_object *parse_and_validate_json(struct crypt_device *cd,
					    const char *json_area, uint64_t hdr_size)
{
	int json_len, r;
	json_object *jobj;
	uint64_t max_length;

	if (hdr_size <= LUKS2_HDR_BIN_LEN || hdr_size > LUKS2_HDR_OFFSET_MAX) {
		log_dbg(cd, "LUKS2 header JSON has bogus size 0x%04" PRIx64 ".", hdr_size);
		return NULL;
	}

	max_length = hdr_size - LUKS2_HDR_BIN_LEN;

	jobj = parse_json_len(cd, json_area, max_length, &json_len);
	if (!jobj)
		return NULL;

	/* successful parse_json_len must not return offset <= 0 */
	assert(json_len > 0);

	r = validate_json_area(cd, json_area, json_len, max_length);
	if (!r)
		r = validate_luks2_json_object(cd, jobj, max_length);

	if (r) {
		json_object_put(jobj);
		jobj = NULL;
	}

	return jobj;
}

static int detect_device_signatures(struct crypt_device *cd, const char *path)
{
	blk_probe_status prb_state;
	int r;
	struct blkid_handle *h;

	if (!blk_supported()) {
		log_dbg(cd, "Blkid probing of device signatures disabled.");
		return 0;
	}

	if ((r = blk_init_by_path(&h, path))) {
		log_dbg(cd, "Failed to initialize blkid_handle by path.");
		return -EINVAL;
	}

	/* We don't care about details. Be fast. */
	blk_set_chains_for_fast_detection(h);

	/* Filter out crypto_LUKS. we don't care now */
	blk_superblocks_filter_luks(h);

	prb_state = blk_safeprobe(h);

	switch (prb_state) {
	case PRB_AMBIGUOUS:
		log_dbg(cd, "Blkid probe couldn't decide device type unambiguously.");
		/* fall through */
	case PRB_FAIL:
		log_dbg(cd, "Blkid probe failed.");
		r = -EINVAL;
		break;
	case PRB_OK: /* crypto_LUKS type is filtered out */
		r = -EINVAL;

		if (blk_is_partition(h))
			log_dbg(cd, "Blkid probe detected partition type '%s'", blk_get_partition_type(h));
		else if (blk_is_superblock(h))
			log_dbg(cd, "blkid probe detected superblock type '%s'", blk_get_superblock_type(h));
		break;
	case PRB_EMPTY:
		log_dbg(cd, "Blkid probe detected no foreign device signature.");
	}
	blk_free(h);
	return r;
}

/*
 * Read and convert on-disk LUKS2 header to in-memory representation..
 * Try to do recovery if on-disk state is not consistent.
 */
int LUKS2_disk_hdr_read(struct crypt_device *cd, struct luks2_hdr *hdr,
			struct device *device, int do_recovery, int do_blkprobe)
{
	enum { HDR_OK, HDR_OBSOLETE, HDR_FAIL, HDR_FAIL_IO } state_hdr1, state_hdr2;
	struct luks2_hdr_disk hdr_disk1, hdr_disk2;
	char *json_area1 = NULL, *json_area2 = NULL;
	json_object *jobj_hdr1 = NULL, *jobj_hdr2 = NULL;
	unsigned int i;
	int r;
	uint64_t hdr_size;
	uint64_t hdr2_offsets[] = LUKS2_HDR2_OFFSETS;

	/* Skip auto-recovery if locks are disabled and we're not doing LUKS2 explicit repair */
	if (do_recovery && do_blkprobe && !crypt_metadata_locking_enabled()) {
		do_recovery = 0;
		log_dbg(cd, "Disabling header auto-recovery due to locking being disabled.");
	}

	/*
	 * Read primary LUKS2 header (offset 0).
	 */
	state_hdr1 = HDR_FAIL;
	r = hdr_read_disk(cd, device, &hdr_disk1, &json_area1, 0, 0);
	if (r == 0) {
		jobj_hdr1 = parse_and_validate_json(cd, json_area1, be64_to_cpu(hdr_disk1.hdr_size));
		state_hdr1 = jobj_hdr1 ? HDR_OK : HDR_OBSOLETE;
	} else if (r == -EIO)
		state_hdr1 = HDR_FAIL_IO;

	/*
	 * Read secondary LUKS2 header (follows primary).
	 */
	state_hdr2 = HDR_FAIL;
	if (state_hdr1 != HDR_FAIL && state_hdr1 != HDR_FAIL_IO) {
		r = hdr_read_disk(cd, device, &hdr_disk2, &json_area2, be64_to_cpu(hdr_disk1.hdr_size), 1);
		if (r == 0) {
			jobj_hdr2 = parse_and_validate_json(cd, json_area2, be64_to_cpu(hdr_disk2.hdr_size));
			state_hdr2 = jobj_hdr2 ? HDR_OK : HDR_OBSOLETE;
		} else if (r == -EIO)
			state_hdr2 = HDR_FAIL_IO;
	} else {
		/*
		 * No header size, check all known offsets.
		 */
		hdr_disk2.hdr_size = 0;
		for (r = -EINVAL,i = 0; r < 0 && i < ARRAY_SIZE(hdr2_offsets); i++)
			r = hdr_read_disk(cd, device, &hdr_disk2, &json_area2, hdr2_offsets[i], 1);

		if (r == 0) {
			jobj_hdr2 = parse_and_validate_json(cd, json_area2, be64_to_cpu(hdr_disk2.hdr_size));
			state_hdr2 = jobj_hdr2 ? HDR_OK : HDR_OBSOLETE;
		} else if (r == -EIO)
			state_hdr2 = HDR_FAIL_IO;
	}

	/*
	 * Check sequence id if both headers are read correctly.
	 */
	if (state_hdr1 == HDR_OK && state_hdr2 == HDR_OK) {
		if (be64_to_cpu(hdr_disk1.seqid) > be64_to_cpu(hdr_disk2.seqid))
			state_hdr2 = HDR_OBSOLETE;
		else if (be64_to_cpu(hdr_disk1.seqid) < be64_to_cpu(hdr_disk2.seqid))
			state_hdr1 = HDR_OBSOLETE;
	}

	/* check header with keyslots to fit the device */
	if (state_hdr1 == HDR_OK)
		hdr_size = LUKS2_hdr_and_areas_size_jobj(jobj_hdr1);
	else if (state_hdr2 == HDR_OK)
		hdr_size = LUKS2_hdr_and_areas_size_jobj(jobj_hdr2);
	else {
		r = (state_hdr1 == HDR_FAIL_IO && state_hdr2 == HDR_FAIL_IO) ? -EIO : -EINVAL;
		goto err;
	}

	r = device_check_size(cd, device, hdr_size, 0);
	if (r)
		goto err;

	/*
	 * Try to rewrite (recover) bad header. Always regenerate salt for bad header.
	 */
	if (state_hdr1 == HDR_OK && state_hdr2 != HDR_OK) {
		log_dbg(cd, "Secondary LUKS2 header requires recovery.");

		if (do_blkprobe && (r = detect_device_signatures(cd, device_path(device)))) {
			log_err(cd, _("Device contains ambiguous signatures, cannot auto-recover LUKS2.\n"
				      "Please run \"cryptsetup repair\" for recovery."));
			goto err;
		}

		if (do_recovery) {
			memcpy(&hdr_disk2, &hdr_disk1, LUKS2_HDR_BIN_LEN);
			r = crypt_random_get(cd, (char*)hdr_disk2.salt, sizeof(hdr_disk2.salt), CRYPT_RND_SALT);
			if (r)
				log_dbg(cd, "Cannot generate header salt.");
			else {
				hdr_from_disk(&hdr_disk1, &hdr_disk2, hdr, 0);
				r = hdr_write_disk(cd, device, hdr, json_area1, 1);
			}
			if (r)
				log_dbg(cd, "Secondary LUKS2 header recovery failed.");
		}
	} else if (state_hdr1 != HDR_OK && state_hdr2 == HDR_OK) {
		log_dbg(cd, "Primary LUKS2 header requires recovery.");

		if (do_blkprobe && (r = detect_device_signatures(cd, device_path(device)))) {
			log_err(cd, _("Device contains ambiguous signatures, cannot auto-recover LUKS2.\n"
				      "Please run \"cryptsetup repair\" for recovery."));
			goto err;
		}

		if (do_recovery) {
			memcpy(&hdr_disk1, &hdr_disk2, LUKS2_HDR_BIN_LEN);
			r = crypt_random_get(cd, (char*)hdr_disk1.salt, sizeof(hdr_disk1.salt), CRYPT_RND_SALT);
			if (r)
				log_dbg(cd, "Cannot generate header salt.");
			else {
				hdr_from_disk(&hdr_disk2, &hdr_disk1, hdr, 1);
				r = hdr_write_disk(cd, device, hdr, json_area2, 0);
			}
			if (r)
				log_dbg(cd, "Primary LUKS2 header recovery failed.");
		}
	}

	free(json_area1);
	json_area1 = NULL;
	free(json_area2);
	json_area2 = NULL;

	/* wrong lock for write mode during recovery attempt */
	if (r == -EAGAIN)
		goto err;

	/*
	 * Even if status is failed, the second header includes salt.
	 */
	if (state_hdr1 == HDR_OK) {
		hdr_from_disk(&hdr_disk1, &hdr_disk2, hdr, 0);
		hdr->jobj = jobj_hdr1;
		json_object_put(jobj_hdr2);
	} else if (state_hdr2 == HDR_OK) {
		hdr_from_disk(&hdr_disk2, &hdr_disk1, hdr, 1);
		hdr->jobj = jobj_hdr2;
		json_object_put(jobj_hdr1);
	}

	/*
	 * FIXME: should this fail? At least one header was read correctly.
	 * r = (state_hdr1 == HDR_FAIL_IO || state_hdr2 == HDR_FAIL_IO) ? -EIO : -EINVAL;
	 */
	return 0;
err:
	log_dbg(cd, "LUKS2 header read failed (%d).", r);

	free(json_area1);
	free(json_area2);
	json_object_put(jobj_hdr1);
	json_object_put(jobj_hdr2);
	hdr->jobj = NULL;
	return r;
}

int LUKS2_hdr_version_unlocked(struct crypt_device *cd, const char *backup_file)
{
	struct {
		char magic[LUKS2_MAGIC_L];
		uint16_t version;
	}  __attribute__ ((packed)) hdr;
	struct device *device = NULL;
	int r = 0, devfd = -1, flags;

	if (!backup_file)
		device = crypt_metadata_device(cd);
	else if (device_alloc(cd, &device, backup_file) < 0)
		return 0;

	if (!device)
		return 0;

	flags = O_RDONLY;
	if (device_direct_io(device))
		flags |= O_DIRECT;

	devfd = open(device_path(device), flags);
	if (devfd != -1 && (read_lseek_blockwise(devfd, device_block_size(cd, device),
	     device_alignment(device), &hdr, sizeof(hdr), 0) == sizeof(hdr)) &&
	    !memcmp(hdr.magic, LUKS2_MAGIC_1ST, LUKS2_MAGIC_L))
		r = (int)be16_to_cpu(hdr.version);

	if (devfd != -1)
		close(devfd);

	if (backup_file)
		device_free(cd, device);

	return r;
}
