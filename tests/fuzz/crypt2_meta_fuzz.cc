// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup LUKS2 metadata API fuzz target
 *
 * Copyright (C) 2026 Red Hat, Inc. All rights reserved.
 */

extern "C" {
#define FILESIZE (16777216)
#include "src/cryptsetup.h"
#include "luks2/luks2.h"
#include "crypto_backend/crypto_backend.h"
#include "FuzzerInterface.h"

static void empty_log(int level, const char *msg, void *usrptr) {}

static bool fix_checksum(const uint8_t *data, size_t size, uint64_t hdr_size,
			 struct luks2_hdr_disk *hdr_out)
{
	char alg[LUKS2_CHECKSUM_ALG_L + 1] = {};
	struct crypt_hash *hd = NULL;
	int hash_size;
	bool r = false;

	memcpy(hdr_out, data, LUKS2_HDR_BIN_LEN);
	memcpy(alg, hdr_out->checksum_alg, LUKS2_CHECKSUM_ALG_L);
	memset(hdr_out->csum, 0, LUKS2_CHECKSUM_L);

	hash_size = crypt_hash_size(alg);
	if (hash_size <= 0 || (size_t)hash_size > LUKS2_CHECKSUM_L)
		return false;
	if (crypt_hash_init(&hd, alg))
		return false;

	if (!crypt_hash_write(hd, (const char *)hdr_out, LUKS2_HDR_BIN_LEN) &&
	    !crypt_hash_write(hd, (const char *)data + LUKS2_HDR_BIN_LEN,
			      (size_t)hdr_size - LUKS2_HDR_BIN_LEN) &&
	    !crypt_hash_final(hd, (char *)hdr_out->csum, (size_t)hash_size))
		r = true;

	crypt_hash_destroy(hd);
	return r;
}

static uint64_t declared_hdr_size(const uint8_t *data, size_t size)
{
	uint64_t hdr_size;

	if (size < LUKS2_HDR_BIN_LEN)
		return 0;

	hdr_size = be64_to_cpu(((const struct luks2_hdr_disk *)(uintptr_t)data)->hdr_size);
	if (hdr_size <= LUKS2_HDR_BIN_LEN || hdr_size > size)
		return 0;

	return hdr_size;
}

static void walk_tokens(struct crypt_device *cd)
{
	int max = crypt_token_max(CRYPT_LUKS2), i, j;

	if (max <= 0)
		return;

	for (i = 0; i < max; i++) {
		const char *type = NULL, *json = NULL;

		(void)crypt_token_status(cd, i, &type);
		(void)crypt_token_json_get(cd, i, &json);
		if(json != NULL)
			(void)crypt_token_json_set(cd, i, json);

		for (j = 0; j < LUKS2_KEYSLOTS_MAX; j++)
			(void)crypt_token_is_assigned(cd, i, j);
	}
}

static void walk_keyslots(struct crypt_device *cd)
{
	int max = crypt_keyslot_max(CRYPT_LUKS2), i;

	if (max <= 0)
		return;

	for (i = 0; i < max; i++) {
		struct crypt_pbkdf_type pbkdf = {};
		uint64_t offset = 0, length = 0;
		size_t key_size = 0;

		(void)crypt_keyslot_status(cd, i);
		(void)crypt_keyslot_get_priority(cd, i);
		(void)crypt_keyslot_get_key_size(cd, i);
		(void)crypt_keyslot_get_encryption(cd, i, &key_size);
		(void)crypt_keyslot_get_pbkdf(cd, i, &pbkdf);
		(void)crypt_keyslot_area(cd, i, &offset, &length);
	}
}

static void read_metadata(struct crypt_device *cd)
{
	struct crypt_params_integrity ip = {};
	struct crypt_params_reencrypt rp = {};
	uint64_t metadata_size = 0, keyslots_size = 0;
	const char *json = NULL;
	uint32_t flags = 0;

	walk_tokens(cd);
	walk_keyslots(cd);
}

static void backup_and_reload(struct crypt_device *cd)
{
	struct crypt_device *cd2 = NULL;
	char backup[] = "/tmp/test-script-fuzz-backup.XXXXXX";
	int fd;

	fd = mkostemp(backup, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC);
	if (fd == -1)
		return;
	close(fd);

	if (!crypt_header_backup(cd, CRYPT_LUKS2, backup) &&
	    crypt_init(&cd2, backup) == 0) {
		if (!crypt_load(cd2, CRYPT_LUKS2, NULL))
			read_metadata(cd2);
	}

	crypt_free(cd2);
	unlink(backup);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int fd;
	struct crypt_device *cd = NULL;
	char name[] = "/tmp/test-script-fuzz.XXXXXX";
	struct luks2_hdr_disk hdr_rw;
	uint64_t hdr_size;
	bool fixed;

	/* if csum calculation fails, keep fuzzer running on original input */
	hdr_size = declared_hdr_size(data, size);
	fixed = hdr_size && fix_checksum(data, size, hdr_size, &hdr_rw);

	fd = mkostemp(name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC);
	if (fd == -1)
		return 0;

	/* enlarge header */
	if (ftruncate(fd, FILESIZE) == -1)
		goto out;

	if (fixed) {
		if (write_buffer(fd, &hdr_rw, LUKS2_HDR_BIN_LEN) != (ssize_t)LUKS2_HDR_BIN_LEN)
			goto out;
		if (write_buffer(fd, data + LUKS2_HDR_BIN_LEN, size - LUKS2_HDR_BIN_LEN) !=
		    (ssize_t)(size - LUKS2_HDR_BIN_LEN))
			goto out;
	} else if (write_buffer(fd, data, size) != (ssize_t)size)
		goto out;

	crypt_set_log_callback(NULL, empty_log, NULL);

	/* Actual fuzzing */
	if (crypt_init(&cd, name) == 0 && !crypt_load(cd, CRYPT_LUKS2, NULL)) {
		read_metadata(cd);
		backup_and_reload(cd);
	}
out:
	crypt_free(cd);
	close(fd);
	unlink(name);

	return 0;
}
}
