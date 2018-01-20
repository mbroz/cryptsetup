/*
 * LUKS - Linux Unified Key Setup v2, LUKS2 type keyslot handler
 *
 * Copyright (C) 2015-2018, Red Hat, Inc. All rights reserved.
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

/* FIXME: move keyslot encryption to crypto backend */
#include "../luks1/af.h"

#define LUKS_SALTSIZE 32
#define LUKS_SLOT_ITERATIONS_MIN 1000
#define LUKS_STRIPES 4000

static int luks2_encrypt_to_storage(char *src, size_t srcLength,
	const char *cipher, const char *cipher_mode,
	struct volume_key *vk, unsigned int sector,
	struct crypt_device *cd)
{
	struct device *device = crypt_metadata_device(cd);
#ifndef ENABLE_AF_ALG /* Support for old kernel without Crypto API */
	int r = device_write_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s.\n"), device_path(device));
		return r;
	}
	r = LUKS_encrypt_to_storage(src, srcLength, cipher, cipher_mode, vk, sector, cd);
	device_write_unlock(crypt_metadata_device(cd));
	return r;
#else
	struct crypt_storage *s;
	int devfd = -1, r;

	/* Only whole sector writes supported */
	if (srcLength % SECTOR_SIZE)
		return -EINVAL;

	/* Encrypt buffer */
	r = crypt_storage_init(&s, 0, cipher, cipher_mode, vk->key, vk->keylength);
	if (r) {
		log_dbg("Userspace crypto wrapper cannot use %s-%s (%d).",
			cipher, cipher_mode, r);
		return r;
	}

	r = crypt_storage_encrypt(s, 0, srcLength / SECTOR_SIZE, src);
	crypt_storage_destroy(s);
	if (r)
		return r;

	r = device_write_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s.\n"),
			device_path(device));
		return r;
	}

	devfd = device_open_locked(device, O_RDWR);
	if (devfd >= 0) {
		if (write_lseek_blockwise(devfd, device_block_size(device),
					  device_alignment(device), src,
					  srcLength, sector * SECTOR_SIZE) < 0)
			r = -EIO;
		else
			r = 0;
		close(devfd);
	} else
		r = -EIO;

	device_write_unlock(device);

	if (r)
		log_err(cd, _("IO error while encrypting keyslot.\n"));

	return r;
#endif
}

static int luks2_decrypt_from_storage(char *dst, size_t dstLength,
	const char *cipher, const char *cipher_mode, struct volume_key *vk,
	unsigned int sector, struct crypt_device *cd)
{
	struct device *device = crypt_metadata_device(cd);
#ifndef ENABLE_AF_ALG /* Support for old kernel without Crypto API */
	int r = device_read_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s.\n"), device_path(device));
		return r;
	}
	r = LUKS_decrypt_from_storage(dst, dstLength, cipher, cipher_mode, vk, sector, cd);
	device_read_unlock(crypt_metadata_device(cd));
	return r;
#else
	struct crypt_storage *s;
	int devfd = -1, r;

	/* Only whole sector writes supported */
	if (dstLength % SECTOR_SIZE)
		return -EINVAL;

	r = crypt_storage_init(&s, 0, cipher, cipher_mode, vk->key, vk->keylength);
	if (r) {
		log_dbg("Userspace crypto wrapper cannot use %s-%s (%d).",
			cipher, cipher_mode, r);
		return r;
	}

	r = device_read_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s.\n"),
			device_path(device));
		crypt_storage_destroy(s);
		return r;
	}

	devfd = device_open_locked(device, O_RDONLY);
	if (devfd >= 0) {
		if (read_lseek_blockwise(devfd, device_block_size(device),
					 device_alignment(device), dst,
					 dstLength, sector * SECTOR_SIZE) < 0)
			r = -EIO;
		else
			r = 0;
		close(devfd);
	} else
		r = -EIO;

	device_read_unlock(device);

	/* Decrypt buffer */
	if (!r)
		r = crypt_storage_decrypt(s, 0, dstLength / SECTOR_SIZE, dst);
	else
		log_err(cd, _("IO error while decrypting keyslot.\n"));

	crypt_storage_destroy(s);
	return r;
#endif
}

static int luks2_keyslot_set_key(struct crypt_device *cd,
	json_object *jobj_keyslot,
	const char *password, size_t passwordLen,
	const char *volume_key, size_t volume_key_len)
{
	struct volume_key *derived_key;
	char salt[LUKS_SALTSIZE], cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	char *AfKey = NULL, *salt_base64 = NULL;
	size_t AFEKSize, keyslot_key_len;
	json_object *jobj2, *jobj_kdf, *jobj_af, *jobj_area;
	uint64_t area_offset;
	const struct crypt_pbkdf_type *pbkdf;
	int r;

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf) ||
	    !json_object_object_get_ex(jobj_keyslot, "af", &jobj_af) ||
	    !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_area, "offset", &jobj2))
		return -EINVAL;
	area_offset = json_object_get_uint64(jobj2);

	if (!json_object_object_get_ex(jobj_area, "encryption", &jobj2))
		return -EINVAL;
	r = crypt_parse_name_and_mode(json_object_get_string(jobj2), cipher, NULL, cipher_mode);
	if (r < 0)
		return r;

	if (!json_object_object_get_ex(jobj_area, "key_size", &jobj2))
		return -EINVAL;
	keyslot_key_len = json_object_get_int(jobj2);

	pbkdf = crypt_get_pbkdf_type(cd);
	if (!pbkdf)
		return -EINVAL;

	r = crypt_benchmark_pbkdf_internal(cd, CONST_CAST(struct crypt_pbkdf_type *)pbkdf, volume_key_len);
	if (r < 0)
		return r;

	if (!strcmp(pbkdf->type, CRYPT_KDF_PBKDF2)) {
		json_object_object_add(jobj_kdf, "hash", json_object_new_string(pbkdf->hash));
		json_object_object_add(jobj_kdf, "iterations", json_object_new_int(pbkdf->iterations));
	} else {
		json_object_object_add(jobj_kdf, "time", json_object_new_int(pbkdf->iterations));
		json_object_object_add(jobj_kdf, "memory", json_object_new_int(pbkdf->max_memory_kb));
		json_object_object_add(jobj_kdf, "cpus", json_object_new_int(pbkdf->parallel_threads));
	}

	json_object_object_add(jobj_kdf, "type", json_object_new_string(pbkdf->type));

	/*
	 * Get salt and allocate derived key storage.
	 */
	r = crypt_random_get(cd, salt, LUKS_SALTSIZE, CRYPT_RND_SALT);
	if (r < 0)
		return r;
	base64_encode_alloc(salt, LUKS_SALTSIZE, &salt_base64);
	if (!salt_base64)
		return -ENOMEM;
	json_object_object_add(jobj_kdf, "salt", json_object_new_string(salt_base64));
	free(salt_base64);

	json_object_object_add(jobj_kdf, "type", json_object_new_string(pbkdf->type));

	json_object_object_add(jobj_af, "hash", json_object_new_string(pbkdf->hash));

	derived_key = crypt_alloc_volume_key(keyslot_key_len, NULL);
	if (!derived_key)
		return -ENOMEM;
	/*
	 * Calculate keyslot content, split and store it to keyslot area.
	 */
	r = crypt_pbkdf(pbkdf->type, pbkdf->hash, password, passwordLen,
			salt, LUKS_SALTSIZE,
			derived_key->key, derived_key->keylength,
			pbkdf->iterations, pbkdf->max_memory_kb,
			pbkdf->parallel_threads);
	if (r < 0) {
		crypt_free_volume_key(derived_key);
		return r;
	}

	// FIXME: verity key_size to AFEKSize
	AFEKSize = AF_split_sectors(volume_key_len, LUKS_STRIPES) * SECTOR_SIZE;
	AfKey = crypt_safe_alloc(AFEKSize);
	if (!AfKey) {
		crypt_free_volume_key(derived_key);
		return -ENOMEM;
	}

	r = AF_split(volume_key, AfKey, volume_key_len, LUKS_STRIPES, pbkdf->hash);

	if (r == 0) {
		log_dbg("Updating keyslot area [0x%04x].", (unsigned)area_offset);
		/* FIXME: sector_offset should be size_t, fix LUKS_encrypt... accordingly */
		r = luks2_encrypt_to_storage(AfKey, AFEKSize, cipher, cipher_mode,
				    derived_key, (unsigned)(area_offset / SECTOR_SIZE), cd);
	}

	crypt_safe_free(AfKey);
	crypt_free_volume_key(derived_key);
	if (r < 0)
		return r;

	JSON_DBG(jobj_keyslot, "Keyslot JSON");
	return 0;
}

static int luks2_keyslot_get_key(struct crypt_device *cd,
	json_object *jobj_keyslot,
	const char *password, size_t passwordLen,
	char *volume_key, size_t volume_key_len)
{
	struct volume_key *derived_key;
	char *AfKey;
	size_t AFEKSize;
	const char *hash = NULL, *af_hash = NULL, *kdf;
	char salt[LUKS_SALTSIZE], cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	json_object *jobj1, *jobj2, *jobj_kdf, *jobj_af, *jobj_area;
	uint32_t iterations, memory, parallel;
	uint64_t area_offset;
	size_t salt_len, keyslot_key_len;
	int r;

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf) ||
	    !json_object_object_get_ex(jobj_keyslot, "af", &jobj_af) ||
	    !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_kdf, "type", &jobj1))
		return -EINVAL;
	kdf = json_object_get_string(jobj1);
	if (!strcmp(kdf, CRYPT_KDF_PBKDF2)) {
		if (!json_object_object_get_ex(jobj_kdf, "hash", &jobj2))
			return -EINVAL;
		hash = json_object_get_string(jobj2);
		if (!json_object_object_get_ex(jobj_kdf, "iterations", &jobj2))
			return -EINVAL;
		iterations = json_object_get_int(jobj2);
		memory = 0;
		parallel = 0;
	} else {
		if (!json_object_object_get_ex(jobj_kdf, "time", &jobj2))
			return -EINVAL;
		iterations = json_object_get_int(jobj2);
		if (!json_object_object_get_ex(jobj_kdf, "memory", &jobj2))
			return -EINVAL;
		memory = json_object_get_int(jobj2);
		if (!json_object_object_get_ex(jobj_kdf, "cpus", &jobj2))
			return -EINVAL;
		parallel = json_object_get_int(jobj2);
	}

	if (!json_object_object_get_ex(jobj_kdf, "salt", &jobj2))
		return -EINVAL;
	salt_len = LUKS_SALTSIZE;
	if (!base64_decode(json_object_get_string(jobj2),
			   json_object_get_string_len(jobj2),
			   salt, &salt_len))
		return -EINVAL;
	if (salt_len != LUKS_SALTSIZE)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_af, "hash", &jobj2))
		return -EINVAL;
	af_hash = json_object_get_string(jobj2);

	if (!json_object_object_get_ex(jobj_area, "offset", &jobj2))
		return -EINVAL;
	area_offset = json_object_get_uint64(jobj2);

	if (!json_object_object_get_ex(jobj_area, "encryption", &jobj2))
		return -EINVAL;
	r = crypt_parse_name_and_mode(json_object_get_string(jobj2), cipher, NULL, cipher_mode);
	if (r < 0)
		return r;

	if (!json_object_object_get_ex(jobj_area, "key_size", &jobj2))
		return -EINVAL;
	keyslot_key_len = json_object_get_int(jobj2);

	/*
	 * Allocate derived key storage space.
	 */
	derived_key = crypt_alloc_volume_key(keyslot_key_len, NULL);
	if (!derived_key)
		return -ENOMEM;

	AFEKSize = AF_split_sectors(volume_key_len, LUKS_STRIPES) * SECTOR_SIZE;
	AfKey = crypt_safe_alloc(AFEKSize);
	if (!AfKey) {
		crypt_free_volume_key(derived_key);
		return -ENOMEM;
	}
	/*
	 * Calculate derived key, decrypt keyslot content and merge it.
	 */
	r = crypt_pbkdf(kdf, hash, password, passwordLen,
			salt, LUKS_SALTSIZE,
			derived_key->key, derived_key->keylength,
			iterations, memory, parallel);

	if (r == 0) {
		log_dbg("Reading keyslot area [0x%04x].", (unsigned)area_offset);
		/* FIXME: sector_offset should be size_t, fix LUKS_decrypt... accordingly */
		r = luks2_decrypt_from_storage(AfKey, AFEKSize, cipher, cipher_mode,
				      derived_key, (unsigned)(area_offset / SECTOR_SIZE), cd);
	}

	if (r == 0)
		r = AF_merge(AfKey, volume_key, volume_key_len, LUKS_STRIPES, af_hash);

	crypt_free_volume_key(derived_key);
	crypt_safe_free(AfKey);

	return r;
}

int luks2_keyslot_alloc(struct crypt_device *cd,
	int keyslot,
	size_t volume_key_len,
	const struct luks2_keyslot_params *params)
{
	struct luks2_hdr *hdr;
	const struct crypt_pbkdf_type *pbkdf;
	char num[16];
	uint64_t area_offset, area_length;
	json_object *jobj_keyslots, *jobj_keyslot, *jobj_kdf, *jobj_af, *jobj_area;
	int r;

	log_dbg("Trying to allocate LUKS2 keyslot %d.", keyslot);

	if (!params || params->area_type != LUKS2_KEYSLOT_AREA_RAW ||
	    params->af_type != LUKS2_KEYSLOT_AF_LUKS1) {
		log_dbg("Invalid LUKS2 keyslot parameters.");
		return -EINVAL;
	}

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	if (keyslot == CRYPT_ANY_SLOT)
		keyslot = LUKS2_keyslot_find_empty(hdr, "luks2");

	if (keyslot < 0 || keyslot > LUKS2_KEYSLOTS_MAX)
		return -ENOMEM;

	if (LUKS2_get_keyslot_jobj(hdr, keyslot)) {
		log_dbg("Cannot modify already active keyslot %d.", keyslot);
		return -EINVAL;
	}

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	r = LUKS2_find_area_gap(cd, hdr, volume_key_len, &area_offset, &area_length);
	if (r < 0)
		return r;

	pbkdf = crypt_get_pbkdf_type(cd);
	if (!pbkdf)
		return -EINVAL;

	r = crypt_benchmark_pbkdf_internal(cd, CONST_CAST(struct crypt_pbkdf_type *)pbkdf, volume_key_len);
	if (r < 0)
		return r;

	jobj_keyslot = json_object_new_object();
	json_object_object_add(jobj_keyslot, "type", json_object_new_string("luks2"));
	json_object_object_add(jobj_keyslot, "key_size", json_object_new_int(volume_key_len));

	/* PBKDF object */
	jobj_kdf = json_object_new_object();
	json_object_object_add(jobj_kdf, "type", json_object_new_string(pbkdf->type));
	if (!strcmp(pbkdf->type, CRYPT_KDF_PBKDF2)) {
		json_object_object_add(jobj_kdf, "iterations", json_object_new_int(pbkdf->iterations));
		json_object_object_add(jobj_kdf, "hash", json_object_new_string(pbkdf->hash));
		json_object_object_add(jobj_kdf, "salt", json_object_new_string(""));
	} else {
		json_object_object_add(jobj_kdf, "time", json_object_new_int(pbkdf->iterations));
		json_object_object_add(jobj_kdf, "memory", json_object_new_int(pbkdf->max_memory_kb));
		json_object_object_add(jobj_kdf, "cpus", json_object_new_int(pbkdf->parallel_threads));
		json_object_object_add(jobj_kdf, "salt", json_object_new_string(""));
	}
	json_object_object_add(jobj_keyslot, "kdf", jobj_kdf);

	/* AF object */
	jobj_af = json_object_new_object();
	json_object_object_add(jobj_af, "type", json_object_new_string("luks1"));
	json_object_object_add(jobj_af, "hash", json_object_new_string(params->af.luks1.hash));
	json_object_object_add(jobj_af, "stripes", json_object_new_int(params->af.luks1.stripes));
	json_object_object_add(jobj_keyslot, "af", jobj_af);

	/* Area object */
	jobj_area = json_object_new_object();
	json_object_object_add(jobj_area, "type", json_object_new_string("raw"));
	json_object_object_add(jobj_area, "encryption", json_object_new_string(params->area.raw.encryption));
	json_object_object_add(jobj_area, "key_size", json_object_new_int(params->area.raw.key_size));
	json_object_object_add(jobj_area, "offset", json_object_new_uint64(area_offset));
	json_object_object_add(jobj_area, "size", json_object_new_uint64(area_length));
	json_object_object_add(jobj_keyslot, "area", jobj_area);

	snprintf(num, sizeof(num), "%d", keyslot);

	json_object_object_add(jobj_keyslots, num, jobj_keyslot);
	if (LUKS2_check_json_size(hdr)) {
		log_dbg("Not enough space in header json area for new keyslot.");
		json_object_object_del(jobj_keyslots, num);
		return -ENOSPC;
	}

	return 0;
}

static int luks2_keyslot_open(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	char *volume_key,
	size_t volume_key_len)
{
	struct luks2_hdr *hdr;
	json_object *jobj_keyslot;

	log_dbg("Trying to open LUKS2 keyslot %d.", keyslot);

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	return luks2_keyslot_get_key(cd, jobj_keyslot,
				     password, password_len,
				     volume_key, volume_key_len);
}

static int luks2_keyslot_store(struct crypt_device *cd,
	int keyslot,
	const char *password,
	size_t password_len,
	const char *volume_key,
	size_t volume_key_len)
{
	struct luks2_hdr *hdr;
	json_object *jobj_keyslot;
	int r;

	log_dbg("Calculating attributes for LUKS2 keyslot %d.", keyslot);

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	r = luks2_keyslot_set_key(cd, jobj_keyslot,
				  password, password_len,
				  volume_key, volume_key_len);
	if (r < 0)
		return r;

	r = LUKS2_hdr_write(cd, hdr);
	if (r < 0)
		return r;

	return keyslot;
}

static int luks2_keyslot_wipe(struct crypt_device *cd, int keyslot)
{
	struct luks2_hdr *hdr;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	/* Remove any reference of deleted keyslot from digests and tokens */
	LUKS2_digest_assign(cd, hdr, keyslot, CRYPT_ANY_DIGEST, 0, 0);
	LUKS2_token_assign(cd, hdr, keyslot, CRYPT_ANY_TOKEN, 0, 0);

	return 0;
}

static int luks2_keyslot_dump(struct crypt_device *cd, int keyslot)
{
	json_object *jobj_keyslot, *jobj1, *jobj_kdf, *jobj_af, *jobj_area;

	jobj_keyslot = LUKS2_get_keyslot_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf) ||
	    !json_object_object_get_ex(jobj_keyslot, "af", &jobj_af) ||
	    !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	json_object_object_get_ex(jobj_area, "encryption", &jobj1);
	log_std(cd, "\tCipher:     %s\n", json_object_get_string(jobj1));

	json_object_object_get_ex(jobj_kdf, "type", &jobj1);
	log_std(cd, "\tPBKDF:      %s\n", json_object_get_string(jobj1));

	if (!strcmp(json_object_get_string(jobj1), CRYPT_KDF_PBKDF2)) {
		json_object_object_get_ex(jobj_kdf, "hash", &jobj1);
		log_std(cd, "\tHash:       %s\n", json_object_get_string(jobj1));

		json_object_object_get_ex(jobj_kdf, "iterations", &jobj1);
		log_std(cd, "\tIterations: %" PRIu64 "\n", json_object_get_uint64(jobj1));
	} else {
		json_object_object_get_ex(jobj_kdf, "time", &jobj1);
		log_std(cd, "\tTime cost:  %" PRIu64 "\n", json_object_get_int64(jobj1));

		json_object_object_get_ex(jobj_kdf, "memory", &jobj1);
		log_std(cd, "\tMemory:     %" PRIu64 "\n", json_object_get_int64(jobj1));

		json_object_object_get_ex(jobj_kdf, "cpus", &jobj1);
		log_std(cd, "\tThreads:    %" PRIu64 "\n", json_object_get_int64(jobj1));
	}
	json_object_object_get_ex(jobj_kdf, "salt", &jobj1);
	log_std(cd, "\tSalt:       ");
	hexprint_base64(cd, jobj1, " ", "            ");


	json_object_object_get_ex(jobj_af, "stripes", &jobj1);
	log_std(cd, "\tAF stripes: %u\n", json_object_get_int(jobj1));

	json_object_object_get_ex(jobj_area, "offset", &jobj1);
	log_std(cd, "\tArea offset:%" PRIu64 " [bytes]\n", json_object_get_uint64(jobj1));

	json_object_object_get_ex(jobj_area, "size", &jobj1);
	log_std(cd, "\tArea length:%" PRIu64 " [bytes]\n", json_object_get_uint64(jobj1));

	return 0;
}

static int contains(json_object *jobj, const char *key, json_type type)
{
	json_object *sobj;

	if (!json_object_object_get_ex(jobj, key, &sobj) ||
	    !json_object_is_type(sobj, type))
		return 0;

	return 1;
}

static int luks2_keyslot_validate(struct crypt_device *cd, int keyslot)
{
	struct luks2_hdr *hdr;
	json_object *jobj_keyslot, *jobj_kdf, *jobj_af, *jobj_area, *jobj1;
	char num[16];

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	snprintf(num, sizeof(num), "%d", keyslot);
	if (LUKS2_keyslot_validate(hdr->jobj, jobj_keyslot, num))
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf) ||
	    !json_object_object_get_ex(jobj_keyslot, "af", &jobj_af) ||
	    !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_kdf, "type", &jobj1))
		return -EINVAL;

	if (!strcmp(json_object_get_string(jobj1), CRYPT_KDF_PBKDF2)) {
		if (!contains(jobj_kdf, "hash", json_type_string) ||
		    !contains(jobj_kdf, "iterations", json_type_int) ||
		    !contains(jobj_kdf, "salt", json_type_string))
			return -EINVAL;
	} else {
		if (!contains(jobj_kdf, "time", json_type_int) ||
		    !contains(jobj_kdf, "memory", json_type_int) ||
		    !contains(jobj_kdf, "cpus", json_type_int) ||
		    !contains(jobj_kdf, "salt", json_type_string))
			return -EINVAL;
	}

	if (!json_object_object_get_ex(jobj_af, "type", &jobj1))
		return -EINVAL;
	if (!strcmp(json_object_get_string(jobj1), "luks1")) {
		if (!contains(jobj_af, "hash", json_type_string) ||
		    !contains(jobj_af, "stripes", json_type_int))
			return -EINVAL;
	} else
		return -EINVAL;

	// FIXME check numbered
	if (!json_object_object_get_ex(jobj_area, "type", &jobj1))
		return -EINVAL;
	if (!strcmp(json_object_get_string(jobj1), "raw")) {
		if (!contains(jobj_area, "encryption", json_type_string) ||
		    !contains(jobj_area, "key_size", json_type_int) ||
		    !contains(jobj_area, "offset", json_type_string) ||
		    !contains(jobj_area, "size", json_type_string))
			return -EINVAL;
	} else
		return -EINVAL;

	return 0;
}

const keyslot_handler luks2_keyslot = {
	.name  = "luks2",
	.alloc  = luks2_keyslot_alloc,
	.open  = luks2_keyslot_open,
	.store = luks2_keyslot_store,
	.wipe  = luks2_keyslot_wipe,
	.dump  = luks2_keyslot_dump,
	.validate = luks2_keyslot_validate,
};
