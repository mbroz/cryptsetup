/*
 * LUKS - Linux Unified Key Setup v2, LUKS2 type keyslot handler
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

/* FIXME: move keyslot encryption to crypto backend */
#include "../luks1/af.h"

#define LUKS_SALTSIZE 32
#define LUKS_SLOT_ITERATIONS_MIN 1000
#define LUKS_STRIPES 4000

/* Serialize memory-hard keyslot access: opttional workaround for parallel processing */
#define MIN_MEMORY_FOR_SERIALIZE_LOCK_KB 32*1024 /* 32MB */

static int luks2_encrypt_to_storage(char *src, size_t srcLength,
	const char *cipher, const char *cipher_mode,
	struct volume_key *vk, unsigned int sector,
	struct crypt_device *cd)
{
	struct device *device = crypt_metadata_device(cd);
#ifndef ENABLE_AF_ALG /* Support for old kernel without Crypto API */
	int r = device_write_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s."), device_path(device));
		return r;
	}
	r = LUKS_encrypt_to_storage(src, srcLength, cipher, cipher_mode, vk, sector, cd);
	device_write_unlock(cd, crypt_metadata_device(cd));
	return r;
#else
	struct crypt_storage *s;
	int devfd = -1, r;

	/* Only whole sector writes supported */
	if (MISALIGNED_512(srcLength))
		return -EINVAL;

	/* Encrypt buffer */
	r = crypt_storage_init(&s, SECTOR_SIZE, cipher, cipher_mode, vk->key, vk->keylength);
	if (r) {
		log_dbg(cd, "Userspace crypto wrapper cannot use %s-%s (%d).",
			cipher, cipher_mode, r);
		return r;
	}

	r = crypt_storage_encrypt(s, 0, srcLength, src);
	crypt_storage_destroy(s);
	if (r)
		return r;

	r = device_write_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire write lock on device %s."),
			device_path(device));
		return r;
	}

	devfd = device_open_locked(cd, device, O_RDWR);
	if (devfd >= 0) {
		if (write_lseek_blockwise(devfd, device_block_size(cd, device),
					  device_alignment(device), src,
					  srcLength, sector * SECTOR_SIZE) < 0)
			r = -EIO;
		else
			r = 0;

		device_sync(cd, device, devfd);
		close(devfd);
	} else
		r = -EIO;

	device_write_unlock(cd, device);

	if (r)
		log_err(cd, _("IO error while encrypting keyslot."));

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
		log_err(cd, _("Failed to acquire read lock on device %s."), device_path(device));
		return r;
	}
	r = LUKS_decrypt_from_storage(dst, dstLength, cipher, cipher_mode, vk, sector, cd);
	device_read_unlock(cd, crypt_metadata_device(cd));
	return r;
#else
	struct crypt_storage *s;
	int devfd = -1, r;

	/* Only whole sector writes supported */
	if (MISALIGNED_512(dstLength))
		return -EINVAL;

	r = crypt_storage_init(&s, SECTOR_SIZE, cipher, cipher_mode, vk->key, vk->keylength);
	if (r) {
		log_dbg(cd, "Userspace crypto wrapper cannot use %s-%s (%d).",
			cipher, cipher_mode, r);
		return r;
	}

	r = device_read_lock(cd, device);
	if (r) {
		log_err(cd, _("Failed to acquire read lock on device %s."),
			device_path(device));
		crypt_storage_destroy(s);
		return r;
	}

	devfd = device_open_locked(cd, device, O_RDONLY);
	if (devfd >= 0) {
		if (read_lseek_blockwise(devfd, device_block_size(cd, device),
					 device_alignment(device), dst,
					 dstLength, sector * SECTOR_SIZE) < 0)
			r = -EIO;
		else
			r = 0;
		close(devfd);
	} else
		r = -EIO;

	device_read_unlock(cd, device);

	/* Decrypt buffer */
	if (!r)
		r = crypt_storage_decrypt(s, 0, dstLength, dst);
	else
		log_err(cd, _("IO error while decrypting keyslot."));

	crypt_storage_destroy(s);
	return r;
#endif
}

static int luks2_keyslot_get_pbkdf_params(json_object *jobj_keyslot,
		                struct crypt_pbkdf_type *pbkdf, char *salt)
{
	json_object *jobj_kdf, *jobj1, *jobj2;
	size_t salt_len;

	if (!jobj_keyslot || !pbkdf)
		return -EINVAL;

	memset(pbkdf, 0, sizeof(*pbkdf));

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf))
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_kdf, "type", &jobj1))
		return -EINVAL;
	pbkdf->type = json_object_get_string(jobj1);
	if (!strcmp(pbkdf->type, CRYPT_KDF_PBKDF2)) {
		if (!json_object_object_get_ex(jobj_kdf, "hash", &jobj2))
			return -EINVAL;
		pbkdf->hash = json_object_get_string(jobj2);
		if (!json_object_object_get_ex(jobj_kdf, "iterations", &jobj2))
			return -EINVAL;
		pbkdf->iterations = json_object_get_int(jobj2);
		pbkdf->max_memory_kb = 0;
		pbkdf->parallel_threads = 0;
	} else {
		if (!json_object_object_get_ex(jobj_kdf, "time", &jobj2))
			return -EINVAL;
		pbkdf->iterations = json_object_get_int(jobj2);
		if (!json_object_object_get_ex(jobj_kdf, "memory", &jobj2))
			return -EINVAL;
		pbkdf->max_memory_kb = json_object_get_int(jobj2);
		if (!json_object_object_get_ex(jobj_kdf, "cpus", &jobj2))
			return -EINVAL;
		pbkdf->parallel_threads = json_object_get_int(jobj2);
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

	return 0;
}

static int luks2_keyslot_set_key(struct crypt_device *cd,
	json_object *jobj_keyslot,
	const char *password, size_t passwordLen,
	const char *volume_key, size_t volume_key_len)
{
	struct volume_key *derived_key;
	char salt[LUKS_SALTSIZE], cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	char *AfKey = NULL;
	const char *af_hash = NULL;
	size_t AFEKSize, keyslot_key_len;
	json_object *jobj2, *jobj_kdf, *jobj_af, *jobj_area;
	uint64_t area_offset;
	struct crypt_pbkdf_type pbkdf;
	int r;

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf) ||
	    !json_object_object_get_ex(jobj_keyslot, "af", &jobj_af) ||
	    !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	/* prevent accidental volume key size change after allocation */
	if (!json_object_object_get_ex(jobj_keyslot, "key_size", &jobj2))
		return -EINVAL;
	if (json_object_get_int(jobj2) != (int)volume_key_len)
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

	if (!json_object_object_get_ex(jobj_af, "hash", &jobj2))
		return -EINVAL;
	af_hash = json_object_get_string(jobj2);

	if (luks2_keyslot_get_pbkdf_params(jobj_keyslot, &pbkdf, salt))
		return -EINVAL;

	/*
	 * Allocate derived key storage.
	 */
	derived_key = crypt_alloc_volume_key(keyslot_key_len, NULL);
	if (!derived_key)
		return -ENOMEM;
	/*
	 * Calculate keyslot content, split and store it to keyslot area.
	 */
	r = crypt_pbkdf(pbkdf.type, pbkdf.hash, password, passwordLen,
			salt, LUKS_SALTSIZE,
			derived_key->key, derived_key->keylength,
			pbkdf.iterations, pbkdf.max_memory_kb,
			pbkdf.parallel_threads);
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

	r = AF_split(cd, volume_key, AfKey, volume_key_len, LUKS_STRIPES, af_hash);

	if (r == 0) {
		log_dbg(cd, "Updating keyslot area [0x%04x].", (unsigned)area_offset);
		/* FIXME: sector_offset should be size_t, fix LUKS_encrypt... accordingly */
		r = luks2_encrypt_to_storage(AfKey, AFEKSize, cipher, cipher_mode,
				    derived_key, (unsigned)(area_offset / SECTOR_SIZE), cd);
	}

	crypt_safe_free(AfKey);
	crypt_free_volume_key(derived_key);
	if (r < 0)
		return r;

	return 0;
}

static int luks2_keyslot_get_key(struct crypt_device *cd,
	json_object *jobj_keyslot,
	const char *password, size_t passwordLen,
	char *volume_key, size_t volume_key_len)
{
	struct volume_key *derived_key;
	struct crypt_pbkdf_type pbkdf;
	char *AfKey;
	size_t AFEKSize;
	const char *af_hash = NULL;
	char salt[LUKS_SALTSIZE], cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
	json_object *jobj2, *jobj_af, *jobj_area;
	uint64_t area_offset;
	size_t keyslot_key_len;
	bool try_serialize_lock = false;
	int r;

	if (!json_object_object_get_ex(jobj_keyslot, "af", &jobj_af) ||
	    !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	if (luks2_keyslot_get_pbkdf_params(jobj_keyslot, &pbkdf, salt))
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
	 * If requested, serialize unlocking for memory-hard KDF. Usually NOOP.
	 */
	if (pbkdf.max_memory_kb > MIN_MEMORY_FOR_SERIALIZE_LOCK_KB)
		try_serialize_lock = true;
	if (try_serialize_lock && crypt_serialize_lock(cd))
		return -EINVAL;
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
	r = crypt_pbkdf(pbkdf.type, pbkdf.hash, password, passwordLen,
			salt, LUKS_SALTSIZE,
			derived_key->key, derived_key->keylength,
			pbkdf.iterations, pbkdf.max_memory_kb,
			pbkdf.parallel_threads);

	if (try_serialize_lock)
		crypt_serialize_unlock(cd);

	if (r == 0) {
		log_dbg(cd, "Reading keyslot area [0x%04x].", (unsigned)area_offset);
		/* FIXME: sector_offset should be size_t, fix LUKS_decrypt... accordingly */
		r = luks2_decrypt_from_storage(AfKey, AFEKSize, cipher, cipher_mode,
				      derived_key, (unsigned)(area_offset / SECTOR_SIZE), cd);
	}

	if (r == 0)
		r = AF_merge(cd, AfKey, volume_key, volume_key_len, LUKS_STRIPES, af_hash);

	crypt_free_volume_key(derived_key);
	crypt_safe_free(AfKey);

	return r;
}

/*
 * currently we support update of only:
 *
 * - af hash function
 * - kdf params
 */
static int luks2_keyslot_update_json(struct crypt_device *cd,
	json_object *jobj_keyslot,
	const struct luks2_keyslot_params *params)
{
	const struct crypt_pbkdf_type *pbkdf;
	json_object *jobj_af, *jobj_area, *jobj_kdf;
	char salt[LUKS_SALTSIZE], *salt_base64 = NULL;
	int r;

	/* jobj_keyslot is not yet validated */

	if (!json_object_object_get_ex(jobj_keyslot, "af", &jobj_af) ||
	    !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	/* update area encryption parameters */
	json_object_object_add(jobj_area, "encryption", json_object_new_string(params->area.raw.encryption));
	json_object_object_add(jobj_area, "key_size", json_object_new_int(params->area.raw.key_size));

	pbkdf = crypt_get_pbkdf_type(cd);
	if (!pbkdf)
		return -EINVAL;

	r = crypt_benchmark_pbkdf_internal(cd, CONST_CAST(struct crypt_pbkdf_type *)pbkdf, params->area.raw.key_size);
	if (r < 0)
		return r;

	/* refresh whole 'kdf' object */
	jobj_kdf = json_object_new_object();
	if (!jobj_kdf)
		return -ENOMEM;
	json_object_object_add(jobj_kdf, "type", json_object_new_string(pbkdf->type));
	if (!strcmp(pbkdf->type, CRYPT_KDF_PBKDF2)) {
		json_object_object_add(jobj_kdf, "hash", json_object_new_string(pbkdf->hash));
		json_object_object_add(jobj_kdf, "iterations", json_object_new_int(pbkdf->iterations));
	} else {
		json_object_object_add(jobj_kdf, "time", json_object_new_int(pbkdf->iterations));
		json_object_object_add(jobj_kdf, "memory", json_object_new_int(pbkdf->max_memory_kb));
		json_object_object_add(jobj_kdf, "cpus", json_object_new_int(pbkdf->parallel_threads));
	}
	json_object_object_add(jobj_keyslot, "kdf", jobj_kdf);

	/*
	 * Regenerate salt and add it in 'kdf' object
	 */
	r = crypt_random_get(cd, salt, LUKS_SALTSIZE, CRYPT_RND_SALT);
	if (r < 0)
		return r;
	base64_encode_alloc(salt, LUKS_SALTSIZE, &salt_base64);
	if (!salt_base64)
		return -ENOMEM;
	json_object_object_add(jobj_kdf, "salt", json_object_new_string(salt_base64));
	free(salt_base64);

	/* update 'af' hash */
	json_object_object_add(jobj_af, "hash", json_object_new_string(params->af.luks1.hash));

	JSON_DBG(cd, jobj_keyslot, "Keyslot JSON:");
	return 0;
}

static int luks2_keyslot_alloc(struct crypt_device *cd,
	int keyslot,
	size_t volume_key_len,
	const struct luks2_keyslot_params *params)
{
	struct luks2_hdr *hdr;
	uint64_t area_offset, area_length;
	json_object *jobj_keyslots, *jobj_keyslot, *jobj_af, *jobj_area;
	int r;

	log_dbg(cd, "Trying to allocate LUKS2 keyslot %d.", keyslot);

	if (!params || params->area_type != LUKS2_KEYSLOT_AREA_RAW ||
	    params->af_type != LUKS2_KEYSLOT_AF_LUKS1) {
		log_dbg(cd, "Invalid LUKS2 keyslot parameters.");
		return -EINVAL;
	}

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	if (keyslot == CRYPT_ANY_SLOT)
		keyslot = LUKS2_keyslot_find_empty(hdr);

	if (keyslot < 0 || keyslot >= LUKS2_KEYSLOTS_MAX)
		return -ENOMEM;

	if (LUKS2_get_keyslot_jobj(hdr, keyslot)) {
		log_dbg(cd, "Cannot modify already active keyslot %d.", keyslot);
		return -EINVAL;
	}

	if (!json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots))
		return -EINVAL;

	r = LUKS2_find_area_gap(cd, hdr, volume_key_len, &area_offset, &area_length);
	if (r < 0) {
		log_err(cd, _("No space for new keyslot."));
		return r;
	}

	jobj_keyslot = json_object_new_object();
	json_object_object_add(jobj_keyslot, "type", json_object_new_string("luks2"));
	json_object_object_add(jobj_keyslot, "key_size", json_object_new_int(volume_key_len));

	/* AF object */
	jobj_af = json_object_new_object();
	json_object_object_add(jobj_af, "type", json_object_new_string("luks1"));
	json_object_object_add(jobj_af, "stripes", json_object_new_int(params->af.luks1.stripes));
	json_object_object_add(jobj_keyslot, "af", jobj_af);

	/* Area object */
	jobj_area = json_object_new_object();
	json_object_object_add(jobj_area, "type", json_object_new_string("raw"));
	json_object_object_add(jobj_area, "offset", json_object_new_uint64(area_offset));
	json_object_object_add(jobj_area, "size", json_object_new_uint64(area_length));
	json_object_object_add(jobj_keyslot, "area", jobj_area);

	json_object_object_add_by_uint(jobj_keyslots, keyslot, jobj_keyslot);

	r = luks2_keyslot_update_json(cd, jobj_keyslot, params);

	if (!r && LUKS2_check_json_size(cd, hdr)) {
		log_dbg(cd, "Not enough space in header json area for new keyslot.");
		r = -ENOSPC;
	}

	if (r)
		json_object_object_del_by_uint(jobj_keyslots, keyslot);

	return r;
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

	log_dbg(cd, "Trying to open LUKS2 keyslot %d.", keyslot);

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	return luks2_keyslot_get_key(cd, jobj_keyslot,
				     password, password_len,
				     volume_key, volume_key_len);
}

/*
 * This function must not modify json.
 * It's called after luks2 keyslot validation.
 */
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

	log_dbg(cd, "Calculating attributes for LUKS2 keyslot %d.", keyslot);

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	if ((r = device_write_lock(cd, crypt_metadata_device(cd)))) {
		log_err(cd, _("Failed to acquire write lock on device %s."),
			device_path(crypt_metadata_device(cd)));
		return r;
	}

	r = luks2_keyslot_set_key(cd, jobj_keyslot,
				  password, password_len,
				  volume_key, volume_key_len);
	if (!r)
		r = LUKS2_hdr_write(cd, hdr);

	device_write_unlock(cd, crypt_metadata_device(cd));

	return r < 0 ? r : keyslot;
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

	json_object_object_get_ex(jobj_area, "key_size", &jobj1);
	log_std(cd, "\tCipher key: %u bits\n", json_object_get_uint32(jobj1) * 8);

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

	json_object_object_get_ex(jobj_af, "hash", &jobj1);
	log_std(cd, "\tAF hash:    %s\n", json_object_get_string(jobj1));

	json_object_object_get_ex(jobj_area, "offset", &jobj1);
	log_std(cd, "\tArea offset:%" PRIu64 " [bytes]\n", json_object_get_uint64(jobj1));

	json_object_object_get_ex(jobj_area, "size", &jobj1);
	log_std(cd, "\tArea length:%" PRIu64 " [bytes]\n", json_object_get_uint64(jobj1));

	return 0;
}

static int luks2_keyslot_validate(struct crypt_device *cd, json_object *jobj_keyslot)
{
	json_object *jobj_kdf, *jobj_af, *jobj_area, *jobj1;
	const char *type;
	int count;

	if (!jobj_keyslot)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf) ||
	    !json_object_object_get_ex(jobj_keyslot, "af", &jobj_af) ||
	    !json_object_object_get_ex(jobj_keyslot, "area", &jobj_area))
		return -EINVAL;

	count = json_object_object_length(jobj_kdf);

	jobj1 = json_contains(cd, jobj_kdf, "", "kdf section", "type", json_type_string);
	if (!jobj1)
		return -EINVAL;
	type = json_object_get_string(jobj1);

	if (!strcmp(type, CRYPT_KDF_PBKDF2)) {
		if (count != 4 || /* type, salt, hash, iterations only */
		    !json_contains(cd, jobj_kdf, "kdf type", type, "hash", json_type_string) ||
		    !json_contains(cd, jobj_kdf, "kdf type", type, "iterations", json_type_int) ||
		    !json_contains(cd, jobj_kdf, "kdf type", type, "salt", json_type_string))
			return -EINVAL;
	} else if (!strcmp(type, CRYPT_KDF_ARGON2I) || !strcmp(type, CRYPT_KDF_ARGON2ID)) {
		if (count != 5 || /* type, salt, time, memory, cpus only */
		    !json_contains(cd, jobj_kdf, "kdf type", type, "time", json_type_int) ||
		    !json_contains(cd, jobj_kdf, "kdf type", type, "memory", json_type_int) ||
		    !json_contains(cd, jobj_kdf, "kdf type", type, "cpus", json_type_int) ||
		    !json_contains(cd, jobj_kdf, "kdf type", type, "salt", json_type_string))
			return -EINVAL;
	}

	if (!json_object_object_get_ex(jobj_af, "type", &jobj1))
		return -EINVAL;
	if (!strcmp(json_object_get_string(jobj1), "luks1")) {
		if (!json_contains(cd, jobj_af, "", "luks1 af", "hash", json_type_string) ||
		    !json_contains(cd, jobj_af, "", "luks1 af", "stripes", json_type_int))
			return -EINVAL;
	} else
		return -EINVAL;

	// FIXME check numbered
	if (!json_object_object_get_ex(jobj_area, "type", &jobj1))
		return -EINVAL;
	if (!strcmp(json_object_get_string(jobj1), "raw")) {
		if (!json_contains(cd, jobj_area, "area", "raw type", "encryption", json_type_string) ||
		    !json_contains(cd, jobj_area, "area", "raw type", "key_size", json_type_int) ||
		    !json_contains(cd, jobj_area, "area", "raw type", "offset", json_type_string) ||
		    !json_contains(cd, jobj_area, "area", "raw type", "size", json_type_string))
			return -EINVAL;
	} else
		return -EINVAL;

	return 0;
}

static int luks2_keyslot_update(struct crypt_device *cd,
	int keyslot,
	const struct luks2_keyslot_params *params)
{
	struct luks2_hdr *hdr;
	json_object *jobj_keyslot;
	int r;

	log_dbg(cd, "Updating LUKS2 keyslot %d.", keyslot);

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, keyslot);
	if (!jobj_keyslot)
		return -EINVAL;

	r = luks2_keyslot_update_json(cd, jobj_keyslot, params);

	if (!r && LUKS2_check_json_size(cd, hdr)) {
		log_dbg(cd, "Not enough space in header json area for updated keyslot %d.", keyslot);
		r = -ENOSPC;
	}

	return r;
}

static void luks2_keyslot_repair(struct crypt_device *cd, json_object *jobj_keyslot)
{
	const char *type;
	json_object *jobj_kdf, *jobj_type;

	if (!json_object_object_get_ex(jobj_keyslot, "kdf", &jobj_kdf) ||
	    !json_object_is_type(jobj_kdf, json_type_object))
		return;

	if (!json_object_object_get_ex(jobj_kdf, "type", &jobj_type) ||
	    !json_object_is_type(jobj_type, json_type_string))
		return;

	type = json_object_get_string(jobj_type);

	if (!strcmp(type, CRYPT_KDF_PBKDF2)) {
		/* type, salt, hash, iterations only */
		json_object_object_foreach(jobj_kdf, key, val) {
			UNUSED(val);
			if (!strcmp(key, "type") || !strcmp(key, "salt") ||
			    !strcmp(key, "hash") || !strcmp(key, "iterations"))
					continue;
			json_object_object_del(jobj_kdf, key);
		}
	} else if (!strcmp(type, CRYPT_KDF_ARGON2I) || !strcmp(type, CRYPT_KDF_ARGON2ID)) {
		/* type, salt, time, memory, cpus only */
		json_object_object_foreach(jobj_kdf, key, val) {
			UNUSED(val);
			if (!strcmp(key, "type") || !strcmp(key, "salt") ||
			    !strcmp(key, "time") || !strcmp(key, "memory") ||
			    !strcmp(key, "cpus"))
					continue;
			json_object_object_del(jobj_kdf, key);
		}
	}
}

const keyslot_handler luks2_keyslot = {
	.name  = "luks2",
	.alloc  = luks2_keyslot_alloc,
	.update = luks2_keyslot_update,
	.open  = luks2_keyslot_open,
	.store = luks2_keyslot_store,
	.wipe  = luks2_keyslot_wipe,
	.dump  = luks2_keyslot_dump,
	.validate = luks2_keyslot_validate,
	.repair = luks2_keyslot_repair
};
