/*
 * LUKS - Linux Unified Key Setup v2, PBKDF2 digest handler (LUKS1 compatible)
 *
 * Copyright (C) 2015-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2015-2020 Milan Broz
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

#define LUKS_DIGESTSIZE 20 // since SHA1
#define LUKS_SALTSIZE 32
#define LUKS_MKD_ITERATIONS_MS 125

static int PBKDF2_digest_verify(struct crypt_device *cd,
	int digest,
	const char *volume_key,
	size_t volume_key_len)
{
	char checkHashBuf[64];
	json_object *jobj_digest, *jobj1;
	const char *hashSpec;
	char *mkDigest = NULL, mkDigestSalt[LUKS_SALTSIZE];
	unsigned int mkDigestIterations;
	size_t len;
	int r;

	/* This can be done only for internally linked digests */
	jobj_digest = LUKS2_get_digest_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), digest);
	if (!jobj_digest)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_digest, "hash", &jobj1))
		return -EINVAL;
	hashSpec = json_object_get_string(jobj1);

	if (!json_object_object_get_ex(jobj_digest, "iterations", &jobj1))
		return -EINVAL;
	mkDigestIterations = json_object_get_int64(jobj1);

	if (!json_object_object_get_ex(jobj_digest, "salt", &jobj1))
		return -EINVAL;
	len = sizeof(mkDigestSalt);
	if (!base64_decode(json_object_get_string(jobj1),
			   json_object_get_string_len(jobj1), mkDigestSalt, &len))
		return -EINVAL;
	if (len != LUKS_SALTSIZE)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_digest, "digest", &jobj1))
		return -EINVAL;
	len = 0;
	if (!base64_decode_alloc(json_object_get_string(jobj1),
			   json_object_get_string_len(jobj1), &mkDigest, &len))
		return -EINVAL;
	if (len < LUKS_DIGESTSIZE ||
	    len > sizeof(checkHashBuf) ||
	    (len != LUKS_DIGESTSIZE && len != (size_t)crypt_hash_size(hashSpec))) {
		free(mkDigest);
		return -EINVAL;
	}

	r = -EPERM;
	if (crypt_pbkdf(CRYPT_KDF_PBKDF2, hashSpec, volume_key, volume_key_len,
			mkDigestSalt, LUKS_SALTSIZE,
			checkHashBuf, len,
			mkDigestIterations, 0, 0) < 0) {
		r = -EINVAL;
	} else {
		if (memcmp(checkHashBuf, mkDigest, len) == 0)
			r = 0;
	}

	free(mkDigest);
	return r;
}

static int PBKDF2_digest_store(struct crypt_device *cd,
	int digest,
	const char *volume_key,
	size_t volume_key_len)
{
	json_object *jobj_digest, *jobj_digests;
	char salt[LUKS_SALTSIZE], digest_raw[128];
	int hmac_size, r;
	char *base64_str;
	struct luks2_hdr *hdr;
	struct crypt_pbkdf_limits pbkdf_limits;
	const struct crypt_pbkdf_type *pbkdf_cd;
	struct crypt_pbkdf_type pbkdf = {
		.type = CRYPT_KDF_PBKDF2,
		.time_ms = LUKS_MKD_ITERATIONS_MS,
	};

	/* Inherit hash from PBKDF setting */
	pbkdf_cd = crypt_get_pbkdf_type(cd);
	if (pbkdf_cd)
		pbkdf.hash = pbkdf_cd->hash;
	if (!pbkdf.hash)
		pbkdf.hash = DEFAULT_LUKS1_HASH;

	log_dbg(cd, "Setting PBKDF2 type key digest %d.", digest);

	r = crypt_random_get(cd, salt, LUKS_SALTSIZE, CRYPT_RND_SALT);
	if (r < 0)
		return r;

	r = crypt_pbkdf_get_limits(CRYPT_KDF_PBKDF2, &pbkdf_limits);
	if (r < 0)
		return r;

	if (crypt_get_pbkdf(cd)->flags & CRYPT_PBKDF_NO_BENCHMARK)
		pbkdf.iterations = pbkdf_limits.min_iterations;
	else {
		r = crypt_benchmark_pbkdf_internal(cd, &pbkdf, volume_key_len);
		if (r < 0)
			return r;
	}

	hmac_size = crypt_hmac_size(pbkdf.hash);
	if (hmac_size < 0 || hmac_size > (int)sizeof(digest_raw))
		return -EINVAL;

	r = crypt_pbkdf(CRYPT_KDF_PBKDF2, pbkdf.hash, volume_key, volume_key_len,
			salt, LUKS_SALTSIZE, digest_raw, hmac_size,
			pbkdf.iterations, 0, 0);
	if (r < 0)
		return r;

	jobj_digest = LUKS2_get_digest_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), digest);
	jobj_digests = NULL;
	if (!jobj_digest) {
		hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
		jobj_digest = json_object_new_object();
		json_object_object_get_ex(hdr->jobj, "digests", &jobj_digests);
	}

	json_object_object_add(jobj_digest, "type", json_object_new_string("pbkdf2"));
	json_object_object_add(jobj_digest, "keyslots", json_object_new_array());
	json_object_object_add(jobj_digest, "segments", json_object_new_array());
	json_object_object_add(jobj_digest, "hash", json_object_new_string(pbkdf.hash));
	json_object_object_add(jobj_digest, "iterations", json_object_new_int(pbkdf.iterations));

	base64_encode_alloc(salt, LUKS_SALTSIZE, &base64_str);
	if (!base64_str) {
		json_object_put(jobj_digest);
		return -ENOMEM;
	}
	json_object_object_add(jobj_digest, "salt", json_object_new_string(base64_str));
	free(base64_str);

	base64_encode_alloc(digest_raw, hmac_size, &base64_str);
	if (!base64_str) {
		json_object_put(jobj_digest);
		return -ENOMEM;
	}
	json_object_object_add(jobj_digest, "digest", json_object_new_string(base64_str));
	free(base64_str);

	if (jobj_digests)
		json_object_object_add_by_uint(jobj_digests, digest, jobj_digest);

	JSON_DBG(cd, jobj_digest, "Digest JSON:");
	return 0;
}

static int PBKDF2_digest_dump(struct crypt_device *cd, int digest)
{
	json_object *jobj_digest, *jobj1;

	/* This can be done only for internally linked digests */
	jobj_digest = LUKS2_get_digest_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), digest);
	if (!jobj_digest)
		return -EINVAL;

	json_object_object_get_ex(jobj_digest, "hash", &jobj1);
	log_std(cd, "\tHash:       %s\n", json_object_get_string(jobj1));

	json_object_object_get_ex(jobj_digest, "iterations", &jobj1);
	log_std(cd, "\tIterations: %" PRIu64 "\n", json_object_get_int64(jobj1));

	json_object_object_get_ex(jobj_digest, "salt", &jobj1);
	log_std(cd, "\tSalt:       ");
	hexprint_base64(cd, jobj1, " ", "            ");

	json_object_object_get_ex(jobj_digest, "digest", &jobj1);
	log_std(cd, "\tDigest:     ");
	hexprint_base64(cd, jobj1, " ", "            ");

	return 0;
}

const digest_handler PBKDF2_digest = {
	.name   = "pbkdf2",
	.verify = PBKDF2_digest_verify,
	.store  = PBKDF2_digest_store,
	.dump   = PBKDF2_digest_dump,
};
