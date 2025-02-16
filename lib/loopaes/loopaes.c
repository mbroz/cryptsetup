// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * loop-AES compatible volume handling
 *
 * Copyright (C) 2011-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2011-2025 Milan Broz
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcryptsetup.h"
#include "loopaes.h"
#include "internal.h"

static const char *get_hash(unsigned int key_size)
{
	const char *hash;

	switch (key_size) {
		case 16: hash = "sha256"; break;
		case 24: hash = "sha384"; break;
		case 32: hash = "sha512"; break;
		default: hash = NULL;
	}

	return hash;
}

static unsigned char get_tweak(unsigned int keys_count)
{
	switch (keys_count) {
		case 64: return 0x55;
		case 65: return 0xF4;
		default: break;
	}
	return 0x00;
}

static int hash_key(const char *src, size_t src_len,
		    char *dst, size_t dst_len,
		    const char *hash_name)
{
	struct crypt_hash *hd = NULL;
	int r;

	if (crypt_hash_init(&hd, hash_name))
		return -EINVAL;

	r = crypt_hash_write(hd, src, src_len);
	if (!r)
		r = crypt_hash_final(hd, dst, dst_len);

	crypt_hash_destroy(hd);
	return r;
}

static int hash_keys(struct crypt_device *cd,
		     struct volume_key **vk,
		     const char *hash_override,
		     const char **input_keys,
		     unsigned int keys_count,
		     unsigned int key_len_output,
		     unsigned int key_len_input)
{
	const char *hash_name;
	char tweak, *key_ptr;
	unsigned int i;
	int r = 0;
	void *key = NULL;

	hash_name = hash_override ?: get_hash(key_len_output);
	tweak = get_tweak(keys_count);

	if (!keys_count || !key_len_output || !hash_name || !key_len_input) {
		log_err(cd, _("Key processing error (using hash %s)."),
			hash_name ?: "[none]");
		return -EINVAL;
	}

	key = crypt_safe_alloc((size_t)key_len_output * keys_count);
	if (!key)
		return -ENOMEM;

	for (i = 0; i < keys_count; i++) {
		key_ptr = &((char *)key)[i * key_len_output];
		r = hash_key(input_keys[i], key_len_input, key_ptr,
			     key_len_output, hash_name);
		if (r < 0)
			goto err;

		key_ptr[0] ^= tweak;
	}

	*vk = crypt_alloc_volume_key_by_safe_alloc(&key);
	if (!*vk) {
		r = -ENOMEM;
		goto err;
	}

	return 0;
err:
	crypt_safe_free(key);
	*vk = NULL;
	return r;
}

static int keyfile_is_gpg(char *buffer, size_t buffer_len)
{
	int r = 0;
	int index = buffer_len < 100 ? buffer_len - 1 : 100;
	char eos = buffer[index];

	buffer[index] = '\0';
	if (strstr(buffer, "BEGIN PGP MESSAGE"))
		r = 1;
	buffer[index] = eos;
	return r;
}

int LOOPAES_parse_keyfile(struct crypt_device *cd,
			  struct volume_key **vk,
			  const char *hash,
			  unsigned int *keys_count,
			  char *buffer,
			  size_t buffer_len)
{
	const char *keys[LOOPAES_KEYS_MAX];
	unsigned int key_lengths[LOOPAES_KEYS_MAX];
	unsigned int i, key_index, key_len, offset;

	log_dbg(cd, "Parsing loop-AES keyfile of size %zu.", buffer_len);

	if (!buffer_len)
		return -EINVAL;

	if (keyfile_is_gpg(buffer, buffer_len)) {
		log_err(cd, _("Detected not yet supported GPG encrypted keyfile."));
		log_std(cd, _("Please use gpg --decrypt <KEYFILE> | cryptsetup --keyfile=- ...\n"));
		return -EINVAL;
	}

	/* Remove EOL in buffer */
	for (i = 0; i < buffer_len; i++)
		if (buffer[i] == '\n' || buffer[i] == '\r')
			buffer[i] = '\0';

	offset = 0;
	key_index = 0;
	key_lengths[0] = 0;
	while (offset < buffer_len && key_index < LOOPAES_KEYS_MAX) {
		keys[key_index] = &buffer[offset];
		key_lengths[key_index] = 0;
		while (offset < buffer_len && buffer[offset]) {
			offset++;
			key_lengths[key_index]++;
		}
		if (offset == buffer_len) {
			log_dbg(cd, "Unterminated key #%d in keyfile.", key_index);
			log_err(cd, _("Incompatible loop-AES keyfile detected."));
			return -EINVAL;
		}
		while (offset < buffer_len && !buffer[offset])
			offset++;
		key_index++;
	}

	/* All keys must be the same length */
	key_len = key_lengths[0];
	for (i = 0; i < key_index; i++)
		if (!key_lengths[i] || (key_lengths[i] != key_len)) {
			log_dbg(cd, "Unexpected length %d of key #%d (should be %d).",
				key_lengths[i], i, key_len);
			key_len = 0;
			break;
		}

	if (offset != buffer_len || key_len == 0 ||
	   (key_index != 1 && key_index !=64 && key_index != 65)) {
		log_err(cd, _("Incompatible loop-AES keyfile detected."));
		return -EINVAL;
	}

	log_dbg(cd, "Keyfile: %d keys of length %d.", key_index, key_len);

	*keys_count = key_index;
	return hash_keys(cd, vk, hash, keys, key_index,
			 crypt_get_volume_key_size(cd), key_len);
}

int LOOPAES_activate(struct crypt_device *cd,
		     const char *name,
		     const char *base_cipher,
		     unsigned int keys_count,
		     struct volume_key *vk,
		     uint32_t flags)
{
	int r;
	uint32_t req_flags, dmc_flags;
	char *cipher = NULL;
	struct crypt_dm_active_device dmd = {
		.flags = flags,
	};

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_EXCL,
				crypt_get_data_offset(cd), &dmd.size, &dmd.flags);
	if (r)
		return r;

	if (keys_count == 1) {
		req_flags = DM_PLAIN64_SUPPORTED;
		r = asprintf(&cipher, "%s-%s", base_cipher, "cbc-plain64");
	} else {
		req_flags = DM_LMK_SUPPORTED;
		r = asprintf(&cipher, "%s:%d-%s", base_cipher, 64, "cbc-lmk");
	}
	if (r < 0)
		return -ENOMEM;

	r = dm_crypt_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd),
			vk, cipher, crypt_get_iv_offset(cd), crypt_get_data_offset(cd),
			NULL, 0, 0, crypt_get_sector_size(cd));

	if (r) {
		free(cipher);
		return r;
	}

	log_dbg(cd, "Trying to activate loop-AES device %s using cipher %s.",
		name, cipher);

	r = dm_create_device(cd, name, CRYPT_LOOPAES, &dmd);

	if (r < 0 && !dm_flags(cd, DM_CRYPT, &dmc_flags) &&
	    (dmc_flags & req_flags) != req_flags) {
		log_err(cd, _("Kernel does not support loop-AES compatible mapping."));
		r = -ENOTSUP;
	}

	dm_targets_free(cd, &dmd);
	free(cipher);

	return r;
}
