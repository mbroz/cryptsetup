/*
 * TCRYPT compatible volume handling
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012, Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "libcryptsetup.h"
#include "tcrypt.h"
#include "internal.h"

/* TCRYPT PBKDF variants */
static struct {
	unsigned int legacy:1;
	char *name;
	char *hash;
	unsigned int iterations;
} tcrypt_kdf[] = {
	{ 0, "pbkdf2", "ripemd160", 2000 },
	{ 0, "pbkdf2", "ripemd160", 1000 },
	{ 0, "pbkdf2", "sha512",    1000 },
	{ 0, "pbkdf2", "whirlpool", 1000 },
	{ 1, "pbkdf2", "sha1",      2000 },
	{ 0, NULL,     NULL,           0 }
};

struct tcrypt_alg {
		const char *name;
		unsigned int key_size;
		unsigned int iv_size;
};

/* TCRYPT cipher variants */
static struct {
	unsigned int legacy:1;
	const char *mode;
	struct tcrypt_alg cipher[3];
} tcrypt_cipher[] = {
	{ 0, "xts-plain64",{{"aes",    64,16}}},
	{ 0, "xts-plain64",{{"serpent",64,16}}},
	{ 0, "xts-plain64",{{"twofish",64,16}}},
	{ 0, "xts-plain64",{{"twofish",64,16},{"aes",    64,16}}},
	{ 0, "xts-plain64",{{"serpent",64,16},{"twofish",64,16},{"aes",    64,16}}},
	{ 0, "xts-plain64",{{"aes",    64,16},{"serpent",64,16}}},
	{ 0, "xts-plain64",{{"aes",    64,16},{"twofish",64,16},{"serpent",64,16}}},
	{ 0, "xts-plain64",{{"serpent",64,16},{"twofish",64,16}}},

	{ 0, "lrw-benbi",  {{"aes",    48,16}}},
	{ 0, "lrw-benbi",  {{"serpent",48,16}}},
	{ 0, "lrw-benbi",  {{"twofish",48,16}}},
	{ 0, "lrw-benbi",  {{"twofish",48,16},{"aes",    48,16}}},
	{ 0, "lrw-benbi",  {{"serpent",48,16},{"twofish",48,16},{"aes",    48,16}}},
	{ 0, "lrw-benbi",  {{"aes",    48,16},{"serpent",48,16}}},
	{ 0, "lrw-benbi",  {{"aes",    48,16},{"twofish",48,16},{"serpent",48,16}}},
	{ 0, "lrw-benbi",  {{"serpent",48,16},{"twofish",48,16}}},

	{ 1, "cbc-tcrypt", {{"aes",    32,16}}},
	{ 1, "cbc-tcrypt", {{"serpent",32,16}}},
	{ 1, "cbc-tcrypt", {{"twofish",32,16}}},
	{ 1, "cbci-tcrypt",{{"twofish",32,16},{"aes",    32,16}}},
	{ 1, "cbci-tcrypt",{{"serpent",32,16},{"twofish",32,16},{"aes",    32,16}}},
	{ 1, "cbci-tcrypt",{{"aes",    32,16},{"serpent",32,16}}},
	{ 1, "cbci-tcrypt",{{"aes",    32,16},{"twofish",32,16},{"serpent",32,16}}},
	{ 1, "cbci-tcrypt",{{"serpent",32,16},{"twofish",32,16}}},

	{ 1, "cbc-tcrypt", {{"cast5",   16,8}}},
	{ 1, "cbc-tcrypt", {{"des3_ede",24,8}}},

	// kernel LRW block size is fixed to 16 bytes
	// thus cannot be used with blowfish where block is 8 bytes
	//{ 1,"lrw-benbi",{{"blowfish",64,8}}},
	//{ 1,"lrw-benbi",{{"blowfish",64,8},{"aes",48,16}}},
	//{ 1,"lrw-benbi",{{"serpent",48,16},{"blowfish",64,8},{"aes",48,16}}},

	// FIXME: why this doesn't work (blowfish key wrong)?
	//{ 1,"cbc-tcrypt",{{"blowfish",56,8}}},
	//{ 1,"cbc-tcrypt",{{"blowfish",56,8},{"aes",32,16}}},
	//{ 1,"cbc-tcrypt",{{"serpent",32,16},{"blowfish",56,8},{"aes",32,16}}},
	{}
};

static void hdr_info(struct crypt_device *cd, struct tcrypt_phdr *hdr,
		     struct crypt_params_tcrypt *params)
{
	log_dbg("Version: %d, required %d", (int)hdr->d.version, (int)hdr->d.version_tc);

	log_dbg("Hidden size: %" PRIu64, hdr->d.hidden_volume_size);
	log_dbg("Volume size: %" PRIu64, hdr->d.volume_size);

	log_dbg("Sector size: %" PRIu64, hdr->d.sector_size);
	log_dbg("Flags: %d", (int)hdr->d.flags);
	log_dbg("MK: offset %d, size %d", (int)hdr->d.mk_offset, (int)hdr->d.mk_size);
	log_dbg("KDF: PBKDF2, hash %s", params->hash_name);
	log_dbg("Cipher: %s%s%s%s%s-%s",
		params->cipher[0],
		params->cipher[1] ? "-" : "", params->cipher[1] ?: "",
		params->cipher[2] ? "-" : "", params->cipher[2] ?: "",
		params->mode);
}

static int hdr_from_disk(struct tcrypt_phdr *hdr,
			 struct crypt_params_tcrypt *params,
			 int kdf_index, int cipher_index)
{
	uint32_t crc32;
	size_t size;

	/* Check CRC32 of header */
	size = TCRYPT_HDR_LEN - sizeof(hdr->d.keys) - sizeof(hdr->d.header_crc32);
	crc32 = crypt_crc32(~0, (unsigned char*)&hdr->d, size) ^ ~0;
	if (be16_to_cpu(hdr->d.version) > 3 &&
	    crc32 != be32_to_cpu(hdr->d.header_crc32)) {
		log_dbg("TCRYPT header CRC32 mismatch.");
		return -EINVAL;
	}

	/* Check CRC32 of keys */
	crc32 = crypt_crc32(~0, (unsigned char*)hdr->d.keys, sizeof(hdr->d.keys)) ^ ~0;
	if (crc32 != be32_to_cpu(hdr->d.keys_crc32)) {
		log_dbg("TCRYPT keys CRC32 mismatch.");
		return -EINVAL;
	}

	/* Convert header to cpu format */
	hdr->d.version  =  be16_to_cpu(hdr->d.version);
	hdr->d.version_tc = le16_to_cpu(hdr->d.version_tc); // ???

	hdr->d.keys_crc32 = be32_to_cpu(hdr->d.keys_crc32);

	hdr->d.hidden_volume_size = be64_to_cpu(hdr->d.hidden_volume_size);
	hdr->d.volume_size        = be64_to_cpu(hdr->d.volume_size);

	hdr->d.mk_offset = be64_to_cpu(hdr->d.mk_offset);
	if (!hdr->d.mk_offset)
		hdr->d.mk_offset = 512;

	hdr->d.mk_size = be64_to_cpu(hdr->d.mk_size);

	hdr->d.flags = be32_to_cpu(hdr->d.flags);

	hdr->d.sector_size = be32_to_cpu(hdr->d.sector_size);
	if (!hdr->d.sector_size)
		hdr->d.sector_size = 512;

	hdr->d.header_crc32 = be32_to_cpu(hdr->d.header_crc32);

	/* Set params */
	params->passphrase = NULL;
	params->passphrase_size = 0;

	params->hash_name  = tcrypt_kdf[kdf_index].hash;

	params->cipher[0]  = tcrypt_cipher[cipher_index].cipher[0].name;
	params->cipher[1]  = tcrypt_cipher[cipher_index].cipher[1].name;
	params->cipher[2]  = tcrypt_cipher[cipher_index].cipher[2].name;
	params->mode     = tcrypt_cipher[cipher_index].mode;
	params->key_size = tcrypt_cipher[cipher_index].cipher[0].key_size; //fixme

	return 0;
}

static int decrypt_hdr_one(const char *name, const char *mode,
			   const char *key, size_t key_size,
			   size_t iv_size, struct tcrypt_phdr *hdr)
{
	char iv[TCRYPT_HDR_IV_LEN] = {};
	char mode_name[MAX_CIPHER_LEN];
	struct crypt_cipher *cipher;
	char *c, *buf = (char*)&hdr->e;
	int r;

	/* Remove IV if present */
	strncpy(mode_name, mode, MAX_CIPHER_LEN);
	c = strchr(mode_name, '-');
	if (c)
		*c = '\0';

	if (!strncmp(mode, "lrw", 3))
		iv[iv_size - 1] = 1;
	else if (!strncmp(mode, "cbc", 3))
		memcpy(iv, &key[key_size], iv_size);

	r = crypt_cipher_init(&cipher, name, mode_name, key, key_size);
	if (r < 0)
		return r;

	r = crypt_cipher_decrypt(cipher, buf, buf, TCRYPT_HDR_LEN, iv, iv_size);
	crypt_cipher_destroy(cipher);

	return r;
}

static void copy_key(char *out_key, const char *key, int key_num,
		     int ks, int ki, const char *mode)
{
	if (!strncmp(mode, "xts", 3)) {
		int ks2 = ks / 2;
		memcpy(out_key, &key[ks2 * ki], ks2);
		memcpy(&out_key[ks2], &key[ks2 * (++key_num + ki)], ks2);
	} else if (!strncmp(mode, "lrw", 3)) {
		/* First is LRW index key */
		ki++;
		ks -= TCRYPT_LRW_IKEY_LEN;
		memcpy(out_key, &key[ks * ki], ks);
		memcpy(&out_key[ks * ki], key, TCRYPT_LRW_IKEY_LEN);
	} else if (!strncmp(mode, "cbc", 3)) {
		ki++;
		memcpy(out_key, &key[ki * 32], ks);
		memcpy(&out_key[ks], key, 32);
	}
}

/*
 * For chanined ciphers and CBC mode we need "inner" decryption.
 * Backend doesn't provide this, so implement it here directly using ECB.
 */
static int decrypt_hdr_cbci(struct tcrypt_alg ciphers[3],
			     const char *key, struct tcrypt_phdr *hdr)
{
	struct crypt_cipher *cipher[3] = {};
	int bs = ciphers[0].iv_size;
	char *buf = (char*)&hdr->e, iv[bs], iv_old[bs];
	int i, j, r;

	memcpy(iv, key, bs);

	/* Initialize all ciphers in chain in ECB mode */
	for (j = 0; j < 3; j++) {
		if (!ciphers[j].name)
			continue;
		r = crypt_cipher_init(&cipher[j], ciphers[j].name, "ecb",
				      &key[(j+1)*32], ciphers[j].key_size);
		if (r < 0)
			goto out;
	}

	/* Implements CBC with chained ciphers in inner loop */
	for (i = 0; i < TCRYPT_HDR_LEN; i += bs) {
		memcpy(iv_old, &buf[i], bs);
		for (j = 2; j >= 0; j--) {
			if (!cipher[j])
				continue;
			r = crypt_cipher_decrypt(cipher[j], &buf[i], &buf[i],
						  bs, NULL, 0);
			if (r < 0)
				goto out;
		}
		for (j = 0; j < bs; j++)
			buf[i + j] ^= iv[j];
		memcpy(iv, iv_old, bs);
	}
out:
	for (j = 0; j < 3; j++)
		if (cipher[j])
			crypt_cipher_destroy(cipher[j]);

	return r;
}

static int top_cipher(struct tcrypt_alg cipher[3])
{
	if (cipher[2].name)
		return 2;

	if (cipher[1].name)
		return 1;

	return 0;
}

static int decrypt_hdr(struct crypt_device *cd, struct tcrypt_phdr *hdr,
			const char *key, int legacy_modes)
{
	char one_key[TCRYPT_HDR_KEY_LEN];
	struct tcrypt_phdr hdr2;
	int i, j, r;

	for (i = 0; tcrypt_cipher[i].cipher[0].name; i++) {
		if (!legacy_modes && tcrypt_cipher[i].legacy)
			continue;
		log_dbg("TCRYPT:  trying cipher: %s%s%s%s%s-%s.",
			tcrypt_cipher[i].cipher[0].name,
			tcrypt_cipher[i].cipher[1].name ? "-" : "", tcrypt_cipher[i].cipher[1].name ?: "",
			tcrypt_cipher[i].cipher[2].name ? "-" : "", tcrypt_cipher[i].cipher[2].name ?: "",
			tcrypt_cipher[i].mode);

		memcpy(&hdr2.e, &hdr->e, TCRYPT_HDR_LEN);

		/* Remove CBC whitening */
		if (!strncmp(tcrypt_cipher[i].mode, "cbc", 3)) {
			char *buf = (char*)&hdr2.e;
			for (j = 0; j < TCRYPT_HDR_LEN; j++)
				buf[j] ^= key[8 + j % 8];
		}

		/* For chained (inner) CBC we do not have API support */
		if (!strncmp(tcrypt_cipher[i].mode, "cbci", 4))
			r = decrypt_hdr_cbci(tcrypt_cipher[i].cipher, key, &hdr2);
		else for (j = 2; j >= 0 ; j--) {
			if (!tcrypt_cipher[i].cipher[j].name)
				continue;
			copy_key(one_key, key, top_cipher(tcrypt_cipher[i].cipher),
				 tcrypt_cipher[i].cipher[j].key_size,
				 j, tcrypt_cipher[i].mode);
			r = decrypt_hdr_one(tcrypt_cipher[i].cipher[j].name,
					    tcrypt_cipher[i].mode, one_key,
					    tcrypt_cipher[i].cipher[j].key_size,
					    tcrypt_cipher[i].cipher[j].iv_size, &hdr2);
			if (r < 0) {
				log_dbg("Error %s.", tcrypt_cipher[i].cipher[j].name);
				break;
			}
		}

		if (!strncmp(hdr2.d.magic, TCRYPT_HDR_MAGIC, TCRYPT_HDR_MAGIC_LEN)) {
			log_dbg("TCRYPT: Signature magic detected.");
			memcpy(&hdr->e, &hdr2.e, TCRYPT_HDR_LEN);
			memset(&hdr2.e, 0, TCRYPT_HDR_LEN);
			r = i;
			break;
		}
		r = -EPERM;
	}

	memset(one_key, 0, sizeof(*one_key));
	return r;
}

static int pool_keyfile(struct crypt_device *cd,
			unsigned char pool[TCRYPT_KEY_POOL_LEN],
			const char *keyfile)
{
	unsigned char data[TCRYPT_KEYFILE_LEN];
	int i, j, fd, data_size;
	uint32_t crc;
	unsigned char *crc_c = (unsigned char*)&crc;

	log_dbg("TCRYPT: using keyfile %s.", keyfile);

	fd = open(keyfile, O_RDONLY);
	if (fd < 0) {
		log_err(cd, _("Failed to open key file.\n"));
		return -EIO;
	}

	/* FIXME: add while */
	data_size = read(fd, data, TCRYPT_KEYFILE_LEN);
	close(fd);
	if (data_size < 0) {
		log_err(cd, _("Error reading keyfile %s.\n"), keyfile);
		return -EIO;
	}

	for (i = 0, j = 0, crc = ~0U; i < data_size; i++) {
		crc = crypt_crc32(crc, &data[i], 1);
		pool[j++] += crc_c[3];
		pool[j++] += crc_c[2];
		pool[j++] += crc_c[1];
		pool[j++] += crc_c[0];
		j %= TCRYPT_KEY_POOL_LEN;
	}

	crc = 0;
	memset(data, 0, TCRYPT_KEYFILE_LEN);

	return 0;
}

static int TCRYPT_init_hdr(struct crypt_device *cd,
			   struct tcrypt_phdr *hdr,
			   struct crypt_params_tcrypt *params)
{
	unsigned char pwd[TCRYPT_KEY_POOL_LEN] = {};
	size_t passphrase_size;
	char *key;
	int r, i, legacy_modes;

	if (posix_memalign((void*)&key, crypt_getpagesize(), TCRYPT_HDR_KEY_LEN))
		return -ENOMEM;

	if (params->keyfiles_count)
		passphrase_size = TCRYPT_KEY_POOL_LEN;
	else
		passphrase_size = params->passphrase_size;

	/* Calculate pool content from keyfiles */
	for (i = 0; i < params->keyfiles_count; i++) {
		r = pool_keyfile(cd, pwd, params->keyfiles[i]);
		if (r < 0)
			goto out;
	}

	/* If provided password, combine it with pool */
	for (i = 0; i < params->passphrase_size; i++)
		pwd[i] += params->passphrase[i];

	legacy_modes = params->flags & CRYPT_TCRYPT_LEGACY_MODES ? 1 : 0;
	for (i = 0; tcrypt_kdf[i].name; i++) {
		if (!legacy_modes && tcrypt_kdf[i].legacy)
			continue;
		/* Derive header key */
		log_dbg("TCRYPT: trying KDF: %s-%s-%d.",
			tcrypt_kdf[i].name, tcrypt_kdf[i].hash, tcrypt_kdf[i].iterations);
		r = crypt_pbkdf(tcrypt_kdf[i].name, tcrypt_kdf[i].hash,
				(char*)pwd, passphrase_size,
				hdr->salt, TCRYPT_HDR_SALT_LEN,
				key, TCRYPT_HDR_KEY_LEN,
				tcrypt_kdf[i].iterations);
		if (r < 0)
			break;

		/* Decrypt header */
		r = decrypt_hdr(cd, hdr, key, legacy_modes);
		if (r != -EPERM)
			break;
	}

	if (r < 0)
		goto out;

	r = hdr_from_disk(hdr, params, i, r);
	if (r < 0)
		goto out;

	hdr_info(cd, hdr, params);
out:
	memset(pwd, 0, TCRYPT_KEY_POOL_LEN);
	if (key)
		memset(key, 0, TCRYPT_HDR_KEY_LEN);
	free(key);
	return r;
}

int TCRYPT_read_phdr(struct crypt_device *cd,
		     struct tcrypt_phdr *hdr,
		     struct crypt_params_tcrypt *params)
{
	struct device *device = crypt_metadata_device(cd);
	ssize_t hdr_size = sizeof(struct tcrypt_phdr);
	int devfd = 0, r;

	assert(sizeof(struct tcrypt_phdr) == 512);

	log_dbg("Reading TCRYPT header of size %d bytes from device %s.",
		hdr_size, device_path(device));

	devfd = open(device_path(device), O_RDONLY | O_DIRECT);
	if (devfd == -1) {
		log_err(cd, _("Cannot open device %s.\n"), device_path(device));
		return -EINVAL;
	}

	if ((params->flags & CRYPT_TCRYPT_HIDDEN_HEADER) &&
	    lseek(devfd, TCRYPT_HDR_HIDDEN_OFFSET, SEEK_SET) < 0) {
		log_err(cd, _("Cannot seek to hidden header for %s.\n"), device_path(device));
		close(devfd);
		return -EIO;
	}

	if (read_blockwise(devfd, device_block_size(device), hdr, hdr_size) == hdr_size)
		r = TCRYPT_init_hdr(cd, hdr, params);
	else
		r = -EIO;

	close(devfd);
	return r;
}

int TCRYPT_activate(struct crypt_device *cd,
		     const char *name,
		     struct tcrypt_phdr *hdr,
		     struct crypt_params_tcrypt *params,
		     uint32_t flags)
{
	char cipher[MAX_CIPHER_LEN], dm_name[PATH_MAX], dm_dev_name[PATH_MAX];
	struct device *device = NULL;
	int i, r;
	struct tcrypt_alg tcipher[3] = {
		{ params->cipher[0], params->key_size, 0 },
		{ params->cipher[1], params->key_size, 0 },
		{ params->cipher[2], params->key_size, 0 }
	};
	struct crypt_dm_active_device dmd = {
		.target = DM_CRYPT,
		.size   = 0,
		.data_device = crypt_data_device(cd),
		.u.crypt  = {
			.cipher = cipher,
			.offset = crypt_get_data_offset(cd),
			.iv_offset = crypt_get_iv_offset(cd),
		}
	};

	if (strstr(params->mode, "-tcrypt")) {
		log_err(cd, _("Kernel doesn't support activation for this TCRYPT legacy mode.\n"));
		return -ENOTSUP;
	}

	r = device_block_adjust(cd, dmd.data_device, DEV_EXCL,
				dmd.u.crypt.offset, &dmd.size, &dmd.flags);
	if (r)
		return r;

	dmd.u.crypt.vk = crypt_alloc_volume_key(params->key_size, NULL);
	if (!dmd.u.crypt.vk)
		return -ENOMEM;

	for (i = 2; i >= 0; i--) {

		if (!params->cipher[i])
			continue;

		if (i == 0) {
			strncpy(dm_name, name, sizeof(dm_name));
			dmd.flags = flags;
		} else {
			snprintf(dm_name, sizeof(dm_name), "%s_%d", name, i);
			dmd.flags = flags | CRYPT_ACTIVATE_PRIVATE;
		}

		snprintf(cipher, sizeof(cipher), "%s-%s",
			 params->cipher[i], params->mode);
		copy_key(dmd.u.crypt.vk->key, hdr->d.keys,
			 top_cipher(tcipher),
			 params->key_size, i, params->mode);

		if (top_cipher(tcipher) != i) {
			snprintf(dm_dev_name, sizeof(dm_dev_name), "%s/%s_%d",
				 dm_get_dir(), name, i + 1);
			r = device_alloc(&device, dm_dev_name);
			if (r)
				break;
			dmd.data_device = device;
			dmd.u.crypt.offset = 0;
		}

		log_dbg("Trying to activate TCRYPT device %s using cipher %s.",
			dm_name, dmd.u.crypt.cipher);
		r = dm_create_device(cd, dm_name, CRYPT_TCRYPT, &dmd, 0);

		device_free(device);
		device = NULL;

		if (r)
			break;
	}

	if (!r && !(dm_flags() & DM_PLAIN64_SUPPORTED)) {
		log_err(cd, _("Kernel doesn't support plain64 IV.\n"));
		r = -ENOTSUP;
	}

	crypt_free_volume_key(dmd.u.crypt.vk);
	return r;
}
