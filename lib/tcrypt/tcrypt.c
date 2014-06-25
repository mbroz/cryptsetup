/*
 * TCRYPT (TrueCrypt-compatible) volume handling
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2014, Milan Broz
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
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
	const char *name;
	const char *hash;
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
		unsigned int key_offset;
		unsigned int iv_offset; /* or tweak key offset */
		unsigned int key_extra_size;
};

struct tcrypt_algs {
	unsigned int legacy:1;
	unsigned int chain_count;
	unsigned int chain_key_size;
	const char *long_name;
	const char *mode;
	struct tcrypt_alg cipher[3];
};

/* TCRYPT cipher variants */
static struct tcrypt_algs tcrypt_cipher[] = {
/* XTS mode */
{0,1,64,"aes","xts-plain64",
	{{"aes",    64,16,0,32,0}}},
{0,1,64,"serpent","xts-plain64",
	{{"serpent",64,16,0,32,0}}},
{0,1,64,"twofish","xts-plain64",
	{{"twofish",64,16,0,32,0}}},
{0,2,128,"twofish-aes","xts-plain64",
	{{"twofish",64,16, 0,64,0},
	 {"aes",    64,16,32,96,0}}},
{0,3,192,"serpent-twofish-aes","xts-plain64",
	{{"serpent",64,16, 0, 96,0},
	 {"twofish",64,16,32,128,0},
	 {"aes",    64,16,64,160,0}}},
{0,2,128,"aes-serpent","xts-plain64",
	{{"aes",    64,16, 0,64,0},
	 {"serpent",64,16,32,96,0}}},
{0,3,192,"aes-twofish-serpent","xts-plain64",
	{{"aes",    64,16, 0, 96,0},
	 {"twofish",64,16,32,128,0},
	 {"serpent",64,16,64,160,0}}},
{0,2,128,"serpent-twofish","xts-plain64",
	{{"serpent",64,16, 0,64,0},
	 {"twofish",64,16,32,96,0}}},

/* LRW mode */
{0,1,48,"aes","lrw-benbi",
	{{"aes",    48,16,32,0,0}}},
{0,1,48,"serpent","lrw-benbi",
	{{"serpent",48,16,32,0,0}}},
{0,1,48,"twofish","lrw-benbi",
	{{"twofish",48,16,32,0,0}}},
{0,2,96,"twofish-aes","lrw-benbi",
	{{"twofish",48,16,32,0,0},
	 {"aes",    48,16,64,0,0}}},
{0,3,144,"serpent-twofish-aes","lrw-benbi",
	{{"serpent",48,16,32,0,0},
	 {"twofish",48,16,64,0,0},
	 {"aes",    48,16,96,0,0}}},
{0,2,96,"aes-serpent","lrw-benbi",
	{{"aes",    48,16,32,0,0},
	 {"serpent",48,16,64,0,0}}},
{0,3,144,"aes-twofish-serpent","lrw-benbi",
	{{"aes",    48,16,32,0,0},
	 {"twofish",48,16,64,0,0},
	 {"serpent",48,16,96,0,0}}},
{0,2,96,"serpent-twofish", "lrw-benbi",
	{{"serpent",48,16,32,0,0},
	 {"twofish",48,16,64,0,0}}},

/* Kernel LRW block size is fixed to 16 bytes for GF(2^128)
 * thus cannot be used with blowfish where block is 8 bytes.
 * There also no GF(2^64) support.
{1,1,64,"blowfish_le","lrw-benbi",
	 {{"blowfish_le",64,8,32,0,0}}},
{1,2,112,"blowfish_le-aes","lrw-benbi",
	 {{"blowfish_le",64, 8,32,0,0},
	  {"aes",        48,16,88,0,0}}},
{1,3,160,"serpent-blowfish_le-aes","lrw-benbi",
	  {{"serpent",    48,16, 32,0,0},
	   {"blowfish_le",64, 8, 64,0,0},
	   {"aes",        48,16,120,0,0}}},*/

/*
 * CBC + "outer" CBC (both with whitening)
 * chain_key_size: alg_keys_bytes + IV_seed_bytes + whitening_bytes
 */
{1,1,32+16+16,"aes","cbc-tcw",
	{{"aes",    32,16,32,0,32}}},
{1,1,32+16+16,"serpent","cbc-tcw",
	{{"serpent",32,16,32,0,32}}},
{1,1,32+16+16,"twofish","cbc-tcw",
	{{"twofish",32,16,32,0,32}}},
{1,2,64+16+16,"twofish-aes","cbci-tcrypt",
	{{"twofish",32,16,32,0,0},
	 {"aes",    32,16,64,0,32}}},
{1,3,96+16+16,"serpent-twofish-aes","cbci-tcrypt",
	{{"serpent",32,16,32,0,0},
	 {"twofish",32,16,64,0,0},
	 {"aes",    32,16,96,0,32}}},
{1,2,64+16+16,"aes-serpent","cbci-tcrypt",
	{{"aes",    32,16,32,0,0},
	 {"serpent",32,16,64,0,32}}},
{1,3,96+16+16,"aes-twofish-serpent", "cbci-tcrypt",
	{{"aes",    32,16,32,0,0},
	 {"twofish",32,16,64,0,0},
	 {"serpent",32,16,96,0,32}}},
{1,2,64+16+16,"serpent-twofish", "cbci-tcrypt",
	{{"serpent",32,16,32,0,0},
	 {"twofish",32,16,64,0,32}}},
{1,1,16+8+16,"cast5","cbc-tcw",
	{{"cast5",   16,8,32,0,24}}},
{1,1,24+8+16,"des3_ede","cbc-tcw",
	{{"des3_ede",24,8,32,0,24}}},
{1,1,56+8+16,"blowfish_le","cbc-tcrypt",
	{{"blowfish_le",56,8,32,0,24}}},
{1,2,88+16+16,"blowfish_le-aes","cbc-tcrypt",
	{{"blowfish_le",56, 8,32,0,0},
	 {"aes",        32,16,88,0,32}}},
{1,3,120+16+16,"serpent-blowfish_le-aes","cbc-tcrypt",
	{{"serpent",    32,16, 32,0,0},
	 {"blowfish_le",56, 8, 64,0,0},
	 {"aes",        32,16,120,0,32}}},
{}
};

static int TCRYPT_hdr_from_disk(struct tcrypt_phdr *hdr,
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
	hdr->d.version_tc = le16_to_cpu(hdr->d.version_tc);

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
	params->key_size = tcrypt_cipher[cipher_index].chain_key_size;
	params->cipher = tcrypt_cipher[cipher_index].long_name;
	params->mode = tcrypt_cipher[cipher_index].mode;

	return 0;
}

/*
 * Kernel implements just big-endian version of blowfish, hack it here
 */
static void TCRYPT_swab_le(char *buf)
{
	uint32_t *l = (uint32_t*)&buf[0];
	uint32_t *r = (uint32_t*)&buf[4];
	*l = swab32(*l);
	*r = swab32(*r);
}

static int decrypt_blowfish_le_cbc(struct tcrypt_alg *alg,
				   const char *key, char *buf)
{
	int bs = alg->iv_size;
	char iv[bs], iv_old[bs];
	struct crypt_cipher *cipher = NULL;
	int i, j, r;

	assert(bs == 2*sizeof(uint32_t));

	r = crypt_cipher_init(&cipher, "blowfish", "ecb",
			      &key[alg->key_offset], alg->key_size);
	if (r < 0)
		return r;

	memcpy(iv, &key[alg->iv_offset], alg->iv_size);
	for (i = 0; i < TCRYPT_HDR_LEN; i += bs) {
		memcpy(iv_old, &buf[i], bs);
		TCRYPT_swab_le(&buf[i]);
		r = crypt_cipher_decrypt(cipher, &buf[i], &buf[i],
					  bs, NULL, 0);
		TCRYPT_swab_le(&buf[i]);
		if (r < 0)
			break;
		for (j = 0; j < bs; j++)
			buf[i + j] ^= iv[j];
		memcpy(iv, iv_old, bs);
	}

	crypt_cipher_destroy(cipher);
	memset(iv, 0, bs);
	memset(iv_old, 0, bs);
	return r;
}

static void TCRYPT_remove_whitening(char *buf, const char *key)
{
	int j;

	for (j = 0; j < TCRYPT_HDR_LEN; j++)
		buf[j] ^= key[j % 8];
}

static void TCRYPT_copy_key(struct tcrypt_alg *alg, const char *mode,
			     char *out_key, const char *key)
{
	int ks2;
	if (!strncmp(mode, "xts", 3)) {
		ks2 = alg->key_size / 2;
		memcpy(out_key, &key[alg->key_offset], ks2);
		memcpy(&out_key[ks2], &key[alg->iv_offset], ks2);
	} else if (!strncmp(mode, "lrw", 3)) {
		ks2 = alg->key_size - TCRYPT_LRW_IKEY_LEN;
		memcpy(out_key, &key[alg->key_offset], ks2);
		memcpy(&out_key[ks2], key, TCRYPT_LRW_IKEY_LEN);
	} else if (!strncmp(mode, "cbc", 3)) {
		memcpy(out_key, &key[alg->key_offset], alg->key_size);
		/* IV + whitening */
		memcpy(&out_key[alg->key_size], &key[alg->iv_offset],
		       alg->key_extra_size);
	}
}

static int TCRYPT_decrypt_hdr_one(struct tcrypt_alg *alg, const char *mode,
				   const char *key,struct tcrypt_phdr *hdr)
{
	char backend_key[TCRYPT_HDR_KEY_LEN];
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
		iv[alg->iv_size - 1] = 1;
	else if (!strncmp(mode, "cbc", 3)) {
		TCRYPT_remove_whitening(buf, &key[8]);
		if (!strcmp(alg->name, "blowfish_le"))
			return decrypt_blowfish_le_cbc(alg, key, buf);
		memcpy(iv, &key[alg->iv_offset], alg->iv_size);
	}

	TCRYPT_copy_key(alg, mode, backend_key, key);
	r = crypt_cipher_init(&cipher, alg->name, mode_name,
			      backend_key, alg->key_size);
	if (!r) {
		r = crypt_cipher_decrypt(cipher, buf, buf, TCRYPT_HDR_LEN,
					 iv, alg->iv_size);
		crypt_cipher_destroy(cipher);
	}

	memset(backend_key, 0, sizeof(backend_key));
	memset(iv, 0, TCRYPT_HDR_IV_LEN);
	return r;
}

/*
 * For chanined ciphers and CBC mode we need "outer" decryption.
 * Backend doesn't provide this, so implement it here directly using ECB.
 */
static int TCRYPT_decrypt_cbci(struct tcrypt_algs *ciphers,
				const char *key, struct tcrypt_phdr *hdr)
{
	struct crypt_cipher *cipher[ciphers->chain_count];
	unsigned int bs = ciphers->cipher[0].iv_size;
	char *buf = (char*)&hdr->e, iv[bs], iv_old[bs];
	unsigned int i, j;
	int r = -EINVAL;

	TCRYPT_remove_whitening(buf, &key[8]);

	memcpy(iv, &key[ciphers->cipher[0].iv_offset], bs);

	/* Initialize all ciphers in chain in ECB mode */
	for (j = 0; j < ciphers->chain_count; j++)
		cipher[j] = NULL;
	for (j = 0; j < ciphers->chain_count; j++) {
		r = crypt_cipher_init(&cipher[j], ciphers->cipher[j].name, "ecb",
				      &key[ciphers->cipher[j].key_offset],
				      ciphers->cipher[j].key_size);
		if (r < 0)
			goto out;
	}

	/* Implements CBC with chained ciphers in loop inside */
	for (i = 0; i < TCRYPT_HDR_LEN; i += bs) {
		memcpy(iv_old, &buf[i], bs);
		for (j = ciphers->chain_count; j > 0; j--) {
			r = crypt_cipher_decrypt(cipher[j - 1], &buf[i], &buf[i],
						  bs, NULL, 0);
			if (r < 0)
				goto out;
		}
		for (j = 0; j < bs; j++)
			buf[i + j] ^= iv[j];
		memcpy(iv, iv_old, bs);
	}
out:
	for (j = 0; j < ciphers->chain_count; j++)
		if (cipher[j])
			crypt_cipher_destroy(cipher[j]);

	memset(iv, 0, bs);
	memset(iv_old, 0, bs);
	return r;
}

static int TCRYPT_decrypt_hdr(struct crypt_device *cd, struct tcrypt_phdr *hdr,
			       const char *key, int legacy_modes)
{
	struct tcrypt_phdr hdr2;
	int i, j, r = -EINVAL;

	for (i = 0; tcrypt_cipher[i].chain_count; i++) {
		if (!legacy_modes && tcrypt_cipher[i].legacy)
			continue;
		log_dbg("TCRYPT:  trying cipher %s-%s",
			tcrypt_cipher[i].long_name, tcrypt_cipher[i].mode);

		memcpy(&hdr2.e, &hdr->e, TCRYPT_HDR_LEN);

		if (!strncmp(tcrypt_cipher[i].mode, "cbci", 4))
			r = TCRYPT_decrypt_cbci(&tcrypt_cipher[i], key, &hdr2);
		else for (j = tcrypt_cipher[i].chain_count - 1; j >= 0 ; j--) {
			if (!tcrypt_cipher[i].cipher[j].name)
				continue;
			r = TCRYPT_decrypt_hdr_one(&tcrypt_cipher[i].cipher[j],
					    tcrypt_cipher[i].mode, key, &hdr2);
			if (r < 0)
				break;
		}

		if (r < 0) {
			log_dbg("TCRYPT:   returned error %d, skipped.", r);
			if (r == -ENOTSUP)
				break;
			r = -ENOENT;
			continue;
		}

		if (!strncmp(hdr2.d.magic, TCRYPT_HDR_MAGIC, TCRYPT_HDR_MAGIC_LEN)) {
			log_dbg("TCRYPT: Signature magic detected.");
			memcpy(&hdr->e, &hdr2.e, TCRYPT_HDR_LEN);
			r = i;
			break;
		}
		r = -EPERM;
	}

	memset(&hdr2, 0, sizeof(hdr2));
	return r;
}

static int TCRYPT_pool_keyfile(struct crypt_device *cd,
				unsigned char pool[TCRYPT_KEY_POOL_LEN],
				const char *keyfile)
{
	unsigned char data[TCRYPT_KEYFILE_LEN];
	int i, j, fd, data_size;
	uint32_t crc;

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
		pool[j++] += (unsigned char)(crc >> 24);
		pool[j++] += (unsigned char)(crc >> 16);
		pool[j++] += (unsigned char)(crc >>  8);
		pool[j++] += (unsigned char)(crc);
		j %= TCRYPT_KEY_POOL_LEN;
	}

	memset(&crc, 0, sizeof(crc));
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
	unsigned int i, skipped = 0;
	int r = -EPERM, legacy_modes;

	if (posix_memalign((void*)&key, crypt_getpagesize(), TCRYPT_HDR_KEY_LEN))
		return -ENOMEM;

	if (params->keyfiles_count)
		passphrase_size = TCRYPT_KEY_POOL_LEN;
	else
		passphrase_size = params->passphrase_size;

	if (params->passphrase_size > TCRYPT_KEY_POOL_LEN) {
		log_err(cd, _("Maximum TCRYPT passphrase length (%d) exceeded.\n"),
			      TCRYPT_KEY_POOL_LEN);
		goto out;
	}

	/* Calculate pool content from keyfiles */
	for (i = 0; i < params->keyfiles_count; i++) {
		r = TCRYPT_pool_keyfile(cd, pwd, params->keyfiles[i]);
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
		if (r < 0 && crypt_hash_size(tcrypt_kdf[i].hash) < 0) {
			log_verbose(cd, _("PBKDF2 hash algorithm %s not available, skipping.\n"),
				      tcrypt_kdf[i].hash);
			continue;
		}
		if (r < 0)
			break;

		/* Decrypt header */
		r = TCRYPT_decrypt_hdr(cd, hdr, key, legacy_modes);
		if (r == -ENOENT) {
			skipped++;
			r = -EPERM;
		}
		if (r != -EPERM)
			break;
	}

	if ((r < 0 && r != -EPERM && skipped && skipped == i) || r == -ENOTSUP) {
		log_err(cd, _("Required kernel crypto interface not available.\n"));
#ifdef ENABLE_AF_ALG
		log_err(cd, _("Ensure you have algif_skcipher kernel module loaded.\n"));
#endif
	}
	if (r < 0)
		goto out;

	r = TCRYPT_hdr_from_disk(hdr, params, i, r);
	if (!r) {
		log_dbg("TCRYPT: Header version: %d, req. %d, sector %d"
			", mk_offset %" PRIu64 ", hidden_size %" PRIu64
			", volume size %" PRIu64, (int)hdr->d.version,
			(int)hdr->d.version_tc, (int)hdr->d.sector_size,
			hdr->d.mk_offset, hdr->d.hidden_volume_size, hdr->d.volume_size);
		log_dbg("TCRYPT: Header cipher %s-%s, key size %zu",
			params->cipher, params->mode, params->key_size);
	}
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
	struct device *base_device, *device = crypt_metadata_device(cd);
	ssize_t hdr_size = sizeof(struct tcrypt_phdr);
	char *base_device_path;
	int devfd = 0, r, bs;

	assert(sizeof(struct tcrypt_phdr) == 512);

	log_dbg("Reading TCRYPT header of size %zu bytes from device %s.",
		hdr_size, device_path(device));

	bs = device_block_size(device);
	if (bs < 0)
		return bs;

	if (params->flags & CRYPT_TCRYPT_SYSTEM_HEADER &&
	    crypt_dev_is_partition(device_path(device))) {
		base_device_path = crypt_get_base_device(device_path(device));

		log_dbg("Reading TCRYPT system header from device %s.", base_device_path ?: "?");
		if (!base_device_path)
			return -EINVAL;

		r = device_alloc(&base_device, base_device_path);
		if (r < 0)
			return r;
		devfd = device_open(base_device, O_RDONLY);
		free(base_device_path);
		device_free(base_device);
	} else
		devfd = device_open(device, O_RDONLY);

	if (devfd == -1) {
		log_err(cd, _("Cannot open device %s.\n"), device_path(device));
		return -EINVAL;
	}

	r = -EIO;
	if (params->flags & CRYPT_TCRYPT_SYSTEM_HEADER) {
		if (lseek(devfd, TCRYPT_HDR_SYSTEM_OFFSET, SEEK_SET) >= 0 &&
		    read_blockwise(devfd, bs, hdr, hdr_size) == hdr_size) {
			r = TCRYPT_init_hdr(cd, hdr, params);
		}
	} else if (params->flags & CRYPT_TCRYPT_HIDDEN_HEADER) {
		if (params->flags & CRYPT_TCRYPT_BACKUP_HEADER) {
			if (lseek(devfd, TCRYPT_HDR_HIDDEN_OFFSET_BCK, SEEK_END) >= 0 &&
			    read_blockwise(devfd, bs, hdr, hdr_size) == hdr_size)
				r = TCRYPT_init_hdr(cd, hdr, params);
		} else {
			if (lseek(devfd, TCRYPT_HDR_HIDDEN_OFFSET, SEEK_SET) >= 0 &&
			    read_blockwise(devfd, bs, hdr, hdr_size) == hdr_size)
				r = TCRYPT_init_hdr(cd, hdr, params);
			if (r &&
			    lseek(devfd, TCRYPT_HDR_HIDDEN_OFFSET_OLD, SEEK_END) >= 0 &&
			    read_blockwise(devfd, bs, hdr, hdr_size) == hdr_size)
				r = TCRYPT_init_hdr(cd, hdr, params);
		}
	} else if (params->flags & CRYPT_TCRYPT_BACKUP_HEADER) {
		if (lseek(devfd, TCRYPT_HDR_OFFSET_BCK, SEEK_END) >= 0 &&
			    read_blockwise(devfd, bs, hdr, hdr_size) == hdr_size)
			r = TCRYPT_init_hdr(cd, hdr, params);
	} else if (read_blockwise(devfd, bs, hdr, hdr_size) == hdr_size)
		r = TCRYPT_init_hdr(cd, hdr, params);

	close(devfd);
	if (r < 0)
		memset(hdr, 0, sizeof (*hdr));
	return r;
}

static struct tcrypt_algs *TCRYPT_get_algs(const char *cipher, const char *mode)
{
	int i;

	if (!cipher || !mode)
		return NULL;

	for (i = 0; tcrypt_cipher[i].chain_count; i++)
		if (!strcmp(tcrypt_cipher[i].long_name, cipher) &&
		    !strcmp(tcrypt_cipher[i].mode, mode))
		    return &tcrypt_cipher[i];

	return NULL;
}

int TCRYPT_activate(struct crypt_device *cd,
		     const char *name,
		     struct tcrypt_phdr *hdr,
		     struct crypt_params_tcrypt *params,
		     uint32_t flags)
{
	char cipher[MAX_CIPHER_LEN], dm_name[PATH_MAX], dm_dev_name[PATH_MAX];
	char *part_path;
	struct device *device = NULL, *part_device = NULL;
	unsigned int i;
	int r;
	uint32_t req_flags;
	struct tcrypt_algs *algs;
	enum devcheck device_check;
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

	if (!hdr->d.version) {
		log_dbg("TCRYPT: this function is not supported without encrypted header load.");
		return -ENOTSUP;
	}

	if (hdr->d.sector_size && hdr->d.sector_size != SECTOR_SIZE) {
		log_err(cd, _("Activation is not supported for %d sector size.\n"),
			hdr->d.sector_size);
		return -ENOTSUP;
	}

	if (strstr(params->mode, "-tcrypt")) {
		log_err(cd, _("Kernel doesn't support activation for this TCRYPT legacy mode.\n"));
		return -ENOTSUP;
	}

	if (strstr(params->mode, "-tcw"))
		req_flags = DM_TCW_SUPPORTED;
	else
		req_flags = DM_PLAIN64_SUPPORTED;

	algs = TCRYPT_get_algs(params->cipher, params->mode);
	if (!algs)
		return -EINVAL;

	if (params->flags & CRYPT_TCRYPT_SYSTEM_HEADER)
		dmd.size = 0;
	else if (params->flags & CRYPT_TCRYPT_HIDDEN_HEADER)
		dmd.size = hdr->d.hidden_volume_size / hdr->d.sector_size;
	else
		dmd.size = hdr->d.volume_size / hdr->d.sector_size;

	if (dmd.flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_SHARED;
	else
		device_check = DEV_EXCL;

	if ((params->flags & CRYPT_TCRYPT_SYSTEM_HEADER) &&
	     !crypt_dev_is_partition(device_path(dmd.data_device))) {
		part_path = crypt_get_partition_device(device_path(dmd.data_device),
						       dmd.u.crypt.offset, dmd.size);
		if (part_path) {
			if (!device_alloc(&part_device, part_path)) {
				log_verbose(cd, _("Activating TCRYPT system encryption for partition %s.\n"),
					    part_path);
				dmd.data_device = part_device;
				dmd.u.crypt.offset = 0;
			}
			free(part_path);
		} else
			/*
			 * System encryption use the whole device mapping, there can
			 * be active partitions.
			 */
			device_check = DEV_SHARED;
	}

	r = device_block_adjust(cd, dmd.data_device, device_check,
				dmd.u.crypt.offset, &dmd.size, &dmd.flags);
	if (r)
		return r;

	/* Frome here, key size for every cipher must be the same */
	dmd.u.crypt.vk = crypt_alloc_volume_key(algs->cipher[0].key_size +
						algs->cipher[0].key_extra_size, NULL);
	if (!dmd.u.crypt.vk)
		return -ENOMEM;

	for (i = algs->chain_count; i > 0; i--) {
		if (i == 1) {
			strncpy(dm_name, name, sizeof(dm_name));
			dmd.flags = flags;
		} else {
			snprintf(dm_name, sizeof(dm_name), "%s_%d", name, i-1);
			dmd.flags = flags | CRYPT_ACTIVATE_PRIVATE;
		}

		snprintf(cipher, sizeof(cipher), "%s-%s",
			 algs->cipher[i-1].name, algs->mode);

		TCRYPT_copy_key(&algs->cipher[i-1], algs->mode,
				dmd.u.crypt.vk->key, hdr->d.keys);

		if (algs->chain_count != i) {
			snprintf(dm_dev_name, sizeof(dm_dev_name), "%s/%s_%d",
				 dm_get_dir(), name, i);
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

	if (r < 0 && !(dm_flags() & req_flags)) {
		log_err(cd, _("Kernel doesn't support TCRYPT compatible mapping.\n"));
		r = -ENOTSUP;
	}

	device_free(part_device);
	crypt_free_volume_key(dmd.u.crypt.vk);
	return r;
}

static int TCRYPT_remove_one(struct crypt_device *cd, const char *name,
		      const char *base_uuid, int index)
{
	struct crypt_dm_active_device dmd = {};
	char dm_name[PATH_MAX];
	int r;

	if (snprintf(dm_name, sizeof(dm_name), "%s_%d", name, index) < 0)
		return -ENOMEM;

	r = dm_status_device(cd, dm_name);
	if (r < 0)
		return r;

	r = dm_query_device(cd, dm_name, DM_ACTIVE_UUID, &dmd);
	if (!r && !strncmp(dmd.uuid, base_uuid, strlen(base_uuid)))
		r = dm_remove_device(cd, dm_name, 0, 0);

	free(CONST_CAST(void*)dmd.uuid);
	return r;
}

int TCRYPT_deactivate(struct crypt_device *cd, const char *name)
{
	struct crypt_dm_active_device dmd = {};
	int r;

	r = dm_query_device(cd, name, DM_ACTIVE_UUID, &dmd);
	if (r < 0)
		return r;
	if (!dmd.uuid)
		return -EINVAL;

	r = dm_remove_device(cd, name, 0, 0);
	if (r < 0)
		goto out;

	r = TCRYPT_remove_one(cd, name, dmd.uuid, 1);
	if (r < 0)
		goto out;

	r = TCRYPT_remove_one(cd, name, dmd.uuid, 2);
	if (r < 0)
		goto out;
out:
	free(CONST_CAST(void*)dmd.uuid);
	return (r == -ENODEV) ? 0 : r;
}

static int TCRYPT_status_one(struct crypt_device *cd, const char *name,
			      const char *base_uuid, int index,
			      size_t *key_size, char *cipher,
			      uint64_t *data_offset, struct device **device)
{
	struct crypt_dm_active_device dmd = {};
	char dm_name[PATH_MAX], *c;
	int r;

	if (snprintf(dm_name, sizeof(dm_name), "%s_%d", name, index) < 0)
		return -ENOMEM;

	r = dm_status_device(cd, dm_name);
	if (r < 0)
		return r;

	r = dm_query_device(cd, dm_name, DM_ACTIVE_DEVICE |
					  DM_ACTIVE_UUID |
					  DM_ACTIVE_CRYPT_CIPHER |
					  DM_ACTIVE_CRYPT_KEYSIZE, &dmd);
	if (r > 0)
		r = 0;
	if (!r && !strncmp(dmd.uuid, base_uuid, strlen(base_uuid))) {
		if ((c = strchr(dmd.u.crypt.cipher, '-')))
			*c = '\0';
		strcat(cipher, "-");
		strncat(cipher, dmd.u.crypt.cipher, MAX_CIPHER_LEN);
		*key_size += dmd.u.crypt.vk->keylength;
		*data_offset = dmd.u.crypt.offset * SECTOR_SIZE;
		device_free(*device);
		*device = dmd.data_device;
	} else {
		device_free(dmd.data_device);
		r = -ENODEV;
	}

	free(CONST_CAST(void*)dmd.uuid);
	free(CONST_CAST(void*)dmd.u.crypt.cipher);
	crypt_free_volume_key(dmd.u.crypt.vk);
	return r;
}

int TCRYPT_init_by_name(struct crypt_device *cd, const char *name,
			const struct crypt_dm_active_device *dmd,
			struct device **device,
			struct crypt_params_tcrypt *tcrypt_params,
			struct tcrypt_phdr *tcrypt_hdr)
{
	struct tcrypt_algs *algs;
	char cipher[MAX_CIPHER_LEN * 4], mode[MAX_CIPHER_LEN], *tmp;
	size_t key_size;
	int r;

	memset(tcrypt_params, 0, sizeof(*tcrypt_params));
	memset(tcrypt_hdr, 0, sizeof(*tcrypt_hdr));
	tcrypt_hdr->d.sector_size = SECTOR_SIZE;
	tcrypt_hdr->d.mk_offset = dmd->u.crypt.offset * SECTOR_SIZE;

	strncpy(cipher, dmd->u.crypt.cipher, MAX_CIPHER_LEN);
	tmp = strchr(cipher, '-');
	if (!tmp)
		return -EINVAL;
	*tmp = '\0';
	strncpy(mode, ++tmp, MAX_CIPHER_LEN);

	key_size = dmd->u.crypt.vk->keylength;
	r = TCRYPT_status_one(cd, name, dmd->uuid, 1, &key_size,
			      cipher, &tcrypt_hdr->d.mk_offset, device);
	if (!r)
		r = TCRYPT_status_one(cd, name, dmd->uuid, 2, &key_size,
				      cipher, &tcrypt_hdr->d.mk_offset, device);

	if (r < 0 && r != -ENODEV)
		return r;

	algs = TCRYPT_get_algs(cipher, mode);
	if (!algs || key_size != algs->chain_key_size)
		return -EINVAL;

	tcrypt_params->key_size = algs->chain_key_size;
	tcrypt_params->cipher = algs->long_name;
	tcrypt_params->mode = algs->mode;
	return 0;
}

uint64_t TCRYPT_get_data_offset(struct crypt_device *cd,
				 struct tcrypt_phdr *hdr,
				 struct crypt_params_tcrypt *params)
{
	uint64_t size;

	/* No real header loaded, initialized by active device */
	if (!hdr->d.version)
		goto hdr_offset;

	/* Mapping through whole device, not partition! */
	if (params->flags & CRYPT_TCRYPT_SYSTEM_HEADER) {
		if (crypt_dev_is_partition(device_path(crypt_metadata_device(cd))))
			return 0;
		goto hdr_offset;
	}

	if (params->mode && !strncmp(params->mode, "xts", 3)) {
		if (hdr->d.version < 3)
			return 1;

		if (params->flags & CRYPT_TCRYPT_HIDDEN_HEADER) {
			if (hdr->d.version > 3)
				return (hdr->d.mk_offset / hdr->d.sector_size);
			if (device_size(crypt_metadata_device(cd), &size) < 0)
				return 0;
			return (size - hdr->d.hidden_volume_size +
				(TCRYPT_HDR_HIDDEN_OFFSET_OLD)) / hdr->d.sector_size;
		}
		goto hdr_offset;
	}

	if (params->flags & CRYPT_TCRYPT_HIDDEN_HEADER) {
		if (device_size(crypt_metadata_device(cd), &size) < 0)
			return 0;
		return (size - hdr->d.hidden_volume_size +
			(TCRYPT_HDR_HIDDEN_OFFSET_OLD)) / hdr->d.sector_size;
	}

hdr_offset:
	return hdr->d.mk_offset / hdr->d.sector_size;
}

uint64_t TCRYPT_get_iv_offset(struct crypt_device *cd,
			      struct tcrypt_phdr *hdr,
			      struct crypt_params_tcrypt *params)
{
	uint64_t iv_offset;

	if (params->mode && !strncmp(params->mode, "xts", 3))
		iv_offset = TCRYPT_get_data_offset(cd, hdr, params);
	else if (params->mode && !strncmp(params->mode, "lrw", 3))
		iv_offset = 0;
	else
		iv_offset = hdr->d.mk_offset / hdr->d.sector_size;

	if (params->flags & CRYPT_TCRYPT_SYSTEM_HEADER)
		iv_offset += crypt_dev_partition_offset(device_path(crypt_metadata_device(cd)));

	return iv_offset;
}

int TCRYPT_get_volume_key(struct crypt_device *cd,
			  struct tcrypt_phdr *hdr,
			  struct crypt_params_tcrypt *params,
			  struct volume_key **vk)
{
	struct tcrypt_algs *algs;
	unsigned int i, key_index;

	if (!hdr->d.version) {
		log_err(cd, _("This function is not supported without TCRYPT header load."));
		return -ENOTSUP;
	}

	algs = TCRYPT_get_algs(params->cipher, params->mode);
	if (!algs)
		return -EINVAL;

	*vk = crypt_alloc_volume_key(params->key_size, NULL);
	if (!*vk)
		return -ENOMEM;

	for (i = 0, key_index = 0; i < algs->chain_count; i++) {
		TCRYPT_copy_key(&algs->cipher[i], algs->mode,
				&(*vk)->key[key_index], hdr->d.keys);
		key_index += algs->cipher[i].key_size;
	}

	return 0;
}

int TCRYPT_dump(struct crypt_device *cd,
		struct tcrypt_phdr *hdr,
		struct crypt_params_tcrypt *params)
{
	log_std(cd, "TCRYPT header information for %s\n",
		device_path(crypt_metadata_device(cd)));
	if (hdr->d.version) {
		log_std(cd, "Version:       \t%d\n", hdr->d.version);
		log_std(cd, "Driver req.:\t%d\n", hdr->d.version_tc);

		log_std(cd, "Sector size:\t%" PRIu32 "\n", hdr->d.sector_size);
		log_std(cd, "MK offset:\t%" PRIu64 "\n", hdr->d.mk_offset);
		log_std(cd, "PBKDF2 hash:\t%s\n", params->hash_name);
	}
	log_std(cd, "Cipher chain:\t%s\n", params->cipher);
	log_std(cd, "Cipher mode:\t%s\n", params->mode);
	log_std(cd, "MK bits:       \t%zu\n", params->key_size * 8);
	return 0;
}
