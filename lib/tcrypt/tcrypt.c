// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * TCRYPT (TrueCrypt-compatible) and VeraCrypt volume handling
 *
 * Copyright (C) 2012-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2025 Milan Broz
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcryptsetup.h"
#include "tcrypt.h"
#include "internal.h"

/* TCRYPT PBKDF variants */
static const struct {
	bool legacy;
	bool veracrypt;
	const char *name;
	const char *hash;
	unsigned int iterations;
	uint32_t veracrypt_pim_const;
	uint32_t veracrypt_pim_mult;
} tcrypt_kdf[] = {
	{ false, false, "pbkdf2", "ripemd160",   2000, 0, 0 },
	{ false, false, "pbkdf2", "ripemd160",   1000, 0, 0 },
	{ false, false, "pbkdf2", "sha512",      1000, 0, 0 },
	{ false, false, "pbkdf2", "whirlpool",   1000, 0, 0 },
	{  true, false, "pbkdf2", "sha1",        2000, 0, 0 },
	{ false,  true, "pbkdf2", "sha512",    500000, 15000, 1000 },
	{ false,  true, "pbkdf2", "whirlpool", 500000, 15000, 1000 },
	{ false,  true, "pbkdf2", "sha256",    500000, 15000, 1000 }, // VeraCrypt 1.0f
	{ false,  true, "pbkdf2", "sha256",    200000,     0, 2048 }, // boot only
	{ false,  true, "pbkdf2", "blake2s-256", 500000, 15000, 1000 }, // VeraCrypt 1.26.2
	{ false,  true, "pbkdf2", "blake2s-256", 200000,     0, 2048 }, // boot only
	{ false,  true, "pbkdf2", "ripemd160", 655331, 15000, 1000 },
	{ false,  true, "pbkdf2", "ripemd160", 327661,     0, 2048 }, // boot only
	{ false,  true, "pbkdf2", "stribog512",500000, 15000, 1000 },
//	{ false,  true, "pbkdf2", "stribog512",200000,     0, 2048 }, // boot only
	{ false, false,     NULL,        NULL,      0,     0,    0 }
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
	bool legacy;
	unsigned int chain_count;
	unsigned int chain_key_size;
	const char *long_name;
	const char *mode;
	const struct tcrypt_alg cipher[3];
};

/* TCRYPT cipher variants */
static const struct tcrypt_algs tcrypt_cipher[] = {
/* XTS mode */
{false,1,64,"aes","xts-plain64",
	{{"aes",    64,16,0,32,0}}},
{false,1,64,"serpent","xts-plain64",
	{{"serpent",64,16,0,32,0}}},
{false,1,64,"twofish","xts-plain64",
	{{"twofish",64,16,0,32,0}}},
{false,2,128,"twofish-aes","xts-plain64",
	{{"twofish",64,16, 0,64,0},
	 {"aes",    64,16,32,96,0}}},
{false,3,192,"serpent-twofish-aes","xts-plain64",
	{{"serpent",64,16, 0, 96,0},
	 {"twofish",64,16,32,128,0},
	 {"aes",    64,16,64,160,0}}},
{false,2,128,"aes-serpent","xts-plain64",
	{{"aes",    64,16, 0,64,0},
	 {"serpent",64,16,32,96,0}}},
{false,3,192,"aes-twofish-serpent","xts-plain64",
	{{"aes",    64,16, 0, 96,0},
	 {"twofish",64,16,32,128,0},
	 {"serpent",64,16,64,160,0}}},
{false,2,128,"serpent-twofish","xts-plain64",
	{{"serpent",64,16, 0,64,0},
	 {"twofish",64,16,32,96,0}}},
{false,1,64,"camellia","xts-plain64",
	{{"camellia",    64,16,0,32,0}}},
{false,1,64,"kuznyechik","xts-plain64",
	{{"kuznyechik",  64,16,0,32,0}}},
{false,2,128,"kuznyechik-camellia","xts-plain64",
	{{"kuznyechik",64,16, 0,64,0},
	 {"camellia",  64,16,32,96,0}}},
{false,2,128,"twofish-kuznyechik","xts-plain64",
	{{"twofish",   64,16, 0,64,0},
	 {"kuznyechik",64,16,32,96,0}}},
{false,2,128,"serpent-camellia","xts-plain64",
	{{"serpent",   64,16, 0,64,0},
	 {"camellia",  64,16,32,96,0}}},
{false,2,128,"aes-kuznyechik","xts-plain64",
	{{"aes",       64,16, 0,64,0},
	 {"kuznyechik",64,16,32,96,0}}},
{false,3,192,"camellia-serpent-kuznyechik","xts-plain64",
	{{"camellia",  64,16, 0, 96,0},
	 {"serpent",   64,16,32,128,0},
	 {"kuznyechik",64,16,64,160,0}}},

/* LRW mode */
{false,1,48,"aes","lrw-benbi",
	{{"aes",    48,16,32,0,0}}},
{false,1,48,"serpent","lrw-benbi",
	{{"serpent",48,16,32,0,0}}},
{false,1,48,"twofish","lrw-benbi",
	{{"twofish",48,16,32,0,0}}},
{false,2,96,"twofish-aes","lrw-benbi",
	{{"twofish",48,16,32,0,0},
	 {"aes",    48,16,64,0,0}}},
{false,3,144,"serpent-twofish-aes","lrw-benbi",
	{{"serpent",48,16,32,0,0},
	 {"twofish",48,16,64,0,0},
	 {"aes",    48,16,96,0,0}}},
{false,2,96,"aes-serpent","lrw-benbi",
	{{"aes",    48,16,32,0,0},
	 {"serpent",48,16,64,0,0}}},
{false,3,144,"aes-twofish-serpent","lrw-benbi",
	{{"aes",    48,16,32,0,0},
	 {"twofish",48,16,64,0,0},
	 {"serpent",48,16,96,0,0}}},
{false,2,96,"serpent-twofish", "lrw-benbi",
	{{"serpent",48,16,32,0,0},
	 {"twofish",48,16,64,0,0}}},

/* Kernel LRW block size is fixed to 16 bytes for GF(2^128)
 * thus cannot be used with blowfish where block is 8 bytes.
 * There also no GF(2^64) support.
{true,1,64,"blowfish_le","lrw-benbi",
	 {{"blowfish_le",64,8,32,0,0}}},
{true,2,112,"blowfish_le-aes","lrw-benbi",
	 {{"blowfish_le",64, 8,32,0,0},
	  {"aes",        48,16,88,0,0}}},
{true,3,160,"serpent-blowfish_le-aes","lrw-benbi",
	  {{"serpent",    48,16, 32,0,0},
	   {"blowfish_le",64, 8, 64,0,0},
	   {"aes",        48,16,120,0,0}}},*/

/*
 * CBC + "outer" CBC (both with whitening)
 * chain_key_size: alg_keys_bytes + IV_seed_bytes + whitening_bytes
 */
{true,1,32+16+16,"aes","cbc-tcw",
	{{"aes",    32,16,32,0,32}}},
{true,1,32+16+16,"serpent","cbc-tcw",
	{{"serpent",32,16,32,0,32}}},
{true,1,32+16+16,"twofish","cbc-tcw",
	{{"twofish",32,16,32,0,32}}},
{true,2,64+16+16,"twofish-aes","cbci-tcrypt",
	{{"twofish",32,16,32,0,0},
	 {"aes",    32,16,64,0,32}}},
{true,3,96+16+16,"serpent-twofish-aes","cbci-tcrypt",
	{{"serpent",32,16,32,0,0},
	 {"twofish",32,16,64,0,0},
	 {"aes",    32,16,96,0,32}}},
{true,2,64+16+16,"aes-serpent","cbci-tcrypt",
	{{"aes",    32,16,32,0,0},
	 {"serpent",32,16,64,0,32}}},
{true,3,96+16+16,"aes-twofish-serpent", "cbci-tcrypt",
	{{"aes",    32,16,32,0,0},
	 {"twofish",32,16,64,0,0},
	 {"serpent",32,16,96,0,32}}},
{true,2,64+16+16,"serpent-twofish", "cbci-tcrypt",
	{{"serpent",32,16,32,0,0},
	 {"twofish",32,16,64,0,32}}},
{true,1,16+8+16,"cast5","cbc-tcw",
	{{"cast5",   16,8,32,0,24}}},
{true,1,24+8+16,"des3_ede","cbc-tcw",
	{{"des3_ede",24,8,32,0,24}}},
{true,1,56+8+16,"blowfish_le","cbc-tcrypt",
	{{"blowfish_le",56,8,32,0,24}}},
{true,2,88+16+16,"blowfish_le-aes","cbc-tcrypt",
	{{"blowfish_le",56, 8,32,0,0},
	 {"aes",        32,16,88,0,32}}},
{true,3,120+16+16,"serpent-blowfish_le-aes","cbc-tcrypt",
	{{"serpent",    32,16, 32,0,0},
	 {"blowfish_le",56, 8, 64,0,0},
	 {"aes",        32,16,120,0,32}}},
{}
};

static int TCRYPT_hdr_from_disk(struct crypt_device *cd,
				struct tcrypt_phdr *hdr,
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
		log_dbg(cd, "TCRYPT header CRC32 mismatch.");
		return -EINVAL;
	}

	/* Check CRC32 of keys */
	crc32 = crypt_crc32(~0, (unsigned char*)hdr->d.keys, sizeof(hdr->d.keys)) ^ ~0;
	if (crc32 != be32_to_cpu(hdr->d.keys_crc32)) {
		log_dbg(cd, "TCRYPT keys CRC32 mismatch.");
		return -EINVAL;
	}

	/* Convert header to cpu format */
	hdr->d.version  =  be16_to_cpu(hdr->d.version);
	hdr->d.version_tc = be16_to_cpu(hdr->d.version_tc);

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
	uint32_t *l = VOIDP_CAST(uint32_t*)&buf[0];
	uint32_t *r = VOIDP_CAST(uint32_t*)&buf[4];
	*l = swab32(*l);
	*r = swab32(*r);
}

static int decrypt_blowfish_le_cbc(const struct tcrypt_alg *alg,
				   const char *key, char *buf)
{
	int bs = alg->iv_size;
	char iv[8], iv_old[8];
	struct crypt_cipher *cipher = NULL;
	int i, j, r;

	assert(bs == 8);

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
	crypt_safe_memzero(iv, bs);
	crypt_safe_memzero(iv_old, bs);
	return r;
}

static void TCRYPT_remove_whitening(char *buf, const char *key)
{
	int j;

	for (j = 0; j < TCRYPT_HDR_LEN; j++)
		buf[j] ^= key[j % 8];
}

static void TCRYPT_copy_key(const struct tcrypt_alg *alg, const char *mode,
			     char *out_key, const char *key)
{
	int ks2;
	if (!strncmp(mode, "xts", 3)) {
		ks2 = alg->key_size / 2;
		crypt_safe_memcpy(out_key, &key[alg->key_offset], ks2);
		crypt_safe_memcpy(&out_key[ks2], &key[alg->iv_offset], ks2);
	} else if (!strncmp(mode, "lrw", 3)) {
		ks2 = alg->key_size - TCRYPT_LRW_IKEY_LEN;
		crypt_safe_memcpy(out_key, &key[alg->key_offset], ks2);
		crypt_safe_memcpy(&out_key[ks2], key, TCRYPT_LRW_IKEY_LEN);
	} else if (!strncmp(mode, "cbc", 3)) {
		crypt_safe_memcpy(out_key, &key[alg->key_offset], alg->key_size);
		/* IV + whitening */
		crypt_safe_memcpy(&out_key[alg->key_size], &key[alg->iv_offset],
		       alg->key_extra_size);
	}
}

static int TCRYPT_decrypt_hdr_one(const struct tcrypt_alg *alg, const char *mode,
				   const char *key,struct tcrypt_phdr *hdr)
{
	char backend_key[TCRYPT_HDR_KEY_LEN];
	char iv[TCRYPT_HDR_IV_LEN] = {};
	char mode_name[MAX_CIPHER_LEN + 1];
	struct crypt_cipher *cipher;
	char *c, *buf = (char*)&hdr->e;
	int r;

	/* Remove IV if present */
	mode_name[MAX_CIPHER_LEN] = '\0';
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

	crypt_safe_memzero(backend_key, sizeof(backend_key));
	crypt_safe_memzero(iv, TCRYPT_HDR_IV_LEN);
	return r;
}

/*
 * For chained ciphers and CBC mode we need "outer" decryption.
 * Backend doesn't provide this, so implement it here directly using ECB.
 */
static int TCRYPT_decrypt_cbci(const struct tcrypt_algs *ciphers,
				const char *key, struct tcrypt_phdr *hdr)
{
	struct crypt_cipher *cipher[3];
	unsigned int bs = ciphers->cipher[0].iv_size;
	char *buf = (char*)&hdr->e, iv[16], iv_old[16];
	unsigned int i, j;
	int r = -EINVAL;

	assert(ciphers->chain_count <= 3);
	assert(bs <= 16);

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

	crypt_safe_memzero(iv, bs);
	crypt_safe_memzero(iv_old, bs);
	return r;
}

static int TCRYPT_decrypt_hdr(struct crypt_device *cd, struct tcrypt_phdr *hdr,
			       const char *key, struct crypt_params_tcrypt *params)
{
	struct tcrypt_phdr hdr2;
	int i, j, r = -EINVAL;

	for (i = 0; tcrypt_cipher[i].chain_count; i++) {
		if (params->cipher && !strstr(tcrypt_cipher[i].long_name, params->cipher))
			continue;
		if (!(params->flags & CRYPT_TCRYPT_LEGACY_MODES) && tcrypt_cipher[i].legacy)
			continue;
		log_dbg(cd, "TCRYPT:  trying cipher %s-%s",
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
			log_dbg(cd, "TCRYPT:   returned error %d, skipped.", r);
			if (r == -ENOTSUP)
				break;
			r = -ENOENT;
			continue;
		}

		if (!strncmp(hdr2.d.magic, TCRYPT_HDR_MAGIC, TCRYPT_HDR_MAGIC_LEN)) {
			log_dbg(cd, "TCRYPT: Signature magic detected.");
			memcpy(&hdr->e, &hdr2.e, TCRYPT_HDR_LEN);
			r = i;
			break;
		}
		if ((params->flags & CRYPT_TCRYPT_VERA_MODES) &&
		     !strncmp(hdr2.d.magic, VCRYPT_HDR_MAGIC, TCRYPT_HDR_MAGIC_LEN)) {
			log_dbg(cd, "TCRYPT: Signature magic detected (Veracrypt).");
			memcpy(&hdr->e, &hdr2.e, TCRYPT_HDR_LEN);
			r = i;
			break;
		}
		r = -EPERM;
	}

	crypt_safe_memzero(&hdr2, sizeof(hdr2));
	return r;
}

static int TCRYPT_pool_keyfile(struct crypt_device *cd,
				unsigned char pool[VCRYPT_KEY_POOL_LEN],
				const char *keyfile, int keyfiles_pool_length)
{
	unsigned char *data;
	int i, j, fd, data_size, r = -EIO;
	uint32_t crc;

	log_dbg(cd, "TCRYPT: using keyfile %s.", keyfile);

	data = malloc(TCRYPT_KEYFILE_LEN);
	if (!data)
		return -ENOMEM;
	memset(data, 0, TCRYPT_KEYFILE_LEN);

	fd = open(keyfile, O_RDONLY);
	if (fd < 0) {
		log_err(cd, _("Failed to open key file."));
		goto out;
	}

	data_size = read_buffer(fd, data, TCRYPT_KEYFILE_LEN);
	close(fd);
	if (data_size < 0) {
		log_err(cd, _("Error reading keyfile %s."), keyfile);
		goto out;
	}

	for (i = 0, j = 0, crc = ~0U; i < data_size; i++) {
		crc = crypt_crc32(crc, &data[i], 1);
		pool[j++] += (unsigned char)(crc >> 24);
		pool[j++] += (unsigned char)(crc >> 16);
		pool[j++] += (unsigned char)(crc >>  8);
		pool[j++] += (unsigned char)(crc);
		j %= keyfiles_pool_length;
	}
	r = 0;
out:
	crypt_safe_memzero(&crc, sizeof(crc));
	crypt_safe_memzero(data, TCRYPT_KEYFILE_LEN);
	free(data);

	return r;
}

static int TCRYPT_init_hdr(struct crypt_device *cd,
			   struct tcrypt_phdr *hdr,
			   struct crypt_params_tcrypt *params)
{
	unsigned char pwd[VCRYPT_KEY_POOL_LEN] = {};
	size_t passphrase_size, max_passphrase_size;
	char *key;
	unsigned int i, skipped = 0, iterations;
	int r = -EPERM, keyfiles_pool_length;

	if (posix_memalign((void*)&key, crypt_getpagesize(), TCRYPT_HDR_KEY_LEN))
		return -ENOMEM;

	if (params->flags & CRYPT_TCRYPT_VERA_MODES &&
	    params->passphrase_size > TCRYPT_KEY_POOL_LEN) {
		/* Really. Keyfile pool length depends on passphrase size in Veracrypt. */
		max_passphrase_size = VCRYPT_KEY_POOL_LEN;
		keyfiles_pool_length = VCRYPT_KEY_POOL_LEN;
	} else {
		max_passphrase_size = TCRYPT_KEY_POOL_LEN;
		keyfiles_pool_length = TCRYPT_KEY_POOL_LEN;
	}

	if (params->keyfiles_count)
		passphrase_size = max_passphrase_size;
	else
		passphrase_size = params->passphrase_size;

	if (params->passphrase_size > max_passphrase_size) {
		log_err(cd, _("Maximum TCRYPT passphrase length (%zu) exceeded."),
			      max_passphrase_size);
		goto out;
	}

	/* Calculate pool content from keyfiles */
	for (i = 0; i < params->keyfiles_count; i++) {
		r = TCRYPT_pool_keyfile(cd, pwd, params->keyfiles[i], keyfiles_pool_length);
		if (r < 0)
			goto out;
	}

	/* If provided password, combine it with pool */
	for (i = 0; i < params->passphrase_size; i++)
		pwd[i] += params->passphrase[i];

	for (i = 0; tcrypt_kdf[i].name; i++) {
		if (params->hash_name && !strstr(tcrypt_kdf[i].hash, params->hash_name))
			continue;
		if (!(params->flags & CRYPT_TCRYPT_LEGACY_MODES) && tcrypt_kdf[i].legacy)
			continue;
		if (!(params->flags & CRYPT_TCRYPT_VERA_MODES) && tcrypt_kdf[i].veracrypt)
			continue;
		if ((params->flags & CRYPT_TCRYPT_VERA_MODES) && params->veracrypt_pim) {
			/* Do not try TrueCrypt modes if we have PIM value */
			if (!tcrypt_kdf[i].veracrypt)
				continue;
			/* adjust iterations to given PIM cmdline parameter */
			iterations = tcrypt_kdf[i].veracrypt_pim_const +
				    (tcrypt_kdf[i].veracrypt_pim_mult * params->veracrypt_pim);
		} else
			iterations = tcrypt_kdf[i].iterations;
		/* Derive header key */
		log_dbg(cd, "TCRYPT: trying KDF: %s-%s-%d%s.",
			tcrypt_kdf[i].name, tcrypt_kdf[i].hash, tcrypt_kdf[i].iterations,
			params->veracrypt_pim && tcrypt_kdf[i].veracrypt ? "-PIM" : "");
		r = crypt_pbkdf(tcrypt_kdf[i].name, tcrypt_kdf[i].hash,
				(char*)pwd, passphrase_size,
				hdr->salt, TCRYPT_HDR_SALT_LEN,
				key, TCRYPT_HDR_KEY_LEN,
				iterations, 0, 0);
		if (r < 0) {
			log_verbose(cd, _("PBKDF2 hash algorithm %s not available, skipping."),
				      tcrypt_kdf[i].hash);
			skipped++;
			r = -EPERM;
			continue;
		}

		/* Decrypt header */
		r = TCRYPT_decrypt_hdr(cd, hdr, key, params);
		if (r == -ENOENT) {
			skipped++;
			r = -EPERM;
			continue;
		}
		if (r != -EPERM)
			break;
	}

	if ((r < 0 && skipped && skipped == i) || r == -ENOTSUP) {
		log_err(cd, _("Required kernel crypto interface not available."));
#if ENABLE_AF_ALG
		log_err(cd, _("Ensure you have algif_skcipher kernel module loaded."));
#endif
		r = -ENOTSUP;
	}
	if (r < 0)
		goto out;

	r = TCRYPT_hdr_from_disk(cd, hdr, params, i, r);
	if (!r) {
		log_dbg(cd, "TCRYPT: Magic: %s, Header version: %d, req. %d, sector %d"
			", mk_offset %" PRIu64 ", hidden_size %" PRIu64
			", volume size %" PRIu64, tcrypt_kdf[i].veracrypt ?
			VCRYPT_HDR_MAGIC : TCRYPT_HDR_MAGIC,
			(int)hdr->d.version, (int)hdr->d.version_tc, (int)hdr->d.sector_size,
			hdr->d.mk_offset, hdr->d.hidden_volume_size, hdr->d.volume_size);
		log_dbg(cd, "TCRYPT: Header cipher %s-%s, key size %zu",
			params->cipher, params->mode, params->key_size);
	}
out:
	crypt_safe_memzero(pwd, TCRYPT_KEY_POOL_LEN);
	if (key)
		crypt_safe_memzero(key, TCRYPT_HDR_KEY_LEN);
	free(key);
	return r;
}

int TCRYPT_read_phdr(struct crypt_device *cd,
		     struct tcrypt_phdr *hdr,
		     struct crypt_params_tcrypt *params)
{
	struct device *base_device = NULL, *device = crypt_metadata_device(cd);
	ssize_t hdr_size = sizeof(struct tcrypt_phdr);
	char *base_device_path;
	int devfd, r;

	assert(sizeof(struct tcrypt_phdr) == 512);

	log_dbg(cd, "Reading TCRYPT header of size %zu bytes from device %s.",
		hdr_size, device_path(device));

	if (params->flags & CRYPT_TCRYPT_SYSTEM_HEADER &&
	    crypt_dev_is_partition(device_path(device))) {
		base_device_path = crypt_get_base_device(device_path(device));

		log_dbg(cd, "Reading TCRYPT system header from device %s.", base_device_path ?: "?");
		if (!base_device_path)
			return -EINVAL;

		r = device_alloc(cd, &base_device, base_device_path);
		free(base_device_path);
		if (r < 0)
			return r;
		devfd = device_open(cd, base_device, O_RDONLY);
	} else
		devfd = device_open(cd, device, O_RDONLY);

	if (devfd < 0) {
		device_free(cd, base_device);
		log_err(cd, _("Cannot open device %s."), device_path(device));
		return -EINVAL;
	}

	r = -EIO;
	if (params->flags & CRYPT_TCRYPT_SYSTEM_HEADER) {
		if (read_lseek_blockwise(devfd, device_block_size(cd, device),
			device_alignment(device), hdr, hdr_size,
			TCRYPT_HDR_SYSTEM_OFFSET) == hdr_size) {
			r = TCRYPT_init_hdr(cd, hdr, params);
		}
	} else if (params->flags & CRYPT_TCRYPT_HIDDEN_HEADER) {
		if (params->flags & CRYPT_TCRYPT_BACKUP_HEADER) {
			if (read_lseek_blockwise(devfd, device_block_size(cd, device),
				device_alignment(device), hdr, hdr_size,
				TCRYPT_HDR_HIDDEN_OFFSET_BCK) == hdr_size)
				r = TCRYPT_init_hdr(cd, hdr, params);
		} else {
			if (read_lseek_blockwise(devfd, device_block_size(cd, device),
				device_alignment(device), hdr, hdr_size,
				TCRYPT_HDR_HIDDEN_OFFSET) == hdr_size)
				r = TCRYPT_init_hdr(cd, hdr, params);
			if (r && read_lseek_blockwise(devfd, device_block_size(cd, device),
				device_alignment(device), hdr, hdr_size,
				TCRYPT_HDR_HIDDEN_OFFSET_OLD) == hdr_size)
				r = TCRYPT_init_hdr(cd, hdr, params);
		}
	} else if (params->flags & CRYPT_TCRYPT_BACKUP_HEADER) {
		if (read_lseek_blockwise(devfd, device_block_size(cd, device),
			device_alignment(device), hdr, hdr_size,
			TCRYPT_HDR_OFFSET_BCK) == hdr_size)
			r = TCRYPT_init_hdr(cd, hdr, params);
	} else if (read_lseek_blockwise(devfd, device_block_size(cd, device),
			device_alignment(device), hdr, hdr_size, 0) == hdr_size)
		r = TCRYPT_init_hdr(cd, hdr, params);

	device_free(cd, base_device);
	if (r < 0)
		memset(hdr, 0, sizeof (*hdr));
	return r;
}

static const struct tcrypt_algs *TCRYPT_get_algs(const char *cipher, const char *mode)
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
	char dm_name[PATH_MAX], dm_dev_name[PATH_MAX], cipher_spec[MAX_CIPHER_LEN*2+1];
	char *part_path;
	unsigned int i;
	int r;
	uint64_t req_flags, dmc_flags;
	const struct tcrypt_algs *algs;
	enum devcheck device_check;
	uint64_t offset, iv_offset;
	struct volume_key *vk = NULL;
	void *key = NULL;
	struct device  *ptr_dev = crypt_data_device(cd), *device = NULL, *part_device = NULL;
	struct crypt_dm_active_device dmd = {
		.flags = flags
	};

	if (!hdr->d.version) {
		log_dbg(cd, "TCRYPT: this function is not supported without encrypted header load.");
		return -ENOTSUP;
	}

	if (hdr->d.sector_size % SECTOR_SIZE) {
		log_err(cd, _("Activation is not supported for %d sector size."),
			hdr->d.sector_size);
		return -ENOTSUP;
	}

	if (strstr(params->mode, "-tcrypt")) {
		log_err(cd, _("Kernel does not support activation for this TCRYPT legacy mode."));
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
		dmd.size = hdr->d.hidden_volume_size / SECTOR_SIZE;
	else
		dmd.size = hdr->d.volume_size / SECTOR_SIZE;

	if (dmd.flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_OK;
	else
		device_check = DEV_EXCL;

	offset = crypt_get_data_offset(cd);
	iv_offset = crypt_get_iv_offset(cd);

	/*
	 * System encryption is tricky, as the TCRYPT header is outside the partition area.
	 * It can be a system partition only (TCRYPT header offset contains MK offset to
	 * a particular partition) or the whole system (then MK offset starts on the header itself).
	 * IV offset is always partition offset, but device offset depends on whether the user
	 * copied the whole disk or just one encrypted partition.
	 * This code tries to guess the most common situations but can still fail and use wrong offsets.
	 * Recent UEFI systems never use whole system encryption.
	 */
	if (params->flags & CRYPT_TCRYPT_SYSTEM_HEADER) {
		if (crypt_dev_is_partition(device_path(crypt_data_device(cd)))) {
			/* One partition */
			offset = 0;
			iv_offset = crypt_dev_partition_offset(device_path(crypt_data_device(cd)));
		} else if (crypt_dev_is_partition(device_path(crypt_metadata_device(cd)))) {
			/* One partition image, header is the original partition */
			offset = 0;
			iv_offset = crypt_dev_partition_offset(device_path(crypt_metadata_device(cd)));
		} else {
			/* No partition info, try partition-only mode searching for partition. */
			part_path = crypt_get_partition_device(device_path(crypt_data_device(cd)),
							       iv_offset, hdr->d.volume_size / SECTOR_SIZE);
			if (!part_path)
				part_path = crypt_get_partition_device(device_path(crypt_metadata_device(cd)),
								       iv_offset, hdr->d.volume_size / SECTOR_SIZE);
			if (part_path) {
				if (!device_alloc(cd, &part_device, part_path)) {
					log_verbose(cd, _("Activating TCRYPT system encryption for partition %s."),
						part_path);
					ptr_dev = part_device;
					offset = 0;
					iv_offset = crypt_dev_partition_offset(part_path);
				}
				free(part_path);
			} else if (device_is_identical(crypt_metadata_device(cd), crypt_data_device(cd))) {
				/*
				 * We have no partition offset and TCRYPT system header is on the data device.
				 * Use the whole device mapping.
				 * There can be active partitions, do not use exclusive flag.
				 */
				device_check = DEV_OK;
				dmd.size = hdr->d.volume_size / SECTOR_SIZE;
				log_err(cd, _("Cannot determine TCRYPT system partition offset, activating whole encrypted area."));
			} else {
				/*
				 * We have no partition offset and TCRYPT system header is on the metadata device
				 * (TCRYPT system header was NOT read from data device).
				 * Expect that data device is a copy of partition and not the whole device.
				 * This will not work for whole system encryption, though.
				 */
				offset = 0;
				log_err(cd, _("Cannot determine TCRYPT system partition offset, activating device as a system partition."));
			}
		}
		log_dbg(cd, "TCRYPT system encryption data_offset %" PRIu64 ", iv_offset %" PRIu64 ".", offset, iv_offset);
	}

	r = device_block_adjust(cd, ptr_dev, device_check,
				offset, &dmd.size, &dmd.flags);
	if (r)
		goto out;

	/* From here, key size for every cipher must be the same */
	vk = crypt_alloc_volume_key(algs->cipher[0].key_size +
				    algs->cipher[0].key_extra_size, NULL);
	if (!vk) {
		r = -ENOMEM;
		goto out;
	}

	for (i = algs->chain_count; i > 0; i--) {
		if (i == 1) {
			dm_name[sizeof(dm_name)-1] = '\0';
			strncpy(dm_name, name, sizeof(dm_name)-1);
			dmd.flags = flags;
		} else {
			if (snprintf(dm_name, sizeof(dm_name), "%s_%d", name, i-1) < 0) {
				r = -EINVAL;
				break;
			}
			dmd.flags = flags | CRYPT_ACTIVATE_PRIVATE;
		}

		key = crypt_safe_alloc(crypt_volume_key_length(vk));
		if (!key) {
			r = -ENOMEM;
			break;
		}

		TCRYPT_copy_key(&algs->cipher[i-1], algs->mode,
				key, hdr->d.keys);

		crypt_volume_key_pass_safe_alloc(vk, &key);

		if (algs->chain_count != i) {
			if (snprintf(dm_dev_name, sizeof(dm_dev_name), "%s/%s_%d", dm_get_dir(), name, i) < 0) {
				r = -EINVAL;
				break;
			}
			r = device_alloc(cd, &device, dm_dev_name);
			if (r)
				break;
			ptr_dev = device;
			offset = 0;
		}

		r = snprintf(cipher_spec, sizeof(cipher_spec), "%s-%s", algs->cipher[i-1].name, algs->mode);
		if (r < 0 || (size_t)r >= sizeof(cipher_spec)) {
			r = -ENOMEM;
			break;
		}

		r = dm_crypt_target_set(&dmd.segment, 0, dmd.size, ptr_dev, vk,
				cipher_spec, iv_offset, offset, NULL, 0, 0, crypt_get_sector_size(cd));
		if (r)
			break;

		log_dbg(cd, "Trying to activate TCRYPT device %s using cipher %s.",
			dm_name, dmd.segment.u.crypt.cipher);
		r = dm_create_device(cd, dm_name, i == 1 ? CRYPT_TCRYPT : CRYPT_SUBDEV, &dmd);

		dm_targets_free(cd, &dmd);
		device_free(cd, device);
		device = NULL;

		if (r)
			break;
	}

	if (r < 0 &&
	    (dm_flags(cd, DM_CRYPT, &dmc_flags) || ((dmc_flags & req_flags) != req_flags))) {
		log_err(cd, _("Kernel does not support TCRYPT compatible mapping."));
		r = -ENOTSUP;
	}

out:
	crypt_safe_free(key);
	crypt_free_volume_key(vk);
	device_free(cd, device);
	device_free(cd, part_device);
	return r;
}

static bool is_tcrypt_subdev(const char *dm_uuid, const char *base_uuid)
{
	const char *base_uuid_name;

	assert(base_uuid);
	base_uuid_name = strchr(base_uuid, '-');

	if (!dm_uuid || !base_uuid_name)
		return false;

	if (!strncmp(dm_uuid, "SUBDEV-", 7))
		return !strncmp(dm_uuid + 6, base_uuid_name, strlen(base_uuid_name));

	/*
	 * FIXME: Drop after shift to dependency based deactivation (CRYPT_SUBDEV)
	 * in later releases
	 */
	return !strncmp(dm_uuid, base_uuid, strlen(base_uuid));
}

static int TCRYPT_remove_one(struct crypt_device *cd, const char *name,
		      const char *base_uuid, int index, uint32_t flags)
{
	struct crypt_dm_active_device dmd;
	char dm_name[PATH_MAX];
	int r;

	if (snprintf(dm_name, sizeof(dm_name), "%s_%d", name, index) < 0)
		return -ENOMEM;

	r = dm_status_device(cd, dm_name);
	if (r < 0)
		return r;

	r = dm_query_device(cd, dm_name, DM_ACTIVE_UUID, &dmd);
	if (!r && is_tcrypt_subdev(dmd.uuid, base_uuid))
		r = dm_remove_device(cd, dm_name, flags);

	free(CONST_CAST(void*)dmd.uuid);
	return r;
}

int TCRYPT_deactivate(struct crypt_device *cd, const char *name, uint32_t flags)
{
	struct crypt_dm_active_device dmd;
	int r;

	r = dm_query_device(cd, name, DM_ACTIVE_UUID, &dmd);
	if (r < 0)
		return r;
	if (!dmd.uuid)
		return -EINVAL;

	r = dm_remove_device(cd, name, flags);
	if (r < 0)
		goto out;

	/* FIXME: replace with dependency based deactivation (CRYPT_SUBDEV) in later releases */
	r = TCRYPT_remove_one(cd, name, dmd.uuid, 1, flags);
	if (r < 0)
		goto out;

	r = TCRYPT_remove_one(cd, name, dmd.uuid, 2, flags);
out:
	free(CONST_CAST(void*)dmd.uuid);
	return (r == -ENODEV) ? 0 : r;
}

static int TCRYPT_status_one(struct crypt_device *cd, const char *name,
			     const char *base_uuid, int index,
			     size_t *key_size, char *cipher,
			     struct tcrypt_phdr *tcrypt_hdr,
			     struct device **device)
{
	struct crypt_dm_active_device dmd;
	struct dm_target *tgt = &dmd.segment;
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
	if (r < 0)
		return r;
	if (!single_segment(&dmd) || tgt->type != DM_CRYPT) {
		r = -ENOTSUP;
		goto out;
	}

	r = 0;

	if (is_tcrypt_subdev(dmd.uuid, base_uuid)) {
		if ((c = strchr(tgt->u.crypt.cipher, '-')))
			*c = '\0';
		strcat(cipher, "-");
		strncat(cipher, tgt->u.crypt.cipher, MAX_CIPHER_LEN);
		*key_size += crypt_volume_key_length(tgt->u.crypt.vk);
		tcrypt_hdr->d.mk_offset = tgt->u.crypt.offset * SECTOR_SIZE;
		device_free(cd, *device);
		MOVE_REF(*device, tgt->data_device);
	} else
		r = -ENODEV;
out:
	dm_targets_free(cd, &dmd);
	free(CONST_CAST(void*)dmd.uuid);
	return r;
}

int TCRYPT_init_by_name(struct crypt_device *cd, const char *name,
			const char *uuid,
			const struct dm_target *tgt,
			struct device **device,
			struct crypt_params_tcrypt *tcrypt_params,
			struct tcrypt_phdr *tcrypt_hdr)
{
	const struct tcrypt_algs *algs;
	char cipher[MAX_CIPHER_LEN * 4], mode[MAX_CIPHER_LEN+1], *tmp;
	size_t key_size;
	int r;

	memset(tcrypt_params, 0, sizeof(*tcrypt_params));
	memset(tcrypt_hdr, 0, sizeof(*tcrypt_hdr));
	tcrypt_hdr->d.sector_size = SECTOR_SIZE;
	tcrypt_hdr->d.mk_offset = tgt->u.crypt.offset * SECTOR_SIZE;

	strncpy(cipher, tgt->u.crypt.cipher, MAX_CIPHER_LEN);
	tmp = strchr(cipher, '-');
	if (!tmp)
		return -EINVAL;
	*tmp = '\0';
	mode[MAX_CIPHER_LEN] = '\0';
	strncpy(mode, ++tmp, MAX_CIPHER_LEN);

	key_size = crypt_volume_key_length(tgt->u.crypt.vk);
	r = TCRYPT_status_one(cd, name, uuid, 1, &key_size,
			      cipher, tcrypt_hdr, device);
	if (!r)
		r = TCRYPT_status_one(cd, name, uuid, 2, &key_size,
				      cipher, tcrypt_hdr, device);

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

	if (!hdr->d.version) {
		/* No real header loaded, initialized by active device, use default mk_offset */
	} else if (params->flags & CRYPT_TCRYPT_SYSTEM_HEADER) {
		/* Mapping through whole device or partition, return mk_offset */
	} else if (params->mode && !strncmp(params->mode, "xts", 3)) {
		if (hdr->d.version < 3)
			return 1;

		if (params->flags & CRYPT_TCRYPT_HIDDEN_HEADER) {
			if (hdr->d.version > 3)
				return (hdr->d.mk_offset / SECTOR_SIZE);
			if (device_size(crypt_metadata_device(cd), &size) < 0)
				return 0;
			return (size - hdr->d.hidden_volume_size +
				(TCRYPT_HDR_HIDDEN_OFFSET_OLD)) / SECTOR_SIZE;
		}
	} else if (params->flags & CRYPT_TCRYPT_HIDDEN_HEADER) {
		if (device_size(crypt_metadata_device(cd), &size) < 0)
			return 0;
		return (size - hdr->d.hidden_volume_size +
			(TCRYPT_HDR_HIDDEN_OFFSET_OLD)) / SECTOR_SIZE;
	}

	return hdr->d.mk_offset / SECTOR_SIZE;
}

uint64_t TCRYPT_get_iv_offset(struct crypt_device *cd,
			      struct tcrypt_phdr *hdr,
			      struct crypt_params_tcrypt *params)
{
	if (params->mode && !strncmp(params->mode, "xts", 3))
		return TCRYPT_get_data_offset(cd, hdr, params);
	else if (params->mode && !strncmp(params->mode, "lrw", 3))
		return 0;

	return hdr->d.mk_offset / SECTOR_SIZE;
}

int TCRYPT_get_volume_key(struct crypt_device *cd,
			  struct tcrypt_phdr *hdr,
			  struct crypt_params_tcrypt *params,
			  struct volume_key **vk)
{
	const struct tcrypt_algs *algs;
	unsigned int i, key_index;
	void *key = NULL;

	if (!hdr->d.version) {
		log_err(cd, _("This function is not supported without TCRYPT header load."));
		return -ENOTSUP;
	}

	algs = TCRYPT_get_algs(params->cipher, params->mode);
	if (!algs)
		return -EINVAL;

	key = crypt_safe_alloc(params->key_size);
	if (!key)
		return -ENOMEM;

	for (i = 0, key_index = 0; i < algs->chain_count; i++) {
		TCRYPT_copy_key(&algs->cipher[i], algs->mode,
				&((char *)key)[key_index], hdr->d.keys);
		key_index += algs->cipher[i].key_size;
	}

	*vk = crypt_alloc_volume_key_by_safe_alloc(&key);
	if (!*vk) {
		crypt_safe_free(key);
		return -ENOMEM;
	}

	return 0;
}

int TCRYPT_dump(struct crypt_device *cd,
		struct tcrypt_phdr *hdr,
		struct crypt_params_tcrypt *params)
{
	log_std(cd, "%s header information for %s\n",
		hdr->d.magic[0] == 'T' ? "TCRYPT" : "VERACRYPT",
		device_path(crypt_metadata_device(cd)));
	if (hdr->d.version) {
		log_std(cd, "Version:       \t%d\n", hdr->d.version);
		log_std(cd, "Driver req.:\t%x.%x\n", hdr->d.version_tc >> 8,
						    hdr->d.version_tc & 0xFF);
		log_std(cd, "Flags:       \t0x%x\n", hdr->d.flags);

		log_std(cd, "Sector size:\t%" PRIu32 " [bytes]\n", hdr->d.sector_size);
		log_std(cd, "MK offset:\t%" PRIu64 " [bytes]\n", hdr->d.mk_offset);
		if (hdr->d.volume_size)
			log_std(cd, "Volume size:\t%" PRIu64 " [bytes]\n", hdr->d.volume_size);
		if (hdr->d.hidden_volume_size)
			log_std(cd, "Hidden size:\t%" PRIu64 " [bytes]\n", hdr->d.hidden_volume_size);
		log_std(cd, "PBKDF2 hash:\t%s\n", params->hash_name);
	}
	log_std(cd, "Cipher chain:\t%s\n", params->cipher);
	log_std(cd, "Cipher mode:\t%s\n", params->mode);
	log_std(cd, "MK bits:       \t%zu\n", params->key_size * 8);
	return 0;
}
