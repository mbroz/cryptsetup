/*
 * FVAULT2 (FileVault2-compatible) volume handling
 *
 * Copyright (C) 2021-2022 Pavel Tobias
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
#include <regex.h>
#include <stdio.h>
#include <uuid/uuid.h>

#include "internal.h"
#include "fvault2.h"

/* Core Storage signature/magic; "CS" big-endian */
#define FVAULT2_CORE_STORAGE_MAGIC 0x4353

/* size of the physical volume header in bytes */
#define FVAULT2_VOL_HEADER_SIZE 512

/* size of a single metadata block in bytes */
#define FVAULT2_MD_BLOCK_SIZE 8192

/* encrypted metadata parsing progress flags (see _read_encrypted_metadata) */
#define FVAULT2_ENC_MD_PARSED_0x0019 0b001
#define FVAULT2_ENC_MD_PARSED_0x001A 0b010
#define FVAULT2_ENC_MD_PARSED_0x0305 0b100
#define FVAULT2_ENC_MD_PARSED_NONE 0b000
#define FVAULT2_ENC_MD_PARSED_ALL 0b111

/* sizes of decoded PassphraseWrappedKEKStruct and KEKWrappedVolumeKeyStruct */
#define FVAULT2_PWK_SIZE 284
#define FVAULT2_KWVK_SIZE 256

/* size of an AES-128 key */
#define FVAULT2_AES_KEY_SIZE 16

/* size of the volume key and the encrypted metadata decryption key */
#define FVAULT2_XTS_KEY_SIZE (FVAULT2_AES_KEY_SIZE * 2)

/* size of an XTS tweak value */
#define FVAULT2_XTS_TWEAK_SIZE 16

struct crc32_checksum {
	uint32_t value;
	uint32_t seed;
} __attribute__((packed));

struct volume_header {
	struct crc32_checksum checksum;
	uint16_t version;
	uint16_t block_type;
	uint8_t unknown1[52];
	uint64_t ph_vol_size;
	uint8_t unknown2[16];
	uint16_t magic;
	uint32_t checksum_algo;
	uint8_t unknown3[2];
	uint32_t block_size;
	uint32_t metadata_size;
	uint64_t disklbl_blkoff;
	uint64_t other_md_blkoffs[3];
	uint8_t unknown4[32];
	uint32_t key_data_size;
	uint32_t cipher;
	uint8_t key_data[FVAULT2_AES_KEY_SIZE];
	uint8_t unknown5[112];
	uint8_t ph_vol_uuid[FVAULT2_UUID_SIZE];
} __attribute__((packed));

struct volume_groups_descriptor {
	uint8_t unknown1[8];
	uint64_t enc_md_blocks_n;
	uint8_t unknown2[16];
	uint64_t enc_md_blkoff;
} __attribute__((packed));

struct metadata_block_header {
	struct crc32_checksum checksum;
	uint16_t version;
	uint16_t block_type;
	uint8_t unknown1[20];
	uint64_t block_num;
	uint8_t unknown2[8];
	uint32_t block_size;
	uint8_t unknown3[12];
} __attribute__((packed));

struct metadata_block_0x0011 {
	struct metadata_block_header header;
	uint32_t md_size;
	uint8_t unknown1[4];
	struct crc32_checksum checksum;
	uint8_t unknown2[140];
	uint32_t vol_gr_des_off;
} __attribute__((packed));

struct metadata_block_0x0019 {
	struct metadata_block_header header;
	uint8_t unknown1[40];
	uint32_t xml_comp_size;
	uint32_t xml_uncomp_size;
	uint32_t xml_off;
	uint32_t xml_size;
} __attribute__((packed));

struct metadata_block_0x001a {
	struct metadata_block_header header;
	uint8_t unknown1[64];
	uint32_t xml_off;
	uint32_t xml_size;
} __attribute__((packed));

struct metadata_block_0x0305 {
	struct metadata_block_header header;
	uint32_t entries_n;
	uint8_t unknown1[36];
	uint32_t log_vol_blkoff;
} __attribute__((packed));

struct passphrase_wrapped_kek {
	uint32_t pbkdf2_salt_type;
	uint32_t pbkdf2_salt_size;
	uint8_t pbkdf2_salt[FVAULT2_PBKDF2_SALT_SIZE];
	uint32_t wrapped_kek_type;
	uint32_t wrapped_kek_size;
	uint8_t wrapped_kek[FVAULT2_WRAPPED_KEY_SIZE];
	uint8_t unknown1[112];
	uint32_t pbkdf2_iters;
} __attribute__((packed));

struct kek_wrapped_volume_key {
	uint32_t wrapped_vk_type;
	uint32_t wrapped_vk_size;
	uint8_t wrapped_vk[FVAULT2_WRAPPED_KEY_SIZE];
} __attribute__((packed));

/**
 * Test whether all bytes of a chunk of memory are equal to a constant value.
 * @param[in] value the value all bytes should be equal to
 * @param[in] data the tested chunk of memory
 * @param[in] data_size byte-size of the chunk of memory
 */
static bool _filled_with(
	uint8_t value,
	const void *data,
	size_t data_size)
{
	const uint8_t *data_bytes = data;
	size_t i;

	for (i = 0; i < data_size; i++)
		if (data_bytes[i] != value)
			return false;

	return true;
}

/**
 * Assert the validity of the CRC checksum of a chunk of memory.
 * @param[in] data a chunk of memory starting with a crc32_checksum struct
 * @param[in] data_size the size of the chunk of memory in bytes
 */
static int _check_crc(
	const void *data,
	size_t data_size)
{
	const size_t crc_size = sizeof(struct crc32_checksum);
	uint32_t seed;
	uint32_t value;

	if (data_size < crc_size)
		return -EINVAL;

	value = le32_to_cpu(((const struct crc32_checksum *)data)->value);
	seed = le32_to_cpu(((const struct crc32_checksum *)data)->seed);
	if (seed != 0xffffffff)
		return -EINVAL;

	if (crypt_crc32c(seed, (const uint8_t *)data + crc_size,
			data_size - crc_size) != value)
		return -EINVAL;

	return 0;
}

/**
 * Search XML plist data for a property and return its value.
 * @param[in] xml a 0-terminated string containing the XML plist data
 * @param[in] prop_key a 0-terminated string with the seeked property's key
 * @param[in] prop_type a 0-terminated string with the seeked property's type
 * @param[out] value a 0-terminated string with the found property's value
 */
static int _search_xml(
	const char *xml,
	const char *prop_key,
	const char *prop_type,
	char **value)
{
	int r = 0;
	char *pattern = NULL;
	bool regex_ready = false;
	regex_t regex;
	regmatch_t match[2];
	const char *value_start;
	size_t value_len;

	if (asprintf(&pattern, "<key>%s</key><%s[^>]*>([^<]+)</%s>",
			prop_key, prop_type, prop_type) < 0) {
		r = -ENOMEM;
		goto out;
	}

	if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
		r = -EINVAL;
		goto out;
	}

	regex_ready = true;

	if (regexec(&regex, xml, 2, match, 0) != 0) {
		r = -EINVAL;
		goto out;
	}

	value_start = xml + match[1].rm_so;
	value_len = match[1].rm_eo - match[1].rm_so;

	*value = calloc(value_len + 1, 1);
	if (*value == NULL) {
		r = -ENOMEM;
		goto out;
	}

	memcpy(*value, value_start, value_len);

out:
	free(pattern);
	if (regex_ready)
		regfree(&regex);
	return r;
}

/**
 * Extract relevant info from a metadata block of type 0x0019.
 * @param[in] md_block the pre-read and decrypted metadata block
 * @param[out] pbkdf2_iters number of PBKDF2 iterations
 * @param[out] pbkdf2_salt PBKDF2 salt (intermt. key derivation from passphrase)
 * @param[out] wrapped_kek KEK AES-wrapped with passphrase-derived key
 * @param[out] wrapped_vk volume key AES-wrapped with KEK
 */
static int _parse_metadata_block_0x0019(
	const struct metadata_block_0x0019 *md_block,
	uint32_t *pbkdf2_iters,
	uint8_t *pbkdf2_salt,
	uint8_t *wrapped_kek,
	uint8_t *wrapped_vk)
{
	int r = 0;
	char *xml = NULL;
	char *pwk_base64 = NULL;
	char *kwvk_base64 = NULL;
	struct passphrase_wrapped_kek *pwk = NULL;
	struct kek_wrapped_volume_key *kwvk = NULL;
	size_t decoded_size;
	uint32_t xml_off = le32_to_cpu(md_block->xml_off);
	uint32_t xml_size = le32_to_cpu(md_block->xml_size);

	if (xml_off + xml_size > FVAULT2_MD_BLOCK_SIZE)
		return -EINVAL;

	xml = strndup((const char *)md_block + xml_off, xml_size);
	if (xml == NULL)
		return -ENOMEM;

	r = _search_xml(xml, "PassphraseWrappedKEKStruct", "data",
		&pwk_base64);
	if (r < 0)
		goto out;
	r = crypt_base64_decode((char **)&pwk, &decoded_size, pwk_base64,
		strlen(pwk_base64));
	if (r < 0)
		goto out;
	if (decoded_size != FVAULT2_PWK_SIZE) {
		r = -EINVAL;
		goto out;
	}

	r = _search_xml(xml, "KEKWrappedVolumeKeyStruct", "data",
		&kwvk_base64);
	if (r < 0)
		goto out;
	r = crypt_base64_decode((char **)&kwvk, &decoded_size, kwvk_base64,
		strlen(kwvk_base64));
	if (r < 0)
		goto out;
	if (decoded_size != FVAULT2_KWVK_SIZE) {
		r = -EINVAL;
		goto out;
	}

	*pbkdf2_iters = le32_to_cpu(pwk->pbkdf2_iters);
	memcpy(pbkdf2_salt, pwk->pbkdf2_salt, FVAULT2_PBKDF2_SALT_SIZE);
	memcpy(wrapped_kek, pwk->wrapped_kek, FVAULT2_WRAPPED_KEY_SIZE);
	memcpy(wrapped_vk, kwvk->wrapped_vk, FVAULT2_WRAPPED_KEY_SIZE);

out:
	free(xml);
	free(pwk_base64);
	free(kwvk_base64);
	free(pwk);
	free(kwvk);
	return r;
}

/**
 * Extract relevant info from a metadata block of type 0x001A.
 * @param[in] md_block the pre-read and decrypted metadata block
 * @param[out] log_vol_size encrypted logical volume size in bytes
 * @param[out] family_uuid logical volume family UUID
 */
static int _parse_metadata_block_0x001a(
	const struct metadata_block_0x001a *md_block,
	uint64_t *log_vol_size,
	uint8_t *family_uuid)
{
	int r = 0;
	char *xml = NULL;
	char *log_vol_size_str = NULL;
	char *family_uuid_str = NULL;
	uint32_t xml_off = le32_to_cpu(md_block->xml_off);
	uint32_t xml_size = le32_to_cpu(md_block->xml_size);

	if (xml_off + xml_size > FVAULT2_MD_BLOCK_SIZE)
		return -EINVAL;

	xml = strndup((const char *)md_block + xml_off, xml_size);
	if (xml == NULL)
		return -ENOMEM;

	r = _search_xml(xml, "com.apple.corestorage.lv.size", "integer",
		&log_vol_size_str);
	if (r < 0)
		goto out;
	*log_vol_size = strtoul(log_vol_size_str, NULL, 16);
	if (*log_vol_size == 0) {
		r = -EINVAL;
		goto out;
	}

	r = _search_xml(xml, "com.apple.corestorage.lv.familyUUID", "string",
		&family_uuid_str);
	if (r < 0)
		goto out;
	r = uuid_parse(family_uuid_str, family_uuid);
	if (r < 0)
		goto out;

out:
	free(xml);
	free(log_vol_size_str);
	free(family_uuid_str);
	return r;
}

/**
 * Extract relevant info from a metadata block of type 0x0305.
 * @param[in] md_block the pre-read and decrypted metadata block
 * @param[out] log_vol_blkoff block-offset of the encrypted logical volume
 */
static int _parse_metadata_block_0x0305(
	const struct metadata_block_0x0305 *md_block,
	uint32_t *log_vol_blkoff)
{
	*log_vol_blkoff = le32_to_cpu(md_block->log_vol_blkoff);
	return 0;
}

/**
 * Extract relevant info from the physical volume header.
 * @param[in] devfd opened device file descriptor
 * @param[in] cd crypt_device passed into FVAULT2_read_metadata
 * @param[out] block_size used to compute byte-offsets from block-offsets
 * @param[out] disklbl_blkoff block-offset of the disk label block
 * @param[out] ph_vol_uuid physical volume UUID
 * @param[out] enc_md_key AES-XTS key used to decrypt the encrypted metadata
 */
static int _read_volume_header(
	int devfd,
	struct crypt_device *cd,
	uint64_t *block_size,
	uint64_t *disklbl_blkoff,
	uint8_t *ph_vol_uuid,
	struct volume_key **enc_md_key)
{
	int r = 0;
	struct device *dev = crypt_metadata_device(cd);
	struct volume_header *vol_header = NULL;

	vol_header = malloc(FVAULT2_VOL_HEADER_SIZE);
	if (vol_header == NULL) {
		r = -ENOMEM;
		goto out;
	}

	if (read_blockwise(devfd, device_block_size(cd, dev),
			device_alignment(dev), vol_header,
			FVAULT2_VOL_HEADER_SIZE) != FVAULT2_VOL_HEADER_SIZE) {
		r = -EINVAL;
		goto out;
	}

	r = _check_crc(vol_header, FVAULT2_VOL_HEADER_SIZE);
	if (r)
		goto out;

	if (le16_to_cpu(vol_header->version) != 1) {
		r = -EINVAL;
		goto out;
	}

	if (be16_to_cpu(vol_header->magic) != FVAULT2_CORE_STORAGE_MAGIC) {
		r = -EINVAL;
		goto out;
	}

	if (le32_to_cpu(vol_header->key_data_size) != FVAULT2_AES_KEY_SIZE) {
		r = -EINVAL;
		goto out;
	}

	*enc_md_key = crypt_alloc_volume_key(FVAULT2_XTS_KEY_SIZE, NULL);
	if (*enc_md_key == NULL) {
		r = -ENOMEM;
		goto out;
	}

	*block_size = le32_to_cpu(vol_header->block_size);
	*disklbl_blkoff = le64_to_cpu(vol_header->disklbl_blkoff);
	memcpy(ph_vol_uuid, vol_header->ph_vol_uuid, FVAULT2_UUID_SIZE);
	memcpy((*enc_md_key)->key, vol_header->key_data, FVAULT2_AES_KEY_SIZE);
	memcpy((*enc_md_key)->key + FVAULT2_AES_KEY_SIZE,
		vol_header->ph_vol_uuid, FVAULT2_AES_KEY_SIZE);

out:
	free(vol_header);
	return r;
}

/**
 * Extract info from the disk label block and the volume groups descriptor.
 * @param[in] devfd opened device file descriptor
 * @param[in] cd crypt_device passed into FVAULT2_read_metadata
 * @param[in] block_size used to compute byte-offsets from block-offsets
 * @param[in] disklbl_blkoff block-offset of the disk label block
 * @param[out] enc_md_blkoff block-offset of the encrypted metadata
 * @param[out] enc_md_blocks_n total count of encrypted metadata blocks
 */
static int _read_disklabel(
	int devfd,
	struct crypt_device *cd,
	uint64_t block_size,
	uint64_t disklbl_blkoff,
	uint64_t *enc_md_blkoff,
	uint64_t *enc_md_blocks_n)
{
	int r = 0;
	off_t off;
	ssize_t size;
	struct metadata_block_0x0011 *md_block = NULL;
	struct volume_groups_descriptor *vol_gr_des = NULL;
	struct device *dev = crypt_metadata_device(cd);

	md_block = malloc(FVAULT2_MD_BLOCK_SIZE);
	if (md_block == NULL) {
		r = -ENOMEM;
		goto out;
	}

	off = block_size * disklbl_blkoff;
	size = FVAULT2_MD_BLOCK_SIZE;
	if (read_lseek_blockwise(devfd, device_block_size(cd, dev),
			device_alignment(dev), md_block, size, off) != size) {
		r = -EIO;
		goto out;
	}

	r = _check_crc(md_block, FVAULT2_MD_BLOCK_SIZE);
	if (r)
		goto out;

	vol_gr_des = malloc(sizeof(*vol_gr_des));
	if (vol_gr_des == NULL) {
		r = -ENOMEM;
		goto out;
	}

	off = block_size * disklbl_blkoff +
		le32_to_cpu(md_block->vol_gr_des_off);
	size = sizeof(struct volume_groups_descriptor);
	if (read_lseek_blockwise(devfd, device_block_size(cd, dev),
			device_alignment(dev), vol_gr_des, size, off) != size) {
		r = -EIO;
		goto out;
	}

	*enc_md_blkoff = le64_to_cpu(vol_gr_des->enc_md_blkoff);
	*enc_md_blocks_n = le64_to_cpu(vol_gr_des->enc_md_blocks_n);

out:
	free(md_block);
	free(vol_gr_des);
	return r;
}

/**
 * Extract info from relevant encrypted metadata blocks.
 * @param[in] devfd opened device file descriptor
 * @param[in] cd crypt_device passed into FVAULT2_read_metadata
 * @param[in] block_size used to compute byte-offsets from block-offsets
 * @param[in] start_blkoff block-offset of the start of the encrypted metadata
 * @param[in] blocks_n total count of encrypted metadata blocks
 * @param[in] key AES-XTS key for decryption
 * @param[out] params decryption parameters struct to fill
 */
static int _read_encrypted_metadata(
	int devfd,
	struct crypt_device *cd,
	uint64_t block_size,
	uint64_t start_blkoff,
	uint64_t blocks_n,
	const struct volume_key *key,
	struct fvault2_params *params)
{
	int r = 0;
	int status = FVAULT2_ENC_MD_PARSED_NONE;
	struct device *dev = crypt_metadata_device(cd);
	struct crypt_cipher *cipher = NULL;
	void *tweak;
	void *md_block_enc = NULL;
	void *md_block = NULL;
	struct metadata_block_header *md_block_header;
	uint32_t log_vol_blkoff;
	uint64_t i;
	off_t off;

	tweak = calloc(FVAULT2_XTS_TWEAK_SIZE, 1);
	if (tweak == NULL) {
		r = -ENOMEM;
		goto out;
	}

	md_block_enc = malloc(FVAULT2_MD_BLOCK_SIZE);
	if (md_block_enc == NULL) {
		r = -ENOMEM;
		goto out;
	}

	md_block = malloc(FVAULT2_MD_BLOCK_SIZE);
	if (md_block == NULL) {
		r = -ENOMEM;
		goto out;
	}

	r = crypt_cipher_init(&cipher, "aes", "xts", key->key,
		FVAULT2_XTS_KEY_SIZE);
	if (r < 0)
		goto out;

	for (i = 0; i < blocks_n; i++) {
		off = start_blkoff * block_size + i * FVAULT2_MD_BLOCK_SIZE;
		if (read_lseek_blockwise(devfd, device_block_size(cd, dev),
				device_alignment(dev), md_block_enc,
				FVAULT2_MD_BLOCK_SIZE, off)
				!= FVAULT2_MD_BLOCK_SIZE) {
			r = -EIO;
			goto out;
		}

		if (_filled_with(0, md_block_enc, FVAULT2_MD_BLOCK_SIZE))
			break;

		*(uint64_t *)tweak = cpu_to_le64(i);
		r = crypt_cipher_decrypt(cipher, md_block_enc, md_block,
			FVAULT2_MD_BLOCK_SIZE, tweak, FVAULT2_XTS_TWEAK_SIZE);
		if (r < 0)
			goto out;

		r = _check_crc(md_block, FVAULT2_MD_BLOCK_SIZE);
		if (r < 0)
			goto out;

		md_block_header = md_block;
		switch (le16_to_cpu(md_block_header->block_type)) {
		case 0x0019:
			r = _parse_metadata_block_0x0019(md_block,
				&params->pbkdf2_iters,
				(uint8_t *)params->pbkdf2_salt,
				(uint8_t *)params->wrapped_kek,
				(uint8_t *)params->wrapped_vk);
			if (r < 0)
				goto out;
			status |= FVAULT2_ENC_MD_PARSED_0x0019;
			break;

		case 0x001A:
			r = _parse_metadata_block_0x001a(md_block,
				&params->log_vol_size,
				(uint8_t *)params->family_uuid);
			if (r < 0)
				goto out;
			status |= FVAULT2_ENC_MD_PARSED_0x001A;
			break;

		case 0x0305:
			r = _parse_metadata_block_0x0305(md_block,
				&log_vol_blkoff);
			params->log_vol_off = log_vol_blkoff * block_size;
			if (r < 0)
				goto out;
			status |= FVAULT2_ENC_MD_PARSED_0x0305;
			break;
		}
	}

	if (status != FVAULT2_ENC_MD_PARSED_ALL) {
		r = -EINVAL;
		goto out;
	}

out:
	free(tweak);
	free(md_block_enc);
	free(md_block);
	if (cipher != NULL)
		crypt_cipher_destroy(cipher);
	return r;
}

int FVAULT2_read_metadata(
	struct crypt_device *cd,
	struct fvault2_params *params)
{
	int r = 0;
	int devfd;
	uint64_t block_size;
	uint64_t disklbl_blkoff;
	uint64_t enc_md_blkoff;
	uint64_t enc_md_blocks_n;
	struct volume_key *enc_md_key = NULL;

	devfd = device_open(cd, crypt_data_device(cd), O_RDONLY);
	if (devfd < 0) {
		r = -EIO;
		goto out;
	}

	r = _read_volume_header(devfd, cd, &block_size, &disklbl_blkoff,
		(uint8_t *)params->ph_vol_uuid, &enc_md_key);
	if (r < 0)
		goto out;

	r = _read_disklabel(devfd, cd, block_size, disklbl_blkoff,
		&enc_md_blkoff, &enc_md_blocks_n);
	if (r < 0)
		goto out;

	r = _read_encrypted_metadata(devfd, cd, block_size, enc_md_blkoff,
		enc_md_blocks_n, enc_md_key, params);
	if (r < 0)
		goto out;

	params->cipher = "aes";
	params->cipher_mode = "xts-plain64";
	params->key_size = FVAULT2_XTS_KEY_SIZE;

out:
	crypt_free_volume_key(enc_md_key);
	return r;
}

int FVAULT2_get_volume_key(
	struct crypt_device *cd,
	const char *passphr,
	size_t passphr_len,
	const struct fvault2_params *params,
	struct volume_key **vol_key)
{
	return -ENOTSUP;
}

int FVAULT2_dump(
	struct crypt_device *cd,
	struct device *device,
	const struct fvault2_params *params)
{
	return -ENOTSUP;
}

int FVAULT2_activate_by_passphrase(
	struct crypt_device *cd,
	const char *name,
	const char *passphr,
	size_t passphr_len,
	const struct fvault2_params *params,
	uint32_t flags)
{
	return -ENOTSUP;
}

int FVAULT2_activate_by_volume_key(
	struct crypt_device *cd,
	const char *name,
	const char *key,
	size_t key_size,
	const struct fvault2_params *params,
	uint32_t flags)
{
	return -ENOTSUP;
}
