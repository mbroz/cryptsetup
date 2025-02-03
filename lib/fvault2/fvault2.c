// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * FVAULT2 (FileVault2-compatible) volume handling
 *
 * Copyright (C) 2021-2022 Pavel Tobias
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

/* maximal offset to read metadata block */
#define FVAULT2_MAX_OFF 1024*1024*1024

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

/* size of a binary representation of a UUID */
#define FVAULT2_UUID_BIN_SIZE 16

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
	uint8_t ph_vol_uuid[FVAULT2_UUID_BIN_SIZE];
	uint8_t unknown6[192];
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

	assert(data_size >= crc_size);

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
 * Unwrap an AES-wrapped key.
 * @param[in] kek the KEK with which the key has been wrapped
 * @param[in] kek_size the size of the KEK in bytes
 * @param[in] key_wrapped the wrapped key
 * @param[in] key_wrapped_size the size of the wrapped key in bytes
 * @param[out] key_buf key an output buffer for the unwrapped key
 * @param[in] key_buf_size the size of the output buffer in bytes
 */
static int _unwrap_key(
	const void *kek,
	size_t kek_size,
	const void *key_wrapped,
	size_t key_wrapped_size,
	void *key_buf,
	size_t key_buf_size)
{
	/* Algorithm and notation taken from NIST Special Publication 800-38F:
	https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38F.pdf

	This implementation supports only 128-bit KEKs and wrapped keys. */

	int r = 0;
	struct crypt_cipher *cipher = NULL;
	void *cipher_in = NULL;
	void *cipher_out = NULL;
	uint64_t a;
	uint64_t r2;
	uint64_t r3;
	uint64_t t;
	uint64_t r2_prev;

	assert(kek_size == 16 && key_wrapped_size == 24 && key_buf_size == 16);

	r = crypt_cipher_init(&cipher, "aes", "ecb", kek, kek_size);
	if (r < 0)
		goto out;

	cipher_in = malloc(16);
	if (cipher_in == NULL) {
		r = -ENOMEM;
		goto out;
	}

	cipher_out = malloc(16);
	if (cipher_out == NULL) {
		r = -ENOMEM;
		goto out;
	}

	/* CHAPTER 6.1, ALGORITHM 2: W^-1(C) */

	/* initialize variables */
	a = ((const uint64_t *)key_wrapped)[0]; /* A = C_1 (see step 1c) */
	r2 = ((const uint64_t *)key_wrapped)[1]; /* R_1 = C_2 (see step 1d) */
	r3 = ((const uint64_t *)key_wrapped)[2]; /* R_2 = C_3 (see step 1d) */

	/* calculate intermediate values for each t = s, ..., 1 (see step 2),
	where s = 6 * (n - 1) (see step 1a) */
	for (t = 6 * (3 - 1); t > 0; t--) {
		/* store current R2 for later assignment (see step 2c) */
		r2_prev = r2;

		/* prepare input for CIPH^{-1}_K (see steps 2a, 2b) */
		((uint64_t *)cipher_in)[0] = a ^ cpu_to_be64(t);
		((uint64_t *)cipher_in)[1] = r3;

		/* A||R2 = CIPH^{-1}_K(...) (see steps 2a, 2b) */
		r = crypt_cipher_decrypt(cipher, cipher_in, cipher_out, 16, NULL, 0);
		if (r < 0)
			goto out;
		a = ((uint64_t *)cipher_out)[0];
		r2 = ((uint64_t *)cipher_out)[1];

		/* assign previous R2 (see step 2c) */
		r3 = r2_prev;
	}

	/* note that A||R_1||R_2 holds the result S (see step 3) */

	/* CHAPTER 6.2, ALGORITHM 4: KW-AD(C) */

	/* check whether MSB_{64}(S) (= A) matches ICV1 (see step 3) */
	if (a != 0xA6A6A6A6A6A6A6A6) {
		r = -EPERM;
		goto out;
	}

	/* return LSB_{128}(S) (= R_1||R_2) (see step 4) */
	((uint64_t *)key_buf)[0] = r2;
	((uint64_t *)key_buf)[1] = r3;
out:
	free(cipher_in);
	free(cipher_out);
	if (cipher != NULL)
		crypt_cipher_destroy(cipher);
	return r;
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

	r = _search_xml(xml, "PassphraseWrappedKEKStruct", "data", &pwk_base64);
	if (r < 0)
		goto out;
	r = crypt_base64_decode((char **)&pwk, &decoded_size, pwk_base64, strlen(pwk_base64));
	if (r < 0)
		goto out;
	if (decoded_size != FVAULT2_PWK_SIZE) {
		r = -EINVAL;
		goto out;
	}

	r = _search_xml(xml, "KEKWrappedVolumeKeyStruct", "data", &kwvk_base64);
	if (r < 0)
		goto out;
	r = crypt_base64_decode((char **)&kwvk, &decoded_size, kwvk_base64, strlen(kwvk_base64));
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
 * Validate a UUID string and reformat it to match system defaults.
 * @param[in] uuid_in the original UUID string
 * @param[out] uuid_out the reformatted UUID string
 */
static int _reformat_uuid(
	const char *uuid_in,
	char *uuid_out)
{
	uint8_t uuid_bin[FVAULT2_UUID_LEN];
	int r;

	r = uuid_parse(uuid_in, uuid_bin);
	if (r < 0)
		return -EINVAL;

	uuid_unparse(uuid_bin, uuid_out);
	return 0;
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
	char *family_uuid)
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

	r = _search_xml(xml, "com.apple.corestorage.lv.size", "integer", &log_vol_size_str);
	if (r < 0)
		goto out;
	*log_vol_size = strtoull(log_vol_size_str, NULL, 16);
	if (*log_vol_size == 0 || *log_vol_size == ULLONG_MAX) {
		r = -EINVAL;
		goto out;
	}

	r = _search_xml(xml, "com.apple.corestorage.lv.familyUUID", "string", &family_uuid_str);
	if (r < 0)
		goto out;
	r = _reformat_uuid(family_uuid_str, family_uuid);
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
	char *ph_vol_uuid,
	struct volume_key **enc_md_key)
{
	int r = 0;
	struct device *dev = crypt_metadata_device(cd);
	struct volume_header *vol_header = NULL;
	void *enc_key = NULL;

	assert(sizeof(*vol_header) == FVAULT2_VOL_HEADER_SIZE);

	vol_header = malloc(FVAULT2_VOL_HEADER_SIZE);
	if (vol_header == NULL) {
		r = -ENOMEM;
		goto out;
	}

	log_dbg(cd, "Reading FVAULT2 volume header of size %u bytes.", FVAULT2_VOL_HEADER_SIZE);
	if (read_blockwise(devfd, device_block_size(cd, dev),
			device_alignment(dev), vol_header,
			FVAULT2_VOL_HEADER_SIZE) != FVAULT2_VOL_HEADER_SIZE) {
		log_err(cd, _("Could not read %u bytes of volume header."), FVAULT2_VOL_HEADER_SIZE);
		r = -EIO;
		goto out;
	}

	r = _check_crc(vol_header, FVAULT2_VOL_HEADER_SIZE);
	if (r < 0) {
		log_dbg(cd, "CRC mismatch.");
		goto out;
	}

	if (le16_to_cpu(vol_header->version) != 1) {
		log_err(cd, _("Unsupported FVAULT2 version %" PRIu16 "."),
			le16_to_cpu(vol_header->version));
		r = -EINVAL;
		goto out;
	}

	if (be16_to_cpu(vol_header->magic) != FVAULT2_CORE_STORAGE_MAGIC) {
		log_dbg(cd, "Invalid Core Storage magic bytes.");
		r = -EINVAL;
		goto out;
	}

	if (le32_to_cpu(vol_header->key_data_size) != FVAULT2_AES_KEY_SIZE) {
		log_dbg(cd, "Unsupported AES key size: %" PRIu32 " bytes.",
			le32_to_cpu(vol_header->key_data_size));
		r = -EINVAL;
		goto out;
	}

	enc_key = crypt_safe_alloc(FVAULT2_XTS_KEY_SIZE);
	if (!enc_key) {
		r = -ENOMEM;
		goto out;
	}

	*block_size = le32_to_cpu(vol_header->block_size);
	*disklbl_blkoff = le64_to_cpu(vol_header->disklbl_blkoff);
	uuid_unparse(vol_header->ph_vol_uuid, ph_vol_uuid);
	crypt_safe_memcpy(enc_key, vol_header->key_data, FVAULT2_AES_KEY_SIZE);
	crypt_safe_memcpy((char *)enc_key + FVAULT2_AES_KEY_SIZE,
		vol_header->ph_vol_uuid, FVAULT2_AES_KEY_SIZE);

	*enc_md_key = crypt_alloc_volume_key_by_safe_alloc(&enc_key);
	if (*enc_md_key == NULL) {
		crypt_safe_free(enc_key);
		r = -ENOMEM;
	}
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
	uint64_t off;
	ssize_t size;
	void *md_block = NULL;
	struct metadata_block_0x0011 *md_block_11;
	struct volume_groups_descriptor *vol_gr_des = NULL;
	struct device *dev = crypt_metadata_device(cd);

	md_block = malloc(FVAULT2_MD_BLOCK_SIZE);
	if (md_block == NULL) {
		r = -ENOMEM;
		goto out;
	}

	if (uint64_mult_overflow(&off, disklbl_blkoff, block_size) ||
	    off > FVAULT2_MAX_OFF) {
		log_dbg(cd, "Device offset overflow.");
		r = -EINVAL;
		goto out;
	}
	size = FVAULT2_MD_BLOCK_SIZE;
	log_dbg(cd, "Reading FVAULT2 disk label header of size %zu bytes.", size);
	if (read_lseek_blockwise(devfd, device_block_size(cd, dev),
			device_alignment(dev), md_block, size, off) != size) {
		r = -EIO;
		goto out;
	}

	r = _check_crc(md_block, FVAULT2_MD_BLOCK_SIZE);
	if (r < 0) {
		log_dbg(cd, "CRC mismatch.");
		goto out;
	}

	vol_gr_des = malloc(sizeof(*vol_gr_des));
	if (vol_gr_des == NULL) {
		r = -ENOMEM;
		goto out;
	}

	md_block_11 = md_block;
	off += le32_to_cpu(md_block_11->vol_gr_des_off);
	if (off > FVAULT2_MAX_OFF) {
		log_dbg(cd, "Device offset overflow.");
		r = -EINVAL;
		goto out;
	}
	size = sizeof(struct volume_groups_descriptor);
	log_dbg(cd, "Reading FVAULT2 volume groups descriptor of size %zu bytes.", size);
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
	uint64_t i, start_off;
	off_t off;
	unsigned int block_type;

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

	r = crypt_cipher_init(&cipher, "aes", "xts", crypt_volume_key_get_key(key), FVAULT2_XTS_KEY_SIZE);
	if (r < 0)
		goto out;

	if (uint64_mult_overflow(&start_off, start_blkoff, block_size) ||
	    start_off > FVAULT2_MAX_OFF) {
		log_dbg(cd, "Device offset overflow.");
		r = -EINVAL;
		goto out;
	}

	log_dbg(cd, "Reading FVAULT2 encrypted metadata blocks.");
	for (i = 0; i < blocks_n; i++) {
		off = start_off + i * FVAULT2_MD_BLOCK_SIZE;
		if (off > FVAULT2_MAX_OFF) {
			log_dbg(cd, "Device offset overflow.");
			r = -EINVAL;
			goto out;
		}
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
		if (r < 0) {
			log_dbg(cd, "CRC mismatch.");
			goto out;
		}

		md_block_header = md_block;
		block_type = le16_to_cpu(md_block_header->block_type);
		switch (block_type) {
		case 0x0019:
			log_dbg(cd, "Get FVAULT2 metadata block %" PRIu64 " type 0x0019.", i);
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
			log_dbg(cd, "Get FVAULT2 metadata block %" PRIu64 " type 0x001A.", i);
			r = _parse_metadata_block_0x001a(md_block,
				&params->log_vol_size,
				params->family_uuid);
			if (r < 0)
				goto out;
			status |= FVAULT2_ENC_MD_PARSED_0x001A;
			break;

		case 0x0305:
			log_dbg(cd, "Get FVAULT2 metadata block %" PRIu64 " type 0x0305.", i);
			r = _parse_metadata_block_0x0305(md_block,
				&log_vol_blkoff);
			if (r < 0)
				goto out;
			if (uint64_mult_overflow(&params->log_vol_off,
			    log_vol_blkoff, block_size)) {
				log_dbg(cd, "Device offset overflow.");
				r = -EINVAL;
				goto out;
			}
			status |= FVAULT2_ENC_MD_PARSED_0x0305;
			break;
		}
	}

	if (status != FVAULT2_ENC_MD_PARSED_ALL) {
		log_dbg(cd, "Necessary FVAULT2 metadata blocks not found.");
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

/**
 * Activate device.
 * @param[in] cd crypt_device struct passed into FVAULT2_activate_by_*
 * @param[in] name name of the mapped device
 * @param[in] vol_key the pre-derived AES-XTS volume key
 * @param[in] params logical volume decryption parameters
 * @param[in] flags flags assigned to the crypt_dm_active_device struct
 */
static int _activate(
	struct crypt_device *cd,
	const char *name,
	struct volume_key *vol_key,
	const struct fvault2_params *params,
	uint32_t flags)
{
	int r = 0;
	char *cipher = NULL;
	struct crypt_dm_active_device dm_dev = {
		.flags = flags,
		.size = params->log_vol_size / SECTOR_SIZE
	};

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_EXCL,
		crypt_get_data_offset(cd), &dm_dev.size, &dm_dev.flags);
	if (r)
		return r;

	if (asprintf(&cipher, "%s-%s", params->cipher, params->cipher_mode) < 0)
		return -ENOMEM;

	r = dm_crypt_target_set(&dm_dev.segment, 0, dm_dev.size,
		crypt_data_device(cd), vol_key, cipher,
		crypt_get_iv_offset(cd), crypt_get_data_offset(cd),
		NULL, 0, 0, crypt_get_sector_size(cd));

	if (!r)
		r = dm_create_device(cd, name, CRYPT_FVAULT2, &dm_dev);

	dm_targets_free(cd, &dm_dev);
	free(cipher);
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
	struct device *device = crypt_metadata_device(cd);

	devfd = device_open(cd, device, O_RDONLY);
	if (devfd < 0) {
		log_err(cd, _("Cannot open device %s."), device_path(device));
		return -EIO;
	}

	r = _read_volume_header(devfd, cd, &block_size, &disklbl_blkoff,
		params->ph_vol_uuid, &enc_md_key);
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
	const char *passphrase,
	size_t passphrase_len,
	const struct fvault2_params *params,
	struct volume_key **r_vol_key)
{
	int r = 0;
	uint8_t family_uuid_bin[FVAULT2_UUID_BIN_SIZE];
	struct crypt_hash *hash = NULL;
	void *passphrase_key = NULL, *kek = NULL, *vol_key= NULL;

	*r_vol_key = NULL;

	if (uuid_parse(params->family_uuid, family_uuid_bin) < 0) {
		log_dbg(cd, "Could not parse logical volume family UUID: %s.",
			params->family_uuid);
		r = -EINVAL;
		goto out;
	}

	passphrase_key = crypt_safe_alloc(FVAULT2_AES_KEY_SIZE);
	if (passphrase_key == NULL) {
		r = -ENOMEM;
		goto out;
	}

	r = crypt_pbkdf("pbkdf2", "sha256", passphrase, passphrase_len,
		params->pbkdf2_salt, FVAULT2_PBKDF2_SALT_SIZE, passphrase_key,
		FVAULT2_AES_KEY_SIZE, params->pbkdf2_iters, 0, 0);
	if (r < 0)
		goto out;

	kek = crypt_safe_alloc(FVAULT2_AES_KEY_SIZE);
	if (kek == NULL) {
		r = -ENOMEM;
		goto out;
	}

	r = _unwrap_key(passphrase_key, FVAULT2_AES_KEY_SIZE, params->wrapped_kek,
			FVAULT2_WRAPPED_KEY_SIZE, kek, FVAULT2_AES_KEY_SIZE);
	if (r < 0)
		goto out;

	vol_key = crypt_safe_alloc(FVAULT2_XTS_KEY_SIZE);
	if (vol_key == NULL) {
		r = -ENOMEM;
		goto out;
	}

	r = _unwrap_key(kek, FVAULT2_AES_KEY_SIZE, params->wrapped_vk,
		FVAULT2_WRAPPED_KEY_SIZE, vol_key, FVAULT2_AES_KEY_SIZE);
	if (r < 0)
		goto out;

	r = crypt_hash_init(&hash, "sha256");
	if (r < 0)
		goto out;
	r = crypt_hash_write(hash, vol_key, FVAULT2_AES_KEY_SIZE);
	if (r < 0)
		goto out;
	r = crypt_hash_write(hash, (char *)family_uuid_bin,
		FVAULT2_UUID_BIN_SIZE);
	if (r < 0)
		goto out;
	r = crypt_hash_final(hash, (char *)vol_key + FVAULT2_AES_KEY_SIZE,
		FVAULT2_AES_KEY_SIZE);
	if (r < 0)
		goto out;

	*r_vol_key = crypt_alloc_volume_key_by_safe_alloc(&vol_key);
	if (!*r_vol_key)
		r = -ENOMEM;
out:
	crypt_safe_free(passphrase_key);
	crypt_safe_free(kek);
	crypt_safe_free(vol_key);
	if (hash != NULL)
		crypt_hash_destroy(hash);
	return r;
}

int FVAULT2_dump(
	struct crypt_device *cd,
	struct device *device,
	const struct fvault2_params *params)
{
	log_std(cd, "Header information for FVAULT2 device %s.\n", device_path(device));

	log_std(cd, "Physical volume UUID: \t%s\n", params->ph_vol_uuid);
	log_std(cd, "Family UUID:          \t%s\n", params->family_uuid);

	log_std(cd, "Logical volume offset:\t%" PRIu64 " [bytes]\n", params->log_vol_off);

	log_std(cd, "Logical volume size:  \t%" PRIu64 " [bytes]\n",
		params->log_vol_size);

	log_std(cd, "Cipher:               \t%s\n", params->cipher);
	log_std(cd, "Cipher mode:          \t%s\n", params->cipher_mode);

	log_std(cd, "PBKDF2 iterations:    \t%" PRIu32 "\n", params->pbkdf2_iters);

	log_std(cd, "PBKDF2 salt:          \t");
	crypt_log_hex(cd, params->pbkdf2_salt, FVAULT2_PBKDF2_SALT_SIZE, " ", 0, NULL);
	log_std(cd, "\n");

	return 0;
}

int FVAULT2_activate_by_volume_key(
	struct crypt_device *cd,
	const char *name,
	struct volume_key *vk,
	const struct fvault2_params *params,
	uint32_t flags)
{
	assert(crypt_volume_key_length(vk) == FVAULT2_XTS_KEY_SIZE);

	return _activate(cd, name, vk, params, flags);
}

size_t FVAULT2_volume_key_size(void)
{
	return FVAULT2_XTS_KEY_SIZE;
}
