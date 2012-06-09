/*
 * dm-verity volume handling
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
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
#include <stdint.h>

#include "verity.h"
#include "internal.h"

#define VERITY_MAX_LEVELS	63

static unsigned get_bits_up(size_t u)
{
	unsigned i = 0;
	while ((1 << i) < u)
		i++;
	return i;
}

static unsigned get_bits_down(size_t u)
{
	unsigned i = 0;
	while ((u >> i) > 1)
		i++;
	return i;
}

static int verify_zero(struct crypt_device *cd, FILE *wr, size_t bytes)
{
	char block[bytes];
	size_t i;

	if (fread(block, bytes, 1, wr) != 1)
		return -EIO;
	for (i = 0; i < bytes; i++)
		if (block[i]) {
			log_err(cd, _("Spare area is not zeroed at position %" PRIu64 ".\n"),
				ftello(wr) - bytes);
			return -EPERM;
		}
	return 0;
}

static int verify_hash_block(const char *hash_name, int version,
			      char *hash, size_t hash_size,
			      const char *data, size_t data_size,
			      const char *salt, size_t salt_size)
{
	struct crypt_hash *ctx = NULL;
	int r;

	if (crypt_hash_init(&ctx, hash_name))
		return -EINVAL;

	if (version == 1 && (r = crypt_hash_write(ctx, salt, salt_size)))
		goto out;

	if ((r = crypt_hash_write(ctx, data, data_size)))
		goto out;

	if (version == 0 && (r = crypt_hash_write(ctx, salt, salt_size)))
		goto out;

	r = crypt_hash_final(ctx, hash, hash_size);
out:
	crypt_hash_destroy(ctx);
	return r;
}

static int create_or_verify(struct crypt_device *cd, FILE *rd, FILE *wr,
				   off_t data_block, size_t data_block_size,
				   off_t hash_block, size_t hash_block_size,
				   off_t blocks, int version,
				   const char *hash_name, int verify,
				   char *calculated_digest, size_t digest_size,
				   const char *salt, size_t salt_size)
{
	char left_block[hash_block_size];
	char data_buffer[data_block_size];
	char read_digest[digest_size];
	size_t hash_per_block = 1 << get_bits_down(hash_block_size / digest_size);
	size_t digest_size_full = 1 << get_bits_up(digest_size);
	off_t blocks_to_write = (blocks + hash_per_block - 1) / hash_per_block;
	size_t left_bytes;
	int i, r;

	if (fseeko(rd, data_block * data_block_size, SEEK_SET))
		return -EIO;

	if (wr && fseeko(wr, hash_block * hash_block_size, SEEK_SET))
		return -EIO;

	memset(left_block, 0, hash_block_size);
	while (blocks_to_write--) {
		left_bytes = hash_block_size;
		for (i = 0; i < hash_per_block; i++) {
			if (!blocks)
				break;
			blocks--;
			if (fread(data_buffer, data_block_size, 1, rd) != 1)
				return -EIO;

			if (verify_hash_block(hash_name, version,
					calculated_digest, digest_size,
					data_buffer, data_block_size,
					salt, salt_size))
				return -EINVAL;

			if (!wr)
				break;
			if (verify) {
				if (fread(read_digest, digest_size, 1, wr) != 1)
					return -EIO;
				if (memcmp(read_digest, calculated_digest, digest_size)) {
					log_err(cd, _("Verification failed at position %" PRIu64 ".\n"),
						ftello(rd) - data_block_size);
					return -EPERM;
				}
			} else {
				if (fwrite(calculated_digest, digest_size, 1, wr) != 1)
					return -EIO;
			}
			if (version == 0) {
				left_bytes -= digest_size;
			} else {
				if (digest_size_full - digest_size) {
					if (verify) {
						r = verify_zero(cd, wr, digest_size_full - digest_size);
						if (r)
							return r;
					} else if (fwrite(left_block, digest_size_full - digest_size, 1, wr) != 1)
						return -EIO;
				}
				left_bytes -= digest_size_full;
			}
		}
		if (wr && left_bytes) {
			if (verify) {
				r = verify_zero(cd , wr, left_bytes);
				if (r)
					return r;
			} else if (fwrite(left_block, left_bytes, 1, wr) != 1)
				return -EIO;
		}
	}

	return 0;
}

static int VERITY_create_or_verify_hash(struct crypt_device *cd,
	int verify,
	int version,
	const char *hash_name,
	const char *hash_device,
	const char *data_device,
	size_t hash_block_size,
	size_t data_block_size,
	off_t data_blocks,
	off_t hash_position,
	char *root_hash,
	size_t digest_size,
	const char *salt,
	size_t salt_size)
{
	char calculated_digest[digest_size];
	FILE *data_file = NULL;
	FILE *hash_file = NULL, *hash_file_2;
	off_t hash_level_block[VERITY_MAX_LEVELS];
	off_t hash_level_size[VERITY_MAX_LEVELS];
	off_t data_file_blocks, s;
	size_t hash_per_block, hash_per_block_bits;
	uint64_t data_device_size;
	int levels, i, r;

	log_dbg("Hash %s %s, data device %s, data blocks %" PRIu64
		", hash_device %s, offset %" PRIu64 ".",
		verify ? "verification" : "creation", hash_name,
		data_device, data_blocks, hash_device, hash_position);

	if (!data_blocks) {
		r = device_size(data_device, &data_device_size);
		if (r < 0)
			return r;

		data_file_blocks = data_device_size / data_block_size;
	} else
		data_file_blocks = data_blocks;

	hash_per_block_bits = get_bits_down(hash_block_size / digest_size);
	hash_per_block = 1 << hash_per_block_bits;
	if (!hash_per_block_bits)
		return -EINVAL;

	levels = 0;
	if (data_file_blocks) {
		while (hash_per_block_bits * levels < 64 &&
		       (data_file_blocks - 1) >> (hash_per_block_bits * levels))
			levels++;
	}

	if (levels > VERITY_MAX_LEVELS) {
		log_err(cd, _("Too many tree levels for verity volume.\n"));
		return -EINVAL;
	}

	for (i = levels - 1; i >= 0; i--) {
		hash_level_block[i] = hash_position;
		// verity position of block data_file_blocks at level i
		s = data_file_blocks >> (i * hash_per_block_bits);
		s = (s + hash_per_block - 1) / hash_per_block;
		hash_level_size[i] = s;
		if (hash_position + s < hash_position ||
		    (hash_position + s) < 0 ||
		    (hash_position + s) != hash_position + s) {
			log_dbg("Hash device offset overflow.");
			return -EINVAL;
		}
		hash_position += s;
	}

	data_file = fopen(data_device, "r");
	if (!data_file) {
		log_err(cd, _("Cannot open device %s.\n"), data_device);
		r = -EIO;
		goto out;
	}

	hash_file = fopen(hash_device, verify ? "r" : "r+");
	if (!hash_file) {
		log_err(cd, _("Cannot open device %s.\n"), hash_device);
		r = -EIO;
		goto out;
	}

	memset(calculated_digest, 0, digest_size);

	for (i = 0; i < levels; i++) {
		if (!i) {
			r = create_or_verify(cd, data_file, hash_file,
						    0, data_block_size,
						    hash_level_block[i], hash_block_size,
						    data_file_blocks, version, hash_name, verify,
						    calculated_digest, digest_size, salt, salt_size);
			if (r)
				goto out;
		} else {
			hash_file_2 = fopen(hash_device, "r");
			if (!hash_file_2) {
				r = -EIO;
				goto out;
			}
			r = create_or_verify(cd, hash_file_2, hash_file,
						    hash_level_block[i - 1], hash_block_size,
						    hash_level_block[i], hash_block_size,
						    hash_level_size[i - 1], version, hash_name, verify,
						    calculated_digest, digest_size, salt, salt_size);
			fclose(hash_file_2);
			if (r)
				goto out;
		}
	}

	if (levels)
		r = create_or_verify(cd, hash_file, NULL,
					    hash_level_block[levels - 1], hash_block_size,
					    0, 0,
					    1, version, hash_name, verify,
					    calculated_digest, digest_size, salt, salt_size);
	else
		r = create_or_verify(cd, data_file, NULL,
					    0, data_block_size,
					    0, 0,
					    data_file_blocks, version, hash_name, verify,
					    calculated_digest, digest_size, salt, salt_size);

	if (r == -EPERM) {
		log_err(cd, _("Verification of data area failed.\n"));
		goto out;
	} else if (!r)
		log_dbg("Verification of data area succeeded.");

	/* root hash verification */
	if (verify) {
		r = memcmp(root_hash, calculated_digest, digest_size) ? -EPERM : 0;
		if (r)
			log_err(cd, _("Verification of root hash failed.\n"));
		else
			log_dbg("Verification of root hash succeeded.");
	} else {
		fsync(fileno(hash_file));
		memcpy(root_hash, calculated_digest, digest_size);
	}
out:
	if (data_file)
		fclose(data_file);
	if (hash_file)
		fclose(hash_file);
	return r;
}

/* Verify verity device using userspace crypto backend */
int VERITY_verify(struct crypt_device *cd,
		  struct crypt_params_verity *verity_hdr,
		  const char *data_device,
		  const char *hash_device,
		  const char *root_hash,
		  size_t root_hash_size)
{
	return VERITY_create_or_verify_hash(cd, 1,
		verity_hdr->hash_type,
		verity_hdr->hash_name,
		hash_device,
		data_device,
		verity_hdr->hash_block_size,
		verity_hdr->data_block_size,
		verity_hdr->data_size,
		VERITY_hash_offset_block(verity_hdr),
		CONST_CAST(char*)root_hash,
		root_hash_size,
		verity_hdr->salt,
		verity_hdr->salt_size);
}

/* Create verity hash */
int VERITY_create(struct crypt_device *cd,
		  struct crypt_params_verity *verity_hdr,
		  const char *data_device,
		  const char *hash_device,
		  char *root_hash,
		  size_t root_hash_size)
{
	int pgsize = crypt_getpagesize();

	if (verity_hdr->salt_size > 256)
		return -EINVAL;

	if (verity_hdr->hash_block_size > pgsize ||
	    verity_hdr->data_block_size > pgsize)
		log_err(cd, _("WARNING: Kernel cannot activate device if block "
			      "size exceeds page size (%u).\n"), pgsize);

	return VERITY_create_or_verify_hash(cd, 0,
		verity_hdr->hash_type,
		verity_hdr->hash_name,
		hash_device,
		data_device,
		verity_hdr->hash_block_size,
		verity_hdr->data_block_size,
		verity_hdr->data_size,
		VERITY_hash_offset_block(verity_hdr),
		root_hash,
		root_hash_size,
		verity_hdr->salt,
		verity_hdr->salt_size);
}
