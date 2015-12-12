/*
 * dm-verity Forward Error Correction (FEC) support
 *
 * Copyright (C) 2015, Google, Inc. All rights reserved.
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "verity.h"
#include "internal.h"
#include "fec.h"
#include "libfec/fec.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) \
		sizeof(array) / sizeof(array[0])
#endif

#define FEC_SIGNATURE "fec...\0\0"
#define FEC_VERSION 0

struct fec_sb {
	uint8_t  signature[8];	/* "fec...\0\0" */
	uint32_t version;	/* superblock version */
	uint8_t  _pad1[4];
	uint32_t roots;		/* parity bytes */
	uint64_t blocks;	/* number of data blocks */
	uint8_t  _pad2[484];
} __attribute__((packed));

struct fec_input_device {
	struct device *device;
	int fd;
	uint64_t start;
	uint64_t count;
};

struct fec_context {
	int rsn;
	int roots;
	uint64_t size;
	uint64_t blocks;
	uint64_t rounds;
	uint32_t block_size;
	struct fec_input_device *inputs;
	size_t ninputs;
};

/* computes ceil(x / y) */
static inline uint64_t FEC_div_round_up(uint64_t x, uint64_t y)
{
	return (x / y) + (x % y > 0 ? 1 : 0);
}

/* writes the entire data buffer to fd */
int FEC_write(int fd, const void *p, size_t count)
{
	const uint8_t *data = (const uint8_t *)p;
	size_t left = count;

	while (left > 0) {
		ssize_t n = TEMP_FAILURE_RETRY(write(fd, data, left));

		if (n == -1)
			return -errno;

		data += n;
		left -= n;
	}

	return 0;
}

/* reads count bytes to data from fd at offset */
int FEC_pread(int fd, uint8_t *data, size_t count, uint64_t offset)
{
	size_t left = count;

	while (left > 0) {
		ssize_t n = TEMP_FAILURE_RETRY(pread64(fd, data, left,
				offset));

		if (n <= 0)
			return -errno;

		data += n;
		left -= n;
		offset += n;
	}

	return 0;
}

/* returns a physical offset for the given RS offset */
static inline uint64_t FEC_interleave(struct fec_context *ctx, uint64_t offset)
{
	return (offset / ctx->rsn) +
			(offset % ctx->rsn) * ctx->rounds * ctx->block_size;
}

/* returns data for a byte at the specified RS offset */
int FEC_read_interleaved(struct fec_context *ctx, uint64_t i, uint8_t *output,
			 size_t count)
{
	size_t n;
	uint64_t offset = FEC_interleave(ctx, i);

	/* offsets outside input area are assumed to contain zeros */
	if (offset >= ctx->size) {
		memset(output, 0, count);
		return 0;
	}

	/* find the correct input device and read from it */
	for (n = 0; n < ctx->ninputs; ++n) {
		if (offset >= ctx->inputs[n].count) {
			offset -= ctx->inputs[n].count;
			continue;
	}

	return FEC_pread(ctx->inputs[n].fd, output, count,
			 ctx->inputs[n].start + offset);
	}

	/* should never be reached */
	return -1;
}

static int FEC_write_sb(struct fec_context *ctx, int fd)
{
	struct fec_sb sb;

	memset(&sb, 0, sizeof(sb));
	memcpy(&sb.signature, FEC_SIGNATURE, sizeof(sb.signature));
	sb.version = FEC_VERSION;
	sb.roots = ctx->roots;
	sb.blocks = ctx->size / ctx->block_size;

	return FEC_write(fd, &sb, sizeof(sb));
}

/* encodes inputs to fd */
static int FEC_encode_inputs(struct crypt_device *cd,
			     struct crypt_params_verity *params,
			     struct fec_input_device *inputs,
			     size_t ninputs, int fd)
{
	int r;
	int i;
	struct fec_context ctx;
	uint32_t b;
	uint64_t n;
	uint8_t parity[params->fec_roots];
	uint8_t rs_block[FEC_RSM];
	uint8_t *buf = NULL;
	void *rs;

	/* initialize parameters */
	ctx.roots = params->fec_roots;
	ctx.rsn = FEC_RSM - ctx.roots;
	ctx.block_size = params->data_block_size;
	ctx.inputs = inputs;
	ctx.ninputs = ninputs;

	rs = init_rs_char(FEC_PARAMS(ctx.roots));

	if (!rs) {
		log_err(cd, _("Failed to allocate RS context.\n"));
		return -ENOMEM;
	}

	/* calculate the total area covered by error correction codes */
	ctx.size = 0;
	for (n = 0; n < ctx.ninputs; ++n)
		ctx.size += ctx.inputs[n].count;

	/* each byte in a data block is covered by a different code */
	ctx.blocks = FEC_div_round_up(ctx.size, ctx.block_size);
	ctx.rounds = FEC_div_round_up(ctx.blocks, ctx.rsn);

	buf = malloc(ctx.rounds * ctx.block_size * ctx.roots);
	if (!buf) {
		log_err(cd, _("Failed to allocate buffer.\n"));
		return -ENOMEM;
	}

	/* write superblock */
	r = FEC_write_sb(&ctx, fd);
	if (r) {
		log_err(cd, _("Failed to write FEC superblock.\n"));
		goto out;
	}

	/* encode input */
	for (n = 0; n < ctx.rounds; ++n) {
		for (i = 0; i < ctx.rsn; ++i) {
			r = FEC_read_interleaved(&ctx,
				n * ctx.rsn * ctx.block_size + i,
				&buf[i * ctx.block_size],
				ctx.block_size);

			if (r) {
				log_err(cd, _("Failed to read RS block %"
					PRIu64 " byte %d.\n"), n, i);
				goto out;
			}
		}

		for (b = 0; b < ctx.block_size; ++b) {
			for (i = 0; i < ctx.rsn; ++i)
				rs_block[i] = buf[i * ctx.block_size + b];

			encode_rs_char(rs, rs_block, parity);
			r = FEC_write(fd, parity, sizeof(parity));

			if (r) {
				log_err(cd, _("Failed to write parity for RS "
					"block %" PRIu64 ".\n"), n);
				goto out;
			}
		}
	}

out:
	if (rs)
		free_rs_char(rs);

	free(buf);

	return r;
}

static int FEC_open_inputs(struct crypt_device *cd,
			   struct fec_input_device *inputs,
			   size_t ninputs)
{
	size_t n;

	for (n = 0; n < ninputs; ++n)
		inputs[n].fd = -1;

	for (n = 0; n < ninputs; ++n) {
		inputs[n].fd =
			TEMP_FAILURE_RETRY(open(device_path(inputs[n].device),
						O_RDWR));
		if (inputs[n].fd == -1) {
			log_err(cd, _("Failed to open %s.\n"),
				device_path(inputs[n].device));
			return -errno;
		}
	}

	return 0;
}

int VERITY_FEC_create(struct crypt_device *cd,
		      struct crypt_params_verity *params)
{
	int r;
	int fd = -1;
	struct fec_input_device inputs[2];

	/* validate parameters */
	if (params->data_block_size != params->hash_block_size) {
		log_err(cd, _("Block sizes must match for FEC.\n"));
		return -EINVAL;
	}

	if (params->fec_roots > FEC_RSM - FEC_MIN_RSN ||
		params->fec_roots < FEC_RSM - FEC_MAX_RSN) {
		log_err(cd, _("Invalid number of parity bytes.\n"));
		return -EINVAL;
	}

	/* open the output device */
	fd = TEMP_FAILURE_RETRY(open(params->fec_device, O_RDWR | O_CLOEXEC));
	if (fd == -1) {
		log_err(cd, _("Cannot open device %s.\n"), params->fec_device);
		return -errno;
	}

	/* input devices */
	memset(inputs, 0, sizeof(inputs));

	inputs[0].device = crypt_data_device(cd);
	inputs[0].count = params->data_size * params->data_block_size;

	/* cover the entire hash device starting from hash_offset */
	inputs[1].device = crypt_metadata_device(cd);
	inputs[1].start = VERITY_hash_offset_block(params) *
				params->data_block_size;

	r = device_size(crypt_metadata_device(cd), &inputs[1].count);
	if (r) {
		log_err(cd, _("Failed to determine size for device %s.\n"),
				device_path(crypt_metadata_device(cd)));
		goto out;
	}

	inputs[1].count -= inputs[1].start;

	r = FEC_open_inputs(cd, inputs, ARRAY_SIZE(inputs));
	if (r)
		goto out;

	r = FEC_encode_inputs(cd, params, inputs, ARRAY_SIZE(inputs), fd);

out:
	if (inputs[0].fd != -1)
		TEMP_FAILURE_RETRY(close(inputs[0].fd));
	if (inputs[1].fd != -1)
		TEMP_FAILURE_RETRY(close(inputs[1].fd));
	if (fd != -1)
		TEMP_FAILURE_RETRY(close(fd));

	return r;
}
