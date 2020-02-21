/*
 * dm-verity Forward Error Correction (FEC) support
 *
 * Copyright (C) 2015 Google, Inc. All rights reserved.
 * Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
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

#include <stdlib.h>
#include <errno.h>

#include "verity.h"
#include "internal.h"
#include "rs.h"

/* ecc parameters */
#define FEC_RSM 255
#define FEC_MIN_RSN 231
#define FEC_MAX_RSN 253

#define FEC_INPUT_DEVICES 2

/* parameters to init_rs_char */
#define FEC_PARAMS(roots) \
    8,          /* symbol size in bits */ \
    0x11d,      /* field generator polynomial coefficients */ \
    0,          /* first root of the generator */ \
    1,          /* primitive element to generate polynomial roots */ \
    (roots),    /* polynomial degree (number of roots) */ \
    0           /* padding bytes at the front of shortened block */

struct fec_input_device {
	struct device *device;
	int fd;
	uint64_t start;
	uint64_t count;
};

struct fec_context {
	uint32_t rsn;
	uint32_t roots;
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

/* returns a physical offset for the given RS offset */
static inline uint64_t FEC_interleave(struct fec_context *ctx, uint64_t offset)
{
	return (offset / ctx->rsn) +
			(offset % ctx->rsn) * ctx->rounds * ctx->block_size;
}

/* returns data for a byte at the specified RS offset */
static int FEC_read_interleaved(struct fec_context *ctx, uint64_t i,
				void *output, size_t count)
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

		/* FIXME: read_lseek_blockwise candidate */
		if (lseek(ctx->inputs[n].fd, ctx->inputs[n].start + offset, SEEK_SET) < 0)
			return -1;
		return (read_buffer(ctx->inputs[n].fd, output, count) == (ssize_t)count) ? 0 : -1;
	}

	/* should never be reached */
	return -1;
}

/* encodes/decode inputs to/from fd */
static int FEC_process_inputs(struct crypt_device *cd,
			      struct crypt_params_verity *params,
			      struct fec_input_device *inputs,
			      size_t ninputs, int fd,
			      int decode, unsigned int *errors)
{
	int r = 0;
	unsigned int i;
	struct fec_context ctx;
	uint32_t b;
	uint64_t n;
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
		log_err(cd, _("Failed to allocate RS context."));
		return -ENOMEM;
	}

	/* calculate the total area covered by error correction codes */
	ctx.size = 0;
	for (n = 0; n < ctx.ninputs; ++n)
		ctx.size += ctx.inputs[n].count;

	/* each byte in a data block is covered by a different code */
	ctx.blocks = FEC_div_round_up(ctx.size, ctx.block_size);
	ctx.rounds = FEC_div_round_up(ctx.blocks, ctx.rsn);

	buf = malloc((size_t)ctx.block_size * ctx.rsn);
	if (!buf) {
		log_err(cd, _("Failed to allocate buffer."));
		r = -ENOMEM;
		goto out;
	}

	/* encode/decode input */
	for (n = 0; n < ctx.rounds; ++n) {
		for (i = 0; i < ctx.rsn; ++i) {
			if (FEC_read_interleaved(&ctx, n * ctx.rsn * ctx.block_size + i,
						 &buf[i * ctx.block_size], ctx.block_size)) {
				log_err(cd, _("Failed to read RS block %" PRIu64 " byte %d."), n, i);
				r = -EIO;
				goto out;
			}
		}

		for (b = 0; b < ctx.block_size; ++b) {
			for (i = 0; i < ctx.rsn; ++i)
				rs_block[i] = buf[i * ctx.block_size + b];

			/* decoding from parity device */
			if (decode) {
				if (read_buffer(fd, &rs_block[ctx.rsn], ctx.roots) < 0) {
					log_err(cd, _("Failed to read parity for RS block %" PRIu64 "."), n);
					r = -EIO;
					goto out;
				}

				/* coverity[tainted_data] */
				r = decode_rs_char(rs, rs_block);
				if (r < 0) {
					log_err(cd, _("Failed to repair parity for block %" PRIu64 "."), n);
					goto out;
				}
				/* return number of detected errors */
				if (errors)
					*errors += r;
				r = 0;
			} else {
				/* encoding and writing parity data to fec device */
				encode_rs_char(rs, rs_block, &rs_block[ctx.rsn]);
				if (write_buffer(fd, &rs_block[ctx.rsn], ctx.roots) < 0) {
					log_err(cd, _("Failed to write parity for RS block %" PRIu64 "."), n);
					r = -EIO;
					goto out;
				}
			}
		}
	}
out:
	free_rs_char(rs);
	free(buf);
	return r;
}

int VERITY_FEC_process(struct crypt_device *cd,
		      struct crypt_params_verity *params,
		      struct device *fec_device, int check_fec,
		      unsigned int *errors)
{
	int r;
	int fd = -1;
	struct fec_input_device inputs[FEC_INPUT_DEVICES] = {
		{
			.device = crypt_data_device(cd),
			.fd = -1,
			.start = 0,
			.count =  params->data_size * params->data_block_size
		},{
			.device = crypt_metadata_device(cd),
			.fd = -1,
			.start = VERITY_hash_offset_block(params) * params->data_block_size
		}
	};

	/* validate parameters */
	if (params->data_block_size != params->hash_block_size) {
		log_err(cd, _("Block sizes must match for FEC."));
		return -EINVAL;
	}

	if (params->fec_roots > FEC_RSM - FEC_MIN_RSN ||
		params->fec_roots < FEC_RSM - FEC_MAX_RSN) {
		log_err(cd, _("Invalid number of parity bytes."));
		return -EINVAL;
	}

	r = -EIO;

	if (check_fec)
		fd = open(device_path(fec_device), O_RDONLY);
	else
		fd = open(device_path(fec_device), O_RDWR);

	if (fd == -1) {
		log_err(cd, _("Cannot open device %s."), device_path(fec_device));
		goto out;
	}

	if (lseek(fd, params->fec_area_offset, SEEK_SET) < 0) {
		log_dbg(cd, "Cannot seek to requested position in FEC device.");
		goto out;
	}

	/* input devices */
	inputs[0].fd = open(device_path(inputs[0].device), O_RDONLY);
	if (inputs[0].fd == -1) {
		log_err(cd, _("Cannot open device %s."), device_path(inputs[0].device));
		goto out;
	}
	inputs[1].fd = open(device_path(inputs[1].device), O_RDONLY);
	if (inputs[1].fd == -1) {
		log_err(cd, _("Cannot open device %s."), device_path(inputs[1].device));
		goto out;
	}

	/* cover the entire hash device starting from hash_offset */
	r = device_size(inputs[1].device, &inputs[1].count);
	if (r) {
		log_err(cd, _("Failed to determine size for device %s."),
				device_path(inputs[1].device));
		goto out;
	}
	inputs[1].count -= inputs[1].start;

	r = FEC_process_inputs(cd, params, inputs, FEC_INPUT_DEVICES, fd, check_fec, errors);
out:
	if (inputs[0].fd != -1)
		close(inputs[0].fd);
	if (inputs[1].fd != -1)
		close(inputs[1].fd);
	if (fd != -1)
		close(fd);

	return r;
}
