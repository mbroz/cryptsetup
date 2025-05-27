// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup - keyslot randomness check
 *
 * Copyright (C) 2024-2025 Milan Broz
 */

#include <math.h>
#include "cryptsetup.h"
#include "utils_luks.h"

static uint64_t bitcount(uint64_t *p, uint64_t count64)
{
	uint64_t i, l, s = 0;

	for (i = 0; i < count64; i++) {
		l = *p++;

		if (l == 0)
			continue;

		l = (l & 0x5555555555555555ULL) + ((l >>  1) & 0x5555555555555555ULL);
		l = (l & 0x3333333333333333ULL) + ((l >>  2) & 0x3333333333333333ULL);
		l = (l & 0x0f0f0f0f0f0f0f0fULL) + ((l >>  4) & 0x0f0f0f0f0f0f0f0fULL);
		l = (l & 0x00ff00ff00ff00ffULL) + ((l >>  8) & 0x00ff00ff00ff00ffULL);
		l = (l & 0x0000ffff0000ffffULL) + ((l >> 16) & 0x0000ffff0000ffffULL);
		l = (l & 0x00000000ffffffffULL) + ((l >> 32) & 0x00000000ffffffffULL);

		s += l;
	}

	return s;
}

static double chisquared_bits(void *b, uint64_t count)
{
	size_t i;
	double f[2] = {0};
	double tmp, t = 0, e = count * 8 / (double)ARRAY_SIZE(f);

	f[1] = bitcount((uint64_t*)b, count / sizeof(uint64_t));
	f[0] = (count * 8) - f[1];

	for (i = 0; i < ARRAY_SIZE(f); i++) {
		/* t += pow(f[i] - e, 2) / e; */
		tmp = f[i] - e;
		tmp = tmp * tmp;
		tmp = tmp / e;
		t += tmp;
	}

	return t;
}

static double chisquared_bytes(unsigned char *N, uint64_t count)
{
	size_t i;
	double f[256] = {0};
	double tmp, t = 0, e = count / (double)ARRAY_SIZE(f);

	for (i = 0; i < count; i++)
		f[N[i]]++;

	for (i = 0; i < ARRAY_SIZE(f); i++) {
		/* t += pow(f[i] - e, 2) / e; */
		tmp = f[i] - e;
		tmp = tmp * tmp;
		tmp = tmp / e;
		t += tmp;
	}

	return t;
}

/*
 * The keyslot area is encrypted, it should contain pseudorandom data.
 * This function performs randomness analysis to detect a possible overwrite
 * with a low-entropy data  (causing keyslot corruption).
 * To limit false positives, it performs these checks:
 *    - splits the keyslot area to 4096-byte blocks
 *    - if the last block is a partial, it uses the last 4096 bytes instead
 *    - with 4096-byte blocks, run Chi-squared test (alpha 0.001 with right tail only)
 *      that expects uniform bytes distribution
 *    - if the test value is larger than the critical value,
 *      it tries to search in 128-byte subblocks
 *    - with 128-byte blocks, run Chi-squared test (alpha 0.0001 with right tail only)
 *      that expects uniform bits distribution
 *
 * Note: this test cannot detect all corruptions and can produce false positives.
 *       It is just a hint for the user.
 */
static void run_analysis(int keyslot, unsigned char *buffer,
			 uint64_t length, uint64_t start,
			 bool *hexdump_hint, int hint_max)
{
	const unsigned int BLOCK = 4096, SUBBLOCK = 128;
	uint64_t ofs, ofs2;
	bool suspected = false;
	int hint_count;

	log_dbg("Keyslot %d [0x%06" PRIx64 " - 0x%06" PRIx64 "] randomness analysis", keyslot, start, start + length);

	for (ofs = 0, hint_count = 0; ofs < length; ofs += BLOCK) {

		/* For the last incomplete block just use the last BLOCK bytes */
		if ((ofs + BLOCK) > length)
			ofs = length - BLOCK;

		/* Chi-squared: 256 buckets (bytes), alpha 0.001, right tail */
		if (chisquared_bytes(buffer + ofs, BLOCK) <= 330.5197)
			continue;

		if (!suspected)
			log_std(_("Keyslot %d binary data could be corrupted.\n"),  keyslot);
		suspected = true;

		for (ofs2 = 0; ofs2 < BLOCK && hint_count < hint_max; ofs2 += SUBBLOCK) {

			/* Chi-squared: 2 buckets (bits), alpha 0.0001, right tail */
			if (chisquared_bits(buffer + ofs + ofs2, SUBBLOCK) <= 15.1367)
				continue;

			if (hint_count < hint_max)
				log_std(_("  Suspected offset: 0x%" PRIx64 "\n"), start + ofs + ofs2);
			*hexdump_hint = true;
			if (++hint_count == hint_max)
				log_std(_("  Subsequent suspected offsets are suppressed.\n"), start + ofs + ofs2);
		}
	}
}

void luks_check_keyslots(struct crypt_device *cd, const char *device)
{
	crypt_keyslot_info ki;
	unsigned char *buffer = NULL;
	uint64_t start, length, data_length;
	int i, fd = -1, r = -EINVAL;
	bool hexdump_hint = false;

	if (crypt_reencrypt_status(cd, NULL) != CRYPT_REENCRYPT_NONE) {
		log_dbg("In reencryption, skipping keyslots randomness test.");
		return;
	}

	fd = open(device, O_RDONLY);
	if (fd == -1)
		return;

	for (i = 0; i < crypt_keyslot_max(crypt_get_type(cd)); i++) {

		ki = crypt_keyslot_status(cd, i);
		if (ki <= CRYPT_SLOT_INACTIVE || ki == CRYPT_SLOT_UNBOUND)
			continue;

		r = crypt_keyslot_area(cd, i, &start, &length);
		if (r < 0)
			goto out;

		r = crypt_keyslot_get_key_size(cd, i);
		if (r < 0)
			goto out;

		/* unbound key or something we should not run randomness analysis */
		if (r <= 1)
			continue;

		/*
		 * data_length is the really used keyslot area
		 * length = data_legth + padding_4096
		 */
		data_length = (uint64_t)r * LUKS_STRIPES;

		buffer = malloc(data_length);
		if (!buffer)
			goto out;

		if (lseek(fd, (off_t)start, SEEK_SET) == -1) {
			log_err(_("Keyslot %d cannot be read from the device."), i);
			goto out;
		}

		if (read_buffer(fd, buffer, data_length) != (ssize_t)data_length) {
			log_err(_("Keyslot %d cannot be read from the device."), i);
			goto out;
		}

		run_analysis(i, buffer, data_length, start, &hexdump_hint, 3);

		free(buffer);
		buffer = NULL;
	}

	if (hexdump_hint)
		log_std(_("You can use hexdump -v -C -n 128 -s <offset_0xXXXX> \"%s\" to inspect the data.\n"), device);
out:
	if (fd != -1)
		close(fd);
	free(buffer);
}
