/*
 * LUKS keyslot entropy tester. Works only for header version 1.
 *
 * Functionality: Determines sample entropy (symbols: bytes) for
 * each (by default) 512B sector in each used keyslot. If it
 * is lower than a threshold, the sector address is printed
 * as it is suspected of having non-"random" data in it, indicating
 * damage by overwriting. This can obviously not find overwriting
 * with random or random-like data (encrypted, compressed).
 *
 * Version history:
 *    v0.1: 09.09.2012 Initial release
 *    v0.2: 08.10.2012 Converted to use libcryptsetup
 *
 * Copyright (C) 2012, Arno Wagner <arno@wagner.name>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <math.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libcryptsetup.h>

const char *help =
"Version 0.2 [8.10.2012]\n"
"\n"
"    chk_luks_keyslots [options] luks-device \n"
"\n"
"This tool checks all keyslots of a LUKS device for \n"
"low entropy sections. If any are found, they are reported. \n"
"This allows to find areas damaged by things like filesystem \n"
"creation or RAID superblocks. \n"
"\n"
"Options: \n"
"  -t <num>  Entropy threshold. Possible values 0.0 ... 1.0 \n"
"            Default: 0.90, which works well for 512B sectors.\n"
"            For 512B sectors, you will get frequent misdetections\n"
"            at thresholds around 0.94\n"
"            Higher value: more sensitive but more false detections.\n"
"  -s <num>  Sector size. Must divide keyslot-size.\n"
"            Default: 512 Bytes.\n"
"            Values smaller than 128 are generally not very useful.\n"
"            For values smaller than the default, you need to adjust\n"
"            the threshold down to reduce misdetection. For values\n"
"            larger than the default you need to adjust the threshold\n"
"            up to retain sensitivity.\n"
"  -v        Print found suspicious sectors verbosely. \n"
"  -d        Print decimal addresses instead of hex ones.\n"
"\n";


/* Config defaults */

static int sector_size = 512;
static double threshold = 0.90;
static int print_decimal = 0;
static int verbose = 0;

/* tools */

/* Calculates and returns sample entropy on byte level for
 * The argument.
 */
static double ent_samp(unsigned char * buf, int len)
{
	int freq[256];   /* stores symbol frequencies */
	int i;
	double e, f;

	/* 0. Plausibility checks */
	if (len <= 0)
		return 0.0;

	/* 1. count all frequencies */
	for (i = 0; i < 256; i++) {
		freq[i] = 0.0;
	}

	for (i = 0; i < len; i ++)
		freq[buf[i]]++;

	/* 2. calculate sample entropy */
	e = 0.0;
	for (i = 0; i < 256; i++) {
		f = freq[i];
		if (f > 0) {
			f =  f / (double)len;
			e += f * log2(f);
		}
	}

	if (e != 0.0)
		e = -1.0 * e;

	e = e / 8.0;
	return e;
}

static void print_address(FILE *out, uint64_t value)
{
	if (print_decimal) {
		fprintf(out,"%08" PRIu64 " ", value);
	} else {
		fprintf(out,"%#08" PRIx64 " ", value);
	}
}

/* uses default "hd" style, i.e. 16 bytes followed by ASCII */
static void hexdump_line(FILE *out, uint64_t address, unsigned char *buf) {
	int i;
	static char tbl[16] = "0123456789ABCDEF";

	fprintf(out,"  ");
	print_address(out, address);
	fprintf(out," ");

	/* hex */
	for (i = 0; i < 16; i++) {
		fprintf(out, "%c%c",
			tbl[(unsigned char)buf[i]>> 4],
			tbl[(unsigned char)buf[i] & 0x0f]);
		fprintf(out," ");
		if (i == 7)
			fprintf(out," ");
	}

	fprintf(out," ");

	/* ascii */
	for (i = 0; i < 16; i++) {
		if (isprint(buf[i])) {
			fprintf(out, "%c", buf[i]);
		} else {
			fprintf(out, ".");
		}
	}
	fprintf(out, "\n");
}

static void hexdump_sector(FILE *out, unsigned char *buf, uint64_t address, int len)
{
	int done;

	done = 0;
	while (len - done >= 16) {
		hexdump_line(out, address + done, buf + done);
		done += 16;
	}
}

static int check_keyslots(FILE *out, struct crypt_device *cd, int f_luks)
{
	int i;
	double ent;
	off_t ofs;
	uint64_t start, length, end;
	crypt_keyslot_info ki;
	unsigned char buffer[sector_size];

	for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS1) ; i++) {
		fprintf(out, "- processing keyslot %d:", i);
		ki = crypt_keyslot_status(cd, i);
		if (ki == CRYPT_SLOT_INACTIVE) {
			fprintf(out, "  keyslot not in use\n");
			continue;
		}

		if (ki == CRYPT_SLOT_INVALID) {
			fprintf(out, "\nError: keyslot invalid.\n");
			return EXIT_FAILURE;
		}

		if (crypt_keyslot_area(cd, i, &start, &length) < 0) {
			fprintf(stderr,"\nError: querying keyslot area failed for slot %d\n", i);
			perror(NULL);
			return EXIT_FAILURE;
		}
		end = start + length;

		fprintf(out, "  start: ");
		print_address(out, start);
		fprintf(out, "  end: ");
		print_address(out, end);
		fprintf(out, "\n");

		/* check whether sector-size divides size */
		if (length % sector_size != 0) {
			fprintf(stderr,"\nError: Argument to -s does not divide keyslot size\n");
			return EXIT_FAILURE;
		}

		for (ofs = start; (uint64_t)ofs < end; ofs += sector_size) {
			if (lseek(f_luks, ofs, SEEK_SET) != ofs) {
				fprintf(stderr,"\nCannot seek to keyslot area.\n");
				return EXIT_FAILURE;
			}
			if (read(f_luks, buffer, sector_size) != sector_size) {
				fprintf(stderr,"\nCannot read keyslot area.\n");
				return EXIT_FAILURE;
			}
			ent = ent_samp(buffer, sector_size);
			if (ent < threshold) {
				fprintf(out, "  low entropy at: ");
				print_address(out, ofs);
				fprintf(out, "   entropy: %f\n", ent);
				if (verbose) {
					fprintf(out, "  Binary dump:\n");
					hexdump_sector(out, buffer, (uint64_t)ofs, sector_size);
					fprintf(out,"\n");
				}
			}
		}
	}

	return EXIT_SUCCESS;
}

/* Main */
int main(int argc, char **argv)
{
	/* for option processing */
	int c, r;
	char *device;

	/* for use of libcryptsetup */
	struct crypt_device *cd;

	/* Other vars */
	int f_luks;   /* device file for the luks device */
	FILE *out;

	/* temporary helper vars */
	int res;

	/* getopt values */
	char *s, *end;
	double tvalue;
	int svalue;

	/* global initializations */
	out = stdout;

	/* get commandline parameters */
	while ((c = getopt (argc, argv, "t:s:vd")) != -1) {
		switch (c) {
		case 't':
			s = optarg;
			tvalue = strtod(s, &end);
			if (s == end) {
				fprintf(stderr, "\nError: Parsing of argument to -t failed.\n");
				exit(EXIT_FAILURE);
			}

			if (tvalue < 0.0 || tvalue > 1.0) {
				fprintf(stderr,"\nError: Argument to -t must be in 0.0 ... 1.0\n");
				exit(EXIT_FAILURE);
			}
			threshold = tvalue;
			break;
		case 's':
			s = optarg;
			svalue = strtol(s, &end, 10);
			if (s == end) {
				fprintf(stderr, "\nError: Parsing of argument to -s failed.\n");
				exit(EXIT_FAILURE);
			}

			if (svalue < 1) {
				fprintf(stderr,"\nError: Argument to -s must be >= 1 \n");
				exit(EXIT_FAILURE);
			}
			sector_size = svalue;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'd':
			print_decimal = 1;
			break;
		case '?':
			if (optopt == 't' || optopt == 's')
				fprintf (stderr,"\nError: Option -%c requires an argument.\n",
					 optopt);
			else if (isprint (optopt)) {
				fprintf(stderr,"\nError: Unknown option `-%c'.\n", optopt);
				fprintf(stderr,"\n\n%s", help);
			} else {
				fprintf (stderr, "\nError: Unknown option character `\\x%x'.\n",
					 optopt);
				fprintf(stderr,"\n\n%s", help);
			}
			exit(EXIT_SUCCESS);
		default:
			exit(EXIT_FAILURE);
		}
	}

	/* parse non-option stuff. Should be exactly one, the device. */
	if (optind+1 != argc) {
		fprintf(stderr,"\nError: exactly one non-option argument expected!\n");
		fprintf(stderr,"\n\n%s", help);
		exit(EXIT_FAILURE);
	}
	device = argv[optind];

	/* test whether we can open and read device */
	/* This is needed as we are reading the actual data
	* in the keyslots directly from the LUKS container.
	*/
	f_luks = open(device, O_RDONLY);
	if (f_luks == -1) {
		fprintf(stderr,"\nError: Opening of device %s failed:\n", device);
		perror(NULL);
		exit(EXIT_FAILURE);
	}

	/* now get the parameters we need via libcryptsetup */
	/* Basically we need all active keyslots and their placement on disk */

	/* first init. This does the following:
	 *   - gets us a crypt_device struct with some values filled in
	 *     Note: This does some init stuff we do not need, but that
	 *     should not cause trouble.
	 */

	res = crypt_init(&cd, device);
	if (res < 0) {
		fprintf(stderr, "crypt_init() failed. Maybe not running as root?\n");
		close(f_luks);
		exit(EXIT_FAILURE);
	}

	/* now load LUKS header into the crypt_device
	 * This should also make sure a valid LUKS1 header is on disk
	 * and hence we should be able to skip magic and version checks.
	 */
	res = crypt_load(cd, CRYPT_LUKS1, NULL);
	if (res < 0) {
		fprintf(stderr, "crypt_load() failed. LUKS header too broken/absent?\n");
		crypt_free(cd);
		close(f_luks);
		exit(EXIT_FAILURE);
	}

	fprintf(out, "\nparameters (commandline and LUKS header):\n");
	fprintf(out, "  sector size: %d\n", sector_size);
	fprintf(out, "  threshold:   %0f\n\n", threshold);

	r = check_keyslots(out, cd, f_luks);

	crypt_free(cd);
	close(f_luks);
	return r;
}
