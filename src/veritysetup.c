/*
 * veritysetup - setup cryptographic volumes for dm-verity
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

#define _FILE_OFFSET_BITS	64

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <arpa/inet.h>
#include <popt.h>

#include "crypto_backend.h"

#define DEFAULT_BLOCK_SIZE	4096
#define DM_VERITY_MAX_LEVELS	63

#define DEFAULT_SALT_SIZE	32
#define MAX_SALT_SIZE		384

#define MODE_VERIFY	0
#define MODE_CREATE	1
#define MODE_ACTIVATE	2

#define MAX_FORMAT_VERSION	1

static int mode = -1;
static int use_superblock = 1;

static const char *dm_device;
static const char *data_device;
static const char *hash_device;
static const char *hash_algorithm = NULL;
static const char *root_hash;

static int version = -1;
static int data_block_size = 0;
static int hash_block_size = 0;
static char *data_blocks_string = NULL;
static long long data_blocks = 0;
static char *hash_start_string = NULL;
static long long hash_start = 0;
static const char *salt_string = NULL;

static FILE *data_file;
static FILE *hash_file;

static off_t data_file_blocks;
static off_t hash_file_blocks;
static off_t used_hash_blocks;

static char *root_hash_bytes;
static char *calculated_digest;

static char *salt_bytes;
static unsigned salt_size;

static unsigned digest_size;
static unsigned char digest_size_bits;
static unsigned char levels;
static unsigned char hash_per_block_bits;

static off_t hash_level_block[DM_VERITY_MAX_LEVELS];
static off_t hash_level_size[DM_VERITY_MAX_LEVELS];

static off_t superblock_position;

static int retval = 0;

static int opt_debug = 0;

struct superblock {
	uint8_t signature[8];
	uint8_t version;
	uint8_t data_block_bits;
	uint8_t hash_block_bits;
	uint8_t pad1[1];
	uint16_t salt_size;
	uint8_t pad2[2];
	uint32_t data_blocks_hi;
	uint32_t data_blocks_lo;
	uint8_t algorithm[16];
	uint8_t salt[MAX_SALT_SIZE];
	uint8_t pad3[88];
};

#define DM_VERITY_SIGNATURE	"verity\0\0"
#define DM_VERITY_VERSION	0

__attribute__((format(printf, 5, 6)))
void logger(struct crypt_device *cd, int level, const char *file,
	   int line, const char *format, ...)
{
        va_list argp;
        char *target = NULL;

        va_start(argp, format);

        if (vasprintf(&target, format, argp) > 0) {
                if (level >= 0) {
                        printf("%s\n", target);
                } else if (opt_debug)
                        printf("# %s\n", target);
        }

        va_end(argp);
        free(target);
}

__attribute__((__noreturn__))
static void help(poptContext popt_context,
		 enum poptCallbackReason reason,
		 struct poptOption *key,
		 const char *arg,
		 void *data)
{
	if (!strcmp(key->longName, "help")) {
		poptPrintHelp(popt_context, stdout, 0);
	} else {
		printf("veritysetup");
		printf("\n");
	}
	exit(0);
}

static struct poptOption popt_help_options[] = {
	{ NULL,			0,	POPT_ARG_CALLBACK, help, 0, NULL, NULL },
	{ "help",		'h',	POPT_ARG_NONE, NULL, 0, "Show help", NULL },
	{ "version",		0,	POPT_ARG_NONE, NULL, 0, "Show version", NULL },
	POPT_TABLEEND
};

static struct poptOption popt_options[] = {
	{ NULL,			'\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, NULL, NULL },
	{ "create",		'c',	POPT_ARG_VAL, &mode, MODE_CREATE, "Create hash", NULL },
	{ "verify",		'v',	POPT_ARG_VAL, &mode, MODE_VERIFY, "Verify integrity", NULL },
	{ "activate",		'a',	POPT_ARG_VAL, &mode, MODE_ACTIVATE, "Activate the device", NULL },
	{ "no-superblock",	0,	POPT_ARG_VAL, &use_superblock, 0, "Do not create/use superblock" },
	{ "format",		0,	POPT_ARG_INT, &version, 0, "Format version (1 - normal format, 0 - original Chromium OS format)", "number" },
	{ "data-block-size",	0, 	POPT_ARG_INT, &data_block_size, 0, "Block size on the data device", "bytes" },
	{ "hash-block-size",	0, 	POPT_ARG_INT, &hash_block_size, 0, "Block size on the hash device", "bytes" },
	{ "data-blocks",	0,	POPT_ARG_STRING, &data_blocks_string, 0, "The number of blocks in the data file", "blocks" },
	{ "hash-start",		0,	POPT_ARG_STRING, &hash_start_string, 0, "Starting block on the hash device", "512-byte sectors" },
	{ "algorithm",		0,	POPT_ARG_STRING, &hash_algorithm, 0, "Hash algorithm (default sha256)", "string" },
	{ "salt",		0,	POPT_ARG_STRING, &salt_string, 0, "Salt", "hex string" },
	POPT_TABLEEND
};

__attribute__((__format__(__printf__, 1, 2), __noreturn__))
static void exit_err(const char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fputc('\n', stderr);
	exit(2);
}

__attribute__((__noreturn__))
static void stream_err(FILE *f, const char *msg)
{
	if (ferror(f)) {
		perror(msg);
		exit(2);
	} else if (feof(f)) {
		exit_err("eof on %s", msg);
	} else {
		exit_err("unknown error on %s", msg);
	}
}

static void *xmalloc(size_t s)
{
	void *ptr = malloc(!s ? 1 : s);
	if (!ptr) exit_err("out of memory");
	return ptr;
}

static char *xstrdup(const char *str)
{
	return strcpy(xmalloc(strlen(str) + 1), str);
}

static char *xprint(unsigned long long num)
{
	size_t s = snprintf(NULL, 0, "%llu", num);
	char *p = xmalloc(s + 1);
	snprintf(p, s + 1, "%llu", num);
	return p;
}

static char *xhexprint(char *bytes, size_t len)
{
	size_t i;
	char *p = xmalloc(len * 2 + 1);
	p[0] = 0;
	for (i = 0; i < len; i++)
		snprintf(p + i * 2, 3, "%02x", (unsigned char)bytes[i]);
	return p;
}

static off_t get_size(FILE *f, const char *name)
{
	struct stat st;
	int h = fileno(f);
	if (h < 0) {
		perror("fileno");
		exit(2);
	}
	if (fstat(h, &st)) {
		perror("fstat");
		exit(2);
	}
	if (S_ISREG(st.st_mode)) {
		return st.st_size;
	} else if (S_ISBLK(st.st_mode)) {
		unsigned long long size64;
		unsigned long sizeul;
		if (!ioctl(h, BLKGETSIZE64, &size64)) {
			return_size64:
			if ((off_t)size64 < 0 || (off_t)size64 != size64) {
				size_overflow:
				exit_err("%s: device size overflow", name);
			}
			return size64;
		}
		if (!ioctl(h, BLKGETSIZE, &sizeul)) {
			size64 = (unsigned long long)sizeul * 512;
			if (size64 / 512 != sizeul) goto size_overflow;
			goto return_size64;
		}
		perror("BLKGETSIZE");
		exit(2);
	} else {
		exit_err("%s is not a file or a block device", name);
	}
	return -1;	/* never reached, shut up warning */
}

static void block_fseek(FILE *f, off_t block, int block_size)
{
	unsigned long long pos = (unsigned long long)block * block_size;
	if (pos / block_size != block ||
	    (off_t)pos < 0 ||
	    (off_t)pos != pos)
		exit_err("seek position overflow");
	if (fseeko(f, pos, SEEK_SET)) {
		perror("fseek");
		exit(2);
	}
}

static off_t verity_position_at_level(off_t block, int level)
{
	return block >> (level * hash_per_block_bits);
}

static void calculate_positions(void)
{
	unsigned long long hash_position;
	int i;

	digest_size_bits = 0;
	while (1 << digest_size_bits < digest_size)
		digest_size_bits++;
	hash_per_block_bits = 0;
	while (((hash_block_size / digest_size) >> hash_per_block_bits) > 1)
		hash_per_block_bits++;
	if (!hash_per_block_bits)
		exit_err("at least two hashes must fit in a hash file block");
	levels = 0;

	if (data_file_blocks) {
		while (hash_per_block_bits * levels < 64 &&
		       (unsigned long long)(data_file_blocks - 1) >>
		       (hash_per_block_bits * levels))
			levels++;
	}

	if (levels > DM_VERITY_MAX_LEVELS)
		exit_err("too many tree levels");

	hash_position = hash_start * 512 / hash_block_size;
	for (i = levels - 1; i >= 0; i--) {
		off_t s;
		hash_level_block[i] = hash_position;
		s = verity_position_at_level(data_file_blocks, i);
		s = (s >> hash_per_block_bits) +
		    !!(s & ((1 << hash_per_block_bits) - 1));
		hash_level_size[i] = s;
		if (hash_position + s < hash_position ||
		    (off_t)(hash_position + s) < 0 ||
		    (off_t)(hash_position + s) != hash_position + s)
			exit_err("hash device offset overflow");
		hash_position += s;
	}
	used_hash_blocks = hash_position;
}

static void create_or_verify_zero(FILE *wr, char *left_block, unsigned left_bytes)
{
	if (left_bytes) {
		if (mode != MODE_CREATE) {
			unsigned x;
			if (fread(left_block, left_bytes, 1, wr) != 1)
				stream_err(wr, "read");
			for (x = 0; x < left_bytes; x++) if (left_block[x]) {
				retval = 1;
				fprintf(stderr, "spare area is not zeroed at position %lld\n", (long long)ftello(wr) - left_bytes);
			}
		} else {
			if (fwrite(left_block, left_bytes, 1, wr) != 1)
				stream_err(wr, "write");
		}
	}
}

static void create_or_verify_stream(FILE *rd, FILE *wr, int block_size, off_t blocks)
{
	char *left_block = xmalloc(hash_block_size);
	char *data_buffer = xmalloc(block_size);
	char *read_digest = mode != MODE_CREATE ? xmalloc(digest_size) : NULL;
	off_t blocks_to_write = (blocks >> hash_per_block_bits) +
				!!(blocks & ((1 << hash_per_block_bits) - 1));
	struct crypt_hash *ctx = NULL;

	if (crypt_hash_init(&ctx, hash_algorithm))
		exit_err("hash_init failed");

	memset(left_block, 0, hash_block_size);
	while (blocks_to_write--) {
		unsigned x;
		unsigned left_bytes = hash_block_size;
		for (x = 0; x < 1 << hash_per_block_bits; x++) {
			if (!blocks)
				break;
			blocks--;
			if (fread(data_buffer, block_size, 1, rd) != 1)
				stream_err(rd, "read");
			if (version >= 1) {
				if (crypt_hash_write(ctx, salt_bytes, salt_size))
					exit_err("hash_write failed");
			}
			if (crypt_hash_write(ctx, data_buffer, block_size))
				exit_err("hash_write failed");
			if (!version) {
				if (crypt_hash_write(ctx, salt_bytes, salt_size))
					exit_err("hash_write failed");
			}
			if (crypt_hash_final(ctx, calculated_digest, digest_size))
					exit_err("hash_final failed");
			if (!wr)
				break;
			if (mode != MODE_CREATE) {
				if (fread(read_digest, digest_size, 1, wr) != 1)
					stream_err(wr, "read");
				if (memcmp(read_digest, calculated_digest, digest_size)) {
					retval = 1;
					fprintf(stderr, "verification failed at position %lld in %s file\n", (long long)ftello(rd) - block_size, rd == data_file ? "data" : "metadata");
				}
			} else {
				if (fwrite(calculated_digest, digest_size, 1, wr) != 1)
					stream_err(wr, "write");
			}
			if (!version) {
				left_bytes -= digest_size;
			} else {
				create_or_verify_zero(wr, left_block, (1 << digest_size_bits) - digest_size);
				left_bytes -= 1 << digest_size_bits;
			}
		}
		if (wr)
			create_or_verify_zero(wr, left_block, left_bytes);
	}
	if (mode == MODE_CREATE && wr) {
		if (fflush(wr)) {
			perror("fflush");
			exit(1);
		}
		if (ferror(wr)) {
			stream_err(wr, "write");
		}
	}
	crypt_hash_destroy(ctx);
	free(left_block);
	free(data_buffer);
	if (mode != MODE_CREATE)
		free(read_digest);
}

static char **make_target_line(void)
{
	const int line_elements = 14;
	char **line = xmalloc(line_elements * sizeof(char *));
	int i = 0;
	char *algorithm_copy = xstrdup(hash_algorithm);
		/* transform ripemdXXX to rmdXXX */
	if (!strncmp(algorithm_copy, "ripemd", 6))
		memmove(algorithm_copy + 1, algorithm_copy + 4, strlen(algorithm_copy + 4) + 1);
	if (!strcmp(algorithm_copy, "whirlpool"))
		strcpy(algorithm_copy, "wp512");
	line[i++] = xstrdup("0");
	line[i++] = xprint((unsigned long long)data_file_blocks * data_block_size / 512);
	line[i++] = xstrdup("verity");
	line[i++] = xprint(version);
	line[i++] = xstrdup(data_device);
	line[i++] = xstrdup(hash_device);
	line[i++] = xprint(data_block_size);
	line[i++] = xprint(hash_block_size);
	line[i++] = xprint(data_file_blocks);
	line[i++] = xprint(hash_start * 512 / hash_block_size);
	line[i++] = algorithm_copy;
	line[i++] = xhexprint(calculated_digest, digest_size);
	line[i++] = !salt_size ? xstrdup("-") : xhexprint(salt_bytes, salt_size);
	line[i++] = NULL;
	if (i > line_elements)
		exit_err("INTERNAL ERROR: insufficient array size");
	return line;
}

static void free_target_line(char **line)
{
	int i;
	for (i = 0; line[i]; i++)
		free(line[i]);
	free(line);
}

static void create_or_verify(void)
{
	int i;

	memset(calculated_digest, 0, digest_size);
	if (mode != MODE_ACTIVATE)
		for (i = 0; i < levels; i++) {
			block_fseek(hash_file, hash_level_block[i], hash_block_size);
			if (!i) {
				block_fseek(data_file, 0, data_block_size);
				create_or_verify_stream(data_file, hash_file, data_block_size, data_file_blocks);
			} else {
				FILE *hash_file_2 = fopen(hash_device, "r");
				if (!hash_file_2) {
					perror(hash_device);
					exit(2);
				}
				block_fseek(hash_file_2, hash_level_block[i - 1], hash_block_size);
				create_or_verify_stream(hash_file_2, hash_file, hash_block_size, hash_level_size[i - 1]);
				fclose(hash_file_2);
			}
		}

	if (levels) {
		block_fseek(hash_file, hash_level_block[levels - 1], hash_block_size);
		create_or_verify_stream(hash_file, NULL, hash_block_size, 1);
	} else {
		block_fseek(data_file, 0, data_block_size);
		create_or_verify_stream(data_file, NULL, data_block_size, data_file_blocks);
	}

	if (mode != MODE_CREATE) {
		if (memcmp(calculated_digest, root_hash_bytes, digest_size)) {
			fprintf(stderr, "verification failed in the root block\n");
			retval = 1;
		}
		if (!retval && mode == MODE_VERIFY)
			fprintf(stderr, "hash successfully verified\n");
	} else {
		char **target_line;
		char *p;
		if (fsync(fileno(hash_file))) {
			perror("fsync");
			exit(1);
		}
		printf("hash device size: %llu\n", (unsigned long long)used_hash_blocks * hash_block_size);
		printf("data block size %u, hash block size %u, %u tree levels\n", data_block_size, hash_block_size, levels);
		if (salt_size)
			p = xhexprint(salt_bytes, salt_size);
		else
			p = xstrdup("-");
		printf("salt: %s\n", p);
		free(p);
		p = xhexprint(calculated_digest, digest_size);
		printf("root hash: %s\n", p);
		free(p);
		printf("target line:");
		target_line = make_target_line();
		for (i = 0; target_line[i]; i++)
			printf(" %s", target_line[i]);
		free_target_line(target_line);
		printf("\n");
	}
}

__attribute__((__noreturn__))
static void activate(void)
{
	int i;
	size_t len = 1;
	char *table_arg;
	char **target_line = make_target_line();
	for (i = 0; target_line[i]; i++) {
		if (i)
			len++;
		len += strlen(target_line[i]);
	}
	table_arg = xmalloc(len);
	table_arg[0] = 0;
	for (i = 0; target_line[i]; i++) {
		if (i)
			strcat(table_arg, " ");
		strcat(table_arg, target_line[i]);
	}
	free_target_line(target_line);
	execlp("dmsetup", "dmsetup", "-r", "create", dm_device, "--table", table_arg, NULL);
	perror("dmsetup");
	exit(2);
}

static void get_hex(const char *string, char **result, size_t len, const char *description)
{
	size_t rl = strlen(string);
	unsigned u;
	if (strspn(string, "0123456789ABCDEFabcdef") != rl)
		exit_err("invalid %s", description);
	if (rl != len * 2)
		exit_err("invalid length of %s", description);
	*result = xmalloc(len);
	memset(*result, 0, len);
	for (u = 0; u < rl; u++) {
		unsigned char c = (string[u] & 15) + (string[u] > '9' ? 9 : 0);
		(*result)[u / 2] |= c << (((u & 1) ^ 1) << 2);
	}
}

static struct superblock superblock;

static void load_superblock(void)
{
	long long sb_data_blocks;

	block_fseek(hash_file, superblock_position, 1);
	if (fread(&superblock, sizeof(struct superblock), 1, hash_file) != 1)
		stream_err(hash_file, "read");
	if (memcmp(superblock.signature, DM_VERITY_SIGNATURE, sizeof(superblock.signature)))
		exit_err("superblock not found on the hash device");
	if (superblock.version > MAX_FORMAT_VERSION)
		exit_err("unknown version");
	if (superblock.data_block_bits < 9 || superblock.data_block_bits >= 31)
		exit_err("invalid data_block_bits in the superblock");
	if (superblock.hash_block_bits < 9 || superblock.hash_block_bits >= 31)
		exit_err("invalid data_block_bits in the superblock");
	sb_data_blocks = ((unsigned long long)ntohl(superblock.data_blocks_hi) << 31 << 1) | ntohl(superblock.data_blocks_lo);
	if (sb_data_blocks < 0 || (off_t)sb_data_blocks < 0 || (off_t)sb_data_blocks != sb_data_blocks)
		exit_err("invalid data blocks in the superblock");
	if (!memchr(superblock.algorithm, 0, sizeof(superblock.algorithm)))
		exit_err("invalid hash algorithm in the superblock");
	if (ntohs(superblock.salt_size) > MAX_SALT_SIZE)
		exit_err("invalid salt_size in the superblock");

	if (version == -1) {
		version = superblock.version;
	} else {
		if (version != superblock.version)
			exit_err("version (%d) does not match superblock value (%d)", version, superblock.version);
	}

	if (!data_block_size) {
		data_block_size = 1 << superblock.data_block_bits;
	} else {
		if (data_block_size != 1 << superblock.data_block_bits)
			exit_err("data block size (%d) does not match superblock value (%d)", data_block_size, 1 << superblock.data_block_bits);
	}

	if (!hash_block_size) {
		hash_block_size = 1 << superblock.hash_block_bits;
	} else {
		if (hash_block_size != 1 << superblock.hash_block_bits)
			exit_err("hash block size (%d) does not match superblock value (%d)", hash_block_size, 1 << superblock.hash_block_bits);
	}

	if (!data_blocks_string) {
		data_blocks = sb_data_blocks;
		data_blocks_string = (char *)"";
	} else {
		if (data_blocks != sb_data_blocks)
			exit_err("data blocks (%lld) does not match superblock value (%lld)", data_blocks, sb_data_blocks);
	}

	if (!hash_algorithm) {
		hash_algorithm = (char *)superblock.algorithm;
	} else {
		if (strcmp(hash_algorithm, (char *)superblock.algorithm))
			exit_err("hash algorithm (%s) does not match superblock value (%s)", hash_algorithm, superblock.algorithm);
	}

	if (!salt_bytes) {
		salt_size = ntohs(superblock.salt_size);
		salt_bytes = xmalloc(salt_size);
		memcpy(salt_bytes, superblock.salt, salt_size);
	} else {
		if (salt_size != ntohs(superblock.salt_size) ||
		    memcmp(salt_bytes, superblock.salt, salt_size))
			exit_err("salt does not match superblock value");
	}
}

static void save_superblock(void)
{
	memset(&superblock, 0, sizeof(struct superblock));

	memcpy(&superblock.signature, DM_VERITY_SIGNATURE, sizeof(superblock.signature));
	superblock.version = version;
	superblock.data_block_bits = ffs(data_block_size) - 1;
	superblock.hash_block_bits = ffs(hash_block_size) - 1;
	superblock.salt_size = htons(salt_size);
	superblock.data_blocks_hi = htonl(data_file_blocks >> 31 >> 1);
	superblock.data_blocks_lo = htonl(data_file_blocks & 0xFFFFFFFF);
	strncpy((char *)superblock.algorithm, hash_algorithm, sizeof superblock.algorithm);
	memcpy(superblock.salt, salt_bytes, salt_size);

	block_fseek(hash_file, superblock_position, 1);
	if (fwrite(&superblock, sizeof(struct superblock), 1, hash_file) != 1)
		stream_err(hash_file, "write");
}

int main(int argc, const char **argv)
{
	poptContext popt_context;
	int r;
	const char *s;
	char *end;

	if (sizeof(struct superblock) != 512)
		exit_err("INTERNAL ERROR: bad superblock size %ld", (long)sizeof(struct superblock));

	popt_context = poptGetContext("verity", argc, argv, popt_options, 0);

	poptSetOtherOptionHelp(popt_context, "[-c | -v | -a] [<device name> if activating] <data device> <hash device> [<root hash> if activating or verifying] [OPTION...]");

	if (argc <= 1) {
		poptPrintHelp(popt_context, stdout, 0);
		exit(1);
	}

	r = poptGetNextOpt(popt_context);
	if (r < -1)
		exit_err("bad option %s", poptBadOption(popt_context, 0));

	if (mode < 0)
		exit_err("verify, create or activate mode not specified");

	if (mode == MODE_ACTIVATE) {
		dm_device = poptGetArg(popt_context);
		if (!dm_device)
			exit_err("device name is missing");
		if (!*dm_device || strchr(dm_device, '/'))
			exit_err("invalid device name to activate");
	}

	data_device = poptGetArg(popt_context);
	if (!data_device)
		exit_err("data device is missing");

	hash_device = poptGetArg(popt_context);
	if (!hash_device)
		exit_err("metadata device is missing");

	if (mode != MODE_CREATE) {
		root_hash = poptGetArg(popt_context);
		if (!root_hash)
			exit_err("root hash not specified");
	}

	s = poptGetArg(popt_context);
	if (s)
		exit_err("extra argument %s", s);

	data_file = fopen(data_device, "r");
	if (!data_file) {
		perror(data_device);
		exit(2);
	}

	hash_file = fopen(hash_device, mode != MODE_CREATE ? "r" : "r+");
	if (!hash_file && errno == ENOENT && mode == MODE_CREATE)
		hash_file = fopen(hash_device, "w+");
	if (!hash_file) {
		perror(hash_device);
		exit(2);
	}

	if (data_blocks_string) {
		data_blocks = strtoll(data_blocks_string, &end, 10);
		if (!*data_blocks_string || *end)
			exit_err("invalid number of data blocks");
	}

	if (hash_start_string) {
		hash_start = strtoll(hash_start_string, &end, 10);
		if (!*hash_start_string || *end)
			exit_err("invalid hash start");
	}

	if (hash_start < 0 ||
	   (unsigned long long)hash_start * 512 / 512 != hash_start ||
	   (off_t)(hash_start * 512) < 0 ||
	   (off_t)(hash_start * 512) != hash_start * 512) exit_err("invalid hash start");

	if (salt_string || !use_superblock) {
		if (!salt_string || !strcmp(salt_string, "-"))
			salt_string = "";
		salt_size = strlen(salt_string) / 2;
		if (salt_size > MAX_SALT_SIZE)
			exit_err("too long salt (max %d bytes)", MAX_SALT_SIZE);
		get_hex(salt_string, &salt_bytes, salt_size, "salt");
	}

	if (use_superblock) {
		superblock_position = hash_start * 512;
		if (mode != MODE_CREATE)
			load_superblock();
	}

	if (version == -1)
		version = MAX_FORMAT_VERSION;
	if (version < 0 || version > MAX_FORMAT_VERSION)
		exit_err("invalid format version");

	if (!data_block_size)
		data_block_size = DEFAULT_BLOCK_SIZE;
	if (!hash_block_size)
		hash_block_size = data_block_size;

	if (data_block_size < 512 || (data_block_size & (data_block_size - 1)) || data_block_size >= 1U << 31)
		exit_err("invalid data block size");

	if (hash_block_size < 512 || (hash_block_size & (hash_block_size - 1)) || hash_block_size >= 1U << 31)
		exit_err("invalid hash block size");

	if (data_blocks < 0 || (off_t)data_blocks < 0 || (off_t)data_blocks != data_blocks)
		exit_err("invalid number of data blocks");

	data_file_blocks = get_size(data_file, data_device) / data_block_size;
	hash_file_blocks = get_size(hash_file, hash_device) / hash_block_size;

	if (data_file_blocks < data_blocks)
		exit_err("data file is too small");
	if (data_blocks_string)
		data_file_blocks = data_blocks;

	if (use_superblock) {
		hash_start = hash_start + (sizeof(struct superblock) + 511) / 512;
		hash_start = (hash_start + (hash_block_size / 512 - 1)) & ~(long long)(hash_block_size / 512 - 1);
	}

	if ((unsigned long long)hash_start * 512 % hash_block_size)
		exit_err("hash start not aligned on block size");

	if (!hash_algorithm)
		hash_algorithm = "sha256";
	if (strlen(hash_algorithm) >= sizeof(superblock.algorithm) && use_superblock)
		exit_err("hash algorithm name is too long");

	if (crypt_backend_init(NULL))
		exit_err("cannot initialize crypto backend");

	digest_size = crypt_hash_size(hash_algorithm);
	if (!digest_size) exit_err("hash algorithm %s not found", hash_algorithm);

	if (!salt_bytes) {
		salt_size = DEFAULT_SALT_SIZE;
		salt_bytes = xmalloc(salt_size);
		if (crypt_backend_rng(salt_bytes, salt_size, CRYPT_RND_SALT, 0))
			exit_err("rng failed");
	}

	calculated_digest = xmalloc(digest_size);

	if (mode != MODE_CREATE) {
		get_hex(root_hash, &root_hash_bytes, digest_size, "root_hash");
	}

	calculate_positions();

	create_or_verify();

	if (use_superblock) {
		if (mode == MODE_CREATE)
			save_superblock();
	}

	fclose(data_file);
	fclose(hash_file);

	if (mode == MODE_ACTIVATE && !retval)
		activate();

	free(salt_bytes);
	free(calculated_digest);
	if (mode != MODE_CREATE)
		free(root_hash_bytes);
	poptFreeContext(popt_context);

	return retval;
}
