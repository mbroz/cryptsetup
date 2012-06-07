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

/* TODO:
 * - init_by_name()
 * - support device without superblock
 * - audit alloc errors / error path
 * - change command names (cryptsetup style)
 * - extend superblock (UUID)
 * - configure.in/config.h defaults
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <popt.h>

#include "cryptsetup.h"

#define PACKAGE_VERITY "veritysetup"

#define MODE_VERIFY	0
#define MODE_CREATE	1
#define MODE_ACTIVATE	2
#define MODE_DUMP	3

static int mode = -1;
static int use_superblock = 1; /* FIXME: no superblock not supported */

static const char *dm_device = NULL;
static const char *data_device = NULL;
static const char *hash_device = NULL;
static const char *hash_algorithm = NULL;
static const char *root_hash = NULL;

static int version = 1;
static int data_block_size = 4096;
static int hash_block_size = 4096;
static char *data_blocks_string = NULL;
static uint64_t data_blocks = 0;
static char *hash_start_string = NULL;
static const char *salt_string = NULL;
static unsigned salt_size = 32;
static uint64_t hash_start = 0;

static int opt_verbose = 0;
static int opt_debug = 0;
static int opt_version_mode = 0;

static int hex_to_bytes(const char *hex, char *result)
{
	char buf[3] = "xx\0", *endp;
	int i, len;

	len = strlen(hex) / 2;
	for (i = 0; i < len; i++) {
		memcpy(buf, &hex[i * 2], 2);
		result[i] = strtoul(buf, &endp, 16);
		if (endp != &buf[2])
			return -EINVAL;
	}
	return i;
}

__attribute__((format(printf, 5, 6)))
static void clogger(struct crypt_device *cd, int level, const char *file,
		   int line, const char *format, ...)
{
	va_list argp;
	char *target = NULL;

	va_start(argp, format);

	if (vasprintf(&target, format, argp) > 0) {
		if (level >= 0) {
			crypt_log(cd, level, target);
#ifdef CRYPT_DEBUG
		} else if (opt_debug)
			printf("# %s:%d %s\n", file ?: "?", line, target);
#else
		} else if (opt_debug)
			printf("# %s\n", target);
#endif
	}

	va_end(argp);
	free(target);
}

static void _log(int level, const char *msg, void *usrptr __attribute__((unused)))
{
	switch(level) {

	case CRYPT_LOG_NORMAL:
		fputs(msg, stdout);
		break;
	case CRYPT_LOG_VERBOSE:
		if (opt_verbose)
			fputs(msg, stdout);
		break;
	case CRYPT_LOG_ERROR:
		fputs(msg, stderr);
		break;
	case CRYPT_LOG_DEBUG:
		if (opt_debug)
			printf("# %s\n", msg);
		break;
	default:
		fprintf(stderr, "Internal error on logging class for msg: %s", msg);
		break;
	}
}

static int action_dump(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_verity params = {};
	int r;

	if ((r = crypt_init(&cd, hash_device)))
		return r;

	params.hash_area_offset = hash_start;
	r = crypt_load(cd, CRYPT_VERITY, &params);
	if (!r)
		crypt_dump(cd);
	crypt_free(cd);
	return r;
}

static int action_activate(int verify)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_verity params = {};
	uint32_t activate_flags = CRYPT_ACTIVATE_READONLY;
	char root_hash_bytes[128];
	int r;

	if ((r = crypt_init(&cd, hash_device)))
		goto out;

	if (verify)
		params.flags |= CRYPT_VERITY_CHECK_HASH;

	if (use_superblock) {
		params.hash_area_offset = hash_start;
		r = crypt_load(cd, CRYPT_VERITY, &params);
	} else {/*
		params.hash_name = hash_algorithm;
		params.salt = salt_bytes;
		params.salt_size = salt_size;
		params.data_block_size = data_block_size;
		params.hash_block_size = hash_block_size;

		params.data_size = data_blocks * data_block_size / 512;
		params.version = version;
		params.flags |= CRYPT_VERITY_NO_HEADER;
		r = crypt_load(cd, CRYPT_VERITY, &params);
		crypt_format(); */
		r = -EINVAL;
		goto out;
	}
	if (r < 0)
		goto out;
	r = crypt_set_data_device(cd, data_device);
	if (r < 0)
		goto out;

	if (hex_to_bytes(root_hash, root_hash_bytes) !=
	    crypt_get_volume_key_size(cd)) {
		r = -EINVAL;
		goto out;
	}
	r = crypt_activate_by_volume_key(cd, dm_device, root_hash_bytes,
					 crypt_get_volume_key_size(cd),
					 activate_flags);
out:
	if (!r)
		crypt_dump(cd);
	crypt_free(cd);
	return r;
}

static int action_create(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_verity params = {};
	char salt_bytes[512];
	int r;

	if ((r = crypt_init(&cd, hash_device)))
		goto out;

	params.hash_name = hash_algorithm ?: "sha256";
	params.data_device = data_device;

	if (salt_string) {
		if (hex_to_bytes(salt_string, salt_bytes) != salt_size) {
			r = -EINVAL;
			goto out;
		}
		params.salt = salt_bytes;
	}

	params.salt_size = salt_size;
	params.data_block_size = data_block_size;
	params.hash_block_size = hash_block_size;
	params.data_size = data_blocks;
	params.hash_area_offset = hash_start;
	params.version = version;
	params.flags = CRYPT_VERITY_CREATE_HASH;
	if (!use_superblock)
		params.flags |= CRYPT_VERITY_NO_HEADER;

	r = crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params);
	if (!r)
		crypt_dump(cd);
out:
	crypt_free(cd);
	return r;
}

static __attribute__ ((noreturn)) void usage(poptContext popt_context,
					     int exitcode, const char *error,
					     const char *more)
{
	poptPrintUsage(popt_context, stderr, 0);
	if (error)
		log_err("%s: %s\n", more, error);
	poptFreeContext(popt_context);
	exit(exitcode);
}

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	if (key->shortName == '?') {
		log_std("%s %s\n", PACKAGE_VERITY, PACKAGE_VERSION);
		poptPrintHelp(popt_context, stdout, 0);
		exit(EXIT_SUCCESS);
	} else
		usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

static void _dbg_version_and_cmd(int argc, const char **argv)
{
	int i;

	log_std("# %s %s processing \"", PACKAGE_VERITY, PACKAGE_VERSION);
	for (i = 0; i < argc; i++) {
		if (i)
			log_std(" ");
		log_std("%s", argv[i]);
	}
	log_std("\"\n");
}

int main(int argc, const char **argv)
{
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,                '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ "version",           '\0', POPT_ARG_NONE, &opt_version_mode,          0, N_("Print package version"), NULL },
		{ "verbose",            0 /*v*/,  POPT_ARG_NONE, &opt_verbose,               0, N_("Shows more detailed error messages"), NULL },
		{ "debug",             '\0', POPT_ARG_NONE, &opt_debug,                 0, N_("Show debug messages"), NULL },
		{ "create",		'c',	POPT_ARG_VAL, &mode, MODE_CREATE, "Create hash", NULL },
		{ "verify",		'v',	POPT_ARG_VAL, &mode, MODE_VERIFY, "Verify integrity", NULL },
		{ "activate",		'a',	POPT_ARG_VAL, &mode, MODE_ACTIVATE, "Activate the device", NULL },
		{ "dump",		'd',	POPT_ARG_VAL, &mode, MODE_DUMP, "Dump the device", NULL },
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
	poptContext popt_context;
	int r;
	char *end;

	crypt_set_log_callback(NULL, _log, NULL);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext("verity", argc, argv, popt_options, 0);

	poptSetOtherOptionHelp(popt_context, "[-c|-v|-a|-d] [<device name> if activating] <data device> <hash device> [<root hash> if activating or verifying] [OPTION...]");

	if (argc <= 1) {
		poptPrintHelp(popt_context, stdout, 0);
		exit(1);
	}

	r = poptGetNextOpt(popt_context);
	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));
	if (opt_version_mode) {
		log_std("%s %s\n", PACKAGE_VERITY, PACKAGE_VERSION);
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	}

	if (mode < 0)
		usage(popt_context, EXIT_FAILURE, _("Unknown action."),
		      poptGetInvocationName(popt_context));

	if (mode == MODE_ACTIVATE) {
		dm_device = poptGetArg(popt_context);
		if (!dm_device || !*dm_device)
			usage(popt_context, EXIT_FAILURE,
			      _("Missing activation device name."),
			      poptGetInvocationName(popt_context));
	}

	data_device = poptGetArg(popt_context);
	if (!data_device)
		usage(popt_context, EXIT_FAILURE, _("Missing data device name."),
		      poptGetInvocationName(popt_context));

	hash_device = poptGetArg(popt_context);
	if (!hash_device)
		usage(popt_context, EXIT_FAILURE, _("Missing hash device name."),
		      poptGetInvocationName(popt_context));

	if (mode == MODE_ACTIVATE || mode == MODE_VERIFY) {
		root_hash = poptGetArg(popt_context);
		if (!root_hash)
		usage(popt_context, EXIT_FAILURE, _("Root hash not specified."),
		      poptGetInvocationName(popt_context));
	}

	if (data_blocks_string) {
		data_blocks = strtoll(data_blocks_string, &end, 10);
		if (!*data_blocks_string || *end)
			usage(popt_context, EXIT_FAILURE,
			      _("Invalid number of data blocks."),
			      poptGetInvocationName(popt_context));
	}

	/* hash start */
	if (hash_start_string) {
		hash_start = strtoll(hash_start_string, &end, 10);
		if (!*hash_start_string || *end)
			usage(popt_context, EXIT_FAILURE,
			      _("Invalid hash device offset."),
			      poptGetInvocationName(popt_context));
		hash_start *= 512;
	}

	if (salt_string || !use_superblock) {
		if (!salt_string || !strcmp(salt_string, "-"))
			salt_string = "";
		salt_size = strlen(salt_string) / 2;
	}

	if (opt_debug) {
		opt_verbose = 1;
		crypt_set_debug_level(-1);
		_dbg_version_and_cmd(argc, argv);
	}

	switch (mode) {
		case MODE_ACTIVATE:
			r = action_activate(0);
			break;
		case MODE_VERIFY:
			r = action_activate(1);
			break;
		case MODE_CREATE:
			r = action_create();
			break;
		case MODE_DUMP:
			r = action_dump();
			break;
	}

	poptFreeContext(popt_context);
	return r;
}
