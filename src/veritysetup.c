/*
 * veritysetup - setup cryptographic volumes for dm-verity
 *
 * Copyright (C) 2012-2013, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2013, Milan Broz
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

#include "cryptsetup.h"

#define PACKAGE_VERITY "veritysetup"

static int use_superblock = 1;

static const char *hash_algorithm = NULL;
static int hash_type = 1;
static int data_block_size = DEFAULT_VERITY_DATA_BLOCK;
static int hash_block_size = DEFAULT_VERITY_HASH_BLOCK;
static uint64_t data_blocks = 0;
static const char *salt_string = NULL;
static uint64_t hash_offset = 0;
static const char *opt_uuid = NULL;

static int opt_version_mode = 0;

static const char **action_argv;
static int action_argc;

static int _prepare_format(struct crypt_params_verity *params,
			   const char *data_device,
			   uint32_t flags)
{
	char *salt = NULL;
	int len;

	params->hash_name = hash_algorithm ?: DEFAULT_VERITY_HASH;
	params->data_device = data_device;

	if (salt_string && !strcmp(salt_string, "-")) {
		params->salt_size = 0;
		params->salt = NULL;
	} else if (salt_string) {
		len = crypt_hex_to_bytes(salt_string, &salt, 0);
		if (len < 0) {
			log_err(_("Invalid salt string specified.\n"));
			return -EINVAL;
		}
		params->salt_size = len;
		params->salt = salt;
	} else {
		params->salt_size = DEFAULT_VERITY_SALT_SIZE;
		params->salt = NULL;
	}

	params->data_block_size = data_block_size;
	params->hash_block_size = hash_block_size;
	params->data_size = data_blocks;
	params->hash_area_offset = hash_offset;
	params->hash_type = hash_type;
	params->flags = flags;

	return 0;
}

static int action_format(int arg)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_verity params = {};
	uint32_t flags = CRYPT_VERITY_CREATE_HASH;
	int r;

	/* Try to create hash image if doesn't exist */
	r = open(action_argv[1], O_WRONLY | O_EXCL | O_CREAT, S_IRUSR | S_IWUSR);
	if (r < 0 && errno != EEXIST) {
		log_err(_("Cannot create hash image %s for writing.\n"), action_argv[1]);
		return -EINVAL;
	} else if (r >= 0) {
		log_dbg("Created hash image %s.", action_argv[1]);
		close(r);
	}

	if ((r = crypt_init(&cd, action_argv[1])))
		goto out;

	if (!use_superblock)
		flags |= CRYPT_VERITY_NO_HEADER;

	r = _prepare_format(&params, action_argv[0], flags);
	if (r < 0)
		goto out;

	r = crypt_format(cd, CRYPT_VERITY, NULL, NULL, opt_uuid, NULL, 0, &params);
	if (!r)
		crypt_dump(cd);
out:
	crypt_free(cd);
	free(CONST_CAST(char*)params.salt);
	return r;
}

static int _activate(const char *dm_device,
		      const char *data_device,
		      const char *hash_device,
		      const char *root_hash,
		      uint32_t flags)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_verity params = {};
	uint32_t activate_flags = CRYPT_ACTIVATE_READONLY;
	char *root_hash_bytes = NULL;
	ssize_t hash_size;
	int r;

	if ((r = crypt_init(&cd, hash_device)))
		goto out;

	if (use_superblock) {
		params.flags = flags;
		params.hash_area_offset = hash_offset;
		r = crypt_load(cd, CRYPT_VERITY, &params);
	} else {
		r = _prepare_format(&params, data_device, flags | CRYPT_VERITY_NO_HEADER);
		if (r < 0)
			goto out;
		r = crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params);
	}
	if (r < 0)
		goto out;
	r = crypt_set_data_device(cd, data_device);
	if (r < 0)
		goto out;

	hash_size = crypt_get_volume_key_size(cd);
	if (crypt_hex_to_bytes(root_hash, &root_hash_bytes, 0) != hash_size) {
		log_err(_("Invalid root hash string specified.\n"));
		r = -EINVAL;
		goto out;
	}
	r = crypt_activate_by_volume_key(cd, dm_device,
					 root_hash_bytes,
					 hash_size,
					 activate_flags);
out:
	crypt_free(cd);
	free(root_hash_bytes);
	free(CONST_CAST(char*)params.salt);
	return r;
}

static int action_create(int arg)
{
	return _activate(action_argv[0],
			 action_argv[1],
			 action_argv[2],
			 action_argv[3], 0);
}

static int action_verify(int arg)
{
	return _activate(NULL,
			 action_argv[0],
			 action_argv[1],
			 action_argv[2],
			 CRYPT_VERITY_CHECK_HASH);
}

static int action_remove(int arg)
{
	struct crypt_device *cd = NULL;
	int r;

	r = crypt_init_by_name(&cd, action_argv[0]);
	if (r == 0)
		r = crypt_deactivate(cd, action_argv[0]);

	crypt_free(cd);
	return r;
}

static int action_status(int arg)
{
	crypt_status_info ci;
	struct crypt_active_device cad;
	struct crypt_params_verity vp = {};
	struct crypt_device *cd = NULL;
	struct stat st;
	char *backing_file;
	unsigned i, path = 0;
	int r = 0;

	/* perhaps a path, not a dm device name */
	if (strchr(action_argv[0], '/') && !stat(action_argv[0], &st))
		path = 1;

	ci = crypt_status(NULL, action_argv[0]);
	switch (ci) {
	case CRYPT_INVALID:
		r = -EINVAL;
		break;
	case CRYPT_INACTIVE:
		if (path)
			log_std("%s is inactive.\n", action_argv[0]);
		else
			log_std("%s/%s is inactive.\n", crypt_get_dir(), action_argv[0]);
		r = -ENODEV;
		break;
	case CRYPT_ACTIVE:
	case CRYPT_BUSY:
		if (path)
			log_std("%s is active%s.\n", action_argv[0],
				ci == CRYPT_BUSY ? " and is in use" : "");
		else
			log_std("%s/%s is active%s.\n", crypt_get_dir(), action_argv[0],
				ci == CRYPT_BUSY ? " and is in use" : "");

		r = crypt_init_by_name_and_header(&cd, action_argv[0], NULL);
		if (r < 0 || !crypt_get_type(cd))
			goto out;

		log_std("  type:        %s\n", crypt_get_type(cd));

		r = crypt_get_active_device(cd, action_argv[0], &cad);
		if (r < 0)
			goto out;

		log_std("  status:      %s\n",
			cad.flags & CRYPT_ACTIVATE_CORRUPTED ? "corrupted" : "verified");

		r = crypt_get_verity_info(cd, &vp);
		if (r < 0)
			goto out;

		log_std("  hash type:   %u\n", vp.hash_type);
		log_std("  data block:  %u\n", vp.data_block_size);
		log_std("  hash block:  %u\n", vp.hash_block_size);
		log_std("  hash name:   %s\n", vp.hash_name);
		log_std("  salt:        ");
		if (vp.salt_size)
			for(i = 0; i < vp.salt_size; i++)
				log_std("%02hhx", (const char)vp.salt[i]);
		else
			log_std("-");
		log_std("\n");

		log_std("  data device: %s\n", vp.data_device);
		if (crypt_loop_device(vp.data_device)) {
			backing_file = crypt_loop_backing_file(vp.data_device);
			log_std("  data loop:   %s\n", backing_file);
			free(backing_file);
		}
		log_std("  size:        %" PRIu64 " sectors\n", cad.size);
		log_std("  mode:        %s\n", cad.flags & CRYPT_ACTIVATE_READONLY ?
					   "readonly" : "read/write");

		log_std("  hash device: %s\n", vp.hash_device);
		if (crypt_loop_device(vp.hash_device)) {
			backing_file = crypt_loop_backing_file(vp.hash_device);
			log_std("  hash loop:   %s\n", backing_file);
			free(backing_file);
		}
		log_std("  hash offset: %" PRIu64 " sectors\n",
			vp.hash_area_offset * vp.hash_block_size / 512);
	}
out:
	crypt_free(cd);
	if (r == -ENOTSUP)
		r = 0;
	return r;
}

static int action_dump(int arg)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_verity params = {};
	int r;

	if ((r = crypt_init(&cd, action_argv[0])))
		return r;

	params.hash_area_offset = hash_offset;
	r = crypt_load(cd, CRYPT_VERITY, &params);
	if (!r)
		crypt_dump(cd);
	crypt_free(cd);
	return r;
}

static struct action_type {
	const char *type;
	int (*handler)(int);
	int required_action_argc;
	const char *arg_desc;
	const char *desc;
} action_types[] = {
	{ "format",	action_format, 2, N_("<data_device> <hash_device>"),N_("format device") },
	{ "verify",	action_verify, 3, N_("<data_device> <hash_device> <root_hash>"),N_("verify device") },
	{ "create",	action_create, 4, N_("<name> <data_device> <hash_device> <root_hash>"),N_("create active device") },
	{ "remove",	action_remove, 1, N_("<name>"),N_("remove (deactivate) device") },
	{ "status",	action_status, 1, N_("<name>"),N_("show active device status") },
	{ "dump",	action_dump,   1, N_("<hash_device>"),N_("show on-disk information") },
	{ NULL, NULL, 0, NULL, NULL }
};

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	struct action_type *action;

	if (key->shortName == '?') {
		log_std("%s %s\n", PACKAGE_VERITY, PACKAGE_VERSION);
		poptPrintHelp(popt_context, stdout, 0);
		log_std(_("\n"
			 "<action> is one of:\n"));
		for(action = action_types; action->type; action++)
			log_std("\t%s %s - %s\n", action->type, _(action->arg_desc), _(action->desc));
		log_std(_("\n"
			 "<name> is the device to create under %s\n"
			 "<data_device> is the data device\n"
			 "<hash_device> is the device containing verification data\n"
			 "<root_hash> hash of the root node on <hash_device>\n"),
			crypt_get_dir());

		log_std(_("\nDefault compiled-in dm-verity parameters:\n"
			 "\tHash: %s, Data block (bytes): %u, "
			 "Hash block (bytes): %u, Salt size: %u, Hash format: %u\n"),
			DEFAULT_VERITY_HASH, DEFAULT_VERITY_DATA_BLOCK,
			DEFAULT_VERITY_HASH_BLOCK, DEFAULT_VERITY_SALT_SIZE,
			1);
		exit(EXIT_SUCCESS);
	} else
		usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

static int run_action(struct action_type *action)
{
	int r;

	log_dbg("Running command %s.", action->type);

	r = action->handler(0);

	show_status(r);
	return translate_errno(r);
}

int main(int argc, const char **argv)
{
	static char *popt_tmp;
	static const char *null_action_argv[] = {NULL};
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,              '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ "version",         '\0', POPT_ARG_NONE, &opt_version_mode, 0, N_("Print package version"), NULL },
		{ "verbose",         'v',  POPT_ARG_NONE, &opt_verbose,      0, N_("Shows more detailed error messages"), NULL },
		{ "debug",           '\0', POPT_ARG_NONE, &opt_debug,        0, N_("Show debug messages"), NULL },
		{ "no-superblock",   0,    POPT_ARG_VAL,  &use_superblock,   0, N_("Do not use verity superblock"), NULL },
		{ "format",          0,    POPT_ARG_INT,  &hash_type,        0, N_("Format type (1 - normal, 0 - original Chrome OS)"), N_("number") },
		{ "data-block-size", 0,    POPT_ARG_INT,  &data_block_size,  0, N_("Block size on the data device"), N_("bytes") },
		{ "hash-block-size", 0,    POPT_ARG_INT,  &hash_block_size,  0, N_("Block size on the hash device"), N_("bytes") },
		{ "data-blocks",     0,    POPT_ARG_STRING, &popt_tmp,       1, N_("The number of blocks in the data file"), N_("blocks") },
		{ "hash-offset",     0,    POPT_ARG_STRING, &popt_tmp,       2, N_("Starting offset on the hash device"), N_("bytes") },
		{ "hash",            'h',  POPT_ARG_STRING, &hash_algorithm, 0, N_("Hash algorithm"), N_("string") },
		{ "salt",            's',  POPT_ARG_STRING, &salt_string,    0, N_("Salt"), N_("hex string") },
		{ "uuid",            '\0', POPT_ARG_STRING, &opt_uuid,       0, N_("UUID for device to use."), NULL },
		POPT_TABLEEND
	};

	poptContext popt_context;
	struct action_type *action;
	const char *aname;
	int r;

	crypt_set_log_callback(NULL, tool_log, NULL);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext("verity", argc, argv, popt_options, 0);
	poptSetOtherOptionHelp(popt_context,
	                       _("[OPTION...] <action> <action-specific>"));

	while((r = poptGetNextOpt(popt_context)) > 0) {
		unsigned long long ull_value;
		char *endp;

		errno = 0;
		ull_value = strtoull(popt_tmp, &endp, 10);
		if (*endp || !*popt_tmp || !isdigit(*popt_tmp) ||
		    (errno == ERANGE && ull_value == ULLONG_MAX) ||
		    (errno != 0 && ull_value == 0))
			r = POPT_ERROR_BADNUMBER;

		switch(r) {
			case 1:
				data_blocks = ull_value;
				break;
			case 2:
				hash_offset = ull_value;
				break;
		}

		if (r < 0)
			break;
	}

	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));

	if (opt_version_mode) {
		log_std("%s %s\n", PACKAGE_VERITY, PACKAGE_VERSION);
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	}

	if (!(aname = poptGetArg(popt_context)))
		usage(popt_context, EXIT_FAILURE, _("Argument <action> missing."),
		      poptGetInvocationName(popt_context));
	for(action = action_types; action->type; action++)
		if (strcmp(action->type, aname) == 0)
			break;
	if (!action->type)
		usage(popt_context, EXIT_FAILURE, _("Unknown action."),
		      poptGetInvocationName(popt_context));

	action_argc = 0;
	action_argv = poptGetArgs(popt_context);
	/* Make return values of poptGetArgs more consistent in case of remaining argc = 0 */
	if(!action_argv)
		action_argv = null_action_argv;

	/* Count args, somewhat unnice, change? */
	while(action_argv[action_argc] != NULL)
		action_argc++;

	if(action_argc < action->required_action_argc) {
		char buf[128];
		snprintf(buf, 128,_("%s: requires %s as arguments"), action->type, action->arg_desc);
		usage(popt_context, EXIT_FAILURE, buf,
		      poptGetInvocationName(popt_context));
	}

	if (data_block_size < 0 || hash_block_size < 0 || hash_type < 0) {
		usage(popt_context, EXIT_FAILURE,
		      _("Negative number for option not permitted."),
		      poptGetInvocationName(popt_context));
	}

	if (opt_debug) {
		opt_verbose = 1;
		crypt_set_debug_level(-1);
		dbg_version_and_cmd(argc, argv);
	}

	r = run_action(action);
	poptFreeContext(popt_context);
	return r;
}
