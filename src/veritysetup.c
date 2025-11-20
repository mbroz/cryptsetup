// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * veritysetup - setup cryptographic volumes for dm-verity
 *
 * Copyright (C) 2012-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2025 Milan Broz
 */

#include "cryptsetup.h"
#include "veritysetup_args.h"

#define PACKAGE_VERITY "veritysetup"

static const char **action_argv;
static int action_argc;
static struct tools_log_params log_parms;

void tools_cleanup(void)
{
	tools_args_free(tool_core_args, ARRAY_SIZE(tool_core_args));
}

static int _prepare_format(struct crypt_params_verity *params,
			   const char *data_device,
			   uint32_t flags)
{
	char *salt = NULL;
	int len;

	params->hash_name = ARG_STR(OPT_HASH_ID);
	params->data_device = data_device;
	params->fec_device = ARG_STR(OPT_FEC_DEVICE_ID);
	params->fec_roots = ARG_UINT32(OPT_FEC_ROOTS_ID);

	if (ARG_STR(OPT_SALT_ID) && !strcmp(ARG_STR(OPT_SALT_ID), "-")) {
		params->salt_size = 0;
		params->salt = NULL;
	} else if (ARG_SET(OPT_SALT_ID)) {
		len = crypt_hex_to_bytes(ARG_STR(OPT_SALT_ID), &salt, 0);
		if (len < 0) {
			log_err(_("Invalid salt string specified."));
			return -EINVAL;
		}
		params->salt_size = len;
		params->salt = salt;
	} else {
		params->salt_size = DEFAULT_VERITY_SALT_SIZE;
		params->salt = NULL;
	}

	params->data_block_size = ARG_UINT32(OPT_DATA_BLOCK_SIZE_ID);
	params->hash_block_size = ARG_UINT32(OPT_HASH_BLOCK_SIZE_ID);
	params->data_size = ARG_UINT64(OPT_DATA_BLOCKS_ID);
	params->hash_area_offset = ARG_UINT64(OPT_HASH_OFFSET_ID);
	params->fec_area_offset = ARG_UINT64(OPT_FEC_OFFSET_ID);
	params->hash_type = ARG_UINT32(OPT_FORMAT_ID);
	params->flags = flags;

	return 0;
}

static int action_format(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_verity params = {};
	uint32_t flags = CRYPT_VERITY_CREATE_HASH;
	char *root_hash_bytes = NULL;
	size_t root_hash_size;
	int root_hash_fd = -1, i, r;

	/* Try to create hash image if doesn't exist */
	r = open(action_argv[1], O_WRONLY | O_EXCL | O_CREAT, S_IRUSR | S_IWUSR);
	if (r < 0 && errno != EEXIST) {
		log_err(_("Cannot create hash image %s for writing."), action_argv[1]);
		return -EINVAL;
	} else if (r >= 0) {
		log_dbg("Created hash image %s.", action_argv[1]);
		close(r);
	}
	/* Try to create FEC image if doesn't exist */
	if (ARG_SET(OPT_FEC_DEVICE_ID)) {
		r = open(ARG_STR(OPT_FEC_DEVICE_ID), O_WRONLY | O_EXCL | O_CREAT, S_IRUSR | S_IWUSR);
		if (r < 0 && errno != EEXIST) {
			log_err(_("Cannot create FEC image %s for writing."), ARG_STR(OPT_FEC_DEVICE_ID));
			return -EINVAL;
		} else if (r >= 0) {
			log_dbg("Created FEC image %s.", ARG_STR(OPT_FEC_DEVICE_ID));
			close(r);
		}
	}

	if ((r = crypt_init(&cd, action_argv[1])))
		goto out;

	if (ARG_SET(OPT_NO_SUPERBLOCK_ID))
		flags |= CRYPT_VERITY_NO_HEADER;

	r = _prepare_format(&params, action_argv[0], flags);
	if (r < 0)
		goto out;

	r = crypt_format(cd, CRYPT_VERITY, NULL, NULL, ARG_STR(OPT_UUID_ID), NULL, 0, &params);
	if (r < 0)
		goto out;

	crypt_dump(cd);

	/* Create or overwrite the root hash file */
	if (ARG_SET(OPT_ROOT_HASH_FILE_ID)) {
		root_hash_size = crypt_get_volume_key_size(cd);
		root_hash_bytes = malloc(root_hash_size);
		if (!root_hash_bytes) {
			r = -ENOMEM;
			goto out;
		}

		r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, root_hash_bytes, &root_hash_size, NULL, 0);
		if (r < 0)
			goto out;

		root_hash_fd = open(ARG_STR(OPT_ROOT_HASH_FILE_ID), O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
		if (root_hash_fd == -1) {
			log_err(_("Cannot create root hash file %s for writing."), ARG_STR(OPT_ROOT_HASH_FILE_ID));
			r = -EINVAL;
			goto out;
		}

		for (i = 0; i < (int)root_hash_size; i++)
			if (dprintf(root_hash_fd, "%02hhx", root_hash_bytes[i]) != 2) {
				log_err(_("Cannot write to root hash file %s."), ARG_STR(OPT_ROOT_HASH_FILE_ID));
				r = -EIO;
				goto out;
			}

		log_dbg("Created root hash file %s.", ARG_STR(OPT_ROOT_HASH_FILE_ID));
	}
out:
	crypt_free(cd);
	free(CONST_CAST(char*)params.salt);
	free(root_hash_bytes);
	if (root_hash_fd != -1)
		close(root_hash_fd);
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
	char *root_hash_bytes = NULL, *root_hash_from_file = NULL;
	ssize_t hash_size, hash_size_hex;
	struct stat st;
	char *signature = NULL;
	int signature_size = 0, root_hash_fd = -1, r;

	if ((r = crypt_init_data_device(&cd, hash_device, data_device)))
		goto out;

	if (ARG_SET(OPT_IGNORE_CORRUPTION_ID))
		activate_flags |= CRYPT_ACTIVATE_IGNORE_CORRUPTION;
	if (ARG_SET(OPT_RESTART_ON_CORRUPTION_ID))
		activate_flags |= CRYPT_ACTIVATE_RESTART_ON_CORRUPTION;
	if (ARG_SET(OPT_PANIC_ON_CORRUPTION_ID))
		activate_flags |= CRYPT_ACTIVATE_PANIC_ON_CORRUPTION;
	if (ARG_SET(OPT_ERROR_AS_CORRUPTION_ID))
		activate_flags |= CRYPT_ACTIVATE_ERROR_AS_CORRUPTION;
	if (ARG_SET(OPT_IGNORE_ZERO_BLOCKS_ID))
		activate_flags |= CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS;
	if (ARG_SET(OPT_CHECK_AT_MOST_ONCE_ID))
		activate_flags |= CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE;
	if (ARG_SET(OPT_USE_TASKLETS_ID))
		activate_flags |= CRYPT_ACTIVATE_TASKLETS;
	if (ARG_SET(OPT_SHARED_ID))
		activate_flags |= CRYPT_ACTIVATE_SHARED;

	if (!ARG_SET(OPT_NO_SUPERBLOCK_ID)) {
		params.flags = flags;
		params.hash_area_offset = ARG_UINT64(OPT_HASH_OFFSET_ID);
		params.fec_area_offset = ARG_UINT64(OPT_FEC_OFFSET_ID);
		params.fec_device = ARG_STR(OPT_FEC_DEVICE_ID);
		params.fec_roots = ARG_UINT32(OPT_FEC_ROOTS_ID);
		r = crypt_load(cd, CRYPT_VERITY, &params);
		if (r)
			log_err(_("Device %s is not a valid VERITY device."), hash_device);

	} else {
		r = _prepare_format(&params, data_device, flags | CRYPT_VERITY_NO_HEADER);
		if (r < 0)
			goto out;
		r = crypt_format(cd, CRYPT_VERITY, NULL, NULL, NULL, NULL, 0, &params);
	}
	if (r < 0)
		goto out;

	hash_size = crypt_get_volume_key_size(cd);
	hash_size_hex = 2 * hash_size;

	if (!root_hash) {
		root_hash_fd = open(ARG_STR(OPT_ROOT_HASH_FILE_ID), O_RDONLY);
		if (root_hash_fd == -1) {
			log_err(_("Cannot read root hash file %s."), ARG_STR(OPT_ROOT_HASH_FILE_ID));
			goto out;
		}

		if (fstat(root_hash_fd, &st) || !S_ISREG(st.st_mode) || st.st_size < hash_size_hex) {
			log_err(_("Invalid root hash file %s."), ARG_STR(OPT_ROOT_HASH_FILE_ID));
			r = -EINVAL;
			goto out;
		}

		root_hash_from_file = malloc(hash_size_hex + 1);
		if (!root_hash_from_file) {
			r = -ENOMEM;
			goto out;
		}

		if (read_buffer(root_hash_fd, root_hash_from_file, hash_size_hex) != hash_size_hex) {
			log_err(_("Cannot read root hash file %s."), root_hash_from_file);
			goto out;
		}

		root_hash_from_file[hash_size_hex] = '\0';
		root_hash = root_hash_from_file;
	}

	if (crypt_hex_to_bytes(root_hash, &root_hash_bytes, 0) != hash_size) {
		log_err(_("Invalid root hash string specified."));
		r = -EINVAL;
		goto out;
	}

	if (ARG_SET(OPT_ROOT_HASH_SIGNATURE_ID)) {
		// FIXME: check max file size
		if (stat(ARG_STR(OPT_ROOT_HASH_SIGNATURE_ID), &st) || !S_ISREG(st.st_mode) || !st.st_size) {
			log_err(_("Invalid signature file %s."), ARG_STR(OPT_ROOT_HASH_SIGNATURE_ID));
			r = -EINVAL;
			goto out;
		}
		signature_size = st.st_size;
		r = tools_read_vk(ARG_STR(OPT_ROOT_HASH_SIGNATURE_ID), &signature, signature_size);
		if (r < 0) {
			log_err(_("Cannot read signature file %s."), ARG_STR(OPT_ROOT_HASH_SIGNATURE_ID));
			goto out;
		}
	}
	r = crypt_activate_by_signed_key(cd, dm_device,
					 root_hash_bytes,
					 hash_size,
					 signature, signature_size,
					 activate_flags);
out:
	crypt_safe_free(signature);
	crypt_free(cd);
	free(root_hash_from_file);
	free(root_hash_bytes);
	free(CONST_CAST(char*)params.salt);
	if (root_hash_fd != -1)
		close(root_hash_fd);
	return r;
}

static int action_open(void)
{
	if (action_argc < 4 && !ARG_SET(OPT_ROOT_HASH_FILE_ID)) {
		log_err(_("Command requires <root_hash> or --root-hash-file option as argument."));
		return -EINVAL;
	}

	if (tools_check_newname(action_argv[1]))
		return -EINVAL;

	return _activate(action_argv[1],
			 action_argv[0],
			 action_argv[2],
			 ARG_SET(OPT_ROOT_HASH_FILE_ID) ? NULL : action_argv[3],
			 ARG_SET(OPT_ROOT_HASH_SIGNATURE_ID) ? CRYPT_VERITY_ROOT_HASH_SIGNATURE : 0);
}

static int action_verify(void)
{
	if (action_argc < 3 && !ARG_SET(OPT_ROOT_HASH_FILE_ID)) {
		log_err(_("Command requires <root_hash> or --root-hash-file option as argument."));
		return -EINVAL;
	}

	return _activate(NULL,
			 action_argv[0],
			 action_argv[1],
			 ARG_SET(OPT_ROOT_HASH_FILE_ID) ? NULL : action_argv[2],
			 CRYPT_VERITY_CHECK_HASH);
}

static int action_close(void)
{
	struct crypt_device *cd = NULL;
	crypt_status_info ci;
	uint32_t flags = 0;
	int r;

	if (ARG_SET(OPT_DEFERRED_ID))
		flags |= CRYPT_DEACTIVATE_DEFERRED;
	if (ARG_SET(OPT_CANCEL_DEFERRED_ID))
		flags |= CRYPT_DEACTIVATE_DEFERRED_CANCEL;

	r = crypt_init_by_name(&cd, action_argv[0]);
	if (r == 0)
		r = crypt_deactivate_by_name(cd, action_argv[0], flags);

	if (!r && ARG_SET(OPT_DEFERRED_ID)) {
		ci = crypt_status(cd, action_argv[0]);
		if (ci == CRYPT_ACTIVE || ci == CRYPT_BUSY)
			log_std(_("Device %s is still active and scheduled for deferred removal.\n"),
				  action_argv[0]);
	}

	crypt_free(cd);
	return r;
}

static int action_status(void)
{
	crypt_status_info ci;
	struct crypt_active_device cad;
	struct crypt_params_verity vp = {};
	struct crypt_device *cd = NULL;
	struct stat st;
	char *backing_file, *root_hash;
	size_t root_hash_size;
	unsigned path = 0;
	int r = 0;
	uint64_t repaired;

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
		if (r < 0)
			goto out;

		log_std("  type:        %s\n", crypt_get_type(cd) ?: "n/a");

		r = crypt_get_active_device(cd, action_argv[0], &cad);
		if (r < 0)
			goto out;

		/* Print only VERITY type devices */
		r = crypt_get_verity_info(cd, &vp);
		if (r < 0)
			goto out;

		log_std("  status:      %s%s\n",
			cad.flags & CRYPT_ACTIVATE_CORRUPTED ? "corrupted" : "verified",
			vp.flags & CRYPT_VERITY_ROOT_HASH_SIGNATURE ? " (with signature)" : "");

		log_std("  hash type:   %u\n", vp.hash_type);
		log_std("  data block:  %u [bytes]\n", vp.data_block_size);
		log_std("  hash block:  %u [bytes]\n", vp.hash_block_size);
		log_std("  hash name:   %s\n", vp.hash_name);
		log_std("  salt:        ");
		if (vp.salt_size)
			crypt_log_hex(NULL, vp.salt, vp.salt_size, "", 0, NULL);
		else
			log_std("-");
		log_std("\n");

		log_std("  data device: %s\n", vp.data_device);
		if ((backing_file = crypt_loop_backing_file(vp.data_device))) {
			log_std("  data loop:   %s\n", backing_file);
			free(backing_file);
		}
		log_std("  size:        %" PRIu64 " [512-byte units] (%" PRIu64 " [bytes])\n", cad.size, cad.size * (uint64_t)SECTOR_SIZE);
		log_std("  mode:        %s\n", cad.flags & CRYPT_ACTIVATE_READONLY ?
					   "readonly" : "read/write");

		log_std("  hash device: %s\n", vp.hash_device);
		if ((backing_file = crypt_loop_backing_file(vp.hash_device))) {
			log_std("  hash loop:   %s\n", backing_file);
			free(backing_file);
		}
		log_std("  hash offset: %" PRIu64 " [512-byte units] (%" PRIu64 " [bytes])\n",
			vp.hash_area_offset * vp.hash_block_size / SECTOR_SIZE, vp.hash_area_offset * vp.hash_block_size);

		if (vp.fec_device) {
			log_std("  FEC device:  %s\n", vp.fec_device);
			if ((backing_file = crypt_loop_backing_file(ARG_STR(OPT_FEC_DEVICE_ID)))) {
				log_std("  FEC loop:    %s\n", backing_file);
				free(backing_file);
			}
			log_std("  FEC offset:  %" PRIu64 " [512-byte units] (%" PRIu64 " [bytes])\n",
				vp.fec_area_offset * vp.hash_block_size / SECTOR_SIZE, vp.fec_area_offset * vp.hash_block_size);
			log_std("  FEC roots:   %u\n", vp.fec_roots);
			if (!crypt_get_verity_repaired(cd, action_argv[0], &repaired))
				log_std("  FEC repaired: %" PRIu64 " [events]\n", repaired);
		}

		root_hash_size = crypt_get_volume_key_size(cd);
		if (root_hash_size > 0 && (root_hash = malloc(root_hash_size))) {
			r = crypt_volume_key_get(cd, CRYPT_ANY_SLOT, root_hash, &root_hash_size, NULL, 0);
			if (!r) {
				log_std("  root hash:   ");
				crypt_log_hex(NULL, root_hash, root_hash_size, "", 0, NULL);
				log_std("\n");
			}
			free(root_hash);
		}

		if (cad.flags & (CRYPT_ACTIVATE_IGNORE_CORRUPTION|
				 CRYPT_ACTIVATE_RESTART_ON_CORRUPTION|
				 CRYPT_ACTIVATE_PANIC_ON_CORRUPTION|
				 CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS|
				 CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE|
				 CRYPT_ACTIVATE_TASKLETS))
			log_std("  flags:       %s%s%s%s%s%s%s\n",
				(cad.flags & CRYPT_ACTIVATE_IGNORE_CORRUPTION) ? "ignore_corruption " : "",
				(cad.flags & CRYPT_ACTIVATE_RESTART_ON_CORRUPTION) ? "restart_on_corruption " : "",
				(cad.flags & CRYPT_ACTIVATE_PANIC_ON_CORRUPTION) ? "panic_on_corruption " : "",
				(cad.flags & CRYPT_ACTIVATE_ERROR_AS_CORRUPTION) ?
				((cad.flags & CRYPT_ACTIVATE_PANIC_ON_CORRUPTION) ? "panic_on_error " : "restart_on_error") : "",
				(cad.flags & CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS) ? "ignore_zero_blocks " : "",
				(cad.flags & CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE) ? "check_at_most_once" : "",
				(cad.flags & CRYPT_ACTIVATE_TASKLETS) ? "try_verify_in_tasklet" : "");
	}
out:
	crypt_free(cd);
	if (r == -ENOTSUP)
		r = 0;
	return r;
}

static int action_dump(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_verity params = {};
	int r;

	if ((r = crypt_init(&cd, action_argv[0])))
		return r;

	params.hash_area_offset = ARG_UINT64(OPT_HASH_OFFSET_ID);
	params.fec_area_offset = ARG_UINT64(OPT_FEC_OFFSET_ID);
	params.fec_device = ARG_STR(OPT_FEC_DEVICE_ID);
	params.fec_roots = ARG_UINT32(OPT_FEC_ROOTS_ID);

	r = crypt_load(cd, CRYPT_VERITY, &params);
	if (!r)
		crypt_dump(cd);
	else
		log_err(_("Device %s is not a valid VERITY device."), action_argv[0]);

	crypt_free(cd);
	return r;
}

static struct action_type {
	const char *type;
	int (*handler)(void);
	int required_action_argc;
	const char *arg_desc;
	const char *desc;
} action_types[] = {
	{ "format",	action_format, 2, N_("<data_device> <hash_device>"),N_("format device") },
	{ "verify",	action_verify, 2, N_("<data_device> <hash_device> [<root_hash>]"),N_("verify device") },
	{ "open",	action_open,   3, N_("<data_device> <name> <hash_device> [<root_hash>]"),N_("open device as <name>") },
	{ "close",	action_close,  1, N_("<name>"),N_("close device (remove mapping)") },
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
		tools_package_version(PACKAGE_VERITY, false);
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
		tools_cleanup();
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else if (key->shortName == 'V') {
		tools_package_version(PACKAGE_VERITY, false);
		tools_cleanup();
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else
		usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

static int run_action(struct action_type *action)
{
	int r;

	log_dbg("Running command %s.", action->type);

	r = action->handler();

	show_status(r);
	return translate_errno(r);
}

static void basic_options_cb(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg,
		 void *data __attribute__((unused)))
{
	tools_parse_arg_value(popt_context, tool_core_args[key->val].type, tool_core_args + key->val, arg, key->val, NULL);

	switch (key->val) {
	case OPT_DEBUG_ID:
		log_parms.debug = true;
		/* fall through */
	case OPT_VERBOSE_ID:
		log_parms.verbose = true;
	}
}

int main(int argc, const char **argv)
{
	static const char *null_action_argv[] = {NULL};
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		{ "version",'V', POPT_ARG_NONE,     NULL, 0, N_("Print package version"),  NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_basic_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, basic_options_cb, 0, NULL, NULL },
#define ARG(A, B, C, D, E, F, G, H) { A, B, C, NULL, A ## _ID, D, E },
#include "veritysetup_arg_list.h"
#undef ARG
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,              '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ NULL,              '\0', POPT_ARG_INCLUDE_TABLE, popt_basic_options, 0, NULL, NULL },
		POPT_TABLEEND
	};

	poptContext popt_context;
	struct action_type *action;
	const char *aname;
	int r;

	crypt_set_log_callback(NULL, tool_log, &log_parms);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext("verity", argc, argv, popt_options, 0);
	if (!popt_context)
		exit(EXIT_FAILURE);

	poptSetOtherOptionHelp(popt_context,
	                       _("[OPTION...] <action> <action-specific>"));

	while((r = poptGetNextOpt(popt_context)) > 0) {}

	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));

	if (!(aname = poptGetArg(popt_context)))
		usage(popt_context, EXIT_FAILURE, _("Argument <action> missing."),
		      poptGetInvocationName(popt_context));

	action_argc = 0;
	action_argv = poptGetArgs(popt_context);
	/* Make return values of poptGetArgs more consistent in case of remaining argc = 0 */
	if(!action_argv)
		action_argv = null_action_argv;

	/* Count args, somewhat unnice, change? */
	while(action_argv[action_argc] != NULL)
		action_argc++;

	/* Handle aliases */
	if (!strcmp(aname, "create") && action_argc > 1) {
		/* create command had historically switched arguments */
		if (action_argv[0] && action_argv[1]) {
			const char *tmp = action_argv[0];
			action_argv[0] = action_argv[1];
			action_argv[1] = tmp;
		}
		aname = "open";
	} else if (!strcmp(aname, "remove")) {
		aname = "close";
	}

	for (action = action_types; action->type; action++)
		if (strcmp(action->type, aname) == 0)
			break;

	if (!action->type)
		usage(popt_context, EXIT_FAILURE, _("Unknown action."),
		      poptGetInvocationName(popt_context));

	if (action_argc < action->required_action_argc) {
		char buf[128];
		if (snprintf(buf, 128,_("%s: requires %s as arguments"), action->type, action->arg_desc) < 0)
			buf[0] = '\0';
		usage(popt_context, EXIT_FAILURE, buf,
		      poptGetInvocationName(popt_context));
	}

	tools_check_args(action->type, tool_core_args, ARRAY_SIZE(tool_core_args), popt_context);

	if (ARG_SET(OPT_IGNORE_CORRUPTION_ID) && ARG_SET(OPT_RESTART_ON_CORRUPTION_ID))
		usage(popt_context, EXIT_FAILURE,
		_("Option --ignore-corruption and --restart-on-corruption cannot be used together."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_PANIC_ON_CORRUPTION_ID) && ARG_SET(OPT_RESTART_ON_CORRUPTION_ID))
		usage(popt_context, EXIT_FAILURE,
		_("Option --panic-on-corruption and --restart-on-corruption cannot be used together."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_ERROR_AS_CORRUPTION_ID) &&
	    !(ARG_SET(OPT_RESTART_ON_CORRUPTION_ID) || ARG_SET(OPT_PANIC_ON_CORRUPTION_ID)))
		usage(popt_context, EXIT_FAILURE,
		_("Option --error-as-corruption must be used with --panic-on-corruption or --restart-on-corruption."),
		poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_CANCEL_DEFERRED_ID) && ARG_SET(OPT_DEFERRED_ID))
		usage(popt_context, EXIT_FAILURE,
		      _("Options --cancel-deferred and --deferred cannot be used at the same time."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_DEBUG_ID)) {
		crypt_set_debug_level(CRYPT_DEBUG_ALL);
		dbg_version_and_cmd(argc, argv);
	}

	r = run_action(action);
	tools_cleanup();
	poptFreeContext(popt_context);
	return r;
}
