// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * integritysetup - setup integrity protected volumes for dm-integrity
 *
 * Copyright (C) 2017-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2017-2025 Milan Broz
 */

#include <uuid/uuid.h>

#define DEFAULT_ALG_NAME "crc32c"

#include "cryptsetup.h"
#include "integritysetup_args.h"

#define PACKAGE_INTEGRITY "integritysetup"

static const char **action_argv;
static int action_argc;
static struct tools_log_params log_parms;

void tools_cleanup(void)
{
	tools_args_free(tool_core_args, ARRAY_SIZE(tool_core_args));
}

static int _read_keys(char **integrity_key, struct crypt_params_integrity *params)
{
	char *int_key = NULL, *journal_integrity_key = NULL, *journal_crypt_key = NULL;
	int r;

	if (integrity_key && ARG_SET(OPT_INTEGRITY_KEY_FILE_ID)) {
		r = tools_read_vk(ARG_STR(OPT_INTEGRITY_KEY_FILE_ID), &int_key, ARG_UINT32(OPT_INTEGRITY_KEY_SIZE_ID));
		if (r < 0)
			return r;
		params->integrity_key_size = ARG_UINT32(OPT_INTEGRITY_KEY_SIZE_ID);
	}

	if (ARG_SET(OPT_JOURNAL_INTEGRITY_KEY_FILE_ID)) {
		r = tools_read_vk(ARG_STR(OPT_JOURNAL_INTEGRITY_KEY_FILE_ID), &journal_integrity_key, ARG_UINT32(OPT_JOURNAL_INTEGRITY_KEY_SIZE_ID));
		if (r < 0) {
			crypt_safe_free(int_key);
			return r;
		}
		params->journal_integrity_key = journal_integrity_key;
		params->journal_integrity_key_size = ARG_UINT32(OPT_JOURNAL_INTEGRITY_KEY_SIZE_ID);
	}

	if (ARG_SET(OPT_JOURNAL_CRYPT_KEY_FILE_ID)) {
		r = tools_read_vk(ARG_STR(OPT_JOURNAL_CRYPT_KEY_FILE_ID), &journal_crypt_key, ARG_UINT32(OPT_JOURNAL_CRYPT_KEY_SIZE_ID));
		if (r < 0) {
			crypt_safe_free(int_key);
			crypt_safe_free(journal_integrity_key);
			return r;
		}
		params->journal_crypt_key = journal_crypt_key;
		params->journal_crypt_key_size = ARG_UINT32(OPT_JOURNAL_CRYPT_KEY_SIZE_ID);
	}

	if (integrity_key)
		*integrity_key = int_key;

	return 0;
}

static int _wipe_data_device(struct crypt_device *cd, const char *integrity_key)
{
	char tmp_name[64], tmp_path[128], tmp_uuid[40];
	uuid_t tmp_uuid_bin;
	int r = -EINVAL;
	char *backing_file = NULL;
	struct tools_progress_params prog_parms = {
		.frequency = ARG_UINT32(OPT_PROGRESS_FREQUENCY_ID),
		.batch_mode = ARG_SET(OPT_BATCH_MODE_ID),
		.json_output = ARG_SET(OPT_PROGRESS_JSON_ID),
		.interrupt_message = _("\nWipe interrupted."),
		.device = tools_get_device_name(crypt_get_device_name(cd), &backing_file)
	};

	if (!ARG_SET(OPT_BATCH_MODE_ID))
		log_std(_("Wiping device to initialize integrity checksum.\n"
			"You can interrupt this by pressing CTRL+c "
			"(rest of not wiped device will contain invalid checksum).\n"));

	/* Activate the device a temporary one */
	uuid_generate(tmp_uuid_bin);
	uuid_unparse(tmp_uuid_bin, tmp_uuid);
	if (snprintf(tmp_name, sizeof(tmp_name), "temporary-cryptsetup-%s", tmp_uuid) < 0)
		goto out;
	if (snprintf(tmp_path, sizeof(tmp_path), "%s/%s", crypt_get_dir(), tmp_name) < 0)
		goto out;

	r = crypt_activate_by_volume_key(cd, tmp_name, integrity_key,
		ARG_UINT32(OPT_INTEGRITY_KEY_SIZE_ID), CRYPT_ACTIVATE_PRIVATE | CRYPT_ACTIVATE_NO_JOURNAL);
	if (r < 0)
		goto out;

	/* Wipe the device */
	set_int_handler(0);
	r = crypt_wipe(cd, tmp_path, CRYPT_WIPE_ZERO, 0, 0, DEFAULT_WIPE_BLOCK,
		       0, &tools_progress, &prog_parms);
	if (crypt_deactivate(cd, tmp_name))
		log_err(_("Cannot deactivate temporary device %s."), tmp_path);
	set_int_block(0);

out:
	free(backing_file);
	return r;
}

static int action_format(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_integrity params = {
		.buffer_sectors = ARG_UINT32(OPT_BUFFER_SECTORS_ID),
		.tag_size = ARG_UINT32(OPT_TAG_SIZE_ID),
		.sector_size = ARG_UINT32(OPT_SECTOR_SIZE_ID),
	}, params2;
	char integrity[MAX_CIPHER_LEN], journal_integrity[MAX_CIPHER_LEN], journal_crypt[MAX_CIPHER_LEN];
	char *integrity_key = NULL, *msg = NULL;
	int r;
	size_t signatures;

	r = crypt_parse_hash_integrity_mode(ARG_STR(OPT_INTEGRITY_ID), integrity);
	if (r < 0) {
		log_err(_("No known integrity specification pattern detected."));
		return r;
	}
	params.integrity = integrity;

	if (!ARG_SET(OPT_INTEGRITY_INLINE_ID)) {
		params.journal_size = ARG_UINT64(OPT_JOURNAL_SIZE_ID);
		params.interleave_sectors = ARG_UINT32(OPT_INTERLEAVE_SECTORS_ID);
		/* in bitmap mode we have to overload these values... */
		params.journal_watermark = ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID) ? ARG_UINT32(OPT_BITMAP_SECTORS_PER_BIT_ID) : ARG_UINT32(OPT_JOURNAL_WATERMARK_ID);
		params.journal_commit_time = ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID) ? ARG_UINT32(OPT_BITMAP_FLUSH_TIME_ID) : ARG_UINT32(OPT_JOURNAL_COMMIT_TIME_ID);

		if (ARG_SET(OPT_JOURNAL_INTEGRITY_ID)) {
			r = crypt_parse_hash_integrity_mode(ARG_STR(OPT_JOURNAL_INTEGRITY_ID), journal_integrity);
			if (r < 0) {
				log_err(_("No known integrity specification pattern detected."));
				return r;
			}
			params.journal_integrity = journal_integrity;
		}

		if (ARG_SET(OPT_JOURNAL_CRYPT_ID)) {
			r = crypt_parse_hash_integrity_mode(ARG_STR(OPT_JOURNAL_CRYPT_ID), journal_crypt);
			if (r < 0) {
				log_err(_("No known integrity specification pattern detected."));
				return r;
			}
			params.journal_crypt = journal_crypt;
		}

	}

	r = _read_keys(&integrity_key, &params);
	if (r)
		goto out;

	r = crypt_init_data_device(&cd, action_argv[0], ARG_STR(OPT_DATA_DEVICE_ID));
	if (r < 0)
		goto out;

	if (!ARG_SET(OPT_BATCH_MODE_ID)) {
		if (ARG_SET(OPT_DATA_DEVICE_ID) && !ARG_SET(OPT_NO_WIPE_ID))
			r = asprintf(&msg, _("This will overwrite data on %s and %s irrevocably.\n"
			"To preserve data device use --no-wipe option (and then activate with --integrity-recalculate)."),
			action_argv[0], ARG_STR(OPT_DATA_DEVICE_ID));
		else
			r = asprintf(&msg, _("This will overwrite data on %s irrevocably."), action_argv[0]);
		if (r == -1) {
			r = -ENOMEM;
			goto out;
		}

		r = yesDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
		free(msg);
		if (r < 0)
			goto out;
	}

	if (!ARG_SET(OPT_DISABLE_BLKID_ID)) {
		r = tools_detect_signatures(action_argv[0], PRB_FILTER_NONE, &signatures, ARG_SET(OPT_BATCH_MODE_ID));
		if (r < 0) {
			if (r == -EIO)
				log_err(_("Blkid scan failed for %s."), action_argv[0]);
			goto out;
		}

		/* Signature candidates found */
		if (signatures && ((r = tools_wipe_all_signatures(action_argv[0], true, false)) < 0))
			goto out;
	}

	if (ARG_SET(OPT_INTEGRITY_LEGACY_PADDING_ID))
		crypt_set_compatibility(cd, CRYPT_COMPAT_LEGACY_INTEGRITY_PADDING);

	if (ARG_SET(OPT_INTEGRITY_LEGACY_HMAC_ID))
		crypt_set_compatibility(cd, CRYPT_COMPAT_LEGACY_INTEGRITY_HMAC);

	if (ARG_SET(OPT_INTEGRITY_INLINE_ID))
		r = crypt_format_inline(cd, CRYPT_INTEGRITY, NULL, NULL, NULL,
					integrity_key, params.integrity_key_size, &params);
	else
		r = crypt_format(cd, CRYPT_INTEGRITY, NULL, NULL, NULL,
				 integrity_key, params.integrity_key_size, &params);
	if (r < 0) /* FIXME: call wipe signatures again */
		goto out;

	if (!ARG_SET(OPT_BATCH_MODE_ID) && !crypt_get_integrity_info(cd, &params2))
		log_std(_("Formatted with tag size %u%s, internal integrity %s.\n"),
			params2.tag_size, ARG_SET(OPT_INTEGRITY_INLINE_ID) ? _(" (inline hw tags)") : "", params2.integrity);

	if (!ARG_SET(OPT_NO_WIPE_ID)) {
		r = _wipe_data_device(cd, integrity_key);
		/* Interrupted wipe should not fail format action */
		if (r == -EINTR)
			r = 0;
	}
out:
	crypt_safe_free(integrity_key);
	crypt_safe_free(CONST_CAST(void*)params.journal_integrity_key);
	crypt_safe_free(CONST_CAST(void*)params.journal_crypt_key);
	crypt_free(cd);
	return r;
}

static int action_resize(void)
{
	int r;
	struct crypt_device *cd = NULL;
	struct crypt_active_device cad;
	uint64_t new_dev_size = 0;
	uint64_t old_dev_size;
	char path[PATH_MAX];
	char *backing_file = NULL;
	uint32_t reactivate_flags;
	struct tools_progress_params prog_parms = {
		.frequency = ARG_UINT32(OPT_PROGRESS_FREQUENCY_ID),
		.batch_mode = ARG_SET(OPT_BATCH_MODE_ID),
		.json_output = ARG_SET(OPT_PROGRESS_JSON_ID),
		.interrupt_message = _("\nWipe interrupted."),
		.device = tools_get_device_name(crypt_get_device_name(cd), &backing_file)
	};

	if (ARG_SET(OPT_DEVICE_SIZE_ID))
		new_dev_size = ARG_UINT64(OPT_DEVICE_SIZE_ID) / SECTOR_SIZE;
	else if (ARG_SET(OPT_SIZE_ID))
		new_dev_size = ARG_UINT64(OPT_SIZE_ID);

	r = crypt_init_by_name_and_header(&cd, action_argv[0], NULL);
	if (r)
		goto out;

	r = crypt_get_active_device(cd, action_argv[0], &cad);
	if (r)
		goto out;
	old_dev_size = cad.size;

	r = snprintf(path, sizeof(path), "%s/%s", crypt_get_dir(), action_argv[0]);
	if (r < 0)
		goto out;
	r = crypt_resize(cd, action_argv[0], new_dev_size);
	if (r)
		goto out;

	r = crypt_get_active_device(cd, action_argv[0], &cad);
	if (r)
		goto out;

	reactivate_flags = CRYPT_ACTIVATE_REFRESH | (cad.flags & CRYPT_ACTIVATE_INLINE_MODE);

	if (!new_dev_size)
		new_dev_size = cad.size;

	if (new_dev_size > old_dev_size) {
		if (ARG_SET(OPT_WIPE_ID)) {
			if (ARG_SET(OPT_BATCH_MODE_ID))
				log_dbg("Wiping the end of the resized device");
			else
				log_std(_("Wiping device to initialize integrity checksum.\n"
					"You can interrupt this by pressing CTRL+c "
					"(rest of not wiped device will contain invalid checksum).\n"));

			set_int_handler(0);
			r = crypt_wipe(cd, path, CRYPT_WIPE_ZERO, old_dev_size * SECTOR_SIZE,
				      (new_dev_size - old_dev_size) * SECTOR_SIZE, DEFAULT_WIPE_BLOCK,
				      0, &tools_progress, &prog_parms);
			set_int_block(0);
		} else {
			log_dbg("Setting recalculate flag");
			reactivate_flags |= CRYPT_ACTIVATE_RECALCULATE;
			r = crypt_activate_by_volume_key(cd, action_argv[0], NULL, 0, reactivate_flags);
			if (r == -ENOTSUP)
				log_err(_("Setting recalculate flag is not supported, you may consider using --wipe instead."));
		}
	}
out:
	free(backing_file);
	crypt_free(cd);
	return r;
}

static int action_open(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_integrity params = {
		/* in bitmap mode we have to overload these values... */
		.journal_watermark = ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID) ? ARG_UINT32(OPT_BITMAP_SECTORS_PER_BIT_ID) : ARG_UINT32(OPT_JOURNAL_WATERMARK_ID),
		.journal_commit_time = ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID) ? ARG_UINT32(OPT_BITMAP_FLUSH_TIME_ID) : ARG_UINT32(OPT_JOURNAL_COMMIT_TIME_ID),
		.buffer_sectors = ARG_UINT32(OPT_BUFFER_SECTORS_ID),
	};
	uint32_t activate_flags = 0;
	char integrity[MAX_CIPHER_LEN], journal_integrity[MAX_CIPHER_LEN], journal_crypt[MAX_CIPHER_LEN];
	char *integrity_key = NULL;
	int r;

	r = crypt_parse_hash_integrity_mode(ARG_STR(OPT_INTEGRITY_ID), integrity);
	if (r < 0) {
		log_err(_("No known integrity specification pattern detected."));
		return r;
	}
	params.integrity = integrity;

	if (ARG_SET(OPT_JOURNAL_INTEGRITY_ID)) {
		r = crypt_parse_hash_integrity_mode(ARG_STR(OPT_JOURNAL_INTEGRITY_ID), journal_integrity);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			return r;

		}
		params.journal_integrity = journal_integrity;
	}

	if (ARG_SET(OPT_JOURNAL_CRYPT_ID)) {
		r = crypt_parse_hash_integrity_mode(ARG_STR(OPT_JOURNAL_CRYPT_ID), journal_crypt);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			return r;
		}
		params.journal_crypt = journal_crypt;
	}

	if (ARG_SET(OPT_INTEGRITY_NO_JOURNAL_ID) || ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID))
		activate_flags |= CRYPT_ACTIVATE_NO_JOURNAL;
	if (ARG_SET(OPT_INTEGRITY_RECOVERY_MODE_ID))
		activate_flags |= CRYPT_ACTIVATE_RECOVERY;
	if (ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID))
		activate_flags |= CRYPT_ACTIVATE_NO_JOURNAL_BITMAP;

	if (ARG_SET(OPT_INTEGRITY_RECALCULATE_ID) || ARG_SET(OPT_INTEGRITY_LEGACY_RECALC_ID))
		activate_flags |= CRYPT_ACTIVATE_RECALCULATE;

	if (ARG_SET(OPT_INTEGRITY_RECALCULATE_RESET_ID))
		activate_flags |= CRYPT_ACTIVATE_RECALCULATE_RESET;

	if (ARG_SET(OPT_ALLOW_DISCARDS_ID))
		activate_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

	if ((r = tools_check_newname(action_argv[1])))
		goto out;

	r = _read_keys(&integrity_key, &params);
	if (r)
		goto out;

	if ((r = crypt_init_data_device(&cd, action_argv[0], ARG_STR(OPT_DATA_DEVICE_ID))))
		goto out;

	r = crypt_load(cd, CRYPT_INTEGRITY, &params);
	if (r) {
		log_err(_("Device %s is not a valid INTEGRITY device."), action_argv[0]);
		goto out;
	}

	if (ARG_SET(OPT_INTEGRITY_LEGACY_RECALC_ID))
		crypt_set_compatibility(cd, CRYPT_COMPAT_LEGACY_INTEGRITY_RECALC);

	r = crypt_activate_by_volume_key(cd, action_argv[1], integrity_key,
					 ARG_UINT32(OPT_INTEGRITY_KEY_SIZE_ID), activate_flags);
out:
	crypt_safe_free(integrity_key);
	crypt_safe_free(CONST_CAST(void*)params.journal_integrity_key);
	crypt_safe_free(CONST_CAST(void*)params.journal_crypt_key);
	crypt_free(cd);
	return r;
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
	struct crypt_params_integrity ip = {};
	struct crypt_device *cd = NULL;
	char *backing_file;
	const char *device, *metadata_device;
	int path = 0, r = 0;

	/* perhaps a path, not a dm device name */
	if (strchr(action_argv[0], '/'))
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

		log_std("  type:    %s\n", crypt_get_type(cd) ?: "n/a");

		r = crypt_get_active_device(cd, action_argv[0], &cad);
		if (r < 0)
			goto out;

		/* Print only INTEGRITY (and LUKS2 with integrity) info */
		r = crypt_get_integrity_info(cd, &ip);
		if (r < 0)
			goto out;

		log_std("  tag size: %u [bytes]\n", ip.tag_size);
		log_std("  integrity: %s\n", ip.integrity ?: "(none)");
		device = crypt_get_device_name(cd);
		metadata_device = crypt_get_metadata_device_name(cd);
		log_std("  device:  %s%s\n", device, metadata_device ? " (detached)" : "");
		if ((backing_file = crypt_loop_backing_file(device))) {
			log_std("  loop:    %s\n", backing_file);
			free(backing_file);
		}
		if (metadata_device) {
			log_std("  metadata device:  %s\n", metadata_device);
			if ((backing_file = crypt_loop_backing_file(metadata_device))) {
				log_std("  loop:    %s\n", backing_file);
				free(backing_file);
			}
		}
		log_std("  sector size:  %" PRIu64 " [bytes]\n", (uint64_t)crypt_get_sector_size(cd) ?: SECTOR_SIZE);
		log_std("  interleave sectors: %u\n", ip.interleave_sectors);
		log_std("  size:    %" PRIu64 " [512-byte units] (%" PRIu64 " [bytes])\n", cad.size, cad.size * SECTOR_SIZE);
		log_std("  mode:    %s%s\n",
			cad.flags & CRYPT_ACTIVATE_READONLY ? "readonly" : "read/write",
			cad.flags & CRYPT_ACTIVATE_RECOVERY ? " recovery" : "");
		log_std("  failures: %" PRIu64 "\n",
			crypt_get_active_integrity_failures(cd, action_argv[0]));
		if (cad.flags & CRYPT_ACTIVATE_NO_JOURNAL_BITMAP) {
			log_std("  bitmap 512-byte sectors per bit: %u\n", ip.journal_watermark);
			log_std("  bitmap flush interval: %u [ms]\n", ip.journal_commit_time);
		}
		if (cad.flags & CRYPT_ACTIVATE_INLINE_MODE) {
			log_std("  inline mode\n");
		}
		if (cad.flags & CRYPT_ACTIVATE_NO_JOURNAL) {
			log_std("  journal: not active\n");
		} else {
			log_std("  journal size: %" PRIu64 " [bytes]\n", ip.journal_size);
			log_std("  journal watermark: %u%%\n", ip.journal_watermark);
			log_std("  journal commit time: %u [ms]\n", ip.journal_commit_time);
			if (ip.journal_integrity)
				log_std("  journal integrity MAC: %s\n", ip.journal_integrity);
			if (ip.journal_crypt)
				log_std("  journal encryption: %s\n", ip.journal_crypt);
		}
		if (cad.flags & (CRYPT_ACTIVATE_ALLOW_DISCARDS))
			log_std("  flags: %s\n",
				(cad.flags & CRYPT_ACTIVATE_ALLOW_DISCARDS) ? "discards " : "");
	}
out:
	crypt_free(cd);
	if (r == -ENOTSUP)
		r = 0;
	return r;
	return -EINVAL;
}

static int action_dump(void)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_integrity params = {};
	int r;

	if ((r = crypt_init(&cd, action_argv[0])))
		return r;

	r = crypt_load(cd, CRYPT_INTEGRITY, &params);
	if (!r)
		crypt_dump(cd);
	else
		log_err(_("Device %s is not a valid INTEGRITY device."), action_argv[0]);

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
	{ FORMAT_ACTION,action_format, 1, N_("<integrity_device>"),N_("format device") },
	{ OPEN_ACTION,	action_open,   2, N_("<integrity_device> <name>"),N_("open device as <name>") },
	{ CLOSE_ACTION,	action_close,  1, N_("<name>"),N_("close device (remove mapping)") },
	{ STATUS_ACTION,action_status, 1, N_("<name>"),N_("show active device status") },
	{ DUMP_ACTION,	action_dump,   1, N_("<integrity_device>"),N_("show on-disk information") },
	{ RESIZE_ACTION,action_resize, 1, N_("<name>"), N_("resize active device") },
	{}
};

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	struct action_type *action;

	if (key->shortName == '?') {
		tools_package_version(PACKAGE_INTEGRITY, false);
		poptPrintHelp(popt_context, stdout, 0);
		log_std(_("\n"
			 "<action> is one of:\n"));
		for(action = action_types; action->type; action++)
			log_std("\t%s %s - %s\n", action->type, _(action->arg_desc), _(action->desc));
		log_std(_("\n"
			 "<name> is the device to create under %s\n"
			 "<integrity_device> is the device containing data with integrity tags\n"),
			crypt_get_dir());

		log_std(_("\nDefault compiled-in dm-integrity parameters:\n"
			  "\tChecksum algorithm: %s\n"
			  "\tMaximum keyfile size: %dkB\n"),
			  DEFAULT_ALG_NAME, DEFAULT_INTEGRITY_KEYFILE_SIZE_MAXKB);
		tools_cleanup();
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else if (key->shortName == 'V') {
		tools_package_version(PACKAGE_INTEGRITY, false);
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

static bool needs_size_conversion(unsigned int arg_id)
{
	return (arg_id == OPT_JOURNAL_SIZE_ID || arg_id == OPT_DEVICE_SIZE_ID);
}

static void basic_options_cb(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg,
		 void *data __attribute__((unused)))
{
	char msg[256];

	tools_parse_arg_value(popt_context, tool_core_args[key->val].type, tool_core_args + key->val, arg, key->val, needs_size_conversion);

	/* special cases additional handling */
	switch (key->val) {
	case OPT_DEBUG_ID:
		log_parms.debug = true;
		/* fall through */
	case OPT_VERBOSE_ID:
		log_parms.verbose = true;
		break;
	case OPT_INTEGRITY_KEY_SIZE_ID:
		/* fall through */
	case OPT_JOURNAL_INTEGRITY_KEY_SIZE_ID:
		/* fall through */
	case OPT_JOURNAL_CRYPT_KEY_SIZE_ID:
		if (ARG_UINT32(key->val) > (DEFAULT_INTEGRITY_KEYFILE_SIZE_MAXKB * 1024)) {
			if (snprintf(msg, sizeof(msg), _("Invalid --%s size. Maximum is %u bytes."),
			    key->longName, DEFAULT_INTEGRITY_KEYFILE_SIZE_MAXKB * 1024) < 0)
				msg[0] = '\0';
			usage(popt_context, EXIT_FAILURE, msg,
			      poptGetInvocationName(popt_context));
		}
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
#include "integritysetup_arg_list.h"
#undef ARG
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ NULL, '\0', POPT_ARG_INCLUDE_TABLE, popt_basic_options, 0, NULL, NULL },
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

	popt_context = poptGetContext("integrity", argc, argv, popt_options, 0);
	if (!popt_context)
		exit(EXIT_FAILURE);

	poptSetOtherOptionHelp(popt_context,
	                       _("[OPTION...] <action> <action-specific>"));


	while ((r = poptGetNextOpt(popt_context)) >= 0) {
	}

	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));

	if (!(aname = poptGetArg(popt_context)))
		usage(popt_context, EXIT_FAILURE, _("Argument <action> missing."),
		      poptGetInvocationName(popt_context));

	action_argc = 0;
	action_argv = poptGetArgs(popt_context);
	/* Make return values of poptGetArgs more consistent in case of remaining argc = 0 */
	if (!action_argv)
		action_argv = null_action_argv;

	/* Count args, somewhat unnice, change? */
	while (action_argv[action_argc] != NULL)
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
			buf[0] ='\0';
		usage(popt_context, EXIT_FAILURE, buf,
		      poptGetInvocationName(popt_context));
	}

	tools_check_args(action->type, tool_core_args, ARRAY_SIZE(tool_core_args), popt_context);

	if (ARG_SET(OPT_INTEGRITY_KEY_FILE_ID) != ARG_SET(OPT_INTEGRITY_KEY_SIZE_ID))
		usage(popt_context, EXIT_FAILURE, _("Both key file and key size options must be specified."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_JOURNAL_INTEGRITY_KEY_FILE_ID) != ARG_SET(OPT_JOURNAL_INTEGRITY_KEY_SIZE_ID))
		usage(popt_context, EXIT_FAILURE, _("Both journal integrity key file and key size options must be specified."),
		      poptGetInvocationName(popt_context));
	if (!ARG_SET(OPT_JOURNAL_INTEGRITY_ID) && ARG_SET(OPT_JOURNAL_INTEGRITY_KEY_FILE_ID))
		usage(popt_context, EXIT_FAILURE, _("Journal integrity algorithm must be specified if journal integrity key is used."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_JOURNAL_CRYPT_KEY_FILE_ID) != ARG_SET(OPT_JOURNAL_CRYPT_KEY_SIZE_ID))
		usage(popt_context, EXIT_FAILURE, _("Both journal encryption key file and key size options must be specified."),
		      poptGetInvocationName(popt_context));
	if (!ARG_SET(OPT_JOURNAL_CRYPT_ID) && ARG_SET(OPT_JOURNAL_CRYPT_KEY_FILE_ID))
		usage(popt_context, EXIT_FAILURE, _("Journal encryption algorithm must be specified if journal encryption key is used."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_INTEGRITY_RECOVERY_MODE_ID) && ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID))
		usage(popt_context, EXIT_FAILURE, _("Recovery and bitmap mode options are mutually exclusive."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID) &&
	    (ARG_SET(OPT_JOURNAL_INTEGRITY_KEY_FILE_ID) ||
	     ARG_SET(OPT_JOURNAL_CRYPT_ID) || ARG_SET(OPT_JOURNAL_WATERMARK_ID) ||
	     ARG_SET(OPT_JOURNAL_COMMIT_TIME_ID)))
		usage(popt_context, EXIT_FAILURE, _("Journal options cannot be used in bitmap mode."),
		      poptGetInvocationName(popt_context));

	if (!ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID) &&
	    (ARG_SET(OPT_BITMAP_FLUSH_TIME_ID) || ARG_SET(OPT_BITMAP_SECTORS_PER_BIT_ID)))
		usage(popt_context, EXIT_FAILURE, _("Bitmap options can be used only in bitmap mode."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_INTEGRITY_INLINE_ID) && (ARG_SET(OPT_INTEGRITY_BITMAP_MODE_ID) ||
	    ARG_SET(OPT_JOURNAL_INTEGRITY_ID) || ARG_SET(OPT_JOURNAL_CRYPT_ID) ||
	    ARG_SET(OPT_JOURNAL_WATERMARK_ID) || ARG_SET(OPT_JOURNAL_COMMIT_TIME_ID)))
		usage(popt_context, EXIT_FAILURE, _("Inline mode cannot be combined with journal or bitmap options."),
		      poptGetInvocationName(popt_context));

	if (ARG_SET(OPT_INTEGRITY_INLINE_ID) && ARG_SET(OPT_DATA_DEVICE_ID))
		usage(popt_context, EXIT_FAILURE, _("Inline mode cannot be combined with separate data device."),
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
