/*
 * integritysetup - setup integrity protected volumes for dm-integrity
 *
 * Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2017-2020 Milan Broz
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
#include <uuid/uuid.h>

#define PACKAGE_INTEGRITY "integritysetup"

#define DEFAULT_ALG_NAME "crc32c"
#define MAX_KEY_SIZE 4096

static const char *opt_journal_size_str = NULL;
static uint64_t opt_journal_size = 0;
static int opt_interleave_sectors = 0;
static int opt_journal_watermark = 0;
static int opt_bitmap_sectors_per_bit = 0;
static int opt_journal_commit_time = 0;
static int opt_bitmap_flush_time = 0;
static int opt_tag_size = 0;
static int opt_sector_size = 0;
static int opt_buffer_sectors = 0;

static int opt_no_wipe = 0;

static const char *opt_data_device = NULL;

static const char *opt_integrity = DEFAULT_ALG_NAME;
static const char *opt_integrity_key_file = NULL;
static int opt_integrity_key_size = 0;

static const char *opt_journal_integrity = NULL; /* none */
static const char *opt_journal_integrity_key_file = NULL;
static int opt_journal_integrity_key_size = 0;

static const char *opt_journal_crypt = NULL; /* none */
static const char *opt_journal_crypt_key_file = NULL;
static int opt_journal_crypt_key_size = 0;

static int opt_integrity_nojournal = 0;
static int opt_integrity_recovery = 0;
static int opt_integrity_bitmap = 0;
static int opt_integrity_legacy_padding = 0;

static int opt_integrity_recalculate = 0;
static int opt_allow_discards = 0;

static const char **action_argv;
static int action_argc;

// FIXME: move this to tools and handle EINTR
static int _read_mk(const char *file, char **key, int keysize)
{
	int fd;

	if (keysize <= 0 || keysize > MAX_KEY_SIZE) {
		log_err(_("Invalid key size."));
		return -EINVAL;
	}

	*key = crypt_safe_alloc(keysize);
	if (!*key)
		return -ENOMEM;

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		log_err(_("Cannot read keyfile %s."), file);
		goto fail;
	}
	if ((read(fd, *key, keysize) != keysize)) {
		log_err(_("Cannot read %d bytes from keyfile %s."), keysize, file);
		close(fd);
		goto fail;
	}
	close(fd);
	return 0;
fail:
	crypt_safe_free(*key);
	*key = NULL;
	return -EINVAL;
}

static int _read_keys(char **integrity_key, struct crypt_params_integrity *params)
{
	char *int_key = NULL, *journal_integrity_key = NULL, *journal_crypt_key = NULL;
	int r;

	if (integrity_key && opt_integrity_key_file) {
		r = _read_mk(opt_integrity_key_file, &int_key, opt_integrity_key_size);
		if (r < 0)
			return r;
		params->integrity_key_size = opt_integrity_key_size;
	}

	if (opt_journal_integrity_key_file) {
		r = _read_mk(opt_journal_integrity_key_file, &journal_integrity_key, opt_journal_integrity_key_size);
		if (r < 0) {
			crypt_safe_free(int_key);
			return r;
		}
		params->journal_integrity_key = journal_integrity_key;
		params->journal_integrity_key_size = opt_journal_integrity_key_size;
	}

	if (opt_journal_crypt_key_file) {
		r = _read_mk(opt_journal_crypt_key_file, &journal_crypt_key, opt_journal_crypt_key_size);
		if (r < 0) {
			crypt_safe_free(int_key);
			crypt_safe_free(journal_integrity_key);
			return r;
		}
		params->journal_crypt_key = journal_crypt_key;
		params->journal_crypt_key_size = opt_journal_crypt_key_size;
	}

	if (integrity_key)
		*integrity_key = int_key;

	return 0;
}

static int _wipe_data_device(struct crypt_device *cd, const char *integrity_key)
{
	char tmp_name[64], tmp_path[128], tmp_uuid[40];
	uuid_t tmp_uuid_bin;
	int r;

	if (!opt_batch_mode)
		log_std(_("Wiping device to initialize integrity checksum.\n"
			"You can interrupt this by pressing CTRL+c "
			"(rest of not wiped device will contain invalid checksum).\n"));

	/* Activate the device a temporary one */
	uuid_generate(tmp_uuid_bin);
	uuid_unparse(tmp_uuid_bin, tmp_uuid);
	if (snprintf(tmp_name, sizeof(tmp_name), "temporary-cryptsetup-%s", tmp_uuid) < 0)
		return -EINVAL;
	if (snprintf(tmp_path, sizeof(tmp_path), "%s/%s", crypt_get_dir(), tmp_name) < 0)
		return -EINVAL;

	r = crypt_activate_by_volume_key(cd, tmp_name, integrity_key,
		opt_integrity_key_size, CRYPT_ACTIVATE_PRIVATE | CRYPT_ACTIVATE_NO_JOURNAL);
	if (r < 0)
		return r;

	/* Wipe the device */
	set_int_handler(0);
	r = crypt_wipe(cd, tmp_path, CRYPT_WIPE_ZERO, 0, 0, DEFAULT_WIPE_BLOCK,
		       0, &tools_wipe_progress, NULL);
	if (crypt_deactivate(cd, tmp_name))
		log_err(_("Cannot deactivate temporary device %s."), tmp_path);
	set_int_block(0);

	return r;
}

static int action_format(int arg)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_integrity params = {
		.journal_size = opt_journal_size,
		.interleave_sectors = opt_interleave_sectors,
		/* in bitmap mode we have to overload these values... */
		.journal_watermark = opt_integrity_bitmap ? opt_bitmap_sectors_per_bit : opt_journal_watermark,
		.journal_commit_time = opt_integrity_bitmap ? opt_bitmap_flush_time : opt_journal_commit_time,
		.buffer_sectors = opt_buffer_sectors,
		.tag_size = opt_tag_size,
		.sector_size = opt_sector_size ?: SECTOR_SIZE,
	}, params2;
	char integrity[MAX_CIPHER_LEN], journal_integrity[MAX_CIPHER_LEN], journal_crypt[MAX_CIPHER_LEN];
	char *integrity_key = NULL, *msg = NULL;
	int r;
	size_t signatures;

	if (opt_integrity) {
		r = crypt_parse_hash_integrity_mode(opt_integrity, integrity);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			return r;
		}
		params.integrity = integrity;
	}

	if (opt_journal_integrity) {
		r = crypt_parse_hash_integrity_mode(opt_journal_integrity, journal_integrity);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			return r;
		}
		params.journal_integrity = journal_integrity;
	}

	if (opt_journal_crypt) {
		r = crypt_parse_hash_integrity_mode(opt_journal_crypt, journal_crypt);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			return r;
		}
		params.journal_crypt = journal_crypt;
	}

	r = _read_keys(&integrity_key, &params);
	if (r)
		goto out;

	r = crypt_init_data_device(&cd, action_argv[0], opt_data_device);
	if (r < 0)
		goto out;

	r = asprintf(&msg, _("This will overwrite data on %s irrevocably."), action_argv[0]);
	if (r == -1) {
		r = -ENOMEM;
		goto out;
	}

	r = yesDialog(msg, _("Operation aborted.\n")) ? 0 : -EINVAL;
	free(msg);
	if (r < 0)
		goto out;

	r = tools_detect_signatures(action_argv[0], 0, &signatures);
	if (r < 0)
		goto out;

	/* Signature candidates found */
	if (signatures && ((r =	tools_wipe_all_signatures(action_argv[0])) < 0))
		goto out;

	if (opt_integrity_legacy_padding)
		crypt_set_compatibility(cd, CRYPT_COMPAT_LEGACY_INTEGRITY_PADDING);

	r = crypt_format(cd, CRYPT_INTEGRITY, NULL, NULL, NULL, NULL, 0, &params);
	if (r < 0) /* FIXME: call wipe signatures again */
		goto out;

	if (!opt_batch_mode && !crypt_get_integrity_info(cd, &params2))
		log_std(_("Formatted with tag size %u, internal integrity %s.\n"),
			params2.tag_size, params2.integrity);

	if (!opt_no_wipe)
		r = _wipe_data_device(cd, integrity_key);
out:
	crypt_safe_free(integrity_key);
	crypt_safe_free(CONST_CAST(void*)params.journal_integrity_key);
	crypt_safe_free(CONST_CAST(void*)params.journal_crypt_key);
	crypt_free(cd);
	return r;
}

static int action_open(int arg)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_integrity params = {
		/* in bitmap mode we have to overload these values... */
		.journal_watermark = opt_integrity_bitmap ? opt_bitmap_sectors_per_bit : opt_journal_watermark,
		.journal_commit_time = opt_integrity_bitmap ? opt_bitmap_flush_time : opt_journal_commit_time,
		.buffer_sectors = opt_buffer_sectors,
	};
	uint32_t activate_flags = 0;
	char integrity[MAX_CIPHER_LEN], journal_integrity[MAX_CIPHER_LEN], journal_crypt[MAX_CIPHER_LEN];
	char *integrity_key = NULL;
	int r;

	if (opt_integrity) {
		r = crypt_parse_hash_integrity_mode(opt_integrity, integrity);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			return r;
		}
		params.integrity = integrity;
	}

	if (opt_journal_integrity) {
		r = crypt_parse_hash_integrity_mode(opt_journal_integrity, journal_integrity);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			return r;

		}
		params.journal_integrity = journal_integrity;
	}

	if (opt_journal_crypt) {
		r = crypt_parse_hash_integrity_mode(opt_journal_crypt, journal_crypt);
		if (r < 0) {
			log_err(_("No known integrity specification pattern detected."));
			return r;
		}
		params.journal_crypt = journal_crypt;
	}

	if (opt_integrity_nojournal || opt_integrity_bitmap)
		activate_flags |= CRYPT_ACTIVATE_NO_JOURNAL;
	if (opt_integrity_recovery)
		activate_flags |= CRYPT_ACTIVATE_RECOVERY;
	if (opt_integrity_bitmap)
		activate_flags |= CRYPT_ACTIVATE_NO_JOURNAL_BITMAP;

	if (opt_integrity_recalculate)
		activate_flags |= CRYPT_ACTIVATE_RECALCULATE;
	if (opt_allow_discards)
		activate_flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

	r = _read_keys(&integrity_key, &params);
	if (r)
		goto out;

	if ((r = crypt_init_data_device(&cd, action_argv[0], opt_data_device)))
		goto out;

	r = crypt_load(cd, CRYPT_INTEGRITY, &params);
	if (r)
		goto out;

	r = crypt_activate_by_volume_key(cd, action_argv[1], integrity_key,
					 opt_integrity_key_size, activate_flags);
out:
	crypt_safe_free(integrity_key);
	crypt_safe_free(CONST_CAST(void*)params.journal_integrity_key);
	crypt_safe_free(CONST_CAST(void*)params.journal_crypt_key);
	crypt_free(cd);
	return r;
}

static int action_close(int arg)
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

		log_std("  tag size: %u\n", ip.tag_size);
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
		log_std("  sector size:  %u bytes\n", crypt_get_sector_size(cd));
		log_std("  interleave sectors: %u\n", ip.interleave_sectors);
		log_std("  size:    %" PRIu64 " sectors\n", cad.size);
		log_std("  mode:    %s%s\n",
			cad.flags & CRYPT_ACTIVATE_READONLY ? "readonly" : "read/write",
			cad.flags & CRYPT_ACTIVATE_RECOVERY ? " recovery" : "");
		log_std("  failures: %" PRIu64 "\n",
			crypt_get_active_integrity_failures(cd, action_argv[0]));
		if (cad.flags & CRYPT_ACTIVATE_NO_JOURNAL_BITMAP) {
			log_std("  bitmap 512-byte sectors per bit: %u\n", ip.journal_watermark);
			log_std("  bitmap flush interval: %u ms\n", ip.journal_commit_time);
		} if (cad.flags & CRYPT_ACTIVATE_NO_JOURNAL) {
			log_std("  journal: not active\n");
		} else {
			log_std("  journal size: %" PRIu64 " bytes\n", ip.journal_size);
			log_std("  journal watermark: %u%%\n", ip.journal_watermark);
			log_std("  journal commit time: %u ms\n", ip.journal_commit_time);
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

static int action_dump(int arg)
{
	struct crypt_device *cd = NULL;
	struct crypt_params_integrity params = {};
	int r;

	if ((r = crypt_init(&cd, action_argv[0])))
		return r;

	r = crypt_load(cd, CRYPT_INTEGRITY, &params);
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
	{ "format",	action_format, 1, N_("<integrity_device>"),N_("format device") },
	{ "open",	action_open,   2, N_("<integrity_device> <name>"),N_("open device as <name>") },
	{ "close",	action_close,  1, N_("<name>"),N_("close device (remove mapping)") },
	{ "status",	action_status, 1, N_("<name>"),N_("show active device status") },
	{ "dump",	action_dump,   1, N_("<integrity_device>"),N_("show on-disk information") },
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
		log_std("%s %s\n", PACKAGE_INTEGRITY, PACKAGE_VERSION);
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
			  "\tChecksum algorithm: %s\n"), DEFAULT_ALG_NAME);
		poptFreeContext(popt_context);
		exit(EXIT_SUCCESS);
	} else if (key->shortName == 'V') {
		log_std("%s %s\n", PACKAGE_INTEGRITY, PACKAGE_VERSION);
		poptFreeContext(popt_context);
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
	static const char *null_action_argv[] = {NULL};
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		{ "version",'V', POPT_ARG_NONE,     NULL, 0, N_("Print package version"),  NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,                 '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, N_("Help options:"), NULL },
		{ "verbose",             'v', POPT_ARG_NONE, &opt_verbose,            0, N_("Shows more detailed error messages"), NULL },
		{ "debug",              '\0', POPT_ARG_NONE, &opt_debug,              0, N_("Show debug messages"), NULL },
		{ "batch-mode",          'q', POPT_ARG_NONE, &opt_batch_mode,         0, N_("Do not ask for confirmation"), NULL },
		{ "progress-frequency", '\0', POPT_ARG_INT,  &opt_progress_frequency, 0, N_("Progress line update (in seconds)"), N_("secs") },
		{ "no-wipe",            '\0', POPT_ARG_NONE, &opt_no_wipe,            0, N_("Do not wipe device after format"), NULL },

		{ "data-device",        '\0', POPT_ARG_STRING, &opt_data_device,      0, N_("Path to data device (if separated)"), N_("path") },

		{ "journal-size",        'j', POPT_ARG_STRING,&opt_journal_size_str,  0, N_("Journal size"), N_("bytes") },
		{ "interleave-sectors", '\0', POPT_ARG_INT,  &opt_interleave_sectors, 0, N_("Interleave sectors"), N_("SECTORS") },
		{ "journal-watermark",  '\0', POPT_ARG_INT,  &opt_journal_watermark,  0, N_("Journal watermark"),N_("percent") },
		{ "journal-commit-time",'\0', POPT_ARG_INT,  &opt_journal_commit_time,0, N_("Journal commit time"), N_("ms") },
		{ "bitmap-sectors-per-bit",'\0', POPT_ARG_INT,&opt_bitmap_sectors_per_bit, 0, N_("Number of 512-byte sectors per bit (bitmap mode)."), NULL },
		{ "bitmap-flush-time",  '\0', POPT_ARG_INT,  &opt_bitmap_flush_time,  0, N_("Bitmap mode flush time"), N_("ms") },
		{ "tag-size",            't', POPT_ARG_INT,  &opt_tag_size,           0, N_("Tag size (per-sector)"), N_("bytes") },
		{ "sector-size",         's', POPT_ARG_INT,  &opt_sector_size,        0, N_("Sector size"), N_("bytes") },
		{ "buffer-sectors",     '\0', POPT_ARG_INT,  &opt_buffer_sectors,     0, N_("Buffers size"), N_("SECTORS") },

		{ "integrity",                  'I', POPT_ARG_STRING, &opt_integrity,                 0, N_("Data integrity algorithm"), NULL },
		{ "integrity-key-size",        '\0', POPT_ARG_INT,    &opt_integrity_key_size,        0, N_("The size of the data integrity key"), N_("BITS") },
		{ "integrity-key-file",        '\0', POPT_ARG_STRING, &opt_integrity_key_file,        0, N_("Read the integrity key from a file"), NULL },

		{ "journal-integrity",         '\0', POPT_ARG_STRING, &opt_journal_integrity,         0, N_("Journal integrity algorithm"), NULL },
		{ "journal-integrity-key-size",'\0', POPT_ARG_INT,    &opt_journal_integrity_key_size,0, N_("The size of the journal integrity key"), N_("BITS") },
		{ "journal-integrity-key-file",'\0', POPT_ARG_STRING, &opt_journal_integrity_key_file,0, N_("Read the journal integrity key from a file"), NULL },

		{ "journal-crypt",             '\0', POPT_ARG_STRING, &opt_journal_crypt,             0, N_("Journal encryption algorithm"), NULL },
		{ "journal-crypt-key-size",    '\0', POPT_ARG_INT,    &opt_journal_crypt_key_size,    0, N_("The size of the journal encryption key"), N_("BITS") },
		{ "journal-crypt-key-file",    '\0', POPT_ARG_STRING, &opt_journal_crypt_key_file,    0, N_("Read the journal encryption key from a file"), NULL },

		{ "integrity-no-journal",       'D', POPT_ARG_NONE,  &opt_integrity_nojournal, 0, N_("Disable journal for integrity device"), NULL },
		{ "integrity-recovery-mode",    'R', POPT_ARG_NONE,  &opt_integrity_recovery,  0, N_("Recovery mode (no journal, no tag checking)"), NULL },
		{ "integrity-bitmap-mode",      'B', POPT_ARG_NONE,  &opt_integrity_bitmap, 0, N_("Use bitmap to track changes and disable journal for integrity device"), NULL },
		{ "integrity-recalculate",     '\0', POPT_ARG_NONE,  &opt_integrity_recalculate,  0, N_("Recalculate initial tags automatically."), NULL },
		{ "integrity-legacy-padding",  '\0', POPT_ARG_NONE,  &opt_integrity_legacy_padding, 0, N_("Use inefficient legacy padding (old kernels)"), NULL },

		{ "allow-discards",            '\0', POPT_ARG_NONE,  &opt_allow_discards, 0, N_("Allow discards (aka TRIM) requests for device"), NULL },
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

	popt_context = poptGetContext("integrity", argc, argv, popt_options, 0);
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
		snprintf(buf, 128,_("%s: requires %s as arguments"), action->type, action->arg_desc);
		usage(popt_context, EXIT_FAILURE, buf,
		      poptGetInvocationName(popt_context));
	}

	if (opt_integrity_recalculate && strcmp(aname, "open"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --integrity-recalculate can be used only for open action."),
		      poptGetInvocationName(popt_context));

	if (opt_allow_discards && strcmp(aname, "open"))
		usage(popt_context, EXIT_FAILURE,
		      _("Option --allow-discards is allowed only for open operation."),
		      poptGetInvocationName(popt_context));

	if (opt_interleave_sectors < 0 || opt_journal_watermark < 0 ||
	    opt_journal_commit_time < 0 || opt_tag_size < 0 ||
	    opt_sector_size < 0 || opt_buffer_sectors < 0 ||
	    opt_integrity_key_size < 0 || opt_journal_integrity_key_size < 0 ||
	    opt_journal_crypt_key_size < 0 || opt_bitmap_flush_time < 0 || opt_bitmap_sectors_per_bit < 0)
                usage(popt_context, EXIT_FAILURE,
                      _("Negative number for option not permitted."),
                      poptGetInvocationName(popt_context));

	if (strcmp(aname, "format") && (opt_journal_size_str || opt_interleave_sectors ||
		opt_sector_size || opt_tag_size || opt_no_wipe ))
		usage(popt_context, EXIT_FAILURE,
		      _("Options --journal-size, --interleave-sectors, --sector-size, --tag-size"
		        " and --no-wipe can be used only for format action."),
		      poptGetInvocationName(popt_context));

	if (opt_journal_size_str &&
	    tools_string_to_size(NULL, opt_journal_size_str, &opt_journal_size))
		usage(popt_context, EXIT_FAILURE, _("Invalid journal size specification."),
		      poptGetInvocationName(popt_context));

	if ((opt_integrity_key_file && !opt_integrity_key_size) ||
	   (!opt_integrity_key_file && opt_integrity_key_size))
		usage(popt_context, EXIT_FAILURE, _("Both key file and key size options must be specified."),
		      poptGetInvocationName(popt_context));
	if (!opt_integrity && opt_integrity_key_file)
		usage(popt_context, EXIT_FAILURE, _("Integrity algorithm must be specified if integrity key is used."),
		      poptGetInvocationName(popt_context));

	if ((opt_journal_integrity_key_file && !opt_journal_integrity_key_size) ||
	   (!opt_journal_integrity_key_file && opt_journal_integrity_key_size))
		usage(popt_context, EXIT_FAILURE, _("Both journal integrity key file and key size options must be specified."),
		      poptGetInvocationName(popt_context));
	if (!opt_journal_integrity && opt_journal_integrity_key_file)
		usage(popt_context, EXIT_FAILURE, _("Journal integrity algorithm must be specified if journal integrity key is used."),
		      poptGetInvocationName(popt_context));

	if ((opt_journal_crypt_key_file && !opt_journal_crypt_key_size) ||
	   (!opt_journal_crypt_key_file && opt_journal_crypt_key_size))
		usage(popt_context, EXIT_FAILURE, _("Both journal encryption key file and key size options must be specified."),
		      poptGetInvocationName(popt_context));
	if (!opt_journal_crypt && opt_journal_crypt_key_file)
		usage(popt_context, EXIT_FAILURE, _("Journal encryption algorithm must be specified if journal encryption key is used."),
		      poptGetInvocationName(popt_context));

	if (opt_integrity_recovery && opt_integrity_bitmap)
		usage(popt_context, EXIT_FAILURE, _("Recovery and bitmap mode options are mutually exclusive."),
		      poptGetInvocationName(popt_context));

	if (opt_integrity_bitmap && (opt_journal_integrity_key_file || opt_journal_crypt || opt_journal_watermark || opt_journal_commit_time))
		usage(popt_context, EXIT_FAILURE, _("Journal options cannot be used in bitmap mode."),
		      poptGetInvocationName(popt_context));

	if (!opt_integrity_bitmap && (opt_bitmap_flush_time || opt_bitmap_sectors_per_bit))
		usage(popt_context, EXIT_FAILURE, _("Bitmap options can be used only in bitmap mode."),
		      poptGetInvocationName(popt_context));

	if (opt_debug) {
		opt_verbose = 1;
		crypt_set_debug_level(-1);
		dbg_version_and_cmd(argc, argv);
	}

	r = run_action(action);
	poptFreeContext(popt_context);
	return r;
}
