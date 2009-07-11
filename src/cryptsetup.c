#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <libcryptsetup.h>
#include <popt.h>

#include "../config.h"

#include "cryptsetup.h"

static int opt_verbose = 1;
static char *opt_cipher = NULL;
static char *opt_hash = DEFAULT_HASH;
static int opt_verify_passphrase = 0;
static char *opt_key_file = NULL;
static unsigned int opt_key_size = 0;
static int opt_key_slot = -1;
static uint64_t opt_size = 0;
static uint64_t opt_offset = 0;
static uint64_t opt_skip = 0;
static int opt_readonly = 0;
static int opt_iteration_time = 1000;
static int opt_batch_mode = 0;
static int opt_version_mode = 0;
static int opt_timeout = 0;
static int opt_tries = 3;
static int opt_align_payload = 0;
static int opt_non_exclusive = 0;

static const char **action_argv;
static int action_argc;

static int action_create(int arg);
static int action_remove(int arg);
static int action_resize(int arg);
static int action_status(int arg);
static int action_luksFormat(int arg);
static int action_luksOpen(int arg);
static int action_luksAddKey(int arg);
static int action_luksDelKey(int arg);
static int action_luksKillSlot(int arg);
static int action_luksRemoveKey(int arg);
static int action_isLuks(int arg);
static int action_luksUUID(int arg);
static int action_luksDump(int arg);

static struct action_type {
	const char *type;
 	int (*handler)(int);
	int arg;
	int required_action_argc;
	const char *arg_desc;
	const char *desc;
} action_types[] = {
	{ "create",	action_create, 0, 2, N_("<name> <device>"), N_("create device") },
	{ "remove",	action_remove, 0, 1, N_("<name>"), N_("remove device") },
	{ "resize",	action_resize, 0, 1, N_("<name>"), N_("resize active device") },
	{ "status",	action_status, 0, 1, N_("<name>"), N_("show device status") },
	{ "luksFormat",	action_luksFormat, 0, 1, N_("<device> [<new key file>]"), N_("formats a LUKS device") },
	{ "luksOpen",	action_luksOpen, 0, 2, N_("<device> <name> "), N_("open LUKS device as mapping <name>") },
	{ "luksAddKey",	action_luksAddKey, 0, 1, N_("<device> [<new key file>]"), N_("add key to LUKS device") },
	{ "luksRemoveKey", action_luksRemoveKey, 0, 1, N_("<device> [<key file>]"), N_("removes supplied key or key file from LUKS device") },
	{ "luksKillSlot",  action_luksKillSlot, 0, 2, N_("<device> <key slot>"), N_("wipes key with number <key slot> from LUKS device") },
	{ "luksUUID",	action_luksUUID, 0, 1, N_("<device>"), N_("print UUID of LUKS device") },
	{ "isLuks",	action_isLuks, 0, 1, N_("<device>"), N_("tests <device> for LUKS partition header") },
	{ "luksClose",	action_remove, 0, 1, N_("<name>"), N_("remove LUKS mapping") },
	{ "luksDump",	action_luksDump, 0, 1, N_("<device>"), N_("dump LUKS partition information") },
	{ "luksDelKey",  action_luksDelKey, 0, 2, N_("<device> <key slot>"), N_("identical to luksKillSlot - DEPRECATED - see man page") },
	{ "reload",	action_create, 1, 2, N_("<name> <device>"), N_("modify active device - DEPRECATED - see man page") },
	{ NULL, NULL, 0, 0, NULL }
};

/* Interface Callbacks */
static int yesDialog(char *msg)
{
	int r = 0;
	if(isatty(0) && !opt_batch_mode) {
		char *answer=NULL;
	        size_t size=0;
		fprintf(stderr,"\nWARNING!\n========\n");
		fprintf(stderr,"%s\n\nAre you sure? (Type uppercase yes): ",msg);
		if(getline(&answer,&size,stdin) == -1)
			return 0;
		if(strcmp(answer,"YES\n") == 0)
			r = 1;
		free(answer);
	} else
		r = 1;
	return r;
}

static void cmdLineLog(int class, char *msg) {
    switch(class) {

    case CRYPT_LOG_NORMAL:
            fputs(msg, stdout);
            break;
    case CRYPT_LOG_ERROR:
            fputs(msg, stderr);
            break;
    default:
            fprintf(stderr, "Internal error on logging class for msg: %s", msg);
            break;
    }
}

static struct interface_callbacks cmd_icb = {
        .yesDialog = yesDialog,
        .log = cmdLineLog,
};

/* End ICBs */

static void show_status(int errcode)
{
	char error[256];

	if(!errcode) {
                fprintf(stderr, _("Command successful.\n"));
                return;
	}

	crypt_get_error(error, sizeof(error));
	if (!opt_verbose) {
		char *error_ = strerror_r(errcode, error, sizeof(error));
		if (error_ != error) {
			strncpy(error, error_, sizeof(error));
			error[sizeof error - 1] = '\0';
		}
	}

	fprintf(stderr, _("Command failed"));
	if (*error)
		fprintf(stderr, ": %s\n", error);
	else
		fputs(".\n", stderr);
	return;
}

static int action_create(int reload)
{
	struct crypt_options options = {
		.name = action_argv[0],
		.device = action_argv[1],
		.cipher = opt_cipher?opt_cipher:DEFAULT_CIPHER,
		.hash = opt_hash,
		.key_file = opt_key_file,
		.key_size = ((opt_key_size)?opt_key_size:DEFAULT_KEY_SIZE)/8,
		.key_slot = opt_key_slot,
		.passphrase_fd = 0,	/* stdin */
		.flags = 0,
		.size = opt_size,
		.offset = opt_offset,
		.skip = opt_skip,
		.timeout = opt_timeout,
		.tries = opt_tries,
		.icb = &cmd_icb,
	};
	int r;

        if(reload) 
                fprintf(stderr, _("The reload action is deprecated. Please use \"dmsetup reload\" in case you really need this functionality.\nWARNING: do not use reload to touch LUKS devices. If that is the case, hit Ctrl-C now.\n"));

	if (options.hash && strcmp(options.hash, "plain") == 0)
		options.hash = NULL;
	if (opt_verify_passphrase)
		options.flags |= CRYPT_FLAG_VERIFY;
	if (opt_readonly)
		options.flags |= CRYPT_FLAG_READONLY;

	if (reload)
		r = crypt_update_device(&options);
	else
		r = crypt_create_device(&options);
	if (r < 0)
		show_status(-r);
	return r;
}

static int action_remove(int arg)
{
	struct crypt_options options = {
		.name = action_argv[0],
		.icb = &cmd_icb,
	};
	int r;

	r = crypt_remove_device(&options);
	if (r < 0)
		show_status(-r);
	return r;
}

static int action_resize(int arg)
{
	struct crypt_options options = {
		.name = action_argv[0],
		.size = opt_size,
		.icb = &cmd_icb,
	};
	int r;

	r = crypt_resize_device(&options);
	if (r < 0)
		show_status(-r);
	return r;
}

static int action_status(int arg)
{
	struct crypt_options options = {
		.name = action_argv[0],
		.icb = &cmd_icb,
	};
	int r;

	r = crypt_query_device(&options);
	
	if (r < 0) {
		/* error */
		show_status(-r);
	} else if (r == 0) {
		/* inactive */
		printf("%s/%s is inactive.\n", crypt_get_dir(), options.name);
		r = 1;
	} else {
		/* active */
		printf("%s/%s is active:\n", crypt_get_dir(), options.name);
		printf("  cipher:  %s\n", options.cipher);
		printf("  keysize: %d bits\n", options.key_size * 8);
		printf("  device:  %s\n", options.device);
		printf("  offset:  %" PRIu64 " sectors\n", options.offset);
		printf("  size:    %" PRIu64 " sectors\n", options.size);
		if (options.skip)
			printf("  skipped: %" PRIu64 " sectors\n", options.skip);
		printf("  mode:    %s\n", (options.flags & CRYPT_FLAG_READONLY)
		                           ? "readonly" : "read/write");
		crypt_put_options(&options);
		r = 0;
	}
	return r;
}

static int action_luksFormat(int arg)
{
	struct crypt_options options = {
		.key_size = (opt_key_size != 0 ? opt_key_size : DEFAULT_LUKS_KEY_SIZE) / 8,
		.key_slot = opt_key_slot,
		.device = action_argv[0],
		.cipher = opt_cipher?opt_cipher:DEFAULT_LUKS_CIPHER,
		.new_key_file = action_argc > 1 ? action_argv[1] : NULL,
		.flags = opt_verify_passphrase ? CRYPT_FLAG_VERIFY : (!opt_batch_mode?CRYPT_FLAG_VERIFY_IF_POSSIBLE :  0),
		.iteration_time = opt_iteration_time,
		.timeout = opt_timeout,
		.align_payload = opt_align_payload,
		.icb = &cmd_icb,
	};

	int r = 0; char *msg = NULL;

	/* Avoid overwriting possibly wrong part of device than user requested by rejecting these options */
	if (opt_offset || opt_skip) {
		fprintf(stderr,"Options --offset and --skip are not supported for luksFormat.\n"); 
		return -EINVAL;
	}

	if(asprintf(&msg, _("This will overwrite data on %s irrevocably."), options.device) == -1) {
		fputs(_("memory allocation error in action_luksFormat"), stderr);
	} else {
		r = yesDialog(msg) ? crypt_luksFormat(&options) : -EINVAL;
		free(msg);
		show_status(-r);
	}
	return r;
}

static int action_luksOpen(int arg)
{
	struct crypt_options options = {
		.name = action_argv[1],
		.device = action_argv[0],
		.key_file = opt_key_file,
		.timeout = opt_timeout,
		.tries = opt_tries,
		.icb = &cmd_icb,
	};
	int r; 

	opt_verbose = 1;
	options.flags = 0;
	if (opt_readonly)
		options.flags |= CRYPT_FLAG_READONLY;
	if (opt_non_exclusive)
		options.flags |= CRYPT_FLAG_NON_EXCLUSIVE_ACCESS;
	r = crypt_luksOpen(&options);
	show_status(-r);
	return r;
}

static int action_luksDelKey(int arg)
{
    fprintf(stderr,"luksDelKey is a deprecated action name.\nPlease use luksKillSlot.\n"); 
    return action_luksKillSlot(arg);
}

static int action_luksKillSlot(int arg)
{
	struct crypt_options options = {
		.device = action_argv[0],
		.key_slot = atoi(action_argv[1]),
		.key_file = opt_key_file,
		.timeout = opt_timeout,
		.flags = !opt_batch_mode?CRYPT_FLAG_VERIFY_ON_DELKEY : 0,
		.icb = &cmd_icb,
	};
	int r; 

	opt_verbose = 1;
	r = crypt_luksKillSlot(&options);
	show_status(-r);
	return r;
}

static int action_luksRemoveKey(int arg)
{
	struct crypt_options options = {
		.device = action_argv[0],
		.new_key_file = action_argc>1?action_argv[1]:NULL,
		.key_file = opt_key_file,
		.timeout = opt_timeout,
		.flags = !opt_batch_mode?CRYPT_FLAG_VERIFY_ON_DELKEY : 0,
		.icb = &cmd_icb,
	};
	int r; 

	opt_verbose = 1;
	r = crypt_luksRemoveKey(&options);
	show_status(-r);
	return r;
}

static int action_luksAddKey(int arg)
{
	struct crypt_options options = {
		.device = action_argv[0],
		.new_key_file = action_argc>1?action_argv[1]:NULL,
		.key_file = opt_key_file,
		.key_slot = opt_key_slot,
		.flags = opt_verify_passphrase ? CRYPT_FLAG_VERIFY : (!opt_batch_mode?CRYPT_FLAG_VERIFY_IF_POSSIBLE : 0),
		.iteration_time = opt_iteration_time,
		.timeout = opt_timeout,
		.icb = &cmd_icb,
	};
	int r; 

	opt_verbose = 1;
	r = crypt_luksAddKey(&options);
	show_status(-r);
	return r;
}

static int action_isLuks(int arg)
{
	struct crypt_options options = {
		.device = action_argv[0],
		.icb = &cmd_icb,
	};
	return crypt_isLuks(&options);
}

static int action_luksUUID(int arg)
{
	struct crypt_options options = {
		.device = action_argv[0],
		.icb = &cmd_icb,
	};
	int r;

	r = crypt_luksUUID(&options);
	if (r < 0)
		show_status(-r);
	return r;
}

static int action_luksDump(int arg)
{
	struct crypt_options options = {
		.device = action_argv[0],
		.icb = &cmd_icb,
	};
	int r; 

	r = crypt_luksDump(&options);
	if (r < 0)
		show_status(-r);
	return r;
}

static void usage(poptContext popt_context, int exitcode,
                  const char *error, const char *more)
{
	poptPrintUsage(popt_context, stderr, 0);
	if (error)
		fprintf(stderr, "%s: %s\n", more, error);
	exit(exitcode);
}

static void help(poptContext popt_context, enum poptCallbackReason reason,
                 struct poptOption *key, const char * arg, void *data)
{
	if (key->shortName == '?') {
		struct action_type *action;

		fprintf(stdout, "%s\n",PACKAGE_STRING);

		poptPrintHelp(popt_context, stdout, 0);

		printf(_("\n"
			 "<action> is one of:\n"));

		for(action = action_types; action->type; action++)
			printf("\t%s %s - %s\n", action->type, _(action->arg_desc), _(action->desc));
		
		printf(_("\n"
			 "<name> is the device to create under %s\n"
			 "<device> is the encrypted device\n"
			 "<key slot> is the LUKS key slot number to modify\n"
			 "<key file> optional key file for the new key for luksAddKey action\n"),
			crypt_get_dir());
		exit(0);
	} else
		usage(popt_context, 0, NULL, NULL);
}                 

int main(int argc, char **argv)
{
	static char *popt_tmp;
	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		POPT_TABLEEND
	};
	static struct poptOption popt_options[] = {
		{ NULL,                '\0', POPT_ARG_INCLUDE_TABLE,                      popt_help_options,      0, N_("Help options:"),                                                   NULL },
		{ "verbose",           'v',  POPT_ARG_NONE,                               &opt_verbose,           0, N_("Shows more detailed error messages"),                              NULL },
		{ "cipher",            'c',  POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &opt_cipher,            0, N_("The cipher used to encrypt the disk (see /proc/crypto)"),          NULL },
		{ "hash",              'h',  POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &opt_hash,              0, N_("The hash used to create the encryption key from the passphrase"),  NULL },
		{ "verify-passphrase", 'y',  POPT_ARG_NONE,                               &opt_verify_passphrase, 0, N_("Verifies the passphrase by asking for it twice"),                  NULL },
		{ "key-file",          'd',  POPT_ARG_STRING,                             &opt_key_file,          0, N_("Read the key from a file (can be /dev/random)"),                   NULL },
		{ "key-size",          's',  POPT_ARG_INT    | POPT_ARGFLAG_SHOW_DEFAULT, &opt_key_size,          0, N_("The size of the encryption key"),                                  N_("BITS") },
		{ "key-slot",          'S',  POPT_ARG_INT,                                &opt_key_slot,          0, N_("Slot number for new key (default is first free)"),      NULL },
		{ "size",              'b',  POPT_ARG_STRING,                             &popt_tmp,              1, N_("The size of the device"),                                          N_("SECTORS") },
		{ "offset",            'o',  POPT_ARG_STRING,                             &popt_tmp,              2, N_("The start offset in the backend device"),                          N_("SECTORS") },
		{ "skip",              'p',  POPT_ARG_STRING,                             &popt_tmp,              3, N_("How many sectors of the encrypted data to skip at the beginning"), N_("SECTORS") },
		{ "readonly",          'r',  POPT_ARG_NONE,                               &opt_readonly,          0, N_("Create a readonly mapping"),                                       NULL },
		{ "iter-time",         'i',  POPT_ARG_INT,                                &opt_iteration_time,    0, N_("PBKDF2 iteration time for LUKS (in ms)"),
		  N_("msecs") },
		{ "batch-mode",        'q',  POPT_ARG_NONE,                               &opt_batch_mode,        0, N_("Do not ask for confirmation"),                                     NULL },
		{ "version",        '\0',  POPT_ARG_NONE,                                 &opt_version_mode,        0, N_("Print package version"),                                     NULL },
 		{ "timeout",           't',  POPT_ARG_INT,                                &opt_timeout,           0, N_("Timeout for interactive passphrase prompt (in seconds)"),          N_("secs") },
  		{ "tries",             'T',  POPT_ARG_INT,                                &opt_tries,             0, N_("How often the input of the passphrase can be retried"),            NULL },
 		{ "align-payload",     '\0',  POPT_ARG_INT,                               &opt_align_payload,     0, N_("Align payload at <n> sector boundaries - for luksFormat"),         N_("SECTORS") },
 		{ "non-exclusive",     '\0',  POPT_ARG_NONE,                              &opt_non_exclusive,     0, N_("Allows non-exclusive access for luksOpen, WARNING see manpage."),        NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;
	struct action_type *action;
	char *aname;
	int r;
	const char *null_action_argv[] = {NULL};

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext(PACKAGE, argc, (const char **)argv,
	                              popt_options, 0);
	poptSetOtherOptionHelp(popt_context,
	                       N_("[OPTION...] <action> <action-specific>]"));

	while((r = poptGetNextOpt(popt_context)) > 0) {
		unsigned long long ull_value;
		char *endp;

		ull_value = strtoull(popt_tmp, &endp, 0);
		if (*endp || !*popt_tmp)
			r = POPT_ERROR_BADNUMBER;

		switch(r) {
			case 1:
				opt_size = ull_value;
				break;
			case 2:
				opt_offset = ull_value;
				break;
			case 3:
				opt_skip = ull_value;
				break;
		}

		if (r < 0)
			break;
	}

	if (r < -1)
		usage(popt_context, 1, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));
	if (opt_version_mode) {
	        printf("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
		exit(0);
	}
	 
	if (opt_key_size % 8)
		usage(popt_context, 1,
		      _("Key size must be a multiple of 8 bits"),
		      poptGetInvocationName(popt_context));
	
	if (!(aname = (char *)poptGetArg(popt_context)))
		usage(popt_context, 1, _("Argument <action> missing."),
		      poptGetInvocationName(popt_context));
	for(action = action_types; action->type; action++)
		if (strcmp(action->type, aname) == 0)
			break;
	if (!action->type)
		usage(popt_context, 1, _("Unknown action."),
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
		usage(popt_context, 1, buf,
		      poptGetInvocationName(popt_context));
	}	
	return action->handler(action->arg);
}

// Local Variables:
// c-basic-offset: 8
// indent-tabs-mode: nil
// End:
