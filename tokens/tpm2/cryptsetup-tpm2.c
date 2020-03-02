/*
 * LUKS - Linux Unified Key Setup v2, TPM type keyslot handler
 *
 * Copyright (C) 2018-2020 Fraunhofer SIT sponsorred by Infineon Technologies AG
 * Copyright (C) 2019-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2019-2020 Daniel Zatovic
 * Copyright (C) 2019-2020 Milan Broz
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

#include "../src/cryptsetup.h"
#include "utils_tpm2.h"

#define PACKAGE_CRYPTSETUP_TPM2 "cryptsetup-tpm2"

#define DEFAULT_PCR_BANK "sha256"
#define DEFAULT_TPM2_SIZE 64
#define DEFAULT_TPM2_SIZE_MAX 512

static uint32_t opt_tpmnv = 0;
static uint32_t opt_tpmpcr = 0;
static uint32_t opt_tpmbanks = 0;
static long int opt_pass_size = DEFAULT_TPM2_SIZE;
static int opt_tpmdaprotect = 0;
static int opt_no_tpm_pin = 0;
static int opt_token = CRYPT_ANY_TOKEN;
static int opt_timeout = 0;

static const char **action_argv;
static int action_argc;

void tools_cleanup(void) {}

static int action_tpm2_open(struct crypt_device *cd)
{
	int r;

	r = crypt_activate_by_token(cd, action_argv[1], opt_token, NULL, 0);

	return r < 0 ? r : 0;
}

static int action_tpm2_dump(struct crypt_device *cd)
{
	return crypt_dump(cd);
}

static int action_tpm2_kill(struct crypt_device *cd)
{
	const char *type;
	int i, r;

	if (!opt_tpmnv && opt_token == CRYPT_ANY_TOKEN) {
		l_err(cd, "Token ID or TPM2 nvindex option must be specified.");
		return -EINVAL;
	}

	if (opt_token == CRYPT_ANY_TOKEN)
		opt_token = tpm2_token_by_nvindex(cd, opt_tpmnv);

	if (opt_token < 0 ||
	    crypt_token_status(cd, opt_token, &type) != CRYPT_TOKEN_EXTERNAL ||
	    strcmp(type, "tpm2")) {
		l_err(cd, "No TPM2 token to destroy.");
		return -EINVAL;
	}

	/* Destroy all keyslots assigned to TPM 2 token */
	for (i = 0; i < crypt_keyslot_max(CRYPT_LUKS2) ; i++) {
		if (!crypt_token_is_assigned(cd, opt_token, i)) {
			r = crypt_keyslot_destroy(cd, i);
			if (r < 0) {
				l_err(cd, "Cannot destroy keyslot %d.", i);
				return r;
			}
		}
	}

	/* Destroy TPM2 NV index and token object itself */
	return tpm2_token_kill(cd, opt_token);
}

static int action_tpm2_add(struct crypt_device *cd)
{
	char *existing_pass = NULL, *tpm_pin = NULL, *random_pass = NULL;
	size_t existing_pass_len, tpm_pin_len = 0;
	int token, r, keyslot = CRYPT_ANY_SLOT;
	bool supports_algs_for_pcrs;
	TSS2_RC tpm_rc;

	if (!opt_tpmbanks) {
		l_err(cd, "PCR banks must be selected.");
		return -EINVAL;
	}

	tpm_rc = tpm2_supports_algs_for_pcrs(NULL, opt_tpmbanks, opt_tpmpcr, &supports_algs_for_pcrs);
	if (tpm_rc != TSS2_RC_SUCCESS) {
		l_err(NULL, "Failed to get PCRS capability from TPM.");
		LOG_TPM_ERR(NULL, tpm_rc);
		return -ECOMM;
	}

	if(!supports_algs_for_pcrs) {
		l_err(NULL, "Your TPM doesn't support selected PCR and banks combination.");
		return -ENOTSUP;
	}

	random_pass = crypt_safe_alloc(opt_pass_size);
	if (!random_pass)
		return -ENOMEM;

	r = tpm_get_random(cd, random_pass, opt_pass_size);
	if (r < 0)
		goto out;

	r = crypt_cli_get_key("Enter existing LUKS2 pasphrase:",
			  &existing_pass, &existing_pass_len,
			  0, 0, NULL, opt_timeout, 0, 0, cd, NULL);
	if (r < 0)
		goto out;

	if (!opt_no_tpm_pin) {
		r = crypt_cli_get_key("Enter new TPM password:",
				  &tpm_pin, &tpm_pin_len,
				  0, 0, NULL, opt_timeout, 1, 0, cd, NULL);
		if (r < 0)
			goto out;
	}

	if (opt_tpmnv == 0) {
		tpm_rc = tpm_nv_find(cd, &opt_tpmnv);
		if (tpm_rc != TSS2_RC_SUCCESS) {
			l_err(cd, "Error while trying to find free NV index.");
			LOG_TPM_ERR(cd, tpm_rc);
			r = -EINVAL;
			goto out;
		}

		if (!opt_tpmnv) {
			l_err(cd, "Error no free TPM NV-Index found.");
			r = -EACCES;
			goto out;
		}
	}

	tpm_rc = tpm_nv_define(cd, opt_tpmnv, tpm_pin, tpm_pin_len, opt_tpmpcr,
			  opt_tpmbanks, opt_tpmdaprotect, NULL, 0, opt_pass_size);
	if (tpm_rc != TSS2_RC_SUCCESS) {
		l_err(cd, "TPM NV-Index definition failed");
		LOG_TPM_ERR(cd, tpm_rc);
		r = -EINVAL;
		goto out;
	}

	tpm_rc = tpm_nv_write(cd, opt_tpmnv, tpm_pin, tpm_pin_len,
			random_pass, opt_pass_size);
	if (tpm_rc != TSS2_RC_SUCCESS) {
		l_err(cd, "TPM NV-Index write error.");
		LOG_TPM_ERR(cd, tpm_rc);
		tpm_nv_undefine(cd, opt_tpmnv);
		r = -EINVAL;
		goto out;
	}

	r = crypt_keyslot_add_by_passphrase(cd, keyslot, existing_pass, existing_pass_len, random_pass, opt_pass_size);
	if (r < 0) {
		if (r == -EPERM)
			l_err(cd, "Wrong LUKS2 passphrase supplied.");
		tpm_nv_undefine(cd, opt_tpmnv);
		goto out;
	}
	keyslot = r;
	l_std(cd, "Using keyslot %d.\n", keyslot);

	r = tpm2_token_add(cd, opt_tpmnv, opt_tpmpcr, opt_tpmbanks, opt_tpmdaprotect, !opt_no_tpm_pin, opt_pass_size);
	if (r < 0) {
		tpm_nv_undefine(cd, opt_tpmnv);
		crypt_keyslot_destroy(cd, keyslot);
		goto out;
	}
	token = r;
	l_std(cd, "Token: %d\n", token);

	r = crypt_token_assign_keyslot(cd, token, keyslot);
	if (r < 0) {
		l_err(cd, "Failed to assign keyslot %d to token %d.", keyslot, token);
		tpm_nv_undefine(cd, opt_tpmnv);
		crypt_keyslot_destroy(cd, keyslot);
		crypt_token_json_set(cd, token, NULL);
	}

	if (r > 0)
		r = 0;
out:
	crypt_safe_free(random_pass);
	crypt_safe_free(existing_pass);
	crypt_safe_free(tpm_pin);

	return r;
}

static int action_tpm2_list(struct crypt_device *cd)
{
	TSS2_RC r;
	TPMS_CAPABILITY_DATA *savedPCRs;
	TPMS_PCR_SELECTION *selection;
	unsigned i, j, k;

	r = getPCRsCapability(cd, &savedPCRs);
	if (r != TSS2_RC_SUCCESS) {
		l_err(cd, "Failed to get PCRS capability from TPM.");
		LOG_TPM_ERR(cd, r);
		return -EINVAL;
	}

	l_std(cd, "Supported PCRs for banks:\n");
	for (i = 0; i <  CRYPT_HASH_ALGS_COUNT; i++) {
		if ((selection = tpm2_get_pcrs_by_alg(savedPCRs, hash_algs[i].crypt_id))) {
			k = 0;
			l_std(cd, "%s:\t", hash_algs[i].name);
			for (j = 0; j < selection->sizeofSelect * 8; j++) {
				if (selection->pcrSelect[i/8] & (1 << i % 8)) {
					l_std(cd, "%s%d", k++ ? ", " : "", j);
				}
			}
			l_std(cd, "\n");
		}
	}

	free(savedPCRs);
	return 0;
}

static struct action_type {
	const char *type;
	int (*handler)(struct crypt_device*);
	int required_action_argc;
	const char *arg_desc;
	const char *desc;
} action_types[] = {
	{ "add",	action_tpm2_add,  1, N_("<data_device>"),N_("add TPM2 token") },
	{ "open",	action_tpm2_open, 2, N_("<data_device> <name>"),N_("open device as <name> using TPM token") },
	{ "kill",	action_tpm2_kill, 1, N_("<data_device> --token-id <id>"),N_("remove specified TPM token and related keyslots") },
	{ "dump",	action_tpm2_dump, 1, N_("<data_device>"),N_("show TPM2 token information") },
	{ "list",	action_tpm2_list, 0, N_("none"),N_("just list supported PCRs for banks") },
	{ NULL, NULL, 0, NULL, NULL }
};

static void help(poptContext popt_context,
		 enum poptCallbackReason reason __attribute__((unused)),
		 struct poptOption *key,
		 const char *arg __attribute__((unused)),
		 void *data __attribute__((unused)))
{
	struct action_type *action;
	unsigned i, n = 0;

	if (key->shortName == '?') {
		log_std("%s %s\n", PACKAGE_CRYPTSETUP_TPM2, PACKAGE_VERSION);
		poptPrintHelp(popt_context, stdout, 0);
		log_std(_("\n"
			 "<action> is one of:\n"));
		for(action = action_types; action->type; action++)
			log_std("\t%s %s - %s\n", action->type, _(action->arg_desc), _(action->desc));
		l_std(NULL, "\nDefault pass-size: %d [bytes]\n", DEFAULT_TPM2_SIZE);
		l_std(NULL, "Default PCRs: (none)\n");
		l_std(NULL, "Default PCR banks: %s\n", DEFAULT_PCR_BANK);

		l_std(NULL, "Possible PCR banks:");
		for (i = 0; i < CRYPT_HASH_ALGS_COUNT; i++) {
			printf("%s %s", n++ ? "," : "", hash_algs[i].name);
		}
		putchar('\n');

		exit(EXIT_SUCCESS);
	} else
		usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

static int run_action(struct action_type *action, struct crypt_device *cd)
{
	int r;

	log_dbg("Running command %s.", action->type);

	r = action->handler(cd);

	show_status(r);
	return translate_errno(r);
}

int main(int argc, const char **argv)
{
	int r = 0;
	struct crypt_device *cd = NULL;
	static const char *null_action_argv[] = {NULL};
	struct action_type *action;
	const char *aname;
	static long int tpmnv = 0;
	static const char *tpmbanks = DEFAULT_PCR_BANK;
	static const char *tpmpcr = NULL;

	static struct poptOption popt_help_options[] = {
		{ NULL,    '\0', POPT_ARG_CALLBACK, help, 0, NULL,                         NULL },
		{ "help",  '?',  POPT_ARG_NONE,     NULL, 0, N_("Show this help message"), NULL },
		{ "usage", '\0', POPT_ARG_NONE,     NULL, 0, N_("Display brief usage"),    NULL },
		POPT_TABLEEND
	};

	static struct poptOption token_popt_options[] = {
		{ NULL,             '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, "Help options:", NULL },
		{ "tpm2-nv",        '\0', POPT_ARG_LONG,   &tpmnv,            0, "Select TPM's NV index", "<0x01800000..0x01BFFFFF>" },
		{ "tpm2-pcr",       '\0', POPT_ARG_STRING, &tpmpcr,       0, "Selection of TPM PCRs", "<pcr>[,<pcr>[,<pcr>[...]]]" },
		{ "tpm2-bank",      '\0', POPT_ARG_STRING, &tpmbanks,     0, "Selection of TPM PCR banks", "<hash1>[,<hash2>[,<hash3>[...]]]" },
		{ "tpm2-daprotect", '\0', POPT_ARG_NONE,   &opt_tpmdaprotect, 0, "Enable TPM dictionary attack protection", NULL},
		{ "tpm2-no-pin",    '\0', POPT_ARG_NONE,   &opt_no_tpm_pin,  0, "Don't PIN protect TPM NV index", NULL},
		{ "tpm2-key-size",  '\0', POPT_ARG_LONG,   &opt_pass_size,    0, "Size of randomly generated key for unlocking keyslot", "<bytes>"},
		{ "token-id",       '\0', POPT_ARG_INT,    &opt_token,        0, "Token number", NULL },
		{ "timeout",        '\0', POPT_ARG_INT,    &opt_timeout,      0, "Timeout for interactive passphrase prompt (in seconds)", "secs" },
		{ "debug",          '\0', POPT_ARG_NONE,   &opt_debug,        0, "Show debug messages", NULL },
		POPT_TABLEEND
	};
	poptContext popt_context;

	crypt_set_log_callback(NULL, tool_log, NULL);

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	popt_context = poptGetContext("cryptsetup_tpm2", argc, argv, token_popt_options, 0);
	poptSetOtherOptionHelp(popt_context, "[OPTION...] <action> <action-specific>");

	while ((r = poptGetNextOpt(popt_context)) > 0) ;
	if (r < -1)
		usage(popt_context, EXIT_FAILURE, poptStrerror(r),
		      poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));

	if (!(aname = poptGetArg(popt_context)))
		usage(popt_context, EXIT_FAILURE, "Argument <action> missing.",
				poptGetInvocationName(popt_context));

	action_argc = 0;
	action_argv = poptGetArgs(popt_context);
	/* Make return values of poptGetArgs more consistent in case of remaining argc = 0 */
	if (!action_argv)
		action_argv = null_action_argv;

	while(action_argv[action_argc] != NULL)
		action_argc++;

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

	opt_tpmnv = (uint32_t)tpmnv;

	if (tpmpcr && tpm2_token_get_pcrs(tpmpcr, &opt_tpmpcr) < 0)
		usage(popt_context, EXIT_FAILURE, "Wrong PCR value.",
		      poptGetInvocationName(popt_context));

	if (tpmbanks && tpm2_token_get_pcrbanks(tpmbanks, &opt_tpmbanks) < 0)
		usage(popt_context, EXIT_FAILURE, "Wrong PCR bank value.",
				poptGetInvocationName(popt_context));

	if (opt_debug) {
		crypt_set_debug_level(CRYPT_DEBUG_ALL);
		dbg_version_and_cmd(argc, argv);
	}

	r = crypt_init(&cd, action_argv[0]);
	if (r < 0) {
		l_err(NULL, "Failed to init device %s.", argv[1]);
		return EXIT_FAILURE;
	}

	r = crypt_token_load(cd, "tpm2");
	if (r < 0) {
		l_err(cd, "Failed to load tpm2 token handler.");
		return EXIT_FAILURE;
	}

	if (strcmp(action->type, "list") != 0)
		r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r < 0) {
		l_err(cd, "Failed to load luks2 device %s.", action_argv[0]);
		r = EXIT_FAILURE;
	} else
		r = run_action(action, cd);

	if (r) {
		l_err(cd, "Action %s FAILED.", action->type);
	} else {
		l_std(cd, "Action %s successful.\n", action->type);
	}

	crypt_free(cd);
	poptFreeContext(popt_context);
	return r;
}
