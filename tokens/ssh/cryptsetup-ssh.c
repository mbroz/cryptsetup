// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Example of LUKS2 token storing third party metadata (EXPERIMENTAL EXAMPLE)
 *
 * Copyright (C) 2016-2025 Milan Broz
 * Copyright (C) 2021-2025 Vojtech Trefny
 *
 * Use:
 *  - generate ssh example token
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <argp.h>
#include <json-c/json.h>
#include <termios.h>
#include <stdbool.h>
#include "libcryptsetup.h"
#include "ssh-utils.h"
#include "../src/cryptsetup.h"

#define TOKEN_NAME "ssh"

#define l_err(cd, x...) crypt_logf(cd, CRYPT_LOG_ERROR, x)
#define l_dbg(cd, x...) crypt_logf(cd, CRYPT_LOG_DEBUG, x)

#define OPT_SSH_SERVER  1
#define OPT_SSH_USER	2
#define OPT_SSH_PATH	3
#define OPT_KEY_PATH	4
#define OPT_DEBUG	5
#define OPT_DEBUG_JSON	6
#define OPT_KEY_SLOT	7
#define OPT_TOKENS_PATH	8

void tools_cleanup(void)
{
}


static int token_add(
		const char *device,
		const char *server,
		const char *user,
		const char *path,
		const char *keypath,
		const char *plugin_path,
		int keyslot)

{
	struct crypt_device *cd;
	json_object *jobj = NULL;
	json_object *jobj_keyslots = NULL;
	const char *string_token;
	int r, token;

	if (plugin_path) {
		r = crypt_token_set_external_path(plugin_path);
		if (r < 0)
			return r;
	}

	r = crypt_init(&cd, device);
	if (r)
		return r;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r) {
		l_err(cd, _("Device %s is not a valid LUKS device."), device);
		goto out;
	}

	jobj = json_object_new_object();
	if (!jobj) {
		r = -ENOMEM;
		goto out;
	}

	/* type is mandatory field in all tokens and must match handler name member */
	json_object_object_add(jobj, "type", json_object_new_string(TOKEN_NAME));

	jobj_keyslots = json_object_new_array();
	if (!jobj_keyslots) {
		r = -ENOMEM;
		goto out;
	}

	/* mandatory array field (may be empty and assigned later */
	json_object_object_add(jobj, "keyslots", jobj_keyslots);

	/* custom metadata */
	json_object_object_add(jobj, "ssh_server", json_object_new_string(server));
	json_object_object_add(jobj, "ssh_user", json_object_new_string(user));
	json_object_object_add(jobj, "ssh_path", json_object_new_string(path));
	json_object_object_add(jobj, "ssh_keypath", json_object_new_string(keypath));

	string_token = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PLAIN);
	if (!string_token) {
		r = -EINVAL;
		goto out;
	}

	l_dbg(cd, "Token JSON: %s", string_token);

	r = crypt_token_json_set(cd, CRYPT_ANY_TOKEN, string_token);
	if (r < 0) {
		l_err(cd, _("Failed to write ssh token json."));
		goto out;
	}

	token = r;
	r = crypt_token_assign_keyslot(cd, token, keyslot);
	if (r != token) {
		crypt_token_json_set(cd, token, NULL);
		r = -EINVAL;
	}
out:
	json_object_put(jobj);
	crypt_free(cd);
	return r;
}

const char *argp_program_version = "cryptsetup-ssh " PACKAGE_VERSION;

static char doc[] = N_("Experimental cryptsetup plugin for unlocking LUKS2 devices with token connected " \
		       "to an SSH server\v" \
		       "This plugin currently allows only adding a token to an existing key slot.\n\n" \
		       "Specified SSH server must contain a key file on the specified path with " \
		       "a passphrase for an existing key slot on the device.\n" \
		       "Provided credentials will be used by cryptsetup to get the password when " \
		       "opening the device using the token.\n\n" \
		       "Note: The information provided when adding the token (SSH server address, user and paths) " \
		       "will be stored in the LUKS2 header in plaintext.");

static char args_doc[] = N_("<action> <device>");

static struct argp_option options[] = {
	{0,		0,		0,	  0, N_("Options for the 'add' action:")},
	{"ssh-server",	OPT_SSH_SERVER, "STRING", 0, N_("IP address/URL of the remote server for this token")},
	{"ssh-user",	OPT_SSH_USER, 	"STRING", 0, N_("Username used for the remote server")},
	{"ssh-path",	OPT_SSH_PATH,	"STRING", 0, N_("Path to the key file on the remote server")},
	{"ssh-keypath",	OPT_KEY_PATH, 	"STRING", 0, N_("Path to the SSH key for connecting to the remote server")},
	{"external-tokens-path",
			OPT_TOKENS_PATH,"STRING", 0, N_("Path to directory containinig libcryptsetup external tokens")},
	{"key-slot",	OPT_KEY_SLOT,	"NUM",	  0, N_("Keyslot to assign the token to. If not specified, token will "\
						        "be assigned to the first keyslot matching provided passphrase.")},
	{0,		0,		0,	  0, N_("Generic options:")},
	{"verbose",	'v',		0,	  0, N_("Shows more detailed error messages")},
	{"debug",	OPT_DEBUG,	0,	  0, N_("Show debug messages")},
	{"debug-json",  OPT_DEBUG_JSON, 0,	  0, N_("Show debug messages including JSON metadata")},
	{ NULL,		0, 		0, 0, NULL }
};

struct arguments {
	char *device;
	char *action;
	char *ssh_server;
	char *ssh_user;
	char *ssh_path;
	char *ssh_keypath;
	char *ssh_plugin_path;
	int keyslot;
	int verbose;
	int debug;
	int debug_json;
};

static error_t
parse_opt (int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;

	switch (key) {
	case OPT_SSH_SERVER:
		arguments->ssh_server = arg;
		break;
	case OPT_SSH_USER:
		arguments->ssh_user = arg;
		break;
	case OPT_SSH_PATH:
		arguments->ssh_path = arg;
		break;
	case OPT_KEY_PATH:
		arguments->ssh_keypath = arg;
		break;
	case OPT_TOKENS_PATH:
		arguments->ssh_plugin_path = arg;
		break;
	case OPT_KEY_SLOT:
		arguments->keyslot = atoi(arg);
		break;
	case 'v':
		arguments->verbose = 1;
		break;
	case OPT_DEBUG:
		arguments->debug = 1;
		break;
	case OPT_DEBUG_JSON:
		arguments->debug = 1;
		arguments->debug_json = 1;
		break;
	case ARGP_KEY_NO_ARGS:
		argp_usage(state);
		break;
	case ARGP_KEY_ARG:
		arguments->action = arg;
		arguments->device = state->argv[state->next];
		state->next = state->argc;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };


static void _log(int level, const char *msg, void *usrptr)
{
	struct arguments *arguments = (struct arguments *)usrptr;

	switch (level) {
	case CRYPT_LOG_NORMAL:
		fprintf(stdout, "%s", msg);
		break;
	case CRYPT_LOG_VERBOSE:
		if (arguments && arguments->verbose)
			fprintf(stdout, "%s", msg);
		break;
	case CRYPT_LOG_ERROR:
		fprintf(stderr, "%s", msg);
		break;
	case CRYPT_LOG_DEBUG_JSON:
		if (arguments && arguments->debug_json)
			fprintf(stdout, "# %s", msg);
		break;
	case CRYPT_LOG_DEBUG:
		if (arguments && arguments->debug)
			fprintf(stdout, "# %s", msg);
		break;
	}
}

static int get_keyslot_for_passphrase(struct arguments *arguments, const char *pin)
{
	int r = 0;
	ssh_key pkey;
	ssh_session ssh;
	char *password = NULL;
	size_t password_len = 0;
	struct crypt_device *cd = NULL;
	char *ssh_pass = NULL;
	size_t key_size = 0;
	char *prompt = NULL;

	r = crypt_init(&cd, arguments->device);
	if (r < 0)
		return r;
	crypt_set_log_callback(cd, &_log, arguments);

	r = ssh_pki_import_privkey_file(arguments->ssh_keypath, pin, NULL, NULL, &pkey);
	if (r != SSH_OK) {
		if (r == SSH_EOF) {
			crypt_log(cd, CRYPT_LOG_ERROR, _("Failed to open and import private key:\n"));
			crypt_free(cd);
			return -EINVAL;
		} else {
			_log(CRYPT_LOG_ERROR, _("Failed to import private key (password protected?).\n"), NULL);
			/* TRANSLATORS: SSH credentials prompt, e.g. "user@server's password: " */
			r = asprintf(&prompt, _("%s@%s's password: "), arguments->ssh_user, arguments->ssh_server);
			if (r < 0) {
				crypt_safe_free(ssh_pass);
				crypt_free(cd);
				return -EINVAL;
			}

			r = tools_get_key(prompt, &ssh_pass, &key_size, 0, 0, NULL, 0, 0, 0, cd);
			if (r < 0) {
				free(prompt);
				crypt_safe_free(ssh_pass);
				crypt_free(cd);
				return -EINVAL;
			}

			/* now try again with the password */
			r = get_keyslot_for_passphrase(arguments, ssh_pass);

			crypt_safe_free(ssh_pass);
			crypt_free(cd);
			free(prompt);

			return r;
		}
	}

	ssh = sshplugin_session_init(cd, arguments->ssh_server, arguments->ssh_user);
	if (!ssh) {
		ssh_key_free(pkey);
		crypt_free(cd);
		return -EINVAL;
	}

	r = sshplugin_public_key_auth(cd, ssh, pkey);
	ssh_key_free(pkey);

	if (r != SSH_AUTH_SUCCESS) {
		crypt_free(cd);
		return r;
	}

	r = sshplugin_download_password(cd, ssh, arguments->ssh_path, &password, &password_len);
	if (r < 0) {
		ssh_disconnect(ssh);
		ssh_free(ssh);
		crypt_free(cd);
		return r;
	}

	ssh_disconnect(ssh);
	ssh_free(ssh);

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r < 0) {
		crypt_safe_memzero(password, password_len);
		free(password);
		crypt_free(cd);
		return r;
	}

	r = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, password, password_len, 0);
	if (r < 0) {
		crypt_safe_memzero(password, password_len);
		free(password);
		crypt_free(cd);
		return r;
	}

	arguments->keyslot = r;

	crypt_safe_memzero(password, password_len);
	free(password);
	crypt_free(cd);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	struct arguments arguments = { 0 };
	arguments.keyslot = CRYPT_ANY_SLOT;

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	ret = argp_parse (&argp, argc, argv, 0, 0, &arguments);
	if (ret != 0) {
		printf(_("Failed to parse arguments.\n"));
		return EXIT_FAILURE;
	}

	crypt_set_log_callback(NULL, _log, &arguments);
	if (arguments.debug)
		crypt_set_debug_level(CRYPT_DEBUG_ALL);
	if (arguments.debug_json)
		crypt_set_debug_level(CRYPT_DEBUG_JSON);

	if (arguments.action == NULL) {
		printf(_("An action must be specified\n"));
		return EXIT_FAILURE;
	}

	if (strcmp("add", arguments.action) == 0) {
		if (!arguments.device) {
			printf(_("Device must be specified for '%s' action.\n"), arguments.action);
			return EXIT_FAILURE;
		}

		if (!arguments.ssh_server) {
			printf(_("SSH server must be specified for '%s' action.\n"), arguments.action);
			return EXIT_FAILURE;
		}

		if (!arguments.ssh_user) {
			printf(_("SSH user must be specified for '%s' action.\n"), arguments.action);
			return EXIT_FAILURE;
		}

		if (!arguments.ssh_path) {
			printf(_("SSH path must be specified for '%s' action.\n"), arguments.action);
			return EXIT_FAILURE;
		}

		if (!arguments.ssh_keypath) {
			printf(_("SSH key path must be specified for '%s' action.\n"), arguments.action);
			return EXIT_FAILURE;
		}

		if (arguments.keyslot == CRYPT_ANY_SLOT) {
			ret = get_keyslot_for_passphrase(&arguments, NULL);
			if (ret != 0) {
				printf(_("Failed open %s using provided credentials.\n"), arguments.device);
				return EXIT_FAILURE;
			}
		}

		ret = token_add(arguments.device,
				arguments.ssh_server,
				arguments.ssh_user,
				arguments.ssh_path,
				arguments.ssh_keypath,
				arguments.ssh_plugin_path,
				arguments.keyslot);
		if (ret < 0)
			return EXIT_FAILURE;
		else
			return EXIT_SUCCESS;
	} else {
		printf(_("Only 'add' action is currently supported by this plugin.\n"));
		return EXIT_FAILURE;
	}
}
