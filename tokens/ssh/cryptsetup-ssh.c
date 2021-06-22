/*
 * Example of LUKS2 token storing third party metadata (EXPERIMENTAL EXAMPLE)
 *
 * Copyright (C) 2016-2021 Milan Broz <gmazyland@gmail.com>
 * Copyright (C) 2021 Vojtech Trefny
 *
 * Use:
 *  - generate ssh example token
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <argp.h>
#include <json-c/json.h>
#include "libcryptsetup.h"

#define TOKEN_NAME "ssh"

#define l_err(cd, x...) crypt_logf(cd, CRYPT_LOG_ERROR, x)
#define l_dbg(cd, x...) crypt_logf(cd, CRYPT_LOG_DEBUG, x)

#define OPT_SSH_SERVER  1
#define OPT_SSH_USER	2
#define OPT_SSH_PATH	3
#define OPT_KEY_PATH	4
#define OPT_DEBUG	5
#define OPT_DEBUG_JSON	6

static int token_add(
		const char *device,
		const char *server,
		const char *user,
		const char *path,
		const char *keypath)

{
	struct crypt_device *cd;
	json_object *jobj = NULL;
	json_object *jobj_keyslots = NULL;
	const char *string_token;
	int r, token;

	r = crypt_init(&cd, device);
	if (r)
		return r;

	r = crypt_load(cd, CRYPT_LUKS2, NULL);
	if (r)
		goto out;

	r = -EINVAL;
	jobj = json_object_new_object();
	if (!jobj)
		goto out;

	/* type is mandatory field in all tokens and must match handler name member */
	json_object_object_add(jobj, "type", json_object_new_string(TOKEN_NAME));

	jobj_keyslots = json_object_new_array();

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
		l_err(cd, "Failed to write ssh token json.");
		goto out;
	}

	token = r;
	r = crypt_token_assign_keyslot(cd, token, CRYPT_ANY_SLOT);
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

static char doc[] = "Experimental cryptsetup plugin for unlocking LUKS2 devices with token connected " \
		    "to an SSH server\v" \
		    "This plugin currently allows only adding a token to an existing key slot.\n\n" \
		    "Specified SSH server must contain a key file on the specified path with " \
		    "a passphrase for an existing key slot on the device.\n" \
		    "Provided credentials will be used by cryptsetup to get the password when " \
		    "opening the device using the token.\n\n" \
		    "Note: The information provided when adding the token (SSH server address, user and paths) " \
		    "will be stored in the LUKS2 header in plaintext.";

static char args_doc[] = "<action> <device>";

static struct argp_option options[] = {
	{0,		0,		0,	  0, "Options for the 'add' action:" },
	{"ssh-server",	OPT_SSH_SERVER, "STRING", 0, "IP address/URL of the remote server for this token" },
	{"ssh-user",	OPT_SSH_USER, 	"STRING", 0, "Username used for the remote server" },
	{"ssh-path",	OPT_SSH_PATH,	"STRING", 0, "Path to the key file on the remote server"},
	{"ssh-keypath",	OPT_KEY_PATH, 	"STRING", 0, "Path to the SSH key for connecting to the remote server" },
	{0,		0,		0,	  0, "Generic options:" },
	{"verbose",	'v',		0,	  0, "Shows more detailed error messages"},
	{"debug",	OPT_DEBUG,	0,	  0, "Show debug messages"},
	{"debug-json",  OPT_DEBUG_JSON, 0,	  0, "Show debug messages including JSON metadata"},
	{ NULL,		0, 		0, 0, NULL }
};

struct arguments {
	char *device;
	char *action;
	char *ssh_server;
	char *ssh_user;
	char *ssh_path;
	char *ssh_keypath;
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


void _log(int level, const char *msg, void *usrptr)
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

int main(int argc, char *argv[])
{
	int ret = 0;
	struct arguments arguments = { 0 };

	ret = argp_parse (&argp, argc, argv, 0, 0, &arguments);
	if (ret != 0) {
		printf("Failed to parse arguments.\n");
		return EXIT_FAILURE;
	}

	crypt_set_log_callback(NULL, _log, &arguments);
	if (arguments.debug)
		crypt_set_debug_level(CRYPT_DEBUG_ALL);
	if (arguments.debug_json)
		crypt_set_debug_level(CRYPT_DEBUG_JSON);

	if (arguments.action == NULL) {
		printf("An action must be specified\n");
		return EXIT_FAILURE;
	}

	if (strcmp("add", arguments.action) == 0) {
		if (!arguments.device) {
			printf("Device must be specified for '%s' action.\n", arguments.action);
			return EXIT_FAILURE;
		}

		if (!arguments.ssh_server) {
			printf("SSH server must be specified for '%s' action.\n", arguments.action);
			return EXIT_FAILURE;
		}

		if (!arguments.ssh_user) {
			printf("SSH user must be specified for '%s' action.\n", arguments.action);
			return EXIT_FAILURE;
		}

		if (!arguments.ssh_path) {
			printf("SSH path must be specified for '%s' action.\n", arguments.action);
			return EXIT_FAILURE;
		}

		if (!arguments.ssh_keypath) {
			printf("SSH key path must be specified for '%s' action.\n", arguments.action);
			return EXIT_FAILURE;
		}

		return token_add(arguments.device,
				 arguments.ssh_server,
				 arguments.ssh_user,
				 arguments.ssh_path,
				 arguments.ssh_keypath);
	} else {
		printf("Only 'add' action is currently supported by this plugin.\n");
		return EXIT_FAILURE;
	}
}
