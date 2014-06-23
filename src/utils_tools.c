/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004, Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2014, Milan Broz
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
#include <signal.h>

int opt_verbose = 0;
int opt_debug = 0;
int opt_batch_mode = 0;

/* interrupt handling */
volatile int quit = 0;
static int signals_blocked = 0;

static void int_handler(int sig __attribute__((__unused__)))
{
	quit++;
}

int tools_signals_blocked(void)
{
	return signals_blocked;
}

void set_int_block(int block)
{
	sigset_t signals_open;

	log_dbg("%slocking interruption on signal.", block ? "B" : "Unb");

	sigemptyset(&signals_open);
	sigaddset(&signals_open, SIGINT);
	sigaddset(&signals_open, SIGTERM);
	sigprocmask(block ? SIG_SETMASK : SIG_UNBLOCK, &signals_open, NULL);
	signals_blocked = block;
	quit = 0;
}

void set_int_handler(int block)
{
	struct sigaction sigaction_open;

	log_dbg("Installing SIGINT/SIGTERM handler.");
	memset(&sigaction_open, 0, sizeof(struct sigaction));
	sigaction_open.sa_handler = int_handler;
	sigaction(SIGINT, &sigaction_open, 0);
	sigaction(SIGTERM, &sigaction_open, 0);
	set_int_block(block);
}

void check_signal(int *r)
{
	if (quit && !*r)
		*r = -EINTR;
}

__attribute__((format(printf, 5, 6)))
void clogger(struct crypt_device *cd, int level, const char *file, int line,
	     const char *format, ...)
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

void tool_log(int level, const char *msg, void *usrptr __attribute__((unused)))
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

void quiet_log(int level, const char *msg, void *usrptr)
{
	if (!opt_verbose && (level == CRYPT_LOG_ERROR || level == CRYPT_LOG_NORMAL))
		level = CRYPT_LOG_VERBOSE;
	tool_log(level, msg, usrptr);
}

int yesDialog(const char *msg, void *usrptr __attribute__((unused)))
{
	char *answer = NULL;
	size_t size = 0;
	int r = 1, block;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	if(isatty(STDIN_FILENO) && !opt_batch_mode) {
		log_std("\nWARNING!\n========\n");
		log_std("%s\n\nAre you sure? (Type uppercase yes): ", msg);
		if(getline(&answer, &size, stdin) == -1) {
			r = 0;
			/* Aborted by signal */
			if (!quit)
				log_err(_("Error reading response from terminal.\n"));
			else
				log_dbg("Query interrupted on signal.");
		} else if(strcmp(answer, "YES\n"))
			r = 0;
	}

	if (block && !quit)
		set_int_block(1);

	free(answer);
	return r;
}

void show_status(int errcode)
{
	char error[256], *error_;

	if(!opt_verbose)
		return;

	if(!errcode) {
		log_std(_("Command successful.\n"));
		return;
	}

	crypt_get_error(error, sizeof(error));

	if (!error[0]) {
		error_ = strerror_r(-errcode, error, sizeof(error));
		if (error_ != error) {
			strncpy(error, error_, sizeof(error));
			error[sizeof(error) - 1] = '\0';
		}
	}

	log_err(_("Command failed with code %i"), -errcode);
	if (*error)
		log_err(": %s\n", error);
	else
		log_err(".\n");
}

const char *uuid_or_device(const char *spec)
{
	static char device[PATH_MAX];
	char s, *ptr;
	int i = 0, uuid_len = 5;

	/* Check if it is correct UUID=<LUKS_UUID> format */
	if (spec && !strncmp(spec, "UUID=", uuid_len)) {
		strcpy(device, "/dev/disk/by-uuid/");
		ptr = &device[strlen(device)];
		i = uuid_len;
		while ((s = spec[i++]) && i < PATH_MAX) {
			if (!isxdigit(s) && s != '-')
				return spec; /* Bail it out */
			if (isalpha(s))
				s = tolower(s);
			*ptr++ = s;
		}
		*ptr = '\0';
		return device;
	}

	return spec;
}

__attribute__ ((noreturn)) void usage(poptContext popt_context,
					     int exitcode, const char *error,
					     const char *more)
{
	poptPrintUsage(popt_context, stderr, 0);
	if (error)
		log_err("%s: %s\n", more, error);
	poptFreeContext(popt_context);
	exit(exitcode);
}

void dbg_version_and_cmd(int argc, const char **argv)
{
	int i;

	log_std("# %s %s processing \"", PACKAGE_NAME, PACKAGE_VERSION);
	for (i = 0; i < argc; i++) {
		if (i)
			log_std(" ");
		log_std("%s", argv[i]);
	}
	log_std("\"\n");
}

/* Translate exit code to simple codes */
int translate_errno(int r)
{
	switch (r) {
	case 0: 	r = EXIT_SUCCESS; break;
	case -EEXIST:
	case -EBUSY:	r = 5; break;
	case -ENOTBLK:
	case -ENODEV:	r = 4; break;
	case -ENOMEM:	r = 3; break;
	case -EPERM:	r = 2; break;
	case -EINVAL:
	case -ENOENT:
	case -ENOSYS:
	default:	r = EXIT_FAILURE;
	}
	return r;
}
