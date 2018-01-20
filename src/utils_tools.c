/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004, Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2018, Milan Broz
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
#include <math.h>
#include <signal.h>

int opt_verbose = 0;
int opt_debug = 0;
int opt_batch_mode = 0;
int opt_progress_frequency = 0;

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
		fflush(stdout);
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
	char *crypt_error;

	if(!opt_verbose)
		return;

	if(!errcode) {
		log_std(_("Command successful.\n"));
		return;
	}

	if (errcode < 0)
		errcode = translate_errno(errcode);

	if (errcode == 1)
		crypt_error = _("wrong or missing parameters");
	else if (errcode == 2)
		crypt_error = _("no permission or bad passphrase");
	else if (errcode == 3)
		crypt_error = _("out of memory");
	else if (errcode == 4)
		crypt_error = _("wrong device or file specified");
	else if (errcode == 5)
		crypt_error = _("device already exists or device is busy");
	else
		crypt_error = _("unknown error");

	log_std(_("Command failed with code %i (%s).\n"), -errcode, crypt_error);
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
		while ((s = spec[i++]) && i < (PATH_MAX - 13)) {
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

/*
 * Device size string parsing, suffixes:
 * s|S - 512 bytes sectors
 * k  |K  |m  |M  |g  |G  |t  |T   - 1024 base
 * kiB|KiB|miB|MiB|giB|GiB|tiB|TiB - 1024 base
 * kb |KB |mM |MB |gB |GB |tB |TB  - 1000 base
 */
int tools_string_to_size(struct crypt_device *cd, const char *s, uint64_t *size)
{
	char *endp = NULL;
	size_t len;
	uint64_t mult_base, mult, tmp;

	*size = strtoull(s, &endp, 10);
	if (!isdigit(s[0]) ||
	    (errno == ERANGE && *size == ULLONG_MAX) ||
	    (errno != 0 && *size == 0))
		return -EINVAL;

	if (!endp || !*endp)
		return 0;

	len = strlen(endp);
	/* Allow "B" and "iB" suffixes */
	if (len > 3 ||
	   (len == 3 && (endp[1] != 'i' || endp[2] != 'B')) ||
	   (len == 2 && endp[1] != 'B'))
		return -EINVAL;

	if (len == 1 || len == 3)
		mult_base = 1024;
	else
		mult_base = 1000;

	mult = 1;
	switch (endp[0]) {
	case 's':
	case 'S': mult = 512;
		break;
	case 't':
	case 'T': mult *= mult_base;
		 /* Fall through */
	case 'g':
	case 'G': mult *= mult_base;
		 /* Fall through */
	case 'm':
	case 'M': mult *= mult_base;
		 /* Fall through */
	case 'k':
	case 'K': mult *= mult_base;
		break;
	default:
		return -EINVAL;
	}

	tmp = *size * mult;
	if (*size && (tmp / *size) != mult) {
		log_dbg("Device size overflow.");
		return -EINVAL;
	}

	*size = tmp;
	return 0;
}

/* Time progress helper */

/* The difference in seconds between two times in "timeval" format. */
static double time_diff(struct timeval *start, struct timeval *end)
{
	return (end->tv_sec - start->tv_sec)
		+ (end->tv_usec - start->tv_usec) / 1E6;
}

void tools_clear_line(void)
{
	if (opt_progress_frequency)
		return;
	/* vt100 code clear line */
	log_std("\33[2K\r");
}

void tools_time_progress(uint64_t device_size, uint64_t bytes,
			 struct timeval *start_time, struct timeval *end_time)
{
	struct timeval now_time;
	unsigned long long mbytes, eta;
	double tdiff, mib, frequency;
	int final = (bytes == device_size);
	const char *eol;

	if (opt_batch_mode)
		return;

	gettimeofday(&now_time, NULL);
	if (start_time->tv_sec == 0 && start_time->tv_usec == 0) {
		*start_time = now_time;
		*end_time = now_time;
		return;
	}

	if (opt_progress_frequency) {
		frequency = (double)opt_progress_frequency;
		eol = "\n";
	} else {
		frequency = 0.5;
		eol = "";
	}

	if (!final && time_diff(end_time, &now_time) < frequency)
		return;

	*end_time = now_time;

	tdiff = time_diff(start_time, end_time);
	if (!tdiff)
		return;

	mbytes = bytes  / 1024 / 1024;
	mib = (double)(mbytes) / tdiff;
	if (!mib)
		return;

	/* FIXME: calculate this from last minute only and remaining space */
	eta = (unsigned long long)(device_size / 1024 / 1024 / mib - tdiff);

	tools_clear_line();
	if (final)
		log_std("Finished, time %02llu:%02llu.%03llu, "
			"%4llu MiB written, speed %5.1f MiB/s\n",
			(unsigned long long)tdiff / 60,
			(unsigned long long)tdiff % 60,
			(unsigned long long)((tdiff - floor(tdiff)) * 1000.0),
			mbytes, mib);
	else
		log_std("Progress: %5.1f%%, ETA %02llu:%02llu, "
			"%4llu MiB written, speed %5.1f MiB/s%s",
			(double)bytes / device_size * 100,
			eta / 60, eta % 60, mbytes, mib, eol);
	fflush(stdout);
}

int tools_wipe_progress(uint64_t size, uint64_t offset, void *usrptr)
{
	static struct timeval start_time = {}, end_time = {};
	int r = 0;

	tools_time_progress(size, offset, &start_time, &end_time);

	check_signal(&r);
	if (r) {
		tools_clear_line();
		log_err("\nWipe interrupted.\n");
	}

	return r;
}
