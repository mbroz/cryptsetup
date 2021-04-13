/*
 * Test utility checking symbol versions in libcryptsetup.
 *
 * Copyright (C) 2021 Red Hat, Inc. All rights reserved.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UNUSED(expr) do { (void)(expr); } while (0)

static int _debug;
static const char *libfile = "libcryptsetup.so.12";

#define LOG_MAX_LEN 256

#define LOG_DEBUG  1
#define LOG_NORMAL 2
#define LOG_ERROR  3

__attribute__((format(printf, 2, 3)))
static void test_logf(int level, const char *format, ...)
{
	va_list argp;
	char target[LOG_MAX_LEN + 2];
	int len;

	va_start(argp, format);

	len = vsnprintf(&target[0], LOG_MAX_LEN, format, argp);
	if (len > 0 && len < LOG_MAX_LEN) {
		switch (level) {
		case LOG_DEBUG:
			if (!_debug)
				break;
		case LOG_NORMAL: /* fall through */
			fprintf(stdout, "%s", target);
			break;
		case LOG_ERROR:
			fflush(stdout);
			strcat(target, "\n");
			fprintf(stderr, "%s", target);
		}
	}

	va_end(argp);
}

#define log_dbg(x...) test_logf(LOG_DEBUG, x)
#define log_std(x...) test_logf(LOG_NORMAL, x)
#define log_err(x...) test_logf(LOG_ERROR, x)

static int check_all_symbols(void *h)
{
	void *sym;
	char *err;
	unsigned scount = 0;

#define CHECK_SYMBOL(SYM, VER)								\
do {											\
	log_dbg("Checking " #SYM "@" #VER "...");					\
	sym = dlvsym(h, #SYM, #VER);							\
	UNUSED(sym);									\
	err = dlerror();								\
											\
	if (err) {									\
		log_err("%s.", err);							\
		return 1;								\
	}										\
											\
	log_dbg("OK\nChecking " #SYM "...");						\
	sym = dlsym(h, #SYM);								\
	UNUSED(sym);									\
	err = dlerror();								\
	if (err) {									\
		log_err("%s", err);							\
		return 1;								\
	}										\
	log_dbg("OK\n");								\
	scount++;									\
} while (0);

#include "test-symbols-list.h"
#undef CHECK_SYMBOL

	if (!scount) {
		log_err("test-symbols-list.h file is probably empty.");
		return 1;
	}

	log_std("Performed %u symbol checks in total\n.", scount);

	return 0;
}

static void usage(const char *app)
{
	log_std("usage:\n\t%s [-v|--verbose|--debug] [optional path to library so file]\n", app);

	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	int i, r;
	void *h;
	const char *libfile = "libcryptsetup.so.12"; /* TODO import proper version */

	for (i = 1; i < argc; i++) {
		if (*argv[i] != '-')
			libfile = argv[i];
		else if (!strcmp("-v", argv[i]) || !strcmp("--verbose", argv[i]) ||
		         !strcmp("--debug", argv[i]))
			_debug = 1;
		else if (!strcmp("-h", argv[i]) || !strcmp("--help", argv[i]))
			usage(argv[0]);
	}

	log_std("Checking dlopen(%s)...", libfile);

	h = dlopen(libfile, RTLD_NOW);
	if (!h) {
		log_err("dlopen(): %s.", dlerror());
		return EXIT_FAILURE;
	}
	dlerror();
	log_std("OK\n");

	r = check_all_symbols(h);

	if (dlclose(h)) {
		log_err("Failed to dlclose %s: %s.", libfile, dlerror());
		return EXIT_FAILURE;
	}

	return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
