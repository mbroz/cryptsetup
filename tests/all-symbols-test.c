// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Test utility checking symbol versions in libcryptsetup.
 *
 * Copyright (C) 2021-2025 Red Hat, Inc. All rights reserved.
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
		/* fall through */
		case LOG_NORMAL:
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

static int check_dlvsym(void *h, const char *symbol, const char *version)
{
#if HAVE_DLVSYM
	void *sym;
	char *err;

	log_dbg("Checking %s@%s...", symbol, version);
	sym = dlvsym(h, symbol, version);
	UNUSED(sym);
	err = dlerror();

	if (err) {
		log_err("%s.", err);
		return 1;
	}

	log_dbg("OK\n");
#else
	UNUSED(h);
	UNUSED(symbol);
	UNUSED(version);
#endif
	return 0;
}

static int check_dlsym(void *h, const char *symbol)
{
	void *sym;
	char *err;

	log_dbg("Checking %s...", symbol);
	sym = dlsym(h, symbol);
	UNUSED(sym);
	err = dlerror();

	if (err) {
		log_err("%s", err);
		return 1;
	}

	log_dbg("OK\n");
	return 0;
}

static int check_all_symbols(void *h)
{
	unsigned scount = 0;

#define CHECK_SYMBOL(SYM, VER)			\
do {						\
	if (check_dlvsym(h, #SYM, #VER))	\
		return 1;			\
	if (check_dlsym(h, #SYM))		\
		return 1;			\
	scount++;				\
} while (0);

#include "test-symbols-list.h"
#undef CHECK_SYMBOL

	if (!scount) {
		log_err("test-symbols-list.h file is probably empty.");
		return 1;
	}

	log_std("Performed %u symbol checks in total.\n", scount);

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
