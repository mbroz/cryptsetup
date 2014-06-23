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

#ifndef CRYPTSETUP_H
#define CRYPTSETUP_H

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>
#include <fcntl.h>
#include <popt.h>
#include <sys/stat.h>

#include "lib/nls.h"
#include "lib/utils_crypt.h"
#include "lib/utils_loop.h"
#include "lib/utils_fips.h"

#include "libcryptsetup.h"

#define CONST_CAST(x) (x)(uintptr_t)
#define DEFAULT_CIPHER(type)	(DEFAULT_##type##_CIPHER "-" DEFAULT_##type##_MODE)
#define SECTOR_SIZE 512
#define ROUND_SECTOR(x) (((x) + SECTOR_SIZE - 1) / SECTOR_SIZE)

extern int opt_debug;
extern int opt_verbose;
extern int opt_batch_mode;
extern int opt_force_password;

/* Common tools */
void clogger(struct crypt_device *cd, int level, const char *file, int line,
	     const char *format, ...)  __attribute__ ((format (printf, 5, 6)));
void tool_log(int level, const char *msg, void *usrptr __attribute__((unused)));
void quiet_log(int level, const char *msg, void *usrptr);

int yesDialog(const char *msg, void *usrptr __attribute__((unused)));
void show_status(int errcode);
const char *uuid_or_device(const char *spec);
__attribute__ ((noreturn)) \
void usage(poptContext popt_context, int exitcode, const char *error, const char *more);
void dbg_version_and_cmd(int argc, const char **argv);
int translate_errno(int r);

extern volatile int quit;
void set_int_block(int block);
void set_int_handler(int block);
void check_signal(int *r);
int tools_signals_blocked(void);

int tools_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  size_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd);

/* Log */
#define log_dbg(x...) clogger(NULL, CRYPT_LOG_DEBUG, __FILE__, __LINE__, x)
#define log_std(x...) clogger(NULL, CRYPT_LOG_NORMAL, __FILE__, __LINE__, x)
#define log_verbose(x...) clogger(NULL, CRYPT_LOG_VERBOSE, __FILE__, __LINE__, x)
#define log_err(x...) clogger(NULL, CRYPT_LOG_ERROR, __FILE__, __LINE__, x)

#endif /* CRYPTSETUP_H */
