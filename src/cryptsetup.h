/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2019 Milan Broz
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
#include <sys/time.h>

#include "lib/nls.h"
#include "lib/utils_crypt.h"
#include "lib/utils_loop.h"
#include "lib/utils_fips.h"
#include "lib/utils_io.h"
#include "lib/utils_blkid.h"

#include "libcryptsetup.h"

#define CONST_CAST(x) (x)(uintptr_t)
#define DEFAULT_CIPHER(type)	(DEFAULT_##type##_CIPHER "-" DEFAULT_##type##_MODE)
#define SECTOR_SIZE 512
#define MAX_SECTOR_SIZE 4096
#define ROUND_SECTOR(x) (((x) + SECTOR_SIZE - 1) / SECTOR_SIZE)

#define DEFAULT_WIPE_BLOCK	1048576 /* 1 MiB */

extern int opt_debug;
extern int opt_debug_json;
extern int opt_verbose;
extern int opt_batch_mode;
extern int opt_force_password;
extern int opt_progress_frequency;

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

typedef enum { CREATED, UNLOCKED, REMOVED  } crypt_object_op;
void tools_keyslot_msg(int keyslot, crypt_object_op op);
void tools_token_msg(int token, crypt_object_op op);

extern volatile int quit;
void set_int_block(int block);
void set_int_handler(int block);
void check_signal(int *r);
int tools_signals_blocked(void);

int tools_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  uint64_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd);
void tools_passphrase_msg(int r);
int tools_is_stdin(const char *key_file);
int tools_string_to_size(struct crypt_device *cd, const char *s, uint64_t *size);
int tools_is_cipher_null(const char *cipher);

void tools_clear_line(void);

void tools_time_progress(uint64_t device_size, uint64_t bytes,
			 struct timeval *start_time, struct timeval *end_time);
int tools_wipe_progress(uint64_t size, uint64_t offset, void *usrptr);
int tools_reencrypt_progress(uint64_t size, uint64_t offset, void *usrptr);

int tools_read_mk(const char *file, char **key, int keysize);
int tools_write_mk(const char *file, const char *key, int keysize);

int tools_read_json_file(struct crypt_device *cd, const char *file, char **json, size_t *json_size);
int tools_write_json_file(struct crypt_device *cd, const char *file, const char *json);

int tools_detect_signatures(const char *device, int ignore_luks, size_t *count);
int tools_wipe_all_signatures(const char *path);

/* Log */
#define log_dbg(x...) clogger(NULL, CRYPT_LOG_DEBUG, __FILE__, __LINE__, x)
#define log_std(x...) clogger(NULL, CRYPT_LOG_NORMAL, __FILE__, __LINE__, x)
#define log_verbose(x...) clogger(NULL, CRYPT_LOG_VERBOSE, __FILE__, __LINE__, x)
#define log_err(x...) clogger(NULL, CRYPT_LOG_ERROR, __FILE__, __LINE__, x)

#endif /* CRYPTSETUP_H */
