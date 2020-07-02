/*
 * libcryptsetup_cli - cryptsetup command line tools library
 *
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2020 Milan Broz
 * Copyright (C) 2020 Ondrej Kozina
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

#ifndef _LIBCRYPTSETUP_CLI_H
#define _LIBCRYPTSETUP_CLI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

struct crypt_cli;
struct crypt_device;

typedef enum {
	CRYPT_ARG_BOOL = 0,
	CRYPT_ARG_STRING,
	CRYPT_ARG_INT32,
	CRYPT_ARG_UINT32,
	CRYPT_ARG_INT64,
	CRYPT_ARG_UINT64
} crypt_arg_type_info;

int crypt_cli_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  uint64_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd, struct crypt_cli *ctx);

int crypt_cli_read_mk(const char *file, char **key, size_t keysize);

bool crypt_cli_arg_set(struct crypt_cli *ctx, const char *name);

int crypt_cli_arg_value(struct crypt_cli *ctx, const char *name, void *value);

int crypt_cli_arg_type(struct crypt_cli *ctx, const char *name, crypt_arg_type_info *type);

void crypt_cli_logger(struct crypt_device *cd, int level, const char *file, int line,
	     const char *format, ...);

/* Log */
#define log_dbg(x...) crypt_cli_logger(NULL, CRYPT_LOG_DEBUG, __FILE__, __LINE__, x)
#define log_std(x...) crypt_cli_logger(NULL, CRYPT_LOG_NORMAL, __FILE__, __LINE__, x)
#define log_verbose(x...) crypt_cli_logger(NULL, CRYPT_LOG_VERBOSE, __FILE__, __LINE__, x)
#define log_err(x...) crypt_cli_logger(NULL, CRYPT_LOG_ERROR, __FILE__, __LINE__, x)

#ifdef __cplusplus
}
#endif

#endif
