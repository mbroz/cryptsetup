/*
 * cryptsetup command line plugin API
 *
 * Copyright (C) 2020 Red Hat, Inc. All rights reserved.
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

#ifndef PLUGIN_H
#define PLUGIN_H

#include <stdbool.h>

#include "libcryptsetup_cli.h"

/* plugin command line argument prefix */
#define CRYPT_PLUGIN "plugin"

typedef struct crypt_token_arg_item {
	const char *name;
	const char *desc; /* optional */
	crypt_arg_type_info arg_type;
	const struct crypt_token_arg_item *next;
} crypt_token_arg_item;

typedef int (*crypt_token_handle_init_func) (struct crypt_cli *ctx, void **handle);
typedef void (*crypt_token_handle_free_func) (void *handle);

typedef int (*crypt_token_create_func) (struct crypt_device *cd, void *token_handle);
typedef int (*crypt_token_validate_create_params_func) (struct crypt_device *cd, void *token_handle);

typedef int (*crypt_token_remove_func) (struct crypt_device *cd, void *token_handle);
typedef int (*crypt_token_validate_remove_params_func) (struct crypt_device *cd, void *token_handle);

typedef crypt_token_arg_item* (*crypt_token_params_func) (void);

#endif
