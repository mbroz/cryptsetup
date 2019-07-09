/*
 * BITLK (BitLocker-compatible) header definition
 *
 * Copyright (C) 2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2019 Milan Broz
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

#ifndef _CRYPTSETUP_BITLK_H
#define _CRYPTSETUP_BITLK_H

#include <stdint.h>
#include <stddef.h>

struct crypt_device;
struct device;
struct crypt_params_bitlk;

int BITLK_read_sb(struct crypt_device *cd, struct crypt_params_bitlk *params);

int BITLK_dump(struct crypt_device *cd, struct device *device);

int BITLK_activate(struct crypt_device *cd,
		   const char *name,
		   const char *password,
		   size_t passwordLen,
		   const struct crypt_params_bitlk *params,
		   uint32_t flags);

#endif
