/*
 * FVAULT2 (FileVault2-compatible) volume handling
 *
 * Copyright (C) 2021-2022 Pavel Tobias
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

#include <errno.h>
#include "internal.h"
#include "fvault2.h"

int FVAULT2_read_metadata(
	struct crypt_device *cd,
	struct fvault2_params *params)
{
	return -ENOTSUP;
}

int FVAULT2_get_volume_key(
	struct crypt_device *cd,
	const char *passphr,
	size_t passphr_len,
	const struct fvault2_params *params,
	struct volume_key **vol_key)
{
	return -ENOTSUP;
}

int FVAULT2_dump(
	struct crypt_device *cd,
	struct device *device,
	const struct fvault2_params *params)
{
	return -ENOTSUP;
}

int FVAULT2_activate_by_passphrase(
	struct crypt_device *cd,
	const char *name,
	const char *passphr,
	size_t passphr_len,
	const struct fvault2_params *params,
	uint32_t flags)
{
	return -ENOTSUP;
}

int FVAULT2_activate_by_volume_key(
	struct crypt_device *cd,
	const char *name,
	const char *key,
	size_t key_size,
	const struct fvault2_params *params,
	uint32_t flags)
{
	return -ENOTSUP;
}
