/*
 * BITLK (BitLocker-compatible) volume handling
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "libcryptsetup.h"
#include "bitlk.h"
#include "internal.h"

int BITLK_read_sb(struct crypt_device *cd, struct crypt_params_bitlk *params)
{
	int devfd;

	devfd = device_open(cd, crypt_data_device(cd), O_RDONLY);
	if(devfd < 0)
		return -EINVAL;

	return 0;
}

int BITLK_dump(struct crypt_device *cd, struct device *device)
{
	log_std(cd, "Info for BITLK device %s.\n", device_path(device));
	return 0;
}

int BITLK_activate(struct crypt_device *cd,
		   const char *name,
		   const char *password,
		   size_t passwordLen,
		   const struct crypt_params_bitlk *params,
		   uint32_t flags)
{
	int r;
	struct crypt_dm_active_device dmd = {
		.flags = flags,
	};

	/* FIXME: Password verify only */
	if (!name)
		return -EINVAL;

	r = device_block_adjust(cd, crypt_data_device(cd), DEV_EXCL,
				crypt_get_data_offset(cd), &dmd.size, &dmd.flags);
	if (r)
		return r;

	/* FIXME: Example - two segments device */
	r = dm_targets_allocate(&dmd.segment, 2);
	if (r)
		goto out;

	/* First sector mapped to DM_LINEAR */
	r = dm_linear_target_set(&dmd.segment, 0, 1, crypt_data_device(cd), 0);
	if (r)
		goto out;

	/* The rest is mapped to DM_ZERO (for now) */
	r = dm_zero_target_set(dmd.segment.next, 1, dmd.size - 1);
	if (r)
		goto out;

	log_dbg(cd, "Trying to activate BITLK on device %s%s%s.",
		device_path(crypt_data_device(cd)), name ? "with name " :"", name ?: "");

	r = dm_create_device(cd, name, CRYPT_BITLK, &dmd);
out:
	dm_targets_free(cd, &dmd);
	return r;
}
