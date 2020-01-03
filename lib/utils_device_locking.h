/*
 * Metadata on-disk locking for processes serialization
 *
 * Copyright (C) 2016-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2020 Ondrej Kozina
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

#ifndef _CRYPTSETUP_UTILS_LOCKING_H
#define _CRYPTSETUP_UTILS_LOCKING_H

struct crypt_device;
struct crypt_lock_handle;
struct device;

int device_locked_readonly(struct crypt_lock_handle *h);
int device_locked(struct crypt_lock_handle *h);

int device_read_lock_internal(struct crypt_device *cd, struct device *device);
int device_write_lock_internal(struct crypt_device *cd, struct device *device);
void device_unlock_internal(struct crypt_device *cd, struct device *device);

int device_locked_verify(struct crypt_device *cd, int fd, struct crypt_lock_handle *h);

int crypt_read_lock(struct crypt_device *cd, const char *name, bool blocking, struct crypt_lock_handle **lock);
int crypt_write_lock(struct crypt_device *cd, const char *name, bool blocking, struct crypt_lock_handle **lock);
void crypt_unlock_internal(struct crypt_device *cd, struct crypt_lock_handle *h);


/* Used only in device internal allocation */
void device_set_lock_handle(struct device *device, struct crypt_lock_handle *h);
struct crypt_lock_handle *device_get_lock_handle(struct device *device);

#endif
