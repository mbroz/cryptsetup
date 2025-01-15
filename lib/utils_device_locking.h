// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Metadata on-disk locking for processes serialization
 *
 * Copyright (C) 2016-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2025 Ondrej Kozina
 */

#ifndef _CRYPTSETUP_UTILS_LOCKING_H
#define _CRYPTSETUP_UTILS_LOCKING_H

#include <stdbool.h>

struct crypt_device;
struct crypt_lock_handle;
struct device;

int device_locked_readonly(struct crypt_lock_handle *h);
int device_locked(struct crypt_lock_handle *h);

int device_read_lock_internal(struct crypt_device *cd, struct device *device);
int device_write_lock_internal(struct crypt_device *cd, struct device *device);
void device_unlock_internal(struct crypt_device *cd, struct device *device);

int device_locked_verify(struct crypt_device *cd, int fd, struct crypt_lock_handle *h);

int crypt_write_lock(struct crypt_device *cd, const char *name, bool blocking, struct crypt_lock_handle **lock);
void crypt_unlock_internal(struct crypt_device *cd, struct crypt_lock_handle *h);


/* Used only in device internal allocation */
void device_set_lock_handle(struct device *device, struct crypt_lock_handle *h);
struct crypt_lock_handle *device_get_lock_handle(struct device *device);

#endif
