// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Generic wrapper for storage functions
 * (experimental only)
 *
 * Copyright (C) 2018-2025 Ondrej Kozina
 */

#ifndef _UTILS_STORAGE_WRAPPERS_H
#define _UTILS_STORAGE_WRAPPERS_H

#include <stdint.h>
#include <sys/types.h>

struct crypt_storage_wrapper;
struct device;
struct volume_key;
struct crypt_device;

#define DISABLE_USPACE	(1 << 0)
#define DISABLE_KCAPI	(1 << 1)
#define DISABLE_DMCRYPT	(1 << 2)
#define OPEN_READONLY	(1 << 3)
#define LARGE_IV	(1 << 4)

typedef enum {
	NONE = 0,
	USPACE,
	DMCRYPT
} crypt_storage_wrapper_type;

int crypt_storage_wrapper_init(struct crypt_device *cd,
	struct crypt_storage_wrapper **cw,
	struct device *device,
	uint64_t data_offset,
	uint64_t iv_start,
	int sector_size,
	const char *cipher,
	struct volume_key *vk,
	uint32_t flags);

void crypt_storage_wrapper_destroy(struct crypt_storage_wrapper *cw);

/* !!! when doing 'read' or 'write' all offset values are RELATIVE to data_offset !!! */
ssize_t crypt_storage_wrapper_read(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length);
ssize_t crypt_storage_wrapper_read_decrypt(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length);
ssize_t crypt_storage_wrapper_decrypt(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length);

ssize_t crypt_storage_wrapper_write(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length);
ssize_t crypt_storage_wrapper_encrypt_write(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length);
ssize_t crypt_storage_wrapper_encrypt(struct crypt_storage_wrapper *cw,
		off_t offset, void *buffer, size_t buffer_length);

int crypt_storage_wrapper_datasync(const struct crypt_storage_wrapper *cw);

crypt_storage_wrapper_type crypt_storage_wrapper_get_type(const struct crypt_storage_wrapper *cw);
#endif
