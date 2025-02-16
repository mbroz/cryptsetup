// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * utils_safe_memory - safe memory helpers
 *
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include <string.h>
#include <sys/mman.h>
#include "internal.h"

struct safe_allocation {
	size_t size;
	bool locked;
	char data[0] __attribute__((aligned(8)));
};
#define OVERHEAD offsetof(struct safe_allocation, data)

/*
 * Replacement for memset(s, 0, n) on stack that can be optimized out
 * Also used in safe allocations for explicit memory wipe.
 */
void crypt_safe_memzero(void *data, size_t size)
{
	if (!data)
		return;

	return crypt_backend_memzero(data, size);
}

/* Memcpy helper to avoid spilling sensitive data through additional registers */
void *crypt_safe_memcpy(void *dst, const void *src, size_t size)
{
	if (!dst || !src)
		return NULL;

	return crypt_backend_memcpy(dst, src, size);
}

/* safe allocations */
void *crypt_safe_alloc(size_t size)
{
	struct safe_allocation *alloc;

	if (!size || size > (SIZE_MAX - OVERHEAD))
		return NULL;

	alloc = malloc(size + OVERHEAD);
	if (!alloc)
		return NULL;

	crypt_backend_memzero(alloc, size + OVERHEAD);
	alloc->size = size;

	/* Ignore failure if it is over limit. */
	if (!mlock(alloc, size + OVERHEAD))
		alloc->locked = true;

	/* coverity[leaked_storage] */
	return &alloc->data;
}

void crypt_safe_free(void *data)
{
	struct safe_allocation *alloc;
	volatile size_t *s;
	void *p;

	if (!data)
		return;

	p = (char *)data - OVERHEAD;
	alloc = (struct safe_allocation *)p;

	crypt_backend_memzero(data, alloc->size);

	if (alloc->locked) {
		munlock(alloc, alloc->size + OVERHEAD);
		alloc->locked = false;
	}

	s = (volatile size_t *)&alloc->size;
	*s = 0x55aa55aa;
	free(alloc);
}

void *crypt_safe_realloc(void *data, size_t size)
{
	struct safe_allocation *alloc;
	void *new_data;
	void *p;

	new_data = crypt_safe_alloc(size);

	if (new_data && data) {

		p = (char *)data - OVERHEAD;
		alloc = (struct safe_allocation *)p;

		if (size > alloc->size)
			size = alloc->size;

		crypt_backend_memcpy(new_data, data, size);
	}

	crypt_safe_free(data);
	return new_data;
}

size_t crypt_safe_alloc_size(const void *data)
{
	const void *p;

	if (!data)
		return 0;

	p = (const char *)data - OVERHEAD;

	return ((const struct safe_allocation *)p)->size;
}
