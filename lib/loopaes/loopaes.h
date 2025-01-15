// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * loop-AES compatible volume handling
 *
 * Copyright (C) 2011-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2011-2025 Milan Broz
 */

#ifndef _LOOPAES_H
#define _LOOPAES_H

#include <stdint.h>
#include <stddef.h>

struct crypt_device;
struct volume_key;

#define LOOPAES_KEYS_MAX 65

int LOOPAES_parse_keyfile(struct crypt_device *cd,
			  struct volume_key **vk,
			  const char *hash,
			  unsigned int *keys_count,
			  char *buffer,
			  size_t buffer_len);

int LOOPAES_activate(struct crypt_device *cd,
		     const char *name,
		     const char *base_cipher,
		     unsigned int keys_count,
		     struct volume_key *vk,
		     uint32_t flags);
#endif
