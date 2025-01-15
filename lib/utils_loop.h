// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * loopback block device utilities
 *
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#ifndef _UTILS_LOOP_H
#define _UTILS_LOOP_H

/* loopback device helpers */

char *crypt_loop_backing_file(const char *loop);
int crypt_loop_device(const char *loop);
int crypt_loop_attach(char **loop, const char *file, int offset,
		      int autoclear, int *readonly, size_t blocksize);
int crypt_loop_detach(const char *loop);
int crypt_loop_resize(const char *loop);

#endif /* _UTILS_LOOP_H */
