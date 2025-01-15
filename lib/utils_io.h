// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * utils - miscellaneous I/O utilities for cryptsetup
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#ifndef _CRYPTSETUP_UTILS_IO_H
#define _CRYPTSETUP_UTILS_IO_H

#include <stddef.h>
#include <sys/types.h>

ssize_t read_buffer(int fd, void *buf, size_t length);
ssize_t read_buffer_intr(int fd, void *buf, size_t length, volatile int *quit);
ssize_t write_buffer(int fd, const void *buf, size_t length);
ssize_t write_buffer_intr(int fd, const void *buf, size_t length, volatile int *quit);
ssize_t write_blockwise(int fd, size_t bsize, size_t alignment,
			void *orig_buf, size_t length);
ssize_t read_blockwise(int fd, size_t bsize, size_t alignment,
		       void *orig_buf, size_t length);
ssize_t write_lseek_blockwise(int fd, size_t bsize, size_t alignment,
			      void *buf, size_t length, off_t offset);
ssize_t read_lseek_blockwise(int fd, size_t bsize, size_t alignment,
			     void *buf, size_t length, off_t offset);

#endif
