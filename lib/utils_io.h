/*
 * utils - miscellaneous I/O utilities for cryptsetup
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2020 Milan Broz
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

#ifndef _CRYPTSETUP_UTILS_IO_H
#define _CRYPTSETUP_UTILS_IO_H

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
