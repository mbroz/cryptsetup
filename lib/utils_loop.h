/*
 * loopback block device utilities
 *
 * Copyright (C) 2011-2012, Red Hat, Inc. All rights reserved.
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

#ifndef _UTILS_LOOP_H
#define _UTILS_LOOP_H

/* loopback device helpers */

char *crypt_loop_get_device(void);
char *crypt_loop_backing_file(const char *loop);
int crypt_loop_device(const char *loop);
int crypt_loop_attach(const char *loop, const char *file, int offset,
		      int autoclear, int *readonly);
int crypt_loop_detach(const char *loop);

#endif /* _UTILS_LOOP_H */
