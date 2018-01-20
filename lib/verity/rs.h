/*
 * Reed-Solomon codecs, based on libfec
 *
 * Copyright (C) 2004 Phil Karn, KA9Q
 * libcryptsetup modifications
 *   Copyright (C) 2017-2018, Red Hat, Inc. All rights reserved.
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

#ifndef _LIBFEC_RS_H
#define _LIBFEC_RS_H

typedef unsigned char data_t;
struct rs;

struct rs *init_rs_char(int symsize, int gfpoly, int fcr, int prim, int nroots, int pad);
void free_rs_char(struct rs *rs);

/* General purpose RS codec, 8-bit symbols */
void encode_rs_char(struct rs *rs, data_t *data, data_t *parity);

#endif
