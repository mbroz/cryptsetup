/*
 * AFsplitter - Anti forensic information splitter
 *
 * Copyright (C) 2004, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
 *
 * AFsplitter diffuses information over a large stripe of data,
 * therefor supporting secure data destruction.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef INCLUDED_CRYPTSETUP_LUKS_AF_H
#define INCLUDED_CRYPTSETUP_LUKS_AF_H

/*
 * AF_split operates on src and produces information split data in
 * dst. src is assumed to be of the length blocksize. The data stripe
 * dst points to must be capable of storing blocksize*blocknumbers.
 * blocknumbers is the data multiplication factor.
 *
 * AF_merge does just the opposite: reproduces the information stored in
 * src of the length blocksize*blocknumbers into dst of the length
 * blocksize.
 *
 * On error, both functions return -1, 0 otherwise.
 */

int AF_split(char *src, char *dst, size_t blocksize, unsigned int blocknumbers, const char *hash);
int AF_merge(char *src, char *dst, size_t blocksize, unsigned int blocknumbers, const char *hash);
size_t AF_split_sectors(size_t blocksize, unsigned int blocknumbers);

#endif
