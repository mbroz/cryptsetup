/*
 * Definitions of common constant and generic macros of libcryptsetup
 *
 * Copyright (C) 2009-2023 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2023 Milan Broz
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

#ifndef _LIBCRYPTSETUP_MACROS_H
#define _LIBCRYPTSETUP_MACROS_H

/* to silent gcc -Wcast-qual for const cast */
#define CONST_CAST(x) (x)(uintptr_t)

/* to silent clang -Wcast-align when working with byte arrays */
#define VOIDP_CAST(x) (x)(void*)

#define UNUSED(x) (void)(x)

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define BITFIELD_SIZE(BF_PTR) (sizeof(*(BF_PTR)) * 8)

#define MOVE_REF(x, y) \
	do { \
		__typeof__(x) *_px = &(x), *_py = &(y); \
		*_px = *_py; \
		*_py = NULL; \
	} while (0)

#define FREE_AND_NULL(x) do { free(x); x = NULL; } while (0)

#define AT_LEAST(a, b) ({ __typeof__(a) __at_least = (a); (__at_least >= (b))?__at_least:(b); })

#define SHIFT_4K          12
#define SECTOR_SHIFT       9
#define SECTOR_SIZE     (1 << SECTOR_SHIFT)
#define MAX_SECTOR_SIZE 4096 /* min page size among all platforms */
#define ROUND_SECTOR(x) (((x) + SECTOR_SIZE - 1) / SECTOR_SIZE)

#define MISALIGNED(a, b)	((a) & ((b) - 1))
#define MISALIGNED_4K(a)	MISALIGNED((a), 1 << SHIFT_4K)
#define MISALIGNED_512(a)	MISALIGNED((a), 1 << SECTOR_SHIFT)
#define NOTPOW2(a)		MISALIGNED((a), (a))

#define DEFAULT_DISK_ALIGNMENT	1048576 /* 1MiB */
#define DEFAULT_MEM_ALIGNMENT	4096

#define DM_UUID_LEN		129
#define DM_BY_ID_PREFIX		"dm-uuid-"
#define DM_BY_ID_PREFIX_LEN	8
#define DM_UUID_PREFIX		"CRYPT-"
#define DM_UUID_PREFIX_LEN	6

#endif /* _LIBCRYPTSETUP_MACROS_H */
