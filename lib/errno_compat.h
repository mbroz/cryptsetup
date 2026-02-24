// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Portability compatibility definitions.
 *
 * Provides fallbacks for Linux-specific errno values and open(2)
 * flags that are not available on all platforms (e.g. macOS / FreeBSD).
 * Numeric values match the Linux kernel definitions so that on-disk
 * or on-wire error codes stay consistent.
 */

#ifndef CRYPTSETUP_COMPAT_H
#define CRYPTSETUP_COMPAT_H

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/* ---- Linux-specific errno values ---- */

#ifndef ENOANO
#define ENOANO		55	/* No anode */
#endif

#ifndef ENOTBLK
#define ENOTBLK		15	/* Block device required */
#endif

#ifndef ENOKEY
#define ENOKEY		126	/* Required key not available */
#endif

#ifndef EKEYEXPIRED
#define EKEYEXPIRED	127	/* Key has expired */
#endif

#ifndef EKEYREVOKED
#define EKEYREVOKED	128	/* Key has been revoked */
#endif

#ifndef EKEYREJECTED
#define EKEYREJECTED	129	/* Key was rejected by service */
#endif

#ifndef ENOMEDIUM
#define ENOMEDIUM	123	/* No medium found */
#endif

/* ---- Linux-specific open(2) flags ---- */

#ifndef O_DIRECT
#define O_DIRECT	0
#endif

#ifndef O_NOFOLLOW
#define O_NOFOLLOW	0
#endif

/* ---- posix_fallocate fallback (not available on macOS/some BSDs) ---- */

#if !HAVE_POSIX_FALLOCATE
#include <sys/types.h>
#include <sys/stat.h>
static inline int posix_fallocate(int fd, off_t offset, off_t len)
{
	off_t end = offset + len;
	struct stat st;
	if (fstat(fd, &st) != 0)
		return errno;
	if (st.st_size < end) {
		if (ftruncate(fd, end) != 0)
			return errno;
	}
	return 0;
}
#endif

#endif /* CRYPTSETUP_COMPAT_H */
